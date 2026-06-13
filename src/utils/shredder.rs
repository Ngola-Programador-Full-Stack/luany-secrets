//! src/utils/shredder.rs
//! Destruição segura do ficheiro original após lock.
//!
//! Algoritmo: DoD 5220.22-M (3 passes)
//!   Pass 1: dados aleatórios (OsRng)
//!   Pass 2: zeros
//!   Pass 3: dados aleatórios (OsRng)
//!   Final:  fsync + unlink
//!
//! ⚠️  AVISO TÉCNICO HONESTO — SSDs e Wear Leveling:
//! Em discos SSD, o controlador de hardware (firmware) mantém um mapa
//! de blocos físicos para distribuir desgaste (Wear Leveling). Quando
//! o software sobrescreve um ficheiro, o controlador pode escrever
//! os novos dados num bloco físico diferente, deixando os dados
//! originais no bloco antigo até que o garbage collector do SSD o limpe.
//! Este módulo faz o melhor possível a nível de software.
//! Para garantia absoluta, use encriptação de disco completo
//! (BitLocker no Windows, FileVault no macOS, LUKS no Linux).

use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::Path;
use rand::RngCore;
use rand::rngs::OsRng;

const OVERWRITE_PASSES: usize = 3;   // DoD 5220.22-M
const CHUNK_SIZE:       usize = 65_536; // 64 KB por iteração

// ── Resultado público ─────────────────────────────────────────────────────────

pub struct ShredResult {
    pub passes_completed: usize,
    pub file_deleted:     bool,
    /// Aviso sobre limitações de SSD — None se HDD detectado
    pub ssd_warning:      Option<String>,
}

// ── API pública ───────────────────────────────────────────────────────────────

/// Destrói um ficheiro de forma segura (DoD 5220.22-M).
///
/// # Processo
/// 1. Overwrite com random (pass 1)
/// 2. Overwrite com zeros  (pass 2)
/// 3. Overwrite com random (pass 3)
/// 4. fsync — força escrita no disco físico
/// 5. unlink — apaga a entrada do sistema de ficheiros
///
/// # Erros comuns
/// Windows: se o ficheiro estiver aberto por outro programa (Excel, etc.),
/// OpenOptions::write() falha com "permission denied". O caller deve avisar
/// o utilizador para fechar a aplicação antes de proteger o ficheiro.
pub fn shred_file(path: &Path) -> io::Result<ShredResult> {
    let file_len = std::fs::metadata(path)?.len() as usize;

    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| {
            if e.kind() == io::ErrorKind::PermissionDenied {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Não foi possível aceder ao ficheiro para shredding.\n\
                     Se o ficheiro estiver aberto numa aplicação (Excel, Word, etc.),\n\
                     fecha-a primeiro e tenta novamente.",
                )
            } else {
                e
            }
        })?;

    let mut passes_completed = 0;

    for pass in 0..OVERWRITE_PASSES {
        file.seek(SeekFrom::Start(0))?;

        if pass % 2 == 0 {
            overwrite_random(&mut file, file_len)?; // passes 1 e 3
        } else {
            overwrite_zeros(&mut file, file_len)?;  // pass 2
        }

        // Forçar escrita no disco físico após cada pass
        file.sync_all()?;
        passes_completed += 1;
    }

    drop(file);

    let file_deleted = std::fs::remove_file(path).is_ok();
    let ssd_warning  = build_ssd_warning(path);

    Ok(ShredResult { passes_completed, file_deleted, ssd_warning })
}

// ── Helpers internos ──────────────────────────────────────────────────────────

fn overwrite_random(file: &mut File, len: usize) -> io::Result<()> {
    let mut buf       = vec![0u8; CHUNK_SIZE];
    let mut remaining = len;

    while remaining > 0 {
        let to_write = remaining.min(CHUNK_SIZE);
        OsRng.fill_bytes(&mut buf[..to_write]);
        file.write_all(&buf[..to_write])?;
        remaining -= to_write;
    }

    // Zeroizar buffer de trabalho antes de desalocar
    buf.iter_mut().for_each(|b| *b = 0);
    Ok(())
}

fn overwrite_zeros(file: &mut File, len: usize) -> io::Result<()> {
    let mut buf       = vec![0u8; CHUNK_SIZE];
    let mut remaining = len;

    while remaining > 0 {
        let to_write = remaining.min(CHUNK_SIZE);
        file.write_all(&buf[..to_write])?;
        remaining -= to_write;
    }

    // Consistência: limpar mesmo que sejam zeros
    buf.iter_mut().for_each(|b| *b = 0);
    Ok(())
}

fn build_ssd_warning(path: &Path) -> Option<String> {
    let likely_ssd = detect_ssd(path).unwrap_or(true); // assume SSD se não sabe

    if likely_ssd {
        Some(format!(
            "⚠️  NOTA DE SEGURANÇA — SSD detectado\n\
             O shredding lógico ({} passes DoD 5220.22-M) foi concluído,\n\
             mas o controlador SSD pode ter retido blocos físicos com dados\n\
             originais devido ao Wear Leveling do hardware.\n\n\
             Para garantia absoluta de eliminação, activa encriptação de disco:\n\
             • Windows : BitLocker  (Painel de Controlo → Sistema)\n\
             • macOS   : FileVault  (Preferências → Segurança)\n\
             • Linux   : LUKS       (configurado na instalação)\n\n\
             Com encriptação de disco activa, blocos órfãos são ilegíveis\n\
             mesmo que o SSD os retenha indefinidamente.",
            OVERWRITE_PASSES
        ))
    } else {
        None
    }
}

fn detect_ssd(_path: &Path) -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/sys/block/sda/queue/rotational") {
            return Some(content.trim() == "0");
        }
        return None;
    }

    // Windows e macOS: maioria dos portáteis modernos tem SSD
    // Detecção nativa via API será implementada na Fase 2
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    {
        return Some(true);
    }

    #[allow(unreachable_code)]
    None
}
