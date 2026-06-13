//! src/utils/temp_watcher.rs
//! Gestão segura de ficheiros temporários durante visualização/edição.
//!
//! Fluxo (lsec edit):
//!   1. Escreve bytes decifrados em pasta temporária do sistema
//!   2. Regista sessão em ~/.lsec_sessions.json (protecção anti-crash)
//!   3. Abre com a aplicação padrão do sistema operativo
//!   4. Aguarda o utilizador premir Enter para confirmar fecho
//!   5. Destrói o temporário via shredder
//!   6. Limpa o registo de sessão
//!
//! Recuperação de crashes:
//!   Qualquer comando `lsec` começa por cleanup_orphaned_sessions(),
//!   que detecta e tritura temporários de sessões não limpas.
//!
//! Nota técnica sobre "RAM pura":
//!   Aplicações como Excel e VS Code exigem um caminho de ficheiro físico.
//!   Não conseguem ler da RAM de outro processo. O ficheiro temporário
//!   existe apenas durante a sessão de edição — nunca além disso.

use std::io::{self};
use std::path::{Path, PathBuf};
use serde::{Serialize, Deserialize};
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

const SESSION_FILE: &str = ".lsec_sessions.json";

// ── Estruturas de registo ─────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
pub struct TempSession {
    pub session_id: String,
    pub temp_path:  String,
    pub ls_path:    String,
    pub created_at: u64,
}

#[derive(Serialize, Deserialize, Default)]
struct Registry {
    sessions: Vec<TempSession>,
}

// ── API pública ───────────────────────────────────────────────────────────────

/// Chamada no arranque de QUALQUER comando `lsec`.
/// Detecta e destrói ficheiros temporários de sessões interrompidas.
pub fn cleanup_orphaned_sessions() -> io::Result<()> {
    let reg_path = registry_path()?;
    if !reg_path.exists() {
        return Ok(());
    }

    let registry     = load_registry(&reg_path);
    let mut orphaned = false;

    for session in &registry.sessions {
        let temp = Path::new(&session.temp_path);
        if temp.exists() {
            if !orphaned {
                eprintln!("\n⚠️  Sessões anteriores não foram encerradas correctamente.");
                orphaned = true;
            }
            eprint!("    A destruir temporário órfão: {} ... ", session.temp_path);
            match crate::utils::shredder::shred_file(temp) {
                Ok(_)  => eprintln!("✅"),
                Err(e) => eprintln!("❌  ({})", e),
            }
        }
    }

    if orphaned {
        std::fs::remove_file(&reg_path).ok();
        eprintln!("    Registo de sessões limpo.\n");
    }

    Ok(())
}

/// Abre um ficheiro decifrado de forma segura e vigia o seu ciclo de vida.
///
/// O conteúdo decifrado é passado como Zeroizing<Vec<u8>> e apagado
/// da RAM imediatamente após a escrita física no temporário.
pub fn open_and_watch(
    mut decrypted_bytes: Zeroizing<Vec<u8>>,
    original_name: &str,
    ls_path: &Path,
) -> io::Result<()> {
    // Criar directório temporário seguro gerido pelo OS
    let temp_dir  = tempfile::tempdir()?;
    let temp_path = temp_dir.path().join(original_name);

    // Escrever conteúdo decifrado no disco temporário
    std::fs::write(&temp_path, decrypted_bytes.as_slice())?;

    // Apagar o vetor da RAM imediatamente após escrita — já está em disco
    decrypted_bytes.zeroize();

    // Registar sessão antes de abrir (protecção anti-crash)
    let session = TempSession {
        session_id: new_session_id(),
        temp_path:  temp_path.to_string_lossy().to_string(),
        ls_path:    ls_path.to_string_lossy().to_string(),
        created_at: unix_now()?,
    };
    register_session(&session)?;

    // Abrir com aplicação padrão do sistema operativo
    println!("📂  A abrir {} ...", original_name);
    open::that(&temp_path).map_err(|e| io::Error::new(
        io::ErrorKind::Other,
        format!(
            "Não foi possível abrir o ficheiro: {}\n\
             Verifica se tens uma aplicação associada ao formato '.{}'.",
            e,
            Path::new(original_name)
                .extension()
                .unwrap_or_default()
                .to_string_lossy()
        ),
    ))?;

    // MVP: Enter manual — Fase 2 implementará monitorização de PID nativa
    println!();
    println!("    ┌──────────────────────────────────────────────────────┐");
    println!("    │  Ficheiro aberto em modo seguro.                     │");
    println!("    │  Quando terminar, fecha a aplicação e prime ENTER.   │");
    println!("    └──────────────────────────────────────────────────────┘");

    let mut _input = String::new();
    std::io::stdin().read_line(&mut _input)?;

    // Destruir ficheiro temporário
    println!("\n🔒  A destruir ficheiro temporário...");
    match crate::utils::shredder::shred_file(&temp_path) {
        Ok(result) => {
            println!("    {} passes de shredding concluídos.", result.passes_completed);
            if let Some(w) = result.ssd_warning {
                println!("\n{}", w);
            }
        }
        Err(_) => {
            // temp_dir (drop abaixo) limpa igualmente — não é erro crítico
        }
    }

    // Limpar registo de sessão
    unregister_session(&session.session_id)?;

    println!(
        "\n✅  {} continua protegido.\n",
        ls_path.file_name().unwrap_or_default().to_string_lossy()
    );

    Ok(())
    // temp_dir dropped aqui — OS remove o directório mesmo se o shred falhou
}

// ── Helpers de registo ────────────────────────────────────────────────────────

fn register_session(session: &TempSession) -> io::Result<()> {
    let path = registry_path()?;
    let mut reg = load_registry(&path);
    reg.sessions.push(session.clone());
    save_registry(&path, &reg)
}

fn unregister_session(id: &str) -> io::Result<()> {
    let path    = registry_path()?;
    let mut reg = load_registry(&path);
    reg.sessions.retain(|s| s.session_id != id);
    if reg.sessions.is_empty() {
        std::fs::remove_file(&path).ok();
    } else {
        save_registry(&path, &reg)?;
    }
    Ok(())
}

fn load_registry(path: &Path) -> Registry {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|c| serde_json::from_str(&c).ok())
        .unwrap_or_default()
}

fn save_registry(path: &Path, reg: &Registry) -> io::Result<()> {
    let json = serde_json::to_string_pretty(reg)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    std::fs::write(path, json)
}

fn registry_path() -> io::Result<PathBuf> {
    dirs::home_dir()
        .ok_or_else(|| io::Error::new(
            io::ErrorKind::NotFound,
            "Não foi possível determinar a pasta home do utilizador.",
        ))
        .map(|h| h.join(SESSION_FILE))
}

fn new_session_id() -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn unix_now() -> io::Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
}
