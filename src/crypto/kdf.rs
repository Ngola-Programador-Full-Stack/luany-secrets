//! src/crypto/kdf.rs
//! Derivação de chave mestre via Argon2id.
//!
//! Parâmetros (OWASP 2024):
//!   - Algoritmo    : Argon2id
//!   - Memória      : 64 MB (resistente a ataques GPU/ASIC)
//!   - Iterações    : 3
//!   - Paralelismo  : 4 threads
//!   - Output       : 32 bytes (chave AES-256)
//!
//! Modos de entrada da senha:
//!   - Interactive  : utilizador digita no terminal (sem eco de caracteres)
//!   - Environment  : lida de LS_MASTER_PASSWORD (pipelines CI/CD)

use argon2::{Argon2, Algorithm, Version, Params};
use zeroize::{Zeroize, Zeroizing};
use std::io;

// ── Parâmetros Argon2id ───────────────────────────────────────────────────────
const MEM_COST_KB:  u32   = 65_536;  // 64 MB
const TIME_COST:    u32   = 3;
const PARALLELISM:  u32   = 4;
const OUTPUT_LEN:   usize = 32;

pub const SALT_LEN: usize = 32;

// ── Tipo de saída protegido ───────────────────────────────────────────────────
pub type MasterKey = Zeroizing<[u8; OUTPUT_LEN]>;

// ── Fonte da senha ────────────────────────────────────────────────────────────
pub enum PasswordSource {
    /// Utilizador digita a senha no terminal
    Interactive,
    /// Lida da variável de ambiente LS_MASTER_PASSWORD (CI/CD)
    Environment,
}

/// Detecta automaticamente a fonte:
/// se LS_MASTER_PASSWORD estiver definida e não vazia → Environment
/// caso contrário → Interactive
pub fn detect_password_source() -> PasswordSource {
    match std::env::var("LS_MASTER_PASSWORD") {
        Ok(v) if !v.is_empty() => PasswordSource::Environment,
        _                      => PasswordSource::Interactive,
    }
}

/// Lê a senha de acordo com a fonte.
/// Retorna Zeroizing<String> — conteúdo apagado da RAM ao sair do scope.
pub fn read_password(source: PasswordSource) -> io::Result<Zeroizing<String>> {
    match source {
        PasswordSource::Environment => {
            let pw = std::env::var("LS_MASTER_PASSWORD")
                .map_err(|_| io::Error::new(
                    io::ErrorKind::NotFound,
                    "Variável LS_MASTER_PASSWORD não encontrada ou vazia.\n\
                     Define-a antes de executar: export LS_MASTER_PASSWORD=<senha>",
                ))?;

            // Apagar do environment deste processo imediatamente após leitura.
            // Nota: não afecta o shell pai — apenas o processo lsec.
            std::env::remove_var("LS_MASTER_PASSWORD");

            if pw.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "LS_MASTER_PASSWORD está vazia.",
                ));
            }

            Ok(Zeroizing::new(pw))
        }

        PasswordSource::Interactive => {
            // Leitura sem eco — nenhum caractere é exibido no terminal
            let pw = rpassword::prompt_password("🔐 Senha Mestre: ")
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

            if pw.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "A senha não pode estar vazia.",
                ));
            }

            Ok(Zeroizing::new(pw))
        }
    }
}

/// Deriva uma MasterKey de 32 bytes a partir da senha e do salt usando Argon2id.
///
/// A senha é consumida (moved) e apagada da RAM ao sair do scope.
/// A MasterKey resultante é encapsulada em Zeroizing.
pub fn derive_master_key(
    password: Zeroizing<String>,
    salt: &[u8; SALT_LEN],
) -> io::Result<MasterKey> {
    let params = Params::new(MEM_COST_KB, TIME_COST, PARALLELISM, Some(OUTPUT_LEN))
        .map_err(|e| io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Parâmetros Argon2id inválidos: {}", e),
        ))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; OUTPUT_LEN]);

    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| io::Error::new(
            io::ErrorKind::Other,
            format!("Falha na derivação Argon2id: {}", e),
        ))?;

    // password é apagada aqui automaticamente (Zeroizing + Drop)
    Ok(key)
}
