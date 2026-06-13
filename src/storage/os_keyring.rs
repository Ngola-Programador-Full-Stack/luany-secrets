//! src/storage/os_keyring.rs
//! Gestão segura de sessão via keychain nativo do sistema operativo.
//!
//! Backend por plataforma:
//!   Windows  → Windows Credential Manager (DPAPI)
//!   macOS    → Keychain (SecKeychain API)
//!   Linux    → Secret Service (GNOME Keyring / KWallet)
//!
//! A senha nunca é escrita em ficheiro no disco — o keychain do OS
//! é responsável pela sua encriptação e protecção física.
//!
//! Timeout de sessão: 1 hora após o último uso.

use keyring::Entry;
use zeroize::{Zeroize, Zeroizing};
use std::io;

const SERVICE_NAME:       &str = "luany-secrets";
const ACCOUNT_NAME:       &str = "master-session";
const SESSION_TIMEOUT_SECS: u64 = 3_600; // 1 hora

// ── Payload de sessão ─────────────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize, Zeroize)]
#[zeroize(drop)]
struct SessionPayload {
    password:   String,
    created_at: u64,
}

// ── API pública ───────────────────────────────────────────────────────────────

/// Guarda a senha mestre no keychain do sistema operativo.
/// Chamada uma vez após autenticação bem-sucedida.
pub fn save_session(password: &Zeroizing<String>) -> io::Result<()> {
    let mut payload = SessionPayload {
        password:   password.as_str().to_string(),
        created_at: unix_now()?,
    };

    // Encapsular o JSON em Zeroizing para limpar a RAM após uso
    let json = Zeroizing::new(
        serde_json::to_string(&payload)
            .map_err(|e| io::Error::new(io::ErrorKind::Other,
                format!("Falha ao serializar sessão: {}", e)))?,
    );

    payload.zeroize(); // Limpar explicitamente antes do drop

    keyring_entry()?
        .set_password(json.as_str())
        .map_err(|e| io::Error::new(io::ErrorKind::Other,
            format!("Falha ao guardar sessão no keychain: {}", e)))?;

    Ok(())
}

/// Recupera a senha mestre da sessão activa, se ainda válida.
///
/// Retorna:
///   Ok(Some(pw)) → sessão válida
///   Ok(None)     → sem sessão ou expirada
///   Err(...)     → erro no keychain
pub fn load_session() -> io::Result<Option<Zeroizing<String>>> {
    let entry = keyring_entry()?;

    let json = match entry.get_password() {
        Ok(j)                           => j,
        Err(keyring::Error::NoEntry)    => return Ok(None),
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other,
            format!("Erro ao ler keychain: {}", e))),
    };

    let payload: SessionPayload = serde_json::from_str(&json)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData,
            "Sessão corrompida no keychain. Executa 'lsec init' novamente."))?;

    // Verificar expiração
    let now = unix_now()?;
    if now.saturating_sub(payload.created_at) > SESSION_TIMEOUT_SECS {
        clear_session()?;
        return Ok(None);
    }

    Ok(Some(Zeroizing::new(payload.password.clone())))
}

/// Apaga a sessão activa do keychain.
pub fn clear_session() -> io::Result<()> {
    match keyring_entry()?.delete_password() {
        Ok(_)                        => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()), // Não havia sessão — ok
        Err(e) => Err(io::Error::new(io::ErrorKind::Other,
            format!("Erro ao limpar sessão do keychain: {}", e))),
    }
}

/// Verifica se existe uma sessão activa sem recuperar a senha.
pub fn has_active_session() -> bool {
    matches!(load_session(), Ok(Some(_)))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn keyring_entry() -> io::Result<Entry> {
    Entry::new(SERVICE_NAME, ACCOUNT_NAME)
        .map_err(|e| io::Error::new(io::ErrorKind::Other,
            format!("Erro ao aceder ao keychain do sistema: {}", e)))
}

fn unix_now() -> io::Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
}
