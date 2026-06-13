//! src/crypto/aes.rs
//! Motor criptográfico AES-256-GCM.
//!
//! Arquitectura de Envelope Encryption (padrão Google KMS / AWS KMS):
//!
//!   Senha Mestre → [Argon2id] → MasterKey (32B)
//!                                    ↓
//!   DEK aleatória (32B) → [AES-256-GCM com MasterKey] → DEK cifrada → Key Slot
//!                ↓
//!   Ficheiro original → [AES-256-GCM com DEK] → Corpo cifrado do .ls
//!
//! Vantagem: se a senha mestre for alterada, só é necessário re-cifrar
//! os Key Slots (60 bytes) — o corpo do ficheiro (potencialmente GBs) não muda.

use aes_gcm::{
    aead::{Aead, KeyInit},
    aead::rand_core::RngCore,
    Aes256Gcm, Key, Nonce,
};
use rand::rngs::OsRng;
use zeroize::Zeroizing;
use std::io;

// ── Tamanhos fixos ────────────────────────────────────────────────────────────
pub const DEK_LEN:   usize = 32;  // AES-256 → 32 bytes
pub const NONCE_LEN: usize = 12;  // GCM nonce (96-bit)
pub const TAG_LEN:   usize = 16;  // GCM authentication tag (128-bit)

// ── Tipos protegidos ──────────────────────────────────────────────────────────
/// DEK em claro — apagada da RAM ao sair do scope
pub type Dek = Zeroizing<[u8; DEK_LEN]>;

/// DEK cifrada (32B ciphertext + 16B tag = 48B)
pub type EncryptedDek = Zeroizing<[u8; DEK_LEN + TAG_LEN]>;

// ══════════════════════════════════════════════════════════════════════════════
//  PARTE 1 — Gestão da DEK
// ══════════════════════════════════════════════════════════════════════════════

/// Gera uma DEK aleatória usando o CSPRNG do sistema operativo.
/// Chamada uma vez por ficheiro no momento do `lsec lock`.
pub fn generate_dek() -> Dek {
    let mut dek = Zeroizing::new([0u8; DEK_LEN]);
    OsRng.fill_bytes(dek.as_mut());
    dek
}

/// Gera um nonce AES-GCM aleatório de 12 bytes.
/// Deve ser único por operação — nunca reutilizar com a mesma chave.
pub fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Cifra a DEK com a MasterKey para guardar no Key Slot.
///
/// Retorna 48 bytes: [32B ciphertext AES-GCM] + [16B tag GCM]
/// O tag garante que qualquer adulteração é detectada no decrypt.
pub fn encrypt_dek(
    dek: &Dek,
    master_key: &crate::crypto::kdf::MasterKey,
    nonce: &[u8; NONCE_LEN],
) -> io::Result<EncryptedDek> {
    let key    = Key::<Aes256Gcm>::from_slice(master_key.as_ref());
    let cipher = Aes256Gcm::new(key);
    let nonce  = Nonce::from_slice(nonce);

    let ct = cipher
        .encrypt(nonce, dek.as_ref())
        .map_err(|_| io::Error::new(
            io::ErrorKind::Other,
            "Falha ao cifrar a DEK com a MasterKey.",
        ))?;

    // AES-GCM devolve ciphertext || tag  (32 + 16 = 48 bytes)
    let mut result = Zeroizing::new([0u8; DEK_LEN + TAG_LEN]);
    result.as_mut().copy_from_slice(&ct);
    Ok(result)
}

/// Decifra a DEK a partir do Key Slot usando a MasterKey.
///
/// Falha com PermissionDenied se a MasterKey for incorrecta.
/// A tag GCM verifica integridade — detecta adulteração do ficheiro.
pub fn decrypt_dek(
    encrypted_dek: &[u8; DEK_LEN + TAG_LEN],
    master_key: &crate::crypto::kdf::MasterKey,
    nonce: &[u8; NONCE_LEN],
) -> io::Result<Dek> {
    let key    = Key::<Aes256Gcm>::from_slice(master_key.as_ref());
    let cipher = Aes256Gcm::new(key);
    let nonce  = Nonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce, encrypted_dek.as_ref())
        .map_err(|_| io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Senha incorrecta ou ficheiro adulterado. Acesso negado.",
        ))?;

    let mut dek = Zeroizing::new([0u8; DEK_LEN]);
    dek.as_mut().copy_from_slice(&plaintext);
    Ok(dek)
}

// ══════════════════════════════════════════════════════════════════════════════
//  PARTE 2 — Cifra do corpo do ficheiro
// ══════════════════════════════════════════════════════════════════════════════

/// Cifra o conteúdo completo do ficheiro com a DEK.
///
/// Retorna Vec<u8> com [ciphertext || tag GCM].
/// Escrito directamente no corpo do ficheiro .ls após o cabeçalho de 512 bytes.
pub fn encrypt_file_body(
    plaintext: &[u8],
    dek: &Dek,
    nonce: &[u8; NONCE_LEN],
) -> io::Result<Vec<u8>> {
    let key    = Key::<Aes256Gcm>::from_slice(dek.as_ref());
    let cipher = Aes256Gcm::new(key);
    let nonce  = Nonce::from_slice(nonce);

    cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| io::Error::new(
            io::ErrorKind::Other,
            "Falha ao cifrar o corpo do ficheiro.",
        ))
}

/// Decifra o corpo do ficheiro .ls e devolve os bytes originais.
///
/// A tag GCM verifica a integridade total.
/// Qualquer alteração de 1 bit no disco causa falha — nunca dados corrompidos silenciosos.
pub fn decrypt_file_body(
    ciphertext: &[u8],
    dek: &Dek,
    nonce: &[u8; NONCE_LEN],
) -> io::Result<Vec<u8>> {
    let key    = Key::<Aes256Gcm>::from_slice(dek.as_ref());
    let cipher = Aes256Gcm::new(key);
    let nonce  = Nonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| io::Error::new(
            io::ErrorKind::InvalidData,
            "Ficheiro corrompido ou adulterado. Integridade GCM falhou.",
        ))
}
