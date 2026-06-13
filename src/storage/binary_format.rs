//! src/storage/binary_format.rs
//! Definição e serialização do formato binário do ficheiro .ls
//!
//! Layout do cabeçalho (512 bytes fixos):
//!
//!  Offset   Tamanho   Campo
//!  ──────   ───────   ─────
//!  0        4         Assinatura mágica: [0x4C,0x53,0x45,0x43] ("LSEC")
//!  4        1         Versão do formato
//!  5        32        ID de auditoria (hostname SHA — apenas metadata)
//!  37       64        Nome original do ficheiro (campo reutilizado)
//!  101      12        Nonce principal AES-GCM
//!  113      32        Salt Argon2id
//!  145      60        Key Slot 1 — DEK cifrada com MasterKey local
//!  205      60        Key Slot 2 — DEK cifrada com Token de Partilha
//!  265      60        Key Slot 3 — RESERVADO (Fase 2: chave pública)
//!  325      187       Padding (zeros — expansão futura sem quebrar ficheiros)
//!  ──────   ───────
//!  Total    512 bytes
//!
//! Após o cabeçalho:
//!  525+     variável  Corpo do ficheiro cifrado com AES-256-GCM

use std::io;
use zeroize::{Zeroize, Zeroizing};

pub const HEADER_SIZE:      usize  = 512;
pub const MAGIC_SIGNATURE:  &[u8; 4] = b"LSEC";
pub const FORMAT_VERSION:   u8     = 1;

// ── Key Slot (60 bytes) ───────────────────────────────────────────────────────

#[derive(Zeroize, Clone)]
#[zeroize(drop)]
pub struct KeySlot {
    /// DEK cifrada com AES-256-GCM (32 bytes de ciphertext)
    pub encrypted_dek: [u8; 32],
    /// Nonce único para esta operação de cifragem (12 bytes)
    pub nonce: [u8; 12],
    /// Tag de autenticação GCM (16 bytes) — detecta adulteração
    pub tag: [u8; 16],
}

impl KeySlot {
    /// Slot vazio — usado para slots não preenchidos (Partilha e Futuro no MVP)
    pub fn empty() -> Self {
        KeySlot {
            encrypted_dek: [0u8; 32],
            nonce:          [0u8; 12],
            tag:            [0u8; 16],
        }
    }

    /// Serializa para 60 bytes. Usa Zeroizing para limpar o buffer após uso.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(60));
        bytes.extend_from_slice(&self.encrypted_dek);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.tag);
        bytes
    }

    /// Desserializa a partir de 60 bytes lidos do disco.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut encrypted_dek = [0u8; 32];
        let mut nonce         = [0u8; 12];
        let mut tag           = [0u8; 16];
        encrypted_dek.copy_from_slice(&bytes[0..32]);
        nonce.copy_from_slice(&bytes[32..44]);
        tag.copy_from_slice(&bytes[44..60]);
        KeySlot { encrypted_dek, nonce, tag }
    }
}

// ── Cabeçalho completo ────────────────────────────────────────────────────────

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct LsHeader {
    /// Versão do formato (actualmente: 1)
    pub versao: u8,
    /// ID da máquina geradora — apenas auditoria, nunca usado em cripto
    pub id_auditoria: [u8; 32],
    /// Nome original do ficheiro (ex: "credenciais.env\0\0\0...")
    pub email_proprietario: [u8; 64],
    /// Nonce AES-GCM para o corpo do ficheiro
    pub nonce_principal: [u8; 12],
    /// Salt Argon2id — único por ficheiro
    pub salt: [u8; 32],
    /// Acesso local (senha mestre do criador)
    pub slot_local: KeySlot,
    /// Acesso por partilha (token gerado em `lsec share`)
    pub slot_partilha: KeySlot,
    /// Reservado — Fase 2: chave pública do destinatário
    pub slot_futuro: KeySlot,
}

impl LsHeader {
    /// Serializa o cabeçalho em exactamente 512 bytes.
    /// Retorna Zeroizing para garantir limpeza da RAM após gravação em disco.
    pub fn serialize(&self) -> io::Result<Zeroizing<[u8; HEADER_SIZE]>> {
        let mut raw = Zeroizing::new([0u8; HEADER_SIZE]);
        let h = raw.as_mut();
        let mut c = 0usize;  // cursor

        // Assinatura mágica (4)
        h[c..c+4].copy_from_slice(MAGIC_SIGNATURE);  c += 4;

        // Versão (1)
        h[c] = self.versao;                           c += 1;

        // ID de auditoria (32)
        h[c..c+32].copy_from_slice(&self.id_auditoria);  c += 32;

        // Nome original do ficheiro (64)
        h[c..c+64].copy_from_slice(&self.email_proprietario);  c += 64;

        // Nonce principal (12)
        h[c..c+12].copy_from_slice(&self.nonce_principal);  c += 12;

        // Salt Argon2id (32)
        h[c..c+32].copy_from_slice(&self.salt);  c += 32;

        // Key Slot 1 — local (60)
        h[c..c+60].copy_from_slice(&self.slot_local.to_bytes());  c += 60;

        // Key Slot 2 — partilha (60)
        h[c..c+60].copy_from_slice(&self.slot_partilha.to_bytes());  c += 60;

        // Key Slot 3 — futuro (60)
        h[c..c+60].copy_from_slice(&self.slot_futuro.to_bytes());

        // c = 325 → restantes 187 bytes ficam a zero (padding)
        // Total: 4+1+32+64+12+32+60+60+60+187 = 512 ✓

        Ok(raw)
    }

    /// Desserializa 512 bytes de um ficheiro .ls para a estrutura LsHeader.
    /// Valida a assinatura mágica e a versão antes de ler os dados.
    pub fn deserialize(raw: &[u8; HEADER_SIZE]) -> io::Result<Self> {
        // Validar assinatura mágica
        if &raw[0..4] != MAGIC_SIGNATURE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Ficheiro inválido. Não é um ficheiro Luany Secrets (.ls).",
            ));
        }

        let mut c = 4usize;

        // Versão
        let versao = raw[c];  c += 1;
        if versao != FORMAT_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "Versão do formato {} não suportada. \
                     Actualiza o Luany Secrets para abrir este ficheiro.",
                    versao
                ),
            ));
        }

        // ID de auditoria
        let mut id_auditoria = [0u8; 32];
        id_auditoria.copy_from_slice(&raw[c..c+32]);  c += 32;

        // Nome original do ficheiro
        let mut email_proprietario = [0u8; 64];
        email_proprietario.copy_from_slice(&raw[c..c+64]);  c += 64;

        // Nonce principal
        let mut nonce_principal = [0u8; 12];
        nonce_principal.copy_from_slice(&raw[c..c+12]);  c += 12;

        // Salt Argon2id
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&raw[c..c+32]);  c += 32;

        // Key Slots
        let slot_local    = KeySlot::from_bytes(&raw[c..c+60]);  c += 60;
        let slot_partilha = KeySlot::from_bytes(&raw[c..c+60]);  c += 60;
        let slot_futuro   = KeySlot::from_bytes(&raw[c..c+60]);

        let _ = c; // 325 — padding ignorado

        Ok(LsHeader {
            versao,
            id_auditoria,
            email_proprietario,
            nonce_principal,
            salt,
            slot_local,
            slot_partilha,
            slot_futuro,
        })
    }
}
