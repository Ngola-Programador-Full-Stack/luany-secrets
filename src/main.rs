//! lsec — Luany Secrets CLI
//! Ponto de entrada da aplicação.
//!
//! Comandos disponíveis:
//!   lsec init                   → configurar senha mestre
//!   lsec lock <ficheiro>        → proteger ficheiro → .ls
//!   lsec unlock <ficheiro>      → restaurar ficheiro .ls
//!   lsec edit <ficheiro>        → abrir .ls em editor e voltar a trancar
//!   lsec share <ficheiro>       → gerar token de partilha
//!   lsec logout                 → apagar sessão do keychain
//!   lsec status                 → estado da sessão actual

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

mod crypto  { pub mod aes; pub mod kdf; }
mod storage { pub mod binary_format; pub mod os_keyring; }
mod utils   { pub mod shredder; pub mod temp_watcher; }

use storage::binary_format::{LsHeader, KeySlot, HEADER_SIZE};
use crypto::kdf::SALT_LEN;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name    = "lsec",
    about   = "🔐 Luany Secrets — Protege qualquer ficheiro com AES-256-GCM",
    version = "0.1.0",
    after_help = "Exemplos:\n  \
        lsec init\n  \
        lsec lock .env\n  \
        lsec edit relatorio.xlsx.ls\n  \
        lsec share contrato.pdf.ls\n  \
        lsec logout"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Configurar a Senha Mestre na primeira utilização
    Init,

    /// Encriptar ficheiro e destruir o original com segurança
    Lock {
        #[arg(help = "Ficheiro a proteger  (ex: .env, relatorio.xlsx)")]
        file: PathBuf,
    },

    /// Desencriptar e restaurar ficheiro .ls no disco
    Unlock {
        #[arg(help = "Ficheiro .ls a restaurar")]
        file: PathBuf,
    },

    /// Abrir .ls no editor padrão — volta a trancar ao premir Enter
    Edit {
        #[arg(help = "Ficheiro .ls a editar em modo seguro")]
        file: PathBuf,
    },

    /// Gerar token de partilha segura para um ficheiro .ls
    Share {
        #[arg(help = "Ficheiro .ls a partilhar")]
        file: PathBuf,
        #[arg(long, help = "Email ou nome do destinatário (para auditoria)")]
        dest: Option<String>,
    },

    /// Apagar sessão activa do keychain do sistema operativo
    Logout,

    /// Mostrar estado da sessão e configuração actual
    Status,
}

// ── PONTO DE ENTRADA ─────────────────────────────────────────────────────────

fn main() {
    // Segurança: sempre limpar temporários órfãos antes de qualquer operação
    if let Err(e) = utils::temp_watcher::cleanup_orphaned_sessions() {
        eprintln!("⚠️  Aviso ao limpar sessões anteriores: {}", e);
    }

    let cli = Cli::parse();

    let result = match cli.command {
        Command::Init                   => cmd_init(),
        Command::Lock   { file }        => cmd_lock(&file),
        Command::Unlock { file }        => cmd_unlock(&file),
        Command::Edit   { file }        => cmd_edit(&file),
        Command::Share  { file, dest }  => cmd_share(&file, dest.as_deref()),
        Command::Logout                 => cmd_logout(),
        Command::Status                 => cmd_status(),
    };

    if let Err(e) = result {
        eprintln!("\n❌  {}\n", e);
        std::process::exit(1);
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  COMANDOS
// ══════════════════════════════════════════════════════════════════════════════

fn cmd_init() -> std::io::Result<()> {
    println!("\n🔐  Luany Secrets — Configuração Inicial\n");

    if storage::os_keyring::has_active_session() {
        println!("✅  Já tens uma sessão activa. Usa 'lsec status' para detalhes.\n");
        return Ok(());
    }

    println!("    Define a tua Senha Mestre. Ela protegerá todos os teus ficheiros .ls.");
    println!("    ⚠️  Não há recuperação se a esqueceres.\n");

    let pw  = crypto::kdf::read_password(crypto::kdf::PasswordSource::Interactive)?;
    let pw2 = {
        println!("    Confirma a senha:");
        crypto::kdf::read_password(crypto::kdf::PasswordSource::Interactive)?
    };

    if pw.as_str() != pw2.as_str() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "As senhas não coincidem. Tenta novamente.",
        ));
    }
    if pw.len() < 8 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "A senha mestre deve ter pelo menos 8 caracteres.",
        ));
    }

    storage::os_keyring::save_session(&pw)?;

    println!("\n✅  Luany Secrets configurado com sucesso!");
    println!("    Sessão activa por 1 hora.\n");
    println!("    Próximos passos:");
    println!("    →  lsec lock <ficheiro>   proteger um ficheiro");
    println!("    →  lsec edit <fich>.ls    abrir e editar em modo seguro");
    println!("    →  lsec --help            todos os comandos\n");
    Ok(())
}

fn cmd_lock(path: &Path) -> std::io::Result<()> {
    require_file(path)?;
    require_not_ls(path)?;

    println!("\n🔒  A proteger: {}\n", path.display());

    let password   = get_session_password()?;
    let salt       = rand_bytes::<SALT_LEN>();
    let nonce      = crypto::aes::generate_nonce();
    let dek        = crypto::aes::generate_dek();
    let master_key = crypto::kdf::derive_master_key(password, &salt)?;

    // Cifrar DEK para Key Slot 1 (acesso local)
    let slot1_nonce = crypto::aes::generate_nonce();
    let enc_dek     = crypto::aes::encrypt_dek(&dek, &master_key, &slot1_nonce)?;

    // Cifrar corpo do ficheiro
    let plaintext  = std::fs::read(path)?;
    let ciphertext = crypto::aes::encrypt_file_body(&plaintext, &dek, &nonce)?;

    // Construir cabeçalho binário de 512 bytes
    let header = LsHeader {
        versao: 1,
        id_auditoria:       machine_id(),
        email_proprietario: encode_filename(path),
        nonce_principal:    nonce,
        salt,
        slot_local: KeySlot {
            encrypted_dek: enc_dek[..32].try_into().unwrap(),
            nonce:          slot1_nonce,
            tag:            enc_dek[32..].try_into().unwrap(),
        },
        slot_partilha: KeySlot::empty(),
        slot_futuro:   KeySlot::empty(),
    };

    // Escrever ficheiro .ls = cabeçalho (512B) + corpo cifrado
    let ls_path = path.with_file_name(format!(
        "{}.ls",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    let mut output = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
    output.extend_from_slice(header.serialize()?.as_ref());
    output.extend_from_slice(&ciphertext);
    std::fs::write(&ls_path, &output)?;

    // Destruir original de forma segura
    let shred = utils::shredder::shred_file(path)?;

    println!("✅  Ficheiro protegido:  {}", ls_path.display());
    println!("    Shredding original:  {} passes (padrão DoD)", shred.passes_completed);
    if let Some(w) = shred.ssd_warning {
        println!("\n{}\n", w);
    } else {
        println!();
    }

    Ok(())
}

fn cmd_unlock(path: &Path) -> std::io::Result<()> {
    require_ls(path)?;

    println!("\n🔓  A desbloquear: {}\n", path.display());

    let (header, ct) = read_ls(path)?;
    let password     = get_session_password()?;
    let master_key   = crypto::kdf::derive_master_key(password, &header.salt)?;

    // ← NOVO: se a senha estiver errada, limpar a sessão cacheada
    let dek = match decrypt_slot1(&header, &master_key) {
        Ok(d) => d,
        Err(e) => {
            storage::os_keyring::clear_session().ok();
            return Err(e);
        }
    };

    let plaintext = crypto::aes::decrypt_file_body(&ct, &dek, &header.nonce_principal)?;

    let name = decode_filename(&header.email_proprietario);
    let out  = path.parent().unwrap_or(Path::new(".")).join(&name);
    std::fs::write(&out, &plaintext)?;

    std::fs::remove_file(path)?;

    println!("✅ Restaurado: {}", out.display());
    println!("    O ficheiro .ls foi removido.\n");
    println!("⚠️  Lembra-te de proteger novamente após editar:");
    println!("    lsec lock {}\n", out.display());
    Ok(())
}



fn cmd_edit(path: &Path) -> std::io::Result<()> {
    require_ls(path)?;

    println!("\n✏️   Modo de edição segura: {}\n", path.display());

    let (header, ct) = read_ls(path)?;
    let password     = get_session_password()?;
    let master_key   = crypto::kdf::derive_master_key(password.clone(), &header.salt)?;

    let dek = match decrypt_slot1(&header, &master_key) {
        Ok(d) => d,
        Err(e) => {
            storage::os_keyring::clear_session().ok();
            return Err(e);
        }
    };
    
    let plaintext = Zeroizing::new(
        crypto::aes::decrypt_file_body(&ct, &dek, &header.nonce_principal)?
    );
    let name = decode_filename(&header.email_proprietario);

    let edited = utils::temp_watcher::open_and_watch(plaintext, &name, path)?;

    if let Some(new_content) = edited {
        println!("💾  A guardar alterações em {}...", path.display());

        let new_nonce   = crypto::aes::generate_nonce();
        let new_dek     = crypto::aes::generate_dek();
        let new_salt    = rand_bytes::<SALT_LEN>();
        let new_mk      = crypto::kdf::derive_master_key(password, &new_salt)?;
        let slot_nonce  = crypto::aes::generate_nonce();
        let enc_dek     = crypto::aes::encrypt_dek(&new_dek, &new_mk, &slot_nonce)?;
        let new_ct      = crypto::aes::encrypt_file_body(&new_content, &new_dek, &new_nonce)?;

        let new_header = LsHeader {
            versao: 1,
            id_auditoria:       machine_id(),
            email_proprietario: encode_filename(Path::new(&name)),
            nonce_principal:    new_nonce,
            salt:               new_salt,
            slot_local: KeySlot {
                encrypted_dek: enc_dek[..32].try_into().unwrap(),
                nonce:          slot_nonce,
                tag:            enc_dek[32..].try_into().unwrap(),
            },
            slot_partilha: KeySlot::empty(),
            slot_futuro:   KeySlot::empty(),
        };

        let mut output = Vec::with_capacity(HEADER_SIZE + new_ct.len());
        output.extend_from_slice(new_header.serialize()?.as_ref());
        output.extend_from_slice(&new_ct);
        std::fs::write(path, &output)?;

        println!("✅  Alterações guardadas e re-encriptadas em {}\n", path.display());
    } else {
        println!("ℹ️   Sem alterações detectadas.\n");
    }

    Ok(())
}


fn cmd_share(path: &Path, dest: Option<&str>) -> std::io::Result<()> {
    require_ls(path)?;

    println!("\n🔗  A gerar token de partilha segura...\n");

    let token = generate_token();

    println!("    Ficheiro  :  {}", path.display());
    if let Some(d) = dest {
        println!("    Para      :  {}", d);
    }
    println!();
    println!("    ┌──────────────────────────────────┐");
    println!("    │   Token:  {}   │", token);
    println!("    └──────────────────────────────────┘");
    println!();
    println!("    Como partilhar:");
    println!("    1. Envia o ficheiro .ls ao destinatário");
    println!("    2. Envia o token por canal separado (SMS, WhatsApp, etc.)");
    println!("    3. O destinatário precisa do Luany Secrets instalado");
    println!("    4. Ao abrir, o software pedirá o token acima");
    println!();
    println!("    ℹ️   Nota: injeção no Key Slot 2 será implementada na Fase 2.");
    println!("        O ficheiro actual usa o Key Slot 1 (acesso local).\n");
    Ok(())
}

fn cmd_logout() -> std::io::Result<()> {
    storage::os_keyring::clear_session()?;
    println!("\n✅  Sessão terminada. Keychain limpo.\n");
    Ok(())
}

fn cmd_status() -> std::io::Result<()> {
    println!();
    println!("🔐  Luany Secrets — Estado do Sistema");
    println!("    ─────────────────────────────────────────────");
    let sessao = if storage::os_keyring::has_active_session() {
        "✅  Activa  (expira 1h após o último uso)"
    } else {
        "❌  Inactiva  →  executa: lsec init"
    };
    println!("    Sessão    :  {}", sessao);
    println!("    Versão    :  0.1.0  (Fase 1 — MVP)");
    println!("    Formato   :  .ls  (Luany Secrets)");
    println!("    Cifra     :  AES-256-GCM");
    println!("    KDF       :  Argon2id  (64MB RAM · 3 iter. · 4 threads)");
    println!("    Cabeçalho :  512 bytes  (3 Key Slots)");
    println!("    Shredding :  DoD 5220.22-M  (3 passes)");
    println!();
    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
//  HELPERS INTERNOS
// ══════════════════════════════════════════════════════════════════════════════

/// Recupera senha da sessão activa ou pede ao utilizador e guarda no keychain.
fn get_session_password() -> std::io::Result<Zeroizing<String>> {
    if let Some(pw) = storage::os_keyring::load_session()? {
        return Ok(pw);
    }
    let pw = crypto::kdf::read_password(crypto::kdf::detect_password_source())?;
    storage::os_keyring::save_session(&pw)?;
    Ok(pw)
}

/// Lê um ficheiro .ls e separa cabeçalho (512B) do corpo cifrado.
fn read_ls(path: &Path) -> std::io::Result<(LsHeader, Vec<u8>)> {
    let raw = std::fs::read(path)?;
    if raw.len() <= HEADER_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Ficheiro .ls inválido ou corrompido.",
        ));
    }
    let hdr_bytes: [u8; HEADER_SIZE] = raw[..HEADER_SIZE].try_into().unwrap();
    let header = LsHeader::deserialize(&hdr_bytes)?;
    let body   = raw[HEADER_SIZE..].to_vec();
    Ok((header, body))
}

/// Decifra a DEK do Key Slot 1 usando a MasterKey.
fn decrypt_slot1(
    header: &LsHeader,
    master_key: &crypto::kdf::MasterKey,
) -> std::io::Result<crypto::aes::Dek> {
    let mut combined = [0u8; 48];
    combined[..32].copy_from_slice(&header.slot_local.encrypted_dek);
    combined[32..].copy_from_slice(&header.slot_local.tag);
    crypto::aes::decrypt_dek(&combined, master_key, &header.slot_local.nonce)
}

fn require_file(p: &Path) -> std::io::Result<()> {
    if !p.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Ficheiro não encontrado: {}", p.display()),
        ));
    }
    Ok(())
}

fn require_not_ls(p: &Path) -> std::io::Result<()> {
    if p.to_string_lossy().ends_with(".ls") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Este ficheiro já está protegido (.ls). Usa 'lsec edit' para editar.",
        ));
    }
    Ok(())
}

fn require_ls(p: &Path) -> std::io::Result<()> {
    require_file(p)?;
    if !p.to_string_lossy().ends_with(".ls") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Não é um ficheiro .ls. Usa 'lsec lock' para proteger primeiro.",
        ));
    }
    Ok(())
}

fn rand_bytes<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut buf = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

/// Token de partilha no formato LS-XXXX-XXXX-XXXX.
fn generate_token() -> String {
    use rand::RngCore;
    let mut b = [0u8; 6];
    rand::rngs::OsRng.fill_bytes(&mut b);
    format!(
        "LS-{:04X}-{:04X}-{:04X}",
        u16::from_be_bytes([b[0], b[1]]),
        u16::from_be_bytes([b[2], b[3]]),
        u16::from_be_bytes([b[4], b[5]]),
    )
}

/// Guarda o nome do ficheiro original nos 64 bytes do cabeçalho.
fn encode_filename(path: &Path) -> [u8; 64] {
    let mut buf   = [0u8; 64];
    let name      = path.file_name().unwrap_or_default().to_string_lossy();
    let bytes     = name.as_bytes();
    let len       = bytes.len().min(64);
    buf[..len].copy_from_slice(&bytes[..len]);
    buf
}

/// Recupera o nome original do ficheiro do cabeçalho.
fn decode_filename(buf: &[u8; 64]) -> String {
    String::from_utf8_lossy(buf)
        .trim_end_matches('\0')
        .to_string()
}

/// Identificador da máquina para auditoria (apenas metadata — nunca usado em cripto).
fn machine_id() -> [u8; 32] {
    let host = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".into());
    let mut id  = [0u8; 32];
    let b       = host.as_bytes();
    let len     = b.len().min(32);
    id[..len].copy_from_slice(&b[..len]);
    id
}
