<div align="center">

# 🔐 Luany Secrets

**Protege qualquer ficheiro com encriptação de grau militar.**  
Um único comando. Um único ficheiro protegido. Sem atrito.

```bash
lsec lock credenciais.env      # → credenciais.env.ls  (original destruído)
lsec edit  credenciais.env.ls  # → abre com segurança, fecha e tranca
lsec share contrato.pdf.ls     # → gera token de partilha
```

[![Rust](https://img.shields.io/badge/Rust-1.75+-orange?logo=rust)](https://rustup.rs)
[![Licença](https://img.shields.io/badge/Licença-MIT-blue)](LICENSE)
[![Versão](https://img.shields.io/badge/Versão-0.1.0--MVP-purple)](CHANGELOG.md)
[![Segurança](https://img.shields.io/badge/Cifra-AES--256--GCM-green)](#segurança)

</div>

---

## O problema que resolve

O sistema operativo trata `credenciais.env` e `lista_de_compras.txt` de forma **idêntica**. Qualquer pessoa com acesso ao disco vê o conteúdo dos dois.

O Luany Secrets cria uma camada de segurança universal:

```
Antes:   credenciais.env     → qualquer pessoa abre e lê
Depois:  credenciais.env.ls  → lixo binário ilegível sem senha
```

**Para quem é:**
- Programadores e DevOps — proteger `.env`, chaves SSH, tokens de API
- Finanças e RH — folhas salariais, relatórios financeiros, dados fiscais
- Advogados e Consultores — contratos, minutas, documentos confidenciais

---

## Instalação rápida

### Pré-requisitos

- [Rust 1.75+](https://rustup.rs) — instalar com `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- Git

### Compilar a partir do código fonte

```bash
# 1. Clonar o repositório
git clone https://github.com/luany/luany-secrets.git
cd luany-secrets

# 2. Compilar em modo release (binário optimizado, < 5MB)
cargo build --release

# 3. Instalar globalmente (Linux/macOS)
sudo cp target/release/lsec /usr/local/bin/

# Windows — copiar para uma pasta no PATH
copy target\release\lsec.exe C:\Windows\System32\
```

### Verificar instalação

```bash
lsec --version
lsec --help
```

---

## Primeiros passos

### 1. Configurar a senha mestre

```bash
lsec init
```

```
🔐  Luany Secrets — Configuração Inicial

    Define a tua Senha Mestre. Ela protegerá todos os teus ficheiros .ls.
    ⚠️  Não há recuperação se a esqueceres.

🔐 Senha Mestre: ████████
    Confirma a senha: ████████

✅  Luany Secrets configurado com sucesso!
    Sessão activa por 1 hora.
```

### 2. Proteger um ficheiro

```bash
lsec lock .env
```

```
🔒  A proteger: .env

✅  Ficheiro protegido:  .env.ls
    Shredding original:  3 passes (padrão DoD)
```

O ficheiro `.env` original é **destruído de forma segura** e substituído por `.env.ls`.

### 3. Editar em modo seguro

```bash
lsec edit .env.ls
```

O ficheiro é decifrado para uma pasta temporária, aberto no editor padrão, e destruído automaticamente quando primes Enter.

### 4. Partilhar com outra pessoa

```bash
lsec share contrato.pdf.ls
```

```
    ┌──────────────────────────────────┐
    │   Token:  LS-A8B9-92F1-C34D   │
    └──────────────────────────────────┘

    1. Envia o ficheiro .ls ao destinatário
    2. Envia o token por canal separado (SMS, WhatsApp)
    3. O destinatário precisa do Luany Secrets instalado
```

---

## Todos os comandos

| Comando | Descrição |
|---------|-----------|
| `lsec init` | Configurar senha mestre na primeira utilização |
| `lsec lock <ficheiro>` | Encriptar e destruir o original |
| `lsec unlock <ficheiro>.ls` | Restaurar o ficheiro original no disco |
| `lsec edit <ficheiro>.ls` | Abrir em modo seguro — tranca ao fechar |
| `lsec share <ficheiro>.ls` | Gerar token de partilha |
| `lsec logout` | Apagar sessão do keychain |
| `lsec status` | Estado da sessão e configuração |

---

## Uso em CI/CD (pipelines automatizados)

Em vez de digitar a senha interactivamente, usa a variável de ambiente:

```bash
# Definir antes de correr o pipeline
export LS_MASTER_PASSWORD="a_tua_senha_mestre"

# O lsec detecta automaticamente e não pede input
lsec unlock config.json.ls

# A senha é apagada do processo após leitura — não fica no histórico
```

> ⚠️ **Nunca passes a senha como argumento:** `lsec unlock --password 1234` expõe a senha no `ps aux` e no histórico do terminal.

---

## Segurança técnica

### Arquitectura criptográfica

```
Senha Mestre
     ↓
[Argon2id]  ← 64MB RAM · 3 iter. · 4 threads · Salt 256-bit por ficheiro
     ↓
MasterKey (AES-256, 32 bytes)
     ↓
[AES-256-GCM]  ← cifra a DEK
     ↓
DEK cifrada  →  Key Slot 1 do cabeçalho .ls
     ↓
DEK em claro  →  [AES-256-GCM]  ←  cifra o corpo do ficheiro
```

### Especificação do formato .ls

```
┌─────────────────────────────────────────────────────────────────┐
│  CABEÇALHO (512 bytes fixos)                                    │
│                                                                  │
│  [LSEC][V][ID Auditoria 32B][Nome 64B][Nonce 12B][Salt 32B]    │
│  [Key Slot 1: 60B][Key Slot 2: 60B][Key Slot 3: 60B]           │
│  [Padding: 187B]                                                 │
├─────────────────────────────────────────────────────────────────┤
│  CORPO (tamanho variável)                                        │
│                                                                  │
│  [Ciphertext AES-256-GCM][Tag GCM 16B]                         │
└─────────────────────────────────────────────────────────────────┘
```

### Propriedades de segurança

| Propriedade | Implementação |
|-------------|---------------|
| Confidencialidade | AES-256-GCM |
| Integridade | Tag GCM 128-bit (detecta qualquer alteração) |
| KDF | Argon2id (resistente a GPU/ASIC) |
| Salt | 256-bit aleatório por ficheiro |
| Nonce | 96-bit aleatório por operação |
| Sessão | Keychain nativo do OS (DPAPI/Keychain/SecretService) |
| RAM | `zeroize` — chaves apagadas após uso |
| Destruição | DoD 5220.22-M (3 passes) |
| Extensibilidade | 3 Key Slots — suporte futuro a partilha por chave pública |

### Aviso sobre SSDs

O shredding lógico (DoD) é efectuado, mas o controlador SSD pode reter dados em blocos físicos devido ao **Wear Leveling**. Para garantia absoluta, activa encriptação de disco completo:

- **Windows:** BitLocker
- **macOS:** FileVault
- **Linux:** LUKS

---

## Estrutura do projecto

```
luany-secrets/
├── Cargo.toml                    # Dependências e configuração
├── README.md
├── SECURITY.md                   # Política de divulgação de vulnerabilidades
├── CONTRIBUTING.md               # Como contribuir
├── LICENSE
├── CHANGELOG.md
│
├── src/
│   ├── main.rs                   # CLI lsec — ponto de entrada
│   │
│   ├── crypto/
│   │   ├── mod.rs
│   │   ├── aes.rs                # Motor AES-256-GCM (DEK + corpo do ficheiro)
│   │   └── kdf.rs                # Derivação de chave Argon2id
│   │
│   ├── storage/
│   │   ├── mod.rs
│   │   ├── binary_format.rs      # Formato binário .ls (cabeçalho 512B)
│   │   └── os_keyring.rs         # Gestão de sessão via keychain do OS
│   │
│   └── utils/
│       ├── mod.rs
│       ├── shredder.rs           # Destruição segura de ficheiros (DoD)
│       └── temp_watcher.rs       # Ficheiros temporários + anti-crash
│
├── scripts/
│   ├── windows/
│   │   └── install_context_menu.reg   # Fase 2: menu clique direito
│   ├── macos/
│   │   └── install.sh                 # Fase 2: Finder extension
│   └── linux/
│       └── install.sh                 # Fase 2: Nautilus extension
│
└── docs/
    ├── ARCHITECTURE.md           # Arquitectura técnica detalhada
    ├── BINARY_FORMAT.md          # Especificação do formato .ls
    └── ROADMAP.md                # Fases de desenvolvimento
```

---

## Roadmap

### ✅ Fase 1 — MVP (actual)
- Motor criptográfico AES-256-GCM + Argon2id
- CLI completa: `init`, `lock`, `unlock`, `edit`, `share`, `logout`, `status`
- Keychain nativo (Windows/macOS/Linux)
- Shredding DoD 5220.22-M
- Gestão de sessões com anti-crash

### 🔄 Fase 2 — Integração com o OS
- Menu de contexto (clique direito) — Windows Explorer e macOS Finder
- Ícone de cadeado personalizado para ficheiros `.ls`
- Monitorização automática de processo (sem ENTER manual)
- Injeção real do token no Key Slot 2 (`lsec share`)

### 📋 Fase 3 — Permissões e Partilha avançada
- Sistema de partilha por chave pública (Key Slot 3)
- Validade configurável de tokens (24h, 7 dias, 1 abertura)
- Revogação de acesso remota

### 🏢 Fase 4 — Plataforma Empresarial
- Dashboard de auditoria
- Gestão centralizada de permissões
- Integração com GitHub/GitLab (detector de `.ls` em commits)
- SDK para programadores

---

## Contribuir

Lê o [CONTRIBUTING.md](CONTRIBUTING.md) antes de abrir um Pull Request.

Para reportar vulnerabilidades de segurança, segue o [SECURITY.md](SECURITY.md).  
**Nunca abras uma issue pública para vulnerabilidades de segurança.**

---

## Licença

MIT — vê [LICENSE](LICENSE) para detalhes.

---

<div align="center">

Desenvolvido com 🔐 por **Luany**  
`AES-256-GCM · Argon2id · Rust`

</div>
