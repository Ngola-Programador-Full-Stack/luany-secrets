# Arquitectura Técnica — Luany Secrets

## Visão geral

O Luany Secrets é um **File Security Middleware** — uma camada entre o sistema de ficheiros e o utilizador que adiciona semântica de segurança ao nível do ficheiro individual.

```
Sistema de Ficheiros (cego semanticamente)
              ↓
    ┌─────────────────────┐
    │   Motor Luany (lsec) │  ← intercepta operações de ficheiro
    │   AES-256-GCM        │
    │   Argon2id           │
    │   Key Slots          │
    └─────────────────────┘
              ↓
    Utilizador autenticado
```

## Camadas do sistema

```
┌─────────────────────────────────────────────────────┐
│  Camada 1 — Interface                               │
│  CLI (lsec) via clap                                │
│  Fase 2: Context Menu (Windows/macOS/Linux)         │
├─────────────────────────────────────────────────────┤
│  Camada 2 — Motor Core                              │
│  src/crypto/aes.rs    — AES-256-GCM                │
│  src/crypto/kdf.rs    — Argon2id                   │
│  src/storage/         — Formato .ls + Keychain      │
├─────────────────────────────────────────────────────┤
│  Camada 3 — Utilitários                             │
│  src/utils/shredder.rs      — DoD 5220.22-M        │
│  src/utils/temp_watcher.rs  — Sessões temporárias  │
└─────────────────────────────────────────────────────┘
```

## Fluxo de lock (lsec lock .env)

```
1. Ler ficheiro original (.env)
2. Gerar salt aleatório 256-bit          [OsRng]
3. Gerar nonce principal 96-bit          [OsRng]
4. Gerar DEK aleatória 256-bit           [OsRng]
5. Ler/pedir senha mestre                [kdf::read_password]
6. Derivar MasterKey via Argon2id        [kdf::derive_master_key]
7. Cifrar DEK com MasterKey              [aes::encrypt_dek]  → Key Slot 1
8. Cifrar corpo do ficheiro com DEK      [aes::encrypt_file_body]
9. Montar cabeçalho 512 bytes            [binary_format::serialize]
10. Escrever .env.ls = cabeçalho + corpo
11. Destruir .env original               [shredder::shred_file]
12. Apagar chaves da RAM                 [zeroize automático]
```

## Fluxo de unlock/edit (lsec edit .env.ls)

```
1. Ler cabeçalho 512 bytes               [binary_format::deserialize]
2. Validar assinatura LSEC + versão
3. Extrair salt e nonce principal
4. Ler/pedir senha mestre                [kdf::read_password / keychain]
5. Derivar MasterKey via Argon2id        [kdf::derive_master_key]
6. Decifrar DEK do Key Slot 1            [aes::decrypt_dek]
7. Decifrar corpo do ficheiro            [aes::decrypt_file_body]
8. Apagar MasterKey e DEK da RAM         [zeroize]
9. Escrever temporário                   [temp_watcher::open_and_watch]
10. Apagar plaintext da RAM              [zeroize]
11. Registar sessão                      [.lsec_sessions.json]
12. Abrir com aplicação padrão           [open::that]
13. Aguardar Enter
14. Destruir temporário                  [shredder::shred_file]
15. Limpar registo de sessão
```

## Formato binário do ficheiro .ls

Ver [BINARY_FORMAT.md](BINARY_FORMAT.md) para especificação completa.

## Modelo de ameaça

| Ameaça | Mitigação |
|--------|-----------|
| Roubo do disco/computador | AES-256-GCM — ficheiro ilegível sem senha |
| Envio acidental por email/cloud | Conteúdo cifrado — ilegível sem lsec + senha |
| Ataque de força bruta à senha | Argon2id — 64MB RAM por tentativa |
| Adulteração do ficheiro .ls | Tag GCM — detectada no decrypt |
| Fuga de chave na RAM | zeroize em todos os tipos sensíveis |
| Ficheiro temporário exposto | temp_watcher + shredder + anti-crash |
| Senha visível no histórico | Variável de ambiente, não argumento |
| Sessão roubada do keychain | Timeout 1h + keychain do OS (DPAPI/Keychain) |

## Decisões de design

**Porquê Envelope Encryption (DEK separada)?**  
Se a senha mestre for alterada, apenas os 60 bytes do Key Slot precisam de ser re-cifrados — o corpo do ficheiro (potencialmente GBs) não é tocado. Padrão usado pelo Google KMS e AWS KMS.

**Porquê 3 Key Slots?**  
Slot 1: acesso local. Slot 2: partilha por token. Slot 3: reservado para Fase 2 (chave pública). O cabeçalho de 512 bytes acomoda os 3 slots e mantém padding para expansão futura sem quebrar ficheiros existentes.

**Porquê ENTER manual no `lsec edit`?**  
Monitorizar automaticamente quando o processo filho fecha é complexo e platform-specific (Excel reutiliza instâncias existentes). O ENTER manual é previsível e correcto. Fase 2 implementará monitorização de PID nativa.

**Porquê não Cloud/servidor no MVP?**  
Valida o produto sem custos de infraestrutura. O formato `.ls` já suporta o Slot 3 para migração futura para modelo híbrido (chave pública) sem quebrar compatibilidade.
