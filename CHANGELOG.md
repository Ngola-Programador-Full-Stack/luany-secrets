# Changelog — Luany Secrets

Todas as alterações notáveis são documentadas aqui.  
Formato: [Semantic Versioning](https://semver.org/lang/pt-BR/)

---

## [0.1.0] — MVP — em desenvolvimento

### Adicionado
- Motor criptográfico AES-256-GCM com Envelope Encryption (DEK por ficheiro)
- Derivação de chave Argon2id (64MB RAM, 3 iterações, 4 threads — OWASP 2024)
- Formato binário `.ls` com cabeçalho de 512 bytes e 3 Key Slots extensíveis
- CLI completa: `init`, `lock`, `unlock`, `edit`, `share`, `logout`, `status`
- Gestão de sessão via keychain nativo (Windows Credential Manager / macOS Keychain / SecretService)
- Shredding DoD 5220.22-M (3 passes) com aviso honesto sobre SSDs
- Sistema anti-crash de ficheiros temporários (`.lsec_sessions.json`)
- Suporte a CI/CD via variável de ambiente `LS_MASTER_PASSWORD`
- Protecção de memória RAM via `zeroize` em todas as operações com chaves

### Segurança
- Salt de 256 bits único por ficheiro (impede ataques de rainbow table)
- Nonce de 96 bits único por operação (impede reutilização de nonce)
- Tag GCM de 128 bits (autenticação — detecta qualquer adulteração)
- Timeout de sessão de 1 hora (keychain)
- Senha nunca aparece em argumentos de linha de comandos

### Conhecido / Pendente (Fase 2)
- `lsec share` gera token mas não o injeta ainda no Key Slot 2
- `lsec edit` requer ENTER manual em vez de monitorização automática de processo
- Menu de contexto (clique direito) não incluído no MVP
- Detecção de SSD apenas por heurística no Windows/macOS
