# Roadmap — Luany Secrets

## Fase 1 — MVP ✅ (actual)

**Objectivo:** provar o conceito e validar com devs e power users.

- [x] Motor criptográfico AES-256-GCM
- [x] Argon2id com parâmetros OWASP 2024
- [x] Formato binário .ls extensível (3 Key Slots)
- [x] CLI: init, lock, unlock, edit, share, logout, status
- [x] Keychain nativo (Windows/macOS/Linux)
- [x] Shredding DoD 5220.22-M
- [x] Anti-crash de sessões temporárias
- [x] Suporte CI/CD (LS_MASTER_PASSWORD)
- [x] Documentação completa

## Fase 2 — Integração com o OS 🔄

**Objectivo:** tornar o produto acessível ao público empresarial (sem terminal).

- [ ] Menu de contexto Windows (clique direito → Proteger/Desproteger)
- [ ] Finder Extension macOS
- [ ] Nautilus Extension Linux
- [ ] Ícone de cadeado personalizado para ficheiros .ls
- [ ] Monitorização automática de PID (sem ENTER manual no `lsec edit`)
- [ ] Injeção real do token no Key Slot 2 (`lsec share`)
- [ ] Detecção de SSD nativa (Windows DeviceIoControl / macOS IOKit)
- [ ] Instalador único (.exe Windows, .dmg macOS, .deb/.rpm Linux)
- [ ] Script de instalação via curl (devs)

## Fase 3 — Permissões avançadas 📋

**Objectivo:** partilha segura sem copiar e colar chaves manualmente.

- [ ] Partilha por chave pública (Key Slot 3)
- [ ] Validade configurável de tokens (24h, 7 dias, 1 abertura)
- [ ] Revogação de acesso remotamente
- [ ] Servidor leve de troca de chaves públicas (zero-knowledge)
- [ ] Modo offline: Token manual continua a funcionar
- [ ] Notificação de abertura por terceiros

## Fase 4 — Plataforma empresarial 🏢

**Objectivo:** mercado B2B — empresas com equipas.

- [ ] Dashboard de auditoria (quem abriu, quando, de onde)
- [ ] Gestão centralizada de permissões
- [ ] Políticas de expiração automática
- [ ] Integração GitHub/GitLab (detectar .ls em PRs)
- [ ] SDK para programadores (Rust/Python/Node)
- [ ] SSO (Single Sign-On) empresarial
- [ ] Modelo de pricing: Free / Pro / Enterprise
