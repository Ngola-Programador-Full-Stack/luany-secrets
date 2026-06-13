# Como Contribuir — Luany Secrets

Obrigado pelo interesse em contribuir! Este documento explica o processo.

## Antes de começar

1. Lê o [README.md](README.md) e o [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
2. Verifica se já existe uma issue para o que queres fazer
3. Para mudanças grandes, abre uma issue primeiro para discutir

## Setup de desenvolvimento

```bash
git clone https://github.com/luany/luany-secrets.git
cd luany-secrets

# Instalar dependências e compilar
cargo build

# Correr os testes
cargo test

# Verificar warnings e lints
cargo clippy -- -D warnings

# Verificar formatação
cargo fmt --check
```

## Processo de contribuição

1. Fork do repositório
2. Cria uma branch: `git checkout -b feat/descricao-curta`
3. Faz as alterações com testes
4. Garante que `cargo test`, `cargo clippy` e `cargo fmt` passam
5. Commit com mensagem clara (ver abaixo)
6. Abre um Pull Request

## Convenção de commits

```
tipo(âmbito): descrição curta em português

Exemplos:
feat(crypto): adicionar suporte a ChaCha20-Poly1305
fix(shredder): corrigir detecção de SSD em Linux
docs(readme): actualizar secção de instalação
security(kdf): aumentar iterações Argon2id para OWASP 2025
```

Tipos: `feat`, `fix`, `docs`, `security`, `refactor`, `test`, `chore`

## Regras para código de segurança

- **Obrigatório:** usar `Zeroizing<>` para qualquer variável que contenha chave, senha ou DEK
- **Obrigatório:** não usar `unwrap()` em código de produção — usar `?` ou mensagens de erro claras
- **Obrigatório:** qualquer novo campo no cabeçalho `.ls` deve manter compatibilidade com ficheiros existentes
- **Recomendado:** adicionar comentário explicando decisões criptográficas não óbvias

## O que precisamos agora (Fase 2)

- [ ] Menu de contexto Windows (`.reg` + Rust handler)
- [ ] Finder Extension macOS
- [ ] Monitorização de PID para `temp_watcher` (sem ENTER manual)
- [ ] Injeção real de token no Key Slot 2
- [ ] Testes de integração para o fluxo `lock → unlock`
- [ ] Detecção de SSD nativa no Windows e macOS

## Código de conduta

Respeito mútuo. Foco técnico. Sem spam.
