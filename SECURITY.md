# Política de Segurança — Luany Secrets

## Versões suportadas

| Versão | Suporte de segurança |
|--------|----------------------|
| 0.1.x  | ✅ Activa            |

## Reportar uma vulnerabilidade

**Nunca abras uma issue pública GitHub para vulnerabilidades de segurança.**

Envia o relatório para: **security@luanysecrets.com**

Inclui:
- Descrição detalhada da vulnerabilidade
- Passos para reproduzir
- Impacto estimado
- Sugestão de correcção (se tiveres)

### O que podes esperar

- **Confirmação de recepção:** até 48 horas
- **Avaliação inicial:** até 7 dias
- **Correcção e release:** até 90 dias (dependendo da gravidade)
- **Crédito público:** o teu nome no CHANGELOG.md (se quiseres)

## Âmbito

Vulnerabilidades em âmbito:
- Motor criptográfico (`src/crypto/`)
- Formato binário `.ls` (`src/storage/binary_format.rs`)
- Gestão de keychain (`src/storage/os_keyring.rs`)
- Fugas de dados sensíveis em memória RAM

Fora do âmbito:
- Ataques que exigem acesso físico ao dispositivo desbloqueado
- Ataques de força bruta à senha mestre (por design — usa Argon2id)
- Limitações do Wear Leveling em SSDs (documentadas e conhecidas)
