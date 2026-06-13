# Especificação do Formato Binário .ls

Versão do formato: **1**

## Layout completo (512 bytes de cabeçalho)

```
Offset   Bytes   Campo                        Notas
──────   ─────   ─────                        ─────
0        4       Assinatura mágica            [0x4C,0x53,0x45,0x43] = "LSEC"
4        1       Versão do formato            Actualmente: 0x01
5        32      ID de auditoria              SHA256(hostname) — apenas metadata
37       64      Nome original do ficheiro    UTF-8, padding com \0
101      12      Nonce principal AES-GCM      96-bit aleatório por operação
113      32      Salt Argon2id                256-bit aleatório por ficheiro
145      60      Key Slot 1 (local)           DEK cifrada com MasterKey
205      60      Key Slot 2 (partilha)        DEK cifrada com Token (Fase 2)
265      60      Key Slot 3 (reservado)       Chave pública — Fase 2
325      187     Padding                      Zeros — expansão futura
──────   ─────
Total    512
```

## Key Slot (60 bytes)

```
Offset   Bytes   Campo
──────   ─────   ─────
0        32      DEK cifrada (AES-256-GCM ciphertext)
32       12      Nonce da operação de cifragem da DEK
44       16      Tag GCM (autenticação e integridade)
──────   ─────
Total    60
```

## Corpo (após o cabeçalho)

```
[Ciphertext AES-256-GCM do ficheiro original] + [Tag GCM 16B]
```

Tamanho = tamanho_original + 16 bytes (tag GCM)

## Verificação de integridade

1. Ler bytes 0-3: deve ser `LSEC`
2. Ler byte 4: deve ser a versão suportada pelo software
3. Decifrar Key Slot 1 com a MasterKey → se falhar, senha incorrecta
4. Decifrar corpo com a DEK → se falhar, ficheiro corrompido

## Compatibilidade futura

O padding de 187 bytes e o Key Slot 3 reservado garantem que versões futuras do formato podem adicionar campos sem quebrar ficheiros existentes. A versão no byte 4 permite que o software recuse graciosamente formatos mais novos.

## Exemplo de ficheiro .ls (hexdump)

```
00000000: 4c53 4543 0100 0000 0000 0000 0000 0000  LSEC............
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000020: 0000 0000 0000 0000 632e 656e 7600 0000  ........c.env...
         [assinatura][ver][id auditoria...][.env\0\0\0...]
```
