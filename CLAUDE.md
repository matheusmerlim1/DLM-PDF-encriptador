# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"  # Gerar DLM_MASTER_KEY
cp .env.example .env   # Preencher DLM_MASTER_KEY no .env
npm install            # Instalar dependências
npm start              # Servidor na porta 3000
```

## Arquitetura

```
Browser (index.html)
    ↕ fetch (FormData)
server.js  →  /api/encrypt  (recebe PDF, retorna .dlm)
           →  /api/decrypt  (recebe .dlm + assinatura MetaMask, retorna PDF)
           →  /api/users/*  (registro e lookup de usernames)
```

O frontend é **HTML + Vanilla JS puro**. Cada módulo em `js/`:

| Arquivo | Responsabilidade |
|---------|-----------------|
| `js/crypto.js` | Parsing do cabeçalho .dlm, helpers (sha256, bufToBase64, bytesToHex) |
| `js/ui.js` | Toasts, steps, progress bar, drag-and-drop, tabs |
| `js/publisher.js` | Fluxo de criptografia (PDF → .dlm via servidor) |
| `js/reader.js` | Fluxo de leitura (.dlm → PDF via MetaMask + servidor) |
| `js/main.js` | Ponto de entrada, inicializa módulos |

### Formato do arquivo .dlm v2

```
MAGIC      4B  : "DLM\x02"
licenseId  8B  : uint64 big-endian
ownerAddr 42B  : endereço Ethereum ASCII ("0x...")
IV        16B  : vetor de inicialização AES
HMAC      32B  : HMAC-SHA-256 de integridade
ciphertext NB  : PDF cifrado AES-256-CBC
```

### Segurança do servidor (`server.js`)

- Chave mestra: `DLM_MASTER_KEY` (32 bytes, só no `.env`, nunca exposta)
- Derivação: HKDF-SHA-256 por (licenseId, ownerAddress) — chave diferente por licença
- Descriptografia exige: assinatura MetaMask válida + janela de 5 min + HMAC correto + ownership no header

## Repositório

**Repositório:** `https://github.com/matheusmerlim1/DLM-PDF-encriptador`

**Não commitar:** `.env`, `storage/`

## Claude Code Skills

| Skill | Quando usar |
|-------|------------|
| `/security-review` | Antes de qualquer PR tocando crypto, server.js ou autenticação |
| `/review` | Revisão geral de código |
| `/update-config` | Alterar hooks ou permissões |

## Regra de Commit

**Sempre que houver qualquer alteração no projeto, realizar o commit imediatamente após a mudança.**
Não acumular alterações sem commitar. Cada conjunto de mudanças relacionadas deve ter seu próprio commit descritivo antes de continuar.
