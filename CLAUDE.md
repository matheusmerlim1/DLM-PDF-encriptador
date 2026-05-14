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

## Features Planejadas (não implementar sem ordem explícita)

### Transferência de posse do arquivo .dlm

Hoje o `.dlm` é criptografado para um dono fixo (ownerAddress no header). Transferir para outra pessoa exige re-encriptação pelo servidor. O fluxo planejado é:

1. **Livraria DLM lista todos os livros em posse do usuário MetaMask** — ao fazer login, buscar todos os tokens do contrato ERC-721 que pertencem ao endereço conectado e exibir na biblioteca.

2. **Cadastro de nome na Livraria DLM** — ao entrar com MetaMask, solicitar que o usuário informe seu nome completo. Armazenar na blockchain (`registerUser(username)`) ou em banco local vinculado ao endereço. O nome é necessário para identificar o destinatário na transferência.

3. **Transferência exige nome completo do destinatário** — ao transferir um livro, o remetente informa a chave pública (endereço Ethereum) do destinatário; o sistema busca e exibe o **nome cadastrado** desse endereço para confirmação antes de prosseguir. Só transfere com confirmação explícita do nome.

4. **Re-encriptação automática na transferência** — ao transferir, o servidor gera um novo `.dlm` criptografado com o endereço do novo dono (nova chave HKDF derivada do novo ownerAddress). O arquivo antigo (do remetente) é invalidado. O novo `.dlm` é baixado automaticamente pelo remetente para ser entregue ao destinatário.

5. **DLM-PDF Platform verifica cadeia de custódia** — ao tentar abrir um `.dlm` cujo `ownerAddress` não corresponde à carteira conectada, o sistema consulta o servidor/blockchain para verificar se houve transferência registrada. Se sim, oferece opção de re-encriptar o arquivo para o novo dono atual antes de abrir. Se não, nega acesso.

6. **Fluxo completo de transferência**:
   - Remetente: abre a Livraria DLM → seleciona livro → clica "Transferir" → informa endereço do destinatário → sistema exibe nome cadastrado → confirma → servidor re-encripta → download do novo `.dlm` → transfere o NFT na blockchain → entrega o arquivo ao destinatário
   - Destinatário: recebe o `.dlm` → abre no DLM-PDF Platform → conecta MetaMask → sistema verifica `ownerAddress` no header == endereço atual → libera leitura

**Dependências técnicas**:
- `server.js`: nova rota `POST /api/reencrypt` (recebe .dlm atual + novo ownerAddress, valida assinatura do dono atual, re-encripta, retorna novo .dlm)
- `server.js`: nova rota `GET /api/users/:address` para buscar nome pelo endereço
- `Livraria DLM / pages/biblioteca.html`: listar tokens ERC-721 via `contract.userTokens(address)`
- `Livraria DLM / pages/auth.html`: solicitar e salvar nome no cadastro
- `DLMBookstore.sol`: função `getUserByAddress(address)` retornando username
