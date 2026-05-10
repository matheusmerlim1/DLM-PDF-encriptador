# DLM-PDF Platform

Interface web para o sistema de custódia digital de e-books via Blockchain.

## Estrutura de arquivos

```
dlm-platform/
│
├── index.html          # Estrutura HTML pura — sem estilos ou scripts inline
│
├── css/
│   └── style.css       # Toda a estilização visual da plataforma
│
├── js/
│   ├── crypto.js       # Lógica criptográfica (AES-256-CBC, HKDF, HMAC, SHA-256)
│   ├── ui.js           # Utilitários de interface (toast, steps, dropzone, tabs)
│   ├── publisher.js    # Aba da editora: criptografar PDF → gerar .dlm
│   ├── reader.js       # Aba do leitor: validar posse + decifrar .dlm + renderizar PDF
│   └── main.js         # Ponto de entrada: inicializa todos os módulos
│
└── README.md
```

## Responsabilidade de cada arquivo

| Arquivo | Responsabilidade |
|---|---|
| `index.html` | Estrutura semântica do HTML. Apenas marcação, sem lógica. |
| `css/style.css` | Variáveis CSS, reset, layout, componentes visuais, animações. |
| `js/crypto.js` | Formato `.dlm`, cifragem AES-256-CBC, derivação HKDF, HMAC, SHA-256. Expõe `window.DLMCrypto`. |
| `js/ui.js` | Toast, setStep, setProgress, setupDrop, initTabs, delay. Expõe `window.UI`. |
| `js/publisher.js` | Fluxo completo da aba Editora. Depende de `DLMCrypto` e `UI`. Expõe `window.Publisher`. |
| `js/reader.js` | Fluxo completo da aba Leitor. Depende de `DLMCrypto`, `UI` e `pdfjsLib`. Expõe `window.Reader`. |
| `js/main.js` | Ponto de entrada. Configura PDF.js worker e inicializa todos os módulos. |

## Como usar

Basta abrir `index.html` em um navegador moderno (Chrome, Firefox, Edge).

> **Não é necessário servidor** — toda a criptografia ocorre no navegador via Web Crypto API.

### Fluxo completo

1. **Aba Editora**: arraste um PDF → defina License ID → clique em "Gerar .dlm" → baixe o arquivo
2. **Aba Leitor**: conecte carteira (ou simule) → arraste o `.dlm` → clique em "Abrir e-book"

## Dependências externas (CDN)

- [PDF.js 3.11.174](https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js) — renderização de PDF
- [Google Fonts](https://fonts.google.com) — Space Mono, Syne, DM Sans

## Criptografia implementada

```
PDF original
    │
    ▼  HKDF-SHA-256(masterKey, licenseId) → chave AES-256
    │
    ▼  AES-256-CBC(chave, IV aleatório)
    │
    ▼  HMAC-SHA-256(chave, licenseId || IV || ciphertext)
    │
    ▼
[MAGIC 4B][licenseId 8B][IV 16B][HMAC 32B][ciphertext NB]
                          arquivo .dlm
```
