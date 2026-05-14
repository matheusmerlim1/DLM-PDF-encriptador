'use strict';
require('dotenv').config();

const express      = require('express');
const multer       = require('multer');
const crypto       = require('crypto');
const { ethers }   = require('ethers');
const path         = require('path');
const fs           = require('fs');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Chave mestra (nunca exposta ao cliente) ────────────────
if (!process.env.DLM_MASTER_KEY || process.env.DLM_MASTER_KEY.length !== 64) {
  console.error('ERRO: DLM_MASTER_KEY ausente ou inválida no .env');
  console.error('Gere com: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  process.exit(1);
}
const MASTER_KEY = Buffer.from(process.env.DLM_MASTER_KEY, 'hex');

// ── Armazenamento de metadados ─────────────────────────────
const KEYS_DIR  = path.join(__dirname, 'storage', 'keys');
const USERS_FILE = path.join(__dirname, 'storage', 'users.json');
fs.mkdirSync(KEYS_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '{}');

function loadUsers() {
  return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
}
function saveUsers(db) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(db, null, 2));
}

// ── Constantes do formato .dlm v2 ─────────────────────────
const DLM_MAGIC   = Buffer.from([0x44, 0x4C, 0x4D, 0x02]); // "DLM\x02"
const OWNER_LEN   = 42;  // "0x" + 40 hex chars
const HEADER_SIZE = 4 + 8 + OWNER_LEN + 16 + 32;           // 102 bytes

// Janela de validade da assinatura MetaMask (5 minutos)
const SIG_WINDOW_MS = 5 * 60 * 1000;

app.use(express.static(__dirname));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
});

// ── Derivação de chaves via HKDF ───────────────────────────

function deriveAESKey(licenseId, ownerAddress) {
  const info = Buffer.from(`dlm-v2-enc:${licenseId}:${ownerAddress.toLowerCase()}`);
  return crypto.hkdfSync('sha256', MASTER_KEY, Buffer.alloc(32), info, 32);
}

function deriveHMACKey(licenseId, ownerAddress) {
  const info = Buffer.from(`dlm-v2-mac:${licenseId}:${ownerAddress.toLowerCase()}`);
  return crypto.hkdfSync('sha256', MASTER_KEY, Buffer.alloc(32), info, 32);
}

// ── Montagem e parsing do arquivo .dlm ────────────────────

function buildDLM(licenseId, ownerAddress, iv, hmac, ciphertext) {
  const licIdBuf = Buffer.alloc(8);
  licIdBuf.writeBigUInt64BE(BigInt(licenseId));

  const ownerBuf = Buffer.alloc(OWNER_LEN);
  Buffer.from(ownerAddress.toLowerCase()).copy(ownerBuf);

  return Buffer.concat([DLM_MAGIC, licIdBuf, ownerBuf, iv, hmac, ciphertext]);
}

function parseDLMHeader(buf) {
  if (!buf.subarray(0, 4).equals(DLM_MAGIC)) {
    // Detecta formato v1 pelo magic antigo
    if (buf[0] === 0x44 && buf[1] === 0x4C && buf[2] === 0x4D && buf[3] === 0x01) {
      throw new Error('Formato .dlm v1 não suportado. Recrie o arquivo com a versão atual.');
    }
    throw new Error('Arquivo .dlm inválido: magic incorreto.');
  }
  const licenseId    = buf.readBigUInt64BE(4).toString();
  const ownerAddress = buf.subarray(12, 54).toString('ascii').replace(/\0/g, '').trim();
  const iv           = buf.subarray(54, 70);
  const storedHmac   = buf.subarray(70, 102);
  const ciphertext   = buf.subarray(102);
  return { licenseId, ownerAddress, iv, storedHmac, ciphertext };
}

// ── POST /api/users/register ───────────────────────────────

app.use(express.json());

app.post('/api/users/register', (req, res) => {
  try {
    const { username, walletAddress } = req.body;

    if (!username || !walletAddress)
      return res.status(400).json({ error: 'username e walletAddress são obrigatórios' });
    if (!/^[a-zA-Z0-9_]{3,30}$/.test(username))
      return res.status(400).json({ error: 'username deve ter 3-30 caracteres (letras, números, _)' });
    if (!/^0x[0-9a-fA-F]{40}$/.test(walletAddress))
      return res.status(400).json({ error: 'walletAddress inválido' });

    const db = loadUsers();

    if (db[username.toLowerCase()])
      return res.status(409).json({ error: 'Username já em uso' });

    // Verifica se essa wallet já tem outro username
    const existingEntry = Object.values(db).find(
      u => u.walletAddress.toLowerCase() === walletAddress.toLowerCase()
    );
    if (existingEntry)
      return res.status(409).json({ error: `Wallet já registrada como "${existingEntry.username}"` });

    db[username.toLowerCase()] = {
      username,
      walletAddress: walletAddress.toLowerCase(),
      registeredAt: new Date().toISOString(),
    };
    saveUsers(db);

    console.log(`[users] registrado: ${username} → ${walletAddress.slice(0, 10)}...`);
    res.json({ success: true, username, walletAddress: walletAddress.toLowerCase() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/users/lookup/:identifier ─────────────────────
// Busca por username ou por endereço Ethereum

app.get('/api/users/lookup/:identifier', (req, res) => {
  try {
    const id = req.params.identifier.trim();
    const db = loadUsers();

    let entry;

    if (/^0x[0-9a-fA-F]{40}$/.test(id)) {
      // Busca por wallet address
      entry = Object.values(db).find(u => u.walletAddress.toLowerCase() === id.toLowerCase());
    } else {
      // Busca por username
      entry = db[id.toLowerCase()];
    }

    if (!entry) return res.status(404).json({ error: 'Usuário não encontrado' });

    res.json({ username: entry.username, walletAddress: entry.walletAddress });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/encrypt ──────────────────────────────────────

app.post('/api/encrypt', upload.single('pdf'), (req, res) => {
  try {
    const { licenseId, ownerAddress } = req.body;

    if (!req.file)
      return res.status(400).json({ error: 'PDF obrigatório' });
    if (!licenseId || !ownerAddress)
      return res.status(400).json({ error: 'licenseId e ownerAddress são obrigatórios' });
    if (!/^0x[0-9a-fA-F]{40}$/.test(ownerAddress))
      return res.status(400).json({ error: 'ownerAddress inválido (formato: 0x + 40 caracteres hex)' });

    const owner = ownerAddress.toLowerCase();
    const lid   = parseInt(licenseId, 10);

    const aesKey  = deriveAESKey(lid, owner);
    const hmacKey = deriveHMACKey(lid, owner);

    const iv         = crypto.randomBytes(16);
    const cipher     = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
    const ciphertext = Buffer.concat([cipher.update(req.file.buffer), cipher.final()]);

    // HMAC sobre (licenseId || ownerAddr || IV || ciphertext)
    const licIdBuf = Buffer.alloc(8);
    licIdBuf.writeBigUInt64BE(BigInt(lid));
    const hmacData = Buffer.concat([licIdBuf, Buffer.from(owner), iv, ciphertext]);
    const hmac     = crypto.createHmac('sha256', hmacKey).update(hmacData).digest();

    const dlm = buildDLM(lid, owner, iv, hmac, ciphertext);

    // Grava metadados do vínculo dono–licença
    const meta = { licenseId: lid, ownerAddress: owner, createdAt: new Date().toISOString() };
    fs.writeFileSync(path.join(KEYS_DIR, `${lid}.json`), JSON.stringify(meta));

    console.log(`[encrypt] license=${lid} owner=${owner.slice(0, 10)}...`);

    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="license-${lid}.dlm"`);
    res.send(dlm);

  } catch (err) {
    console.error('[encrypt]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/decrypt ──────────────────────────────────────

app.post('/api/decrypt', upload.single('dlm'), async (req, res) => {
  try {
    const { walletAddress, signature, message } = req.body;

    if (!req.file)
      return res.status(400).json({ error: 'Arquivo .dlm obrigatório' });
    if (!walletAddress || !signature || !message)
      return res.status(400).json({ error: 'walletAddress, signature e message são obrigatórios' });

    // 1. Extrai cabeçalho do .dlm
    const { licenseId, ownerAddress, iv, storedHmac, ciphertext } =
      parseDLMHeader(req.file.buffer);

    // 2. Carteira conectada deve ser a dona do arquivo
    if (walletAddress.toLowerCase() !== ownerAddress.toLowerCase()) {
      return res.status(403).json({
        error: `Acesso negado: este arquivo pertence a ${ownerAddress.slice(0, 10)}...${ownerAddress.slice(-6)}`
      });
    }

    // 3. Verifica assinatura MetaMask — prova que o usuário controla a carteira
    let recovered;
    try {
      recovered = ethers.verifyMessage(message, signature);
    } catch {
      return res.status(401).json({ error: 'Assinatura MetaMask inválida' });
    }
    if (recovered.toLowerCase() !== walletAddress.toLowerCase()) {
      return res.status(401).json({ error: 'Assinatura não corresponde à carteira informada' });
    }

    // 4. Valida janela de tempo da assinatura (evita replay attack)
    const tsMatch = message.match(/:(\d+)$/);
    if (!tsMatch || Date.now() - parseInt(tsMatch[1], 10) > SIG_WINDOW_MS) {
      return res.status(401).json({ error: 'Assinatura expirada. Tente novamente.' });
    }

    // 5. Verifica metadados armazenados no servidor
    const metaPath = path.join(KEYS_DIR, `${licenseId}.json`);
    if (fs.existsSync(metaPath)) {
      const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
      if (meta.ownerAddress.toLowerCase() !== walletAddress.toLowerCase()) {
        return res.status(403).json({ error: 'Titularidade inválida' });
      }
    }

    // 6. Recalcula HMAC — detecta adulteração do arquivo
    const aesKey  = deriveAESKey(licenseId, ownerAddress);
    const hmacKey = deriveHMACKey(licenseId, ownerAddress);

    const licIdBuf = Buffer.alloc(8);
    licIdBuf.writeBigUInt64BE(BigInt(licenseId));
    const hmacData = Buffer.concat([licIdBuf, Buffer.from(ownerAddress.toLowerCase()), iv, ciphertext]);
    const computed = crypto.createHmac('sha256', hmacKey).update(hmacData).digest();

    if (!crypto.timingSafeEqual(computed, storedHmac)) {
      return res.status(400).json({ error: 'Verificação HMAC falhou: arquivo corrompido ou adulterado' });
    }

    // 7. Descriptografa na memória — nunca salva em disco
    const decipher   = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
    const pdfBuffer  = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    console.log(`[decrypt] license=${licenseId} owner=${ownerAddress.slice(0, 10)}... OK`);

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('X-DLM-LicenseId', licenseId);
    res.setHeader('X-DLM-Owner', ownerAddress);
    res.send(pdfBuffer);

  } catch (err) {
    console.error('[decrypt]', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`\nDLM-PDF Platform -> http://localhost:${PORT}`);
  console.log(`Chave mestra: ${MASTER_KEY.length * 8}-bit (carregada do .env)\n`);
});
