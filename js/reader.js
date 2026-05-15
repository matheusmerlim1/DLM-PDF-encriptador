/**
 * js/reader.js
 *
 * Fluxo de abertura de .dlm — suporta dois formatos:
 *
 *  v2 (DLM\x02) — gerado pelo DML-PDF encriptador:
 *    1. Carrega .dlm → lê ownerAddress do cabeçalho
 *    2. Conecta MetaMask → verifica address == ownerAddress
 *    3. Assina mensagem com MetaMask (prova de posse real)
 *    4. POST /api/decrypt no servidor local → recebe PDF
 *    5. Renderiza PDF
 *
 *  v3 (DLM\x03) — gerado pela DRM API (APIDLM.encrypt):
 *    1. Carrega .dlm → lê licenseId e ownerAddress do cabeçalho
 *    2. Conecta MetaMask → verifica address == ownerAddress
 *    3. Assina mensagem "DLM:decrypt:<licenseId>:<timestamp>"
 *    4. POST /decrypt na DLM PDF API → recebe PDF + novo .dlm re-cifrado
 *    5. Renderiza PDF
 *
 *  v1 (DLM\x01) — gerado pela Livraria DLM / DLM PDF API:
 *    1. Carrega .dlm → lê licenseId do cabeçalho
 *    2. Conecta MetaMask
 *    3. Autentica na DLM PDF API (challenge → signature → JWT)
 *    4. POST /licenses/:id/read com dlmBase64 → recebe PDF
 *    5. Renderiza PDF
 *
 *  Demo mode: completamente bloqueado para ambos os formatos.
 */

'use strict';

let walletAddr    = null;
let readDLMBuffer = null;
let fileVersion   = null;   // 1 ou 2
let fileOwnerAddr = null;
let fileLicenseId = null;

// URL da DLM PDF API (usada para arquivos v1)
const DLM_API_BASE = window.DLM_API_BASE || 'https://dlm-pdf-server-production.up.railway.app/api/v1';

function initReader() {
  document.getElementById('btn-connect').addEventListener('click', connectMetaMask);
  UI.setupDrop('read-drop', 'read-file', '.dlm', handleDLMLoad);
  document.getElementById('btn-open').addEventListener('click', handleOpen);
}

// ── Conexão de Carteira ───────────────────────────────────

async function connectMetaMask() {
  // Tenta obter o provider via window.ethereum (injeção clássica) ou
  // via EIP-6963 (padrão moderno que MetaMask 11+ usa em domínios novos).
  // Aguarda até 3s porque GitHub Pages pode demorar a liberar a injeção.
  let provider = window.ethereum || await new Promise(resolve => {
    const timer = setTimeout(() => resolve(window.ethereum || null), 3000);
    window.addEventListener('eip6963:announceProvider', e => {
      clearTimeout(timer);
      resolve(e.detail.provider);
    }, { once: true });
    window.dispatchEvent(new Event('eip6963:requestProvider'));
  });

  if (!provider) {
    UI.toast(
      'MetaMask não encontrado. Verifique: (1) extensão instalada em metamask.io, ' +
      '(2) MetaMask habilitado para este site no ícone da extensão, ' +
      '(3) recarregue a página após habilitar.',
      'err', 9000
    );
    return;
  }

  try {
    const accounts = await provider.request({ method: 'eth_requestAccounts' });
    if (!accounts || accounts.length === 0) {
      UI.toast('Nenhuma conta encontrada. Desbloqueie o MetaMask e tente novamente.', 'err');
      return;
    }
    walletAddr = accounts[0].toLowerCase();
    showWallet();
    UI.toast('Carteira MetaMask conectada!', 'ok');
  } catch (err) {
    if (err.code === 4001) {
      UI.toast('Conexão recusada. Clique em "Conectar" no MetaMask quando solicitado.', 'err');
    } else {
      UI.toast('Erro ao conectar MetaMask: ' + (err.message || err), 'err');
    }
  }
}


function showWallet() {
  const badge = document.getElementById('wallet-badge');
  badge.style.display = 'flex';
  document.getElementById('wallet-addr').textContent =
    walletAddr.slice(0, 8) + '...' + walletAddr.slice(-6);
  checkOpenReady();
}

// ── Carregamento do .dlm ──────────────────────────────────

async function handleDLMLoad(file) {
  readDLMBuffer = await file.arrayBuffer();

  document.getElementById('read-fname').textContent = file.name;
  document.getElementById('read-chip').style.display = 'flex';

  try {
    const { licenseId, ownerAddress, version } = DLMCrypto.readDLMHeader(readDLMBuffer);
    fileLicenseId = licenseId;
    fileOwnerAddr = ownerAddress;
    fileVersion   = version;

    document.getElementById('read-licid').value = licenseId;

    const ownerField = document.getElementById('read-owner');
    if (ownerField) {
      ownerField.value = ownerAddress
        ? ownerAddress
        : '(não vinculado — formato v1, validado pela blockchain)';
    }

    UI.setStep('rstep-1', 'done');
    UI.setStep('rstep-2', 'done');
    UI.toast(`Arquivo .dlm v${version} carregado — License #${licenseId}`, 'ok');
  } catch (err) {
    UI.toast('Arquivo inválido: ' + err.message, 'err');
    readDLMBuffer = null;
    fileOwnerAddr = null;
    fileLicenseId = null;
    fileVersion   = null;
    document.getElementById('read-chip').style.display = 'none';
    return;
  }

  checkOpenReady();
}

function checkOpenReady() {
  const btn = document.getElementById('btn-open');

  if (!walletAddr || !readDLMBuffer) { btn.disabled = true; return; }

  // v2 e v3: verifica que carteira conectada é a dona do arquivo
  if (fileVersion === 2 || fileVersion === 3) {
    if (!fileOwnerAddr) {
      btn.disabled = true;
      UI.toast(`Arquivo .dlm v${fileVersion} sem endereço de proprietário — arquivo corrompido.`, 'err');
      return;
    }
    if (walletAddr.toLowerCase() !== fileOwnerAddr.toLowerCase()) {
      btn.disabled = true;
      UI.toast(
        `Acesso negado: este arquivo pertence a ${fileOwnerAddr.slice(0, 8)}...${fileOwnerAddr.slice(-6)}`,
        'err'
      );
      return;
    }
  }

  btn.disabled = false;
}

// ── Abertura do arquivo ───────────────────────────────────

async function handleOpen() {
  const btn = document.getElementById('btn-open');
  btn.disabled  = true;
  btn.innerHTML = '<span class="spin"></span> Validando...';
  UI.resetProgress('read-prog');

  try {
    if (fileVersion === 3) {
      await openV3();
    } else if (fileVersion === 2) {
      await openV2();
    } else {
      await openV1();
    }
  } catch (err) {
    ['rstep-3', 'rstep-4', 'rstep-5', 'rstep-6'].forEach(s => UI.setStep(s, 'fail'));
    UI.toast('Erro: ' + err.message, 'err');
  }

  btn.innerHTML = '🔓 Abrir e-book';
  btn.disabled  = false;
}

// ── V3: DLM PDF API com cadeia de custódia ────────────────

async function openV3() {
  // Step 3: Assina mensagem com MetaMask (prova de posse da carteira)
  UI.setStep('rstep-3', 'active');
  UI.setProgress('read-prog', 20);

  const timestamp = Date.now();
  const message   = `DLM:decrypt:${fileLicenseId}:${timestamp}`;
  const signature = await window.ethereum.request({
    method: 'personal_sign',
    params: [message, walletAddr],
  });
  UI.setStep('rstep-3', 'done');

  // Step 4: Envia para a DLM PDF API → verifica licenseRegistry + descriptografa
  UI.setStep('rstep-4', 'active');
  UI.setProgress('read-prog', 50);

  const dlmBase64 = DLMCrypto.bufToBase64(readDLMBuffer);
  const resp = await fetch(`${DLM_API_BASE}/decrypt`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      dlmBase64,
      publicKey: walletAddr,
      signature,
      message,
    }),
  });

  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    throw new Error(err.error || 'Acesso negado pela API DRM.');
  }
  UI.setStep('rstep-4', 'done');

  // Step 5: Decodifica PDF recebido
  UI.setStep('rstep-5', 'active');
  UI.setProgress('read-prog', 75);

  const { pdfBase64 } = await resp.json();
  const pdfBuffer = Uint8Array.from(atob(pdfBase64), c => c.charCodeAt(0)).buffer;
  UI.setStep('rstep-5', 'done');

  await finishOpen(pdfBuffer, fileLicenseId, walletAddr);
}

// ── V2: servidor local (encriptador próprio) ──────────────

async function openV2() {
  // Step 3: Assinatura MetaMask real
  UI.setStep('rstep-3', 'active');
  UI.setProgress('read-prog', 20);

  const message   = `DLM-Decrypt:${fileLicenseId}:${walletAddr}:${Date.now()}`;
  const signature = await window.ethereum.request({
    method: 'personal_sign',
    params: [message, walletAddr],
  });
  UI.setStep('rstep-3', 'done');

  // Step 4: Verifica titularidade no servidor local
  UI.setStep('rstep-4', 'active');
  UI.setProgress('read-prog', 45);

  const formData = new FormData();
  formData.append('dlm', new Blob([readDLMBuffer]), 'file.dlm');
  formData.append('walletAddress', walletAddr);
  formData.append('signature', signature);
  formData.append('message', message);

  const resp = await fetch('/api/decrypt', { method: 'POST', body: formData });
  if (!resp.ok) {
    const err = await resp.json();
    throw new Error(err.error || 'Acesso negado pelo servidor');
  }
  UI.setStep('rstep-4', 'done');

  // Step 5: Recebe PDF
  UI.setStep('rstep-5', 'active');
  UI.setProgress('read-prog', 68);
  const pdfBuffer = await resp.arrayBuffer();
  UI.setStep('rstep-5', 'done');

  await finishOpen(pdfBuffer, fileLicenseId, walletAddr);
}

// ── V1: DLM PDF API (Livraria DLM) ───────────────────────

async function openV1() {
  // Step 3: Autentica na DLM PDF API via MetaMask
  UI.setStep('rstep-3', 'active');
  UI.setProgress('read-prog', 15);

  // 3a. Solicita desafio
  const challengeResp = await fetch(
    `${DLM_API_BASE}/auth/challenge?address=${encodeURIComponent(walletAddr)}`
  );
  if (!challengeResp.ok) throw new Error('Falha ao obter desafio de autenticação da API.');
  const { message: challengeMsg } = await challengeResp.json();

  // 3b. Assina com MetaMask
  const signature = await window.ethereum.request({
    method: 'personal_sign',
    params: [challengeMsg, walletAddr],
  });

  // 3c. Login na DLM PDF API → JWT
  const loginResp = await fetch(`${DLM_API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ address: walletAddr, message: challengeMsg, signature }),
  });
  if (!loginResp.ok) {
    const err = await loginResp.json();
    throw new Error(err.error || 'Falha na autenticação na DLM PDF API.');
  }
  const { token } = await loginResp.json();
  UI.setStep('rstep-3', 'done');

  // Step 4: Envia .dlm para a DLM PDF API → verifica posse on-chain + descriptografa
  UI.setStep('rstep-4', 'active');
  UI.setProgress('read-prog', 50);

  const dlmBase64 = DLMCrypto.bufToBase64(readDLMBuffer);
  const readResp  = await fetch(`${DLM_API_BASE}/licenses/${fileLicenseId}/read`, {
    method: 'POST',
    headers: {
      'Content-Type':  'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify({ dlmBase64 }),
  });

  if (readResp.status === 403) {
    const err = await readResp.json();
    throw new Error(err.error || 'Acesso negado pela blockchain.');
  }
  if (!readResp.ok) throw new Error('Falha ao ler licença na API.');

  UI.setStep('rstep-4', 'done');

  // Step 5: Decodifica PDF recebido
  UI.setStep('rstep-5', 'active');
  UI.setProgress('read-prog', 75);

  const { pdfBase64 } = await readResp.json();
  const pdfBuffer = Uint8Array.from(atob(pdfBase64), c => c.charCodeAt(0)).buffer;

  UI.setStep('rstep-5', 'done');

  await finishOpen(pdfBuffer, fileLicenseId, walletAddr);
}

// ── Finalização comum ─────────────────────────────────────

async function finishOpen(pdfBuffer, licenseId, owner) {
  UI.setStep('rstep-6', 'active');
  UI.setProgress('read-prog', 85);
  await renderPDF(pdfBuffer);
  UI.setStep('rstep-6', 'done');
  UI.setProgress('read-prog', 100);
  showLicenseInfo(licenseId, owner);
  UI.toast('E-book aberto com sucesso!', 'ok');
}

// ── Renderização PDF ──────────────────────────────────────

async function renderPDF(pdfBuffer) {
  const container = document.getElementById('pdf-pages');
  container.innerHTML = '';
  document.getElementById('read-empty').style.display   = 'none';
  document.getElementById('read-toolbar').style.display = 'flex';

  const pdf   = await pdfjsLib.getDocument({ data: pdfBuffer }).promise;
  const total = pdf.numPages;
  document.getElementById('read-pageinfo').textContent =
    `${total} página${total > 1 ? 's' : ''}`;

  for (let n = 1; n <= total; n++) {
    const page     = await pdf.getPage(n);
    const viewport = page.getViewport({ scale: 1.4 });
    const canvas   = document.createElement('canvas');
    canvas.width   = viewport.width;
    canvas.height  = viewport.height;
    container.appendChild(canvas);
    await page.render({ canvasContext: canvas.getContext('2d'), viewport }).promise;
  }
}

function showLicenseInfo(licenseId, owner) {
  const card = document.getElementById('read-info');
  card.style.display = 'block';
  document.getElementById('ri-id').textContent    = licenseId;
  document.getElementById('ri-owner').textContent = owner.slice(0, 10) + '...' + owner.slice(-6);
  document.getElementById('ri-access').textContent = 'CONCEDIDO';
  document.getElementById('ri-tx').textContent     = 'assinatura MetaMask verificada';
  document.getElementById('ri-hmac').textContent   = 'VALIDO';
}

window.Reader = { initReader };
