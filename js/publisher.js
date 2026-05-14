/**
 * js/publisher.js
 * Criptografa PDF enviando ao servidor (/api/encrypt).
 * O servidor deriva as chaves, cifra com AES-256-CBC e retorna o .dlm.
 */

'use strict';

let pubPdfBuffer   = null;
let pubDLMBuffer   = null;
let pubContentHash = '';

function initPublisher() {
  UI.setupDrop('pub-drop', 'pub-file', '.pdf', handlePDFLoad);
  document.getElementById('btn-encrypt').addEventListener('click', handleEncrypt);
  document.getElementById('btn-download').addEventListener('click', handleDownload);
  document.getElementById('btn-copy-hash').addEventListener('click', () => {
    UI.copyToClipboard(pubContentHash, 'Hash SHA-256 copiado!');
  });

  // Botão para buscar wallet por username
  const btnLookup = document.getElementById('btn-lookup-owner');
  if (btnLookup) btnLookup.addEventListener('click', handleLookupOwner);
}

async function handlePDFLoad(file) {
  pubPdfBuffer = await file.arrayBuffer();

  document.getElementById('pub-fname').textContent = file.name;
  document.getElementById('pub-chip').style.display = 'flex';
  document.getElementById('btn-encrypt').disabled = false;

  UI.setStep('pstep-1', 'done');
  pubContentHash = await DLMCrypto.sha256(pubPdfBuffer);
  UI.toast(`PDF carregado: ${file.name}`, 'ok');
}

async function handleLookupOwner() {
  const val = document.getElementById('pub-owner').value.trim();
  if (!val) { UI.toast('Digite um nome de usuário para buscar.', 'err'); return; }

  try {
    const resp = await fetch(`/api/users/lookup/${encodeURIComponent(val)}`);
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Usuário não encontrado');
    document.getElementById('pub-owner').value = data.walletAddress;
    UI.toast(`Wallet de "${data.username}" carregada.`, 'ok');
  } catch (err) {
    UI.toast('Erro: ' + err.message, 'err');
  }
}

async function handleEncrypt() {
  if (!pubPdfBuffer) return;

  const licenseId    = document.getElementById('pub-licid').value.trim() || '1';
  const ownerAddress = document.getElementById('pub-owner').value.trim();

  if (!/^0x[0-9a-fA-F]{40}$/.test(ownerAddress)) {
    UI.toast('Endereço do proprietário inválido. Informe uma carteira Ethereum (0x...) ou use "Buscar username".', 'err');
    return;
  }

  const btn = document.getElementById('btn-encrypt');
  btn.disabled  = true;
  btn.innerHTML = '<span class="spin"></span> Cifrando...';

  UI.resetProgress('pub-prog');
  document.getElementById('pub-result').style.display = 'none';

  try {
    // Step 2: envia para o servidor criptografar
    UI.setStep('pstep-2', 'active');
    UI.setProgress('pub-prog', 20);

    const formData = new FormData();
    formData.append('pdf', new Blob([pubPdfBuffer], { type: 'application/pdf' }), 'file.pdf');
    formData.append('licenseId', licenseId);
    formData.append('ownerAddress', ownerAddress);

    const resp = await fetch('/api/encrypt', { method: 'POST', body: formData });
    if (!resp.ok) {
      const err = await resp.json();
      throw new Error(err.error || 'Erro no servidor');
    }

    UI.setStep('pstep-2', 'done');
    UI.setStep('pstep-3', 'active');
    UI.setProgress('pub-prog', 55);

    pubDLMBuffer = await resp.arrayBuffer();

    UI.setStep('pstep-3', 'done');
    UI.setStep('pstep-4', 'active');
    UI.setProgress('pub-prog', 80);
    UI.setStep('pstep-4', 'done');
    UI.setStep('pstep-5', 'active');
    UI.setProgress('pub-prog', 100);
    UI.setStep('pstep-5', 'done');

    await showEncryptResult(licenseId, ownerAddress);
    UI.toast('Arquivo .dlm gerado com sucesso!', 'ok');

  } catch (err) {
    UI.toast('Erro na cifragem: ' + err.message, 'err');
    ['pstep-2', 'pstep-3', 'pstep-4', 'pstep-5'].forEach(s => UI.setStep(s, 'fail'));
  }

  btn.innerHTML = '🔒 Gerar arquivo .dlm';
  btn.disabled  = false;
}

async function showEncryptResult(licenseId, ownerAddress) {
  const dlmHash = await DLMCrypto.sha256(pubDLMBuffer);
  const title   = document.getElementById('pub-title').value || '(sem título)';

  document.getElementById('pub-result').style.display = 'block';
  document.getElementById('pub-hash-display').innerHTML =
    `<span style="color:var(--muted)">SHA-256 do .dlm gerado:</span><br>${dlmHash}<br><br>` +
    `<span style="color:var(--muted)">SHA-256 do PDF original:</span><br>${pubContentHash}`;

  document.getElementById('pub-empty').style.display   = 'none';
  document.getElementById('pub-preview').style.display = 'flex';

  document.getElementById('pub-tech-view').innerHTML = `
    <div style="margin-bottom:.6rem;color:var(--text)">
      📦 <strong>${title}</strong> — License #${licenseId}
    </div>
    <div style="color:var(--muted)">
      Proprietário:
      <span style="color:var(--cyan)">${ownerAddress.slice(0, 10)}...${ownerAddress.slice(-6)}</span>
    </div>
    <div style="color:var(--muted);margin-top:.4rem">
      Tamanho .dlm:
      <span style="color:var(--cyan)">${(pubDLMBuffer.byteLength / 1024).toFixed(1)} KB</span>
    </div>
    <div style="color:var(--muted);margin-top:.4rem">
      🔑 Chave AES: <span style="color:var(--green)">armazenada no servidor (não exposta)</span>
    </div>
  `;

  const hexStr = DLMCrypto.bytesToHex(pubDLMBuffer, 128);
  document.getElementById('pub-hex').textContent = hexStr.match(/.{1,47}/g).join('\n');
}

function handleDownload() {
  if (!pubDLMBuffer) return;

  const title = (document.getElementById('pub-title').value || 'ebook').replace(/\s+/g, '-');
  const licId = document.getElementById('pub-licid').value || '1';
  const fname = `${title}-license${licId}.dlm`;

  const blob = new Blob([pubDLMBuffer], { type: 'application/octet-stream' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = fname;
  a.click();
  URL.revokeObjectURL(url);

  UI.toast(`Download iniciado: ${fname}`, 'ok');
}

window.Publisher = { initPublisher };
