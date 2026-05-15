/**
 * js/crypto.js
 * Utilitários de parsing do formato .dlm e funções de display.
 * Toda a criptografia/descriptografia acontece no servidor (server.js).
 *
 * Formato do arquivo .dlm v2:
 * ┌──────────────────────────────────────────────────────────┐
 * │ MAGIC       4B  : "DLM\x02"                             │
 * │ licenseId   8B  : uint64 big-endian                      │
 * │ ownerAddr  42B  : endereço Ethereum em ASCII ("0x...")   │
 * │ IV         16B  : vetor de inicialização AES             │
 * │ HMAC       32B  : HMAC-SHA-256 de integridade            │
 * │ ciphertext  NB  : conteúdo AES-256-CBC                   │
 * └──────────────────────────────────────────────────────────┘
 */

'use strict';

const DLM_MAGIC_V2 = [0x44, 0x4C, 0x4D, 0x02]; // "DLM\x02"
const DLM_MAGIC_V3 = [0x44, 0x4C, 0x4D, 0x03]; // "DLM\x03"

function hexToBytes(hex) {
  return new Uint8Array(hex.match(/.{2}/g).map(h => parseInt(h, 16)));
}

function bytesToHex(buf, len) {
  const arr = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Array.from(len ? arr.slice(0, len) : arr)
    .map(b => b.toString(16).padStart(2, '0'))
    .join(' ');
}

function randomBytes(n) {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

async function sha256(buf) {
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Lê o cabeçalho de um arquivo .dlm (v1 ou v2) sem descriptografar.
 * @param {ArrayBuffer} dlmBuffer
 * @returns {{ version: number, licenseId: string, ownerAddress: string|null }}
 */
function readDLMHeader(dlmBuffer) {
  const bytes = new Uint8Array(dlmBuffer);
  const isV1  = bytes[0] === 0x44 && bytes[1] === 0x4C && bytes[2] === 0x4D && bytes[3] === 0x01;
  const isV2  = bytes[0] === 0x44 && bytes[1] === 0x4C && bytes[2] === 0x4D && bytes[3] === 0x02;
  const isV3  = bytes[0] === 0x44 && bytes[1] === 0x4C && bytes[2] === 0x4D && bytes[3] === 0x03;

  if (!isV1 && !isV2 && !isV3) throw new Error('Arquivo .dlm inválido: formato não reconhecido.');

  const view      = new DataView(dlmBuffer);
  const licenseId = view.getBigUint64(4, false).toString();

  if (isV1) return { version: 1, licenseId, ownerAddress: null };

  // v2 e v3 têm ownerAddr nos bytes 12–54
  const ownerAddress = new TextDecoder('ascii').decode(bytes.slice(12, 54)).replace(/\0/g, '').trim();
  return { version: isV3 ? 3 : 2, licenseId, ownerAddress };
}

/**
 * Converte ArrayBuffer para string base64 sem estourar a call stack.
 * btoa(String.fromCharCode(...bytes)) falha com arquivos > ~1 MB.
 */
function bufToBase64(buf) {
  const bytes = new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i += 8192) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192));
  }
  return btoa(binary);
}

window.DLMCrypto = {
  DLM_MAGIC_V2,
  DLM_MAGIC_V3,
  hexToBytes,
  bytesToHex,
  randomBytes,
  sha256,
  readDLMHeader,
  readLicenseId: readDLMHeader,
  bufToBase64,
};
