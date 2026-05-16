/**
 * js/main.js
 * Ponto de entrada do DLM-PDF Leitor (descriptografador).
 *
 * Ordem de carregamento:
 *  1. pdf.min.js (CDN)
 *  2. crypto.js  → window.DLMCrypto
 *  3. ui.js      → window.UI
 *  4. reader.js  → window.Reader
 *  5. main.js    (este arquivo — último)
 */

'use strict';

pdfjsLib.GlobalWorkerOptions.workerSrc =
  'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';

document.addEventListener('DOMContentLoaded', () => {
  Reader.initReader();
  console.log('[DLM-PDF] Leitor inicializado.');
});
