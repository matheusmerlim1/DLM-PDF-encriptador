/**
 * __tests__/encrypt.route.test.js
 *
 * Regressão: publisher.js enviava `ownerAddress` mas a rota POST /api/encrypt
 * espera `publicKey` + `userName` + `userCPF`. Qualquer campo faltando → 400.
 *
 * Bug corrigido em 2026-05-15: publisher.js atualizado para enviar os campos corretos.
 */

process.env.DRM_API_URL    = 'http://localhost:9999'; // URL inválida — não deve ser chamada
process.env.DLM_MASTER_KEY = '0'.repeat(64);

const request = require('supertest');
const app     = require('../server');

const VALID_ADDRESS = '0xaabbccddEEff0011223344556677889900112233';
const VALID_PDF     = Buffer.from('%PDF-1.4 fake content');

function buildForm(overrides = {}) {
  return {
    publicKey: VALID_ADDRESS,
    userName:  'Maria Silva',
    userCPF:   '12345678901',
    ...overrides,
  };
}

describe('POST /api/encrypt — validação de campos (regressão bug 2026-05-15)', () => {

  test('rejeita 400 quando publicKey ausente (ex-bug: campo era ownerAddress)', async () => {
    const resp = await request(app)
      .post('/api/encrypt')
      .field('userName', 'Maria Silva')
      .field('userCPF',  '12345678901')
      .attach('pdf', VALID_PDF, 'test.pdf');
    expect(resp.status).toBe(400);
    expect(resp.body.error).toMatch(/obrigatório/i);
  });

  test('rejeita 400 quando ownerAddress é enviado no lugar de publicKey', async () => {
    const resp = await request(app)
      .post('/api/encrypt')
      .field('ownerAddress', VALID_ADDRESS)   // campo antigo (bug)
      .field('userName',     'Maria Silva')
      .field('userCPF',      '12345678901')
      .attach('pdf', VALID_PDF, 'test.pdf');
    expect(resp.status).toBe(400);
    expect(resp.body.error).toMatch(/obrigatório/i);
  });

  test('rejeita 400 quando userName ausente', async () => {
    const resp = await request(app)
      .post('/api/encrypt')
      .field('publicKey', VALID_ADDRESS)
      .field('userCPF',   '12345678901')
      .attach('pdf', VALID_PDF, 'test.pdf');
    expect(resp.status).toBe(400);
    expect(resp.body.error).toMatch(/obrigatório/i);
  });

  test('rejeita 400 quando userCPF ausente', async () => {
    const resp = await request(app)
      .post('/api/encrypt')
      .field('publicKey', VALID_ADDRESS)
      .field('userName',  'Maria Silva')
      .attach('pdf', VALID_PDF, 'test.pdf');
    expect(resp.status).toBe(400);
    expect(resp.body.error).toMatch(/obrigatório/i);
  });

  test('rejeita 400 quando publicKey não é endereço Ethereum válido', async () => {
    const resp = await request(app)
      .post('/api/encrypt')
      .field('publicKey', '0xINVALID')
      .field('userName',  'Maria Silva')
      .field('userCPF',   '12345678901')
      .attach('pdf', VALID_PDF, 'test.pdf');
    expect(resp.status).toBe(400);
    expect(resp.body.error).toMatch(/inválido/i);
  });

  test('rejeita 400 quando PDF não é enviado', async () => {
    const resp = await request(app)
      .post('/api/encrypt')
      .field('publicKey', VALID_ADDRESS)
      .field('userName',  'Maria Silva')
      .field('userCPF',   '12345678901');
    expect(resp.status).toBe(400);
    expect(resp.body.error).toMatch(/pdf/i);
  });
});
