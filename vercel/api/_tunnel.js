'use strict';
// Protocolo de túnel cifrado (AES-256-GCM). Idéntico en backend y vercel.
// Petición : [1 ver][8 ts ms][16 nonce][12 iv][ciphertext][16 tag]   AAD = ver+ts+nonce
// Respuesta: [1 ver][12 iv][ciphertext][16 tag]                      AAD = nonce de la petición
// Claves distintas para petición/respuesta (HKDF) -> sin ataques de reflexión.
const crypto = require('crypto');

const VERSION = 1;
const MAX_SKEW_MS = 60_000;

function deriveKeys(secret) {
  if (!secret || secret.length < 32) throw new Error('TUNNEL_SECRET debe tener al menos 32 caracteres');
  const ikm = Buffer.from(secret, 'utf8');
  const salt = Buffer.from('quackback-tunnel-v1');
  return {
    req: Buffer.from(crypto.hkdfSync('sha256', ikm, salt, 'request', 32)),
    res: Buffer.from(crypto.hkdfSync('sha256', ikm, salt, 'response', 32)),
  };
}

function seal(key, plaintext, aad) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(aad);
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return Buffer.concat([iv, ct, c.getAuthTag()]);
}

function open(key, blob, aad) {
  if (blob.length < 28) throw new Error('frame corto');
  const d = crypto.createDecipheriv('aes-256-gcm', key, blob.subarray(0, 12));
  d.setAAD(aad);
  d.setAuthTag(blob.subarray(blob.length - 16));
  return Buffer.concat([d.update(blob.subarray(12, blob.length - 16)), d.final()]);
}

// payload = [4 bytes len meta][meta JSON][body crudo]
function encodePayload(meta, body) {
  const m = Buffer.from(JSON.stringify(meta));
  const len = Buffer.alloc(4);
  len.writeUInt32BE(m.length);
  return Buffer.concat([len, m, body || Buffer.alloc(0)]);
}
function decodePayload(buf) {
  const n = buf.readUInt32BE(0);
  return { meta: JSON.parse(buf.subarray(4, 4 + n).toString()), body: buf.subarray(4 + n) };
}

function packRequest(keys, meta, body) {
  const ts = Buffer.alloc(8);
  ts.writeBigUInt64BE(BigInt(Date.now()));
  const nonce = crypto.randomBytes(16);
  const head = Buffer.concat([Buffer.from([VERSION]), ts, nonce]);
  return { nonce, frame: Buffer.concat([head, seal(keys.req, encodePayload(meta, body), head)]) };
}

function unpackRequest(keys, frame) {
  if (frame.length < 25 + 28 || frame[0] !== VERSION) throw new Error('frame inválido');
  const head = frame.subarray(0, 25);
  const ts = Number(head.readBigUInt64BE(1));
  if (Math.abs(Date.now() - ts) > MAX_SKEW_MS) throw new Error('timestamp fuera de rango');
  const plain = open(keys.req, frame.subarray(25), head); // lanza si la clave/AAD no cuadran
  return { nonce: head.subarray(9, 25), ...decodePayload(plain) };
}

function packResponse(keys, nonce, meta, body) {
  return Buffer.concat([Buffer.from([VERSION]), seal(keys.res, encodePayload(meta, body), nonce)]);
}

function unpackResponse(keys, nonce, frame) {
  if (frame[0] !== VERSION) throw new Error('versión inválida');
  return decodePayload(open(keys.res, frame.subarray(1), nonce));
}

module.exports = { deriveKeys, packRequest, unpackRequest, packResponse, unpackResponse, MAX_SKEW_MS };
