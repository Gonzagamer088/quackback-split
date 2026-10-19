'use strict';
// Puerta de entrada pública (puerto de Pterodactyl). Solo atiende POST /__tunnel/v1;
// cualquier otra ruta devuelve 404 vacío, así que la app no es accesible directamente.
const http = require('http');
const https = require('https');
const fs = require('fs');
const { deriveKeys, unpackRequest, packResponse, MAX_SKEW_MS } = require('./tunnel');

const HOP = new Set(['connection', 'keep-alive', 'transfer-encoding', 'te', 'trailer', 'upgrade', 'proxy-authorization', 'proxy-authenticate']);

function createGateway({ secret, appPort, maxBody = 8 * 1024 * 1024, tlsCert, tlsKey, log = console.log }) {
  const keys = deriveKeys(secret);
  const seen = new Map(); // nonce -> expiración (anti-replay)
  setInterval(() => { const n = Date.now(); for (const [k, e] of seen) if (e < n) seen.delete(k); }, 30_000).unref();

  const deny = (res) => { res.writeHead(404, { 'content-length': 0 }); res.end(); };

  function readBody(req, limit) {
    return new Promise((resolve, reject) => {
      const chunks = []; let size = 0;
      req.on('data', (c) => { size += c.length; if (size > limit) { reject(new Error('body grande')); req.destroy(); } else chunks.push(c); });
      req.on('end', () => resolve(Buffer.concat(chunks)));
      req.on('error', reject);
    });
  }

  function callApp(meta, body) {
    return new Promise((resolve, reject) => {
      const headers = {};
      for (const [k, v] of Object.entries(meta.headers || {})) if (!HOP.has(k.toLowerCase()) && k.toLowerCase() !== 'content-length') headers[k] = v;
      headers['x-forwarded-proto'] = 'https';
      if (meta.ip) headers['x-forwarded-for'] = meta.ip;
      if (body.length) headers['content-length'] = body.length;
      const r = http.request({ host: '127.0.0.1', port: appPort, method: meta.method, path: meta.path, headers, timeout: 60_000 }, (up) => {
        const chunks = []; let size = 0;
        up.on('data', (c) => { size += c.length; if (size > maxBody * 4) { up.destroy(new Error('respuesta grande')); } else chunks.push(c); });
        up.on('end', () => resolve({ status: up.statusCode, headers: up.headers, body: Buffer.concat(chunks) }));
        up.on('error', reject);
      });
      r.on('timeout', () => r.destroy(new Error('timeout app')));
      r.on('error', reject);
      r.end(body);
    });
  }

  const handler = async (req, res) => {
    if (req.method !== 'POST' || req.url !== '/__tunnel/v1') return deny(res);
    let parsed;
    try {
      parsed = unpackRequest(keys, await readBody(req, maxBody + 65536));
    } catch { return deny(res); } // clave incorrecta / manipulado / caducado
    const nonceHex = parsed.nonce.toString('hex');
    if (seen.has(nonceHex)) return deny(res); // replay
    seen.set(nonceHex, Date.now() + MAX_SKEW_MS * 2);

    let out;
    try {
      const r = await callApp(parsed.meta, parsed.body);
      out = packResponse(keys, parsed.nonce, { status: r.status, headers: r.headers }, r.body);
    } catch (e) {
      log('[gateway] error app:', e.message);
      out = packResponse(keys, parsed.nonce, { status: 502, headers: { 'content-type': 'text/plain' } }, Buffer.from('Bad gateway'));
    }
    res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': out.length, 'cache-control': 'no-store' });
    res.end(out);
  };

  if (tlsCert && tlsKey) return https.createServer({ cert: fs.readFileSync(tlsCert), key: fs.readFileSync(tlsKey) }, handler);
  return http.createServer(handler);
}

module.exports = { createGateway };
