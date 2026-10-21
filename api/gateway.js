'use strict';
// Función de Vercel: recibe TODO el tráfico del navegador, lo cifra y lo envía al origen.
const http = require('http');
const https = require('https');
const { deriveKeys, packRequest, unpackResponse } = require('./_tunnel');

const ORIGIN = process.env.ORIGIN_URL;       // p.ej. http://203.0.113.10:25565
const SECRET = process.env.TUNNEL_SECRET;
const ALLOW_SELF_SIGNED = process.env.ORIGIN_ALLOW_SELF_SIGNED === 'true';
const CACHE_RE = new RegExp(process.env.IMMUTABLE_PATH_REGEX || '^/assets/');
const MAX_BODY = 4 * 1024 * 1024; // límite de Vercel ≈ 4.5 MB

const DROP_REQ = new Set(['host', 'connection', 'keep-alive', 'transfer-encoding', 'te', 'trailer', 'upgrade', 'content-length', 'accept-encoding', 'proxy-authorization']);
const DROP_RES = new Set(['connection', 'keep-alive', 'transfer-encoding', 'content-length', 'content-encoding', 'te', 'trailer', 'upgrade']);

let keys;
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', (c) => { size += c.length; if (size > MAX_BODY) { reject(new Error('too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function post(url, body) {
  const u = new URL(url);
  const lib = u.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    const r = lib.request({
      hostname: u.hostname, port: u.port || undefined, path: u.pathname, method: 'POST', timeout: 28_000,
      rejectUnauthorized: !ALLOW_SELF_SIGNED,
      headers: { 'content-type': 'application/octet-stream', 'content-length': body.length },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
    });
    r.on('timeout', () => r.destroy(new Error('timeout')));
    r.on('error', reject);
    r.end(body);
  });
}

function resolvePath(req) {
  // Soporta que Vercel conserve la URL original o que la reescriba a /api/gateway?__p=...
  const u = new URL(req.url, 'http://local');
  let p = u.searchParams.get('__p');
  if (p !== null) {
    u.searchParams.delete('__p');
    // searchParams.get() decodifica (%20 -> espacio): volvemos a codificar para que la ruta sea válida
    p = encodeURI(p).replace(/\?/g, '%3F').replace(/#/g, '%23');
  } else p = u.pathname === '/api/gateway' ? '/' : u.pathname;
  return { u, path: (p.startsWith('/') ? p : '/' + p) + (u.search || '') };
}

async function diag(req, res, u) {
  const out = { ok: false, reqUrl: req.url, host: req.headers.host, hasOriginUrl: !!ORIGIN, hasTunnelSecret: !!SECRET };
  try {
    keys = keys || deriveKeys(SECRET);
    const t0 = Date.now();
    const { nonce, frame } = packRequest(keys, { method: 'GET', path: '/api/health/live', headers: { host: req.headers.host }, ip: '' }, Buffer.alloc(0));
    const r = await post(ORIGIN.replace(/\/$/, '') + '/__tunnel/v1', frame);
    out.tunnelHttpStatus = r.status;
    if (r.status === 200) { const m = unpackResponse(keys, nonce, r.body).meta; out.appHealthStatus = m.status; out.ok = m.status === 200; }
    out.ms = Date.now() - t0;
  } catch (e) { out.error = e.message; }
  res.statusCode = 200;
  res.setHeader('content-type', 'application/json');
  res.setHeader('cache-control', 'no-store');
  res.end(JSON.stringify(out, null, 2));
}

module.exports = async (req, res) => {
  const t0 = Date.now();
  let path = '?';
  try {
    if (!ORIGIN || !SECRET) { res.statusCode = 500; return res.end('Faltan ORIGIN_URL / TUNNEL_SECRET'); }
    keys = keys || deriveKeys(SECRET);

    const rp = resolvePath(req);
    if (rp.u.searchParams.has('__diag')) return await diag(req, res, rp.u);
    path = rp.path;

    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) {
      const l = k.toLowerCase();
      if (DROP_REQ.has(l) || l.startsWith('x-vercel-') || l.startsWith('x-forwarded-') || l === 'x-real-ip') continue;
      headers[l] = v;
    }
    headers.host = req.headers.host;       // el dominio público de Vercel (= BASE_URL)
    headers['accept-encoding'] = 'identity';
    const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();

    const body = ['GET', 'HEAD'].includes(req.method) ? Buffer.alloc(0) : await readBody(req);
    const { nonce, frame } = packRequest(keys, { method: req.method, path, headers, ip }, body);

    const r = await post(ORIGIN.replace(/\/$/, '') + '/__tunnel/v1', frame);
    if (r.status !== 200) { console.log(JSON.stringify({ m: req.method, path, tunnel: r.status, ms: Date.now() - t0 })); res.statusCode = 502; return res.end('Origin rejected the tunnel request'); }
    const { meta, body: out } = unpackResponse(keys, nonce, r.body);

    res.statusCode = meta.status;
    for (const [k, v] of Object.entries(meta.headers || {})) if (!DROP_RES.has(k.toLowerCase())) res.setHeader(k, v);
    if (meta.status === 200 && CACHE_RE.test(path.split('?')[0])) res.setHeader('cache-control', 'public, max-age=31536000, s-maxage=31536000, immutable');
    res.setHeader('content-length', out.length);
    console.log(JSON.stringify({ m: req.method, path, status: meta.status, ms: Date.now() - t0 }));
    res.end(req.method === 'HEAD' ? undefined : out);
  } catch (e) {
    console.error(JSON.stringify({ m: req.method, path, error: e.message, ms: Date.now() - t0 }));
    res.statusCode = e.message === 'too large' ? 413 : 502;
    res.end(res.statusCode === 413 ? 'Payload too large' : 'Bad gateway');
  }
};
