#!/usr/bin/env node
'use strict';
/**
 * Quackback para Pterodactyl — un único punto de entrada.
 *   1. Carga .env  2. Instala Bun  3. Clona/actualiza el repo  4. bun install + build
 *   5. Arranca Quackback en 127.0.0.1  6. Abre el gateway cifrado en el puerto público
 * Uso: node index.js            (arranque normal)
 *      node index.js --gen-secret
 */
const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');
const { createGateway } = require('./lib/gateway');

if (process.argv.includes('--gen-secret')) {
  console.log(crypto.randomBytes(48).toString('base64url'));
  process.exit(0);
}

const ROOT = __dirname;
const log = (...a) => console.log(new Date().toISOString(), '[quackback]', ...a);

// ---------- .env ----------
const envFile = path.join(ROOT, '.env');
if (fs.existsSync(envFile)) {
  for (const line of fs.readFileSync(envFile, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (!m || line.trim().startsWith('#')) continue;
    if (process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^(['"])(.*)\1$/, '$2');
  }
}
const E = (k, d) => process.env[k] ?? d;

const cfg = {
  repoUrl: E('REPO_URL', 'https://github.com/QuackbackIO/quackback.git'),
  repoRef: E('REPO_REF', 'main'),
  appDir: path.join(ROOT, 'app'),
  appPort: Number(E('APP_PORT', '3000')),
  gatewayPort: Number(E('GATEWAY_PORT', E('SERVER_PORT', E('PORT', '8080')))),
  bunVersion: E('BUN_VERSION', '1.4.0'),
  startCmd: E('START_CMD', 'bun run --cwd apps/web start'),
  autoUpdate: E('AUTO_UPDATE', 'false') === 'true',
  forceBuild: E('FORCE_BUILD', 'false') === 'true',
};

// ---------- validación ----------
const missing = ['DATABASE_URL', 'REDIS_URL', 'SECRET_KEY', 'BASE_URL', 'TUNNEL_SECRET'].filter((k) => !process.env[k]);
if (missing.length) { log('Faltan variables en .env:', missing.join(', ')); process.exit(1); }
if (process.env.SECRET_KEY.length < 32) { log('SECRET_KEY debe tener ≥32 caracteres'); process.exit(1); }
if (process.env.TUNNEL_SECRET.length < 32) { log('TUNNEL_SECRET debe tener ≥32 caracteres'); process.exit(1); }
if (!/^https?:\/\//.test(process.env.BASE_URL)) { log('BASE_URL debe ser una URL absoluta http(s)'); process.exit(1); }

// ---------- helpers ----------
function run(cmd, opts = {}) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, { shell: true, stdio: 'inherit', ...opts, env: { ...process.env, ...(opts.env || {}) } });
    p.on('exit', (c) => (c === 0 ? resolve() : reject(new Error(`"${cmd}" salió con código ${c}`))));
    p.on('error', reject);
  });
}
const capture = (cmd, cwd) => spawnSync(cmd, { shell: true, cwd, encoding: 'utf8' });

async function ensureBun() {
  const sys = capture('bun --version');
  if (sys.status === 0) { log('Bun del sistema:', sys.stdout.trim()); return 'bun'; }
  const rt = path.join(ROOT, '.runtime');
  const bin = path.join(rt, 'node_modules', '.bin', 'bun');
  if (!fs.existsSync(bin)) {
    log(`Instalando Bun ${cfg.bunVersion} (vía npm)…`);
    fs.mkdirSync(rt, { recursive: true });
    await run(`npm install --prefix "${rt}" bun@${cfg.bunVersion} --no-audit --no-fund`);
  }
  if (capture(`"${bin}" --version`).status !== 0) throw new Error('Bun no se pudo ejecutar en este contenedor (¿imagen sin glibc?). Usa una imagen Debian/Ubuntu.');
  return bin;
}

async function ensureRepo() {
  const gitDir = path.join(cfg.appDir, '.git');
  if (!fs.existsSync(gitDir)) {
    log('Clonando', cfg.repoUrl, '…');
    await run(`git clone --depth 1 --branch ${cfg.repoRef} ${cfg.repoUrl} "${cfg.appDir}"`);
  } else if (cfg.autoUpdate) {
    log('Actualizando repo…');
    await run(`git fetch --depth 1 origin ${cfg.repoRef} && git reset --hard FETCH_HEAD`, { cwd: cfg.appDir });
  }
  return capture('git rev-parse HEAD', cfg.appDir).stdout.trim();
}

async function prepare(bun) {
  const sha = await ensureRepo();
  const stamp = path.join(cfg.appDir, '.build-stamp');
  const built = fs.existsSync(stamp) && fs.readFileSync(stamp, 'utf8') === sha;
  if (built && !cfg.forceBuild) { log('Build al día (' + sha.slice(0, 7) + ')'); return; }
  log('Instalando dependencias…');
  await run(`"${bun}" install --frozen-lockfile`, { cwd: cfg.appDir }).catch(() => run(`"${bun}" install`, { cwd: cfg.appDir }));
  log('Compilando (puede tardar y necesita ~2 GB de RAM)…');
  await run(`"${bun}" run build`, { cwd: cfg.appDir, env: { NODE_ENV: 'production' } });
  fs.writeFileSync(stamp, sha);
}

// ---------- proceso de la app ----------
let child = null, stopping = false, crashes = 0;
let useNode = E('RUNTIME', 'bun') === 'node';

// RUNTIME=node: sirve el build con el Node actual (process.execPath). Bun solo se usa para install/build/migraciones.
function resolveStartCmd(bun) {
  if (useNode) {
    if (E('NODE_START_CMD')) return E('NODE_START_CMD');
    const f = ['apps/web/.output/server/index.mjs', 'apps/web/.output/server/index.js', 'apps/web/dist/server/index.mjs']
      .find((c) => fs.existsSync(path.join(cfg.appDir, c)));
    if (f) return `"${process.execPath}" ${f}`;
    log('RUNTIME=node: no encontré salida de build ejecutable con Node; uso Bun.');
    useNode = false;
  }
  return cfg.startCmd.replace(/^bun\b/, `"${bun}"`);
}

function startApp(bun) {
  const cmd = resolveStartCmd(bun);
  log(`Arrancando app (${useNode ? 'Node ' + process.version : 'Bun'}):`, cmd);
  child = spawn(cmd, {
    shell: true, cwd: cfg.appDir, stdio: 'inherit',
    env: {
      ...process.env,
      NODE_ENV: 'production',
      HOST: '127.0.0.1', HOSTNAME: '127.0.0.1', PORT: String(cfg.appPort),
      QUACKBACK_ROLE: E('QUACKBACK_ROLE', 'all'),
      TRUSTED_PROXY_HOPS: '1',          // el gateway local es el único proxy
      CHAT_TRANSPORT_MODE: 'poll',      // Vercel no soporta SSE largo
    },
  });
  const started = Date.now();
  child.on('exit', (code, sig) => {
    if (stopping) return;
    if (useNode && Date.now() - started < 20_000) { log('Falló al arrancar en Node; cambio a Bun.'); useNode = false; }
    crashes = Date.now() - started > 60_000 ? 0 : crashes + 1;
    const wait = Math.min(30, 2 ** crashes);
    log(`App terminó (code=${code} sig=${sig}). Reinicio en ${wait}s`);
    setTimeout(() => startApp(bun), wait * 1000);
  });
}

function waitReady(timeoutMs = 240_000) {
  const end = Date.now() + timeoutMs;
  return new Promise((resolve) => {
    const tick = () => {
      const r = http.get({ host: '127.0.0.1', port: cfg.appPort, path: '/api/health/live', timeout: 2000 }, (res) => {
        res.resume();
        if (res.statusCode === 200) return resolve(true);
        retry();
      });
      r.on('error', retry); r.on('timeout', () => r.destroy());
    };
    const retry = () => (Date.now() > end ? resolve(false) : setTimeout(tick, 2000));
    tick();
  });
}

// ---------- main ----------
(async () => {
  const bun = await ensureBun();
  await prepare(bun);
  startApp(bun);

  const gw = createGateway({
    secret: process.env.TUNNEL_SECRET, appPort: cfg.appPort, log,
    tlsCert: E('TLS_CERT') && path.resolve(ROOT, E('TLS_CERT')),
    tlsKey: E('TLS_KEY') && path.resolve(ROOT, E('TLS_KEY')),
  });
  gw.listen(cfg.gatewayPort, '0.0.0.0', () => log(`Gateway cifrado escuchando en :${cfg.gatewayPort}`));

  log((await waitReady()) ? 'Quackback listo ✔' : 'Quackback aún no responde /api/health/live (revisa los logs)');

  const shutdown = () => { stopping = true; log('Apagando…'); child?.kill('SIGTERM'); gw.close(); setTimeout(() => process.exit(0), 5000).unref(); };
  process.on('SIGTERM', shutdown); process.on('SIGINT', shutdown);
})().catch((e) => { log('ERROR FATAL:', e.message); process.exit(1); });
