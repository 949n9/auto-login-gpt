import http from 'node:http';
import https from 'node:https';
import { createHash, randomBytes } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isIP } from 'node:net';

const COOKIE = '__Host-tosub2_session';
const LOGGED_OUT_COOKIE = '__Host-tosub2_logged_out';
const BODY_LIMIT = 8192;
const SESSION_MS = 12 * 60 * 60 * 1000;
const REMEMBER_MS = 30 * 24 * 60 * 60 * 1000;
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const CSP = "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
const digest = value => createHash('sha256').update(value).digest('hex');
const json = value => JSON.stringify(value);

function integer(value, fallback, minimum, maximum) {
  const number = value === undefined ? fallback : Number(value);
  if (!Number.isSafeInteger(number) || number < minimum || number > maximum) throw new Error('Invalid numeric configuration');
  return number;
}

function configuration(options) {
  const env = options.env ?? process.env;
  const publicOrigin = options.publicOrigin ?? env.PUBLIC_ORIGIN;
  const verifyUrl = options.verifyUrl ?? env.AUTH_VERIFY_URL;
  const passwordFile = options.passwordFile ?? env.AUTH_PASSWORD_FILE;
  const stateDir = options.stateDir ?? env.AUTH_STATE_DIR;
  if (![publicOrigin, verifyUrl, passwordFile, stateDir].every(v => typeof v === 'string' && v.length)) {
    throw new Error('Required authentication configuration is missing');
  }
  const origin = new URL(publicOrigin);
  const insecure = options.allowInsecureLoopback === true || env.AUTH_ALLOW_INSECURE_LOOPBACK === 'true';
  if (origin.origin !== publicOrigin || origin.username || origin.password ||
      (origin.protocol !== 'https:' && !(insecure && origin.protocol === 'http:' &&
        ['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname)))) throw new Error('PUBLIC_ORIGIN must be HTTPS');
  const target = new URL(verifyUrl);
  if (!['http:', 'https:'].includes(target.protocol) || target.username || target.password || target.hash) {
    throw new Error('Invalid verification URL');
  }
  if (!path.isAbsolute(passwordFile) || !path.isAbsolute(stateDir)) throw new Error('Authentication paths must be absolute');
  return {
    publicOrigin, target, passwordFile, stateDir,
    staticDir: path.resolve(options.staticDir ?? env.AUTH_STATIC_DIR ?? fileURLToPath(new URL('./public/', import.meta.url))),
    clock: options.clock ?? Date.now,
    timeoutMs: integer(options.timeoutMs ?? env.AUTH_TIMEOUT_MS, 5000, 10, 5000),
    rateWindowMs: integer(options.rateWindowMs ?? env.AUTH_RATE_WINDOW_MS, 60000, 1, 3600000),
    rateIpMax: integer(options.rateIpMax ?? env.AUTH_RATE_IP_MAX, 10, 1, 10000),
    rateGlobalMax: integer(options.rateGlobalMax ?? env.AUTH_RATE_GLOBAL_MAX, 100, 1, 100000),
    maxSessions: integer(options.maxSessions ?? env.AUTH_MAX_SESSIONS, 1000, 1, 1000),
    maxUserSessions: integer(options.maxUserSessions ?? env.AUTH_MAX_USER_SESSIONS, 20, 1, 20),
    trustProxy: options.trustProxy === true || env.AUTH_TRUST_PROXY === 'true',
  };
}

async function passwordRevision(config) {
  const stat = await fs.stat(config.passwordFile);
  if (!stat.isFile() || stat.size === 0 || stat.size > 1048576) throw new Error('Invalid credential file');
  return digest(await fs.readFile(config.passwordFile));
}

function cookieToken(req) {
  const matches = (req.headers.cookie ?? '').split(';').map(v => v.trim()).filter(v => v.startsWith(`${COOKIE}=`));
  if (matches.length !== 1) return null;
  const token = matches[0].slice(COOKIE.length + 1);
  return /^[a-f0-9]{64}$/.test(token) ? token : null;
}

function cookie(token, remember = false, clear = false) {
  return `${COOKIE}=${token}; Path=/; Secure; HttpOnly; SameSite=Lax${clear ? '; Max-Age=0' : remember ? `; Max-Age=${REMEMBER_MS / 1000}` : ''}`;
}

function loggedOutCookie(clear = false) {
  return `${LOGGED_OUT_COOKIE}=${clear ? '' : '1'}; Path=/; Secure; HttpOnly; SameSite=Lax${clear ? '; Max-Age=0' : ''}`;
}

function credentials(username, password) {
  return typeof username === 'string' && typeof password === 'string' && username.length > 0 && username.length <= 256 &&
    password.length > 0 && password.length <= 4096 && !/[:\u0000-\u001f\u007f]/.test(username) && !/[\u0000-\u001f\u007f]/.test(password);
}

function basicCredentials(header) {
  if (typeof header !== 'string' || !/^Basic [A-Za-z0-9+/]+={0,2}$/i.test(header) || header.length > BODY_LIMIT) return null;
  const encoded = header.slice(6);
  const buffer = Buffer.from(encoded, 'base64');
  if (buffer.toString('base64') !== encoded) return null;
  let decoded;
  try { decoded = new TextDecoder('utf-8', { fatal: true }).decode(buffer); } catch { return null; }
  const colon = decoded.indexOf(':');
  if (colon < 1) return null;
  const username = decoded.slice(0, colon), password = decoded.slice(colon + 1);
  return credentials(username, password) ? { username, password } : null;
}

function verifyCredentials(config, username, password) {
  return new Promise((resolve, reject) => {
    const transport = config.target.protocol === 'https:' ? https : http;
    const request = transport.request(config.target, {
      method: 'GET', headers: { Authorization: `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}` },
    }, response => {
      clearTimeout(timer);
      response.destroy();
      if (response.statusCode === 200 || response.statusCode === 204) resolve(true);
      else if (response.statusCode === 401 || response.statusCode === 403) resolve(false);
      else reject(new Error('Credential verifier unavailable'));
    });
    const timer = setTimeout(() => request.destroy(new Error('Credential verifier timeout')), config.timeoutMs);
    request.on('error', () => { clearTimeout(timer); reject(new Error('Credential verifier unavailable')); });
    request.end();
  });
}

function readBody(req, timeoutMs) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    const finish = (error, body) => {
      clearTimeout(timer);
      req.off('data', data); req.off('end', end); req.off('error', aborted); req.off('aborted', aborted);
      if (error) { req.pause(); reject(error); } else resolve(body);
    };
    const fail = status => Object.assign(new Error('Invalid request body'), { status });
    const data = chunk => { size += chunk.length; if (size > BODY_LIMIT) finish(fail(413)); else chunks.push(chunk); };
    const end = () => finish(null, Buffer.concat(chunks));
    const aborted = () => finish(fail(400));
    const timer = setTimeout(() => finish(fail(408)), timeoutMs);
    req.on('data', data); req.on('end', end); req.on('error', aborted); req.on('aborted', aborted);
    if (Number(req.headers['content-length']) > BODY_LIMIT) finish(fail(413));
  });
}

function parseForm(bytes) {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const result = Object.create(null);
  for (const pair of text.split('&')) {
    const equal = pair.indexOf('=');
    if (equal < 1) throw new Error('Malformed form');
    const key = decodeURIComponent(pair.slice(0, equal).replace(/\+/g, ' '));
    const value = decodeURIComponent(pair.slice(equal + 1).replace(/\+/g, ' '));
    if (!['username', 'password', 'remember'].includes(key) || Object.hasOwn(result, key)) throw new Error('Malformed form');
    result[key] = value;
  }
  if (!credentials(result.username, result.password) ||
      (result.remember !== undefined && !['on', 'true', '1', 'false', '0', ''].includes(result.remember))) throw new Error('Malformed form');
  return { username: result.username, password: result.password, remember: ['on', 'true', '1'].includes(result.remember) };
}

export async function createAuthServer(options = {}) {
  const config = configuration(options);
  await fs.mkdir(config.stateDir, { recursive: true, mode: 0o700 });
  await fs.chmod(config.stateDir, 0o700);
  const stateFile = path.join(config.stateDir, 'sessions.json');
  let revision = await passwordRevision(config);
  let sessions = new Map();
  try {
    if (!(await fs.lstat(stateFile)).isFile()) throw new Error('Invalid session store');
    const stored = JSON.parse(await fs.readFile(stateFile, 'utf8'));
    if (stored.version !== 1 || !Array.isArray(stored.sessions) || stored.sessions.length > config.maxSessions) throw new Error('Invalid session store');
    for (const session of stored.sessions) {
      if (!session || !/^[a-f0-9]{64}$/.test(session.digest) || !/^[a-f0-9]{64}$/.test(session.credentialRevision) ||
          !credentials(session.username, 'validation') || !Number.isSafeInteger(session.expires) || sessions.has(session.digest) ||
          Object.keys(session).sort().join(',') !== 'credentialRevision,digest,expires,username') throw new Error('Invalid session store');
      if (session.expires > config.clock() && session.credentialRevision === revision) sessions.set(session.digest, session);
    }
    await fs.chmod(stateFile, 0o600);
  } catch (error) { if (error.code !== 'ENOENT') throw error; }

  async function persist() {
    const temporary = path.join(config.stateDir, `.sessions-${randomBytes(16).toString('hex')}.tmp`);
    const handle = await fs.open(temporary, 'wx', 0o600);
    try {
      await handle.writeFile(json({ version: 1, sessions: [...sessions.values()] }));
      await handle.sync(); await handle.close();
      await fs.rename(temporary, stateFile);
      const directory = await fs.open(config.stateDir, 'r');
      try { await directory.sync(); } finally { await directory.close(); }
    } catch (error) {
      await handle.close().catch(() => {}); await fs.unlink(temporary).catch(() => {}); throw error;
    }
  }
  await persist();
  let queue = Promise.resolve();
  function transaction(operation) {
    const task = queue.then(async () => {
      const current = await passwordRevision(config);
      let changed = false;
      if (current !== revision) { revision = current; sessions.clear(); changed = true; }
      for (const [key, value] of sessions) if (value.expires <= config.clock()) { sessions.delete(key); changed = true; }
      if (changed) await persist();
      return operation();
    });
    queue = task.catch(() => {});
    return task;
  }

  const buckets = new Map();
  let globalBucket = { end: 0, count: 0 };
  function reserve(req) {
    const now = config.clock();
    for (const [key, bucket] of buckets) if (bucket.end <= now) buckets.delete(key);
    if (globalBucket.end <= now) globalBucket = { end: now + config.rateWindowMs, count: 0 };
    const forwarded = req.headers['x-real-ip'];
    const ip = config.trustProxy && typeof forwarded === 'string' && isIP(forwarded) ? forwarded : req.socket.remoteAddress;
    const bucket = buckets.get(ip) ?? { end: now + config.rateWindowMs, count: 0 };
    if (bucket.count >= config.rateIpMax || globalBucket.count >= config.rateGlobalMax) return null;
    buckets.set(ip, bucket); bucket.count++; globalBucket.count++;
    const global = globalBucket;
    return () => { bucket.count--; global.count--; };
  }

  const statusSession = req => transaction(() => {
    const token = cookieToken(req);
    return token ? sessions.get(digest(token)) ?? null : null;
  });
  const sameOrigin = origin => origin === config.publicOrigin;
  const redirect = (res, location, headers = {}) => { res.writeHead(303, { Location: location, ...headers }); res.end(); };
  const respond = (res, status, body = '', headers = {}) => { res.writeHead(status, headers); res.end(body); };

  async function staticFile(req, res, pathname) {
    let relative;
    if (pathname === '/login') relative = 'login.html';
    else {
      try { relative = decodeURIComponent(pathname.slice('/login-assets/'.length)); } catch { return respond(res, 404); }
      if (!relative || relative.includes('\\') || relative.split('/').some(part => !part || part === '.' || part === '..')) return respond(res, 404);
    }
    const base = await fs.realpath(config.staticDir);
    let file;
    try {
      file = await fs.realpath(path.join(base, relative));
      if (!file.startsWith(base + path.sep) || !(await fs.stat(file)).isFile()) return respond(res, 404);
    } catch (error) { if (error.code === 'ENOENT') return respond(res, 404); throw error; }
    const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
      '.svg': 'image/svg+xml', '.png': 'image/png', '.webp': 'image/webp', '.jpg': 'image/jpeg', '.woff2': 'font/woff2', '.ico': 'image/x-icon' };
    const type = types[path.extname(file).toLowerCase()];
    if (!type) return respond(res, 404);
    return respond(res, 200, await fs.readFile(file), { 'Content-Type': type });
  }

  const server = http.createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Security-Policy', CSP);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    try {
      const rawPath = req.url.split('?')[0];
      if (req.method === 'GET' && rawPath === '/healthz') return respond(res, 204);
      if (req.method === 'GET' && (rawPath === '/login' || rawPath.startsWith('/login-assets/'))) return await staticFile(req, res, rawPath);
      if (req.method === 'GET' && rawPath === '/auth/status') {
        const session = await statusSession(req);
        return respond(res, 200, json(session ? { authenticated: true, username: session.username } : { authenticated: false }), { 'Content-Type': 'application/json' });
      }
      if (req.method === 'POST' && ['/auth/login', '/auth/logout'].includes(rawPath)) {
        if (!sameOrigin(req.headers.origin)) return respond(res, 403);
        if (rawPath === '/auth/logout') {
          await readBody(req, config.timeoutMs);
          await transaction(async () => { const token = cookieToken(req); if (token && sessions.delete(digest(token))) await persist(); });
          return redirect(res, '/login', { 'Set-Cookie': [cookie('', false, true), loggedOutCookie()] });
        }
        if (!reserve(req)) return redirect(res, '/login?error=rate_limited', { 'Retry-After': String(Math.ceil(config.rateWindowMs / 1000)) });
        const bytes = await readBody(req, config.timeoutMs);
        let form;
        try {
          if (!/^application\/x-www-form-urlencoded(?:\s*;\s*charset=utf-8)?$/i.test(req.headers['content-type'] ?? '')) throw new Error('Invalid content type');
          form = parseForm(bytes);
        } catch { return redirect(res, '/login?error=bad_request'); }
        const before = await transaction(() => revision);
        let valid;
        try { valid = await verifyCredentials(config, form.username, form.password); }
        catch { return redirect(res, '/login?error=unavailable'); }
        if (!valid) return redirect(res, '/login?error=credentials');
        const token = await transaction(async () => {
          if (before !== revision) return null;
          const existing = cookieToken(req); if (existing) sessions.delete(digest(existing));
          const byExpiry = [...sessions.values()].sort((a, b) => a.expires - b.expires);
          let userCount = byExpiry.filter(value => value.username === form.username).length;
          for (const value of byExpiry) {
            if (value.username === form.username && userCount >= config.maxUserSessions) { sessions.delete(value.digest); userCount--; }
          }
          for (const value of byExpiry) if (sessions.size >= config.maxSessions) sessions.delete(value.digest);
          const raw = randomBytes(32).toString('hex');
          sessions.set(digest(raw), { digest: digest(raw), username: form.username,
            expires: config.clock() + (form.remember ? REMEMBER_MS : SESSION_MS), credentialRevision: revision });
          try { await persist(); } catch (error) { sessions.delete(digest(raw)); throw error; }
          return raw;
        });
        if (!token) return redirect(res, '/login?error=credentials');
        return redirect(res, '/', { 'Set-Cookie': [cookie(token, form.remember), loggedOutCookie(true)] });
      }
      if (req.method === 'GET' && rawPath === '/auth/check') {
        const originalMethod = req.headers['x-original-method'];
        const origin = req.headers['x-original-origin'];
        if (typeof originalMethod !== 'string' || !/^[A-Z]+$/.test(originalMethod)) return respond(res, 400);
        if (origin && !sameOrigin(origin)) return respond(res, 403);
        const session = await statusSession(req);
        if (session) {
          if (!SAFE_METHODS.has(originalMethod) && !sameOrigin(origin)) return respond(res, 403);
          return respond(res, 204);
        }
        // 浏览器退出后仍可能自动附带缓存的 Basic 凭据，须等显式表单登录清除退出标记。
        if ((req.headers.cookie ?? '').split(';').some(value => value.trim().startsWith(`${LOGGED_OUT_COOKIE}=`))) return respond(res, 401);
        const basic = basicCredentials(req.headers.authorization);
        if (!basic) return respond(res, 401);
        const release = reserve(req);
        if (!release) return respond(res, 401, '', { 'Retry-After': String(Math.ceil(config.rateWindowMs / 1000)) });
        const before = await transaction(() => revision);
        const valid = await verifyCredentials(config, basic.username, basic.password);
        if (!valid || before !== await transaction(() => revision)) return respond(res, 401);
        release();
        return respond(res, 204);
      }
      return respond(res, 404);
    } catch (error) {
      if (!res.headersSent && !res.destroyed) {
        if (error.status) { res.setHeader('Connection', 'close'); res.once('finish', () => req.destroy()); }
        respond(res, error.status ?? 503);
      } else res.destroy();
    }
  });
  server.requestTimeout = config.timeoutMs;
  server.headersTimeout = config.timeoutMs;
  server.keepAliveTimeout = 5000;
  server.maxHeadersCount = 50;
  server.on('clientError', (_error, socket) => { if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'); });
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    const server = await createAuthServer();
    const port = integer(process.env.AUTH_PORT, 8080, 1, 65535);
    server.listen(port, process.env.AUTH_HOST ?? '0.0.0.0');
    const stop = () => server.close(() => process.exit(0));
    process.on('SIGTERM', stop); process.on('SIGINT', stop);
  } catch { process.stderr.write('Authentication service failed to start.\n'); process.exitCode = 1; }
}
