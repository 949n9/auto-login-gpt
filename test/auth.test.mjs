import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { createAuthServer } from '../auth/server.mjs';

const ORIGIN = 'https://login.example.test';
const BASIC = `Basic ${Buffer.from('operator:fixture-password').toString('base64')}`;

async function listen(server) {
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return `http://127.0.0.1:${server.address().port}`;
}
async function close(server) {
  if (!server.listening) return;
  await new Promise((resolve, reject) => { server.close(error => error ? reject(error) : resolve()); server.closeAllConnections(); });
}

async function fixture(t, options = {}) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'tosub2-auth-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const passwordFile = path.join(directory, 'htpasswd');
  await fs.writeFile(passwordFile, 'operator:fixture-credential-revision\n', { mode: 0o600 });
  const staticDir = path.join(directory, 'public'); await fs.mkdir(staticDir);
  await fs.writeFile(path.join(staticDir, 'login.html'), '<!doctype html><form action="/auth/login"></form>');
  await fs.writeFile(path.join(staticDir, 'login.css'), 'body { color: black }');
  let verifierMode = 'normal', verifyCalls = 0;
  const verifier = http.createServer((req, res) => {
    verifyCalls++;
    assert.equal(req.url, '/verify'); assert.equal(req.method, 'GET');
    if (verifierMode === 'timeout') return;
    if (verifierMode === 'redirect') { res.writeHead(302, { Location: 'http://127.0.0.1:9/never' }); return res.end(); }
    if (verifierMode === 'rotate') fs.writeFile(passwordFile, 'operator:new-revision\n').then(() => { res.writeHead(204); res.end(); });
    else { res.writeHead(req.headers.authorization === BASIC ? 204 : 401, { 'WWW-Authenticate': 'Basic realm="private"' }); res.end(); }
  });
  const verifyOrigin = await listen(verifier); t.after(() => close(verifier));
  let now = 1_800_000_000_000;
  const config = { env: {}, publicOrigin: ORIGIN, verifyUrl: `${verifyOrigin}/verify`, passwordFile,
    stateDir: path.join(directory, 'state'), staticDir, clock: () => now,
    rateIpMax: 100, rateGlobalMax: 500, ...options };
  let server = await createAuthServer(config), base = await listen(server);
  t.after(() => close(server));
  const request = (route, init = {}) => fetch(`${base}${route}`, { redirect: 'manual', ...init });
  const login = (extra = {}) => request('/auth/login', {
    method: 'POST', headers: { Origin: ORIGIN, 'Content-Type': 'application/x-www-form-urlencoded', ...extra.headers },
    body: extra.body ?? new URLSearchParams({ username: 'operator', password: 'fixture-password', ...(extra.remember ? { remember: 'on' } : {}) }).toString(),
  });
  return { directory, config, passwordFile, request, login,
    cookie: response => response.headers.get('set-cookie')?.split(';')[0],
    now: () => now, advance: ms => { now += ms; },
    verifyCalls: () => verifyCalls, verifierMode: mode => { verifierMode = mode; },
    restart: async () => { await close(server); server = await createAuthServer(config); base = await listen(server); },
  };
}

test('successful form login creates opaque secure session with no secrets persisted', async t => {
  const f = await fixture(t); const response = await f.login();
  assert.equal(response.status, 303); assert.equal(response.headers.get('location'), '/');
  const header = response.headers.getSetCookie()[0];
  assert.match(header, /^__Host-tosub2_session=[a-f0-9]{64}; Path=\/; Secure; HttpOnly; SameSite=Lax$/);
  const token = f.cookie(response).split('=')[1];
  const stateFile = path.join(f.config.stateDir, 'sessions.json');
  const text = await fs.readFile(stateFile, 'utf8');
  assert.ok(!text.includes(token)); assert.ok(!text.includes('fixture-password'));
  const stored = JSON.parse(text).sessions[0];
  assert.deepEqual(Object.keys(stored).sort(), ['credentialRevision', 'digest', 'expires', 'username']);
  assert.equal(stored.digest, createHash('sha256').update(token).digest('hex'));
  assert.equal(stored.expires, f.now() + 12 * 3600000);
  assert.equal((await fs.stat(stateFile)).mode & 0o777, 0o600);
  const status = await f.request('/auth/status', { headers: { Cookie: f.cookie(response) } });
  assert.deepEqual(await status.json(), { authenticated: true, username: 'operator' });
  assert.equal(status.headers.get('cache-control'), 'no-store');
});

test('wrong credentials give generic redirect without password or authentication challenge', async t => {
  const f = await fixture(t);
  const response = await f.login({ body: 'username=operator&password=wrong-secret' });
  assert.equal(response.status, 303); assert.equal(response.headers.get('location'), '/login?error=credentials');
  assert.equal(response.headers.get('set-cookie'), null); assert.equal(response.headers.get('www-authenticate'), null);
  assert.deepEqual(await (await f.request('/auth/status')).json(), { authenticated: false });
});

test('remember session survives server restart, expires after 30 days, and never stores password', async t => {
  const f = await fixture(t); const response = await f.login({ remember: true }); const cookie = f.cookie(response);
  assert.match(response.headers.get('set-cookie'), /Max-Age=2592000/);
  await f.restart();
  assert.equal((await (await f.request('/auth/status', { headers: { Cookie: cookie } })).json()).authenticated, true);
  f.advance(30 * 86400000 + 1);
  assert.deepEqual(await (await f.request('/auth/status', { headers: { Cookie: cookie } })).json(), { authenticated: false });
  assert.equal(JSON.parse(await fs.readFile(path.join(f.config.stateDir, 'sessions.json'))).sessions.length, 0);
});

test('ordinary sessions expire after 12 hours and logout revokes persistently', async t => {
  const f = await fixture(t); let cookie = f.cookie(await f.login());
  f.advance(12 * 3600000 + 1);
  assert.deepEqual(await (await f.request('/auth/status', { headers: { Cookie: cookie } })).json(), { authenticated: false });
  cookie = f.cookie(await f.login());
  const response = await f.request('/auth/logout', { method: 'POST', headers: { Origin: ORIGIN, Cookie: cookie } });
  assert.equal(response.status, 303); assert.equal(response.headers.get('location'), '/login');
  assert.match(response.headers.get('set-cookie'), /Max-Age=0/);
  await f.restart();
  assert.deepEqual(await (await f.request('/auth/status', { headers: { Cookie: cookie } })).json(), { authenticated: false });
});

test('credential file rotation invalidates existing sessions and racing login', async t => {
  const f = await fixture(t); const cookie = f.cookie(await f.login());
  await fs.writeFile(f.passwordFile, 'operator:changed-credential-revision\n');
  assert.deepEqual(await (await f.request('/auth/status', { headers: { Cookie: cookie } })).json(), { authenticated: false });
  f.verifierMode('rotate');
  const response = await f.login();
  assert.equal(response.headers.get('location'), '/login?error=credentials');
  assert.equal(response.headers.get('set-cookie'), null);
});

test('login/logout require exact Origin and cookie unsafe auth checks reject missing or foreign Origin', async t => {
  const f = await fixture(t); const cookie = f.cookie(await f.login());
  for (const origin of [undefined, 'https://evil.test', `${ORIGIN}/`, 'null']) {
    const headers = { Cookie: cookie, ...(origin === undefined ? {} : { Origin: origin }) };
    for (const route of ['/auth/login', '/auth/logout']) assert.equal((await f.request(route, { method: 'POST', headers, body: '' })).status, 403);
    assert.equal((await f.request('/auth/check', { headers: { Cookie: cookie, 'X-Original-Method': 'POST',
      ...(origin === undefined ? {} : { 'X-Original-Origin': origin }) } })).status, 403);
  }
  assert.equal((await f.request('/auth/check', { headers: { Cookie: cookie, 'X-Original-Method': 'POST', 'X-Original-Origin': ORIGIN } })).status, 204);
  assert.equal((await f.request('/auth/check', { headers: { Cookie: cookie, 'X-Original-Method': 'GET' } })).status, 204);
});

test('Basic compatibility validates credentials without creating sessions, challenges, or CORS', async t => {
  const f = await fixture(t);
  for (const method of ['GET', 'POST']) {
    const response = await f.request('/auth/check', { headers: { Authorization: BASIC, 'X-Original-Method': method } });
    assert.equal(response.status, 204); assert.equal(response.headers.get('set-cookie'), null);
    assert.equal(response.headers.get('access-control-allow-origin'), null);
  }
  assert.equal((await f.request('/auth/check', { headers: { Authorization: BASIC, 'X-Original-Method': 'POST', 'X-Original-Origin': 'https://evil.test' } })).status, 403);
  for (const authorization of [undefined, 'Basic !!!!', `Basic ${Buffer.from('operator:bad').toString('base64')}`]) {
    const response = await f.request('/auth/check', { headers: { 'X-Original-Method': 'GET', ...(authorization ? { Authorization: authorization } : {}) } });
    assert.equal(response.status, 401); assert.equal(response.headers.get('www-authenticate'), null);
  }
  assert.equal((await f.request('/auth/check')).status, 400);
});

test('logout sentinel blocks cached Basic until explicit login without affecting ordinary Basic clients', async t => {
  const f = await fixture(t);
  const basicHeaders = { Authorization: BASIC, 'X-Original-Method': 'GET' };
  assert.equal((await f.request('/auth/check', { headers: basicHeaders })).status, 204);
  const logout = await f.request('/auth/logout', { method: 'POST', headers: { Origin: ORIGIN, Authorization: BASIC } });
  const cookies = logout.headers.getSetCookie();
  assert.match(cookies[0], /^__Host-tosub2_session=;.*Max-Age=0$/);
  assert.equal(cookies[1], '__Host-tosub2_logged_out=1; Path=/; Secure; HttpOnly; SameSite=Lax');
  const sentinel = cookies[1].split(';')[0], before = f.verifyCalls();
  const blocked = await f.request('/auth/check', { headers: { ...basicHeaders, Cookie: sentinel } });
  assert.equal(blocked.status, 401); assert.equal(blocked.headers.get('www-authenticate'), null);
  assert.equal(f.verifyCalls(), before);
  assert.equal((await f.request('/auth/check', { headers: basicHeaders })).status, 204);
  const login = await f.login({ headers: { Cookie: sentinel } });
  assert.equal(login.status, 303);
  assert.equal(login.headers.getSetCookie()[1], '__Host-tosub2_logged_out=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0');
  assert.equal((await f.request('/auth/check', { headers: { Cookie: `${f.cookie(login)}; ${sentinel}`, 'X-Original-Method': 'GET' } })).status, 204);
});

test('IP and global login limits use clock windows and trusted proxy header only when configured', async t => {
  const f = await fixture(t, { rateIpMax: 2, rateGlobalMax: 3, rateWindowMs: 1000, trustProxy: true });
  const bad = ip => f.login({ body: 'username=operator&password=bad', headers: { 'X-Real-IP': ip } });
  assert.equal((await bad('192.0.2.1')).headers.get('location'), '/login?error=credentials');
  await bad('192.0.2.1');
  assert.equal((await bad('192.0.2.1')).headers.get('location'), '/login?error=rate_limited');
  await bad('192.0.2.2');
  assert.equal((await bad('192.0.2.3')).headers.get('location'), '/login?error=rate_limited');
  assert.equal(f.verifyCalls(), 3);
  f.advance(1001);
  assert.equal((await bad('192.0.2.1')).headers.get('location'), '/login?error=credentials');
});

test('bad Basic attempts are limited while successful Basic requests do not exhaust login budget', async t => {
  const f = await fixture(t, { rateIpMax: 2 });
  const call = authorization => f.request('/auth/check', { headers: { Authorization: authorization, 'X-Original-Method': 'GET' } });
  for (let index = 0; index < 5; index++) assert.equal((await call(BASIC)).status, 204);
  const bad = `Basic ${Buffer.from('operator:bad').toString('base64')}`;
  assert.equal((await call(bad)).status, 401); assert.equal((await call(bad)).status, 401);
  const limited = await call(bad);
  assert.equal(limited.status, 401); assert.ok(limited.headers.get('retry-after'));
});

test('malformed forms, duplicate keys, wrong encoding, and large bodies cannot reach verifier', async t => {
  const f = await fixture(t);
  for (const body of ['username=x&password=%ZZ', 'username=x&username=y&password=p', 'username=x&password=p&admin=1',
    'username=x&password=', 'username=x%3Ay&password=z', 'username=%FF&password=z', 'username=x&password=z&remember=maybe', 'broken']) {
    const response = await f.login({ body }); assert.equal(response.headers.get('location'), '/login?error=bad_request');
  }
  assert.equal((await f.login({ body: '{}', headers: { 'Content-Type': 'application/json' } })).headers.get('location'), '/login?error=bad_request');
  assert.equal((await f.login({ body: 'a'.repeat(8193) })).status, 413);
  assert.equal(f.verifyCalls(), 0);
});

test('upstream timeout and redirects fail closed without forwarding credentials elsewhere', async t => {
  const f = await fixture(t, { timeoutMs: 50 });
  for (const mode of ['redirect', 'timeout']) {
    f.verifierMode(mode); const response = await f.login();
    assert.equal(response.headers.get('location'), '/login?error=unavailable');
    assert.equal(response.headers.get('set-cookie'), null);
  }
  assert.equal(f.verifyCalls(), 2);
});

test('session caps and duplicate cookie rejection prevent unbounded or ambiguous authentication', async t => {
  const f = await fixture(t, { maxSessions: 3, maxUserSessions: 2 });
  const one = f.cookie(await f.login()); f.advance(1);
  const two = f.cookie(await f.login()); f.advance(1);
  const three = f.cookie(await f.login());
  assert.deepEqual(await (await f.request('/auth/status', { headers: { Cookie: one } })).json(), { authenticated: false });
  assert.equal((await (await f.request('/auth/status', { headers: { Cookie: two } })).json()).authenticated, true);
  assert.deepEqual(await (await f.request('/auth/status', { headers: { Cookie: `${two}; ${three}` } })).json(), { authenticated: false });
  assert.equal(JSON.parse(await fs.readFile(path.join(f.config.stateDir, 'sessions.json'))).sessions.length, 2);
});

test('static routing rejects traversal and symlinks outside assets and sets security headers', async t => {
  const f = await fixture(t);
  const login = await f.request('/login?error=credentials'); assert.equal(login.status, 200);
  assert.match(login.headers.get('content-security-policy'), /form-action 'self'; frame-ancestors 'none'/);
  assert.equal((await f.request('/login-assets/login.css')).status, 200);
  assert.equal((await f.request('/healthz')).status, 204);
  await fs.symlink(f.passwordFile, path.join(f.config.staticDir, 'escape.css'));
  assert.equal((await f.request('/login-assets/escape.css')).status, 404);
  assert.equal((await f.request('/login-assets/%2e%2e%2fhtpasswd')).status, 404);
});

test('required config and HTTPS are enforced, with explicit loopback-only test exception', async t => {
  await assert.rejects(createAuthServer({ env: {} }), /missing/);
  const f = await fixture(t);
  await assert.rejects(createAuthServer({ ...f.config, publicOrigin: 'http://example.test' }), /HTTPS/);
  await assert.rejects(createAuthServer({ ...f.config, publicOrigin: 'http://example.test', allowInsecureLoopback: true }), /HTTPS/);
  const local = await createAuthServer({ ...f.config, publicOrigin: 'http://127.0.0.1:8080', allowInsecureLoopback: true });
  await close(local);
});
