import assert from "node:assert/strict";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createServerDatabase } from "../src/server-database.mjs";
import { seedCrsConfiguration } from "../src/crs-integration.mjs";

// 真实上号器 HTTP 与数据库联动；供应商、CRS 和登录子进程均使用本地夹具
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dir = await fs.mkdtemp(path.join(os.tmpdir(), "dynamic-proxy-http-"));
const output = path.join(dir, "jobs"); await fs.mkdir(output);
const observations = path.join(dir, "observations.jsonl");
const extractionLog = path.join(dir, "extractions.jsonl");
const email = "dynamic-fixture@example.com";
const proxy = (n) => `http://fixture:secret${n}@gateway.example:8080/`;
let account = null; let currentProxy = null; let oldProxyDead = false; let prepared = 0;
const calls = [];
const crs = http.createServer(async (req, res) => {
  let raw = ""; for await (const chunk of req) raw += chunk;
  const body = raw ? JSON.parse(raw) : {};
  const url = new URL(req.url, "http://localhost"); calls.push({ path: url.pathname, body });
  function send(status, data) { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify({ code: status, data })); }
  if (req.headers["x-api-key"] !== "fixture-admin-key") return send(401, {});
  if (url.pathname === "/api/admin/accounts") return send(200, { items: account ? [{ id: account.accountId, email }] : [], page: { totalPages: 1 } });
  if (url.pathname === "/api/admin/proxies/probe") return send(200, { success: !(oldProxyDead && body.proxyUrl === proxy(1)) });
  if (url.pathname === "/api/admin/accounts/proxy-demand") {
    if (req.method === "POST") assert.equal(body.expectedProxyId, account.proxyId);
    return send(200, req.method === "GET" ? [] : null);
  }
  if (url.pathname === "/api/admin/accounts/export") return send(200, { documents: [{ provider: "openai", document: { accounts: [{ id: account.accountId, email, outbound_proxy_url: currentProxy }] } }] });
  if (url.pathname === "/api/admin/accounts/proxy-recovery") {
    if (req.method === "GET") return send(200, account);
    if (body.action === "prepareInitial") { prepared++; currentProxy = body.proxyUrl; return send(200, { proxyId: "proxy_fixture" }); }
    if (body.action === "begin") {
      assert.equal(account.enabled, true); assert.equal(account.quotaAllowed, true);
      account.enabled = false;
      account.guardian.state = { status: "proxy_recovery", proxyRecovery: { operationId: body.operationId } };
      account.guardian.revision++; return send(200, account.guardian);
    }
    if (body.action === "complete") {
      assert.equal(body.operationId, account.guardian.state.proxyRecovery.operationId);
      currentProxy = body.proxyUrl; account.guardian.state.status = "verifying";
      account.quotaAllowed = false; return send(200, account.guardian);
    }
  }
  send(404, {});
});
await new Promise((r) => crs.listen(0, "127.0.0.1", r));
const crsUrl = `http://127.0.0.1:${crs.address().port}`;
const db = createServerDatabase({ outputRoot: output });
seedCrsConfiguration(db, { baseUrl: crsUrl, authType: "apiKey", apiKey: "fixture-admin-key", autoUpload: false }); db.close();
const originalDynamic = pathToFileURL(path.join(root, "src/dynamic-proxy.mjs")).href;
const originalCredentials = pathToFileURL(path.join(root, "src/credential-store.mjs")).href;
const fakeExtractor = `export * from ${JSON.stringify(originalDynamic + "?real")};
import fs from "node:fs/promises";
let count = 0;
export function create1024Extractor() { return async () => {
  count++; await fs.appendFile(process.env.DYNAMIC_TEST_EXTRACTIONS, JSON.stringify({count}) + "\\n");
  return "http://fixture:secret" + count + "@gateway.example:8080/";
}; }`;
const fakeCredentials = `export function createCredentialStore(){ const values = new Map(); return {async save(email,value){values.set(email,value)},async load(email){return values.get(email)||{password:"",totpSecret:"",proxyUrl:""}},async delete(email){values.delete(email)}}}`;
const loader = path.join(dir, "loader.mjs");
await fs.writeFile(loader, `export async function load(url,context,next){
if(url===${JSON.stringify(originalDynamic)})return {format:"module",shortCircuit:true,source:${JSON.stringify(fakeExtractor)}};
if(url===${JSON.stringify(originalCredentials)})return {format:"module",shortCircuit:true,source:${JSON.stringify(fakeCredentials)}};
return next(url,context);}`);
const preload = path.join(dir, "preload.mjs");
await fs.writeFile(preload, `import {register} from "node:module";register(${JSON.stringify(pathToFileURL(loader).href)},import.meta.url);`);
const protocol = path.join(dir, "protocol.mjs");
await fs.writeFile(protocol, `import fs from "node:fs/promises";
await fs.appendFile(process.env.DYNAMIC_TEST_OBSERVATIONS,JSON.stringify({proxy:process.env.CHATGPT_PROXY_URL})+"\\n");
console.log("Email OTP (r=resend, q=quit):");
await new Promise(r=>{const timer=setTimeout(r,60000);process.once("SIGTERM",()=>{clearTimeout(timer);r()})});`);
const portServer = http.createServer(); await new Promise((r) => portServer.listen(0, "127.0.0.1", r));
const port = portServer.address().port; await new Promise((r) => portServer.close(r));
const baseUrl = `http://127.0.0.1:${port}`;
const child = spawn(process.execPath, ["--import", preload, path.join(root, "src/console-server.mjs"), "--host", "127.0.0.1", "--port", String(port)], {
  cwd: root, env: { ...process.env, ONBOARDING_OUTPUT_ROOT: output, ONBOARDING_PROTOCOL_SCRIPT: protocol, DYNAMIC_TEST_OBSERVATIONS: observations, DYNAMIC_TEST_EXTRACTIONS: extractionLog, TOSUB2_DYNAMIC_PROXY_EXTRACTION: "1", CRS_LOGIN_BRIDGE_KEY: "fixture-bridge-key", TOSUB2_TLS_PROFILE: "chrome142" }, stdio: ["ignore", "pipe", "pipe"],
});
let logs = ""; child.stdout.on("data", (x) => { logs = (logs + x).slice(-8000); }); child.stderr.on("data", (x) => { logs = (logs + x).slice(-8000); });
const exited = new Promise((r) => child.once("exit", r));
let headers;
async function waitFor(fn) { const end = Date.now() + 20000; while (Date.now() < end) { const v = await fn(); if (v) return v; await new Promise((r) => setTimeout(r, 60)); } throw Error(`fixture timeout\n${logs}`); }
async function request(endpoint, body, expected = 200) {
  const res = await fetch(baseUrl + endpoint, { headers, ...(body === undefined ? {} : { method: "POST", body: JSON.stringify(body) }) });
  const data = await res.json(); assert.equal(res.status, expected, JSON.stringify(data)); return data;
}
async function getJob(id) { return (await request("/api/jobs?page=1&pageSize=50")).jobs.find((value) => value.id === id); }
async function lines(file) { try { return (await fs.readFile(file, "utf8")).trim().split("\n").filter(Boolean).map(JSON.parse); } catch (e) { if (e.code === "ENOENT") return []; throw e; } }
try {
  const bootstrap = await waitFor(async () => { try { const res = await fetch(baseUrl + "/api/bootstrap"); return res.ok ? res.json() : null; } catch { return null; } });
  assert.equal((await fetch(baseUrl + "/api/dynamic-proxies")).status, 403);
  headers = { "content-type": "application/json", "x-console-token": bootstrap.token };
  const profile = { id: "fixture", name: "测试动态住宅", country: "US", protocol: "http", key: "fixture-supplier-key", enabled: true };
  const saved = await request("/api/dynamic-proxies", { action: "saveProfile", profile, revision: 0 });
  assert.doesNotMatch(JSON.stringify(saved), /fixture-supplier-key/);
  assert.equal((await lines(extractionLog)).length, 0);
  const created = await request("/api/jobs/batch", { text: email, proxyAssignments: [{ email, proxyUrl: { dynamicProfileId: profile.id } }] }, 201);
  const id = created.jobs[0].id;
  await waitFor(async () => (await lines(observations)).length === 1);
  assert.equal((await lines(extractionLog)).length, 1); assert.equal(prepared, 1);
  assert.equal(currentProxy, proxy(1)); assert.equal((await lines(observations))[0].proxy, currentProxy);
  await request(`/api/jobs/${id}/cancel`, {});
  await waitFor(async () => (await getJob(id)).status === "canceled");
  const binding = (await request("/api/dynamic-proxies")).bindings[0];
  account = { accountId: "acct_fixture", email, enabled: true, quotaAllowed: true, proxyId: "proxy_fixture", guardian: { config: { enabled: true }, revision: 1, state: { status: "watching", proxyRecovery: { operationId: binding.id } } } };
  oldProxyDead = true;
  await request("/api/jobs/relogin-batch", { ids: [id], proxyAssignments: [{ id, proxyUrl: { dynamicProfileId: profile.id } }] });
  await waitFor(async () => (await request("/api/dynamic-proxies")).bindings[0].status === "verifying");
  assert.equal((await lines(extractionLog)).length, 2);
  assert.equal(currentProxy, proxy(2)); assert.equal((await lines(observations)).length, 1);
  await waitFor(async () => !["queued", "running", "starting"].includes((await getJob(id)).status));
  account.enabled = true; account.quotaAllowed = true; account.guardian.state.status = "watching";
  await request("/api/jobs/relogin-batch", { ids: [id], proxyAssignments: [{ id, proxyUrl: { dynamicProfileId: profile.id } }] });
  await waitFor(async () => (await lines(observations)).length === 2);
  assert.equal((await lines(observations))[1].proxy, currentProxy);
  assert.equal((await lines(extractionLog)).length, 2);
  await request(`/api/jobs/${id}/cancel`, {});
  await waitFor(async () => (await getJob(id)).status === "canceled");
  account.enabled = false; account.guardian.state.status = "degraded";
  await request("/api/jobs/relogin-batch", { ids: [id], proxyAssignments: [{ id, proxyUrl: { dynamicProfileId: profile.id } }] });
  await waitFor(async () => (await getJob(id)).status === "failed");
  assert.equal((await lines(observations)).length, 2); assert.equal((await lines(extractionLog)).length, 2);
  assert(calls.some((v) => v.body.action === "begin")); assert(calls.some((v) => v.body.action === "complete"));
  account.proxyId = "proxy_fixed"; account.guardian.state.status = "paused"; account.guardian.state.proxyRecovery = null; account.guardian.revision++;
  currentProxy = "socks5://fixed-user:fixed-secret@fixed.example:6666";
  await waitFor(async () => (await request("/api/dynamic-proxies")).bindings.length === 0);
  const staleBridge = await fetch(baseUrl + "/api/integrations/crs/login", { method: "POST", headers: { authorization: "Bearer fixture-bridge-key", "content-type": "application/json" }, body: JSON.stringify({ operationId: "stale-dynamic-relogin", email, password: "fixture-password", proxyUrl: proxy(2) }) });
  assert.equal(staleBridge.status, 202); assert.equal((await staleBridge.json()).status, "failed");
  assert.equal((await lines(observations)).length, 2);
  await request("/api/jobs/relogin-batch", { ids: [id], proxyAssignments: [{ id, proxyUrl: currentProxy }] });
  await waitFor(async () => (await lines(observations)).length === 3);
  assert.equal((await lines(observations))[2].proxy, currentProxy);
  assert.equal((await lines(extractionLog)).length, 2);
  const savedDb = createServerDatabase({ outputRoot: output });
  const archived = savedDb.get("dynamic-proxy-archive", binding.id);
  assert.equal(archived.extractionCount, 2); assert.equal(savedDb.loadCredentials(email).proxyUrl, currentProxy); savedDb.close();
  await request(`/api/jobs/${id}/cancel`, {});
  console.log("dynamic proxy HTTP integration passed: manual selection and encrypted archive, exact proxy, isolated renewal, quality gate, degradation stop, authenticated settings, zero real supplier calls");
  if (process.env.DYNAMIC_PROXY_TEST_PREVIEW === "1") { console.log(`Preview: ${baseUrl}`); await new Promise((r) => process.once("SIGTERM", r)); }
} finally {
  child.kill("SIGTERM"); await exited; crs.closeAllConnections(); await new Promise((r) => crs.close(r));
  await fs.rm(dir, { recursive: true, force: true });
}
