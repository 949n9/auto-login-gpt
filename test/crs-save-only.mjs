import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { createCrsIntegration, makeCrsExport, seedCrsConfiguration } from "../src/crs-integration.mjs";
import { createServerDatabase } from "../src/server-database.mjs";

const temporaryRoot = await fs.mkdtemp(path.join(os.tmpdir(), "tosub2-crs-save-only-"));
const database = createServerDatabase({ outputRoot: temporaryRoot });
const jobs = new Map();
const tasks = new Map();
const submissions = new Map();
const requests = [];
let behavior = "success";
let imports = 0;
let retries = 0;
let logins = 0;
let afterLogin;
let expireImportAuth = false;
let mockGroups = [{ id: "group-openai", name: "OpenAI", enabled: true }, { id: "group-special", name: "专用", enabled: true }];
let service;
const password = "mock-crs-password-private";
const apiKey = "mock-crs-api-key-private";
const cookie = "mock-crs-session-private";
const remote = http.createServer(async (req, res) => {
  let raw = "";
  for await (const chunk of req) raw += chunk;
  const body = raw ? JSON.parse(raw) : {};
  const url = new URL(req.url, "http://localhost");
  requests.push({ method: req.method, path: url.pathname, body });
  if (url.pathname === "/api/auth/login") {
    logins += 1;
    assert.equal(body.mode, "admin");
    if (body.password !== password) return send(401, { code: 401 });
    afterLogin?.();
    afterLogin = null;
    res.setHeader("set-cookie", `crs_session=${cookie}; Path=/; HttpOnly; SameSite=Lax`);
    return send(200, { code: 200, data: {} });
  }
  if (req.headers.cookie !== `crs_session=${cookie}` && req.headers["x-api-key"] !== apiKey) return send(401, { code: 401 });
  if (url.pathname === "/api/admin/account-groups/options") return send(200, { code: 200, data: { items: mockGroups, page: { totalPages: 1 } } });
  if (url.pathname === "/api/admin/system/version") {
    if (behavior === "redirect") { res.writeHead(302, { location: "http://127.0.0.1:1/leak" }); res.end(); return; }
    if (behavior === "oversize") { res.writeHead(200, { "content-type": "application/json" }); res.end("x".repeat(1024 * 1024 + 1)); return; }
    return send(200, { code: 200, data: { version: "3.42.0-custom19" } });
  }
  if (url.pathname === "/api/admin/accounts/import-tasks" && req.method === "GET") return send(200, { code: 200, data: { items: [] } });
  if (url.pathname === "/api/admin/accounts/import-tasks" && req.method === "POST") {
    if (expireImportAuth) { expireImportAuth = false; return send(401, { code: 401 }); }
    imports += 1;
    assert.match(body.submissionId, /^[a-f0-9-]{36}$/);
    assert.equal(body.items.length, 1);
    assert.equal(body.items[0].provider, "openai");
    assert.deepEqual(Object.keys(body.items[0]).sort(), ["data", "provider", "settings"]);
    assert.doesNotMatch(JSON.stringify(body.items[0].data), /proxy_key|proxies|login-proxy|routing|password/);
    let taskId = submissions.get(body.submissionId);
    if (!taskId) {
      taskId = crypto.randomUUID(); submissions.set(body.submissionId, taskId);
      tasks.set(taskId, { behavior, attempts: 1 });
    }
    if (behavior === "disconnect") { req.socket.destroy(); return; }
    return send(202, { code: 200, data: { taskId, counts: { pending: 1 }, finishedAt: null } });
  }
  if (url.pathname === "/api/admin/accounts/import-tasks/retry" && req.method === "POST") {
    assert.equal(body.index, 0);
    const task = tasks.get(body.taskId);
    assert.ok(task); task.attempts += 1; retries += 1;
    return send(202, { code: 200, data: detail(body.taskId, task) });
  }
  if (url.pathname === "/api/admin/accounts/import-tasks/detail") {
    const taskId = url.searchParams.get("taskId");
    const task = tasks.get(taskId);
    if (!task || task.behavior === "lost") return send(404, { code: 404 });
    return send(200, { code: 200, data: detail(taskId, task) });
  }
  send(404, { code: 404 });
  function send(status, payload) { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(payload)); }
  function detail(taskId, task) {
    const pending = task.behavior === "slow";
    const failed = task.behavior === "always-fail" || (task.behavior === "retry" && task.attempts < 2);
    const unknown = task.behavior === "unknown";
    const status = pending ? "running" : unknown ? "unknown" : failed ? "failed" : "succeeded";
    return { taskId, finishedAt: pending ? null : new Date().toISOString(), counts: { [status]: 1 }, items: [{ index: 0, provider: "openai", status, accountIds: status === "succeeded" ? ["acct_mock"] : [], canRetry: failed, message: `untrusted ${password} ${cookie} access-token-private` }] };
  }
});
await new Promise((resolve) => remote.listen(0, "127.0.0.1", resolve));
const baseUrl = `http://127.0.0.1:${remote.address().port}`;
const config = { baseUrl, authType: "password", username: "admin", password, autoUpload: false };

let afterReadExport;
try {
  seedCrsConfiguration(database, config);
  service = create();
  service.putConfiguration({ ...config, autoUpload: true }, 1);
  const deferred = job("deferred"); deferred.loginDeferred = true;
  await service.authorizationCompleted(deferred);
  assert.equal(service.status().items.length, 0, "global auto-upload cannot enqueue a saved-only account");
  await assert.rejects(service.enqueue([deferred.id]), /仅记录/);
  assert.equal(imports, 0);

  const changed = job("changed-during-read");
  afterReadExport = (item) => { item.loginDeferred = true; };
  await assert.rejects(service.enqueue([changed.id]), /仅记录/, "a pause racing an export read prevents publication");
  assert.equal(service.status().items.length, 0);

  const pending = job("paused-before-worker");
  assert.equal((await service.enqueue([pending.id])).queued, 1);
  pending.loginDeferred = true;
  await service.close(); service = create();
  await state(pending.id, "failed");
  assert.equal(imports, 0, "restart must not submit a persisted pending export while the account is saved-only");
  assert.throws(() => service.retry([pending.id]), /仅记录/);
  assert.equal(imports, 0);
  pending.loginDeferred = false;
  assert.equal(service.retry([pending.id]).queued, 1);
  await state(pending.id, "succeeded");
  assert.equal(imports, 1, "explicitly resumed accounts can publish again");
  console.log("CRS save-only guards: auto/manual enqueue, concurrent pause, durable pending worker and retry passed");
} finally {
  await service?.close(); database.close();
  await new Promise((resolve) => remote.close(resolve));
  await fs.rm(temporaryRoot, { recursive: true, force: true });
}

function create() { return createCrsIntegration({ database, getJob: (id) => jobs.get(id), readExport: async (item) => { afterReadExport?.(item); afterReadExport = null; return item.exportData; }, requestTimeoutMs: 300, pollIntervalMs: 5, taskTimeoutMs: 80 }); }
function job(label) {
  const id = crypto.randomUUID();
  const email = `${label}@example.invalid`;
  const value = { id, email, resultSaved: true, exportData: { type: "sub2api-data", proxies: [{ password: "login-proxy-private" }], accounts: [{ name: email, proxy_key: "login-proxy-private", routing: "private", credentials: { email, access_token: "access-token-private", refresh_token: `refresh-token-private-${label}`, password: "login-password-private" } }] } };
  jobs.set(id, value); return value;
}
async function state(id, status) { return waitFor(() => service.status().items.find((entry) => entry.jobId === id)?.status === status); }
async function waitFor(operation) {
  const deadline = Date.now() + 8000;
  while (Date.now() < deadline) { const result = await operation(); if (result) return result; await new Promise((resolve) => setTimeout(resolve, 5)); }
  throw new Error("CRS test state timed out");
}
