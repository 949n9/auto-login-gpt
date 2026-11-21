import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { createCrsIntegration, makeCrsExport, seedCrsConfiguration } from "../src/crs-integration.mjs";
import { createServerDatabase } from "../src/server-database.mjs";

const temporaryRoot = await fs.mkdtemp(path.join(os.tmpdir(), "tosub2-crs-"));
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

try {
  const seeded = seedCrsConfiguration(database, { ...config, autoUpload: true });
  assert.equal(seeded.config.autoUpload, false);
  assert.equal(imports, 0, "preconfiguration performs no account import");
  assert.deepEqual(seedCrsConfiguration(database, { baseUrl: "invalid" }), seeded, "seeding never overwrites configured server");
  service = create();
  const publicConfig = service.getConfiguration();
  assert.equal(publicConfig.config.hasPassword, true);
  assert.doesNotMatch(JSON.stringify(publicConfig), new RegExp(password));
  const preserved = service.putConfiguration({ ...config, password: "" }, 1);
  assert.equal(preserved.revision, 2);
  assert.equal(preserved.config.hasPassword, true);
  assert.equal(service.putConfiguration(config, 1).conflict, true);
  assert.throws(() => service.putConfiguration({ ...config, username: "changed", password: "" }, 2), /重新填写/);
  assert.throws(() => service.putConfiguration({ ...config, baseUrl: "http://127.0.0.1:1", password: "" }, 2), /重新填写/);
  assert.throws(() => service.putConfiguration({ ...config, baseUrl: `${baseUrl}/path` }, 2), /根地址/);
  const beforeDraft = service.getConfiguration();
  assert.equal((await service.testConfiguration(config)).version, "3.42.0-custom19");
  assert.deepEqual(service.getConfiguration(), beforeDraft, "testing a draft does not persist it");
  const readonlyCount = requests.filter((request) => request.path.includes("import-tasks") && request.method === "POST").length;
  assert.equal(readonlyCount, 0, "connection testing performs no imports");

  const first = job("first");
  assert.equal((await service.enqueue([first.id])).queued, 1);
  await state(first.id, "succeeded");
  assert.equal(imports, 1);
  const firstRequest = requests.find((request) => request.path.endsWith("import-tasks") && request.method === "POST").body.items[0];
  assert.deepEqual(firstRequest.settings.groupIds, ["group-openai"]);
  assert.equal(firstRequest.settings.concurrencyLimit, 7);
  assert.equal(firstRequest.settings.credentialGuardian.enabled, false);
  assert.deepEqual(service.status().items.find((item) => item.jobId === first.id).accountIds, ["acct_mock"]);
  const originalSubmissionId = requests.find((request) => request.path.endsWith("import-tasks") && request.method === "POST").body.submissionId;
  assert.equal((await service.enqueue([first.id])).skipped, 1);
  assert.equal(imports, 1);
  const reversed = { ...first.exportData, accounts: [{ ...first.exportData.accounts[0], credentials: Object.fromEntries(Object.entries(first.exportData.accounts[0].credentials).reverse()) }] };
  assert.deepEqual(makeCrsExport(reversed), makeCrsExport(first.exportData));
  first.exportData = reversed;
  assert.equal((await service.enqueue([first.id])).skipped, 1, "credential key order does not defeat content deduplication");
  await service.close();
  service = create();
  assert.equal((await service.enqueue([first.id])).skipped, 1, "successful deduplication survives process restart");

  // Pending survives a shutdown before the worker starts.
  const pending = job("pending");
  await service.enqueue([pending.id]);
  await service.close();
  assert.equal(database.get("runtime", "crs-outbox").entries.find((entry) => entry.jobId === pending.id).status, "pending");
  service = create();
  await state(pending.id, "succeeded");
  const deleted = job("deleted-before-submit");
  const importsBeforeDelete = imports;
  await service.enqueue([deleted.id]);
  jobs.delete(deleted.id);
  await state(deleted.id, "failed");
  assert.equal(imports, importsBeforeDelete, "deleting a pending local account prevents its first upload");
  await service.close();
  service = create();
  const deletedDuringLogin = job("deleted-during-login");
  await service.groups();
  expireImportAuth = true;
  afterLogin = () => jobs.delete(deletedDuringLogin.id);
  await service.enqueue([deletedDuringLogin.id]);
  await state(deletedDuringLogin.id, "failed");
  assert.equal(imports, importsBeforeDelete, "deleting during asynchronous authentication prevents the following import POST");
  const pausedDuringLogin = job("paused-during-login");
  expireImportAuth = true;
  afterLogin = () => { pausedDuringLogin.resting = true; };
  await service.enqueue([pausedDuringLogin.id]);
  await state(pausedDuringLogin.id, "unknown");
  assert.equal(imports, importsBeforeDelete, "moving during authentication prevents the following import POST");

  behavior = "retry";
  const retryJob = job("retry");
  await service.enqueue([retryJob.id]);
  await state(retryJob.id, "succeeded");
  assert.equal(retries, 1);
  const retryEntry = database.get("runtime", "crs-outbox").entries.find((entry) => entry.jobId === retryJob.id);
  assert.equal(retryEntry.attempts, 2);
  const retryPosts = requests.filter((request) => request.method === "POST" && request.body.submissionId === retryEntry.submissionId);
  assert.equal(retryPosts.length, 1, "known failures retry the existing remote task without a second submission");

  behavior = "always-fail";
  const bounded = job("bounded");
  await service.enqueue([bounded.id]);
  await state(bounded.id, "failed");
  await waitFor(() => database.get("runtime", "crs-outbox").entries.find((entry) => entry.jobId === bounded.id).attempts === 3);
  assert.equal(service.retry([bounded.id]).queued, 0, "known failure retry limit is durable and bounded");

  behavior = "disconnect";
  const ambiguous = job("ambiguous");
  await service.enqueue([ambiguous.id]);
  await state(ambiguous.id, "unknown");
  await service.saveAccountSettings([ambiguous.id], { groupIds: ["group-special"], concurrencyLimit: 9 });
  await assert.rejects(service.enqueue([ambiguous.id]), /未确认/, "changed settings cannot bypass ambiguous-submission protection");
  const afterAmbiguous = imports;
  await new Promise((resolve) => setTimeout(resolve, 60));
  assert.equal(imports, afterAmbiguous, "a potentially committed submission is never blindly replayed");
  assert.equal(service.retry().queued, 0, "retry all does not retry unknown results");
  behavior = "success";
  assert.equal(service.retry([ambiguous.id]).queued, 1);
  await state(ambiguous.id, "succeeded");
  const repeated = requests.filter((request) => request.method === "POST" && request.body.submissionId === database.get("runtime", "crs-outbox").entries.find((entry) => entry.jobId === ambiguous.id).submissionId);
  assert.equal(repeated.length, 2);
  assert.equal(tasks.size, imports - 1, "explicit unknown retry reuses the remote submission identifier");

  behavior = "lost";
  const lost = job("lost"); await service.enqueue([lost.id]); await state(lost.id, "unknown");
  behavior = "unknown";
  const unknown = job("unknown"); await service.enqueue([unknown.id]); await state(unknown.id, "unknown");
  const beforeReconcile = imports;
  const unknownEntry = database.get("runtime", "crs-outbox").entries.find((entry) => entry.jobId === unknown.id);
  tasks.get(unknownEntry.taskId).behavior = "success";
  assert.equal(service.retry([unknown.id]).queued, 1);
  await state(unknown.id, "succeeded");
  assert.equal(imports, beforeReconcile, "unknown entries with a task ID reconcile the existing task without resubmission");
  assert.doesNotMatch(JSON.stringify(service.status()), /mock-crs-password-private|mock-crs-session-private|access-token-private|refresh-token-private/);
  behavior = "slow";
  const slow = job("slow"); await service.enqueue([slow.id]); await state(slow.id, "unknown");

  behavior = "success";
  const countBeforeAuto = imports;
  const autoConfig = service.putConfiguration({ ...config, password: "", autoUpload: true }, 2);
  assert.equal(autoConfig.revision, 3);
  await new Promise((resolve) => setTimeout(resolve, 30));
  assert.equal(imports, countBeforeAuto, "enabling auto upload does not backfill historical authorizations");
  const automatic = job("automatic");
  await service.authorizationCompleted(automatic);
  await state(automatic.id, "succeeded");
  automatic.exportData.accounts[0].credentials.access_token = "new-access-token-private";
  await service.authorizationCompleted(automatic);
  await state(automatic.id, "succeeded");
  assert.equal(service.status().items.filter((entry) => entry.jobId === automatic.id).length, 1, "public status shows only the latest authorization for each job");
  assert.equal(database.get("runtime", "crs-outbox").entries.filter((entry) => entry.jobId === automatic.id).length, 2);

  behavior = "redirect";
  await assert.rejects(service.testConfiguration(config));
  behavior = "oversize";
  await assert.rejects(service.testConfiguration(config), /大小限制/);
  behavior = "success";
  const apiKeyConfig = service.putConfiguration({ baseUrl, authType: "apiKey", apiKey, autoUpload: false }, 3);
  assert.equal(apiKeyConfig.config.hasApiKey, true);
  assert.equal(apiKeyConfig.config.hasPassword, false);
  const previousLogins = logins;
  assert.equal((await service.testConfiguration()).ok, true);
  assert.equal(logins, previousLogins, "API key authentication does not use session login");
  assert.throws(() => service.retry([lost.id]), /身份已改变/, "old uploads cannot silently move to a different login identity");
  const badPasswordConfig = service.putConfiguration({ ...config, password: "incorrect-private-password" }, 4);
  assert.equal(badPasswordConfig.revision, 5);
  const authenticationFailed = job("auth-failed");
  const beforeRejectedImport = imports;
  await assert.rejects(service.enqueue([authenticationFailed.id]), /HTTP 401/);
  assert.equal(imports, beforeRejectedImport, "failed authentication does not submit account data");
  service.putConfiguration(config, 5);
  assert.equal((await service.enqueue([authenticationFailed.id])).queued, 1);
  await state(authenticationFailed.id, "succeeded");
  assert.equal(database.get("runtime", "crs-outbox").entries.find((entry) => entry.jobId === authenticationFailed.id).target.password, password, "same-target manual retry refreshes changed credentials");
  const configured = job("configured");
  await service.saveAccountSettings([configured.id], { groupIds: ["group-special"], concurrencyLimit: 11, weight: 23, credentialGuardian: { enabled: true } });
  await service.enqueue([configured.id]);
  await state(configured.id, "succeeded");
  const savedEntry = database.get("runtime", "crs-outbox").entries.find((entry) => entry.jobId === configured.id);
  assert.equal(savedEntry.settings.concurrencyLimit, 11);
  assert.equal(savedEntry.settings.weight, 23);
  const submittedSettings = requests.find((request) => request.method === "POST" && request.body.submissionId === savedEntry.submissionId).body.items[0].settings;
  assert.equal(submittedSettings.concurrencyLimit, 11);
  assert.equal(submittedSettings.weight, 23);
  assert.deepEqual(submittedSettings.credentialGuardian, { enabled: true });
  assert.deepEqual(savedEntry.settings.credentialGuardian, { enabled: true }, "upload changes the guardian switch without resetting remote policy");
  assert.deepEqual(savedEntry.settings.groupIds, ["group-special"]);
  await service.close(); service = create();
  assert.equal(service.accountSettings().settings[configured.id].concurrencyLimit, 11);
  assert.equal(service.accountSettings().settings[configured.id].weight, 23);
  await assert.rejects(service.saveAccountSettings([configured.id], { groupIds: ["group-special"], weight: 101 }), /优先级/);
  const restingJob = job("resting-blocked"); restingJob.resting = true;
  await assert.rejects(service.enqueue([restingJob.id]), /静置区/);
  mockGroups = [{ id: "group-special", name: "专用", enabled: true }];
  assert.deepEqual((await service.groups()).defaultGroupIds, []);
  await assert.rejects(service.enqueue([job("missing-default").id]), /分组/);
  await assert.rejects(service.saveAccountSettings([configured.id], { groupIds: [], concurrencyLimit: 7 }), /分组/);
  await assert.rejects(service.saveAccountSettings([configured.id], { groupIds: ["group-special"], concurrencyLimit: 0 }), /并发/);
  mockGroups = [{ id: "group-openai", name: "OpenAI", enabled: true }, { id: "group-special", name: "专用", enabled: true }];
  await service.close();
  assert.throws(() => service.retry([first.id]), /关闭/);
  await assert.rejects(service.enqueue([first.id]), /关闭/);
  assert.match(originalSubmissionId, /^[a-f0-9-]{36}$/);
  const capacityRoot = path.join(temporaryRoot, "capacity");
  const capacityDatabase = createServerDatabase({ outputRoot: capacityRoot });
  seedCrsConfiguration(capacityDatabase, config);
  const historical = Array.from({ length: 1999 }, (_, index) => ({ id: `history-${index}`, jobId: `history-${index}`, email: "history@example.invalid", hash: `history-${index}`, target: config, status: "succeeded", updatedAt: new Date().toISOString() }));
  capacityDatabase.put("runtime", "crs-outbox", { entries: historical });
  const capacityService = createCrsIntegration({ database: capacityDatabase, getJob: (id) => jobs.has(id) ? { ...jobs.get(id) } : null, readExport: async (item) => item.exportData });
  const capacityFirst = job("capacity-first"); const capacitySecond = job("capacity-second");
  await assert.rejects(capacityService.enqueue([capacityFirst.id, capacitySecond.id]), /上限/);
  assert.equal(capacityService.status().items.length, 1999, "capacity rejection does not partially mutate the in-memory batch");
  assert.equal(capacityDatabase.get("runtime", "crs-outbox").entries.length, 1999, "capacity rejection does not partially persist a batch");
  await capacityService.close(); capacityDatabase.close();
  console.log("CRS private configuration, authentication, proxy stripping, durable outbox, deduplication, bounded retries, unknown results, auto-upload and shutdown tests passed");
} finally {
  await service?.close();
  database.close();
  await new Promise((resolve) => remote.close(resolve));
  await fs.rm(temporaryRoot, { recursive: true, force: true });
}

function create() { return createCrsIntegration({ database, getJob: (id) => jobs.has(id) ? { ...jobs.get(id) } : null, readExport: async (item) => item.exportData, requestTimeoutMs: 300, pollIntervalMs: 5, taskTimeoutMs: 80 }); }
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
