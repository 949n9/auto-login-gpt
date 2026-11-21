import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { createServerDatabase } from "../src/server-database.mjs";

const root = path.resolve(import.meta.dirname, "..");
const temporary = await fs.mkdtemp(path.join(os.tmpdir(), "console-save-only-"));
const output = path.join(temporary, "jobs");
const observationsPath = path.join(temporary, "observations.jsonl");
const socks = "socks5h://synthetic-user:synthetic-proxy-pass@proxy.example.invalid:1080";
const password = "synthetic-account-password";
const secret = "JBSWY3DPEHPK3PXP";
const submissions = [], tasks = new Map(), remoteRequests = [];
const remote = http.createServer(async (request, response) => {
  let bytes = ""; for await (const chunk of request) bytes += chunk;
  const body = bytes ? JSON.parse(bytes) : {};
  const url = new URL(request.url, "http://127.0.0.1");
  remoteRequests.push(url.pathname);
  const send = (status, data) => { response.writeHead(status, { "content-type": "application/json" }); response.end(JSON.stringify({ code: 200, data })); };
  if (url.pathname === "/api/admin/account-groups/options") return send(200, { items: [{ id: "openai", name: "OpenAI", enabled: true }], page: { totalPages: 1 } });
  if (url.pathname === "/api/admin/proxies") return send(200, { items: [{ id: "socks-local", endpoint: "socks5://proxy.example.invalid:1080", hasAuthentication: true, enabled: true }], page: { page: 1, totalPages: 1 } });
  if (url.pathname === "/api/admin/accounts/import-tasks" && request.method === "POST") {
    submissions.push(body); tasks.set(body.submissionId, body);
    return send(202, { taskId: body.submissionId });
  }
  if (url.pathname === "/api/admin/accounts/import-tasks/detail") {
    const taskId = url.searchParams.get("taskId");
    return send(200, { taskId, finishedAt: new Date().toISOString(), items: [{ index: 0, status: "succeeded", accountIds: [`remote-${taskId}`] }] });
  }
  return send(404, {});
});
await new Promise((resolve) => remote.listen(0, "127.0.0.1", resolve));
const portServer = net.createServer();
await new Promise((resolve) => portServer.listen(0, "127.0.0.1", resolve));
const port = portServer.address().port;
await new Promise((resolve) => portServer.close(resolve));
const baseUrl = `http://127.0.0.1:${port}`;
let child, exited, headers, logs = "";
try {
  await start();
  await request("/api/crs/config", { config: { baseUrl: `http://127.0.0.1:${remote.address().port}`, authType: "apiKey", apiKey: "test-admin-key", autoUpload: true }, revision: 0 }, "PUT");
  const plain = (await request("/api/jobs", { email: "plain@example.invalid", startLogin: false })).job;
  assert.equal(plain.status, "ready"); assert.equal(plain.loginDeferred, true); assert.equal(plain.proxyConfigured, false);
  await request("/api/jobs", { email: "mailbox-not-polled@example.invalid", mailApiUrl: `http://127.0.0.1:${remote.address().port}/messages`, startLogin: false });
  const first = (await request("/api/jobs", { email: "saved-first@example.invalid", password, totpSecret: secret, proxyUrl: socks, startLogin: false })).job;
  assert.equal(first.canRotateTotp, true, "saved credentials permit security without OAuth");
  const batch = await request("/api/jobs/batch", { text: `saved-first@example.invalid\nbatch@example.invalid----${password}----${secret}\nBATCH@example.invalid----${password}----${secret}`, startLogin: false });
  assert.equal(batch.created, 1); assert.equal(batch.updated, 1);
  const firstAgain = batch.jobs.find((job) => job.id === first.id);
  assert.equal(firstAgain.proxyEndpoint, "socks5h://proxy.example.invalid:1080", "omitted batch proxy preserves the account proxy");
  assert.equal(firstAgain.hasTotpKey, true, "email-only import preserves credentials");
  assert.equal(firstAgain.autoRepairEligible, false);
  assert.match(firstAgain.autoRepairEligibilityReason, /仅记录/);
  await request("/api/jobs", { email: plain.email, password, totpSecret: secret, startLogin: false });
  assert.equal((await request(`/api/jobs/${plain.id}/details`)).canRotateTotp, true, "email-only saved record can later receive credentials");
  for (const flag of ["false", 0, null]) {
    await rejected("/api/jobs", { email: "bad-flag@example.invalid", startLogin: flag }, 400);
    await rejected("/api/jobs/batch", { text: "bad-flag@example.invalid", startLogin: flag }, 400);
  }
  await rejected("/api/jobs", { email: "dynamic-save@example.invalid", startLogin: false, proxyUrl: { dynamicProfileId: "must-not-resolve" } }, 400);
  const duplicates = await Promise.all(Array.from({ length: 5 }, () => request("/api/jobs", { email: "unique@example.invalid", startLogin: false })));
  assert.equal(duplicates.filter((result) => result.created).length, 1);
  assert.equal(new Set(duplicates.map((result) => result.job.id)).size, 1);
  assert.equal((await observations()).length, 0, "save-only imports never launch a protocol child"); assert.equal(submissions.length, 0);
  assert.equal(remoteRequests.length, 0, "recording accounts never queries mailbox, proxy, or CPR APIs");
  await stop(); await start();
  for (const id of [first.id, plain.id]) assert.equal((await request(`/api/jobs/${id}/details`)).loginDeferred, true, "deferred state survives restart");
  const bridge = await fetch(baseUrl + "/api/integrations/crs/login", { method: "POST", headers: { "content-type": "application/json", authorization: "Bearer scheduled-test-bridge" }, body: JSON.stringify({ operationId: "saved-only-bridge", email: first.email }) });
  assert.equal(bridge.status, 202); assert.equal((await bridge.json()).status, "failed");
  assert.equal((await observations()).length, 0, "bridge cannot start saved-only accounts");
  await rejected(`/api/jobs/${plain.id}/security`, { action: "rotate-totp" }, 409);
  await rejected(`/api/jobs/${first.id}/retry`, { proxyUrl: "malformed-proxy" }, 400);
  assert.equal((await request(`/api/jobs/${first.id}/details`)).loginDeferred, true, "invalid resume options do not clear the saved-only pause");
  await request(`/api/jobs/${first.id}/security`, { action: "rotate-totp", proxyUrl: socks });
  await waitFor(async () => (await request(`/api/jobs/${first.id}/details`)).securityOperation?.status === "completed");
  const afterSecurity = await request(`/api/jobs/${first.id}/details`);
  assert.equal(afterSecurity.loginDeferred, true); assert.equal(afterSecurity.status, "ready");
  assert.equal(afterSecurity.securityOperation.credentialsUpdatedAt !== null, true);
  assert.equal((await observations()).filter((entry) => entry.email === first.email).map((entry) => entry.action).join(), "rotate-totp");
  assert.equal(submissions.length, 0, "standalone rotation never triggers global auto-upload");
  const db = createServerDatabase({ outputRoot: output, mustExist: true });
  try { assert.equal(db.loadCredentials(first.email).totpSecret, "NB2W45DFOIZAQWER"); } finally { db.close(); }
  await stop(); await start();
  assert.equal((await request(`/api/jobs/${first.id}/details`)).loginDeferred, true);
  await request(`/api/jobs/${first.id}/relogin`, {});
  await waitFor(async () => (await request(`/api/jobs/${first.id}/details`)).status === "completed");
  await waitFor(async () => submissions.length === 1);
  assert.equal((await request(`/api/jobs/${first.id}/details`)).loginDeferred, false);
  await waitFor(async () => (await request("/api/crs/status")).items.some((item) => item.jobId === first.id && item.status === "succeeded"));
  await request("/api/jobs", { email: first.email, startLogin: false });
  await rejected("/api/crs/upload", { ids: [first.id] }, 409);
  assert.equal(submissions.length, 1, "an old OAuth result cannot bypass the saved-only pause");
  const plannedJob = batch.jobs.find((job) => job.email.toLowerCase() === "batch@example.invalid");
  const scheduled = await request("/api/schedules", { ...input(plannedJob.email, 6500, "rotate-totp"), text: plannedJob.email });
  await waitFor(async () => (await detail(scheduled)).items[0].status === "waiting");
  assert.equal((await request(`/api/jobs/${plannedJob.id}/details`)).loginDeferred, true, "preparation preserves saved-only state");
  await rejected("/api/jobs", { email: plannedJob.email, startLogin: false }, 409);
  assert.equal((await detail(scheduled)).items[0].status, "waiting", "save-only import does not cancel an existing plan");
  await waitFor(async () => (await detail(scheduled)).items[0].status === "completed");
  assert.equal((await request(`/api/jobs/${plannedJob.id}/details`)).loginDeferred, false, "due scheduled login explicitly resumes");
  assert.equal(submissions.length, 2);
  const active = (await request("/api/jobs", { email: "hold-active@example.invalid", password, totpSecret: secret, proxyUrl: socks })).job;
  await waitFor(async () => (await observations()).some((entry) => entry.email === active.email));
  await rejected("/api/jobs", { email: active.email, startLogin: false }, 409);
  await rejected("/api/jobs/batch", { text: `new-rejected@example.invalid\n${active.email}`, startLogin: false }, 409);
  const page = await request("/api/jobs");
  assert.equal(page.jobs.some((job) => job.email === "new-rejected@example.invalid"), false, "batch conflict does not partially import");
  await request(`/api/jobs/${active.id}/cancel`, {});
  assert.equal((await observations()).filter((entry) => entry.email === active.email).length, 1, "save-only conflict never restarts active work");
  const failure = (await request("/api/jobs", { email: "fail-proxy@example.invalid", password, totpSecret: secret, startLogin: false })).job;
  await request(`/api/jobs/${failure.id}/security`, { action: "rotate-totp-logout-all", proxyUrl: socks });
  await waitFor(async () => (await request(`/api/jobs/${failure.id}/details`)).securityOperation?.status === "failed");
  const diagnosed = await request(`/api/jobs/${failure.id}/details`);
  assert.match(diagnosed.securityOperation.error, /SOCKS5.*认证失败.*HTTP 407/);
  assert.doesNotMatch(diagnosed.securityOperation.error, /退出代码 1|DO-NOT-EXPOSE|synthetic-account-password|secret@/);
  await stop(); await start();
  assert.equal((await request(`/api/jobs/${failure.id}/details`)).securityOperation.error, diagnosed.securityOperation.error, "classified failure persists across restart");
  const publicData = JSON.stringify(await request("/api/jobs")) + JSON.stringify(await request(`/api/jobs/${first.id}/details`));
  for (const value of [password, secret, "NB2W45DFOIZAQWER", "synthetic-proxy-pass"]) assert.equal(publicData.includes(value), false);
  console.log("save-only console: atomic single/batch import, optional proxy, restart, bridge pause, independent rotation, manual/scheduled resume and conflict guards passed");
} catch (error) { console.error(logs.slice(-5000)); throw error; }
finally { await stop(); await new Promise((resolve) => remote.close(resolve)); await fs.rm(temporary, { recursive: true, force: true }); }

async function rejected(endpoint, body, expected) {
  const response = await fetch(baseUrl + endpoint, { method: "POST", headers, body: JSON.stringify(body) });
  assert.equal(response.status, expected, `${endpoint}: ${JSON.stringify(await response.json())}`);
}

function input(email, ahead, securityAction = null) {
  return { clientRequestId: crypto.randomUUID(), text: `${email}----${password}----${secret}`, proxyUrl: socks,
    scheduledLocal: new Date(Date.now() + ahead + 8 * 3600000).toISOString().slice(0, 19), timeZone: "Asia/Shanghai", prepareLeadMinutes: 30, postLogoutDelayMinutes: 0, securityAction };
}
async function request(endpoint, body, method = body === undefined ? "GET" : "POST") {
  const response = await fetch(baseUrl + endpoint, { method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  const data = await response.json();
  assert.ok(response.ok, `${endpoint}: ${response.status} ${JSON.stringify(data)}`);
  return data;
}
async function detail(value) { return request(`/api/schedules/${value.schedule.id}`); }
async function observations() { try { return (await fs.readFile(observationsPath, "utf8")).split("\n").filter(Boolean).map(JSON.parse); } catch (error) { if (error.code === "ENOENT") return []; throw error; } }
async function start() {
  child = spawn(process.execPath, ["src/console-server.mjs", "--host", "127.0.0.1", "--port", String(port)], { cwd: root, env: { ...process.env, NODE_ENV: "production", ONBOARDING_OUTPUT_ROOT: output, ONBOARDING_PROTOCOL_SCRIPT: path.join(root, "test/mock-save-only-protocol.mjs"), SCHEDULE_TEST_OBSERVATIONS: observationsPath, CRS_LOGIN_BRIDGE_KEY: "scheduled-test-bridge", TOSUB2_REQUIRE_SOCKS5: "1", TOSUB2_PIN_PROXY_SESSION: "1" }, stdio: ["ignore", "pipe", "pipe"] });
  exited = new Promise((resolve) => child.once("exit", resolve));
  child.stdout.on("data", (chunk) => { logs += chunk; }); child.stderr.on("data", (chunk) => { logs += chunk; });
  const bootstrap = await waitFor(async () => { if (child.exitCode !== null) throw new Error(`console exited: ${logs}`); try { const response = await fetch(baseUrl + "/api/bootstrap"); return response.ok ? response.json() : null; } catch { return null; } });
  headers = { "content-type": "application/json", "x-console-token": bootstrap.token };
}
async function stop() {
  if (!child || child.exitCode !== null || child.signalCode) return;
  const processToStop = child;
  processToStop.kill("SIGTERM");
  const timer = setTimeout(() => processToStop.kill("SIGKILL"), 5000);
  try { await exited; } finally { clearTimeout(timer); }
}
async function waitFor(check) { const deadline = Date.now() + 22000; while (Date.now() < deadline) { const value = await check(); if (value) return value; await delay(60); } throw new Error("schedule state timeout"); }
function delay(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }
