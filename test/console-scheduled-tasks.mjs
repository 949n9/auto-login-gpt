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
const temporary = await fs.mkdtemp(path.join(os.tmpdir(), "console-schedules-"));
const output = path.join(temporary, "jobs");
const observationsPath = path.join(temporary, "observations.jsonl");
const socks = "socks5h://synthetic-user:synthetic-proxy-pass@proxy.example.invalid:1080";
const password = "synthetic-account-password";
const secret = "JBSWY3DPEHPK3PXP";
const submissions = [], tasks = new Map();
const remote = http.createServer(async (request, response) => {
  let bytes = ""; for await (const chunk of request) bytes += chunk;
  const body = bytes ? JSON.parse(bytes) : {};
  const url = new URL(request.url, "http://127.0.0.1");
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
  const draft = input("scheduled-first@example.invalid", 9000, "rotate-totp-logout-all");
  const preview = await request("/api/schedules/preview", draft);
  assert.equal(preview.validCount, 1);
  assert.equal(preview.crsSettings.concurrencyLimit, 20);
  assert.equal(preview.crsSettings.weight, 99);
  assert.equal(preview.crsSettings.credentialGuardian.enabled, true);
  const invalid = await request("/api/schedules/preview", { ...draft, proxyUrl: "http://proxy.example.invalid:8080" });
  assert.equal(invalid.invalidCount, 1);
  assert.equal(invalid.accounts[0].email, "scheduled-first@example.invalid");
  const created = await request("/api/schedules", draft);
  assert.equal((await request("/api/schedules", draft)).schedule.id, created.schedule.id);
  const item = created.items[0];
  await waitFor(async () => (await detail(created)).items[0].status === "waiting");
  assert.equal((await observations()).filter((entry) => entry.email === item.email && entry.action === "login").length, 0);
  assert.equal(submissions.length, 0, "global auto-upload must not publish during preparation");
  const waiting = (await detail(created)).items[0];
  assert.ok(waiting.logoutAcceptedAt);
  assert.ok(Date.parse(waiting.loginNotBefore) >= Date.parse(created.schedule.plannedAt));
  await stop();
  await start();
  await waitFor(async () => (await detail(created)).items[0].status === "completed");
  const seen = (await observations()).filter((entry) => entry.email === item.email);
  assert.deepEqual(seen.map((entry) => entry.action), ["rotate-totp-logout-all", "login"]);
  assert.ok(Date.parse(seen[1].at) >= Date.parse(created.schedule.plannedAt));
  assert.deepEqual(seen[0].tls, seen[1].tls);
  assert.equal(seen[1].proxy, socks);
  assert.equal(submissions.length, 1);
  assert.equal(submissions[0].items[0].settings.weight, 99);
  assert.equal(submissions[0].items[0].settings.concurrencyLimit, 20);
  assert.equal(submissions[0].items[0].settings.credentialGuardian.enabled, true);
  await stop(); await start(); await delay(1200);
  assert.equal(submissions.length, 1, "restart must not publish twice");

  const cancel = await request("/api/schedules", input("cancel-planned@example.invalid", 60000));
  await request(`/api/schedules/${cancel.schedule.id}/cancel`, { itemIds: [cancel.items[0].id] });
  assert.equal((await detail(cancel)).items[0].status, "canceled");
  assert.equal((await observations()).some((entry) => entry.email === cancel.items[0].email), false);

  const manual = await request("/api/schedules", input("manual-override@example.invalid", 60000));
  await request(`/api/jobs/${manual.items[0].jobId}/relogin`, {});
  assert.equal((await detail(manual)).items[0].status, "superseded");

  const bad = await request("/api/schedules", input("uncertain-logout@example.invalid", 60000, "logout-all"));
  await waitFor(async () => (await detail(bad)).items[0].status === "needs_attention");
  assert.equal((await observations()).filter((entry) => entry.email === bad.items[0].email).length, 1);
  const retry = await request("/api/schedules", input("email-retry-one@example.invalid", 2000));
  await waitFor(async () => (await detail(retry)).items[0].status === "failed");
  const retryJob = await request(`/api/jobs/${retry.items[0].jobId}/details`);
  assert.equal(retryJob.emailLoginAttempt, 3);
  assert.equal(retryJob.emailLoginReason, "EMAIL_OTP_REQUIRED");
  assert.match(retryJob.lastError, /3.*邮箱/);
  assert.equal(retryJob.emailLoginAutoPaused, true);
  assert.equal((await observations()).filter(entry => entry.email === retry.items[0].email && entry.action === 'login').length, 4, 'email challenge must receive three complete-login retries');
  await stop(); await start();
  assert.equal((await request(`/api/jobs/${retry.items[0].jobId}/details`)).emailLoginAutoPaused, true, "email retry stop survives restart");
  const beforeBridge = (await observations()).filter((entry) => entry.email === retry.items[0].email).length;
  for (let index = 0; index < 2; index++) {
    const response = await fetch(baseUrl + "/api/integrations/crs/login", { method: "POST", headers: { "content-type": "application/json", authorization: "Bearer scheduled-test-bridge" }, body: JSON.stringify({ operationId: `blocked-${index}`, email: retry.items[0].email }) });
    assert.equal(response.status, 202);
    assert.equal((await response.json()).status, "failed");
  }
  assert.equal((await observations()).filter((entry) => entry.email === retry.items[0].email).length, beforeBridge, "automatic bridge cannot restart another three attempts");
  await request("/api/jobs", { email: retry.items[0].email, password: password + "-updated", totpSecret: secret });
  assert.equal((await request(`/api/jobs/${retry.items[0].jobId}/details`)).emailLoginAutoPaused, false, "explicit account update resumes automatic eligibility");
  const beforeRecoverySubmissions = submissions.length;
  const recover = await request('/api/schedules', input('email-retry-recover@example.invalid', 2000, 'rotate-totp-logout-all'));
  await waitFor(async () => (await detail(recover)).items[0].status === 'completed');
  const recovery = (await observations()).filter(entry => entry.email === recover.items[0].email);
  assert.deepEqual(recovery.map(entry => entry.action), ['rotate-totp-logout-all', 'login', 'login', 'login', 'login']);
  assert.equal((await request(`/api/jobs/${recover.items[0].jobId}/details`)).emailLoginAutoPaused, false);
  assert.equal(submissions.length, beforeRecoverySubmissions + 1, 'recovered schedule publishes once');
  const interrupted = await request("/api/schedules", input("email-security-interrupt-one@example.invalid", 60000, "rotate-totp"));
  const inspector = createServerDatabase({ outputRoot: output, mustExist: true });
  try {
    await waitFor(async () => {
      const metadata = inspector.getJob(interrupted.items[0].jobId);
      const owner = inspector.get("scheduled-task", interrupted.schedule.id).items[0];
      return metadata?.email_login_auto_paused === true && inspector.get("account-security-operation", owner.securityOperationId)?.status === "running";
    });
  } finally { inspector.close(); }
  child.kill("SIGKILL"); await exited;
  await start();
  await waitFor(async () => (await detail(interrupted)).items[0].status === "failed");
  const restoredInterrupted = await request(`/api/jobs/${interrupted.items[0].jobId}/details`);
  assert.equal(restoredInterrupted.emailLoginAutoPaused, true, "security restoration must not erase a durable retry pause before job hydration");
  assert.equal(restoredInterrupted.emailLoginAttempt, 3);
  const blockedAfterCrash = await fetch(baseUrl + "/api/integrations/crs/login", { method: "POST", headers: { "content-type": "application/json", authorization: "Bearer scheduled-test-bridge" }, body: JSON.stringify({ operationId: "blocked-after-security-crash", email: interrupted.items[0].email }) });
  assert.equal((await blockedAfterCrash.json()).status, "failed");
  const data = JSON.stringify(await request("/api/schedules")) + JSON.stringify(await detail(created));
  for (const sensitive of [password, secret, "NB2W45DFOIZAQWER", "synthetic-proxy-pass", "test-admin-key"]) assert.equal(data.includes(sensitive), false);
  const db = createServerDatabase({ outputRoot: output, mustExist: true });
  try { assert.equal(db.loadCredentials(item.email).totpSecret, "NB2W45DFOIZAQWER"); } finally { db.close(); }
  console.log("scheduled console: deferred import, BJT timing, safe preparation, restart, unique publication, cancellation, manual override and bounded email markers passed");
} catch (error) { console.error(logs.slice(-5000)); throw error; }
finally { await stop(); await new Promise((resolve) => remote.close(resolve)); await fs.rm(temporary, { recursive: true, force: true }); }

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
  child = spawn(process.execPath, ["src/console-server.mjs", "--host", "127.0.0.1", "--port", String(port)], { cwd: root, env: { ...process.env, TOSUB2_LOGIN_RETRY_DELAY_MS: "50", NODE_ENV: "production", ONBOARDING_OUTPUT_ROOT: output, ONBOARDING_PROTOCOL_SCRIPT: path.join(root, "test/mock-scheduled-protocol.mjs"), SCHEDULE_TEST_OBSERVATIONS: observationsPath, CRS_LOGIN_BRIDGE_KEY: "scheduled-test-bridge" }, stdio: ["ignore", "pipe", "pipe"] });
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
