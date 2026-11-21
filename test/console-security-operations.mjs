import assert from "node:assert/strict";
import fs from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { createServerDatabase } from "../src/server-database.mjs";

const root = path.resolve(import.meta.dirname, "..");
const temporaryRoot = await fs.mkdtemp(path.join(os.tmpdir(), "tosub2-security-api-"));
const output = path.join(temporaryRoot, "jobs");
const observationsPath = path.join(temporaryRoot, "observations.jsonl");
const listener = net.createServer();
await new Promise((resolve, reject) => { listener.once("error", reject); listener.listen(0, "127.0.0.1", resolve); });
const port = listener.address().port;
await new Promise((resolve) => listener.close(resolve));
const baseUrl = `http://127.0.0.1:${port}`;
const socks = "socks5h://test-user:test-proxy-secret@proxy.example.invalid:1080";
const otherSocks = "socks5://second-user:second-proxy-secret@other.example.invalid:1080";
const originalSecret = "JBSWY3DPEHPK3PXP";
const rotatedSecret = "NB2W45DFOIZAQWER";
const password = "TEST-only-password-security";
let child, childExit, headers, consoleLogs = "";

try {
  await start();
  const primary = await create("security-normal-one@example.invalid", socks);
  assert.equal((await fetch(`${baseUrl}/api/jobs/${primary.id}/security`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: "logout-all" }) })).status, 403);
  assert.equal((await api(`/api/jobs/${primary.id}/details`)).canRotateTotp, true);
  assert.equal((await api(`/api/jobs/${primary.id}/details`)).canLogoutAll, true);
  assert.equal((await api(`/api/jobs/${primary.id}/details`)).canRotateTotpLogoutAll, true);
  await post(`/api/jobs/${primary.id}/security`, { action: "not-an-operation" }, [400]);

  // A security mutation may never silently fall back to direct or HTTP transport.
  const noProxy = await create("security-direct-one@example.invalid", "");
  const httpProxy = await create("security-http-one@example.invalid", "http://proxy.example.invalid:8080");
  for (const job of [noProxy, httpProxy]) {
    await post(`/api/jobs/${job.id}/security`, { action: "logout-all" }, [400, 409]);
    await post(`/api/jobs/${job.id}/security`, { action: "rotate-totp" }, [400, 409]);
    assert.equal((await securityObservations(job.email)).length, 0, "invalid transport must reject before spawning");
  }

  await post(`/api/jobs/${primary.id}/security`, { action: "rotate-totp" });
  const first = await operationDone(primary.id);
  assert.equal(first.securityOperation.status, "completed");
  assert.equal(first.securityAutoLoginPaused, false, "rotating TOTP alone must not pause automatic login");
  assert.equal((await secrets(primary.id)).totpSecret, rotatedSecret);
  assert.equal((await secrets(primary.id)).password, password);
  assert.ok(first.securityOperations.some((operation) => operation.operationId === first.securityOperation.operationId && operation.action === "rotate-totp"));
  const loginObservation = (await observations()).find((item) => item.email === primary.email && item.action === "login");
  const rotateObservation = (await securityObservations(primary.email))[0];
  assert.deepEqual(rotateObservation.tlsIdentity, loginObservation.tlsIdentity, "account identity must survive a security operation");
  assert.equal(rotateObservation.proxy, socks);
  assert.equal(rotateObservation.pinProxySession, "1");
  assert.equal(rotateObservation.requireSocks5, "1");
  await assertPrivate(primary.id);

  await post(`/api/jobs/${primary.id}/security`, { action: "logout-all" });
  const loggedOut = await operationDone(primary.id, first.securityOperation.operationId);
  assert.equal(loggedOut.securityOperation.status, "completed");
  assert.equal(loggedOut.securityOperation.action, "logout-all");
  assert.equal(loggedOut.securityOperation.workResetSucceeded, true);
  assert.equal(loggedOut.securityAutoLoginPaused, true, "global logout must pause automatic login");
  assert.equal((await secrets(primary.id)).totpSecret, rotatedSecret, "logout must preserve the current TOTP key");
  assert.equal(loggedOut.securityOperations.length, 2);
  await assertPrivate(primary.id);
  await post(`/api/jobs/${primary.id}/relogin`, {});
  await waitFor(async () => (await api(`/api/jobs/${primary.id}/details`)).status === "completed");
  assert.equal((await api(`/api/jobs/${primary.id}/details`)).securityAutoLoginPaused, false, "explicit relogin must resume automatic login");

  // Same-account requests race under the real email lock, not a mocked HTTP handler.
  const slow = await create("security-slow-one@example.invalid", socks);
  const racing = await Promise.all(Array.from({ length: 2 }, () => request(`/api/jobs/${slow.id}/security`, { action: "rotate-totp" })));
  assert.equal(racing.filter((item) => [200, 202].includes(item.status)).length, 1);
  assert.equal(racing.filter((item) => item.status === 409).length, 1);
  await post(`/api/jobs/${slow.id}/relogin`, {}, [409]);
  await post("/api/jobs", { email: slow.email, proxyUrl: otherSocks }, [409]);
  await operationDone(slow.id);
  assert.equal((await securityObservations(slow.email)).length, 1);

  // Simulate a verified worker commit that the console has not loaded yet.
  const proxyOnly = await create("security-proxy-only-one@example.invalid", socks);
  const credentialWriter = createServerDatabase({ outputRoot: output, mustExist: true });
  try {
    const latest = credentialWriter.loadCredentials(proxyOnly.email);
    credentialWriter.saveCredentials(proxyOnly.email, { ...latest, totpSecret: rotatedSecret });
  } finally { credentialWriter.close(); }
  await post("/api/jobs", { email: proxyOnly.email, proxyUrl: otherSocks });
  assert.equal((await secrets(proxyOnly.id)).totpSecret, rotatedSecret, "proxy-only edit must preserve a worker's newer database key");

  const batchGood = await create("security-batch-one@example.invalid", socks);
  const batch = await post("/api/jobs/security/batch", { ids: [batchGood.id, noProxy.id], action: "logout-all" });
  assert.equal(batch.started, 1);
  assert.equal(batch.errors.length, 1, "invalid account must have its own batch error");
  assert.equal(batch.errors[0].id, noProxy.id);
  assert.equal((await operationDone(batchGood.id)).securityOperation.status, "completed");
  const selected = await post("/api/jobs/security/batch", {
    ids: [primary.id, batchGood.id], action: "logout-all",
    proxyAssignments: [{ id: batchGood.id, proxyUrl: socks }, { id: primary.id, proxyUrl: otherSocks }],
  });
  assert.equal(selected.started, 2);
  await waitFor(async () => (await securityObservations(primary.email)).filter((item) => item.action === "logout-all").length === 2);
  await waitFor(async () => (await securityObservations(batchGood.email)).filter((item) => item.action === "logout-all").length === 2);
  assert.equal((await securityObservations(primary.email)).at(-1).proxy, otherSocks);
  assert.equal((await securityObservations(batchGood.email)).at(-1).proxy, socks);
  await operationDone(primary.id, loggedOut.securityOperation.operationId);
  await operationDone(batchGood.id);

  // Activation alone is insufficient. Persisted credentials change only after MFA verification.
  const partial = await create("security-partial-one@example.invalid", socks);
  await post(`/api/jobs/${partial.id}/security`, { action: "rotate-totp" });
  const partialDone = await operationDone(partial.id);
  assert.equal(partialDone.securityOperation.status, "needs_attention");
  assert.equal(partialDone.canRotateTotp, false);
  assert.equal((await secrets(partial.id)).totpSecret, originalSecret);
  await post(`/api/jobs/${partial.id}/security`, { action: "rotate-totp" }, [409]);
  await assertPrivate(partial.id);
  const partialObservation = (await securityObservations(partial.email))[0];
  const savedPartial = JSON.parse(await fs.readFile(partialObservation.resultPath, "utf8"));
  await fs.writeFile(partialObservation.resultPath, JSON.stringify({ ...savedPartial, status: "completed", stage: "verified", activation_succeeded: true, mfa_verified: true, updatedAt: new Date().toISOString() }), { mode: 0o600 });
  await post(`/api/jobs/${partial.id}/security/recover`, {});
  assert.equal((await secrets(partial.id)).totpSecret, rotatedSecret);
  assert.equal((await api(`/api/jobs/${partial.id}/details`)).securityOperation.status, "completed");
  assert.equal((await securityObservations(partial.email)).length, 1, "recover must ingest the existing result without network replay");

  // Successful-looking files for another account or operation must never replace credentials.
  for (const prefix of ["security-wrong-op-", "security-wrong-email-"]) {
    const invalid = await create(`${prefix}one@example.invalid`, socks);
    await post(`/api/jobs/${invalid.id}/security`, { action: "rotate-totp" });
    const done = await operationDone(invalid.id);
    assert.notEqual(done.securityOperation.status, "completed");
    assert.equal((await secrets(invalid.id)).totpSecret, originalSecret);
    await assertPrivate(invalid.id);
  }

  const connectionFailure = await create("security-proxy-failure-one@example.invalid", socks);
  await post(`/api/jobs/${connectionFailure.id}/security`, { action: "rotate-totp" });
  assert.notEqual((await operationDone(connectionFailure.id)).securityOperation.status, "completed");
  await delay(500);
  assert.equal((await securityObservations(connectionFailure.email)).length, 1, "security failures must not trigger automatic network replay");
  assert.equal((await secrets(connectionFailure.id)).totpSecret, originalSecret);

  const canceled = await create("security-cancel-one@example.invalid", socks);
  await post(`/api/jobs/${canceled.id}/security`, { action: "rotate-totp" });
  await waitFor(async () => (await securityObservations(canceled.email)).length === 1);
  await post(`/api/jobs/${canceled.id}/cancel`, {});
  assert.notEqual((await operationDone(canceled.id)).securityOperation.status, "completed");
  assert.equal((await secrets(canceled.id)).totpSecret, originalSecret);

  const combined = await create("security-combined-success-one@example.invalid", socks);
  await post(`/api/jobs/${combined.id}/security`, { action: "rotate-totp-logout-all" });
  const combinedDone = await operationDone(combined.id);
  assert.equal(combinedDone.securityOperation.status, "completed");
  assert.equal(combinedDone.securityOperation.workResetSucceeded, true);
  assert.equal(combinedDone.securityOperation.logoutAccepted, true);
  assert.equal(combinedDone.securityAutoLoginPaused, true);
  assert.equal((await secrets(combined.id)).totpSecret, rotatedSecret);
  await assertPrivate(combined.id);

  const compatibilityRuns = [];
  for (const action of ["logout-all", "rotate-totp-logout-all"]) {
    const compatible = await create(`security-work-reset-unavailable-${action}@example.invalid`, socks);
    await post(`/api/jobs/${compatible.id}/security`, { action });
    const compatibleDone = await operationDone(compatible.id);
    compatibilityRuns.push(compatible);
    assert.equal(compatibleDone.securityOperation.status, "completed");
    assert.equal(compatibleDone.securityOperation.workResetSucceeded, false);
    assert.equal(compatibleDone.securityOperation.workResetUnavailable, true);
    assert.equal(compatibleDone.securityOperation.logoutAccepted, true);
    assert.equal(compatibleDone.resting, true);
    assert.match((await post("/api/jobs/query", { emails: [compatible.email] })).jobs[0].prompt, /Work 接口不可用.*404.*已跳过重置并提交登出/);
    assert.equal((await secrets(compatible.id)).totpSecret, action === "logout-all" ? originalSecret : rotatedSecret);
  }
  const unavailableFailure = await create("security-work-reset-unavailable-logout-failure-one@example.invalid", socks);
  await post(`/api/jobs/${unavailableFailure.id}/security`, { action: "rotate-totp-logout-all" });
  const unavailableFailureDone = await operationDone(unavailableFailure.id);
  assert.equal(unavailableFailureDone.securityOperation.status, "needs_attention");
  assert.equal(unavailableFailureDone.securityOperation.workResetSucceeded, false);
  assert.equal(unavailableFailureDone.securityOperation.workResetUnavailable, true);
  assert.equal(unavailableFailureDone.securityOperation.logoutAccepted, false);
  assert.equal(unavailableFailureDone.resting, true);
  assert.equal((await secrets(unavailableFailure.id)).totpSecret, rotatedSecret);
  assert.match(unavailableFailureDone.securityOperation.error, /Work 接口不可用.*404.*登出所有设备尚未确认/);

  for (const [email, paused, resetSucceeded] of [
    ["security-combined-logout-failure-one@example.invalid", true, true],
    ["security-work-reset-failure-one@example.invalid", false, false],
  ]) {
    const incomplete = await create(email, socks);
    await post(`/api/jobs/${incomplete.id}/security`, { action: "rotate-totp-logout-all" });
    const incompleteDone = await operationDone(incomplete.id);
    assert.equal(incompleteDone.securityOperation.status, "needs_attention");
    assert.equal(incompleteDone.securityOperation.workResetSucceeded, resetSucceeded);
    assert.equal(incompleteDone.securityOperation.logoutAccepted, false);
    assert.equal(incompleteDone.securityAutoLoginPaused, paused, "pause only when logout was accepted or requested with an uncertain outcome");
    assert.equal((await secrets(incomplete.id)).totpSecret, rotatedSecret, "a verified new TOTP must survive a later Work reset or logout failure");
    assert.equal(incompleteDone.canRotateTotp, false);
    assert.equal(incompleteDone.canRotateTotpLogoutAll, false);
    await assertPrivate(incomplete.id);
  }

  // A verified private result survives a server interruption before child exit handling.
  const interrupted = await create("security-crash-ready-one@example.invalid", socks);
  await post(`/api/jobs/${interrupted.id}/security`, { action: "rotate-totp" });
  await waitFor(async () => {
    const item = (await securityObservations(interrupted.email))[0];
    if (!item) return false;
    try { return JSON.parse(await fs.readFile(item.resultPath, "utf8")).mfa_verified; } catch { return false; }
  });
  await stop();
  await start();
  const recovered = await operationDone(interrupted.id);
  assert.equal(recovered.securityOperation.status, "completed");
  assert.equal((await secrets(interrupted.id)).totpSecret, rotatedSecret);
  for (const compatible of compatibilityRuns) {
    const restoredCompatibility = await api(`/api/jobs/${compatible.id}/details`);
    assert.equal(restoredCompatibility.securityOperation.status, "completed");
    assert.equal(restoredCompatibility.securityOperation.workResetSucceeded, false);
    assert.equal(restoredCompatibility.securityOperation.workResetUnavailable, true);
    assert.equal(restoredCompatibility.resting, true);
    assert.equal((await securityObservations(compatible.email)).length, 1, "restart must retain Work compatibility without replaying the logout");
  }
  assert.equal((await securityObservations(interrupted.email)).length, 1, "restart must not run the mutation again");
  assert.equal((await api(`/api/jobs/${primary.id}/details`)).securityOperations.length, 3);
  assert.equal((await secrets(primary.id)).totpSecret, rotatedSecret);
  await assertPrivate(interrupted.id);
  console.log("console security operations: transport, account binding, concurrency, batch results, private credentials, recovery and cancellation passed");
} catch (error) {
  error.message += `\nConsole output:\n${consoleLogs}`;
  throw error;
} finally {
  await stop();
  // A hard-killed parent can leave mock children alive; stop only PIDs written by our mock.
  for (const item of (await observations()).filter((entry) => entry.email.startsWith("security-crash-ready-") && entry.action !== "login")) {
    try { process.kill(item.pid, "SIGTERM"); } catch {}
  }
  await fs.rm(temporaryRoot, { recursive: true, force: true });
}

async function start() {
  child = spawn(process.execPath, ["src/console-server.mjs", "--host", "127.0.0.1", "--port", String(port)], {
    cwd: root,
    env: { ...process.env, ONBOARDING_OUTPUT_ROOT: output, ONBOARDING_PROTOCOL_SCRIPT: path.join(root, "test/mock-security-protocol.mjs"), SECURITY_TEST_OBSERVATIONS: observationsPath, TOSUB2_MAC_CREDENTIAL_ROOT: path.join(temporaryRoot, "test-credentials"), TOSUB2_TLS_PROFILE: "chrome152" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  childExit = new Promise((resolve) => child.once("exit", resolve));
  for (const stream of [child.stdout, child.stderr]) stream.on("data", (chunk) => { consoleLogs = `${consoleLogs}${chunk}`.slice(-20000); });
  const bootstrap = await waitFor(async () => {
    if (child.exitCode !== null) throw new Error(`server exited with ${child.exitCode}`);
    try { const response = await fetch(`${baseUrl}/api/bootstrap`); return response.ok ? response.json() : null; } catch { return null; }
  });
  headers = { "content-type": "application/json", "x-console-token": bootstrap.token };
}
async function stop() {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  if (!await Promise.race([childExit.then(() => true), delay(5000).then(() => false)])) {
    child.kill("SIGKILL");
    await childExit;
  }
}
async function request(endpoint, body) {
  const response = await fetch(`${baseUrl}${endpoint}`, { method: body === undefined ? "GET" : "POST", headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  const data = await response.json();
  assert.equal(response.headers.get("cache-control"), "no-store", endpoint);
  return { status: response.status, data };
}
async function api(endpoint) {
  const response = await request(endpoint);
  assert.equal(response.status, 200, `${endpoint}: ${JSON.stringify(response.data)}`);
  return response.data;
}
async function post(endpoint, body, allowed = [200, 202]) {
  const response = await request(endpoint, body);
  assert.ok(allowed.includes(response.status), `${endpoint}: ${response.status} ${JSON.stringify(response.data)}`);
  return response.data;
}
async function create(email, proxyUrl) {
  const result = await post("/api/jobs", { email, proxyUrl, password, totpSecret: originalSecret }, [200, 201]);
  const job = result.job;
  await waitFor(async () => (await api(`/api/jobs/${job.id}/details`)).status === "completed");
  return job;
}
async function secrets(id) { return post(`/api/jobs/${id}/secrets`, {}); }
async function operationDone(id, previousId = null) {
  return waitFor(async () => {
    const detail = await api(`/api/jobs/${id}/details`);
    const operation = detail.securityOperation;
    return operation && operation.operationId !== previousId && ["completed", "failed", "needs_attention", "canceled"].includes(operation.status) ? detail : false;
  });
}
async function observations() {
  try { return (await fs.readFile(observationsPath, "utf8")).split("\n").filter(Boolean).map((line) => JSON.parse(line)); } catch (error) { if (error.code === "ENOENT") return []; throw error; }
}
async function securityObservations(email) { return (await observations()).filter((entry) => entry.email === email && entry.action !== "login"); }
async function assertPrivate(id) {
  for (const endpoint of ["/api/jobs", `/api/jobs/${id}/details`, `/api/jobs/${id}/logs`]) {
    const value = JSON.stringify(await api(endpoint));
    for (const sensitive of [originalSecret, rotatedSecret, password, "test-proxy-secret", "second-proxy-secret"]) assert.equal(value.includes(sensitive), false, `${endpoint} leaked ${sensitive}`);
  }
}
async function waitFor(check) {
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) { const value = await check(); if (value) return value; await delay(50); }
  throw new Error("security test state did not settle before timeout");
}
function delay(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }
