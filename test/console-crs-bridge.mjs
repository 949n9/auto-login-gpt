import assert from "node:assert/strict";
import fs from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const root = await fs.mkdtemp(path.join(os.tmpdir(), "tosub2-bridge-http-"));
const outputRoot = path.join(root, "output");
const port = await availablePort();
const base = `http://127.0.0.1:${port}`;
const bridgeHeaders = { authorization: "Bearer test-dedicated-service-key", "content-type": "application/json" };
const consoleToken = "test-stable-console-token-123456789";
const consoleHeaders = { "x-console-token": consoleToken, "content-type": "application/json" };
const runtimePath = "/api/integrations/crs/runtime";
const loginPath = "/api/integrations/crs/login";
let imports = 0;
const remote = http.createServer(async (req, res) => {
  for await (const chunk of req) { void chunk; }
  let data;
  if (req.url.startsWith("/api/admin/account-groups/options")) data = { items: [{ id: "openai-group", name: "openai", enabled: true }], page: { totalPages: 1 } };
  else if (req.method === "POST") { imports += 1; data = { taskId: "11223344-5566-7788-99aa-bbccddeeff00" }; }
  else data = { items: [{ status: "succeeded", accountIds: ["crs-account"] }], finishedAt: new Date().toISOString() };
  res.writeHead(req.method === "POST" ? 202 : 200, { "content-type": "application/json" }); res.end(JSON.stringify({ code: 200, data }));
});
await new Promise((resolve) => remote.listen(0, "127.0.0.1", resolve));
let child;
let logs = "";
function launch(standby) {
  child = spawn(process.execPath, [path.join(projectRoot, "src/console-server.mjs"), "--host", "127.0.0.1", "--port", String(port)], { cwd: projectRoot, env: { ...process.env, ONBOARDING_OUTPUT_ROOT: outputRoot, TOSUB2_MAC_CREDENTIAL_ROOT: path.join(root, "credentials"), ONBOARDING_PROTOCOL_SCRIPT: path.join(projectRoot, "test/mock-crs-bridge-protocol.mjs"), TOSUB2_LOGIN_RETRY_DELAY_MS: "100", TOSUB2_TLS_PROFILE: "chrome142", CPR_PROXY_CAPTURE: path.join(root, "proxy-capture.jsonl"), CRS_LOGIN_BRIDGE_KEY: "test-dedicated-service-key", TOSUB2_CONSOLE_TOKEN: consoleToken, TOSUB2_STANDBY: standby ? "1" : "0", TOSUB2_ACTIVATION_FILE: path.join(root, "activated.json") }, stdio: ["ignore", "pipe", "pipe"] });
  child.stdout.on("data", (chunk) => { logs = `${logs}${chunk}`.slice(-20_000); });
  child.stderr.on("data", (chunk) => { logs = `${logs}${chunk}`.slice(-20_000); });
}
async function request(url, method = "GET", body, headers = bridgeHeaders) {
  const response = await fetch(`${base}${url}`, { method, headers, ...(body === undefined ? {} : { body: typeof body === "string" ? body : JSON.stringify(body) }) });
  return { status: response.status, value: await response.json() };
}
async function waitFor(probe, predicate = (value) => value) {
  const deadline = Date.now() + 15_000;
  let last;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`server exited: ${child.exitCode}`);
    try { const value = await probe(); last = value; if (predicate(value)) return value; } catch (error) { if (error.name === "AssertionError") throw error; }
    await new Promise((resolve) => setTimeout(resolve, 80));
  }
  throw new Error(`condition did not become true: ${JSON.stringify(last)}`);
}
async function stop() {
  if (child.exitCode !== null) return;
  const exited = new Promise((resolve) => child.once("exit", resolve));
  child.kill("SIGTERM");
  const timer = setTimeout(() => child.kill("SIGKILL"), 5000);
  await exited; clearTimeout(timer);
}

try {
  launch(true);
  const standby = await waitFor(() => request(`${runtimePath}/status`), (r) => r.value.mode === "standby");
  assert.equal(standby.value.databaseOpened, false);
  await assert.rejects(fs.access(outputRoot), { code: "ENOENT" });
  await stop();
  launch(true);
  await waitFor(() => request(`${runtimePath}/status`), (r) => r.value.mode === "standby");
  await assert.rejects(fs.access(outputRoot), { code: "ENOENT" });
  assert.equal((await request(`${runtimePath}/status`, "GET", undefined, consoleHeaders)).status, 401);
  assert.equal((await request(`${runtimePath}/activate`, "POST", {})).status, 202);
  await waitFor(() => request(`${runtimePath}/status`), (r) => r.value.mode === "active");
  assert.equal((await request("/api/bootstrap", "GET", undefined, {})).value.token, consoleToken);
  await fs.access(path.join(outputRoot, "tosub2.sqlite3"));
  assert.equal((await request(loginPath, "POST", { operationId: "unauthorized", email: "bridge@example.com" }, consoleHeaders)).status, 401);
  assert.equal((await request(loginPath, "POST", "x".repeat(16 * 1024 + 1))).status, 413);
  assert.equal((await request(`${loginPath}?key=not-accepted`, "POST", {})).status, 400);
  assert.equal((await request("/api/crs/config", "PUT", { revision: 0, config: { baseUrl: `http://127.0.0.1:${remote.address().port}`, authType: "apiKey", apiKey: "test-crs-key", autoUpload: true } }, consoleHeaders)).status, 200);

  const input = { operationId: "bridge-one", email: "bridge@example.com", password: "test-password", totpSecret: "JBSWY3DPEHPK3PXP", proxyUrl: "http://127.0.0.1:65500" };
  const accepted = await Promise.all(Array.from({ length: 6 }, () => request(loginPath, "POST", input)));
  assert.ok(accepted.every((response) => response.status === 202));
  assert.equal(new Set(accepted.map((response) => response.value.jobId)).size, 1);
  const jobId = accepted[0].value.jobId;
  const success = await waitFor(() => request(`${loginPath}/bridge-one`), (r) => r.value.status === "succeeded");
  assert.equal(success.value.credentials.email, input.email);
  assert.equal(success.value.credentials.refresh_token, `test-refresh-${input.email}`);
  assert.equal(imports, 0, "bridge completion must not auto-upload credentials to CRS");
  assert.equal((await request("/api/jobs", "GET", undefined, consoleHeaders)).value.jobs.find((job) => job.id === jobId).accountTerm, null, "a new CPR bridge account remains unset when no type was provided");
  const second = await request(loginPath, "POST", { operationId: "bridge-two", email: input.email });
  assert.equal(second.status, 202);
  assert.equal(second.value.jobId, jobId, "saved password should reuse the same account");
  await waitFor(() => request(`${loginPath}/bridge-two`), (r) => r.value.status === "succeeded");
  assert.equal(imports, 0);
  assert.equal((await request("/api/jobs", "GET", undefined, consoleHeaders)).value.jobs.find((job) => job.id === jobId).accountTerm, null, "reusing a CPR account must not invent its type");
  assert.equal((await request("/api/jobs", "GET", undefined, consoleHeaders)).value.jobs.find((job) => job.id === jobId).proxyConfigured, true, "omitted proxy retains saved proxy");
  await request(loginPath, "POST", { operationId: "bridge-direct", email: input.email, proxyUrl: null, totpSecret: "" });
  await waitFor(() => request(`${loginPath}/bridge-direct`), (r) => r.value.status === "succeeded");
  assert.equal((await request("/api/jobs", "GET", undefined, consoleHeaders)).value.jobs.find((job) => job.id === jobId).proxyConfigured, false, "explicit null switches to direct");
  const captures = (await fs.readFile(path.join(root, "proxy-capture.jsonl"), "utf8")).trim().split("\n").map(JSON.parse);
  assert.equal(captures[0].proxy, new URL(input.proxyUrl).toString());
  assert.equal(captures[0].totp, input.totpSecret);
  assert.equal(captures[0].pin, "1");
  assert.equal(captures[1].proxy, new URL(input.proxyUrl).toString());
  assert.equal(captures[2].proxy, "");
  assert.equal(captures[0].tls.account, input.email);
  assert.equal(captures[0].tls.profile, "chrome152_macos");
  assert.equal(captures[0].tls.mode, "native");
  assert.equal(captures[0].tls.version, 2);
  assert.equal(Object.hasOwn(captures[0].tls, "extensionOrder"), false);
  assert.deepEqual(captures[1].tls, captures[0].tls, "CPR relogin must reuse the account TLS identity");
  assert.deepEqual(captures[2].tls, captures[0].tls, "switching proxy must not rotate account TLS");
  console.log("Verified CPR proxy and TOTP reach worker, pinned session, explicit direct and saved proxy semantics");
  assert.equal((await request(loginPath, "POST", { ...input, password: "changed" })).status, 409);
  const marked = await request(`/api/jobs/${jobId}/account-term`, "POST", { accountTerm: "long" }, consoleHeaders);
  assert.equal(marked.value.job.accountTerm, "long");
  await request(loginPath, "POST", { operationId: "bridge-marked", email: input.email });
  await waitFor(() => request(`${loginPath}/bridge-marked`), (r) => r.value.status === "succeeded");
  assert.equal((await request("/api/jobs", "GET", undefined, consoleHeaders)).value.jobs.find((job) => job.id === jobId).accountTerm, "long", "CPR relogin preserves a manually assigned type");
  const failed = await request(loginPath, "POST", { operationId: "missing-material", email: "missing@example.com" });
  assert.equal(failed.value.status, "failed");
  assert.doesNotMatch(JSON.stringify((await request(`${loginPath}/missing-material`)).value), /test-password/);

  async function retryCase(name, expectedStatus, expectedAttempts) {
    const email = `auto-retry-${name}@example.com`;
    const accepted = await request(loginPath, 'POST', {operationId: `retry-${name}`, email, password:'test-password', totpSecret:'JBSWY3DPEHPK3PXP'});
    assert.equal(accepted.status, 202);
    const result = await waitFor(() => request(`${loginPath}/retry-${name}`), r => ['succeeded','failed'].includes(r.value.status));
    assert.equal(result.value.status, expectedStatus);
    assert.equal(Number(await fs.readFile(path.join(outputRoot, email + '.attempts'), 'utf8')), expectedAttempts);
    return accepted.value.jobId;
  }
  const retriedId = await retryCase('success', 'failed', 1);
  await retryCase('always', 'failed', 1);
  await retryCase('email-success', 'failed', 1);
  await retryCase('email-always', 'failed', 1);
  await retryCase('permanent', 'failed', 1);
  const retriedJob = (await request('/api/jobs', 'GET', undefined, consoleHeaders)).value.jobs.find(j => j.id===retriedId);
  assert.equal(retriedJob.loginAutoRetryCount, 0);
  assert.equal(retriedJob.autoRepairBlocked, true);
  assert.equal(retriedJob.accountTerm, null, "automatic login retries preserve the unset type");
  assert.equal(imports, 0, 'retry must preserve the bridge operation and avoid unrelated CRS upload');
  const sameFailure = await request(loginPath, 'POST', {operationId:'retry-success', email:'auto-retry-success@example.com', password:'test-password', totpSecret:'JBSWY3DPEHPK3PXP'});
  assert.equal(sameFailure.value.status, 'failed', 'polling or repeating an operation cannot replay failed OAuth');
  await new Promise(resolve => setTimeout(resolve, 600));
  assert.equal(Number(await fs.readFile(path.join(outputRoot, 'auto-retry-success@example.com.attempts'), 'utf8')), 1);
  const beforeRisk = (await fs.readFile(path.join(root, "proxy-capture.jsonl"), "utf8")).trim().split("\n").length;
  await request(loginPath, "POST", { operationId: "proxy-risk", email: "proxy-risk@example.com", password: "test-password", proxyUrl: "http://test-sid-fixed:secret@127.0.0.1:65500" });
  await waitFor(() => request(`${loginPath}/proxy-risk`), r => r.value.status === "failed");
  const afterRisk = (await fs.readFile(path.join(root, "proxy-capture.jsonl"), "utf8")).trim().split("\n").length;
  assert.equal(afterRisk - beforeRisk, 1, "CPR selected proxy failure must stop without session rotation or repeated workers");
  console.log("Verified CPR proxy risk failure stops without restarting worker");

  const waiting = await request(loginPath, "POST", { operationId: "drain-job", email: "mfa-prompt@example.com", password: "test-password" });
  const waitingId = waiting.value.jobId;
  await waitFor(() => request("/api/jobs", "GET", undefined, consoleHeaders), (r) => r.value.jobs?.some((job) => job.id === waitingId && job.status === "mfa_otp"));
  const drain = await request(`${runtimePath}/drain`, "POST", {});
  assert.equal(drain.value.mode, "draining");
  assert.equal(drain.value.readyToStop, false);
  assert.equal((await request(loginPath, "POST", { operationId: "blocked", email: input.email })).status, 409);
  assert.equal((await request("/api/jobs", "POST", { email: "blocked@example.com" }, consoleHeaders)).status, 409);
  assert.equal((await request(`/api/jobs/${waitingId}/input`, "POST", { action: "mfa_otp", value: "123456" }, consoleHeaders)).status, 200);
  await waitFor(() => request(`${loginPath}/drain-job`), (r) => r.value.status === "succeeded");
  await waitFor(() => request(`${runtimePath}/status`), (r) => r.value.readyToStop === true);
  assert.equal((await request(`${runtimePath}/resume`, "POST", {})).value.mode, "active");
  assert.equal((await request(`/api/jobs/${jobId}/relogin`, "POST", {}, consoleHeaders)).status, 200);
  await waitFor(() => imports, (value) => value === 1);
  assert.deepEqual((await request(`${loginPath}/bridge-one`)).value, success.value, "later manual login must not replace bridge result");
  await waitFor(() => request("/api/crs/status", "GET", undefined, consoleHeaders), (r) => r.value.counts?.succeeded === 1);
  await stop();
  launch(true);
  await waitFor(() => request(`${runtimePath}/status`), (r) => r.value.mode === "active");
  assert.deepEqual((await request(`${loginPath}/bridge-one`)).value, success.value);
  assert.equal((await request("/api/bootstrap", "GET", undefined, {})).value.token, consoleToken);
  assert.equal(imports, 1, "restart must not replay completed uploads");
  const restoredJobs = (await request("/api/jobs", "GET", undefined, consoleHeaders)).value.jobs;
  assert.equal(restoredJobs.find((job) => job.id === retriedId).accountTerm, null, "an unset CPR account remains unset after restart");
  assert.equal(restoredJobs.find((job) => job.id === jobId).accountTerm, "long", "the manually assigned type survives restart");
  await request(loginPath, "POST", { operationId: "no-new-output", email: input.email, password: "test-no-result" });
  await waitFor(() => request(`${loginPath}/no-new-output`), (r) => r.value.status === "failed");
  assert.equal((await request("/api/jobs", "GET", undefined, consoleHeaders)).value.jobs.find(job => job.id === jobId).loginAutoRetryCount, 0);
  assert.equal((await request(`${loginPath}/no-new-output`)).value.credentials, undefined, "previous authorization must not satisfy a new bridge attempt");
  // New accounts follow the same single-attempt policy.
  const initialEmail = 'auto-retry-initial@example.com';
  const initial = await request('/api/jobs', 'POST', {email:initialEmail,password:'test-password',proxyUrl:''}, consoleHeaders);
  assert.equal(initial.status, 201);
  await waitFor(() => request('/api/jobs', 'GET', undefined, consoleHeaders), r => r.value.jobs.some(j => j.id===initial.value.job.id && j.status==='failed' && j.autoRepairBlocked));
  assert.equal(Number(await fs.readFile(path.join(outputRoot, initialEmail+'.attempts'), 'utf8')), 1);
  console.log('Verified failed authorization pauses after one attempt, bridge identity and idempotent failure polling');

  console.log("console bridge auth, saved credentials, auto-upload isolation, standby activation, drain and restart tests passed");
} catch (error) {
  error.message += `\nConsole output:\n${logs}`;
  throw error;
} finally {
  await stop();
  await new Promise((resolve) => remote.close(resolve));
  await fs.rm(root, { recursive: true, force: true });
}

async function availablePort() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}
