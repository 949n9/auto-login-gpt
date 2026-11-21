import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createServerDatabase } from "../src/server-database.mjs";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporaryRoot = await fs.mkdtemp(path.join(os.tmpdir(), "tosub2-proxy-selection-"));
const outputRoot = path.join(temporaryRoot, "jobs");
const observationsPath = path.join(temporaryRoot, "observations.jsonl");
const mockProtocol = path.join(temporaryRoot, "mock-protocol.mjs");
const credentialLoader = path.join(temporaryRoot, "credential-loader.mjs");
const preload = path.join(temporaryRoot, "preload.mjs");
await fs.mkdir(outputRoot);

// This test exercises real HTTP handlers without contacting account providers or native Keychain/DPAPI.
await fs.writeFile(mockProtocol, `
import fs from "node:fs/promises";
const emailAt = process.argv.indexOf("--email");
const email = process.argv[emailAt + 1];
const mode = process.argv.includes("--setup-totp") ? "totp" : process.argv.includes("--add-password") ? "password" : "login";
await fs.appendFile(process.env.PROXY_TEST_OBSERVATIONS, JSON.stringify({ email, mode, proxy: process.env.CHATGPT_PROXY_URL }) + "\\n");
console.log("Email OTP (r=resend, q=quit):");
await new Promise((resolve) => { const timer = setTimeout(resolve, 60000); process.once("SIGTERM", () => { clearTimeout(timer); resolve(); }); });
`);
const credentialSource = `export function createCredentialStore() {
  const entries = new Map();
  return {
    async save(email, value) { entries.set(email.toLowerCase(), { ...value }); },
    async load(email) { return entries.get(email.toLowerCase()) || { password: "", totpSecret: "", proxyUrl: "" }; },
    async delete(email) { entries.delete(email.toLowerCase()); }
  };
}`;
await fs.writeFile(credentialLoader, `
export async function load(url, context, nextLoad) {
  if (url === ${JSON.stringify(pathToFileURL(path.join(projectRoot, "src/credential-store.mjs")).href)}) {
    return { format: "module", shortCircuit: true, source: ${JSON.stringify(credentialSource)} };
  }
  return nextLoad(url, context);
}
`);
await fs.writeFile(preload, `import { register } from "node:module"; register(${JSON.stringify(pathToFileURL(credentialLoader).href)}, import.meta.url);\n`);

const port = await availablePort();
const baseUrl = `http://127.0.0.1:${port}`;
const child = spawn(process.execPath, ["--import", preload, path.join(projectRoot, "src/console-server.mjs"), "--host", "127.0.0.1", "--port", String(port)], {
  cwd: projectRoot,
  env: {
    ...process.env,
    ONBOARDING_OUTPUT_ROOT: outputRoot,
    ONBOARDING_PROTOCOL_SCRIPT: mockProtocol,
    PROXY_TEST_OBSERVATIONS: observationsPath,
    TOSUB2_TLS_PROFILE: "chrome142",
  },
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true,
});
let consoleLogs = "";
child.stdout.on("data", (chunk) => { consoleLogs = `${consoleLogs}${chunk}`.slice(-12000); });
child.stderr.on("data", (chunk) => { consoleLogs = `${consoleLogs}${chunk}`.slice(-12000); });
const childExit = new Promise((resolve) => child.once("exit", resolve));
let headers;
const proxyA = new URL("http://test-user-a:test-secret-a@proxy-a.example:8081").toString();
const proxyB = new URL("socks5h://test-user-b:test-secret-b@proxy-b.example:1081").toString();
const proxyShared = new URL("https://test-shared:test-secret-shared@proxy-shared.example:8443").toString();
const batchText = "alpha-user@example.com\nbeta@example.com\nALPHA-USER@example.com";

try {
  const bootstrap = await waitFor(async () => {
    if (child.exitCode !== null) throw new Error("console stopped before startup");
    try {
      const response = await fetch(`${baseUrl}/api/bootstrap`);
      return response.ok ? response.json() : null;
    } catch { return null; }
  });
  headers = { "content-type": "application/json", "x-console-token": bootstrap.token };

  const previewText = "alpha-user@example.com----demo1234----JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\nbeta@example.com\nALPHA-USER@example.com";
  const preview = await post("/api/jobs/preview", { text: previewText });
  assert.deepEqual(preview, { accounts: [{ email: "ALPHA-USER@example.com" }, { email: "beta@example.com" }], count: 2 });
  assert.equal((await page()).pagination.total, 0, "preview must not create jobs");
  assert.deepEqual((await fs.readdir(outputRoot, { withFileTypes: true })).filter((entry) => entry.isDirectory()), [], "preview must not create job files");

  const invalidAssignments = [
    null,
    {},
    [{ email: "alpha-user@example.com", proxyUrl: proxyA }],
    [{ email: "alpha-user@example.com", proxyUrl: proxyA }, { email: "ALPHA-USER@example.com", proxyUrl: proxyB }],
    [{ email: "alpha-user@example.com", proxyUrl: proxyA }, { email: "extra@example.com", proxyUrl: proxyB }],
    [{ email: "alpha-user@example.com", proxyUrl: proxyA }, { email: "beta@example.com", proxyUrl: "invalid-proxy-credential" }],
    [{ email: "alpha-user@example.com", proxyUrl: proxyA }, { email: "beta@example.com" }],
    [{ email: "alpha-user@example.com", proxyUrl: proxyA }, { email: "beta@example.com", proxyUrl: { password: "invalid-proxy-credential" } }],
  ];
  for (const proxyAssignments of invalidAssignments) {
    const response = await post("/api/jobs/batch", { text: batchText, proxyAssignments }, 400);
    assert.doesNotMatch(JSON.stringify(response), /test-secret|invalid-proxy-credential/);
    assert.equal((await page()).pagination.total, 0, "invalid mapping must reject before creating any jobs");
  }

  const created = await post("/api/jobs/batch", {
    text: batchText,
    proxyAssignments: [{ email: "BETA@example.com", proxyUrl: proxyB }, { email: "alpha-user@example.com", proxyUrl: proxyA }],
  }, 201);
  assert.equal(created.created, 2);
  const alpha = created.jobs.find((job) => job.email.toLowerCase() === "alpha-user@example.com");
  const beta = created.jobs.find((job) => job.email === "beta@example.com");
  assert.equal(alpha.proxyEndpoint, "http://proxy-a.example:8081");
  assert.equal(beta.proxyEndpoint, "socks5h://proxy-b.example:1081");
  assert.doesNotMatch(JSON.stringify(created), /test-user|test-secret/);
  await observed(alpha.email, "login", proxyA);
  await observed(beta.email, "login", proxyB);

  const reused = await post("/api/jobs/batch", {
    text: "reuse-a@example.com\nreuse-b@example.com",
    proxyAssignments: [{ email: "reuse-a@example.com", proxyUrl: proxyShared }, { email: "reuse-b@example.com", proxyUrl: proxyShared }],
  }, 201);
  assert.ok(reused.jobs.every((job) => job.proxyEndpoint === "https://proxy-shared.example:8443"), "manual reuse of one proxy is allowed");
  const legacy = await post("/api/jobs/batch", { text: "legacy@example.com", proxyUrl: proxyShared }, 201);
  assert.equal(legacy.jobs[0].proxyEndpoint, "https://proxy-shared.example:8443");
  const direct = await post("/api/jobs/batch", { text: "direct@example.com", proxyAssignments: [{ email: "direct@example.com", proxyUrl: "" }] }, 201);
  assert.equal(direct.jobs[0].proxyConfigured, false);
  assert.equal(direct.jobs[0].proxyEndpoint, null);

  // The active first account is skipped; reordered assignments still belong to their explicit IDs.
  await post(`/api/jobs/${beta.id}/cancel`, {});
  await waitFor(async () => (await getJob(beta.id)).status === "canceled");
  const invalidAction = [{ id: alpha.id, proxyUrl: "invalid-proxy-credential" }, { id: beta.id, proxyUrl: proxyShared }];
  for (const action of ["reauthorize", "relogin", "setup-2fa", "add-password"]) {
    const before = await page();
    await post(`/api/jobs/${action}-batch`, { ids: [alpha.id, beta.id], proxyAssignments: invalidAction }, 400);
    const after = await page();
    for (const id of [alpha.id, beta.id]) {
      const old = before.jobs.find((job) => job.id === id);
      const next = after.jobs.find((job) => job.id === id);
      assert.equal(next.attempt, old.attempt);
      assert.equal(next.proxyEndpoint, old.proxyEndpoint, "validation must include skipped jobs before changing any proxy");
    }
  }
  const relogin = await post("/api/jobs/relogin-batch", {
    ids: [alpha.id, beta.id],
    proxyAssignments: [{ id: beta.id, proxyUrl: proxyShared }, { id: alpha.id, proxyUrl: proxyB }],
  });
  assert.equal(relogin.started, 1);
  assert.equal(relogin.skipped, 1);
  assert.equal(relogin.jobs[0].id, beta.id);
  assert.equal(relogin.jobs[0].proxyEndpoint, "https://proxy-shared.example:8443");
  assert.equal((await getJob(alpha.id)).proxyEndpoint, "http://proxy-a.example:8081");
  await observed(beta.email, "login", proxyShared);

  for (const id of [alpha.id, beta.id]) await post(`/api/jobs/${id}/cancel`, {});
  const reauthorized = await post("/api/jobs/reauthorize-batch", {
    ids: [alpha.id, beta.id],
    proxyAssignments: [{ id: beta.id, proxyUrl: proxyA }, { id: alpha.id, proxyUrl: proxyB }],
  });
  assert.equal(reauthorized.started, 2);
  assert.equal(reauthorized.jobs.find((job) => job.id === alpha.id).proxyEndpoint, "socks5h://proxy-b.example:1081");
  assert.equal(reauthorized.jobs.find((job) => job.id === beta.id).proxyEndpoint, "http://proxy-a.example:8081");
  await observed(alpha.email, "login", proxyB);
  await observed(beta.email, "login", proxyA);

  const skipped = await seedCompleted("skip@example.com", { has_password: true, has_totp_key: true });
  const first = await seedCompleted("first@example.com");
  const second = await seedCompleted("second@example.com");
  const selectedIds = [skipped.id, first.id, second.id];
  await waitFor(async () => {
    const visibleIds = new Set((await page()).jobs.map((job) => job.id));
    return selectedIds.every((id) => visibleIds.has(id));
  });
  await post("/api/jobs/setup-2fa-batch", { ids: selectedIds, proxyAssignments: [{ id: first.id, proxyUrl: proxyA }, { id: second.id, proxyUrl: proxyB }] }, 400);
  const totp = await post("/api/jobs/setup-2fa-batch", {
    ids: selectedIds,
    proxyAssignments: [{ id: second.id, proxyUrl: proxyB }, { id: skipped.id, proxyUrl: proxyShared }, { id: first.id, proxyUrl: proxyA }],
  });
  assert.equal(totp.started, 2);
  assert.equal(totp.skipped, 1);
  await observed(first.email, "totp", proxyA);
  await observed(second.email, "totp", proxyB);
  assert.equal((await getJob(skipped.id)).proxyConfigured, false);
  for (const job of [first, second]) await post(`/api/jobs/${job.id}/cancel`, {});
  const passwords = await post("/api/jobs/add-password-batch", {
    ids: selectedIds,
    proxyAssignments: [{ id: second.id, proxyUrl: proxyA }, { id: first.id, proxyUrl: proxyB }, { id: skipped.id, proxyUrl: proxyShared }],
  });
  assert.equal(passwords.started, 2);
  assert.equal(passwords.skipped, 1);
  await observed(first.email, "password", proxyB);
  await observed(second.email, "password", proxyA);
  assert.equal((await getJob(skipped.id)).proxyConfigured, false);
  const selection = (await page()).selection;
  assert.equal(selection.find((job) => job.id === first.id).proxyEndpoint, "socks5h://proxy-b.example:1081");
  assert.doesNotMatch(JSON.stringify(selection), /test-user|test-secret/);
  await post(`/api/jobs/${first.id}/proxy`, { proxyUrl: proxyShared }, 409);
  const saved = await post('/api/jobs', {email: 'proxy-only@example.invalid', startLogin: false, password: 'fixture-password', totpSecret: 'JBSWY3DPEHPK3PXP'}, 201);
  const id = saved.job.id;
  await post(`/api/jobs/${id}/proxy`, {}, 400);
  await post(`/api/jobs/${id}/proxy`, {proxyUrl: 'invalid'}, 400);
  await post(`/api/jobs/${id}/proxy`, {proxyUrl: {dynamicProfileId: 'invalid'}}, 400);
  const observationsBefore = await fs.readFile(observationsPath, 'utf8');
  const changed = await post(`/api/jobs/${id}/proxy`, {proxyUrl: proxyB});
  assert.equal(changed.job.proxyEndpoint, 'socks5h://proxy-b.example:1081');
  assert.equal(changed.job.loginDeferred, true);
  assert.equal(changed.job.status, 'ready');
  assert.doesNotMatch(JSON.stringify(changed), /test-user|test-secret/);
  const db = createServerDatabase({outputRoot, mustExist: true});
  try {
    const credentials = db.loadCredentials(saved.job.email);
    assert.equal(credentials.proxyUrl, proxyB);
    assert.equal(credentials.password, 'fixture-password');
    assert.equal(credentials.totpSecret, 'JBSWY3DPEHPK3PXP');
  } finally { db.close(); }
  const directChange = await post(`/api/jobs/${id}/proxy`, {proxyUrl: ''});
  assert.equal(directChange.job.proxyConfigured, false);
  assert.equal(directChange.job.loginDeferred, true);
  assert.equal(await fs.readFile(observationsPath, 'utf8'), observationsBefore, 'proxy changes must not start workers');
  console.log("console explicit proxy selection tests passed");
} catch (error) {
  error.message = `${error.message}\nConsole output:\n${consoleLogs}`;
  throw error;
} finally {
  if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
  const stopped = await Promise.race([childExit.then(() => true), delay(5000).then(() => false)]);
  if (!stopped) child.kill("SIGKILL");
  await fs.rm(temporaryRoot, { recursive: true, force: true });
}

async function post(endpoint, body, status = 200) {
  const response = await fetch(`${baseUrl}${endpoint}`, { method: "POST", headers, body: JSON.stringify(body) });
  const payload = await response.json();
  assert.equal(response.status, status, `${endpoint}: ${JSON.stringify(payload)}`);
  return payload;
}

async function page() {
  const response = await fetch(`${baseUrl}/api/jobs`, { headers });
  assert.equal(response.status, 200);
  return response.json();
}

async function getJob(id) {
  return (await page()).jobs.find((job) => job.id === id);
}

async function observed(email, mode, proxy) {
  await waitFor(async () => {
    try {
      const entries = (await fs.readFile(observationsPath, "utf8")).trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
      return entries.some((entry) => entry.email === email && entry.mode === mode && entry.proxy === proxy);
    } catch { return false; }
  });
}

async function seedCompleted(email, flags = {}) {
  const id = crypto.randomUUID();
  const directory = path.join(outputRoot, id);
  await fs.mkdir(directory);
  const metadata = { version: 1, email, status: "completed", ...flags };
  const output = { type: "sub2api-data", version: 1, accounts: [{ credentials: { email } }] };
  const database = createServerDatabase({ outputRoot, mustExist: true });
  try {
    database.saveJob(id, metadata);
    database.saveArtifact(path.join(directory, "sub2api-import-oauth.json"), output);
  } finally { database.close(); }
  await fs.writeFile(path.join(directory, "job-meta.json"), JSON.stringify(metadata));
  await fs.writeFile(path.join(directory, "sub2api-import-oauth.json"), JSON.stringify(output));
  return { id, email };
}

async function waitFor(check) {
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    const result = await check();
    if (result) return result;
    await delay(50);
  }
  throw new Error("timed out waiting for proxy selection test state");
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function availablePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}
