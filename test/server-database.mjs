import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createServerDatabase } from "../src/server-database.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporaryRoot = await fs.mkdtemp(path.join(os.tmpdir(), "tosub2-database-"));
const outputRoot = path.join(temporaryRoot, "data");
const id = crypto.randomUUID();
const email = "database-test@example.invalid";
const privateValue = "database-test-private-password-123";
const exportValue = { type: "sub2api-data", accounts: [{ credentials: { email, refresh_token: "database-test-refresh-secret" } }] };
const jobDirectory = path.join(outputRoot, id);
let database;
let application;
let provider;
let token;
let baseUrl;
let applicationOutput = "";

try {
  await fs.mkdir(jobDirectory, { recursive: true });
  await fs.writeFile(path.join(jobDirectory, "job-meta.json"), JSON.stringify({ version: 1, email, status: "completed" }));
  await fs.writeFile(path.join(jobDirectory, "sub2api-import-oauth.json"), JSON.stringify(exportValue));
  database = createServerDatabase({ outputRoot });
  database.migrateLegacy();
  assert.equal(database.jobIds().length, 1);
  assert.deepEqual(database.readArtifact(path.join(jobDirectory, "sub2api-import-oauth.json")), exportValue);
  database.saveCredentials(email, { password: privateValue, totpSecret: "JBSWY3DPEHPK3PXP", proxyUrl: "http://u:p@proxy.example.invalid:8080/" });
  database.saveLogs(id, "persisted sanitized log\n");
  const first = database.putSetting("proxyLibrary", { proxies: [], selectedId: "direct" }, 0);
  assert.equal(first.revisions.proxyLibrary, 1);
  const secondConnection = createServerDatabase({ outputRoot, mustExist: true });
  assert.equal(secondConnection.putSetting("proxyLibrary", { proxies: [], selectedId: "" }, 0).conflict, true);
  secondConnection.close();
  database.migrateSettings({ proxyLibrary: { proxies: [], selectedId: "" }, mail: { method: "GET", url: "", headersText: '{}'} });
  assert.equal(database.getSettings().settings.proxyLibrary.selectedId, "direct", "migration never overwrites existing sections");
  database.close();
  database = null;

  // Reconstruct every compatibility work file from the database alone.
  await fs.rm(jobDirectory, { recursive: true });
  database = createServerDatabase({ outputRoot, mustExist: true });
  database.restoreWorkspace();
  assert.deepEqual(JSON.parse(await fs.readFile(path.join(jobDirectory, "sub2api-import-oauth.json"))), exportValue);
  assert.equal(database.loadCredentials(email).password, privateValue);
  assert.equal(database.get("job-logs", id), "persisted sanitized log\n");
  assert.equal((await fs.stat(database.databasePath)).mode & 0o777, 0o600);
  assert.equal((await fs.stat(database.keyPath)).mode & 0o777, 0o600);
  for (const filename of ["tosub2.sqlite3", "tosub2.sqlite3-wal"]) {
    const bytes = await fs.readFile(path.join(outputRoot, filename)).catch(() => Buffer.alloc(0));
    for (const secret of [privateValue, "database-test-refresh-secret", "JBSWY3DPEHPK3PXP"]) assert.equal(bytes.includes(Buffer.from(secret)), false, "database files contain no plaintext secrets");
  }
  database.close();
  database = null;
  const keyPath = path.join(outputRoot, ".tosub2-database-key");
  const savedKey = await fs.readFile(keyPath);
  const savedWorkFile = await fs.readFile(path.join(jobDirectory, "job-meta.json"));
  await fs.writeFile(keyPath, crypto.randomBytes(32));
  database = createServerDatabase({ outputRoot, mustExist: true });
  assert.throws(() => database.restoreWorkspace(), /无法解密/);
  assert.deepEqual(await fs.readFile(path.join(jobDirectory, "job-meta.json")), savedWorkFile, "failed integrity preflight preserves original working copies");
  database.close();
  database = null;
  await fs.writeFile(keyPath, savedKey, { mode: 0o600 });

  await startApplication();
  assert.equal((await request("/api/settings")).settings.proxyLibrary.selectedId, "direct");
  const independent = await request("/api/settings", "PUT", { section: "sms", revision: 0, value: { selectedProviderId: "luban", configs: { luban: { apiKey: "test-sms-key", serviceId: "123" } } } });
  assert.equal(independent.revisions.sms, 1);
  assert.equal(independent.revisions.proxyLibrary, 1);
  const stale = await request("/api/settings", "PUT", { section: "sms", revision: 0, value: { selectedProviderId: "luban", configs: {} } }, 409);
  assert.equal(stale.settings.sms.configs.luban.apiKey, "test-sms-key");
  await request("/api/settings", "PUT", { section: "invalid", revision: 0, value: {} }, 400);
  await request("/api/settings", "PUT", { section: "proxyLibrary", revision: 1, value: { proxies: [{ id: "bad", name: "bad", url: "ftp://invalid/" }], selectedId: "bad" } }, 400);
  await request("/api/settings", "PUT", { section: "mail", revision: 1, value: { method: "GET", headersText: "not-json" } }, 400);
  const migrated = await request("/api/settings/migrate", "POST", { settings: { sms: { selectedProviderId: "luban", configs: { luban: { apiKey: "stale-key" } } }, sub2api: { baseUrl: "https://sub2api.example.invalid", adminApiKey: "test-admin-key", groupIds: [], monitorEnabled: true } } });
  assert.equal(migrated.settings.sms.configs.luban.apiKey, "test-sms-key");
  assert.equal(migrated.settings.sub2api.monitorEnabled, false, "browser migration never enables unattended monitoring");
  assert.equal((await request("/api/sub2api/monitor")).enabled, false);
  assert.equal((await request("/api/jobs")).jobs[0].proxyEndpoint, "http://proxy.example.invalid:8080");
  assert.match((await request(`/api/jobs/${id}/logs`)).logs, /persisted sanitized log/);
  const noToken = await fetch(`${baseUrl}/api/settings`);
  assert.equal(noToken.status, 403);
  assert.equal(noToken.headers.get("cache-control"), "no-store");
  await stopApplication();
  await startApplication();
  assert.equal((await request("/api/settings")).settings.sms.configs.luban.apiKey, "test-sms-key");
  assert.equal((await request("/api/jobs")).pagination.total, 1);
  await request("/api/jobs/delete-batch", "POST", { ids: [id] });
  await stopApplication();
  // Even a late old worker recreating a cache file cannot resurrect a deleted job.
  await fs.mkdir(jobDirectory, { recursive: true });
  await fs.writeFile(path.join(jobDirectory, "job-meta.json"), JSON.stringify({ version: 1, email, status: "completed" }));
  await fs.writeFile(path.join(jobDirectory, "sub2api-import-oauth.json"), JSON.stringify(exportValue));
  database = createServerDatabase({ outputRoot, mustExist: true });
  assert.equal(database.saveArtifact(path.join(jobDirectory, "sub2api-import-oauth.json"), exportValue), false);
  assert.equal(database.saveJob(id, { email }), false);
  database.close();
  database = null;
  await startApplication();
  assert.equal((await request("/api/jobs")).pagination.total, 0);
  await stopApplication();

  // Real protocol worker: inspect the DB while it waits at the next prompt,
  // proving checkpoints commit immediately rather than only on process exit.
  const port = await availablePort();
  const providerUrl = `http://127.0.0.1:${port}`;
  provider = spawn(process.execPath, [path.join(root, "test/mock-add-phone-page-server.mjs"), String(port)], { cwd: root, stdio: "ignore" });
  await waitFor(async () => { try { return (await fetch(providerUrl)).ok; } catch { return false; } });
  const protocolId = crypto.randomUUID();
  const protocolDirectory = path.join(outputRoot, protocolId);
  database = createServerDatabase({ outputRoot, mustExist: true });
  database.saveJob(protocolId, { version: 1, email: "add-phone-page@example.com" });
  let checkpointObserved = false;
  const steps = [
    { pattern: /Email OTP \(r=resend/, value: "123456" },
    { pattern: /Phone number, E\.164 format/, value: "+60123456789", before: () => { checkpointObserved = Boolean(database.readArtifact(path.join(protocolDirectory, "login-checkpoint.json"))); } },
    { pattern: /Phone OTP \(r=resend/, value: "654321" },
  ];
  const protocol = spawn(process.execPath, [path.join(root, "src/protocol-login.mjs"), "--legacy-web-login", "--email", "add-phone-page@example.com", "--chatgpt-base", providerUrl, "--auth-base", providerUrl, "--output-mode", "sub2api", "--sub2api-out", path.join(protocolDirectory, "sub2api-import-oauth.json"), "--checkpoint", path.join(protocolDirectory, "login-checkpoint.json"), "--verbose"], {
    cwd: root, env: { ...process.env, NODE_ENV: "test", TOSUB2_TEST_SENTINEL_TOKEN: "mock-sentinel-challenge", TOSUB2_TEST_SENTINEL_SO_TOKEN: "mock-so-token", ONBOARDING_OUTPUT_ROOT: outputRoot, ONBOARDING_DATABASE_PATH: database.databasePath }, stdio: ["pipe", "pipe", "pipe"],
  });
  let protocolOutput = "";
  let tail = "";
  let index = 0;
  protocol.stdout.on("data", (chunk) => {
    protocolOutput += chunk; tail += chunk;
    const step = steps[index];
    if (step?.pattern.test(tail)) { step.before?.(); protocol.stdin.write(`${step.value}\n`); index += 1; tail = ""; }
  });
  protocol.stderr.on("data", (chunk) => { protocolOutput += chunk; });
  const timer = setTimeout(() => protocol.kill("SIGKILL"), 25000);
  const exitCode = await new Promise((resolve) => protocol.once("close", resolve));
  clearTimeout(timer);
  assert.equal(exitCode, 0, protocolOutput);
  assert.equal(checkpointObserved, true);
  assert.equal(database.readArtifact(path.join(protocolDirectory, "login-checkpoint.json")), null);
  assert.equal(database.readArtifact(path.join(protocolDirectory, "sub2api-import-oauth.json")).type, "sub2api-data");
  database.close();
  database = null;
  console.log("server database migration, encryption, settings concurrency, restart, deletion and live protocol persistence tests passed");
} catch (error) {
  error.message += `\nConsole output:\n${applicationOutput}`;
  throw error;
} finally {
  database?.close();
  await stopApplication();
  if (provider?.exitCode === null) { const exited = new Promise((resolve) => provider.once("close", resolve)); provider.kill("SIGTERM"); await exited; }
  await fs.rm(temporaryRoot, { recursive: true, force: true });
}

async function startApplication() {
  const port = await availablePort();
  baseUrl = `http://127.0.0.1:${port}`;
  application = spawn(process.execPath, [path.join(root, "src/console-server.mjs"), "--port", String(port)], { cwd: root, env: { ...process.env, NODE_ENV: "test", ONBOARDING_OUTPUT_ROOT: outputRoot }, stdio: ["ignore", "pipe", "pipe"] });
  application.stdout.on("data", (chunk) => { applicationOutput = `${applicationOutput}${chunk}`.slice(-20000); });
  application.stderr.on("data", (chunk) => { applicationOutput = `${applicationOutput}${chunk}`.slice(-20000); });
  token = (await waitFor(async () => { if (application.exitCode !== null) throw new Error("application stopped"); try { const response = await fetch(`${baseUrl}/api/bootstrap`); return response.ok ? response.json() : null; } catch { return null; } })).token;
}
async function stopApplication() {
  if (!application || application.exitCode !== null) return;
  const exited = new Promise((resolve) => application.once("close", resolve));
  application.kill("SIGTERM");
  await exited;
  application = null;
}
async function request(endpoint, method = "GET", body, expectedStatus = 200) {
  const response = await fetch(`${baseUrl}${endpoint}`, { method, headers: { "content-type": "application/json", "x-console-token": token }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  const payload = await response.json();
  assert.equal(response.status, expectedStatus, JSON.stringify(payload));
  assert.equal(response.headers.get("cache-control"), "no-store");
  return payload;
}
async function waitFor(operation) {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) { const result = await operation(); if (result) return result; await new Promise((resolve) => setTimeout(resolve, 50)); }
  throw new Error("database test state timed out");
}
async function availablePort() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}
