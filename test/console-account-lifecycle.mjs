import assert from "node:assert/strict";
import fs from "node:fs/promises";
import net from "node:net";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
const root = path.resolve(import.meta.dirname, "..");
const temporary = await fs.mkdtemp(path.join(os.tmpdir(), "console-lifecycle-"));
const output = path.join(temporary, "jobs");
const controlPath = path.join(temporary, "control.json");
const fixture = path.join(temporary, "protocol.mjs");
await fs.writeFile(controlPath, "{}");
await fs.writeFile(fixture, `import fs from "node:fs/promises";
import path from "node:path";
import {createServerDatabase} from ${JSON.stringify(new URL("../src/server-database.mjs", import.meta.url).href)};
import {createSecurityFailureMarker} from ${JSON.stringify(new URL("../src/security-failure.mjs", import.meta.url).href)};
const arg=n=>process.argv[process.argv.indexOf(n)+1];const email=arg('--email');
const control=JSON.parse(await fs.readFile(process.env.LIFECYCLE_CONTROL,'utf8'));
const db=createServerDatabase({databasePath:process.env.ONBOARDING_DATABASE_PATH,outputRoot:process.env.ONBOARDING_OUTPUT_ROOT,mustExist:true});
if(process.argv.includes('--security-action') && control.securityError){
 console.log('[security-failure] '+JSON.stringify(createSecurityFailureMarker(Object.assign(new Error(control.securityError),{httpStatus:control.httpStatus||403}),{phase:'login',journalPresent:false,mutationStarted:false})));process.exitCode=1;
}else if(process.argv.includes('--security-action')){
 const action=arg('--security-action');const now=new Date().toISOString();
 const result={version:1,operationId:arg('--security-operation-id'),email,action,status:control.uncertain?'needs_attention':'completed',stage:'logout_requested',startedAt:now,updatedAt:now,work_reset_succeeded:true,logout_accepted:!control.uncertain,logoutAcceptedAt:control.uncertain?null:now};
 db.put('security-operation-result',result.operationId,result);await fs.writeFile(arg('--security-result'),JSON.stringify(result));
 console.log('[security] logout_requested');
 if(control.hang)await new Promise(()=>setInterval(()=>{},1000));
}else if(control.fail){console.log('[security-check-required]');process.exitCode=1;
}else{
 if(control.delay)await new Promise(r=>setTimeout(r,control.delay));
 const output=arg('--sub2api-out');const data={type:'sub2api-data',version:1,exported_at:new Date().toISOString(),accounts:[{name:email,credentials:{email,access_token:'synthetic-access',refresh_token:'synthetic-refresh'}}]};
 await fs.mkdir(path.dirname(output),{recursive:true});await fs.writeFile(output,JSON.stringify(data));db.saveArtifact(output,data);console.log('[ok] Saved sub2api import: '+output);
}db.close();`);
const listener = net.createServer();
await new Promise((resolve) => listener.listen(0, "127.0.0.1", resolve));
const port = listener.address().port; await new Promise((resolve) => listener.close(resolve));
const base = `http://127.0.0.1:${port}`;
let child, exited, headers, logs = "";
let uploadSeen = false, releaseUpload;
const uploadGate = new Promise(resolve => { releaseUpload = resolve; });
const remote = http.createServer(async (request, response) => {
  for await (const chunk of request) { void chunk; }
  uploadSeen = true;
  await uploadGate;
  response.writeHead(200, { "content-type": "application/json" });
  response.end(JSON.stringify({ success: 1 }));
});
await new Promise(resolve => remote.listen(0, "127.0.0.1", resolve));
try {
  await start();
  const primary = (await api("/api/jobs", { email: "primary@example.invalid", startLogin: false, accountTerm: "short", password: "synthetic-password", totpSecret: "JBSWY3DPEHPK3PXP", proxyUrl: "socks5://proxy.example.invalid:1080" })).job;
  assert.equal(primary.accountTerm, "short"); assert.equal(primary.firstAuthorizedAt, null);
  const batch = await api("/api/jobs/batch", { text: "batch-a@example.invalid\nbatch-b@example.invalid", startLogin: false, accountTerm: "short", accountTerms: [{ email: "batch-b@example.invalid", accountTerm: "long" }] });
  assert.deepEqual(batch.jobs.map((job) => job.accountTerm), ["short", "long"]);
  const beforeCount = (await api("/api/jobs")).pagination.total;
  for (const body of [{ accountTerm: "invalid" }, { accountTerms: [{ email: "unknown@example.invalid", accountTerm: "short" }] }, { accountTerms: [{ email: "rejected@example.invalid", accountTerm: "long" }, { email: "rejected@example.invalid", accountTerm: "short" }] }]) {
    await rejected("/api/jobs/batch", { text: "rejected@example.invalid\nother-rejected@example.invalid", startLogin: false, ...body });
  }
  assert.equal((await api("/api/jobs")).pagination.total, beforeCount, "bad type assignments never partially import");
  const edited = (await api(`/api/jobs/${primary.id}/account-term`, { accountTerm: "long" })).job;
  assert.equal(edited.accountTerm, "long"); assert.equal(edited.status, "ready"); assert.equal(edited.firstAuthorizedAt, null);
  await api(`/api/jobs/${primary.id}/relogin`, {});
  await waitFor(async () => (await detail(primary)).status === "completed");
  const upload = api("/api/sub2api/upload", { ids: [primary.id], config: {
    baseUrl: `http://127.0.0.1:${remote.address().port}`, adminApiKey: "synthetic-key",
  } });
  await waitFor(() => uploadSeen);
  await rejected(`/api/jobs/${primary.id}/rest`, {}, 409);
  await rejected(`/api/jobs/${primary.id}/retire`, { reason: "不能与推送竞争" }, 409);
  releaseUpload(); await upload;
  await assert.rejects(api("/api/sub2api/upload", { ids: [primary.id], config: {
    baseUrl: "http://127.0.0.1:9", adminApiKey: "synthetic-key",
  } }), "a failed upload must also release the movement guard");
  const manuallyRested = (await api(`/api/jobs/${primary.id}/rest`, {})).job;
  assert.equal(manuallyRested.resting, true);
  assert.equal(manuallyRested.restingReason, "manual");
  assert.equal(manuallyRested.securityOperation ?? null, null, "manual partition never sends logout");
  await rejected("/api/sub2api/upload", { ids: [primary.id], config: { baseUrl: "http://127.0.0.1:9", adminApiKey: "synthetic-key" } }, 409);
  await stop(); await start();
  assert.equal((await detail(primary)).restingReason, "manual", "manual rest survives restart");
  await api(`/api/jobs/${primary.id}/relogin`, {});
  await waitFor(async () => (await detail(primary)).status === "completed" && !(await detail(primary)).resting);
  const first = (await detail(primary)).firstAuthorizedAt;
  assert.ok(first); assert.equal((await detail(primary)).firstAuthorizedAtSource, "recorded");
  await api(`/api/jobs/${primary.id}/security`, { action: "logout-all" });
  await waitFor(async () => (await detail(primary)).securityOperation?.status === "completed");
  const rest = await detail(primary);
  assert.equal(rest.resting, true); assert.equal(rest.restingReason, "logout_accepted"); assert.ok(rest.restingSince);
  const normal = await api("/api/jobs?area=active"); const resting = await api("/api/jobs?area=resting");
  assert.equal(normal.jobs.some((job) => job.id === primary.id), false);
  assert.deepEqual(resting.selection.map((job) => job.id), [primary.id]);
  assert.deepEqual(resting.areaCounts, { active: 2, resting: 1, retired: 0, all: 3 });
  const filtered = await api("/api/jobs/query", { area: "active", emails: [primary.email] });
  assert.equal(filtered.jobs.length, 0); assert.equal(filtered.selection.length, 0);
  await rejected("/api/jobs/query", { area: "bad" });
  await rejected(`/api/jobs/${primary.id}/retire`, { reason: "" });
  const retired = (await api(`/api/jobs/${primary.id}/retire`, { reason: "上游账号已永久停用" })).job;
  assert.equal(retired.retired, true); assert.ok(retired.retiredAt);
  assert.equal(retired.accountTerm, "long"); assert.equal(retired.firstAuthorizedAt, first); assert.equal(retired.restingSince, rest.restingSince);
  assert.equal((await api("/api/jobs?area=resting")).selection.length, 0, "retired accounts do not also appear in the resting partition");
  assert.equal((await api("/api/jobs?area=retired")).selection[0].id, primary.id);
  assert.deepEqual((await api("/api/jobs?area=all")).areaCounts, { active: 2, resting: 0, retired: 1, all: 3 });
  assert.equal((await api("/api/jobs/query", { area: "active", emails: [primary.email] })).jobs.length, 0);
  await stop(); await start();
  assert.equal((await detail(primary)).retiredAt, retired.retiredAt); assert.equal((await detail(primary)).retiredReason, "上游账号已永久停用");
  assert.equal((await detail(primary)).restingSince, rest.restingSince); assert.equal((await detail(primary)).firstAuthorizedAt, first);
  await api(`/api/jobs/${primary.id}/regenerate`, {});
  await waitFor(async () => { const job = await detail(primary); return job.status === "completed" && job.lastOperationType === "reauthorize"; });
  assert.equal((await detail(primary)).resting, true, "refresh authorization cannot release rest");
  assert.equal((await detail(primary)).retired, true, "refresh cannot recover a retired account");
  assert.equal((await detail(primary)).firstAuthorizedAt, first);
  await fs.writeFile(controlPath, JSON.stringify({ fail: true }));
  await api(`/api/jobs/${primary.id}/relogin`, {});
  await waitFor(async () => ["failed", "reauth_required", "resume_available"].includes((await detail(primary)).status));
  assert.equal((await detail(primary)).resting, true, "failed full login cannot release rest");
  assert.equal((await detail(primary)).retired, true, "failed full login cannot recover a retired account");
  await stop(); await start();
  assert.equal((await detail(primary)).resting, true, "failed relogin cannot release rest after restart");
  await fs.writeFile(controlPath, JSON.stringify({ delay: 600 }));
  const pending = await api(`/api/jobs/${primary.id}/relogin`, {});
  await rejected(`/api/jobs/${primary.id}/rest`, {}, 409);
  await rejected(`/api/jobs/${primary.id}/retire`, { reason: "不能与上号任务竞争" }, 409);
  assert.equal(pending.job.resting, true, "queueing a full login does not release rest");
  await waitFor(async () => (await detail(primary)).status === "completed");
  assert.equal((await detail(primary)).resting, false); assert.equal((await detail(primary)).firstAuthorizedAt, first);
  assert.equal((await detail(primary)).retired, false, "successful full login recovers a retired account");
  await stop(); await start();
  assert.equal((await detail(primary)).resting, false, "old security history must not re-enter rest after successful full login");
  await fs.writeFile(controlPath, JSON.stringify({ uncertain: true, hang: true }));
  await api(`/api/jobs/${primary.id}/security`, { action: "logout-all" });
  await waitFor(async () => (await detail(primary)).restingReason === "logout_requested");
  assert.equal((await detail(primary)).resting, true, "a persisted logout request enters rest while its worker is still awaiting a response");
  await api(`/api/jobs/${primary.id}/cancel`, {});
  assert.equal((await detail(primary)).resting, true);
  const automatic = (await api("/api/jobs", { email: "automatic-retirement@example.invalid", startLogin: false, password: "synthetic-password", totpSecret: "JBSWY3DPEHPK3PXP", proxyUrl: "socks5://proxy.example.invalid:1080" })).job;
  for (const reason of ["HTTP 401 token_revoked", "HTTP 403 challenge required", "HTTP 403 IP blocked", "invalid_password"]) {
    await fs.writeFile(controlPath, JSON.stringify({ securityError: reason }));
    await api(`/api/jobs/${automatic.id}/security`, { action: "logout-all" });
    await waitFor(async () => (await detail(automatic)).securityOperation?.status === "failed");
    assert.equal((await detail(automatic)).retired, false, reason);
  }
  await fs.writeFile(controlPath, JSON.stringify({ securityError: 'HTTP 403 {"error":{"code":"account_deactivated"}}' }));
  await api(`/api/jobs/${automatic.id}/security`, { action: "logout-all" });
  await waitFor(async () => (await detail(automatic)).retired);
  const automaticRetired = await detail(automatic);
  assert.match(automaticRetired.retiredReason, /账号已被上游删除或停用/);
  assert.equal((await api("/api/jobs?area=retired")).selection.some((job) => job.id === automatic.id), true);
  await stop(); await start();
  assert.equal((await detail(automatic)).retiredAt, automaticRetired.retiredAt);
  console.log("console account lifecycle: single/batch types, atomic validation, tag-only edits, first authorization persistence, partitioned selection, logout duration, failed/queued/refresh exclusion and successful-login release passed");
} catch (error) { console.error(logs.slice(-4000)); throw error; }
finally { releaseUpload(); await stop(); await new Promise(resolve => remote.close(resolve)); await fs.rm(temporary, { recursive: true, force: true }); }
async function api(endpoint, body) {
  const response = await fetch(base + endpoint, { method: body === undefined ? "GET" : "POST", headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  const data = await response.json(); assert.ok(response.ok, `${endpoint}: ${response.status} ${JSON.stringify(data)}`); return data;
}
async function rejected(endpoint, body, expectedStatus = 400) { const r = await fetch(base + endpoint, { method: "POST", headers, body: JSON.stringify(body) }); assert.equal(r.status, expectedStatus); }
async function detail(job) { return api(`/api/jobs/${job.id}/details`); }
async function start() {
  child = spawn(process.execPath, ["src/console-server.mjs", "--host", "127.0.0.1", "--port", String(port)], { cwd: root, env: { ...process.env, NODE_ENV: "production", ONBOARDING_OUTPUT_ROOT: output, ONBOARDING_PROTOCOL_SCRIPT: fixture, LIFECYCLE_CONTROL: controlPath }, stdio: ["ignore", "pipe", "pipe"] });
  exited = new Promise((resolve) => child.once("exit", resolve)); child.stdout.on("data", (chunk) => { logs += chunk; }); child.stderr.on("data", (chunk) => { logs += chunk; });
  const bootstrap = await waitFor(async () => { if (child.exitCode !== null) throw new Error(logs); try { const r = await fetch(base + "/api/bootstrap"); return r.ok ? r.json() : null; } catch { return null; } });
  headers = { "content-type": "application/json", "x-console-token": bootstrap.token };
}
async function stop() { if (!child || child.exitCode !== null || child.signalCode) return; const current = child; current.kill("SIGTERM"); const timer = setTimeout(() => current.kill("SIGKILL"), 5000); try { await exited; } finally { clearTimeout(timer); } }
async function waitFor(check) { const deadline = Date.now() + 15000; while (Date.now() < deadline) { const value = await check(); if (value) return value; await new Promise((resolve) => setTimeout(resolve, 45)); } throw new Error("account lifecycle timeout"); }
