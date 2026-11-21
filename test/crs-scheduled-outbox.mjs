import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import { createCrsIntegration, seedCrsConfiguration } from "../src/crs-integration.mjs";

// This test contacts only its own loopback CPR mock. Credentials and jobs are synthetic.
const records = new Map();
const database = {
  get(kind, id) { return structuredClone(records.get(`${kind}:${id}`)); },
  put(kind, id, value) { records.set(`${kind}:${id}`, structuredClone(value)); },
  getJob() { return {}; },
};
const jobs = new Map();
const tasks = new Map();
const submissions = [];
const apiKey = "private-test-crs-key";
const rotatedApiKey = "private-test-rotated-crs-key";
const keyValues = [apiKey, rotatedApiKey];
let service;
let readCount = 0;
const remote = http.createServer(async (request, response) => {
  try {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {};
    const url = new URL(request.url, "http://127.0.0.1");
    if (!keyValues.includes(request.headers["x-api-key"])) return send(401, {});
    if (url.pathname === "/api/admin/account-groups/options") return send(200, { items: [{ id: "openai", name: "OpenAI", enabled: true }, { id: "planned", name: "Planned", enabled: true }], page: { totalPages: 1 } });
    if (url.pathname === "/api/admin/accounts/import-tasks" && request.method === "POST") {
      submissions.push({ body, apiKey: request.headers["x-api-key"] });
      const account = body.items[0].data.accounts[0];
      const taskId = crypto.randomUUID();
      tasks.set(taskId, { status: account.name.startsWith("slow-") ? "running" : "succeeded" });
      if (account.name.startsWith("uncertain-")) { request.socket.destroy(); return; }
      return send(202, { taskId });
    }
    if (url.pathname === "/api/admin/accounts/import-tasks/detail") {
      const taskId = url.searchParams.get("taskId");
      const task = tasks.get(taskId);
      if (!task) return send(404, {});
      return send(200, { taskId, finishedAt: task.status === "running" ? null : new Date().toISOString(), items: [{ index: 0, status: task.status, canRetry: false, accountIds: task.status === "succeeded" ? [`account-${taskId}`] : [] }] });
    }
    return send(404, {});
    function send(status, data) { response.writeHead(status, { "content-type": "application/json" }); response.end(JSON.stringify({ code: status >= 400 ? status : 200, data })); }
  } catch (error) {
    response.writeHead(500, { "content-type": "application/json" });
    response.end(JSON.stringify({ code: 500, data: {} }));
  }
});
await new Promise((resolve, reject) => { remote.once("error", reject); remote.listen(0, "127.0.0.1", resolve); });
const config = { baseUrl: `http://127.0.0.1:${remote.address().port}`, authType: "apiKey", apiKey, autoUpload: true };
seedCrsConfiguration(database, config);
const settings = { groupIds: ["planned"], concurrencyLimit: 20, weight: 99, credentialGuardian: { enabled: true } };

try {
  service = create();
  configure(config);
  const targetIdentity = service.getTargetIdentity();
  assert.deepEqual(targetIdentity, { baseUrl: config.baseUrl, authType: "apiKey", username: "" });
  assert.equal(service.lookupScheduled("missing-item"), null);
  const first = job("first");
  for (const weight of [0, 101, 1.5, "99", null]) {
    if (weight === null) continue; // Missing/null uses the ordinary manual-import default.
    await assert.rejects(service.saveAccountSettings([first.id], { ...settings, weight }), /优先级/);
  }
  await service.saveAccountSettings([first.id], { ...settings, weight: 100 });
  assert.equal(service.accountSettings().settings[first.id].weight, 100);
  const firstInput = { scheduleItemId: "planned-first", settings: structuredClone(settings), targetIdentity };
  const firstPromise = service.enqueueScheduled(first.id, firstInput);
  firstInput.settings.concurrencyLimit = 1;
  const concurrent = service.enqueueScheduled(first.id, { scheduleItemId: "planned-first", settings, targetIdentity });
  const [firstEntry, duplicate] = await Promise.all([firstPromise, concurrent]);
  assert.equal(firstEntry.entryId, duplicate.entryId, "concurrent scheduler ticks share one persisted submission");
  const completed = await waitState("planned-first", "succeeded");
  assert.deepEqual(submissions[0].body.items[0].settings, { enabled: true, ...settings }, "the plan snapshot overrides later account defaults and caller mutation");
  assert.equal(submissions[0].body.items[0].settings.priority, undefined, "CPR priority must be serialized as weight");
  const submittedCount = submissions.length;
  const readsBeforeReentry = readCount;
  first.exportData.accounts[0].credentials.access_token = "private-access-new-generation";
  assert.equal((await service.enqueueScheduled(first.id, { scheduleItemId: "planned-first", settings, targetIdentity })).entryId, completed.entryId);
  assert.equal(readCount, readsBeforeReentry, "existing planned publication must not reread a later login generation");
  assert.equal(submissions.length, submittedCount);
  assert.equal((await service.cancelScheduled("planned-first")).status, "succeeded", "cancel cannot rewrite an accepted import");
  await assert.rejects(service.enqueueScheduled(job("different").id, { scheduleItemId: "planned-first", settings, targetIdentity }), /其他账号/);
  await assert.rejects(service.enqueueScheduled(first.id, { scheduleItemId: "planned-first", settings, targetIdentity: { ...targetIdentity, username: "different" } }), /其他账号/);

  await service.close();
  service = create();
  assert.equal((await service.enqueueScheduled(first.id, { scheduleItemId: "planned-first", settings, targetIdentity })).entryId, firstEntry.entryId, "stable item deduplication survives restoration");
  assert.equal(submissions.length, submittedCount);
  // Ordinary later imports change job-level status, but not the planned operation's evidence.
  await service.enqueue([first.id]);
  await waitFor(() => submissions.length === submittedCount + 1);
  assert.deepEqual(service.lookupScheduled("planned-first").accountIds, completed.accountIds);

  const canceled = job("canceled");
  const beforeCancel = submissions.length;
  await service.enqueueScheduled(canceled.id, { scheduleItemId: "planned-canceled", settings, targetIdentity });
  assert.equal((await service.cancelScheduled("planned-canceled")).status, "canceled");
  await delay(30);
  assert.equal(submissions.length, beforeCancel);
  assert.equal((await service.enqueueScheduled(canceled.id, { scheduleItemId: "planned-canceled", settings, targetIdentity })).status, "canceled", "a canceled item cannot create a replacement submission");
  assert.ok(service.status().counts.canceled >= 1);

  const uncertain = job("uncertain-one");
  await service.enqueueScheduled(uncertain.id, { scheduleItemId: "planned-uncertain", settings, targetIdentity });
  const unknown = await waitState("planned-uncertain", "unknown");
  assert.ok(unknown.submittedAt);
  const beforeUnknownReentry = submissions.length;
  uncertain.exportData.accounts[0].credentials.access_token = "private-access-after-unknown";
  await service.close(); service = create();
  assert.equal((await service.enqueueScheduled(uncertain.id, { scheduleItemId: "planned-uncertain", settings, targetIdentity })).status, "unknown");
  assert.equal((await service.cancelScheduled("planned-uncertain")).status, "unknown");
  await delay(30);
  assert.equal(submissions.length, beforeUnknownReentry, "an uncertain submission is never automatically replayed");

  const slow = job("slow-one");
  await service.enqueueScheduled(slow.id, { scheduleItemId: "planned-slow", settings, targetIdentity });
  const running = await waitFor(() => { const value = service.lookupScheduled("planned-slow"); return value?.taskId && value.status === "running" ? value : null; });
  assert.equal((await service.cancelScheduled("planned-slow")).status, "running", "cancel after acceptance returns the actual state");
  tasks.get(running.taskId).status = "succeeded";
  await waitState("planned-slow", "succeeded");

  const changed = job("target-changed");
  const beforeChange = submissions.length;
  await service.enqueueScheduled(changed.id, { scheduleItemId: "planned-target-changed", settings, targetIdentity });
  configure({ ...config, authType: "password", username: "different-admin", password: "private-other-password" });
  assert.equal((await waitState("planned-target-changed", "failed")).submittedAt, null);
  assert.equal(submissions.length, beforeChange, "changing target identity before dispatch blocks the import");
  await assert.rejects(service.enqueueScheduled(job("wrong-target").id, { scheduleItemId: "planned-wrong-target", settings, targetIdentity }), /目标或登录身份/);
  configure(config);

  const rotated = job("rotated-api-key");
  await service.enqueueScheduled(rotated.id, { scheduleItemId: "planned-key-rotation", settings, targetIdentity });
  configure({ ...config, apiKey: rotatedApiKey });
  await waitState("planned-key-rotation", "succeeded");
  assert.equal(submissions.at(-1).apiKey, rotatedApiKey, "same-identity credential rotation is honored at dispatch");

  const gated = job("early-preparation");
  gated.scheduleItemId = "planned-future";
  const beforeAutomatic = submissions.length;
  await service.authorizationCompleted(gated);
  await delay(30);
  assert.equal(submissions.length, beforeAutomatic, "planned jobs must wait for the scheduler even when global auto-upload is enabled");
  assert.equal(service.lookupScheduled(gated.scheduleItemId), null);
  delete gated.scheduleItemId;
  await service.authorizationCompleted(gated);
  await waitFor(() => submissions.length === beforeAutomatic + 1);

  for (const id of ["planned-first", "planned-uncertain", "planned-key-rotation"]) {
    assert.doesNotMatch(JSON.stringify(service.lookupScheduled(id)), /private-|access_token|refresh_token|snapshot|apiKey/);
  }
  console.log("CPR scheduled outbox: priority mapping, frozen settings, stable item deduplication, restart, cancellation, target binding, credential rotation and automatic-upload gate passed");
} finally {
  await service?.close();
  await new Promise((resolve) => remote.close(resolve));
}

function create() { return createCrsIntegration({ database, getJob: (id) => jobs.get(id), readExport: async (item) => { readCount += 1; return item.exportData; }, requestTimeoutMs: 300, pollIntervalMs: 5, taskTimeoutMs: 3000 }); }
function configure(value) { return service.putConfiguration(value, service.getConfiguration().revision); }
function job(label) {
  const id = crypto.randomUUID();
  const email = `${label}@example.invalid`;
  const value = { id, email, resultSaved: true, exportData: { type: "sub2api-data", accounts: [{ name: label, credentials: { email, access_token: `private-access-${label}`, refresh_token: `private-refresh-${label}` } }] } };
  jobs.set(id, value); return value;
}
function waitState(id, expected) { return waitFor(() => { const value = service.lookupScheduled(id); return value?.status === expected ? value : null; }); }
async function waitFor(check) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) { const result = check(); if (result) return result; await delay(5); }
  throw new Error("scheduled CPR outbox test timed out");
}
function delay(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }
