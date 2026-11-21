import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { createScheduledTaskEngine, createScheduledTaskStore, normalizeSchedule, publicSchedule, publicScheduleItem } from "../src/scheduled-tasks.mjs";

const origin = Date.parse("2026-11-12T00:00:00.000Z");
const defaultLocal = "2026-11-12T09:00:00"; // 01:00 UTC, explicitly Beijing time.

test("Beijing date validation, exact UTC conversion and safe defaults", () => {
  const result = normalizeSchedule({ scheduledLocal: defaultLocal });
  assert.equal(result.timeZone, "Asia/Shanghai");
  assert.equal(result.plannedAt, "2026-11-12T01:00:00.000Z");
  assert.equal(result.prepareAt, "2026-11-12T00:30:00.000Z");
  assert.equal(result.prepareLeadMinutes, 30);
  assert.equal(result.postLogoutDelayMinutes, 30);
  assert.deepEqual(result.crsSettings, { concurrencyLimit: 20, weight: 99, credentialGuardian: { enabled: true } });
  assert.equal(normalizeSchedule({ scheduledLocal: "2024-02-29T00:00" }).plannedAt, "2024-02-28T16:00:00.000Z");
  for (const scheduledLocal of ["2026-02-29T09:00", "2026-04-31T09:00", "2026-13-01T09:00", "2026-11-12T24:00", "2026-11-12T09:60", "2026-11-12T09:00:60", "2026-11-12T09:00Z", "2026-11-12 09:00", "2019-01-01T00:00", "2101-01-01T00:00", ""]) {
    assert.throws(() => normalizeSchedule({ scheduledLocal }), undefined, scheduledLocal);
  }
  assert.throws(() => normalizeSchedule({ scheduledLocal: defaultLocal, timeZone: "America/Detroit" }), /北京时间/);
  for (const field of ["prepareLeadMinutes", "postLogoutDelayMinutes"]) {
    for (const value of [0, 1440]) assert.equal(normalizeSchedule({ scheduledLocal: defaultLocal, [field]: value })[field], value);
    for (const value of [-1, 1441, 0.5, "30", Number.NaN]) assert.throws(() => normalizeSchedule({ scheduledLocal: defaultLocal, [field]: value }), /1440/);
  }
  for (const weight of [0, 101, 1.5, "99"]) assert.throws(() => normalizeSchedule({ scheduledLocal: defaultLocal, crsSettings: { weight } }), /优先级/);
  assert.throws(() => normalizeSchedule({ scheduledLocal: defaultLocal, crsSettings: { concurrencyLimit: 0 } }), /并发/);
  assert.throws(() => normalizeSchedule({ scheduledLocal: defaultLocal, securityAction: "unknown" }), /安全操作/);
  assert.equal(normalizeSchedule({ scheduledLocal: defaultLocal, crsSettings: { credentialGuardian: { enabled: false } } }).crsSettings.credentialGuardian.enabled, false);
});

test("plan creation is idempotent and one normalized email retains one owner", (t) => {
  const f = fixture(t);
  const job = f.job("owner@example.invalid");
  const first = f.plan({ accounts: [{ jobId: job.id, email: "Owner@Example.Invalid" }], clientRequestId: "request-owner-0001", fingerprint: "same-request" });
  const repeated = f.plan({ accounts: [{ jobId: job.id, email: "Owner@Example.Invalid" }], clientRequestId: "request-owner-0001", fingerprint: "same-request" });
  assert.equal(repeated.id, first.id);
  assert.equal(f.store.list().length, 1);
  assert.equal(f.store.owner(" owner@example.invalid ").item.id, first.items[0].id);
  assert.throws(() => f.plan({ clientRequestId: "request-owner-0001", fingerprint: "different-request" }), (error) => error.status === 409);
  assert.throws(() => f.plan({ accounts: [{ jobId: job.id, email: "owner@example.invalid" }] }), (error) => error.status === 409);
  f.store.updateItem(first.id, first.items[0].id, { status: "needs_attention" });
  assert.ok(f.store.owner(job.email), "unresolved mutations must continue to reserve the email");
  f.store.updateItem(first.id, first.items[0].id, { status: "canceled" });
  assert.equal(f.store.owner(job.email), null);
  assert.notEqual(f.plan({ accounts: [{ jobId: job.id, email: job.email }] }).id, first.id);
});

test("duplicate normalized emails within one request reject atomically", (t) => {
  const f = fixture(t);
  const job = f.job("duplicate@example.invalid");
  assert.throws(() => f.plan({ accounts: [{ jobId: job.id, email: job.email }, { jobId: job.id, email: "DUPLICATE@example.invalid" }] }), (error) => error.status === 409);
  assert.equal(f.store.list().length, 0);
  assert.equal(f.store.owner(job.email), null);
});

test("a failed account save rolls back credentials, plan, request and owner together", (t) => {
  const f = fixture(t);
  const account = f.job("atomic@example.invalid");
  const clientRequestId = "atomic-create-request";
  assert.throws(() => f.store.create({ clientRequestId, fingerprint: "atomic", config: normalizeSchedule({ scheduledLocal: defaultLocal }),
    accounts: [{ email: account.email, jobId: account.id }], targetIdentity: {},
    persistAccounts() { f.database.put("credentials", account.email, { password: "synthetic" }); throw new Error("injected account save failure"); },
  }), /injected/);
  assert.equal(f.store.list().length, 0);
  assert.equal(f.store.owner(account.email), null);
  assert.equal(f.store.request(clientRequestId, "atomic"), null);
  assert.equal(f.database.get("credentials", account.email), undefined);
});

test("security preparation starts once at the lead time, including concurrent ticks", async (t) => {
  const f = fixture(t);
  const plan = f.plan({ securityAction: "rotate-totp-logout-all" });
  const item = plan.items[0];
  f.at("2026-11-12T00:29:59.999Z");
  await f.engine.tick();
  assert.equal(f.calls.security.length, 0);
  f.at(plan.prepareAt);
  await Promise.all([f.engine.tick(), f.engine.tick(), f.engine.tick()]);
  assert.equal(f.calls.security.length, 1);
  assert.equal(f.item(plan, item).status, "preparing");
  await f.engine.tick();
  assert.equal(f.calls.security.length, 1);
  assert.equal(f.calls.login.length, 0);
});

test("actual logout plus cooldown can postpone login beyond the planned time", async (t) => {
  const f = fixture(t);
  const plan = f.plan({ securityAction: "logout-all", postLogoutDelayMinutes: 30 });
  const item = plan.items[0];
  f.at(plan.prepareAt);
  await f.engine.tick();
  const operationId = f.item(plan, item).securityOperationId;
  f.security.set(operationId, { status: "completed", result: { logout_accepted: true, logoutAcceptedAt: "2026-11-12T00:55:00.000Z" } });
  f.at(plan.plannedAt);
  await f.engine.tick();
  assert.equal(f.item(plan, item).loginNotBefore, "2026-11-12T01:25:00.000Z");
  assert.equal(f.calls.login.length, 0);
  f.at("2026-11-12T01:24:59.999Z"); await f.engine.tick();
  assert.equal(f.calls.login.length, 0);
  f.at("2026-11-12T01:25:00.000Z"); await f.engine.tick();
  assert.equal(f.calls.login.length, 1);
  await f.engine.tick();
  assert.equal(f.calls.login.length, 1);
  assert.equal(f.item(plan, item).attempts, 1);
});

test("an earlier logout or rotation never starts login before the planned time", async (t) => {
  for (const action of ["rotate-totp", "logout-all"]) {
    const f = fixture(t);
    const plan = f.plan({ securityAction: action, postLogoutDelayMinutes: 0 });
    const item = plan.items[0];
    f.at(plan.prepareAt); await f.engine.tick();
    f.security.set(f.item(plan, item).securityOperationId, { status: "completed", result: { logout_accepted: true, logoutAcceptedAt: plan.prepareAt } });
    await f.engine.tick();
    assert.equal(f.item(plan, item).loginNotBefore, plan.plannedAt);
    assert.equal(f.calls.login.length, 0);
    f.at(plan.plannedAt); await f.engine.tick();
    assert.equal(f.calls.login.length, 1);
  }
});

test("restart during an unrecorded security start requires attention without replay", async (t) => {
  const f = fixture(t);
  const plan = f.plan({ securityAction: "rotate-totp" });
  const item = plan.items[0];
  f.store.updateItem(plan.id, item.id, { status: "preparing", phase: "security", securityOperationId: "record-lost-after-intent" });
  await f.restart();
  f.at(plan.plannedAt); await f.engine.tick(); await f.engine.tick();
  assert.equal(f.item(plan, item).status, "needs_attention");
  assert.equal(f.calls.security.length, 0);
  assert.equal(f.calls.login.length, 0);
  assert.ok(f.store.owner(item.email));
});

test("confirmed security without a valid logout acknowledgement never proceeds", async (t) => {
  const f = fixture(t);
  const plan = f.plan({ securityAction: "logout-all" });
  const item = plan.items[0];
  f.at(plan.prepareAt); await f.engine.tick();
  f.security.set(f.item(plan, item).securityOperationId, { status: "completed", result: { logout_accepted: true } });
  f.at(plan.plannedAt); await f.engine.tick();
  assert.equal(f.item(plan, item).status, "needs_attention");
  assert.equal(f.calls.login.length, 0);
});

test("matching login generation publishes once and survives engine restoration", async (t) => {
  const f = fixture(t);
  const plan = f.plan();
  const item = plan.items[0];
  f.at(plan.plannedAt); await f.engine.tick();
  const persistedAttempt = f.item(plan, item).loginAttemptId;
  await f.restart(); await f.engine.tick();
  assert.equal(f.calls.login.length, 1, "restart must inspect the prior login generation");
  assert.equal(f.item(plan, item).loginAttemptId, persistedAttempt);
  f.jobs.get(item.jobId).status = "completed";
  await f.engine.tick();
  assert.equal(f.calls.publish.length, 1);
  await f.engine.tick();
  assert.equal(f.calls.publish.length, 1, "pending remote entry must be looked up rather than republished");
  const published = f.published.get(item.id);
  f.published.set(item.id, { ...published, status: "succeeded", accountIds: ["synthetic-crs-account"] });
  await f.engine.tick();
  assert.equal(f.item(plan, item).status, "completed");
  assert.equal(f.store.owner(item.email), null);
  assert.deepEqual(f.item(plan, item).crs.accountIds, ["synthetic-crs-account"]);
  assert.equal(publicSchedule(f.store.read(plan.id)).status, "completed");
});

test("the login hook rejects a stale generation instead of publishing it", async (t) => {
  const f = fixture(t);
  const plan = f.plan();
  const item = plan.items[0];
  f.at(plan.plannedAt); await f.engine.tick();
  Object.assign(f.jobs.get(item.jobId), { status: "completed", scheduledLoginAttemptId: "another-login-generation" });
  await f.engine.tick();
  assert.equal(f.item(plan, item).status, "failed");
  assert.equal(f.calls.publish.length, 0);
});

test("unknown CPR result remains visible and is never automatically resubmitted", async (t) => {
  const f = fixture(t);
  const plan = f.plan();
  const item = plan.items[0];
  f.at(plan.plannedAt); await f.engine.tick();
  f.jobs.get(item.jobId).status = "completed";
  await f.engine.tick();
  const original = f.published.get(item.id);
  f.published.set(item.id, { ...original, status: "unknown", message: "Submission response was interrupted", submittedAt: new Date(f.now()).toISOString() });
  await f.engine.tick();
  await f.restart(); await f.engine.tick();
  assert.equal(f.calls.publish.length, 1);
  assert.equal(f.item(plan, item).status, "needs_attention");
  assert.equal(f.item(plan, item).outboxEntryId, original.entryId);
  assert.equal(f.item(plan, item).crs.status, "unknown");
  assert.ok(f.store.owner(item.email));
});

test("cancel handles pending publication and preserves already submitted results", async (t) => {
  for (const [remoteStatus, submittedAt, expected] of [["pending", null, "canceled"], ["running", "2026-11-12T01:00:00.000Z", "needs_attention"], ["unknown", "2026-11-12T01:00:00.000Z", "needs_attention"], ["succeeded", "2026-11-12T01:00:00.000Z", "completed"]]) {
    const f = fixture(t);
    const plan = f.plan();
    const item = plan.items[0];
    f.store.updateItem(plan.id, item.id, { status: "publishing", phase: "publish" });
    f.published.set(item.id, { entryId: "persisted-entry", status: remoteStatus, submittedAt, accountIds: remoteStatus === "succeeded" ? ["accepted-account"] : [], message: "remote state" });
    await f.engine.cancel(plan.id, [item.id]);
    assert.equal(f.item(plan, item).status, expected);
    assert.equal(f.calls.cancelPublish.length, 1);
    assert.equal(f.calls.cancelJob.length, remoteStatus === "pending" ? 1 : 0);
    if (remoteStatus === "succeeded") assert.deepEqual(f.item(plan, item).crs.accountIds, ["accepted-account"]);
    await f.engine.tick();
    assert.equal(f.calls.publish.length, 0);
  }
});

test("cancel preserves uncertain security changes and partial batch outcomes", async (t) => {
  const f = fixture(t);
  const a = f.job("partial-a@example.invalid");
  const b = f.job("partial-b@example.invalid");
  const plan = f.plan({ securityAction: "rotate-totp", accounts: [a, b].map((job) => ({ jobId: job.id, email: job.email })) });
  const [first, second] = plan.items;
  f.store.updateItem(plan.id, first.id, { status: "completed", phase: "done" });
  f.store.updateItem(plan.id, second.id, { status: "preparing", phase: "security", securityOperationId: "partial-security" });
  f.security.set("partial-security", { status: "needs_attention", error: "New key activated; confirmation interrupted" });
  await f.engine.cancel(plan.id);
  assert.equal(f.item(plan, first).status, "completed");
  assert.equal(f.item(plan, second).status, "needs_attention");
  assert.equal(f.item(plan, second).securityOperationId, "partial-security");
  assert.equal(publicSchedule(f.store.read(plan.id)).status, "needs_attention");
  assert.ok(f.store.owner(second.email));
});

test("manual supersession prevents every later scheduled phase and releases ownership", async (t) => {
  for (const phase of ["scheduled", "waiting", "login_queued", "publishing"]) {
    const f = fixture(t);
    const plan = f.plan({ securityAction: "rotate-totp-logout-all" });
    const item = plan.items[0];
    f.store.updateItem(plan.id, item.id, { status: phase });
    f.store.updateItem(plan.id, item.id, { status: "superseded", error: "A manual operation replaced the schedule" });
    f.at("2026-11-13T00:00:00.000Z");
    await f.engine.tick();
    assert.equal(f.calls.security.length + f.calls.login.length + f.calls.publish.length, 0);
    assert.equal(f.store.owner(item.email), null);
    assert.equal(f.item(plan, item).status, "superseded");
  }
});

test("public schedule summaries omit credentials and internal login generation", (t) => {
  const f = fixture(t);
  const job = f.job("private@example.invalid");
  const plan = f.plan({ accounts: [{ jobId: job.id, email: job.email, password: "test-private-password", totpSecret: "JBSWY3DPEHPK3PXP" }] });
  const item = f.store.updateItem(plan.id, plan.items[0].id, { loginAttemptId: "private-login-generation" });
  const serialized = JSON.stringify({ plan: publicSchedule(f.store.read(plan.id)), item: publicScheduleItem(item) });
  assert.doesNotMatch(serialized, /test-private-password|JBSWY3DPEHPK3PXP|private-login-generation|fingerprint|targetIdentity/);
});

function fixture(t) {
  let clock = origin;
  const records = new Map();
  const database = {
    get(kind, id) { return structuredClone(records.get(`${kind}:${id}`)); },
    put(kind, id, value) { records.set(`${kind}:${id}`, structuredClone(value)); },
    remove(kind, id) { records.delete(`${kind}:${id}`); },
    recordIds(kind) { return [...records.keys()].filter((key) => key.startsWith(`${kind}:`)).map((key) => key.slice(kind.length + 1)); },
    transaction(work) { const before = structuredClone(records); try { return work(); } catch (error) { records.clear(); for (const [key, value] of before) records.set(key, value); throw error; } },
  };
  const store = createScheduledTaskStore(database, { now: () => clock });
  const jobs = new Map(), security = new Map(), published = new Map(), locks = new Map();
  const calls = { security: [], login: [], publish: [], cancelPublish: [], cancelJob: [] };
  const hooks = {
    getJob: (id) => jobs.get(id),
    canStart: (job) => job.status === "completed",
    paused: () => false,
    safeError: (value) => String(value).replaceAll("test-private-password", "[hidden]"),
    withLock(email, work) { const key = email.toLowerCase(); const promise = (locks.get(key) || Promise.resolve()).then(work); locks.set(key, promise.catch(() => {})); return promise; },
    async startSecurity(schedule, item, operationId) { calls.security.push({ scheduleId: schedule.id, itemId: item.id, operationId }); security.set(operationId, { status: "running" }); },
    readSecurity: (id) => security.get(id),
    async startLogin(schedule, item, attemptId) { calls.login.push({ scheduleId: schedule.id, itemId: item.id, attemptId }); Object.assign(jobs.get(item.jobId), { status: "running", scheduledLoginAttemptId: attemptId }); },
    loginState(item, job) { return job.scheduledLoginAttemptId !== item.loginAttemptId ? { status: "failed", error: "Login result belongs to another generation" } : { status: job.status }; },
    lookupPublish: (item) => published.get(item.id) || null,
    async publish(schedule, item) { calls.publish.push({ scheduleId: schedule.id, itemId: item.id }); const result = { entryId: crypto.randomUUID(), status: "pending", accountIds: [], message: "waiting" }; published.set(item.id, result); return result; },
    async cancelPublish(item) { calls.cancelPublish.push(item.id); const result = published.get(item.id); if (result?.status === "pending" && !result.submittedAt) { const canceled = { ...result, status: "canceled" }; published.set(item.id, canceled); return canceled; } return result; },
    async cancelJob(item) { calls.cancelJob.push(item.id); },
  };
  const createEngine = () => createScheduledTaskEngine({ store, hooks, now: () => clock });
  const f = { database, store, jobs, security, published, calls, hooks, engine: createEngine(), now: () => clock,
    at(value) { clock = typeof value === "number" ? value : Date.parse(value); assert.ok(Number.isFinite(clock)); },
    job(email = `${crypto.randomUUID()}@example.invalid`) { const job = { id: crypto.randomUUID(), email, status: "completed" }; jobs.set(job.id, job); return job; },
    plan(options = {}) { const job = options.accounts ? null : f.job(); const config = normalizeSchedule({ scheduledLocal: defaultLocal, ...options }); return store.create({ clientRequestId: options.clientRequestId || crypto.randomUUID(), fingerprint: options.fingerprint || crypto.randomUUID(), config, targetIdentity: { baseUrl: "http://127.0.0.1:1", authType: "apiKey", username: "" }, accounts: options.accounts || [{ jobId: job.id, email: job.email }] }); },
    item(plan, item) { return store.read(plan.id).items.find((value) => value.id === item.id); },
    async restart() { await f.engine.close(); f.engine = createEngine(); },
  };
  t.after(() => f.engine.close());
  return f;
}
