import assert from "node:assert/strict";
import { createSecurityOperationStore, publicSecurityOperation, requireSocks5Proxy, safeSecurityError, securityActionMode, validateSecurityResult } from "../src/security-operation-store.mjs";

const records = new Map();
const database = {
  get(kind, id) { return structuredClone(records.get(`${kind}:${id}`)); },
  put(kind, id, value) { records.set(`${kind}:${id}`, structuredClone(value)); },
  remove(kind, id) { records.delete(`${kind}:${id}`); },
  transaction(work) { return work(); },
};
const store = createSecurityOperationStore(database);
const secret = "NB2W45DFOIZAQWER";
const job = { id: "synthetic-job", email: "owner@example.invalid", status: "completed", prompt: "done", totpSecret: "JBSWY3DPEHPK3PXP" };
for (const invalid of ["", "http://host.invalid:8080", "https://host.invalid:443", "socks5://host.invalid", "socks5h://host.invalid", "file:///tmp/local", "invalid"]) assert.throws(() => requireSocks5Proxy(invalid));
assert.equal(requireSocks5Proxy("socks5h://user:password@host.invalid:1080"), "socks5h://user:password@host.invalid:1080");
assert.equal(requireSocks5Proxy("socks5://host.invalid:1080"), "socks5://host.invalid:1080");
assert.throws(() => securityActionMode("invalid"));

for (const action of ["rotate-totp", "logout-all", "rotate-totp-logout-all"]) {
  const operation = store.begin(job, action);
  assert.equal(operation.status, "queued");
  assert.equal(operation.stage, "prepared");
  const base = { version: 1, operationId: operation.operationId, email: job.email, action, status: "completed", stage: "verified", startedAt: operation.startedAt, updatedAt: operation.updatedAt, ...(action === "logout-all" ? {} : { secret }), activation_succeeded: true, mfa_verified: true, credentials_saved: true, work_reset_succeeded: true, logout_accepted: true };
  assert.equal(validateSecurityResult({ ...base, email: job.email.toUpperCase() }, operation).email, job.email);
  for (const bad of [{ version: 2 }, { operationId: "another-operation" }, { email: "another@example.invalid" }, { action: "unknown" }, { stage: "unknown" }, { status: "unknown" }, { secret: "invalid-key" }]) assert.throws(() => validateSecurityResult({ ...base, ...bad }, operation));
  if (action === "logout-all") assert.throws(() => validateSecurityResult({ ...base, secret }, operation));
  for (const stage of ["disable_requested", "old_disabled", "enrolled", "activation_requested", "activated", "verified", "work_reset_requested", "work_reset_confirmed", "logout_requested"]) {
    const parsed = validateSecurityResult({ ...base, stage, status: "needs_attention", accessToken: "must-not-persist", cookies: ["must-not-persist"] }, operation);
    assert.equal(parsed.stage, stage);
    assert.equal(Object.hasOwn(parsed, "accessToken"), false);
    assert.equal(Object.hasOwn(parsed, "cookies"), false);
    store.update(operation.operationId, { status: "needs_attention", stage, result: parsed });
    const safe = publicSecurityOperation(store.read(operation.operationId));
    assert.equal(safe.recoveryNeeded, true);
    assert.equal(safe.canRecover, true);
    for (const denied of [secret, "must-not-persist", job.email]) assert.equal(JSON.stringify(safe).includes(denied), false);
    assert.equal(safe.workResetSucceeded, true);
    assert.equal(safe.workResetUnavailable, false);
    assert.equal(safe.logoutAccepted, true);
  }
  if (action !== "logout-all") assert.equal(store.blockingRotation(job).operationId, operation.operationId);
  store.update(operation.operationId, { status: "completed" });
  assert.equal(store.blockingRotation(job), undefined);
  assert.throws(() => store.update(operation.operationId, { status: "invalid" }));
  const skippedReset = validateSecurityResult({ ...base, work_reset_succeeded: false, work_reset_unavailable: true }, operation);
  assert.equal(skippedReset.work_reset_unavailable, true);
  assert.equal(skippedReset.work_reset_succeeded, false);
  store.update(operation.operationId, { result: skippedReset });
  const skippedSummary = publicSecurityOperation(store.read(operation.operationId));
  assert.equal(skippedSummary.workResetUnavailable, true);
  assert.equal(skippedSummary.workResetSucceeded, false);
  assert.equal(validateSecurityResult({ ...base, work_reset_unavailable: "true" }, operation).work_reset_unavailable, false);
  const safeResult = validateSecurityResult({ ...base, error: `secret=${secret} accessToken=private-token https://user:password@host.invalid/path` }, operation);
  assert.doesNotMatch(safeResult.error, /private-token|user:password|NB2W45DFOIZAQWER/);
}
assert.equal(store.detail(job).length, 3);
assert.equal(store.list({ ...job, email: "another@example.invalid" }).length, 0);
const safeError = safeSecurityError(`password=private-password\nAuthorization: Bearer private-bearer\nCookie: private-cookie\n${secret}\nsocks5://user:private-proxy@host.invalid:1080`);
assert.doesNotMatch(safeError, /private-password|private-bearer|private-cookie|private-proxy|NB2W45DFOIZAQWER/);
assert.ok(safeError.length <= 500);
store.delete(job);
assert.equal(store.detail(job).length, 0);
console.log("security operation store: transport validation, result identity binding, recovery stages, safe summaries and credential redaction passed");
