import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { createServerDatabase } from "../src/server-database.mjs";
import {
  ACCOUNT_TLS_EXTENSIONS,
  DEFAULT_ACCOUNT_TLS_PROFILE,
  getAccountTls,
  upgradeAccountTlsIdentity,
  validateAccountTls,
} from "../src/account-tls.mjs";

function legacyIdentity(account, profile) {
  const extensionOrder = ACCOUNT_TLS_EXTENSIONS
    .filter((value) => profile !== "chrome146" || value !== 51764).join("-");
  const id = crypto.createHash("sha256").update(`${profile}:${extensionOrder}`).digest("hex");
  return { version: 1, account, profile, extensionOrder, id };
}

function rawLegacyRecords(databasePath) {
  const readonly = new DatabaseSync(databasePath, { readOnly: true });
  try {
    return readonly.prepare("SELECT kind,id,hex(payload) payload,updated_at FROM records WHERE kind IN ('account-tls-v1','account-tls-order-v1') ORDER BY kind,id").all();
  } finally { readonly.close(); }
}

const outputRoot = await fs.mkdtemp(path.join(os.tmpdir(), "account-tls-native-"));
let database = createServerDatabase({ outputRoot });
try {
  const first = getAccountTls(database, "  Alice@Example.test ");
  assert.equal(DEFAULT_ACCOUNT_TLS_PROFILE, "chrome152_macos");
  assert.equal(first.version, 2);
  assert.equal(first.profile, DEFAULT_ACCOUNT_TLS_PROFILE);
  assert.equal(first.mode, "native");
  assert.equal(Object.hasOwn(first, "extensionOrder"), false);
  assert.deepEqual(getAccountTls(database, "alice@example.test"), first);
  assert.equal(database.get("account-tls-v1", first.account), null, "new accounts do not allocate legacy orders");
  const second = getAccountTls(database, "bob@example.test");
  assert.notEqual(second.id, first.id, "configuration IDs are bound to accounts");
  assert.deepEqual(upgradeAccountTlsIdentity(first, first.account), first);
  assert.throws(() => validateAccountTls(first, second.account), /ACCOUNT_TLS_INVALID/);

  for (const profile of ["chrome146", "chrome152"]) {
    const account = `legacy-${profile}@example.test`;
    const old = legacyIdentity(account, profile);
    database.put("account-tls-v1", account, old);
    database.put("account-tls-order-v1", old.id, { account });
    const before = rawLegacyRecords(database.databasePath);
    const migrated = getAccountTls(database, account);
    assert.equal(migrated.version, 2);
    assert.equal(migrated.profile, "chrome152_macos");
    assert.equal(migrated.mode, "native");
    assert.equal(Object.hasOwn(migrated, "extensionOrder"), false);
    assert.deepEqual(getAccountTls(database, account), migrated);
    assert.deepEqual(upgradeAccountTlsIdentity(old, account), migrated, "explicit CLI legacy identity upgrades identically");
    assert.deepEqual(rawLegacyRecords(database.databasePath), before, "legacy payloads and timestamps remain byte-for-byte unchanged");
    assert.deepEqual(validateAccountTls(database.get("account-tls-v1", account), account), old);
    assert.throws(() => upgradeAccountTlsIdentity(old, first.account), /ACCOUNT_TLS_INVALID/);
  }

  for (const patch of [
    { account: second.account }, { profile: "chrome152" }, { mode: "fixed" },
    { id: "tampered" }, { version: 3 }, { extensionOrder: undefined },
    { extensionOrder: null }, { extensionOrder: "0-5" },
  ]) {
    const invalid = { ...first, ...patch };
    assert.throws(() => validateAccountTls(invalid, first.account), /ACCOUNT_TLS_INVALID/);
    assert.throws(() => upgradeAccountTlsIdentity(invalid, first.account), /ACCOUNT_TLS_INVALID/);
  }

  for (const [label, mutation] of [
    ["invalid-order", (old) => ({ ...old, extensionOrder: "0-5" })],
    ["invalid-id", (old) => ({ ...old, id: "invalid" })],
    ["missing-reservation", (old) => old],
    ["wrong-reservation", (old) => old],
  ]) {
    const account = `${label}@example.test`;
    const old = mutation(legacyIdentity(account, "chrome152"));
    database.put("account-tls-v1", account, old);
    // These synthetic identities intentionally share the same old order ID.
    if (label === "missing-reservation") database.remove("account-tls-order-v1", old.id);
    else database.put("account-tls-order-v1", old.id, { account: label === "wrong-reservation" ? first.account : account });
    const before = rawLegacyRecords(database.databasePath);
    assert.throws(() => getAccountTls(database, account), /ACCOUNT_TLS_INVALID/);
    assert.equal(database.get("account-tls-v2", account), null, "invalid migration leaves no v2 identity");
    assert.deepEqual(rawLegacyRecords(database.databasePath), before, "failed migration leaves legacy records unchanged");
  }

  const interruptedAccount = "write-interrupted@example.test";
  assert.throws(() => getAccountTls({
    ...database,
    put(...args) { database.put(...args); throw new Error("simulated write interruption"); },
  }, interruptedAccount), /simulated write interruption/);
  assert.equal(database.get("account-tls-v2", interruptedAccount), null, "a write failure rolls back the transaction");

  database.saveJob("job-one", { email: first.account });
  database.deleteJob("job-one");
  assert.deepEqual(getAccountTls(database, first.account), first, "job deletion/recreation preserves account configuration");
  database.close();
  database = createServerDatabase({ outputRoot, mustExist: true });
  assert.deepEqual(getAccountTls(database, first.account), first, "identity survives process restart");
  const secondConnection = createServerDatabase({ outputRoot, mustExist: true });
  try { assert.deepEqual(getAccountTls(secondConnection, first.account), first); }
  finally { secondConnection.close(); }

  database.put("account-tls-v2", first.account, { ...first, id: "corrupt" });
  assert.throws(() => getAccountTls(database, first.account), /ACCOUNT_TLS_INVALID/, "v2 corruption is not silently regenerated");
  assert.equal(database.get("account-tls-v2", first.account).id, "corrupt");
  database.put("account-tls-v2", second.account, false);
  assert.throws(() => getAccountTls(database, second.account), /ACCOUNT_TLS_INVALID/);
  assert.equal(database.get("account-tls-v2", second.account), false, "malformed records are not silently overwritten");
  console.log("Account TLS: native macOS persistence, both legacy migrations, immutable rollback records and corruption checks passed");
} finally {
  database.close();
  await fs.rm(outputRoot, { recursive: true, force: true });
}
