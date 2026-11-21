import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createServerDatabase } from "../src/server-database.mjs";
import { createDynamicProxies, create1024Extractor, parseExtractedProxy } from "../src/dynamic-proxy.mjs";
import { createDynamicCrsAdapter } from "../src/dynamic-proxy-crs.mjs";

const profile = { id: "residential", name: "Test", key: "fixture-secret", country: "US", protocol: "socks5h", enabled: true };
const url = (number) => `socks5h://fixture:secret@proxy${number}.example:1080`;
const email = "test@example.com";
function fixture(t, overrides = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dynamic-proxy-test-"));
  const db = createServerDatabase({ outputRoot: dir });
  t.after(() => { db.close(); fs.rmSync(dir, { recursive: true, force: true }); });
  const state = { calls: 0, allowed: true, valid: true, published: 0, verify: false, quality: "pending", time: 100000 };
  const config = {
    database: db, allowExtraction: true, now: () => state.time,
    extract: async () => url(++state.calls), probe: async () => state.valid,
    synchronize: async () => {},
    crs: {
      eligibility: async () => ({ allowed: state.allowed }),
      isolate: async (record) => ({ operationId: record.operationId }),
      publish: async () => { state.published++; return { proxyId: "proxy_1", requiresVerification: state.verify }; },
      recoveryStatus: async () => state.quality,
    }, ...overrides,
  };
  const service = createDynamicProxies(config);
  service.saveProfile(profile, 0); service.bind(email, profile.id, { target: "https://crs.example" });
  return { db, service, state, config };
}
test("saving profiles and 100 bindings never extracts or exposes secrets", (t) => {
  const { service, state } = fixture(t);
  for (let i = 0; i < 100; i++) service.bind(`account${i}@example.com`, profile.id);
  assert.equal(state.calls, 0);
  assert.equal(service.bindings().length, 101);
  assert(!JSON.stringify(service.profiles()).includes(profile.key));
});
test("concurrent use extracts once and healthy later requests reuse it", async (t) => {
  const { service, state } = fixture(t);
  const replies = await Promise.all(Array.from({ length: 20 }, () => service.ensure(email)));
  assert.equal(state.calls, 1); assert.equal(state.published, 1);
  assert(replies.every((reply) => reply.generation === 1 && reply.proxyUrl === url(1)));
  await service.ensure(email); assert.equal(state.calls, 1);
  assert(!JSON.stringify(service.bindings()).includes("secret@"));
});
test("timeout and process restart never repeat an uncertain extraction", async (t) => {
  let calls = 0;
  const f = fixture(t, { extract: async () => { calls++; throw new Error("lost response"); } });
  await assert.rejects(f.service.ensure(email), /结果未知/);
  const restarted = createDynamicProxies(f.config);
  await assert.rejects(restarted.ensure(email), /结果未知/);
  assert.equal(calls, 1); assert.equal(restarted.binding(email).extractionCount, 1);
});
test("disabled, exhausted or degraded eligibility blocks extraction", async (t) => {
  const { service, state } = fixture(t); state.allowed = false;
  await assert.rejects(service.ensure(email)); assert.equal(state.calls, 0);
});
test("disabling during extraction retains the paid result without publishing", async (t) => {
  let finish; let sent;
  const sending = new Promise((r) => { sent = r; });
  const f = fixture(t, { extract: async () => { sent(); return new Promise((r) => { finish = r; }); } });
  const running = f.service.ensure(email); await sending;
  f.state.allowed = false; finish(url(1));
  await assert.rejects(running); assert.equal(f.state.published, 0);
  assert.equal(f.service.binding(email).status, "candidate");
  assert.equal(f.service.binding(email).extractionCount, 1);
});
test("quality pending and explicit degradation never cause another extraction", async (t) => {
  const { service, state } = fixture(t); state.verify = true;
  await assert.rejects(service.ensure(email), /质量检查/);
  for (let i = 0; i < 5; i++) await assert.rejects(service.ensure(email), /质量检查/);
  state.quality = "degraded";
  await assert.rejects(service.ensure(email), /降智/);
  assert.equal(state.calls, 1);
});
test("synchronization failure retries the saved candidate without extracting", async (t) => {
  let rejectPublish = true;
  const f = fixture(t, { synchronize: async (_, { phase }) => { if (phase === "publish" && rejectPublish) throw new Error("offline"); } });
  await assert.rejects(f.service.ensure(email), /offline/);
  rejectPublish = false; await f.service.ensure(email);
  assert.equal(f.state.calls, 1); assert.equal(f.state.published, 1);
});
test("valid accounts have no lifetime IP limit", async (t) => {
  let generation = 0;
  const f = fixture(t, { extract: async () => url(++generation), probe: async (value) => value === url(generation) });
  await f.service.ensure(email);
  for (let i = 0; i < 7; i++) {
    generation++;
    await f.service.ensure(email);
  }
  assert.equal(f.service.binding(email).extractionCount, 8);
});
test("real extraction is off by default and parser rejects errors and multiple IPs", async () => {
  let calls = 0;
  const extract = create1024Extractor({ fetchImpl: () => { calls++; } });
  await assert.rejects(extract(profile), /未启用/); assert.equal(calls, 0);
  assert.equal(parseExtractedProxy("proxy.example:443:user:p@ss:word\n", "http"), "http://user:p%40ss%3Aword@proxy.example:443/");
  for (const body of ['{"error":"no balance"}', "a:443:u:p\nb:443:u:p", "a:0:u:p", "<html>error</html>"]) assert.throws(() => parseExtractedProxy(body, "socks5h"));
});

test("the supplier request preserves the selected New York region without fallback", async () => {
  const requests = [];
  const extract = create1024Extractor({ allowExtraction: true, fetchImpl: async (value) => {
    requests.push(new URL(value));
    return new Response(requests.length === 1 ? "proxy.example:443:fixture:secret" : "No IP available");
  } });
  const selected = { ...profile, state: "New York", city: "Buffalo" };
  await extract(selected);
  await assert.rejects(extract(selected), /响应格式无法确认/);
  assert.equal(requests.length, 2);
  for (const request of requests) {
    assert.equal(request.origin, "https://apisocks.1024proxy.com");
    assert.equal(request.searchParams.get("country"), "US");
    assert.equal(request.searchParams.get("state"), "New York");
    assert.equal(request.searchParams.get("city"), "Buffalo");
    assert.equal(request.searchParams.get("num"), "1");
    assert.equal(request.searchParams.get("format"), "n");
  }
});

test("two service instances sharing the durable ledger cannot both extract", async (t) => {
  const f = fixture(t);
  const second = createDynamicProxies(f.config);
  const results = await Promise.allSettled([f.service.ensure(email), second.ensure(email)]);
  assert(results.some((value) => value.status === "fulfilled"));
  assert.equal(f.state.calls, 1);
});
test("a dead replacement can renew after cooldown without a lifetime cap", async (t) => {
  let count = 0;
  const f = fixture(t, { extract: async () => url(++count), probe: async (value) => value === url(2) });
  await assert.rejects(f.service.ensure(email), /未通过/);
  await assert.rejects(f.service.ensure(email), /退避/);
  assert.equal(count, 1);
  f.state.time += 60001;
  await f.service.ensure(email);
  assert.equal(count, 2);
});

test("shutdown waits for a dispatched result, saves it, and stops publication", async (t) => {
  let finish; let sent;
  const sending = new Promise((r) => { sent = r; });
  const f = fixture(t, { extract: async () => { sent(); return new Promise((r) => { finish = r; }); } });
  const running = f.service.ensure(email); const rejection = assert.rejects(running, /关闭/);
  await sending;
  let stopped = false; const closing = f.service.close().then(() => { stopped = true; });
  await Promise.resolve(); assert.equal(stopped, false);
  finish(url(1)); await rejection; await closing;
  assert.equal(f.service.binding(email).status, "candidate"); assert.equal(f.state.published, 0);
  const restarted = createDynamicProxies({ ...f.config, allowExtraction: false }); await restarted.ensure(email);
  assert.equal(restarted.binding(email).extractionCount, 1); assert.equal(f.state.published, 1);
});
test("manual reconciliation uses the recorded result and rejects a stale revision", async (t) => {
  const f = fixture(t, { extract: async () => { throw Error("lost response"); } });
  await assert.rejects(f.service.ensure(email));
  const binding = f.service.binding(email);
  assert.throws(() => f.service.reconcile(email, url(1), binding.revision - 1), /状态已变化/);
  f.service.reconcile(email, url(1), binding.revision);
  await f.service.ensure(email);
  assert.equal(f.service.binding(email).extractionCount, 1); assert.equal(f.state.published, 1);
});

test("managed login never randomizes supplier session credentials", async () => {
  const { TlsFingerprintTransport } = await import("../src/tls-transport.mjs");
  const proxyUrl = "http://customer-sid-original-t-20:secret@gateway.example:8080/";
  const transport = new TlsFingerprintTransport({ pinProxySession: true });
  let configured;
  transport.configure = async (value) => { configured = value; };
  transport.request = async () => new Response("ok");
  assert.equal(await transport.prepareProxy(proxyUrl, "https://chatgpt.com/"), proxyUrl);
  assert.equal(configured, proxyUrl);
});

test("adopting an existing login proxy synchronizes exact credentials without extraction", async (t) => {
  const f = fixture(t, { allowExtraction: false });
  f.service.bind("existing@example.com", profile.id, { target: "https://crs.example", proxyUrl: url(7) });
  const result = await f.service.ensure("existing@example.com");
  assert.equal(result.proxyUrl, url(7)); assert.equal(f.state.calls, 0); assert.equal(f.state.published, 1);
  await f.service.ensure("existing@example.com");
  assert.equal(f.state.calls, 0); assert.equal(f.state.published, 1);
});

test("adoption survives lost begin and complete responses with extraction disabled", async (t) => {
  const account = { accountId: "acct_fixture", email, enabled: true, quotaAllowed: true, proxyId: "proxy_fixture", guardian: { config: { enabled: true }, revision: 1, state: { status: "watching" } } };
  let loseBegin = true; let loseComplete = true; let beginCount = 0; let completeCount = 0; let synced;
  const adapter = createDynamicCrsAdapter({
    dynamicTarget: () => "https://crs.example",
    dynamicRequest: async (path, body) => {
      if (!body) return structuredClone(account);
      if (path.endsWith("proxy-demand")) return null;
      if (body.action === "begin") {
        assert.equal(account.enabled, true); beginCount++;
        account.enabled = false; account.guardian.state = { status: "proxy_recovery", proxyRecovery: { operationId: body.operationId } };
        if (loseBegin) { loseBegin = false; throw Error("lost begin response"); }
      }
      if (body.action === "complete") {
        assert.equal(body.operationId, account.guardian.state.proxyRecovery.operationId); completeCount++;
        account.quotaAllowed = false; account.guardian.state.status = "verifying";
        if (loseComplete) { loseComplete = false; throw Error("lost complete response"); }
      }
      return {};
    },
  });
  const f = fixture(t, { allowExtraction: false, crs: adapter, synchronize: async (record, { phase }) => { if (phase === "publish") synced = record.proxyUrl; } });
  f.db.put("dynamic-proxy", email, { ...f.db.get("dynamic-proxy", email), accountId: account.accountId, proxyId: account.proxyId, proxyUrl: url(7), generation: 1, status: "ready" });
  await assert.rejects(f.service.ensure(email), /lost begin/);
  const operationId = f.service.binding(email).operationId;
  assert.equal(account.guardian.state.proxyRecovery.operationId, operationId);
  const restarted = createDynamicProxies(f.config);
  await assert.rejects(restarted.ensure(email), /lost complete/);
  assert.equal(synced, url(7));
  await assert.rejects(restarted.ensure(email), /质量检查/);
  account.enabled = true; account.quotaAllowed = true; account.guardian.state.status = "watching";
  const result = await restarted.ensure(email);
  assert.equal(result.proxyUrl, url(7)); assert.equal(result.generation, 2);
  assert.equal(beginCount, 1); assert.equal(completeCount, 2); assert.equal(f.state.calls, 0);
});

test("late supplier response cannot overwrite a manually reconciled ledger", async (t) => {
  let finish; let sent;
  const sending = new Promise((resolve) => { sent = resolve; });
  const f = fixture(t, { extract: async () => { sent(); return new Promise((resolve) => { finish = resolve; }); } });
  const running = f.service.ensure(email); const rejection = assert.rejects(running, /状态已变化/);
  await sending; f.state.time += 60001;
  const second = createDynamicProxies({ ...f.config, allowExtraction: false });
  second.reconcile(email, url(2), second.binding(email).revision);
  finish(url(1)); await rejection;
  assert.equal(f.state.published, 0);
  assert.equal((await second.ensure(email)).proxyUrl, url(2));
  assert.equal(second.binding(email).extractionCount, 1);
});

test("pausing a supplier profile retains an in-flight result until resumed", async (t) => {
  let finish; let sent;
  const sending = new Promise((resolve) => { sent = resolve; });
  const f = fixture(t, { extract: async () => { sent(); return new Promise((resolve) => { finish = resolve; }); } });
  const running = f.service.ensure(email); const rejection = assert.rejects(running, /已暂停/);
  await sending; f.service.saveProfile({ ...profile, enabled: false }, 1);
  finish(url(1)); await rejection;
  assert.equal(f.service.binding(email).status, "candidate"); assert.equal(f.state.published, 0);
  f.service.saveProfile(profile, 2);
  const restarted = createDynamicProxies({ ...f.config, allowExtraction: false });
  assert.equal((await restarted.ensure(email)).proxyUrl, url(1));
  assert.equal(restarted.binding(email).extractionCount, 1);
});

test("manual CRS selection waits for a late result, archives it, and survives restart", async (t) => {
  let sent; let finish; let switched = false; let synchronized;
  const sending = new Promise((r) => { sent = r; });
  const f = fixture(t, { extract: async () => { sent(); return new Promise((r) => { finish = r; }); }, synchronize: async (record, { phase }) => { if (phase === "manual") synchronized = record.proxyUrl; } });
  f.config.crs.manualSelection = async () => switched ? { proxyUrl: url(9), proxyId: "proxy_fixed", accountId: "acct_fixture" } : null;
  f.config.crs.eligibility = async () => ({ allowed: !switched });
  const running = f.service.ensure(email); const rejected = assert.rejects(running);
  await sending;
  switched = true;
  const refreshing = f.service.refreshManualSelection(email);
  assert.equal(synchronized, undefined);
  finish(url(1)); await rejected; await refreshing;
  assert.equal(synchronized, url(9)); assert.equal(f.state.published, 0);
  assert.equal(f.service.binding(email), null);
  const archive = f.db.get("dynamic-proxy-archive", f.db.recordIds("dynamic-proxy-archive")[0]);
  assert.equal(archive.candidateUrl, url(1)); assert.equal(archive.extractionCount, 1);
  assert.equal(archive.replacementProxyId, "proxy_fixed");
  const restarted = createDynamicProxies({ ...f.config, allowExtraction: false });
  assert.equal(await restarted.refreshManualSelection(email), false);
  await assert.rejects(restarted.ensure(email), /未绑定/);
});

test("manual synchronization failure retains the ledger for retry without extraction", async (t) => {
  let unavailable = true;
  const f = fixture(t, { allowExtraction: false, synchronize: async () => { if (unavailable) throw Error("busy"); } });
  f.config.crs.manualSelection = async () => ({ proxyId: "proxy_fixed", proxyUrl: url(9) });
  await assert.rejects(f.service.refreshManualSelection(email), /busy/);
  assert(f.service.binding(email)); assert.equal(f.db.recordIds("dynamic-proxy-archive").length, 0);
  unavailable = false;
  assert.equal(await f.service.refreshManualSelection(email), true);
  assert.equal(f.state.calls, 0);
});

test("CRS manual selection exports exact proxy credentials and rejects a changing account", async () => {
  const record = { email, accountId: "acct_fixture", proxyId: "proxy_old", target: "https://crs.example" };
  const account = { email, accountId: record.accountId, proxyId: "proxy_old", guardian: { revision: 1 } };
  let exports = 0; let changeDuringExport = false;
  const adapter = createDynamicCrsAdapter({ dynamicTarget: () => record.target, dynamicRequest: async (path) => {
    if (path.startsWith("/api/admin/accounts/export?")) {
      exports++;
      if (changeDuringExport) account.proxyId = "proxy_raced";
      return { documents: [{ provider: "openai", document: { accounts: [{ id: record.accountId, email, outbound_proxy_url: url(9) }] } }] };
    }
    return structuredClone(account);
  } });
  assert.equal(await adapter.manualSelection(record), null); assert.equal(exports, 0);
  account.proxyId = "proxy_fixed";
  assert.equal((await adapter.manualSelection(record)).proxyUrl, url(9));
  await assert.rejects(adapter.status(record), /已更换代理/);
  changeDuringExport = true;
  await assert.rejects(adapter.manualSelection(record), /正在变化/);
});
