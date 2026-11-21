import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import https from "node:https";
import { EventEmitter } from "node:events";
import { Readable } from "node:stream";
import { createServerDatabase } from "../src/server-database.mjs";
import { createOperationProxies, parseOperationProxy, createWhiteOperationExtractor,
  createOperationExitProbe, WHITE_OPERATION_PROXY_ENDPOINT } from "../src/operation-proxy.mjs";

const email = "test@example.invalid";
const address = "8.9.10.11:1080";
const exitIp = "12.13.14.15";
const successfulProbe = async () => ({ success: true, country: "US", ip: exitIp });

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "operation-proxy-"));
  let database = createServerDatabase({ outputRoot: root });
  const operationId = crypto.randomUUID();
  let extracted = 0;
  const extract = async () => { extracted += 1; return address; };
  return { root, operationId, get database() { return database; }, extract, count: () => extracted,
    reopen() { database.close(); database = createServerDatabase({ outputRoot: root, mustExist: true }); },
    close() { database.close(); fs.rmSync(root, { recursive: true, force: true }); } };
}

test("disabled is the default and does not read extraction environment or consume a lease", async () => {
  const f = fixture();
  try {
    const manager = createOperationProxies({ database: f.database, extract: f.extract, probe: successfulProbe });
    assert.equal(manager.enabled, false);
    await assert.rejects(manager.ensure({ email, operationId: f.operationId }), { code: "OPERATION_PROXY_DISABLED" });
    assert.equal(f.count(), 0); assert.equal(manager.status(email, f.operationId), null);
  } finally { f.close(); }
});

test("one logical operation persists sent before extraction and reuses one verified sticky endpoint", async () => {
  const f = fixture();
  let calls = 0;
  try {
    const manager = createOperationProxies({ database: f.database, enabled: true,
      extract: async (input) => {
        calls += 1;
        assert.deepEqual(input, { email, operationId: f.operationId });
        assert.equal(f.database.get("operation-proxy", f.operationId).status, "sent");
        await new Promise((resolve) => setImmediate(resolve));
        return address;
      }, probe: async (proxy, input) => {
        assert.equal(proxy, "socks5h://" + address);
        assert.equal(input.operationId, f.operationId);
        return successfulProbe();
      } });
    const [first, second] = await Promise.all([manager.ensure({ email, operationId: f.operationId }),
      manager.ensure({ email: email.toUpperCase(), operationId: f.operationId.toUpperCase() })]);
    assert.deepEqual(first, second);
    assert.equal(calls, 1);
    assert.equal(first.proxyUrl, "socks5h://" + address);
    assert.equal(first.exitCountry, "US"); assert.equal(first.exitIp, exitIp);
    assert.deepEqual(await manager.ensure({ email, operationId: f.operationId }), first);
    assert.equal(calls, 1); assert.equal(manager.activeOperations(), 0);
    assert.equal(manager.status(email, f.operationId).usable, true);
    assert.equal(JSON.stringify(manager.status(email, f.operationId)).includes(address), false);
    assert.equal(fs.readFileSync(f.database.databasePath).includes(Buffer.from("socks5h://" + address)), false);
  } finally { f.close(); }
});

test("ready survives restart, and an expired operation never obtains another IP", async () => {
  const f = fixture(); let clock = Date.parse("2026-11-13T00:00:00Z");
  try {
    let manager = createOperationProxies({ database: f.database, enabled: true, extract: f.extract, probe: successfulProbe, now: () => clock });
    const first = await manager.ensure({ email, operationId: f.operationId });
    f.reopen();
    manager = createOperationProxies({ database: f.database, enabled: true, extract: f.extract, probe: successfulProbe, now: () => clock });
    assert.deepEqual(await manager.ensure({ email, operationId: f.operationId }), first);
    clock += 10 * 60_000;
    await assert.rejects(manager.ensure({ email, operationId: f.operationId }), { code: "OPERATION_PROXY_EXPIRED" });
    assert.equal(manager.status(email, f.operationId).usable, false);
    assert.equal(f.count(), 1);
  } finally { f.close(); }
});

for (const status of ["sent", "unknown"]) {
  test(`restart with ${status} cannot extract or probe again`, async () => {
    const f = fixture();
    try {
      f.database.put("operation-proxy", f.operationId, { email, operationId: f.operationId, status });
      f.reopen(); let probes = 0;
      const manager = createOperationProxies({ database: f.database, enabled: true, extract: f.extract,
        probe: async () => { probes += 1; return successfulProbe(); } });
      await assert.rejects(manager.ensure({ email, operationId: f.operationId }), { code: "OPERATION_PROXY_UNKNOWN" });
      assert.equal(f.count(), 0); assert.equal(probes, 0);
    } finally { f.close(); }
  });
}

test("separate managers cannot both consume the same operation", async () => {
  const f = fixture(); let finish;
  try {
    const first = createOperationProxies({ database: f.database, enabled: true,
      extract: () => new Promise((resolve) => { finish = resolve; }), probe: successfulProbe });
    const waiting = first.ensure({ email, operationId: f.operationId });
    await new Promise((resolve) => setImmediate(resolve));
    const second = createOperationProxies({ database: f.database, enabled: true, extract: f.extract, probe: successfulProbe });
    await assert.rejects(second.ensure({ email, operationId: f.operationId }), { code: "OPERATION_PROXY_UNKNOWN" });
    assert.equal(f.count(), 0); finish(address); await waiting;
  } finally { f.close(); }
});

test("operation IDs cannot be shared by different accounts, including an in-flight extraction", async () => {
  const f = fixture(); let finish;
  try {
    const manager = createOperationProxies({ database: f.database, enabled: true,
      extract: () => new Promise((resolve) => { finish = resolve; }), probe: successfulProbe });
    const waiting = manager.ensure({ email, operationId: f.operationId });
    await assert.rejects(manager.ensure({ email: "other@example.invalid", operationId: f.operationId }), { code: "OPERATION_PROXY_BOUND" });
    await new Promise((resolve) => setImmediate(resolve)); finish(address); await waiting;
    await assert.rejects(manager.ensure({ email: "other@example.invalid", operationId: f.operationId }), { code: "OPERATION_PROXY_BOUND" });
    assert.throws(() => manager.status("other@example.invalid", f.operationId), { code: "OPERATION_PROXY_BOUND" });
  } finally { f.close(); }
});

test("strict single IPv4 endpoint permits only socks5h and rejects supplier errors without echoing them", () => {
  assert.equal(parseOperationProxy(address + "\r\n"), "socks5h://" + address);
  for (const body of ["http://8.9.10.11:80", "socks5h://8.9.10.11:1080", "8.9.10.11:1080:user:SECRET", "{\"error\":\"RAW-SECRET\"}",
    "未授权 RAW-SECRET", "8.9.10.11:1\n8.9.10.12:2", "8.9.10.11:0", "8.9.10.11:65536", "999.1.1.1:80", "127.0.0.1:80", "10.1.1.1:80", "169.254.1.1:80", "x".repeat(4097)]) {
    assert.throws(() => parseOperationProxy(body), (error) => error.code === "OPERATION_PROXY_EXTRACT_FAILED" && !/RAW-SECRET|SECRET/.test(error.message));
  }
});

for (const [label, extract, probe, code] of [
  ["provider rejection", async () => { throw Error("RAW-SECRET provider-key"); }, successfulProbe, "OPERATION_PROXY_EXTRACT_FAILED"],
  ["provider malformed", async () => "RAW-SECRET", successfulProbe, "OPERATION_PROXY_EXTRACT_FAILED"],
  ["non-US exit", async () => address, async () => ({ success: true, country: "CA", ip: exitIp }), "OPERATION_PROXY_PROBE_FAILED"],
  ["unknown exit", async () => address, async () => ({ success: true, country: "US" }), "OPERATION_PROXY_PROBE_FAILED"],
  ["SOCKS probe rejection", async () => address, async () => { throw Error("RAW-SECRET proxy-auth"); }, "OPERATION_PROXY_PROBE_FAILED"],
]) {
  test(`${label} becomes unknown and is never automatically retried`, async () => {
    const f = fixture(); let calls = 0;
    try {
      const manager = createOperationProxies({ database: f.database, enabled: true,
        extract: async (...args) => { calls += 1; return extract(...args); }, probe });
      await assert.rejects(manager.ensure({ email, operationId: f.operationId }), (error) => error.code === code && !error.message.includes("RAW-SECRET"));
      assert.equal(manager.status(email, f.operationId).status, "unknown");
      await assert.rejects(manager.ensure({ email, operationId: f.operationId }), { code: "OPERATION_PROXY_UNKNOWN" });
      assert.equal(calls, 1);
    } finally { f.close(); }
  });
}

test("a lease that expires during verification is retained and rejected without replacement", async () => {
  const f = fixture(); let clock = 1000;
  try {
    const manager = createOperationProxies({ database: f.database, enabled: true, extract: f.extract,
      now: () => clock, probe: async () => { clock += 10 * 60_000; return successfulProbe(); } });
    await assert.rejects(manager.ensure({ email, operationId: f.operationId }), { code: "OPERATION_PROXY_EXPIRED" });
    await assert.rejects(manager.ensure({ email, operationId: f.operationId }), { code: "OPERATION_PROXY_UNKNOWN" });
    assert.equal(f.count(), 1);
  } finally { f.close(); }
});

test("close prevents new operations and retains a sent lease without publishing it", async () => {
  const f = fixture(); let finish;
  try {
    const manager = createOperationProxies({ database: f.database, enabled: true,
      extract: () => new Promise((resolve) => { finish = resolve; }), probe: successfulProbe });
    const waiting = manager.ensure({ email, operationId: f.operationId });
    await new Promise((resolve) => setImmediate(resolve));
    let closed = false;
    const stopping = manager.close().then(() => { closed = true; });
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(closed, false, "shutdown must keep the database open until the sent request settles");
    finish(address);
    await assert.rejects(waiting, { code: "OPERATION_PROXY_CLOSED" });
    assert.equal(manager.status(email, f.operationId).status, "unknown");
    await assert.rejects(manager.ensure({ email, operationId: crypto.randomUUID() }), { code: "OPERATION_PROXY_CLOSED" });
    await stopping;
    assert.equal(closed, true);
    assert.equal(manager.activeOperations(), 0);
  } finally { f.close(); }
});

test("close before a queued ensure starts does not consume an extraction", async () => {
  const f = fixture();
  try {
    const manager = createOperationProxies({ database: f.database, enabled: true, extract: f.extract, probe: successfulProbe });
    const waiting = manager.ensure({ email, operationId: f.operationId });
    const stopping = manager.close();
    await assert.rejects(waiting, { code: "OPERATION_PROXY_CLOSED" });
    await stopping;
    assert.equal(f.count(), 0);
    assert.equal(manager.status(email, f.operationId), null);
    assert.equal(manager.activeOperations(), 0);
  } finally { f.close(); }
});

function requestStub({ status = 200, body = address, headers = {}, chunks, network = false } = {}) {
  const calls = [];
  return { calls, requestImpl(url, options, callback) {
    calls.push({ url: url.toString(), options });
    const request = new EventEmitter();
    request.setTimeout = (milliseconds) => { assert.equal(milliseconds, 20_000); };
    request.destroy = () => {};
    request.end = () => queueMicrotask(() => {
      if (network) { request.emit("error", Error("RAW-SECRET")); return; }
      const response = Readable.from(chunks || [Buffer.from(body)]);
      response.statusCode = status; response.headers = headers;
      callback(response);
    });
    return request;
  } };
}

test("default extractor uses one fixed US HTTPS request and an independent direct agent", async () => {
  const stub = requestStub();
  assert.equal(await createWhiteOperationExtractor(stub)(), address);
  assert.equal(stub.calls.length, 1);
  assert.equal(stub.calls[0].url, WHITE_OPERATION_PROXY_ENDPOINT);
  assert.equal(new URL(stub.calls[0].url).searchParams.get("region"), "US");
  assert.equal(stub.calls[0].options.agent instanceof https.Agent, true);
  assert.notEqual(stub.calls[0].options.agent, https.globalAgent);
  assert.equal(stub.calls[0].options.agent.keepAlive, false);
});

test("absolute extraction deadline stops a continuously streaming response and clears its timer", async () => {
  let expire, cleared, requestDestroyed = false;
  const request = new EventEmitter();
  const response = new Readable({ read() {} });
  response.statusCode = 200; response.headers = {};
  request.setTimeout = (milliseconds) => assert.equal(milliseconds, 20_000);
  request.destroy = () => { requestDestroyed = true; response.destroy(); };
  request.end = () => queueMicrotask(() => {
    callback(response);
    response.push(Buffer.from("8.9."));
    response.push(Buffer.from("10.11:"));
  });
  let callback;
  const token = {};
  const extract = createWhiteOperationExtractor({ requestImpl: (_url, _options, onResponse) => { callback = onResponse; return request; },
    setTimeoutImpl: (fn, milliseconds) => { assert.equal(milliseconds, 20_000); expire = fn; return token; },
    clearTimeoutImpl: (value) => { cleared = value; } });
  const waiting = extract();
  const rejection = assert.rejects(waiting, (error) => error.code === "OPERATION_PROXY_EXTRACT_FAILED"
    && error.message === "默认代理提取失败，已停止本次操作");
  await new Promise((resolve) => setImmediate(resolve));
  expire();
  await rejection;
  assert.equal(requestDestroyed, true);
  assert.equal(cleared, token);
});

for (const options of [{ status: 302 }, { status: 403, body: "RAW-SECRET" }, { headers: { "content-length": "4097" } },
  { chunks: [Buffer.alloc(3000), Buffer.alloc(3000)] }, { network: true }]) {
  test(`default extractor rejects redirect/error/oversize without a second request: ${JSON.stringify(options).slice(0, 90)}`, async () => {
    const stub = requestStub(options);
    await assert.rejects(createWhiteOperationExtractor(stub)(), (error) => error.code === "OPERATION_PROXY_EXTRACT_FAILED" && !error.message.includes("RAW-SECRET"));
    assert.equal(stub.calls.length, 1);
  });
}

test("default exit validation configures strict pinned SOCKS5 and never retries HTTP or changes sessions", async () => {
  const calls = []; let options, closed = false;
  const probe = createOperationExitProbe({ transportFactory(value) {
    options = value;
    return { configure: async (proxy) => calls.push(proxy), request: async (method, url, opts) => {
      assert.equal(method, "GET"); assert.equal(url, "https://www.cloudflare.com/cdn-cgi/trace");
      assert.equal(opts.retryRiskControl, false);
      return { status: 200, headers: new Headers(), text: async () => `ip=${exitIp}\nloc=US\n` };
    }, close: async () => { closed = true; } };
  } });
  assert.deepEqual(await probe("socks5h://" + address), { success: true, country: "US", ip: exitIp });
  assert.deepEqual(calls, ["socks5h://" + address]);
  assert.equal(options.requireSocks5, true); assert.equal(options.pinProxySession, true);
  assert.equal(options.maxProxySessionAttempts, 0); assert.equal(options.sameProxyRiskRetries, 0);
  assert.equal(options.cloudflareSolver, false); assert.equal(closed, true);
});

for (const body of [`ip=${exitIp}\nloc=CA\n`, `ip=${exitIp}\n`, `ip=${exitIp}\nloc=US\nloc=CA\n`, "ip=unknown\nloc=US\n"]) {
  test("default exit validation rejects non-US, missing and ambiguous trace data", async () => {
    const probe = createOperationExitProbe({ transportFactory: () => ({ configure: async () => {},
      request: async () => ({ status: 200, headers: new Headers(), text: async () => body }), close: async () => {} }) });
    await assert.rejects(probe("socks5h://" + address), { code: "OPERATION_PROXY_PROBE_FAILED" });
  });
}
