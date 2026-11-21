import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createCrsIntegration, resolveCrsProxy, seedCrsConfiguration } from "../src/crs-integration.mjs";
import { createServerDatabase } from "../src/server-database.mjs";

const root = await fs.mkdtemp(path.join(os.tmpdir(), "crs-proxy-binding-"));
const database = createServerDatabase({ outputRoot: root });
const proxyUrl = "http://login-user:login-secret@PROXY.example:8080/";
const firstProxy = { id: "proxy-one", endpoint: "http://proxy.example:8080/", hasAuthentication: true, enabled: true };
const secondProxy = { id: "proxy-two", endpoint: "socks5h://[2001:db8::1]:1080", hasAuthentication: true, enabled: true };
let catalog = [firstProxy, secondProxy];
let pageSize = 100;
let malformedPage = false;
let behavior = "success";
let createBehavior = "success";
const creates = [];
let afterCreate;
let hook;
let service;
const jobs = new Map();
const posts = [];
const requests = [];
const tasks = new Map();
const config = { baseUrl: "http://crs.example", authType: "apiKey", apiKey: "private-crs-key", autoUpload: false };
seedCrsConfiguration(database, config);

async function fetchImpl(input, options) {
  const url = new URL(input);
  const body = options.body ? JSON.parse(options.body) : null;
  requests.push({ path: url.pathname, query: url.search, body });
  assert.equal(options.headers["X-API-Key"], config.apiKey);
  assert.equal(options.redirect, "error");
  const respond = (data, status = 200) => new Response(JSON.stringify({ code: 200, data }), { status, headers: { "content-type": "application/json" } });
  if (url.pathname === "/api/admin/account-groups/options") return respond({ items: [{ id: "openai", name: "openai", enabled: true }], page: { totalPages: 1 } });
  if (url.pathname === "/api/admin/proxies") {
    const page = Number(url.searchParams.get("page"));
    const result = { items: catalog.slice((page - 1) * pageSize, page * pageSize), page: { page, totalPages: malformedPage ? 101 : Math.ceil(catalog.length / pageSize) } };
    if (hook) { const operation = hook; hook = null; await operation(); }
    return respond(result);
  }
  if (url.pathname === "/api/admin/proxies/create") {
    assert.equal(options.method, "POST");
    assert.equal(body.length, 1);
    options.signal.throwIfAborted();
    creates.push(structuredClone(body[0]));
    if (createBehavior === "reject") return respond([{ status: "failed", httpStatus: 403, message: "untrusted login-secret" }]);
    if (createBehavior === "unknown") throw new Error("connection reset socks5://login-user:login-secret@hidden.example:1080");
    const url = new URL(body[0].proxyUrl);
    const hasAuthentication = Boolean(url.username || url.password); url.username = ""; url.password = "";
    const record = { id: `created-${creates.length}`, endpoint: url.href, hasAuthentication, enabled: true };
    catalog.push(record);
    if (afterCreate) { const operation = afterCreate; afterCreate = null; await operation(); }
    if (createBehavior === "disconnect") throw new Error("response lost");
    if (createBehavior === "conflict") return respond([{ status: "failed", httpStatus: 409 }]);
    return respond([{ status: "succeeded", data: { record, configRevision: 1 } }]);
  }
  if (url.pathname === "/api/admin/accounts/import-tasks" && options.method === "POST") {
    posts.push(structuredClone(body));
    if (!tasks.has(body.submissionId)) tasks.set(body.submissionId, { taskId: body.submissionId, status: behavior === "failed" ? "failed" : "succeeded" });
    if (behavior === "disconnect") throw new Error("connection reset");
    return respond({ taskId: body.submissionId }, 202);
  }
  if (url.pathname === "/api/admin/accounts/import-tasks/retry") {
    const task = tasks.get(body.taskId); task.status = "succeeded";
    return respond(detail(task), 202);
  }
  if (url.pathname === "/api/admin/accounts/import-tasks/detail") return respond(detail(tasks.get(url.searchParams.get("taskId"))));
  throw new Error(`Unexpected mock route: ${url.pathname}`);
}
function detail(task) {
  return { finishedAt: new Date().toISOString(), items: [{ index: 0, status: task.status, canRetry: task.status === "failed", accountIds: task.status === "succeeded" ? ["account-one"] : [] }] };
}
function create() { return createCrsIntegration({ database, getJob: (id) => jobs.get(id), readExport: async (job) => job.exportData, fetchImpl, pollIntervalMs: 5 }); }
function job(label, proxy = proxyUrl) {
  const value = { id: label, email: `${label}@example.invalid`, resultSaved: true, proxyUrl: proxy, exportData: { type: "sub2api-data", accounts: [{ name: label, credentials: { email: `${label}@example.invalid`, access_token: `access-${label}` } }] } };
  jobs.set(label, value); return value;
}
function entry(id) { return database.get("runtime", "crs-outbox").entries.filter((value) => value.jobId === id).at(-1); }
async function state(id, expected) {
  const deadline = Date.now() + 4000;
  while (Date.now() < deadline) {
    if (service.status().items.find((item) => item.jobId === id)?.status === expected) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error(`Expected ${id} to be ${expected}; observed ${entry(id)?.status}`);
}
function submission(id) { return posts.filter((post) => post.items[0].data.accounts[0].name === id).at(-1); }

try {
  assert.equal(resolveCrsProxy("HTTP://u:p@Proxy.Example:80", [{ ...firstProxy, endpoint: "http://proxy.example/" }]).id, firstProxy.id);
  assert.equal(resolveCrsProxy("socks5h://u:p@[2001:db8::1]:1080/", catalog).id, secondProxy.id);
  assert.equal(resolveCrsProxy(null, catalog), null);
  assert.equal(resolveCrsProxy("socks5://u:p@[2001:db8::1]", catalog).id, secondProxy.id);
  assert.throws(() => resolveCrsProxy("http://u:p@[2001:db8::1]:1080", catalog), /未找到/);
  const socksLocalDns = { ...secondProxy, id: "socks-local-dns", endpoint: "socks5://[2001:db8::1]:1080" };
  const dnsVariants = [secondProxy, socksLocalDns];
  assert.equal(resolveCrsProxy("socks5://u:p@[2001:db8::1]:1080", dnsVariants).id, socksLocalDns.id);
  assert.equal(resolveCrsProxy("socks5h://u:p@[2001:db8::1]:1080", dnsVariants).id, secondProxy.id);
  assert.throws(() => resolveCrsProxy("socks5://u:p@[2001:db8::1]:1080", [...dnsVariants, { ...socksLocalDns, id: "duplicate-local-dns" }]), /多条/);
  assert.throws(() => resolveCrsProxy("socks5://u:p@[2001:db8::1]:1080", [secondProxy, { ...socksLocalDns, enabled: false }]), /停用/);
  assert.throws(() => resolveCrsProxy("socks5://u:p@[2001:db8::1]:1080", [secondProxy, { ...socksLocalDns, hasAuthentication: false }]), /认证配置不一致/);
  assert.throws(() => resolveCrsProxy("http://u:p@proxy.example:8080/path", catalog), /无效/);
  assert.throws(() => resolveCrsProxy(proxyUrl, [{ ...firstProxy, hasAuthentication: false }]), /认证配置不一致/);

  service = create();
  pageSize = 1;
  const first = job("manual");
  await service.enqueue([first.id]);
  await state(first.id, "succeeded");
  assert.equal(submission(first.id).items[0].outboundProxyId, firstProxy.id);
  assert.deepEqual(submission(first.id).items[0].settings.groupIds, ["openai"]);
  assert.ok(requests.some((request) => request.query.includes("page=2")), "read every catalog page");
  assert.match(service.status().items.find((item) => item.jobId === first.id).message, /绑定登录所用代理/);
  assert.equal((await service.enqueue([first.id])).skipped, 1);
  assert.doesNotMatch(JSON.stringify({ posts, status: service.status(), outbox: entry(first.id) }), /login-user|login-secret/);

  // A changed proxy must not be suppressed by an earlier successful credential upload.
  first.proxyUrl = "socks5h://u:p@[2001:db8::1]:1080";
  assert.equal((await service.enqueue([first.id])).queued, 1);
  await state(first.id, "succeeded");
  assert.equal(submission(first.id).items[0].outboundProxyId, secondProxy.id);

  // The catalog loader must retain the raw protocol after canonicalization.
  catalog = [firstProxy, ...dnsVariants];
  const localDnsJob = job("local-dns", "socks5://u:p@[2001:db8::1]:1080");
  await service.enqueue([localDnsJob.id]); await state(localDnsJob.id, "succeeded");
  assert.equal(submission(localDnsJob.id).items[0].outboundProxyId, socksLocalDns.id);
  catalog = [firstProxy, secondProxy];

  const direct = job("direct", null);
  const catalogReads = requests.filter((request) => request.path.endsWith("/proxies")).length;
  await service.enqueue([direct.id]); await state(direct.id, "succeeded");
  assert.equal(Object.hasOwn(submission(direct.id).items[0], "outboundProxyId"), false);
  assert.equal(requests.filter((request) => request.path.endsWith("/proxies")).length, catalogReads);

  // A short-lived operation lease must never be created or bound as a CPR
  // business proxy, including after a later manual upload of saved credentials.
  const leased = job("operation-lease", "socks5h://128.1.12.151:7000");
  database.put("operation-proxy-selection", leased.email.toLowerCase(), {
    operationId: "11111111-1111-4111-8111-111111111111", proxyUrl: leased.proxyUrl,
    expiresAt: new Date(Date.now() - 60_000).toISOString(),
  });
  // An old account-bound dynamic configuration is unrelated to this login lease.
  database.put("dynamic-proxy", leased.email.toLowerCase(), { status: "expired", proxyUrl: "socks5h://old.example:1080" });
  const beforeLeaseCreates = creates.length;
  const beforeLeaseCatalog = requests.filter((request) => request.path.endsWith("/proxies")).length;
  await service.enqueue([leased.id]); await state(leased.id, "succeeded");
  assert.equal(Object.hasOwn(submission(leased.id).items[0], "outboundProxyId"), false);
  assert.equal(creates.length, beforeLeaseCreates);
  assert.equal(requests.filter((request) => request.path.endsWith("/proxies")).length, beforeLeaseCatalog);
  assert.doesNotMatch(JSON.stringify(entry(leased.id)), /128\.1\.12\.151|7000/);
  database.remove("dynamic-proxy", leased.email.toLowerCase());
  leased.proxyUrl = proxyUrl;
  await service.enqueue([leased.id]); await state(leased.id, "succeeded");
  assert.equal(submission(leased.id).items[0].outboundProxyId, firstProxy.id, "a distinct explicit static choice still binds normally");

  // Validate the complete selection before proxy creation or account import.
  const good = job("batch-good"); const missing = job("batch-missing", "http://u:p@missing.example:8080");
  const beforeBatch = posts.length;
  const lostProxy = job("missing-saved-proxy", null);
  database.saveJob(lostProxy.id, { email: lostProxy.email, proxy_configured: true });
  await assert.rejects(service.enqueue([missing.id, lostProxy.id]), /代理配置已缺失/);
  assert.equal(entry(lostProxy.id), undefined);
  assert.equal(entry(good.id), undefined); assert.equal(posts.length, beforeBatch);
  assert.equal(creates.length, 0);
  const conflicting = job("conflicting-proxy", "http://other:password@missing.example:8080");
  await assert.rejects(service.enqueue([missing.id, conflicting.id]), /认证信息不同/);
  assert.equal(creates.length, 0);
  catalog = [firstProxy, { ...firstProxy, id: "duplicate", enabled: false }];
  await assert.rejects(service.enqueue([good.id]), /多条/);
  catalog = [{ ...firstProxy, enabled: false }];
  await assert.rejects(service.enqueue([good.id]), /停用/);
  catalog = [{ ...firstProxy, hasAuthentication: false }];
  await assert.rejects(service.enqueue([good.id]), /认证配置不一致/);
  catalog = [firstProxy, secondProxy]; malformedPage = true;
  await assert.rejects(service.enqueue([good.id]), /列表格式/); malformedPage = false;

  // Missing proxy is created with its full credentials before the account import.
  await service.enqueue([missing.id]); await state(missing.id, "succeeded");
  assert.equal(creates.length, 1);
  assert.equal(creates[0].proxyUrl, "http://u:p@missing.example:8080/");
  assert.equal(creates[0].autoLocation, false);
  assert.equal(submission(missing.id).items[0].outboundProxyId, "created-1");
  assert.equal((await service.enqueue([missing.id])).skipped, 1);
  assert.equal(creates.length, 1);
  const sameProxy = job("same-missing-proxy", missing.proxyUrl);
  await service.enqueue([sameProxy.id]); await state(sameProxy.id, "succeeded");
  assert.equal(creates.length, 1);

  // Concurrent uploads sharing one missing proxy create it once and both bind it.
  const concurrentUrl = "socks5h://login-user:login-secret@concurrent.example";
  const concurrentA = job("concurrent-a", concurrentUrl); const concurrentB = job("concurrent-b", concurrentUrl);
  await Promise.all([service.enqueue([concurrentA.id]), service.enqueue([concurrentB.id])]);
  await state(concurrentA.id, "succeeded"); await state(concurrentB.id, "succeeded");
  assert.equal(creates.length, 2);
  assert.equal(creates[1].proxyUrl, `${concurrentUrl}:1080`);
  assert.equal(submission(concurrentA.id).items[0].outboundProxyId, submission(concurrentB.id).items[0].outboundProxyId);
  assert.doesNotMatch(JSON.stringify({ status: service.status(), entry: entry(concurrentA.id), sync: database.get("runtime", "crs-proxy-sync") }), /login-user|login-secret/);

  createBehavior = "reject";
  const rejected = job("create-rejected", "http://login-user:login-secret@reject.example:80");
  await assert.rejects(service.enqueue([rejected.id]), /创建代理失败/);
  assert.equal(entry(rejected.id), undefined); assert.equal(submission(rejected.id), undefined);
  assert.deepEqual(database.get("runtime", "crs-proxy-sync"), {});
  createBehavior = "success";
  await service.enqueue([rejected.id]); await state(rejected.id, "succeeded");

  createBehavior = "disconnect";
  const committed = job("create-committed", "http://u:p@committed.example:8080");
  await service.enqueue([committed.id]); await state(committed.id, "succeeded");
  assert.ok(submission(committed.id).items[0].outboundProxyId.startsWith("created-"));
  createBehavior = "conflict";
  const conflict = job("create-conflict", "http://u:p@conflict.example:8080");
  await service.enqueue([conflict.id]); await state(conflict.id, "succeeded");

  // Unknown create outcomes survive restart and block a second blind create.
  createBehavior = "unknown";
  const uncertain = job("create-unknown", "http://u:p@uncertain.example:8080");
  await assert.rejects(service.enqueue([uncertain.id]), /创建结果尚未确认/);
  const createCount = creates.length;
  await service.close(); service = create(); createBehavior = "success";
  await assert.rejects(service.enqueue([uncertain.id]), /创建结果尚未确认/);
  assert.equal(creates.length, createCount); assert.equal(submission(uncertain.id), undefined);
  catalog.push({ ...firstProxy, id: "eventually-visible", endpoint: "http://uncertain.example:8080/" });
  await service.enqueue([uncertain.id]); await state(uncertain.id, "succeeded");
  assert.equal(submission(uncertain.id).items[0].outboundProxyId, "eventually-visible");
  assert.equal(creates.length, createCount);
  assert.deepEqual(database.get("runtime", "crs-proxy-sync"), {});

  const deletedOnCreate = job("deleted-during-create", "http://u:p@deleted.example:8080");
  afterCreate = () => jobs.delete(deletedOnCreate.id);
  await assert.rejects(service.enqueue([deletedOnCreate.id]), /账号或登录代理已改变/);
  assert.equal(submission(deletedOnCreate.id), undefined);

  // Recheck a saved binding after downtime; never silently substitute a new proxy ID.
  const replaced = job("replaced-after-enqueue");
  await service.enqueue([replaced.id]); await service.close();
  catalog = [{ ...firstProxy, id: "replacement" }, secondProxy];
  service = create(); await state(replaced.id, "failed");
  assert.match(entry(replaced.id).message, /已更换/);
  assert.equal(submission(replaced.id), undefined);
  catalog = [firstProxy, secondProxy];
  service.retry([replaced.id]); await state(replaced.id, "succeeded");
  assert.equal(submission(replaced.id).items[0].outboundProxyId, firstProxy.id);

  const disabled = job("disabled-after-enqueue");
  await service.enqueue([disabled.id]); await service.close();
  catalog = [{ ...firstProxy, enabled: false }, secondProxy];
  service = create(); await state(disabled.id, "failed");
  assert.equal(submission(disabled.id), undefined);
  catalog = [firstProxy, secondProxy];

  // Automatic completion uses the same selection and fail-closed behavior.
  service.putConfiguration({ ...config, autoUpload: true }, 1);
  const automatic = job("automatic"); await service.authorizationCompleted(automatic); await state(automatic.id, "succeeded");
  assert.equal(submission(automatic.id).items[0].outboundProxyId, firstProxy.id);
  const autoMissing = job("auto-create", "http://u:p@automatic.example:8080");
  await service.authorizationCompleted(autoMissing); await state(autoMissing.id, "succeeded");
  assert.ok(submission(autoMissing.id).items[0].outboundProxyId.startsWith("created-"));

  behavior = "failed";
  const retry = job("remote-retry"); await service.enqueue([retry.id]); await state(retry.id, "succeeded");
  assert.equal(posts.filter((post) => post.items[0].data.accounts[0].name === retry.id).length, 1);
  assert.equal(entry(retry.id).outboundProxy.id, firstProxy.id);

  // A disconnected response is ambiguous. An explicit retry keeps the exact payload/ID.
  behavior = "disconnect";
  const unknown = job("ambiguous"); await service.enqueue([unknown.id]); await state(unknown.id, "unknown");
  const original = submission(unknown.id);
  await service.close(); service = create();
  behavior = "success"; service.retry([unknown.id]); await state(unknown.id, "succeeded");
  assert.deepEqual(submission(unknown.id), original);

  // 动态代理使用服务端核对过的独立 ID，同网关不同认证可同时上传
  const dynamicA = job("dynamic-a", "http://user:a@proxy.example:8080/");
  const dynamicB = job("dynamic-b", "http://user:b@proxy.example:8080/");
  catalog = [firstProxy, { ...firstProxy, id: "proxy-dynamic-b" }];
  for (const [value, proxyId] of [[dynamicA, firstProxy.id], [dynamicB, "proxy-dynamic-b"]]) {
    database.put("dynamic-proxy", value.email, { id: value.id, target: config.baseUrl, proxyUrl: value.proxyUrl, proxyId, generation: 1, status: "ready" });
  }
  await service.enqueue([dynamicA.id, dynamicB.id]);
  await state(dynamicA.id, "succeeded"); await state(dynamicB.id, "succeeded");
  assert.equal(submission(dynamicA.id).items[0].outboundProxyId, firstProxy.id);
  assert.equal(submission(dynamicB.id).items[0].outboundProxyId, "proxy-dynamic-b");
  assert.equal(submission(dynamicA.id).items[0].settings.credentialGuardian.enabled, true);
  const dynamicStale = job("dynamic-stale", dynamicA.proxyUrl);
  database.put("dynamic-proxy", dynamicStale.email, { id: dynamicStale.id, target: config.baseUrl, proxyUrl: dynamicStale.proxyUrl, proxyId: firstProxy.id, generation: 1, status: "ready" });
  await service.enqueue([dynamicStale.id]); await service.close();
  database.put("dynamic-proxy", dynamicStale.email, { ...database.get("dynamic-proxy", dynamicStale.email), generation: 2 });
  service = create(); await state(dynamicStale.id, "failed");
  assert.equal(submission(dynamicStale.id), undefined);
  catalog = [firstProxy, secondProxy];

  const change = job("config-race");
  hook = () => service.putConfiguration({ ...config, baseUrl: "http://different.example" }, 2);
  await assert.rejects(service.enqueue([change.id]), /目标或登录身份已改变/);
  assert.equal(entry(change.id), undefined);
  assert.doesNotMatch(JSON.stringify(service.status()), /login-user|login-secret|private-crs-key/);
  console.log("CRS proxy binding and auto-create: manual/automatic, pagination, matching, validation, concurrency, restart, ambiguous creation, rejection, retries and secret exclusion passed");
} finally {
  await service?.close(); database.close(); await fs.rm(root, { recursive: true, force: true });
}
