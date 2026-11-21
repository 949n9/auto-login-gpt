import crypto from "node:crypto";

const CONFIG_RECORD = "crs-config";
const OUTBOX_RECORD = "crs-outbox";
const SETTINGS_RECORD = "crs-account-settings";
const PROXY_SYNC_RECORD = "crs-proxy-sync";
export const DEFAULT_GUARDIAN = Object.freeze({ enabled: false, autoRelogin: true, definitionId: "candy", modelId: "gpt-6.1-sol", reasoningEffort: "medium", intervalSeconds: 120, retrySeconds: 60 });
const MAX_ATTEMPTS = 3;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_EXPORT_BYTES = 2 * 1024 * 1024;
const CREDENTIAL_FIELDS = new Set([
  "email", "access_token", "refresh_token", "id_token", "expires_at",
  "expires_in", "token_type", "scope", "client_id", "chatgpt_account_id",
  "chatgpt_user_id", "account_id", "user_id",
]);

function failure(status, message, extra = {}) { return Object.assign(new Error(message), { status, ...extra }); }
function object(value) { return Boolean(value && typeof value === "object" && !Array.isArray(value)); }
function text(value, maximum) {
  if (typeof value !== "string" || value.length > maximum) throw failure(400, "CRS 配置字段格式不正确");
  return value;
}
function normalizeBaseUrl(value) {
  const raw = text(value, 2048).trim().replace(/\/+$/, "");
  let parsed;
  try { parsed = new URL(raw); } catch { throw failure(400, "请输入有效的 CRS HTTP 或 HTTPS 地址"); }
  if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash || (parsed.pathname !== "/" && parsed.pathname !== "")) {
    throw failure(400, "CRS 地址必须为 HTTP 或 HTTPS 服务根地址，不能包含登录信息或路径");
  }
  return parsed.origin;
}
function normalizeConfiguration(value, previous = null) {
  if (!object(value)) throw failure(400, "CRS 配置格式不正确");
  const baseUrl = normalizeBaseUrl(value.baseUrl || "");
  const authType = value.authType;
  if (!["password", "apiKey"].includes(authType)) throw failure(400, "CRS 登录方式无效");
  const username = authType === "password" ? text(value.username || "", 160).trim() : "";
  if (authType === "password" && !username) throw failure(400, "请输入 CRS 管理员用户名");
  const sameIdentity = previous?.baseUrl === baseUrl && previous?.authType === authType && previous?.username === username;
  const passwordInput = value.password == null ? "" : text(value.password, 4096);
  const apiKeyInput = value.apiKey == null ? "" : text(value.apiKey, 4096).trim();
  const password = authType === "password" ? (passwordInput || (sameIdentity ? previous.password : "")) : "";
  const apiKey = authType === "apiKey" ? (apiKeyInput || (sameIdentity ? previous.apiKey : "")) : "";
  if (authType === "password" && !password) throw failure(400, "目标或用户名改变后，请重新填写 CRS 管理员密码");
  if (authType === "apiKey" && (!apiKey || /[\r\n]/.test(apiKey))) throw failure(400, "目标改变后，请重新填写有效的 CRS 管理员 API Key");
  return { baseUrl, authType, username, password, apiKey, autoUpload: value.autoUpload === true };
}
function publicConfiguration(saved) {
  const config = saved?.config;
  return {
    config: { baseUrl: config?.baseUrl || "", authType: config?.authType || "password", username: config?.username || "", hasPassword: Boolean(config?.password), hasApiKey: Boolean(config?.apiKey), autoUpload: config?.autoUpload === true },
    revision: saved?.revision || 0,
  };
}

export function seedCrsConfiguration(database, config) {
  if (database.get("runtime", CONFIG_RECORD)) return publicConfiguration(database.get("runtime", CONFIG_RECORD));
  const normalized = normalizeConfiguration({ ...config, autoUpload: false });
  database.put("runtime", CONFIG_RECORD, { config: normalized, revision: 1 });
  return publicConfiguration({ config: normalized, revision: 1 });
}

// Keep raw proxy credentials and Sub2API settings out of the OAuth document.
// Saved CRS proxies are selected separately through outboundProxyId.
export function makeCrsExport(value) {
  if (!object(value) || value.type !== "sub2api-data" || !Array.isArray(value.accounts) || value.accounts.length !== 1) throw failure(400, "授权文件不是有效的单账号导入数据");
  const account = value.accounts[0];
  if (!object(account) || !object(account.credentials)) throw failure(400, "授权文件缺少账号凭据");
  const credentials = {};
  for (const field of CREDENTIAL_FIELDS) {
    const fieldValue = account.credentials[field];
    if (["string", "number"].includes(typeof fieldValue)) credentials[field] = fieldValue;
  }
  if (!credentials.access_token && !credentials.refresh_token) throw failure(400, "授权文件缺少可导入的令牌");
  const extra = {};
  for (const field of ["email", "chatgpt_user_id", "chatgpt_account_id", "account_id", "user_id"]) {
    if (["string", "number"].includes(typeof account.extra?.[field])) extra[field] = account.extra[field];
  }
  const result = { type: "sub2api-data", version: 1, accounts: [{ name: typeof account.name === "string" ? account.name.slice(0, 300) : credentials.email || extra.email || "toSub2", credentials, ...(Object.keys(extra).length ? { extra } : {}) }] };
  if (Buffer.byteLength(JSON.stringify(result)) > MAX_EXPORT_BYTES) throw failure(400, "账号授权数据超过上传大小限制");
  return result;
}

function proxyIdentity(value) {
  let url;
  try { url = new URL(value); } catch { throw failure(400, "登录代理地址无效，请重新选择代理"); }
  if (typeof value !== "string" || value.length > 4096 || /[\r\n\t]/.test(value)
    || !["http:", "https:", "socks5:", "socks5h:"].includes(url.protocol)
    || !url.hostname || url.port === "0"
    || !["", "/"].includes(url.pathname) || url.search || url.hash) throw failure(400, "登录代理地址无效，请重新选择代理");
  const hasAuthentication = Boolean(url.username || url.password);
  url.username = ""; url.password = "";
  // SOCKS5 and SOCKS5H address the same proxy; only DNS resolution differs.
  const protocol = url.protocol === "socks5h:" ? "socks5:" : url.protocol;
  const port = url.port || ({ "http:": "80", "https:": "443", "socks5:": "1080" })[protocol];
  return { endpoint: `${protocol}//${url.hostname.toLowerCase()}:${port}`, hasAuthentication, protocol: url.protocol };
}

function matchProxy(identity, proxies) {
  let matches = proxies.filter((proxy) => proxyIdentity(proxy.endpoint).endpoint === identity.endpoint);
  if (!matches.length) throw failure(409, "CRS 未找到登录所用代理", { proxyMissing: true });
  // SOCKS5 and SOCKS5H can coexist in CPR because they resolve DNS differently.
  // Preserve the explicitly selected protocol when the canonical address has
  // multiple records; never choose by list order or change an account binding.
  if (matches.length > 1) {
    const exact = matches.filter((proxy) => (proxy.protocol || proxyIdentity(proxy.endpoint).protocol) === identity.protocol);
    if (exact.length === 1) matches = exact;
  }
  if (matches.length !== 1) throw failure(409, "CRS 中存在多条相同地址的代理，无法确定对应关系，请整理后重新推送");
  const proxy = matches[0];
  if (proxy.enabled !== true) throw failure(409, "CRS 中对应代理已停用，请启用后重新推送");
  if (proxy.hasAuthentication !== identity.hasAuthentication) throw failure(409, "两边代理的认证配置不一致，请同步代理后重新推送");
  if (typeof proxy.id !== "string" || !proxy.id || proxy.id.length > 160) throw failure(502, "CRS 代理编号无效");
  return { id: proxy.id, endpoint: identity.endpoint, protocol: proxy.protocol || proxyIdentity(proxy.endpoint).protocol, hasAuthentication: identity.hasAuthentication };
}

export function resolveCrsProxy(proxyUrl, proxies) {
  return proxyUrl ? matchProxy(proxyIdentity(proxyUrl), proxies) : null;
}

function proxySyncKey(proxyUrl, target) {
  const url = new URL(proxyUrl);
  return crypto.createHash("sha256").update(JSON.stringify([target.baseUrl, proxyIdentity(proxyUrl).endpoint, url.username, url.password])).digest("hex");
}

export function createCrsIntegration({ database, getJob, readExport, fetchImpl = fetch, requestTimeoutMs = 15000, pollIntervalMs = 1000, taskTimeoutMs = 5 * 60_000 }) {
  let closed = false;
  let workerPromise = null;
  let timer = null;
  let lastError = null;
  let enqueueTail = Promise.resolve();
  let pendingEnqueues = 0;
  const controllers = new Set();
  const sessions = new Map();
  const outbox = database.get("runtime", OUTBOX_RECORD) || { entries: [] };
  if (!Array.isArray(outbox.entries)) throw new Error("CRS 上传队列格式不正确，已停止恢复");
  for (const entry of outbox.entries) {
    if (entry.status === "running" && !entry.taskId) { entry.status = "unknown"; entry.message = "服务在提交期间中断，CRS 是否接收尚未确认；请先核对后手动重试"; entry.updatedAt = new Date().toISOString(); }
  }
  persist();

  function persist() { database.put("runtime", OUTBOX_RECORD, outbox); }
  function savedConfiguration() { return database.get("runtime", CONFIG_RECORD); }
  function safeMessage(value, fallback = "CRS 请求失败") {
    let result = typeof value === "string" && value.trim() ? value : fallback;
    for (const entry of outbox.entries) {
      const credentials = entry.snapshot?.accounts?.[0]?.credentials || {};
      for (const field of ["access_token", "refresh_token", "id_token"]) if (typeof credentials[field] === "string" && credentials[field]) result = result.replaceAll(credentials[field], "<已隐藏>");
    }
    for (const config of [savedConfiguration()?.config, ...outbox.entries.map((entry) => entry.target)]) {
      for (const field of ["password", "apiKey"]) if (config?.[field]) result = result.replaceAll(config[field], "<已隐藏>");
    }
    for (const cookie of sessions.values()) {
      if (cookie) result = result.replaceAll(cookie, "<已隐藏>");
      for (const pair of cookie.split(";")) { const secret = pair.slice(pair.indexOf("=") + 1).trim(); if (secret) result = result.replaceAll(secret, "<已隐藏>"); }
    }
    return result.replace(/Bearer\s+\S+/gi, "Bearer <已隐藏>").replace(/(?:https?|socks5h?):\/\/\S+/gi, "<接口地址已隐藏>").replace(/[\r\n]+/g, " ").slice(0, 300);
  }
  function update(entry, status, message) { entry.status = status; entry.message = safeMessage(message); entry.updatedAt = new Date().toISOString(); persist(); }
  function targetKey(config) { return `${config.baseUrl}|${config.authType}|${config.username}|${crypto.createHash("sha256").update(config.password || config.apiKey || "").digest("hex")}`; }
  function targetIdentity(config) {
    return config ? { baseUrl: config.baseUrl, authType: config.authType, username: config.username || "" } : null;
  }
  function sameTargetIdentity(left, right) {
    return Boolean(left && right && left.baseUrl === right.baseUrl && left.authType === right.authType && (left.username || "") === (right.username || ""));
  }
  function requireScheduledTarget(expected) {
    const current = savedConfiguration()?.config;
    if (!current || !sameTargetIdentity(expected, current)) throw failure(409, "计划绑定的 CPR 目标或登录身份已改变，已停止推送", { targetChanged: true });
    return current;
  }
  function assertScheduledTargetCurrent(entry) {
    if (entry.scheduleItemId) requireScheduledTarget(entry.targetIdentity);
  }
  function responseData(payload) {
    if (!object(payload) || payload.code !== 200 || !object(payload.data)) throw failure(502, "CRS 返回了无法识别的响应");
    return payload.data;
  }
  async function request(config, endpoint, options = {}, authenticated = true, retried = false) {
    if (closed) throw failure(503, "CRS 上传服务正在关闭");
    const controller = new AbortController();
    controllers.add(controller);
    const timeout = setTimeout(() => controller.abort(), requestTimeoutMs);
    try {
      const headers = { accept: "application/json", ...(options.body ? { "content-type": "application/json" } : {}) };
      if (authenticated) {
        if (config.authType === "apiKey") headers["X-API-Key"] = config.apiKey;
        else {
          const key = targetKey(config);
          if (!sessions.has(key)) await login(config);
          headers.cookie = sessions.get(key);
        }
      }
      const requestOptions = { ...options };
      delete requestOptions.beforeSend;
      options.beforeSend?.();
      const response = await fetchImpl(`${config.baseUrl}${endpoint}`, { ...requestOptions, headers, redirect: "error", signal: controller.signal });
      const declaredLength = Number(response.headers.get("content-length") || 0);
      if (declaredLength > MAX_RESPONSE_BYTES) { await response.body?.cancel(); throw failure(502, "CRS 响应超过大小限制"); }
      const reader = response.body?.getReader();
      const chunks = []; let length = 0;
      if (reader) {
        try { while (true) { const next = await reader.read(); if (next.done) break; length += next.value.byteLength; if (length > MAX_RESPONSE_BYTES) { await reader.cancel(); throw failure(502, "CRS 响应超过大小限制"); } chunks.push(Buffer.from(next.value)); } }
        finally { reader.releaseLock(); }
      }
      let payload;
      try { payload = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { throw failure(502, "CRS 返回了无效的 JSON 响应"); }
      if ((response.status === 401 || response.status === 403) && authenticated && config.authType === "password" && !retried) {
        sessions.delete(targetKey(config));
        return request(config, endpoint, options, true, true);
      }
      if (!response.ok || payload?.code !== 200) throw failure(502, `CRS 返回 HTTP ${response.status}`, { remoteStatus: response.status, remoteCode: payload?.code });
      return { payload, cookies: response.headers.getSetCookie?.() || [], status: response.status };
    } catch (error) {
      if (error.remoteStatus) throw error;
      throw failure(error.status || 502, closed ? "CRS 上传服务正在关闭" : error.name === "AbortError" ? "CRS 请求超时" : safeMessage(error.message), { ambiguous: true, localDeleted: error.localDeleted === true, targetChanged: error.targetChanged === true });
    } finally { clearTimeout(timeout); controllers.delete(controller); }
  }
  async function login(config) {
    const result = await request(config, "/api/auth/login", { method: "POST", body: JSON.stringify({ mode: "admin", username: config.username, password: config.password }) }, false);
    const cookie = result.cookies.map((value) => value.split(";", 1)[0]).filter((value) => /^[^=;\s]+=[^;\r\n]*$/.test(value)).join("; ");
    if (!cookie) throw failure(502, "CRS 管理员登录未返回会话，请检查账号密码");
    sessions.set(targetKey(config), cookie);
  }
  async function checkConnection(config) {
    const version = responseData((await request(config, "/api/admin/system/version")).payload).version;
    responseData((await request(config, "/api/admin/accounts/import-tasks")).payload);
    return { ok: true, version: typeof version === "string" ? version.slice(0, 100) : "unknown", message: "CRS 管理员连接正常，支持后台导入任务" };
  }
  async function groups() {
    const config = savedConfiguration()?.config;
    if (!config) throw failure(409, "请先配置 CRS 服务器");
    const items = [];
    for (let page = 1; page <= 100; page += 1) {
      const data = responseData((await request(config, `/api/admin/account-groups/options?page=${page}&pageSize=200&enabled=true`)).payload);
      if (!Array.isArray(data.items) || !Number.isSafeInteger(data.page?.totalPages) || data.page.totalPages > 100) throw failure(502, "CRS 分组列表格式不正确");
      for (const group of data.items) {
        if (typeof group.id !== "string" || typeof group.name !== "string") throw failure(502, "CRS 分组列表格式不正确");
        if (group.enabled === true) items.push({ id: group.id, name: group.name, color: group.color, enabled: true });
      }
      if (page >= data.page.totalPages) break;
    }
    const defaults = items.filter((group) => group.name.trim().toLowerCase() === "openai");
    return { items, defaultGroupIds: defaults.length === 1 ? [defaults[0].id] : [], defaultConcurrency: 7, defaultGuardian: DEFAULT_GUARDIAN, ...(defaults.length !== 1 ? { message: "未找到唯一可用的 openai 分组，请选择 CRS 分组" } : {}) };
  }
  async function proxies(config) {
    const items = [];
    const ids = new Set();
    for (let page = 1; page <= 100; page += 1) {
      const data = responseData((await request(config, `/api/admin/proxies?page=${page}&pageSize=100`)).payload);
      if (!Array.isArray(data.items) || data.items.length > 100 || !Number.isSafeInteger(data.page?.totalPages)
        || data.page.totalPages < 0 || data.page.totalPages > 100 || data.page.page !== page) throw failure(502, "CRS 代理列表格式不正确");
      for (const item of data.items) {
        if (!object(item) || typeof item.id !== "string" || !item.id || ids.has(item.id)
          || typeof item.endpoint !== "string" || typeof item.enabled !== "boolean" || typeof item.hasAuthentication !== "boolean") throw failure(502, "CRS 代理列表格式不正确");
        ids.add(item.id);
        const identity = proxyIdentity(item.endpoint);
        if (identity.hasAuthentication) throw failure(502, "CRS 代理列表未按预期隐藏认证信息");
        items.push({ id: item.id, endpoint: identity.endpoint, protocol: identity.protocol, enabled: item.enabled, hasAuthentication: item.hasAuthentication });
      }
      if (page >= data.page.totalPages) return items;
      if (!data.items.length) throw failure(502, "CRS 代理列表分页不完整");
    }
    throw failure(502, "CRS 代理列表超过读取上限");
  }
  async function verifyProxy(entry) {
    if (!entry.outboundProxy) return;
    try {
      assertDynamicProxyCurrent(entry);
      const catalog = await proxies(entry.target);
      const current = matchProxy(entry.outboundProxy, entry.outboundProxy.dynamicBindingId ? catalog.filter((value) => value.id === entry.outboundProxy.id) : catalog);
      if (current.id !== entry.outboundProxy.id) throw failure(409, "CRS 对应代理已更换，请核对原上传后重新推送");
    } catch (error) {
      throw failure(error.status || 502, error.message, { proxyBinding: true });
    }
  }
  function assertDynamicProxyCurrent(entry) {
    if (!entry.outboundProxy?.dynamicBindingId) return;
    const current = database.get("dynamic-proxy", entry.email.trim().toLowerCase());
    if (!current || current.id !== entry.outboundProxy.dynamicBindingId || current.generation !== entry.outboundProxy.dynamicGeneration || current.proxyId !== entry.outboundProxy.id || current.status !== "ready" || current.blockedReason || current.target !== entry.target.baseUrl) throw failure(409, "动态代理状态已变化，停止上传并等待重新检查");
  }
  function assertCurrentTarget(target) {
    if (closed) throw failure(503, "CRS 上传服务正在关闭");
    if (targetKey(target) !== targetKey(savedConfiguration()?.config || {})) throw failure(409, "CRS 目标或登录身份已改变，请重新推送");
  }
  async function ensureProxy(proxyUrl, target, beforeCreate) {
    if (!proxyUrl) return null;
    const identity = proxyIdentity(proxyUrl);
    const url = new URL(proxyUrl);
    if (["socks5:", "socks5h:"].includes(url.protocol) && !url.port) url.port = "1080";
    const syncId = proxySyncKey(proxyUrl, target);
    const sync = database.get("runtime", PROXY_SYNC_RECORD) || {};
    const clear = () => { delete sync[syncId]; database.put("runtime", PROXY_SYNC_RECORD, sync); };
    // Always reread the catalog inside the serialized enqueue operation.
    try {
      const existing = matchProxy(identity, await proxies(target));
      if (sync[syncId]) clear();
      return existing;
    } catch (error) { if (!error.proxyMissing) throw error; }
    if (sync[syncId]) throw failure(409, "代理创建结果尚未确认，请先核对 CRS 代理列表后重新推送");
    if (Object.keys(sync).length >= 2000) throw failure(409, "待核对的 CRS 代理创建记录已达到上限");
    assertCurrentTarget(target); beforeCreate();
    let sent = false;
    let rejected = false;
    let createdId;
    try {
      const result = await request(target, "/api/admin/proxies/create", {
        method: "POST",
        body: JSON.stringify([{ name: `toSub2 ${identity.endpoint}`.slice(0, 100), proxyUrl: url.href, autoLocation: false }]),
        beforeSend: () => {
          assertCurrentTarget(target); beforeCreate();
          sync[syncId] = { status: "unknown", updatedAt: new Date().toISOString() };
          database.put("runtime", PROXY_SYNC_RECORD, sync); sent = true;
        },
      });
      const items = result.payload.data;
      if (!Array.isArray(items) || items.length !== 1) throw failure(502, "CRS 代理创建响应格式不正确");
      const item = items[0];
      if (item?.status === "failed" && Number.isInteger(item.httpStatus) && item.httpStatus >= 400 && item.httpStatus < 500) rejected = true;
      if (item?.status !== "succeeded" || !object(item.data?.record)) throw failure(502, "CRS 未确认代理创建成功");
      createdId = matchProxy(identity, [item.data.record]).id;
    } catch (error) {
      if (!sent) throw failure(error.status || 502, "创建 CRS 代理前校验失败，请检查配置后重新推送");
      if (error.remoteStatus >= 400 && error.remoteStatus < 500) rejected = true;
    }
    // A timeout or duplicate conflict may still have committed a proxy. Reconcile
    // before importing; never send a second create while the outcome is unknown.
    let binding;
    try { binding = matchProxy(identity, await proxies(target)); }
    catch (error) {
      if (rejected) clear();
      if (error.proxyMissing && rejected) throw failure(502, "CRS 创建代理失败，请检查权限和代理配置后重新推送");
      throw failure(409, "代理创建结果尚未确认，请先核对 CRS 代理列表后重新推送");
    }
    if (createdId && binding.id !== createdId) throw failure(409, "CRS 新建代理已被更换，请核对代理列表后重新推送");
    clear();
    return binding;
  }
  function accountSettings() {
    const target = savedConfiguration()?.config.baseUrl;
    const saved = database.get("runtime", SETTINGS_RECORD) || {};
    return { settings: saved[target] || {} };
  }
  function normalizeSettings(value, catalog) {
    if (!object(value)) throw failure(400, "CRS 账号设置格式不正确");
    const groupIds = value.groupIds ?? catalog.defaultGroupIds;
    if (!Array.isArray(groupIds) || !groupIds.length || groupIds.length > 100 || groupIds.some((id) => typeof id !== "string" || !catalog.items.some((group) => group.id === id))) throw failure(400, "请选择可用的 CRS 分组");
    const concurrencyLimit = value.concurrencyLimit ?? 7;
    if (!Number.isSafeInteger(concurrencyLimit) || concurrencyLimit < 1 || concurrencyLimit > 4294967295) throw failure(400, "账号并发必须是大于 0 的整数");
    const weight = value.weight ?? 1;
    if (!Number.isSafeInteger(weight) || weight < 1 || weight > 100) throw failure(400, "CPR 账号优先级必须是 1 至 100 的整数");
    if (value.credentialGuardian !== undefined && (!object(value.credentialGuardian) || typeof value.credentialGuardian.enabled !== "boolean")) throw failure(400, "401 重登设置格式不正确");
    return { enabled: true, concurrencyLimit, weight, groupIds: [...new Set(groupIds)].sort(), credentialGuardian: { enabled: value.credentialGuardian?.enabled === true } };
  }
  async function saveAccountSettings(ids, value) {
    if (!Array.isArray(ids) || !ids.length || ids.length > 500 || ids.some((id) => typeof id !== "string" || !getJob(id))) throw failure(400, "请选择有效的账号");
    const target = savedConfiguration()?.config.baseUrl;
    const catalog = await groups();
    if (target !== savedConfiguration()?.config.baseUrl) throw failure(409, "CRS 目标已改变，请重新加载分组");
    const settings = normalizeSettings(value, catalog);
    const saved = database.get("runtime", SETTINGS_RECORD) || {};
    const selections = { ...saved[target] };
    for (const id of new Set(ids)) selections[id] = settings;
    if (Object.keys(selections).length > 10000) throw failure(409, "CRS 账号设置已达到容量上限");
    saved[target] = selections;
    database.put("runtime", SETTINGS_RECORD, saved);
    return accountSettings();
  }
  function status() {
    const config = savedConfiguration()?.config;
    const counts = { pending: 0, running: 0, succeeded: 0, failed: 0, unknown: 0, canceled: 0 };
    const latest = new Map(outbox.entries.map((entry) => [entry.jobId, entry]));
    for (const entry of latest.values()) if (Object.hasOwn(counts, entry.status)) counts[entry.status] += 1;
    return { configured: Boolean(config), autoUpload: config?.autoUpload === true, counts, items: [...latest.values()].map(({ jobId, email, status: entryStatus, message, updatedAt, accountIds }) => ({ jobId, email, status: entryStatus, message, updatedAt, accountIds: accountIds || [] })).reverse(), ...(lastError ? { lastError } : {}) };
  }
  function schedule(wait = 0) {
    if (closed || timer || workerPromise) return;
    if (!outbox.entries.some((entry) => entry.status === "pending" || entry.status === "running")) return;
    timer = setTimeout(() => {
      timer = null;
      workerPromise = work().catch((error) => { lastError = safeMessage(error.message); }).finally(() => { workerPromise = null; schedule(pollIntervalMs); });
    }, wait);
    timer.unref?.();
  }
  async function applyDetail(entry, detail) {
    if (!Array.isArray(detail.items) || detail.items.length !== 1) { update(entry, "unknown", "CRS 导入结果结构不完整，请核对远端账号后手动重试"); return; }
    const item = detail.items[0];
    entry.canRetry = item.canRetry === true;
    entry.remoteIndex = Number.isSafeInteger(item.index) ? item.index : 0;
    if (item.status === "succeeded") {
      if (!Array.isArray(item.accountIds) || !item.accountIds.length) { update(entry, "unknown", "CRS 返回成功状态但没有账号编号，请核对账号列表"); return; }
      if (item.accountIds.some((id) => typeof id !== "string" || !id)) { update(entry, "unknown", "CRS 返回的账号编号无效，请核对账号列表"); return; }
      entry.accountIds = [...new Set(item.accountIds)];
      update(entry, "succeeded", entry.outboundProxy ? "账号已导入 CRS，并绑定登录所用代理" : "账号已导入 CRS"); return;
    }
    if (item.status === "failed" || item.status === "skipped") {
      update(entry, "failed", "CRS 未完成账号导入");
      if (item.canRetry === true && entry.attempts < MAX_ATTEMPTS && !closed) {
        entry.retryRemote = true; update(entry, "pending", "CRS 明确允许重试，等待有限次数重试");
      }
      return;
    }
    if (item.status === "unknown" || detail.finishedAt) { update(entry, "unknown", "CRS 未能确认导入结果，请核对后手动重试"); return; }
    if (!["pending", "running"].includes(item.status)) { update(entry, "unknown", "CRS 返回了无法识别的导入状态"); return; }
    update(entry, "running", "CRS 正在导入账号");
  }
  function assertUploadAllowed(job) {
    if (job?.loginDeferred) throw failure(409, "账号仅记录，尚未恢复上号；请先手动上号或等待定时任务", { loginDeferred: true });
    if (job?.resting || job?.retired) throw failure(409, "静置区或废号区的账号不能推送，请先成功登录恢复在用");
  }
  async function work() {
    for (const entry of outbox.entries) {
      if (closed) return;
      if (!["pending", "running"].includes(entry.status)) continue;
      if (entry.status === "running" && Date.now() - Date.parse(entry.startedAt) > taskTimeoutMs) { update(entry, "unknown", "CRS 导入结果等待超时，请核对后手动重试"); continue; }
      if (entry.status === "pending") {
        const localJob = getJob(entry.jobId);
        if (!entry.taskId && (!localJob || localJob.deleted)) {
          update(entry, "failed", "本地账号已删除，已停止上传");
          continue;
        }
        if (localJob?.loginDeferred || localJob?.resting || localJob?.retired) {
          update(entry, "failed", "账号已暂停，已停止后续推送；请先成功登录恢复在用");
          continue;
        }
        entry.attempts += 1; entry.startedAt = new Date().toISOString();
        update(entry, "running", "正在提交 CRS 后台导入任务");
        try {
          if (entry.scheduleItemId) {
            // Preserve the planned server identity while allowing its credentials to be rotated.
            entry.target = { ...requireScheduledTarget(entry.targetIdentity) };
            persist();
          }
          const jobBeforeRequest = getJob(entry.jobId);
          if ((entry.reconcileOnly || !jobBeforeRequest || jobBeforeRequest.deleted) && entry.taskId) {
            entry.reconcileOnly = false;
            const detail = responseData((await request(entry.target, `/api/admin/accounts/import-tasks/detail?taskId=${encodeURIComponent(entry.taskId)}`)).payload);
            await applyDetail(entry, detail);
            continue;
          } else if (entry.retryRemote && entry.taskId) {
            await verifyProxy(entry);
            const detail = responseData((await request(entry.target, "/api/admin/accounts/import-tasks/retry", { method: "POST", body: JSON.stringify({ taskId: entry.taskId, index: entry.remoteIndex || 0 }), beforeSend: () => { assertScheduledTargetCurrent(entry); assertDynamicProxyCurrent(entry); const job = getJob(entry.jobId); assertUploadAllowed(job); if (!job || job.deleted) throw failure(409, "本地账号已删除，已停止重新导入"); } })).payload);
            entry.retryRemote = false;
            await applyDetail(entry, detail);
          } else {
            // Authenticate before submission; a failed login cannot create a task.
            if (entry.target.authType === "password" && !sessions.has(targetKey(entry.target))) await login(entry.target);
            await verifyProxy(entry);
            const jobBeforeSubmission = getJob(entry.jobId);
            assertUploadAllowed(jobBeforeSubmission);
            if (!jobBeforeSubmission || jobBeforeSubmission.deleted) {
              update(entry, "failed", "本地账号已删除，已停止上传");
              continue;
            }
            const result = await request(entry.target, "/api/admin/accounts/import-tasks", { method: "POST", body: JSON.stringify({ submissionId: entry.submissionId, items: [{ provider: "openai", data: entry.snapshot, ...(entry.settings ? { settings: entry.settings } : {}), ...(entry.outboundProxy ? { outboundProxyId: entry.outboundProxy.id } : {}) }] }), beforeSend: () => { assertScheduledTargetCurrent(entry); assertDynamicProxyCurrent(entry); const job = getJob(entry.jobId); assertUploadAllowed(job); if (!job || job.deleted) throw failure(409, "本地账号已删除，已停止上传", { localDeleted: true }); entry.submittedAt ||= new Date().toISOString(); persist(); } });
            const summary = responseData(result.payload);
            if (result.status !== 202 || typeof summary.taskId !== "string" || !summary.taskId) throw failure(502, "CRS 未返回后台导入任务编号", { ambiguous: true });
            entry.taskId = summary.taskId;
            persist();
          }
        } catch (error) {
          lastError = safeMessage(error.message);
          if (error.proxyBinding || error.targetChanged || error.loginDeferred) {
            update(entry, !entry.taskId && !entry.submittedAt ? "failed" : "unknown", error.message);
            continue;
          }
          const definiteRejection = !entry.taskId && error.remoteStatus && error.remoteStatus < 500;
          update(entry, definiteRejection || error.localDeleted ? "failed" : "unknown", error.localDeleted ? "本地账号已删除，已停止上传" : definiteRejection ? "CRS 拒绝了上传，请检查配置后重试" : "提交结果尚未确认，请核对 CRS 后手动重试");
          continue;
        }
      }
      if (entry.status !== "running" || !entry.taskId || closed) continue;
      try {
        const detail = responseData((await request(entry.target, `/api/admin/accounts/import-tasks/detail?taskId=${encodeURIComponent(entry.taskId)}`)).payload);
        await applyDetail(entry, detail);
      } catch (error) { lastError = safeMessage(error.message); update(entry, "unknown", "无法确认 CRS 后台任务结果，已停止自动重传，请核对后手动重试"); }
    }
  }
  function enqueue(ids, automatic = false) {
    return serializeEnqueue(() => enqueueBatch(ids, automatic));
  }
  function serializeEnqueue(callback) {
    pendingEnqueues += 1;
    const operation = enqueueTail.then(callback);
    enqueueTail = operation.then(() => {}, () => {}).finally(() => { pendingEnqueues -= 1; });
    return operation;
  }
  function validateScheduleItemId(id) {
    if (typeof id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9:_-]{0,159}$/.test(id)) throw failure(400, "计划账号编号格式无效");
    return id;
  }
  function scheduledEntry(id) {
    validateScheduleItemId(id);
    return outbox.entries.find((entry) => entry.scheduleItemId === id) || null;
  }
  function publicScheduledEntry(entry) {
    return entry ? {
      entryId: entry.id, scheduleItemId: entry.scheduleItemId, status: entry.status,
      taskId: entry.taskId || null, accountIds: [...(entry.accountIds || [])],
      message: safeMessage(entry.message), submittedAt: entry.submittedAt || null,
      createdAt: entry.createdAt, updatedAt: entry.updatedAt,
    } : null;
  }
  function enqueueScheduled(jobId, options = {}) {
    // Snapshot callers' mutable objects before yielding to the serialized queue.
    const input = structuredClone(options);
    return serializeEnqueue(async () => {
      if (closed) throw failure(503, "CRS 上传服务正在关闭");
      const scheduleItemId = validateScheduleItemId(input.scheduleItemId);
      const existing = scheduledEntry(scheduleItemId);
      if (existing) {
        if (existing.jobId !== jobId || (input.targetIdentity && !sameTargetIdentity(input.targetIdentity, existing.targetIdentity))) throw failure(409, "计划账号编号已绑定其他账号或 CPR 目标");
        return publicScheduledEntry(existing);
      }
      const expectedTarget = input.targetIdentity || targetIdentity(savedConfiguration()?.config);
      requireScheduledTarget(expectedTarget);
      if (!object(input.settings)) throw failure(400, "请保存计划使用的 CPR 账号设置");
      await enqueueBatch([jobId], false, { scheduleItemId, settings: input.settings, targetIdentity: targetIdentity(expectedTarget) });
      const entry = scheduledEntry(scheduleItemId);
      if (!entry) throw failure(409, "计划账号尚无已保存的授权结果，未提交 CPR");
      return publicScheduledEntry(entry);
    });
  }
  function lookupScheduled(scheduleItemId) { return publicScheduledEntry(scheduledEntry(scheduleItemId)); }
  function cancelScheduled(scheduleItemId) {
    validateScheduleItemId(scheduleItemId);
    return serializeEnqueue(() => {
      if (closed) throw failure(503, "CRS 上传服务正在关闭");
      const entry = scheduledEntry(scheduleItemId);
      if (entry?.status === "pending" && !entry.submittedAt && !entry.taskId) update(entry, "canceled", "计划已取消，未提交 CPR");
      return publicScheduledEntry(entry);
    });
  }
  async function enqueueBatch(ids, automatic = false, scheduled = null) {
    if (closed) throw failure(503, "CRS 上传服务正在关闭");
    const target = savedConfiguration()?.config;
    if (!target) throw failure(409, "请先配置 CRS 服务器");
    if (scheduled) requireScheduledTarget(scheduled.targetIdentity);
    if (automatic && !target.autoUpload) return { queued: 0, skipped: 0, status: status() };
    if (!Array.isArray(ids) || !ids.length || ids.length > 500 || ids.some((id) => typeof id !== "string")) throw failure(400, "请选择 1 至 500 个账号");
    const catalog = await groups();
    if (target.baseUrl !== savedConfiguration()?.config.baseUrl) throw failure(409, "CRS 目标已改变，请重新加载分组");
    const selectedSettings = accountSettings().settings;
    const snapshots = [];
    let proxyCatalog;
    const selectedProxies = new Map();
    for (const jobId of [...new Set(ids)]) {
      const job = getJob(jobId);
      if (!job) throw failure(404, "部分账号不存在，请刷新后重试");
      assertUploadAllowed(job);
      if (!job.resultSaved) continue;
      if (!job.proxyUrl && database.getJob?.(jobId)?.proxy_configured) throw failure(409, "该账号原先使用代理登录，但代理配置已缺失，请重新选择登录代理后推送");
      const snapshot = makeCrsExport(await readExport(job));
      const settings = normalizeSettings(scheduled?.settings || selectedSettings[jobId] || {}, catalog);
      const operationSelection = database.get("operation-proxy-selection", job.email.trim().toLowerCase());
      // A ten-minute onboarding/security lease is not a durable CPR business
      // proxy. Omitting outboundProxyId preserves CPR's existing selection.
      const operationOnlyProxy = Boolean(job.proxyUrl && operationSelection?.proxyUrl === job.proxyUrl);
      const dynamic = operationOnlyProxy ? null : database.get("dynamic-proxy", job.email.trim().toLowerCase());
      if (dynamic) {
        if (dynamic.target !== target.baseUrl || dynamic.proxyUrl !== job.proxyUrl || dynamic.status !== "ready" || dynamic.blockedReason) throw failure(409, "动态代理尚未就绪或版本已变化");
        settings.credentialGuardian = { enabled: true };
      }
      const proxyUrl = operationOnlyProxy ? null : job.proxyUrl;
      if (proxyUrl && !dynamic) {
        const endpoint = proxyIdentity(proxyUrl).endpoint;
        const key = proxySyncKey(proxyUrl, target);
        if (selectedProxies.has(endpoint) && selectedProxies.get(endpoint) !== key) throw failure(409, "所选账号使用同一代理地址但认证信息不同，请分开同步并核对代理绑定");
        selectedProxies.set(endpoint, key);
      }
      if (proxyUrl && !proxyCatalog) proxyCatalog = await proxies(target);
      let outboundProxy;
      try {
        outboundProxy = dynamic
          ? { ...matchProxy(proxyIdentity(proxyUrl), (proxyCatalog || []).filter((value) => value.id === dynamic.proxyId)), dynamicBindingId: dynamic.id, dynamicGeneration: dynamic.generation }
          : resolveCrsProxy(proxyUrl, proxyCatalog || []);
      }
      catch (error) { if (dynamic || !error.proxyMissing) throw error; }
      snapshots.push({ job, snapshot, settings, proxyUrl, loginProxyUrl: job.proxyUrl, outboundProxy });
    }
    assertCurrentTarget(target);
    // Validate all accounts before creating any missing remote proxy.
    const assertJobsCurrent = () => {
      for (const { job, loginProxyUrl } of snapshots) {
        const current = getJob(job.id);
        assertUploadAllowed(current);
        if (!current || current.deleted || current.proxyUrl !== loginProxyUrl) throw failure(409, "账号或登录代理已改变，请重新选择账号后推送");
      }
    };
    assertJobsCurrent();
    for (const item of snapshots) {
      const hash = crypto.createHash("sha256").update(JSON.stringify({ snapshot: item.snapshot, settings: item.settings, ...(item.outboundProxy ? { outboundProxy: item.outboundProxy } : {}) })).digest("hex");
      const unresolved = outbox.entries.filter((entry) => entry.jobId === item.job.id && entry.target.baseUrl === target.baseUrl && ["pending", "running", "unknown"].includes(entry.status));
      if (unresolved.some((entry) => entry.hash !== hash)) throw failure(409, "该账号已有未确认的 CRS 上传，请先等待或核对原上传结果");
    }
    for (const item of snapshots) {
      if (item.proxyUrl && !item.outboundProxy) item.outboundProxy = await ensureProxy(item.proxyUrl, target, assertJobsCurrent);
      else if (item.proxyUrl) {
        const sync = database.get("runtime", PROXY_SYNC_RECORD) || {};
        const key = proxySyncKey(item.proxyUrl, target);
        if (sync[key]) { delete sync[key]; database.put("runtime", PROXY_SYNC_RECORD, sync); }
      }
      item.hash = crypto.createHash("sha256").update(JSON.stringify({ snapshot: item.snapshot, settings: item.settings, ...(item.outboundProxy ? { outboundProxy: item.outboundProxy } : {}) })).digest("hex");
    }
    assertCurrentTarget(target); assertJobsCurrent();
    const additions = []; let skipped = ids.length - snapshots.length;
    for (const { job, snapshot, settings, outboundProxy, hash } of snapshots) {
      const existing = !scheduled && outbox.entries.find((entry) => entry.jobId === job.id && entry.hash === hash && entry.target.baseUrl === target.baseUrl && entry.status !== "canceled");
      if (existing) { skipped += 1; continue; }
      if (outbox.entries.some((entry) => entry.jobId === job.id && entry.target.baseUrl === target.baseUrl && ["pending", "running", "unknown"].includes(entry.status))) throw failure(409, "该账号已有未确认的 CRS 上传，请先等待或核对原上传结果");
      const timestamp = new Date().toISOString();
      additions.push({ id: crypto.randomUUID(), jobId: job.id, email: job.email, snapshot, settings, ...(outboundProxy ? { outboundProxy } : {}), ...(scheduled ? { scheduleItemId: scheduled.scheduleItemId, targetIdentity: scheduled.targetIdentity } : {}), hash, target: { ...target }, submissionId: crypto.randomUUID(), taskId: null, status: "pending", message: "等待上传 CRS", attempts: 0, canRetry: false, createdAt: timestamp, updatedAt: timestamp });
    }
    if (outbox.entries.length + additions.length > 2000 || Buffer.byteLength(JSON.stringify(outbox)) + Buffer.byteLength(JSON.stringify(additions)) > 32 * 1024 * 1024) throw failure(409, "CRS 上传记录已达到大小上限");
    outbox.entries.push(...additions);
    persist(); schedule();
    return { queued: additions.length, skipped, status: status() };
  }

  schedule();
  return {
    dynamicTarget: () => savedConfiguration()?.config.baseUrl || null,
    async dynamicRequest(endpoint, body) {
      if (!/^\/api\/admin\/(accounts|proxies)(?:[/?]|$)/.test(endpoint)) throw failure(400, "动态代理接口无效");
      const target = savedConfiguration()?.config;
      if (!target) throw failure(409, "请先配置 CRS 服务器");
      const response = await request(target, endpoint, body === undefined ? {} : { method: "POST", body: JSON.stringify(body) });
      assertCurrentTarget(target);
      return response.payload.data;
    },
    runtimeStatus: () => ({ pending: outbox.entries.filter((entry) => entry.status === "pending").length, running: outbox.entries.filter((entry) => entry.status === "running").length, workerActive: Boolean(workerPromise || controllers.size || pendingEnqueues) }),
    groups,
    accountSettings,
    saveAccountSettings,
    getConfiguration() { return publicConfiguration(savedConfiguration()); },
    putConfiguration(config, revision) {
      if (!Number.isSafeInteger(revision) || revision < 0) throw failure(400, "CRS 配置版本无效");
      const previous = savedConfiguration();
      if ((previous?.revision || 0) !== revision) return { conflict: true, ...publicConfiguration(previous) };
      const normalized = normalizeConfiguration(config, previous?.config);
      const saved = { config: normalized, revision: revision + 1 };
      database.put("runtime", CONFIG_RECORD, saved);
      sessions.clear();
      return { conflict: false, ...publicConfiguration(saved) };
    },
    async testConfiguration(draft) {
      const config = draft ? normalizeConfiguration(draft, savedConfiguration()?.config) : savedConfiguration()?.config;
      if (!config) throw failure(409, "请先填写 CRS 服务器配置");
      return checkConnection(config);
    },
    enqueue,
    enqueueScheduled,
    lookupScheduled,
    cancelScheduled,
    getTargetIdentity() { return targetIdentity(savedConfiguration()?.config); },
    async authorizationCompleted(job) {
      if (job.scheduleItemId || job.loginDeferred) return;
      if (!closed && savedConfiguration()?.config.autoUpload) {
        try { await enqueue([job.id], true); } catch (error) { lastError = safeMessage(error.message); }
      }
    },
    retry(ids) {
      if (closed) throw failure(503, "CRS 上传服务正在关闭");
      if (ids !== undefined && (!Array.isArray(ids) || !ids.length || ids.length > 500 || ids.some((id) => typeof id !== "string"))) throw failure(400, "重试账号列表无效");
      const selected = ids ? new Set(ids) : null;
      let queued = 0; let skipped = 0;
      const latest = new Map(outbox.entries.map((entry) => [entry.jobId, entry]));
      const config = savedConfiguration()?.config;
      for (const entry of latest.values()) {
        if (selected ? !selected.has(entry.jobId) : entry.status !== "failed") continue;
        if (!["failed", "unknown"].includes(entry.status)) continue;
        assertUploadAllowed(getJob(entry.jobId));
        if (!config || config.baseUrl !== entry.target.baseUrl || config.authType !== entry.target.authType || config.username !== entry.target.username) {
          throw failure(409, "CRS 目标或登录身份已改变，请恢复原目标后重试，旧上传不会转发到其他服务器");
        }
      }
      for (const entry of latest.values()) {
        if (selected && !selected.has(entry.jobId)) continue;
        const localJob = getJob(entry.jobId);
        if (!entry.taskId && (!localJob || localJob.deleted)) { skipped += 1; continue; }
        if (entry.status === "failed" && entry.canRetry && entry.taskId && entry.attempts < MAX_ATTEMPTS) entry.retryRemote = true;
        else if (entry.status === "unknown" && selected) { entry.reconcileOnly = Boolean(entry.taskId); entry.retryRemote = false; entry.attempts = 0; }
        else if (entry.status === "failed" && !entry.taskId) { entry.retryRemote = false; entry.attempts = 0; }
        else { skipped += 1; continue; }
        entry.target = { ...config };
        update(entry, "pending", "已请求手动重试 CRS 上传"); queued += 1;
      }
      schedule(); return { queued, skipped, status: status() };
    },
    status,
    async close() {
      closed = true;
      if (timer) { clearTimeout(timer); timer = null; }
      for (const controller of controllers) controller.abort();
      await enqueueTail;
      await workerPromise;
      sessions.clear();
    },
  };
}
