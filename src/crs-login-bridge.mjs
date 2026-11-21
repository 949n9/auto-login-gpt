import crypto from "node:crypto";

const KIND = "crs-login-operation";
const INDEX = "crs-login-operation-index";
const error = (status, message) => Object.assign(new Error(message), { status });
const operationPattern = /^[A-Za-z0-9][A-Za-z0-9:_-]{0,127}$/;

export function authenticateBridge(header, secret) {
  if (typeof secret !== "string" || !secret) throw error(503, "CRS 登录桥接未配置");
  const supplied = typeof header === "string" && /^Bearer [^\s]+$/.test(header) ? header.slice(7) : "";
  if (!supplied || !crypto.timingSafeEqual(crypto.createHash("sha256").update(supplied).digest(), crypto.createHash("sha256").update(secret).digest())) throw error(401, "CRS 登录桥接认证失败");
}

export function validateBridgeInput(input) {
  if (!input || typeof input !== "object" || Array.isArray(input) || Object.keys(input).some((key) => !["operationId", "email", "password", "totpSecret", "proxyUrl"].includes(key))) throw error(400, "登录请求格式无效");
  if (typeof input.operationId !== "string" || !operationPattern.test(input.operationId)) throw error(400, "operationId 格式无效");
  if (typeof input.email !== "string" || input.email.length > 320 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input.email.trim())) throw error(400, "邮箱格式无效");
  const normalized = { operationId: input.operationId, email: input.email.trim().toLowerCase() };
  for (const field of ["password", "totpSecret"]) {
    if (!Object.hasOwn(input, field)) continue;
    if (field === "totpSecret" && input[field] === "") continue;
    if (typeof input[field] !== "string" || !input[field] || input[field].length > (field === "password" ? 4096 : 256)) throw error(400, "登录材料格式无效");
    normalized[field] = input[field];
  }
  if (Object.hasOwn(input, "proxyUrl")) {
    if (input.proxyUrl === "") normalized.proxyUrl = "";
    else if (input.proxyUrl !== null) {
      if (typeof input.proxyUrl !== "string" || !input.proxyUrl.trim() || input.proxyUrl.length > 4096) throw error(400, "代理地址格式无效");
      let url;
      try { url = new URL(input.proxyUrl); } catch { throw error(400, "代理地址格式无效"); }
      if (!["http:", "https:", "socks5:", "socks5h:"].includes(url.protocol) || !url.hostname || url.search || url.hash) throw error(400, "代理地址格式无效");
      normalized.proxyUrl = url.toString();
    } else normalized.proxyUrl = null;
  }
  return normalized;
}

// Persist the operation before starting work. Uncertain starts never silently replay.
export function createCrsLoginBridge({ database, start, inspect, readCredentials, isRetrying = () => false, now = Date.now, resultTtlMs = 24 * 60 * 60_000, maxOperations = 10000, maxResultBytes = 32 * 1024, maxTotalResultBytes = 64 * 1024 * 1024 }) {
  const pending = new Map();
  const index = database.get("runtime", INDEX) || {};
  let closed = false;
  function saveIndex() { database.put("runtime", INDEX, index); }
  function cleanup() {
    if (closed) return;
    let changed = false;
    for (const [id, item] of Object.entries(index)) {
      if (!item.expiresAt || item.expiresAt > now()) continue;
      const value = database.get(KIND, id);
      if (value) {
        delete value.credentials;
        delete value.email;
        fail(value, "登录结果已过期，请使用新的 operationId 发起操作");
      }
      index[id] = { expiresAt: null, bytes: 0 };
      changed = true;
    }
    if (changed) saveIndex();
  }
  function record(id) {
    if (!operationPattern.test(id)) throw error(400, "operationId 格式无效");
    const value = database.get(KIND, id);
    if (!value) throw error(404, "登录任务不存在");
    return value;
  }
  function save(value) { database.put(KIND, value.operationId, value); }
  function fail(value, message) { value.status = "failed"; value.error = message; save(value); return value; }
  async function get(id) {
    cleanup();
    const value = record(id);
    if (!["succeeded", "failed"].includes(value.status)) {
      // A bound existing job still has its previous generation until start finishes.
      if (pending.has(id)) return { jobId: value.jobId || null, status: "pending" };
      if (!value.jobId) {
        if (!pending.has(id)) fail(value, "登录任务启动被中断，请重新发起操作");
      } else {
        const job = inspect(value.jobId);
        if (!job || job.deleted || job.crsBridgeOperationId !== id) fail(value, "登录任务已取消或被后续操作替代");
        else if (job.status === "completed") {
          const credentials = await readCredentials(job);
          if (["succeeded", "failed"].includes(record(id).status)) return get(id);
          if (inspect(value.jobId) !== job || job.deleted || job.crsBridgeOperationId !== id || job.status !== "completed") fail(value, "登录任务已取消或被后续操作替代");
          else if (!credentials || typeof credentials.access_token !== "string" || !credentials.access_token || typeof credentials.refresh_token !== "string" || !credentials.refresh_token || (credentials.email && (typeof credentials.email !== "string" || credentials.email.trim().toLowerCase() !== value.email))) fail(value, "登录结果未通过账号校验");
          else {
            value.credentials = Object.fromEntries(["access_token", "refresh_token", "id_token", "email"].filter((key) => typeof credentials[key] === "string").map((key) => [key, credentials[key]]));
            const bytes = Buffer.byteLength(JSON.stringify(value.credentials));
            if (bytes > maxResultBytes || Object.entries(index).reduce((sum, [key, item]) => sum + (key === id ? 0 : item.bytes || 0), bytes) > maxTotalResultBytes) {
              delete value.credentials;
              fail(value, "登录结果超过桥接存储容量，请检查工具中的任务状态");
            } else {
              index[id] = { expiresAt: now() + resultTtlMs, bytes };
              saveIndex();
              value.status = "succeeded";
              save(value);
            }
          }
        } else if (isRetrying(job)) value.status = "running";
        else if (["failed", "canceled", "reauth_required", "resume_available"].includes(job.status)) fail(value, "重新登录未完成，请检查工具中的任务状态");
        else value.status = job.status === "queued" ? "pending" : "running";
      }
    }
    return { jobId: value.jobId || null, status: value.status === "starting" ? "pending" : value.status, ...(value.status === "succeeded" ? { credentials: value.credentials } : {}), ...(value.status === "failed" ? { error: value.error } : {}) };
  }
  async function submit(raw) {
    if (closed) throw error(503, "CRS 登录桥接正在关闭");
    cleanup();
    const input = validateBridgeInput(raw);
    const fingerprint = crypto.createHash("sha256").update(JSON.stringify(input)).digest("hex");
    const existing = database.get(KIND, input.operationId);
    if (existing) {
      if (existing.fingerprint !== fingerprint) throw error(409, "operationId 已用于不同的登录请求");
      await pending.get(input.operationId);
      return get(input.operationId);
    }
    if (Object.hasOwn(index, input.operationId)) throw error(409, "登录任务记录不完整，请使用新的 operationId");
    if (Object.keys(index).length >= maxOperations) throw error(503, "登录桥接操作记录已达到容量上限");
    index[input.operationId] = { expiresAt: null, bytes: 0 };
    saveIndex();
    const value = { operationId: input.operationId, email: input.email, fingerprint, status: "starting", createdAt: new Date(now()).toISOString() };
    save(value);
    const operation = Promise.resolve().then(async () => {
      try {
        await start(input, (jobId) => { value.jobId = jobId; value.status = "pending"; save(value); });
      } catch {
        fail(value, "无法开始登录，请检查已保存的登录材料及任务状态");
      }
    });
    pending.set(input.operationId, operation);
    try { await operation; } finally { pending.delete(input.operationId); }
    return get(input.operationId);
  }
  cleanup();
  const cleanupTimer = setInterval(cleanup, 60_000);
  cleanupTimer.unref?.();
  return { submit, get, cleanup, close() { closed = true; clearInterval(cleanupTimer); }, complete: (job) => job.crsBridgeOperationId ? get(job.crsBridgeOperationId) : null, activeStarts: () => pending.size };
}
