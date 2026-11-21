import crypto from "node:crypto";

const KIND = "dynamic-proxy";
const PROFILE_KIND = "dynamic-proxy-profile";
const failure = (status, message) => Object.assign(new Error(message), { status });
const identifier = (value) => typeof value === "string" && /^[a-zA-Z0-9_-]{1,128}$/.test(value);
const accountKey = (email) => {
  if (typeof email !== "string" || email.length > 320 || !/^[^\s@]+@[^\s@]+$/.test(email)) throw failure(400, "账号邮箱无效");
  return email.trim().toLowerCase();
};

export function validateDynamicProfile(input, previous = {}) {
  if (!input || typeof input !== "object" || !identifier(input.id)) throw failure(400, "动态代理配置编号无效");
  const key = input.key === undefined ? previous.key : input.key;
  if (typeof key !== "string" || !key.trim() || key.length > 2048 || /[\s\x00-\x1f]/.test(key)) throw failure(400, "请输入供应商密钥");
  if (!["http", "https", "socks5h"].includes(input.protocol)) throw failure(400, "请选择实际代理协议");
  if (!/^[A-Za-z]{2}$/.test(input.country || "")) throw failure(400, "国家需使用两位代码");
  for (const field of ["state", "city", "ips"]) if (typeof (input[field] || "") !== "string" || (input[field] || "").length > 256 || /[\r\n]/.test(input[field] || "")) throw failure(400, "地区或白名单格式无效");
  return { id: input.id, name: String(input.name || "动态住宅代理").slice(0, 80), key, protocol: input.protocol, country: input.country.toUpperCase(), state: input.state || "", city: input.city || "", ips: input.ips || "", enabled: input.enabled === true };
}

// 固定请求纯文本 type=2，仅接受单条凭据，不猜测未知 JSON 错误或过期时间
export function parseExtractedProxy(body, protocol) {
  if (typeof body !== "string" || body.length > 4096) throw failure(502, "供应商响应格式无法确认，停止自动提取");
  const match = /^([a-zA-Z0-9.-]+):(\d{1,5}):([^:\r\n\s]+):([^\r\n\s]+)$/.exec(body.trim());
  if (!match || Number(match[2]) < 1 || Number(match[2]) > 65535 || !["http", "https", "socks5h"].includes(protocol)) throw failure(502, "供应商响应格式无法确认，停止自动提取");
  const url = new URL(`${protocol}://${match[1]}:${match[2]}`);
  url.username = encodeURIComponent(match[3]); url.password = encodeURIComponent(match[4]);
  return url.toString();
}

export function create1024Extractor({ fetchImpl = fetch, allowExtraction = false } = {}) {
  return async (profile) => {
    if (!allowExtraction) throw failure(409, "真实代理提取未启用");
    const url = new URL("https://apisocks.1024proxy.com/api/getIpInfo");
    for (const [name, value] of Object.entries({ key: profile.key, port: "443", num: "1", country: profile.country, state: profile.state, city: profile.city, type: "2", format: "n", ips: profile.ips })) if (value) url.searchParams.set(name, value);
    const response = await fetchImpl(url, { redirect: "error", signal: AbortSignal.timeout(20000) });
    if (!response.ok || Number(response.headers.get("content-length") || 0) > 4096) { await response.body?.cancel(); throw failure(502, "供应商提取结果无法确认"); }
    const reader = response.body?.getReader();
    if (!reader) throw failure(502, "供应商提取结果为空");
    let bytes = 0; const chunks = [];
    try {
      while (true) { const { done, value } = await reader.read(); if (done) break; bytes += value.length; if (bytes > 4096) { await reader.cancel(); throw failure(502, "供应商响应过大"); } chunks.push(Buffer.from(value)); }
    } finally { reader.releaseLock(); }
    return parseExtractedProxy(Buffer.concat(chunks).toString("utf8"), profile.protocol);
  };
}

// 提取账本使用同一加密数据库事务 CAS，进程退出后 sent 状态永不自动重发
export function createDynamicProxies({ database, crs, extract, probe, synchronize, now = Date.now, allowExtraction = false }) {
  const pending = new Map();
  const refreshing = new Map();
  let closed = false;
  const read = (email) => database.get(KIND, accountKey(email));
  const write = (record) => database.put(KIND, record.email, record);
  const mutate = (email, operation) => database.transaction(() => {
    const record = read(email);
    if (!record) throw failure(404, "账号未绑定动态代理");
    const result = operation(record);
    record.revision += 1; write(record); return result === undefined ? record : result;
  });
  const update = (record, operation) => mutate(record.email, (value) => {
    if (value.revision !== record.revision) throw failure(409, "代理状态已变化，请重试");
    operation(value);
  });
  const profileView = ({ key: _key, ...profile }) => ({ ...profile, hasKey: true });
  function publicBinding(record) {
    if (!record) return null;
    const { proxyUrl: _url, candidateUrl: _candidate, ...view } = record;
    return view;
  }
  function profile(id) {
    const value = database.get(PROFILE_KIND, id);
    if (!value) throw failure(404, "动态代理配置不存在");
    return value;
  }
  function checkOpen() { if (closed) throw failure(503, "动态代理服务正在关闭"); }
  function checkPublishing(record) {
    checkOpen();
    if (!profile(record.profileId).enabled) throw failure(409, "动态代理配置已暂停");
  }
  function beginOperation(record, candidateUrl = null) {
    return update(record, (value) => {
      // 先落盘操作编号，再隔离 CRS；响应丢失后仍能认领同一次恢复
      if (!value.operationId) {
        value.operationId = value.accountId ? crypto.randomUUID() : value.id;
        value.gate ||= { operationId: value.operationId };
      }
      value.candidateUrl = candidateUrl;
      value.status = candidateUrl ? "candidate" : "empty";
    });
  }
  async function isolate(record, intent) {
    checkPublishing(record);
    const gate = await crs.isolate(record, intent);
    const updated = update(record, (value) => { value.gate = gate; });
    await synchronize(updated, { phase: "isolate", intent });
    return updated;
  }
  async function eligibility(record, intent) {
    const state = await crs.eligibility(record, intent);
    const blockedReason = state?.allowed === true ? null : state?.message || "账号当前不允许续换代理";
    if ((record.blockedReason || null) !== blockedReason) {
      const updated = mutate(record.email, (value) => {
        if (value.revision !== record.revision) throw failure(409, "代理状态已变化，请重试");
        value.blockedReason = blockedReason;
      });
      Object.assign(record, updated);
    }
    if (blockedReason) throw failure(409, blockedReason);
    return state;
  }
  function saveProfile(input, expectedRevision) {
    checkOpen();
    return database.transaction(() => {
      const previous = database.get(PROFILE_KIND, input?.id);
      if ((previous?.revision || 0) !== expectedRevision) throw failure(409, "动态代理配置已变化，请刷新后重试");
      const value = { ...validateDynamicProfile(input, previous), revision: expectedRevision + 1 };
      database.put(PROFILE_KIND, value.id, value);
      return profileView(value);
    });
  }
  function bind(email, profileId, initial = {}) {
    checkOpen(); profile(profileId); email = accountKey(email);
    return database.transaction(() => {
      const current = read(email);
      if (current) {
        if (current.profileId !== profileId) throw failure(409, "账号已有动态代理绑定");
        return publicBinding(current);
      }
      const value = { id: crypto.randomUUID(), email, profileId, revision: 1, generation: initial.proxyUrl ? 1 : 0, status: initial.proxyUrl ? "ready" : "empty", target: initial.target, extractionCount: 0, operationId: null, proxyUrl: initial.proxyUrl || null, candidateUrl: null, proxyId: initial.proxyId || null, accountId: initial.accountId || null, retryAt: 0, updatedAt: now() };
      write(value); return publicBinding(value);
    });
  }
  async function ensure(email, intent = "login") {
    checkOpen(); email = accountKey(email);
    if (refreshing.has(email)) await refreshing.get(email);
    if (!["login", "business"].includes(intent)) throw failure(400, "代理使用目的无效");
    if (pending.has(email)) return pending.get(email);
    const operation = Promise.resolve().then(() => run(email, intent));
    pending.set(email, operation);
    try { return await operation; } finally { pending.delete(email); }
  }
  async function refreshManualSelection(email) {
    checkOpen(); email = accountKey(email);
    if (refreshing.has(email)) return refreshing.get(email);
    const operation = Promise.resolve().then(async () => {
      // 等待已发送的提取落账，不能丢弃迟到结果，也不能与旧发布交错写入登录凭据
      await pending.get(email)?.catch(() => {});
      const record = read(email);
      if (!record) return false;
      const selected = await crs.manualSelection(record);
      if (!selected) return false;
      await synchronize({ ...record, ...selected }, { phase: "manual", intent: "business" });
      database.transaction(() => {
        const current = read(email);
        if (!current || current.id !== record.id || current.revision !== record.revision) throw failure(409, "代理状态已变化，请重新同步");
        database.put("dynamic-proxy-archive", record.id, { ...record, detachedAt: now(), reason: "manual_proxy_selection", replacementProxyId: selected.proxyId });
        database.remove(KIND, email);
      });
      return true;
    });
    refreshing.set(email, operation);
    try { return await operation; } finally { refreshing.delete(email); }
  }
  async function run(email, intent) {
    checkOpen();
    let record = read(email);
    if (!record) throw failure(404, "账号未绑定动态代理");
    const eligibilityResult = await eligibility(record, intent);
    if (eligibilityResult.accountId && !record.accountId) {
      record = update(record, (value) => { value.accountId = eligibilityResult.accountId; value.proxyId = eligibilityResult.proxyId; if (eligibilityResult.verifying && !value.candidateUrl) value.status = "verifying"; });
    }
    if (record.status === "unknown" || record.status === "sent") throw failure(409, "上次提取结果未知，请核对供应商记录");
    if (record.status === "verifying") {
      const status = await crs.recoveryStatus(record);
      if (status !== "ready") {
        if (status === "degraded") throw failure(409, "账号已降智停用");
        if (await probe(record.proxyUrl) || await probe(record.proxyUrl)) throw failure(409, "新代理等待额度与质量检查");
        record = update(record, (value) => { value.status = "empty"; });
      }
      if (status === "ready") record = update(record, (value) => { value.status = "ready"; });
    }
    if (record.status === "ready" && await probe(record.proxyUrl)) {
      await eligibility(record, intent);
      if (!record.gate || record.operationId) {
        // 接管已有登录代理也要在 CRS 核对并提交完整地址，不能只认同一网关端口
        record = beginOperation(record, record.proxyUrl);
        return publish(record, intent);
      }
      await synchronize(record, { phase: "use", intent });
      return { bindingId: record.id, generation: record.generation, proxyUrl: record.proxyUrl, proxyId: record.proxyId };
    }
    if (record.retryAt > now()) throw failure(409, "代理恢复正在退避，请等待下一次使用");
    const configuration = profile(record.profileId);
    if (!configuration.enabled) throw failure(409, "动态代理配置已暂停");
    // 新代理已持久化时仅重试发布，不能因同步失败再次消费
    if (record.candidateUrl && record.status !== "unreachable") return publish(record, intent);
    if (record.status === "unreachable") {
      if (await probe(record.candidateUrl)) return publish(record, intent);
      record = update(record, (value) => { value.candidateUrl = null; value.status = "empty"; });
    }
    if (!allowExtraction) throw failure(409, "动态代理提取未启用");
    if (record.status === "ready" && await probe(record.proxyUrl)) return run(email, intent);
    const beforeExtraction = await eligibility(record, intent);
    if (beforeExtraction.canExtract === false) throw failure(409, "账号额度尚未确认可用，停止续换");
    record = beginOperation(record);
    record = await isolate(record, intent);
    await eligibility(record, intent);
    checkPublishing(record);
    record = update(record, (value) => {
      value.status = "sent";
      value.extractionCount += 1; value.updatedAt = now();
    });
    let proxyUrl;
    try { proxyUrl = await extract(profile(record.profileId)); }
    catch {
      update(record, (value) => { value.status = "unknown"; value.updatedAt = now(); });
      throw failure(502, "提取结果未知，已停止自动重试，请核对供应商记录");
    }
    record = update(record, (value) => { value.candidateUrl = proxyUrl; value.status = "candidate"; value.updatedAt = now(); });
    return publish(record, intent);
  }
  async function publish(record, intent) {
    checkPublishing(record);
    await eligibility(record, intent);
    record = await isolate(record, intent);
    if (!await probe(record.candidateUrl)) {
      update(record, (value) => { value.status = "unreachable"; value.retryAt = now() + 60000; });
      throw failure(502, "新代理连接检查未通过");
    }
    // 两边均保持隔离，先同步上号器，再由 CRS 原子切换并进入质量验证
    await synchronize({ ...record, proxyUrl: record.candidateUrl, generation: record.generation + 1 }, { phase: "publish", intent });
    await eligibility(record, intent);
    checkPublishing(record);
    const result = await crs.publish(record, intent);
    const updated = update(record, (value) => {
      value.proxyUrl = value.candidateUrl; value.candidateUrl = null; value.generation += 1;
      value.proxyId = result.proxyId; value.accountId = result.accountId || null; value.operationId = null;
      value.status = result.requiresVerification ? "verifying" : "ready";
      value.retryAt = 0; value.updatedAt = now();
    });
    if (updated.status === "verifying") throw failure(409, "新代理等待额度与质量检查");
    return { bindingId: updated.id, generation: updated.generation, proxyUrl: updated.proxyUrl, proxyId: updated.proxyId };
  }
  return {
    saveProfile, bind, ensure, refreshManualSelection, activeOperations: () => pending.size + refreshing.size,
    acknowledgeDemand(email, requestedAt) { mutate(email, (value) => { value.consumedDemandAt = requestedAt; }); },
    reconcile(email, proxyUrl, expectedRevision) {
      checkOpen();
      if (pending.has(accountKey(email))) throw failure(409, "提取仍在处理中，请等待结果后核对");
      return publicBinding(mutate(email, (value) => {
        if (value.revision !== expectedRevision) throw failure(409, "代理状态已变化，请刷新后核对");
        if (!["sent", "unknown"].includes(value.status)) throw failure(409, "该账号没有待核对的提取");
        if (value.status === "sent" && now() - value.updatedAt < 60000) throw failure(409, "提取仍可能在处理中，请稍后核对");
        if (proxyUrl) {
          let url; try { url = new URL(proxyUrl); } catch { throw failure(400, "代理地址无效"); }
          if (!["http:", "https:", "socks5h:"].includes(url.protocol) || !url.hostname || !url.port || url.search || url.hash || !["", "/"].includes(url.pathname)) throw failure(400, "代理地址无效");
          value.candidateUrl = url.href; value.status = "candidate";
        } else { value.status = "empty"; value.retryAt = now() + 60000; }
      }));
    },
    profiles: () => database.recordIds(PROFILE_KIND).map((id) => profileView(profile(id))),
    bindings: () => database.recordIds(KIND).map((email) => publicBinding(read(email))),
    binding: (email) => publicBinding(read(email)),
    managedBinding(email) {
      email = accountKey(email);
      const current = read(email);
      if (current) return publicBinding(current);
      const previous = database.recordIds("dynamic-proxy-archive").map((id) => database.get("dynamic-proxy-archive", id))
        .filter((record) => record.email === email).sort((a, b) => b.detachedAt - a.detachedAt)[0];
      return previous ? publicBinding({ ...previous, proxyId: null }) : null;
    },
    async close() { closed = true; await Promise.allSettled([...pending.values(), ...refreshing.values()]); },
  };
}
