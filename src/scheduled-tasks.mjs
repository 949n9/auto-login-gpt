import crypto from "node:crypto";

const KIND = "scheduled-task";
const REQUEST = "scheduled-task-request";
const OWNER = "scheduled-account-owner";
const FINAL = new Set(["completed", "failed", "needs_attention", "canceled", "superseded"]);
const RELEASED = new Set(["completed", "failed", "canceled", "superseded"]);
const fail = (message, status = 400) => Object.assign(new Error(message), { status });
const emailKey = (value) => String(value || "").trim().toLowerCase();

export function normalizeSchedule(value = {}) {
  if (value.timeZone && value.timeZone !== "Asia/Shanghai") throw fail("计划时间必须使用北京时间 Asia/Shanghai");
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/.exec(String(value.scheduledLocal || ""));
  if (!match) throw fail("请填写北京时间日期和时间");
  const [year, month, day, hour, minute, second] = match.slice(1).map((part) => Number(part || 0));
  const localUtc = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  if (year < 2020 || year > 2100 || localUtc.getUTCFullYear() !== year || localUtc.getUTCMonth() !== month - 1
    || localUtc.getUTCDate() !== day || localUtc.getUTCHours() !== hour || localUtc.getUTCMinutes() !== minute || localUtc.getUTCSeconds() !== second) throw fail("计划日期时间无效");
  const duration = (name) => {
    const result = value[name] ?? 30;
    if (!Number.isInteger(result) || result < 0 || result > 1440) throw fail("提前准备和登出等待时间必须为 0 至 1440 分钟");
    return result;
  };
  const prepareLeadMinutes = duration("prepareLeadMinutes");
  const postLogoutDelayMinutes = duration("postLogoutDelayMinutes");
  const securityAction = value.securityAction || null;
  if (securityAction && !["rotate-totp", "logout-all", "rotate-totp-logout-all"].includes(securityAction)) throw fail("计划安全操作无效");
  const settings = value.crsSettings || {};
  const concurrencyLimit = settings.concurrencyLimit ?? 20;
  const weight = settings.weight ?? 99;
  if (!Number.isSafeInteger(concurrencyLimit) || concurrencyLimit < 1 || concurrencyLimit > 4294967295) throw fail("CPR 账号并发必须是正整数");
  if (!Number.isInteger(weight) || weight < 1 || weight > 100) throw fail("CPR 优先级必须为 1 至 100");
  if (settings.credentialGuardian !== undefined && typeof settings.credentialGuardian?.enabled !== "boolean") throw fail("401 重登设置无效");
  if (settings.groupIds !== undefined && (!Array.isArray(settings.groupIds) || !settings.groupIds.length || settings.groupIds.some((id) => typeof id !== "string" || !id))) throw fail("CPR 分组设置无效");
  const plannedAt = new Date(localUtc.getTime() - 8 * 60 * 60_000).toISOString();
  return { timeZone: "Asia/Shanghai", scheduledLocal: localUtc.toISOString().slice(0, 19), plannedAt,
    prepareAt: new Date(Date.parse(plannedAt) - prepareLeadMinutes * 60_000).toISOString(),
    prepareLeadMinutes, postLogoutDelayMinutes, securityAction,
    crsSettings: { concurrencyLimit, weight, credentialGuardian: { enabled: settings.credentialGuardian?.enabled !== false }, ...(settings.groupIds ? { groupIds: [...new Set(settings.groupIds)] } : {}) } };
}

export function publicScheduleItem(item) {
  return Object.fromEntries(["id", "email", "jobId", "line", "status", "phase", "plannedAt", "prepareAt", "loginNotBefore", "logoutAcceptedAt",
    "attempts", "securityOperationId", "createdAt", "updatedAt", "completedAt", "error", "crs", "cancelRequestedAt"].filter((key) => item[key] !== undefined).map((key) => [key, item[key]]));
}

export function publicSchedule(schedule) {
  const counts = {};
  for (const item of schedule.items) counts[item.status] = (counts[item.status] || 0) + 1;
  const statuses = schedule.items.map((item) => item.status);
  const status = statuses.some((value) => !FINAL.has(value))
    ? statuses.every((value) => value === "scheduled") ? "scheduled" : "running"
    : statuses.every((value) => value === "completed") ? "completed"
      : statuses.some((value) => value === "needs_attention") ? "needs_attention"
        : statuses.every((value) => value === "canceled" || value === "superseded") ? "canceled"
          : statuses.some((value) => value === "completed") ? "partial" : "failed";
  const result = Object.fromEntries(["id", "createdAt", "updatedAt", "plannedAt", "prepareAt", "scheduledLocal", "timeZone", "prepareLeadMinutes", "postLogoutDelayMinutes", "securityAction", "crsSettings"].map((key) => [key, schedule[key]]));
  return { ...result, status, counts, total: schedule.items.length };
}

export function createScheduledTaskStore(database, { now = () => Date.now() } = {}) {
  const timestamp = () => new Date(now()).toISOString();
  const read = (id) => database.get(KIND, id);
  const list = () => database.recordIds(KIND).map(read).filter(Boolean).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  function owner(email) {
    const value = database.get(OWNER, emailKey(email));
    if (!value) return null;
    const schedule = read(value.scheduleId);
    const item = schedule?.items.find((candidate) => candidate.id === value.itemId);
    return item && !RELEASED.has(item.status) ? { schedule, item } : null;
  }
  function request(clientRequestId, fingerprint) {
    if (!/^[a-zA-Z0-9_-]{8,128}$/.test(String(clientRequestId || ""))) throw fail("clientRequestId 必须是唯一请求编号");
    const value = database.get(REQUEST, clientRequestId);
    if (!value) return null;
    if (value.fingerprint !== fingerprint) throw fail("同一请求编号已用于不同的计划，请重新确认", 409);
    return read(value.scheduleId);
  }
  function updateItem(scheduleId, itemId, changes) {
    return database.transaction(() => {
      const schedule = read(scheduleId);
      const item = schedule?.items.find((candidate) => candidate.id === itemId);
      if (!item) throw fail("计划账号不存在", 404);
      Object.assign(item, changes, { id: item.id, email: item.email, updatedAt: timestamp() });
      if (FINAL.has(item.status)) item.completedAt ||= timestamp();
      schedule.updatedAt = timestamp();
      database.put(KIND, schedule.id, schedule);
      if (RELEASED.has(item.status)) {
        const current = database.get(OWNER, emailKey(item.email));
        if (current?.itemId === item.id) database.remove(OWNER, emailKey(item.email));
      }
      return item;
    });
  }
  return { read, list, owner, request, updateItem,
    create({ clientRequestId, fingerprint, config, targetIdentity, accounts, persistAccounts }) {
      return database.transaction(() => {
        const existing = request(clientRequestId, fingerprint);
        if (existing) return existing;
        const emails = accounts.map((account) => emailKey(account.email));
        if (new Set(emails).size !== emails.length) throw fail("同一计划不能重复填写邮箱", 409);
        for (const account of accounts) if (owner(account.email)) throw fail(`${account.email} 已有未结束的定时任务`, 409);
        const createdAt = timestamp();
        const id = crypto.randomUUID();
        const items = accounts.map((account) => ({ ...account, id: crypto.randomUUID(), scheduleId: id,
          status: "scheduled", phase: "waiting_prepare", plannedAt: config.plannedAt, prepareAt: config.prepareAt,
          loginNotBefore: config.plannedAt, attempts: 0, createdAt, updatedAt: createdAt, error: null }));
        const value = { version: 1, id, clientRequestId, ...config, targetIdentity, items, createdAt, updatedAt: createdAt };
        persistAccounts?.(value);
        database.put(KIND, id, value);
        database.put(REQUEST, clientRequestId, { fingerprint, scheduleId: id });
        for (const item of items) database.put(OWNER, emailKey(item.email), { scheduleId: id, itemId: item.id });
        return value;
      });
    },
  };
}

// The clock only advances persisted intentions. Security requests are never
// replayed after a restart; login and upload results must belong to this item.
export function createScheduledTaskEngine({ store, hooks, now = () => Date.now(), intervalMs = 1000 }) {
  let timer = null, running = null, closed = false;
  const change = (schedule, item, value) => {
    const updated = store.updateItem(schedule.id, item.id, value);
    hooks.updated?.(updated);
    return updated;
  };
  const errorText = (error) => hooks.safeError?.(error?.message || String(error)) || String(error?.message || error).slice(0, 500);
  async function processItem(schedule, original) {
    let item = store.read(schedule.id)?.items.find((value) => value.id === original.id);
    if (!item || FINAL.has(item.status) || closed || hooks.paused?.()) return;
    const job = hooks.getJob(item.jobId);
    if (!job || job.deleted) { change(schedule, item, { status: "failed", error: "账号已删除，计划已停止" }); return; }
    if (item.cancelRequestedAt) { await cancelItem(schedule, item); return; }
    if (item.status === "scheduled") {
      if (now() < Date.parse(schedule.securityAction ? item.prepareAt : item.plannedAt)) return;
      if (!hooks.canStart(job)) return;
      if (schedule.securityAction) {
        const operationId = crypto.randomUUID();
        item = change(schedule, item, { status: "preparing", phase: "security", securityOperationId: operationId });
        await hooks.startSecurity(schedule, item, operationId);
        return;
      }
      item = change(schedule, item, { status: "waiting", phase: "waiting_login" });
    }
    if (item.status === "preparing") {
      const operation = hooks.readSecurity(item.securityOperationId);
      if (!operation) { change(schedule, item, { status: "needs_attention", error: "安全准备启动被中断，未自动重做，请核实" }); return; }
      if (["queued", "running"].includes(operation.status)) return;
      if (operation.status !== "completed") { change(schedule, item, { status: operation.status === "needs_attention" ? "needs_attention" : "failed", error: operation.error || "安全准备未完成，计划未继续登录" }); return; }
      let logoutAcceptedAt = null;
      if (schedule.securityAction !== "rotate-totp") {
        logoutAcceptedAt = operation.result?.logoutAcceptedAt;
        if (!operation.result?.logout_accepted || !Number.isFinite(Date.parse(logoutAcceptedAt))) { change(schedule, item, { status: "needs_attention", error: "缺少已确认登出时间，未开始计划登录" }); return; }
      }
      const loginNotBefore = new Date(Math.max(Date.parse(item.plannedAt), logoutAcceptedAt ? Date.parse(logoutAcceptedAt) + schedule.postLogoutDelayMinutes * 60_000 : 0)).toISOString();
      item = change(schedule, item, { status: "waiting", phase: "waiting_login", logoutAcceptedAt, loginNotBefore });
    }
    if (item.status === "waiting") {
      if (now() < Date.parse(item.loginNotBefore) || !hooks.canStart(job)) return;
      const loginAttemptId = crypto.randomUUID();
      item = change(schedule, item, { status: "login_queued", phase: "login", loginAttemptId, attempts: item.attempts + 1 });
      await hooks.startLogin(schedule, item, loginAttemptId);
      return;
    }
    if (["login_queued", "logging_in"].includes(item.status)) {
      const state = hooks.loginState(item, job);
      if (Number.isInteger(state.attempts) && state.attempts > item.attempts) item = change(schedule, item, { attempts: state.attempts });
      if (state.status === "completed") item = change(schedule, item, { status: "publishing", phase: "publish" });
      else if (state.status === "failed") { change(schedule, item, { status: "failed", error: state.error || "计划登录失败" }); return; }
      else { if (state.status === "running" && item.status !== "logging_in") change(schedule, item, { status: "logging_in" }); return; }
    }
    if (item.status === "publishing") {
      let result = hooks.lookupPublish(item);
      if (!result) result = await hooks.publish(schedule, item);
      const crs = { status: result.status, message: result.message || null, accountIds: result.accountIds || [] };
      if (result.status === "succeeded") change(schedule, item, { status: "completed", phase: "done", crs, outboxEntryId: result.entryId });
      else if (result.status === "unknown") change(schedule, item, { status: "needs_attention", crs, outboxEntryId: result.entryId, error: result.message || "CPR 推送结果未知，未自动重传" });
      else if (["failed", "canceled"].includes(result.status)) change(schedule, item, { status: result.status, crs, outboxEntryId: result.entryId, error: result.message || "CPR 推送未完成" });
      else change(schedule, item, { crs, outboxEntryId: result.entryId });
    }
  }
  async function cancelItem(schedule, item) {
    if (FINAL.has(item.status)) return item;
    const remote = hooks.lookupPublish(item);
    if (remote) {
      const result = await hooks.cancelPublish(item);
      if (result && !["canceled", "failed"].includes(result.status)) {
        return change(schedule, item, { status: result.status === "succeeded" ? "completed" : "needs_attention", error: "CPR 推送已提交，取消无法撤销远端操作，请核实结果", crs: { status: result.status, message: result.message, accountIds: result.accountIds || [] } });
      }
    }
    await hooks.cancelJob(item);
    const operation = item.securityOperationId && hooks.readSecurity(item.securityOperationId);
    return change(schedule, item, { status: operation?.status === "needs_attention" ? "needs_attention" : "canceled", error: operation?.status === "needs_attention" ? operation.error || "已取消，但安全变更结果仍需核实" : null });
  }
  async function tick() {
    if (running || closed || hooks.paused?.()) return running;
    running = (async () => {
      for (const schedule of store.list()) for (const item of schedule.items) {
        if (closed || hooks.paused?.()) return;
        if (FINAL.has(item.status)) continue;
        await hooks.withLock(item.email, async () => {
          try { await processItem(schedule, item); }
          catch (error) {
            const latest = store.read(schedule.id)?.items.find((value) => value.id === item.id);
            if (!latest || FINAL.has(latest.status)) return;
            change(schedule, latest, { status: ["preparing", "publishing"].includes(latest.status) ? "needs_attention" : "failed", error: errorText(error) });
          }
        });
      }
    })().finally(() => { running = null; });
    return running;
  }
  return { tick,
    start() { if (!timer && !closed) { timer = setInterval(() => void tick(), intervalMs); timer.unref?.(); void tick(); } },
    async close() { closed = true; clearInterval(timer); timer = null; await running; },
    active: () => Boolean(running),
    async cancel(scheduleId, itemIds) {
      const schedule = store.read(scheduleId);
      if (!schedule) throw fail("计划不存在", 404);
      if (itemIds !== undefined && (!Array.isArray(itemIds) || !itemIds.length || itemIds.some((id) => !schedule.items.some((item) => item.id === id)))) throw fail("取消账号列表无效");
      for (const item of schedule.items.filter((value) => !itemIds || itemIds.includes(value.id))) {
        await hooks.withLock(item.email, async () => {
          const current = store.read(scheduleId).items.find((value) => value.id === item.id);
          if (FINAL.has(current.status)) return;
          const marked = change(schedule, current, { cancelRequestedAt: new Date(now()).toISOString() });
          await cancelItem(schedule, marked);
        });
      }
      return store.read(scheduleId);
    },
  };
}
