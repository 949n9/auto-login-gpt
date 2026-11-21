import crypto from "node:crypto";

export const SECURITY_ACTIONS = new Set(["rotate-totp", "logout-all", "rotate-totp-logout-all"]);
const STAGES = new Set(["prepared", "disable_requested", "old_disabled", "enrollment_requested", "enrolled", "activation_requested", "activated", "verified", "work_reset_requested", "work_reset_confirmed", "logout_requested"]);
const STATUSES = new Set(["queued", "running", "completed", "failed", "needs_attention", "canceled"]);
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;

export function isSecurityMode(mode) {
  return mode === "security_rotate_totp" || mode === "security_logout_all" || mode === "security_rotate_totp_logout_all";
}

export function securityActionMode(action) {
  if (!SECURITY_ACTIONS.has(action)) throw Object.assign(new Error("安全操作只支持更换 2FA、登出所有设备或先更换 2FA 再登出"), { status: 400 });
  return action === "rotate-totp" ? "security_rotate_totp" : action === "logout-all" ? "security_logout_all" : "security_rotate_totp_logout_all";
}

export function requireSocks5Proxy(value) {
  let proxy;
  try { proxy = new URL(String(value || "")); } catch {}
  if (!proxy || !["socks5:", "socks5h:"].includes(proxy.protocol) || !proxy.hostname || !proxy.port) {
    throw Object.assign(new Error("账号安全操作必须配置 SOCKS5 或 SOCKS5H 代理，不允许直连或 HTTP 代理"), { status: 409 });
  }
  return proxy.toString();
}

export function safeSecurityError(value, secrets = []) {
  let message = String(value || "安全操作未完成");
  for (const secret of secrets.filter((item) => typeof item === "string" && item.length)) message = message.replaceAll(secret, "<已隐藏>");
  return message
    .replace(/(?:https?|socks5h?):\/\/[^\s<>"']+/gi, "<已隐藏地址>")
    .replace(/(?:authorization|cookie)\s*[:=]\s*[^\r\n]+/gi, "<已隐藏凭据>")
    .replace(/(?:access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|password|secret|totp[_-]?secret|2fa[_-]?key|code)\s*["']?\s*[:=]\s*["']?[^\s,}"']+/gi, "<已隐藏凭据>")
    .replace(/\b[A-Z2-7]{16,128}\b/g, "<已隐藏密钥>")
    .replace(/[\r\n]+/g, " ").slice(0, 500);
}

export function validateSecurityResult(result, operation) {
  if (!result || result.version !== 1 || result.operationId !== operation.operationId
    || String(result.email || "").trim().toLowerCase() !== operation.email.toLowerCase()
    || result.action !== operation.action || !STAGES.has(result.stage)
    || !["running", "completed", "failed", "needs_attention"].includes(result.status)) {
    throw new Error("安全操作结果与当前账号或操作不匹配，已保留结果等待核实");
  }
  const secret = typeof result.secret === "string" ? result.secret.toUpperCase().replace(/[\s=]/g, "") : null;
  if (secret && (operation.action === "logout-all" || !/^[A-Z2-7]{16,128}$/.test(secret))) {
    throw new Error("安全操作结果中的 2FA 密钥格式不正确，已保留结果等待核实");
  }
  // Retain only the contract fields; this encrypted record never reaches public APIs.
  return {
    version: 1, operationId: operation.operationId, email: operation.email, action: operation.action,
    status: result.status, stage: result.stage,
    startedAt: validDate(result.startedAt) || operation.startedAt,
    updatedAt: validDate(result.updatedAt) || new Date().toISOString(),
    secret,
    oldFactorId: typeof result.oldFactorId === "string" ? result.oldFactorId.slice(0, 256) : null,
    newFactorId: typeof result.newFactorId === "string" ? result.newFactorId.slice(0, 256) : null,
    activation_succeeded: result.activation_succeeded === true,
    mfa_verified: result.mfa_verified === true,
    logout_accepted: result.logout_accepted === true,
    logoutAcceptedAt: validDate(result.logoutAcceptedAt),
    credentials_saved: result.credentials_saved === true,
    work_reset_succeeded: result.work_reset_succeeded === true,
    work_reset_unavailable: result.work_reset_unavailable === true,
    error: result.error ? safeSecurityError(result.error, [secret]) : null,
  };
}

function validDate(value) {
  return typeof value === "string" && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : null;
}

export function publicSecurityOperation(operation) {
  if (!operation) return null;
  return {
    operationId: operation.operationId, action: operation.action,
    status: operation.status, stage: operation.stage,
    startedAt: operation.startedAt, updatedAt: operation.updatedAt,
    completedAt: operation.completedAt || null,
    error: operation.error || null,
    credentialsUpdatedAt: operation.credentialsUpdatedAt || null,
    logoutAccepted: operation.result?.logout_accepted === true,
    logoutAcceptedAt: operation.result?.logoutAcceptedAt || null,
    workResetSucceeded: operation.result?.work_reset_succeeded === true,
    workResetUnavailable: operation.result?.work_reset_unavailable === true,
    recoveryNeeded: operation.status === "needs_attention",
    canRecover: operation.status === "needs_attention",
    proxyRequired: "socks5",
  };
}

export function createSecurityOperationStore(database) {
  const kind = "account-security-operation";
  const indexKind = "account-security-index";
  function read(id) {
    if (!UUID.test(String(id || ""))) return null;
    return database.get(kind, id);
  }
  function list(job) {
    return (database.get(indexKind, job.id) || []).map(read).filter((item) => item && item.jobId === job.id
      && item.email.toLowerCase() === job.email.toLowerCase());
  }
  function update(id, changes) {
    const current = read(id);
    if (!current) throw new Error("安全操作记录不存在");
    if (changes.status && !STATUSES.has(changes.status)) throw new Error("安全操作状态无效");
    const next = { ...current, ...changes, operationId: current.operationId, jobId: current.jobId, email: current.email,
      action: current.action, updatedAt: new Date().toISOString() };
    database.put(kind, id, next);
    return next;
  }
  return {
    read, list, update,
    begin(job, action, requestedId = null) {
      securityActionMode(action);
      const operationId = requestedId || crypto.randomUUID();
      if (!UUID.test(operationId) || read(operationId)) throw Object.assign(new Error("安全操作编号已存在或无效，未重复执行"), { status: 409 });
      const now = new Date().toISOString();
      const operation = {
        version: 1, operationId, jobId: job.id, email: job.email, action,
        status: "queued", stage: "prepared", startedAt: now, updatedAt: now, completedAt: null,
        error: null, result: null, credentialsUpdatedAt: null,
        previousTotpFingerprint: crypto.createHash("sha256").update(String(job.totpSecret || "")).digest("hex"),
        priorStatus: job.status, priorPrompt: job.prompt, priorError: job.lastError || null,
      };
      database.transaction(() => {
        database.put(kind, operationId, operation);
        database.put(indexKind, job.id, [...(database.get(indexKind, job.id) || []), operationId]);
      });
      return operation;
    },
    latest(job) { return list(job).at(-1) || null; },
    blockingRotation(job) { return list(job).find((item) => item.action !== "logout-all" && item.status === "needs_attention"); },
    detail(job) { return list(job).slice().reverse().map(publicSecurityOperation); },
    delete(job) {
      for (const operation of list(job)) {
        database.remove(kind, operation.operationId);
        database.remove("security-operation-result", operation.operationId);
      }
      database.remove(indexKind, job.id);
    },
  };
}
