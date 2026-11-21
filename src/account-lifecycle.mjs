// Account attributes share the existing authenticated encrypted database.
const KIND = "account-lifecycle";
const key = (email) => String(email).trim().toLowerCase();
const date = (value) => typeof value === "string" && Number.isFinite(Date.parse(value))
  ? new Date(value).toISOString() : null;
const earliest = (values) => values.map(date).filter(Boolean).sort()[0] || null;

// Only an explicit account state is enough to classify an account as retired.
// Authentication rejection, token revocation, proxy blocks and challenges are
// intentionally absent: they do not establish deletion or account deactivation.
export function isRetiredAccountFailure(value) {
  const text = String(value || "");
  return /\b(?:account|user)_(?:deactivated|deleted)\b|\b(?:your|this) account (?:has been|is|was) (?:deleted|deactivated)\b|\baccount has been (?:deleted|deactivated)\b|\bdo not have an account because it has been deleted\b/i.test(text);
}

export function normalizeAccountTerm(value) {
  if (value !== "long" && value !== "short") throw Object.assign(new Error("账号类型请选择长效或短效"), { status: 400 });
  return value;
}

export function normalizeAccountArea(value = "all") {
  if (!["active", "resting", "retired", "all"].includes(value)) throw Object.assign(new Error("账号分区无效"), { status: 400 });
  return value;
}

export function resolveAccountTerms(entries, body) {
  const defaultTerm = Object.hasOwn(body, "accountTerm") ? normalizeAccountTerm(body.accountTerm) : null;
  const expected = new Set(entries.map((entry) => key(entry.email)));
  const overrides = new Map();
  if (Object.hasOwn(body, "accountTerms")) {
    if (!Array.isArray(body.accountTerms) || body.accountTerms.length > entries.length) {
      throw Object.assign(new Error("账号类型分配格式无效"), { status: 400 });
    }
    for (const assignment of body.accountTerms) {
      const email = typeof assignment?.email === "string" ? key(assignment.email) : "";
      if (!expected.has(email) || overrides.has(email)) throw Object.assign(new Error("账号类型分配包含重复账号或未录入的账号"), { status: 400 });
      overrides.set(email, normalizeAccountTerm(assignment.accountTerm));
    }
  }
  return {
    term: (email) => overrides.get(key(email)) || defaultTerm || "long",
    explicit: (email) => overrides.has(key(email)) || defaultTerm !== null,
  };
}

export function createAccountLifecycle(database) {
  function read(email) { return database.get(KIND, key(email)); }
  function save(email, value) { database.put(KIND, key(email), value); return value; }
  function blank(knownFromAddition = false) {
    return { version: 1, accountTerm: null, knownFromAddition, firstAuthorizedAt: null,
      firstAuthorizedAtSource: null, lastFullAuthorizedAt: null, lastLogoutAt: null,
      restingSince: null, restingReason: null, logoutOperationId: null,
      retiredAt: null, retiredReason: null };
  }
  function reconcile(value) {
    if (value.manualRestAt && (!value.lastLogoutAt || value.manualRestAt >= value.lastLogoutAt)
        && (!value.lastFullAuthorizedAt || value.lastFullAuthorizedAt <= value.manualRestAt)) {
      value.restingSince = value.manualRestAt;
      value.restingReason = "manual";
    } else if (value.lastLogoutAt && (!value.lastFullAuthorizedAt || value.lastFullAuthorizedAt <= value.lastLogoutAt)) {
      value.restingSince = value.lastLogoutAt;
    } else {
      value.restingSince = null;
      value.restingReason = null;
    }
    return value;
  }
  return {
    read,
    public(email) {
      const value = read(email) || blank();
      return { accountTerm: value.accountTerm || null,
        firstAuthorizedAt: value.firstAuthorizedAt || null, firstAuthorizedAtSource: value.firstAuthorizedAtSource || null,
        resting: Boolean(value.restingSince), restingSince: value.restingSince || null,
        restingReason: value.restingReason || null, retired: Boolean(value.retiredAt),
        retiredAt: value.retiredAt || null, retiredReason: value.retiredReason || null };
    },
    initialize(email, accountTerm = null) {
      if (!read(email)) save(email, { ...blank(true), accountTerm: accountTerm === null ? null : normalizeAccountTerm(accountTerm) });
    },
    setTerm(email, term) {
      return save(email, { ...(read(email) || blank()), accountTerm: normalizeAccountTerm(term) });
    },
    rest(email, at = new Date().toISOString()) {
      const manualRestAt = date(at);
      if (!manualRestAt) throw new Error("静置时间无效");
      const value = read(email) || blank();
      if (value.retiredAt) throw Object.assign(new Error("废号需成功登录后才能恢复"), { status: 409 });
      // 本地分区不代表已向上游发送登出请求；完整登录成功后才恢复在用。
      value.manualRestAt = manualRestAt;
      return save(email, reconcile(value));
    },
    authorized(email, at, mode) {
      const authorizedAt = date(at);
      if (!authorizedAt) throw new Error("授权完成时间无效");
      const value = read(email) || blank();
      if (!value.firstAuthorizedAt) {
        value.firstAuthorizedAt = authorizedAt;
        value.firstAuthorizedAtSource = value.knownFromAddition ? "recorded" : "historical";
      }
      if (mode === "full") {
        if (!value.lastFullAuthorizedAt || value.lastFullAuthorizedAt < authorizedAt) value.lastFullAuthorizedAt = authorizedAt;
        if (!value.retiredAt || value.retiredAt < authorizedAt) { value.retiredAt = null; value.retiredReason = null; }
      }
      save(email, reconcile(value));
    },
    retire(email, reason, at = new Date().toISOString()) {
      const retiredAt = date(at);
      if (!retiredAt) throw new Error("作废时间无效");
      const value = read(email) || blank();
      if (!value.retiredAt) { value.retiredAt = retiredAt; value.retiredReason = String(reason || "账号已被上游删除或停用").slice(0, 500); }
      return save(email, value);
    },
    logout(email, operation) {
      if (operation.action === "rotate-totp" || (!operation.result?.logout_accepted && operation.result?.stage !== "logout_requested")) return;
      const value = read(email) || blank();
      const result = operation.result;
      const at = date(result.logoutAcceptedAt) || date(result.updatedAt) || date(operation.completedAt) || date(operation.updatedAt) || date(operation.startedAt);
      if (!at || value.lastLogoutAt && value.lastLogoutAt > at) return;
      value.lastLogoutAt = at;
      value.logoutOperationId = operation.operationId;
      value.restingReason = result.logout_accepted ? "logout_accepted" : "logout_requested";
      save(email, reconcile(value));
    },
    backfill(job, operations) {
      const value = read(job.email) || blank();
      // Restored file mtimes and completed history events can reflect recovery
      // or an unsuccessful retry that retained an older export. Use only data
      // written by successful authorization, retaining its historical provenance.
      const artifact = database.readArtifact(job.outputPath);
      const metadata = database.getJob(job.id) || {};
      const first = earliest([value.firstAuthorizedAt, artifact?.exported_at, metadata.last_auth_automated_at]);
      if (first && (!value.firstAuthorizedAt || !value.knownFromAddition && first < value.firstAuthorizedAt)) {
        value.firstAuthorizedAt = first;
        value.firstAuthorizedAtSource = "historical";
      }
      const full = date(metadata.last_auth_automated_at);
      if (full && (!value.lastFullAuthorizedAt || value.lastFullAuthorizedAt < full)) value.lastFullAuthorizedAt = full;
      save(job.email, reconcile(value));
      for (const operation of operations) this.logout(job.email, operation);
    },
    remove(email) { database.remove(KIND, key(email)); },
  };
}
