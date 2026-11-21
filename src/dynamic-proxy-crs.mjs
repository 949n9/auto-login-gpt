const fail = (message) => Object.assign(new Error(message), { status: 409 });

export function createDynamicCrsAdapter(integration) {
  const request = (path, body) => integration.dynamicRequest(path, body);
  function checkTarget(record) {
    if (!record.target || record.target !== integration.dynamicTarget()) throw fail("CRS 目标已变化，动态代理绑定已暂停");
  }
  async function findAccount(record) {
    checkTarget(record);
    if (record.accountId) return record.accountId;
    const query = new URLSearchParams({ page: "1", pageSize: "200", provider: "openai", search: record.email });
    const page = await request(`/api/admin/accounts?${query}`);
    const matches = page.items.filter((value) => value.email?.trim().toLowerCase() === record.email);
    if (matches.length > 1 || page.page.totalPages > 1) throw fail("CRS 中账号邮箱不唯一，无法自动绑定");
    return matches[0]?.id || null;
  }
  async function accountStatus(record) {
    const id = await findAccount(record);
    if (!id) return null;
    const value = await request(`/api/admin/accounts/proxy-recovery?accountId=${encodeURIComponent(id)}`);
    if (value.email?.trim().toLowerCase() !== record.email) throw fail("CRS 账号绑定已变化");
    return value;
  }
  async function status(record) {
    const value = await accountStatus(record);
    if (value && record.proxyId && value.proxyId !== record.proxyId) throw fail("CRS 已更换代理，等待同步人工选择");
    return value;
  }
  return {
    status,
    async manualSelection(record) {
      if (!record.proxyId) return null;
      const value = await accountStatus(record);
      if (!value || value.proxyId === record.proxyId) return null;
      if (!value.proxyId) throw fail("CRS 账号未配置代理，停止动态续换");
      // 完整认证只从已有敏感导出读取，不将账号令牌或代理密码带入普通状态响应
      const query = new URLSearchParams({ accountIds: value.accountId, confirm: "export_sensitive_accounts" });
      const bundle = await request(`/api/admin/accounts/export?${query}`);
      const accounts = (bundle.documents || []).filter((item) => item.provider === "openai").flatMap((item) => item.document?.accounts || []);
      const selected = accounts.filter((item) => item.id === value.accountId && item.email?.trim().toLowerCase() === record.email);
      if (selected.length !== 1 || !selected[0].outbound_proxy_url) throw fail("CRS 新代理信息尚未同步");
      const confirmed = await accountStatus(record);
      if (!confirmed || confirmed.proxyId !== value.proxyId || confirmed.guardian.revision !== value.guardian.revision) throw fail("CRS 代理正在变化，等待重新同步");
      return { accountId: value.accountId, proxyId: value.proxyId, proxyUrl: selected[0].outbound_proxy_url };
    },
    async eligibility(record, intent) {
      const value = await status(record);
      if (!value) return { allowed: intent === "login" && !record.accountId, message: "仅首次登录可以分配初始代理" };
      const guardian = value.guardian;
      const ownRecovery = [record.operationId, record.gate?.operationId || record.id].filter(Boolean).includes(guardian.state.proxyRecovery?.operationId);
      const recovering = ownRecovery && ["proxy_recovery", "verifying"].includes(guardian.state.status);
      const allowed = guardian.config.enabled && guardian.state.status !== "degraded" && (value.enabled || recovering) && (value.quotaAllowed || ownRecovery && guardian.state.status === "verifying");
      const message = guardian.state.status === "degraded" ? "账号已降智停用" : !guardian.config.enabled ? "账号质量守护未启用" : !value.enabled && !recovering ? "账号已停用" : "账号额度不可用或尚未确认";
      return { allowed, canExtract: value.quotaAllowed, accountId: value.accountId, proxyId: value.proxyId, verifying: ownRecovery && guardian.state.status === "verifying", message };
    },
    async isolate(record, intent) {
      const value = await status(record);
      if (!value) {
        if (intent !== "login") throw fail("首次代理只能由登录任务申请");
        return { operationId: record.id };
      }
      const existing = value.guardian.state.proxyRecovery;
      if (!record.operationId) throw fail("代理恢复操作尚未持久化");
      if (existing?.operationId === record.operationId && ["proxy_recovery", "verifying", "watching"].includes(value.guardian.state.status)) return { operationId: record.operationId, accountId: value.accountId };
      if (value.enabled) await request("/api/admin/accounts/proxy-demand", { accountId: value.accountId, bindingId: record.id, expectedProxyId: value.proxyId });
      const operationId = record.operationId;
      await request("/api/admin/accounts/proxy-recovery", { action: "begin", accountId: value.accountId, operationId, expectedRevision: value.guardian.revision });
      return { operationId, accountId: value.accountId };
    },
    async publish(record) {
      const value = await status(record);
      if (value) {
        await request("/api/admin/accounts/proxy-recovery", { action: "complete", accountId: value.accountId, operationId: record.gate.operationId, proxyUrl: record.candidateUrl });
        return { proxyId: value.proxyId, accountId: value.accountId, requiresVerification: true };
      }
      const result = await request("/api/admin/accounts/proxy-recovery", { action: "prepareInitial", bindingId: record.id, email: record.email, proxyUrl: record.candidateUrl });
      return { proxyId: result.proxyId, requiresVerification: false };
    },
    async recoveryStatus(record) {
      const value = await status(record);
      if (value?.guardian.state.status === "degraded") return "degraded";
      return value?.enabled && value.quotaAllowed && value.guardian.state.status === "watching" ? "ready" : "pending";
    },
    async probe(proxyUrl) {
      const result = await request("/api/admin/proxies/probe", { proxyUrl, detectLocation: false });
      return result.success === true;
    },
    demands: () => request("/api/admin/accounts/proxy-demand"),
    async register(record) {
      const value = await status(record);
      if (value) await request("/api/admin/accounts/proxy-demand", { accountId: value.accountId, bindingId: record.id, expectedProxyId: value.proxyId });
      return value;
    },
  };
}
