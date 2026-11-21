import React, { useEffect, useRef, useState } from "react";
import { Check, CircleAlert, Clock3, LoaderCircle, RefreshCw, Send, Settings2, X } from "lucide-react";

const STATUS_LABELS = { pending: "排队中", running: "上传中", succeeded: "已成功", failed: "失败", unknown: "待确认" };
const EMPTY_CONFIG = { baseUrl: "", authType: "password", username: "", hasPassword: false, hasApiKey: false, autoUpload: false };
const EMPTY_STATUS = { configured: false, autoUpload: false, counts: { pending: 0, running: 0, succeeded: 0, failed: 0, unknown: 0 }, items: [] };

function configDraft(config) {
  return { ...EMPTY_CONFIG, ...config, password: "", apiKey: "" };
}

function configPayload(draft) {
  const payload = { baseUrl: draft.baseUrl.trim(), authType: draft.authType, username: draft.username.trim(), autoUpload: Boolean(draft.autoUpload) };
  if (draft.password) payload.password = draft.password;
  if (draft.apiKey) payload.apiKey = draft.apiKey;
  return payload;
}

function normalizeStatus(data) {
  return { ...EMPTY_STATUS, ...data, counts: { ...EMPTY_STATUS.counts, ...data?.counts }, items: Array.isArray(data?.items) ? data.items : [] };
}

async function crsRequest(token, endpoint, options = {}) {
  const controller = new AbortController();
  const abort = () => controller.abort();
  options.signal?.addEventListener("abort", abort, { once: true });
  if (options.signal?.aborted) controller.abort();
  const timeout = window.setTimeout(abort, 30_000);
  try {
    const response = await fetch(endpoint, {
      ...options, cache: "no-store", signal: controller.signal,
      headers: { "content-type": "application/json", "x-console-token": token },
    });
    let data;
    try { data = await response.json(); } catch { throw new Error(`CRS 服务响应无法读取：HTTP ${response.status}`); }
    if (!response.ok) {
      const error = new Error(data.error || `CRS 请求失败：HTTP ${response.status}`);
      error.status = response.status;
      error.data = data;
      throw error;
    }
    return data;
  } catch (error) {
    if (error.name === "AbortError" && !options.signal?.aborted) throw new Error("CRS 请求超时，请检查连接或查看上传结果");
    throw error;
  } finally {
    window.clearTimeout(timeout);
    options.signal?.removeEventListener("abort", abort);
  }
}

export function useCrsIntegration(token) {
  const [groups, setGroups] = useState([]);
  const [defaultGroupIds, setDefaultGroupIds] = useState([]);
  const [accountSettings, setAccountSettings] = useState({});
  const [groupError, setGroupError] = useState("");
  const [groupsReady, setGroupsReady] = useState(false);
  const [config, setConfig] = useState(EMPTY_CONFIG);
  const [revision, setRevision] = useState(0);
  const [status, setStatus] = useState(EMPTY_STATUS);
  const [ready, setReady] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [statusError, setStatusError] = useState("");
  const [actionError, setActionError] = useState("");
  const [notice, setNotice] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [busy, setBusy] = useState("");
  const actionInFlight = useRef(false);
  const [configOpen, setConfigOpen] = useState(false);
  const [resultsOpen, setResultsOpen] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    let stopped = false;
    let timer;
    setReady(false);
    setLoadError("");
    if (!token) return () => controller.abort();
    const poll = async () => {
      try {
        const data = await crsRequest(token, "/api/crs/status", { signal: controller.signal });
        if (!stopped) { setStatus(normalizeStatus(data)); setStatusError(""); }
      } catch (error) {
        if (!stopped) setStatusError(error.message);
      } finally {
        if (!stopped) timer = window.setTimeout(poll, 2_500);
      }
    };
    const load = async () => {
      try {
        const [saved, current] = await Promise.all([
          crsRequest(token, "/api/crs/config", { signal: controller.signal }),
          crsRequest(token, "/api/crs/status", { signal: controller.signal }),
        ]);
        if (!stopped) {
          setConfig({ ...EMPTY_CONFIG, ...saved.config });
          setRevision(saved.revision || 0);
          setStatus(normalizeStatus(current));
          setStatusError("");
          setReady(true);
          timer = window.setTimeout(poll, 2_500);
        }
      } catch (error) {
        if (!stopped) setLoadError(`CRS 配置加载失败：${error.message}`);
      }
    };
    void load();
    return () => { stopped = true; controller.abort(); window.clearTimeout(timer); };
  }, [token, attempt]);

  useEffect(() => {
    const controller = new AbortController();
    setGroupsReady(false); setGroups([]); setDefaultGroupIds([]); setAccountSettings({}); setGroupError("");
    if (!token || !status.configured) return () => controller.abort();
    Promise.all([crsRequest(token, "/api/crs/groups", { signal: controller.signal }), crsRequest(token, "/api/crs/account-settings", { signal: controller.signal })])
      .then(([catalog, saved]) => {
        if (controller.signal.aborted) return;
        setGroups(catalog.items); setDefaultGroupIds(catalog.defaultGroupIds); setAccountSettings(saved.settings || {}); setGroupError(catalog.message || ""); setGroupsReady(true);
      }).catch((error) => { if (!controller.signal.aborted) setGroupError(error.message); });
    return () => controller.abort();
  }, [token, status.configured, config.baseUrl, revision, attempt]);

  async function saveAccountSettings(ids, settings) {
    if (!groupsReady || actionInFlight.current) throw new Error("请等待 CRS 分组与当前操作完成");
    actionInFlight.current = true; setBusy("settings");
    try {
      const data = await crsRequest(token, "/api/crs/account-settings", { method: "PUT", body: JSON.stringify({ ids, settings }) });
      setAccountSettings(data.settings || {}); return data;
    } finally { actionInFlight.current = false; setBusy(""); }
  }

  async function saveConfig(draft) {
    if (!ready || actionInFlight.current) throw new Error("请等待当前请求完成");
    actionInFlight.current = true;
    setBusy("config");
    try {
      const data = await crsRequest(token, "/api/crs/config", { method: "PUT", body: JSON.stringify({ config: configPayload(draft), revision }) });
      setConfig({ ...EMPTY_CONFIG, ...data.config });
      setRevision(data.revision || 0);
      setStatus((current) => ({ ...current, configured: Boolean(data.config?.baseUrl && (data.config.authType === "apiKey" ? data.config.hasApiKey : data.config.hasPassword)), autoUpload: Boolean(data.config?.autoUpload) }));
      setActionError("");
      return data;
    } catch (error) {
      if (error.status === 409 && error.data?.config) {
        setConfig({ ...EMPTY_CONFIG, ...error.data.config });
        setRevision(error.data.revision || 0);
        error.message = "其他页面已修改 CRS 配置，已同步最新值，请核对后再保存";
        error.latestConfig = error.data.config;
      }
      throw error;
    } finally { actionInFlight.current = false; setBusy(""); }
  }

  async function refreshStatus() {
    try {
      const data = await crsRequest(token, "/api/crs/status");
      setStatus(normalizeStatus(data.status && typeof data.status === "object" ? data.status : data));
      setStatusError("");
    } catch (error) { setStatusError(error.message); }
  }

  async function upload(ids) {
    if (!ready || actionInFlight.current || !ids.length) return;
    actionInFlight.current = true;
    setBusy("upload"); setActionError(""); setNotice(""); setResultsOpen(true);
    try {
      const data = await crsRequest(token, "/api/crs/upload", { method: "POST", body: JSON.stringify({ ids }) });
      if (data.status && typeof data.status === "object") setStatus(normalizeStatus(data.status));
      setNotice(`已加入上传队列 ${Number(data.queued) || 0} 个账号${data.skipped ? `，跳过 ${data.skipped} 个` : ""}。实际结果会在下方更新。`);
      await refreshStatus();
    } catch (error) { setActionError(`${error.message}。请先查看上传结果，确认状态后再操作。`); }
    finally { actionInFlight.current = false; setBusy(""); }
  }

  async function retry(ids) {
    if (!ready || actionInFlight.current) return;
    actionInFlight.current = true;
    setBusy("retry"); setActionError(""); setNotice("");
    try {
      const data = await crsRequest(token, "/api/crs/retry", { method: "POST", body: JSON.stringify(ids ? { ids } : {}) });
      setStatus(normalizeStatus(data.status && typeof data.status === "object" ? data.status : data));
      setNotice(typeof data.queued === "number"
        ? `已加入重试队列 ${data.queued} 个账号${data.skipped ? `，跳过 ${data.skipped} 个` : ""}。实际结果会在下方更新。`
        : "已提交重试，实际结果会在下方更新。");
    } catch (error) { setActionError(error.message); }
    finally { actionInFlight.current = false; setBusy(""); }
  }

  return { token, config, revision, status, ready, busy, loadError, statusError, actionError, notice, groups, defaultGroupIds, accountSettings, groupError, groupsReady, saveAccountSettings, configOpen, resultsOpen, setConfigOpen, setResultsOpen, reload: () => setAttempt((current) => current + 1), saveConfig, refreshStatus, upload, retry };
}

function defaultAccountSettings(crs) { return { groupIds: crs.defaultGroupIds, concurrencyLimit: 7, weight: 1, credentialGuardian: { enabled: false } }; }

function CrsSettingsFields({ crs, draft, setDraft, disabled }) {
  return <div className="crs-account-fields">
    <details className="crs-group-picker"><summary>{draft.groupIds.length ? draft.groupIds.map((id) => crs.groups.find((group) => group.id === id)?.name || "分组已不可用").join("、") : "选择 CRS 分组"}</summary>
      <div className="crs-group-options">{crs.groups.map((group) => <label key={group.id}><input type="checkbox" disabled={disabled} checked={draft.groupIds.includes(group.id)} onChange={(event) => setDraft((current) => ({ ...current, groupIds: event.target.checked ? [...current.groupIds, group.id] : current.groupIds.filter((id) => id !== group.id) }))} />{group.name}</label>)}{!crs.groups.length && <span>暂无可用分组</span>}</div>
    </details>
    <label className="crs-concurrency"><span>账号并发</span><input aria-label="CRS 账号并发" type="number" min="1" max="4294967295" value={draft.concurrencyLimit} disabled={disabled} onChange={(event) => setDraft((current) => ({ ...current, concurrencyLimit: event.target.value === "" ? "" : Number(event.target.value) }))} /></label>
    <label className="crs-concurrency"><span>账号优先级</span><input aria-label="CRS 账号优先级" type="number" min="1" max="100" step="1" value={draft.weight ?? 1} disabled={disabled} onChange={(event) => setDraft((current) => ({ ...current, weight: event.target.value === "" ? "" : Number(event.target.value) }))} /></label>
    <label className="crs-guard-toggle"><input type="checkbox" checked={draft.credentialGuardian.enabled} disabled={disabled} onChange={(event) => setDraft((current) => ({ ...current, credentialGuardian: { ...current.credentialGuardian, enabled: event.target.checked } }))} />401 重登</label>
  </div>;
}

export function CrsAccountSettings({ crs, job }) {
  const saved = crs.accountSettings[job.id] || defaultAccountSettings(crs);
  const signature = JSON.stringify(saved);
  const [draft, setDraft] = useState(saved);
  const [error, setError] = useState("");
  const [savedNotice, setSavedNotice] = useState(false);
  useEffect(() => { setDraft(JSON.parse(signature)); }, [signature]);
  async function save(upload = false) {
    setError(""); setSavedNotice(false);
    try { await crs.saveAccountSettings([job.id], draft); setSavedNotice(true); if (upload) await crs.upload([job.id]); }
    catch (failure) { setError(failure.message); }
  }
  if (!crs.status.configured) return <button type="button" className="selection-text-button" onClick={() => crs.setConfigOpen(true)}>配置 CRS</button>;
  return <div className="crs-account-settings">
    <CrsSettingsFields crs={crs} draft={draft} setDraft={(value) => { setSavedNotice(false); setDraft(value); }} disabled={!crs.groupsReady || Boolean(crs.busy)} />
    <div className="crs-account-actions"><button type="button" className="selection-text-button" disabled={!crs.groupsReady || Boolean(crs.busy) || !draft.groupIds.length} onClick={() => save()}>保存设置</button><button type="button" className="selection-text-button" disabled={!crs.groupsReady || Boolean(crs.busy) || !draft.groupIds.length || !job.canDownload || job.loginDeferred} onClick={() => save(true)}>上传 CRS</button>{savedNotice && <span role="status">已保存</span>}</div>
    {error && <span className="row-error" role="alert">{error}</span>}
  </div>;
}

export function CrsBatchSettingsButton({ crs, jobs }) {
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState(() => defaultAccountSettings(crs));
  const [error, setError] = useState("");
  async function save(upload) {
    setError("");
    try { await crs.saveAccountSettings(jobs.map((job) => job.id), draft); setOpen(false); if (upload) await crs.upload(jobs.filter((job) => job.canDownload && !job.loginDeferred).map((job) => job.id)); }
    catch (failure) { setError(failure.message); }
  }
  return <><button type="button" className="secondary-button bulk-button" disabled={!crs.groupsReady || !jobs.length || Boolean(crs.busy)} onClick={() => { setDraft(defaultAccountSettings(crs)); setError(""); setOpen(true); }}><Settings2 size={16} />批量设置 CRS</button>
    {open && <div className="modal-backdrop"><section className="batch-dialog crs-batch-settings" role="dialog" aria-modal="true" aria-labelledby="crs-batch-title"><div className="dialog-header"><h2 id="crs-batch-title">设置选中的 {jobs.length} 个账号</h2><button type="button" className="icon-button" aria-label="关闭批量设置" disabled={Boolean(crs.busy)} onClick={() => setOpen(false)}><X size={18} /></button></div><CrsSettingsFields crs={crs} draft={draft} setDraft={setDraft} disabled={Boolean(crs.busy)} />{error && <p className="dialog-error" role="alert">{error}</p>}<div className="dialog-actions"><button type="button" className="cancel-button" disabled={Boolean(crs.busy)} onClick={() => setOpen(false)}>取消</button><button type="button" className="secondary-button" disabled={Boolean(crs.busy) || !draft.groupIds.length} onClick={() => save(false)}>保存设置</button><button type="button" className="primary-button" disabled={Boolean(crs.busy) || !draft.groupIds.length || !jobs.some((job) => job.canDownload && !job.loginDeferred)} onClick={() => save(true)}>保存并上传</button></div></section></div>}
  </>;
}

export function CrsUploadButton({ crs, jobs, disabled = false }) {
  const ids = jobs.filter((job) => job.canDownload && !job.loginDeferred).map((job) => job.id);
  return <button type="button" className="secondary-button bulk-button" disabled={disabled || !crs.ready || Boolean(crs.busy) || !ids.length} onClick={() => crs.status.configured ? crs.upload(ids) : crs.setConfigOpen(true)}><Send size={16} />上传到 CRS</button>;
}

export function CrsToolbar({ crs }) {
  const counts = crs.status.counts;
  const pending = counts.pending + counts.running;
  return <>
    <div className="provider-toolbar crs-toolbar" aria-label="CRS 配置与上传">
      <div className="provider-heading"><Send size={17} /><strong>CRS</strong></div>
      <span className="provider-name">{crs.config.baseUrl || "未配置后端"}</span>
      <span className={`provider-ready ${crs.status.configured ? "" : "incomplete"}`}>{crs.status.configured ? <Check size={14} /> : <CircleAlert size={14} />}{!crs.ready ? (crs.loadError ? "加载失败" : "正在加载") : crs.status.configured ? `已配置 · ${crs.config.autoUpload ? "新授权自动上传" : "手动上传"}` : "未完成配置"}</span>
      <button type="button" className="secondary-button provider-settings-button" disabled={!crs.ready || Boolean(crs.busy)} onClick={() => crs.setConfigOpen(true)}><Settings2 size={16} />配置 CRS</button>
      <button type="button" className="selection-text-button" disabled={!crs.ready} onClick={() => crs.setResultsOpen(true)}>查看上传结果{pending ? ` · ${pending} 个处理中` : counts.failed ? ` · ${counts.failed} 个失败` : counts.unknown ? ` · ${counts.unknown} 个待确认` : ""}</button>
      <span className="proxy-toolbar-note">已有账号请勾选后上传到 CRS</span>
      {crs.groupError && <div className="crs-inline-error" role="alert"><CircleAlert size={14} /><span>{crs.groupError}</span><button type="button" className="selection-text-button" onClick={crs.reload}>刷新分组</button></div>}
      {(crs.loadError || crs.statusError) && <div className="crs-inline-error" role="alert"><CircleAlert size={14} /><span>{crs.loadError || `上传状态读取失败：${crs.statusError}`}</span><button type="button" className="selection-text-button" onClick={crs.loadError ? crs.reload : crs.refreshStatus}>重试</button></div>}
    </div>
    {crs.configOpen && <CrsConfigDialog crs={crs} />}
    {crs.resultsOpen && <CrsResultsDialog crs={crs} />}
  </>;
}

function CrsConfigDialog({ crs }) {
  const [draft, setDraft] = useState(() => configDraft(crs.config));
  const [error, setError] = useState("");
  const [testMessage, setTestMessage] = useState("");
  const [testing, setTesting] = useState(false);
  const saving = crs.busy === "config";
  const waiting = testing || saving;
  const setField = (field, value) => { setDraft((current) => ({ ...current, [field]: value })); setTestMessage(""); };
  async function test() {
    setTesting(true); setError(""); setTestMessage("");
    try {
      const data = await crsRequest(crs.token, "/api/crs/test", { method: "POST", body: JSON.stringify({ config: configPayload(draft) }) });
      if (!data.ok) throw new Error(data.message || "CRS 连接测试失败");
      setTestMessage(`${data.message || "CRS 连接正常"}${data.version ? ` · ${data.version}` : ""}`);
    } catch (failure) { setError(failure.message); } finally { setTesting(false); }
  }
  async function save(event) {
    event.preventDefault(); setError("");
    try { await crs.saveConfig(draft); crs.setConfigOpen(false); }
    catch (failure) { if (failure.latestConfig) setDraft(configDraft(failure.latestConfig)); setError(failure.message); }
  }
  return <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !waiting) crs.setConfigOpen(false); }}>
    <form className="batch-dialog crs-config-dialog" role="dialog" aria-modal="true" aria-labelledby="crs-config-title" onSubmit={save}>
      <div className="dialog-header"><div><h2 id="crs-config-title">CRS 配置</h2><span>配置保存在服务器</span></div><button type="button" className="icon-button" title="关闭 CRS 配置" disabled={waiting} onClick={() => crs.setConfigOpen(false)}><X size={18} /></button></div>
      <div className="provider-config-grid sub2api-config-grid crs-config-grid">
        <label className="settings-field"><span>CRS 后端地址</span><input aria-label="CRS 后端地址" type="url" required value={draft.baseUrl} onChange={(event) => setField("baseUrl", event.target.value)} placeholder="https://crs.example.com" disabled={waiting} /></label>
        <label className="settings-field"><span>认证方式</span><select aria-label="CRS 认证方式" value={draft.authType} onChange={(event) => setField("authType", event.target.value)} disabled={waiting}><option value="password">管理员账号和密码</option><option value="apiKey">管理员 API Key</option></select></label>
        {draft.authType === "password" ? <>
          <label className="settings-field"><span>管理员账号</span><input aria-label="CRS 管理员账号" autoComplete="username" value={draft.username} onChange={(event) => setField("username", event.target.value)} disabled={waiting} /></label>
          <label className="settings-field wide-settings-field"><span>管理员密码 {draft.hasPassword && <small className="crs-secret-saved">已保存</small>}</span><input aria-label="CRS 管理员密码" type="password" autoComplete="new-password" value={draft.password} onChange={(event) => setField("password", event.target.value)} placeholder={draft.hasPassword ? "留空保留已保存密码" : "输入管理员密码"} disabled={waiting} /></label>
        </> : <label className="settings-field"><span>管理员 API Key {draft.hasApiKey && <small className="crs-secret-saved">已保存</small>}</span><input aria-label="CRS 管理员 API Key" type="password" autoComplete="new-password" value={draft.apiKey} onChange={(event) => setField("apiKey", event.target.value)} placeholder={draft.hasApiKey ? "留空保留已保存 API Key" : "输入管理员 API Key"} disabled={waiting} /></label>}
        <label className="crs-auto-upload wide-settings-field"><input type="checkbox" checked={draft.autoUpload} onChange={(event) => setField("autoUpload", event.target.checked)} disabled={waiting} /><span>新授权完成后自动上传到 CRS<small>仅影响之后完成的授权；已有账号请勾选后手动上传。</small></span></label>
      </div>
      <p className="dialog-hint">账号分组、并发、优先级和 401 重登可在列表中单独或批量设置</p>
      {testMessage && <div className="crs-test-success" role="status"><Check size={15} />{testMessage}</div>}
      {error && <div className="dialog-error" role="alert"><CircleAlert size={15} />{error}</div>}
      <div className="dialog-actions"><button type="button" className="secondary-button" disabled={waiting || !draft.baseUrl.trim()} onClick={test}>{testing ? <LoaderCircle className="spin" size={16} /> : <RefreshCw size={16} />}测试连接</button><span className="dialog-actions-spacer" /><button type="button" className="cancel-button" disabled={waiting} onClick={() => crs.setConfigOpen(false)}>取消</button><button type="submit" className="primary-button" disabled={waiting}>{saving ? <LoaderCircle className="spin" size={16} /> : <Check size={16} />}保存 CRS 配置</button></div>
    </form>
  </div>;
}

function CrsResultsDialog({ crs }) {
  const { counts, items } = crs.status;
  return <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) crs.setResultsOpen(false); }}>
    <section className="batch-dialog crs-results-dialog" role="dialog" aria-modal="true" aria-labelledby="crs-results-title">
      <div className="dialog-header"><div><h2 id="crs-results-title">CRS 上传结果</h2><span>后台自动更新</span></div><button type="button" className="icon-button" title="关闭 CRS 上传结果" onClick={() => crs.setResultsOpen(false)}><X size={18} /></button></div>
      <div className="crs-result-counts">{Object.entries(STATUS_LABELS).map(([key, label]) => <span key={key} className={`crs-status crs-status-${key}`}>{label} <strong>{counts[key]}</strong></span>)}</div>
      {crs.notice && <p className="crs-result-notice" role="status">{crs.notice}</p>}
      {(crs.actionError || crs.statusError || crs.status.lastError) && <div className="dialog-error" role="alert"><CircleAlert size={15} />{crs.actionError || crs.statusError || crs.status.lastError}</div>}
      <div className="crs-results-list">{items.length ? items.map((item, index) => <div className="crs-result-row" key={`${item.jobId}-${index}`}>
        <div className="crs-result-identity"><strong>{item.email || "账号"}</strong>{item.message && <span>{item.message}</span>}{item.updatedAt && <small>{formatResultTime(item.updatedAt)}</small>}</div>
        <span className={`crs-status crs-status-${item.status}`}>{["pending", "running"].includes(item.status) ? <Clock3 size={13} /> : item.status === "succeeded" ? <Check size={13} /> : <CircleAlert size={13} />}{STATUS_LABELS[item.status] || "待确认"}</span>
        {item.status === "failed" && <button type="button" className="selection-text-button" disabled={Boolean(crs.busy)} onClick={() => crs.retry([item.jobId])}>重试</button>}
        {item.status === "unknown" && <button type="button" className="selection-text-button" disabled={Boolean(crs.busy)} onClick={() => {
          if (window.confirm("请先在 CRS 核对该账号，确认尚未导入后再重试。你已确认该账号未导入，继续重试吗？")) void crs.retry([item.jobId]);
        }}>核对后重试</button>}
      </div>) : <div className="crs-results-empty">还没有上传记录。勾选已完成授权的账号后，点击「上传到 CRS」。</div>}</div>
      {counts.unknown > 0 && <p className="dialog-hint">待确认表示尚未确认 CRS 是否接收成功，请先到 CRS 核对账号。</p>}
      <div className="dialog-footer"><button type="button" className="secondary-button" onClick={crs.refreshStatus}><RefreshCw size={15} />刷新结果</button><button type="button" className="secondary-button" disabled={!counts.failed || Boolean(crs.busy)} onClick={() => crs.retry()}>{crs.busy === "retry" ? <LoaderCircle className="spin" size={15} /> : <RefreshCw size={15} />}重试失败项</button><button type="button" className="cancel-button" onClick={() => crs.setResultsOpen(false)}>关闭</button></div>
    </section>
  </div>;
}

function formatResultTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "" : date.toLocaleString("zh-CN");
}
