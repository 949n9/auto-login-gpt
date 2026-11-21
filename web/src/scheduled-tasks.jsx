import React, { useCallback, useEffect, useRef, useState } from "react";
import { ArrowRight, Ban, CalendarClock, Check, ChevronLeft, CircleAlert, Clock3, Globe2, ListChecks, LoaderCircle, Plus, RefreshCw, Send, ShieldCheck, X } from "lucide-react";
import { ProxyAssignments, selectedProxyUrl, DEFAULT_OPERATION_PROXY_ID, operationProxySelection } from "./proxy-controls.jsx";
import { formatScheduleBjt, scheduleLocalToIso, defaultScheduleTime } from "./schedule-time.mjs";
export { formatScheduleBjt, scheduleLocalToIso } from "./schedule-time.mjs";

const TIME_ZONE = "Asia/Shanghai";
const TERMINAL = new Set(["completed", "failed", "needs_attention", "canceled", "superseded"]);
const STATUS_LABELS = {
  scheduled: "等待准备", preparing: "准备中", waiting: "等待上号", login_queued: "上号排队中",
  logging_in: "正在上号", publishing: "推送 CPR 中", completed: "已完成", failed: "失败",
  needs_attention: "需要核实", canceled: "已取消", superseded: "已被后续操作替代",
  running: "执行中", partial: "部分账号已结束",
};
const PHASE_LABELS = {
  scheduled: "等待计划执行", preparing: "执行登录前准备", security: "执行账号安全操作",
  waiting: "等待计划时间或登出等待期结束", login: "登录并获取授权", logging_in: "登录并获取授权",
  login_queued: "等待上号槽位", publishing: "推送至 CPR", completed: "已推送至 CPR",
  prepared: "准备账号安全操作", old_disabled: "旧 2FA 已关闭", enrolled: "已生成新的 2FA",
  activated: "新 2FA 已启用", verified: "新 2FA 已验证", credentials_saved: "新 2FA 已保存",
  work_reset_requested: "正在重置 Work", work_reset_confirmed: "Work 已重置",
  logout_requested: "已请求全设备登出", logout_accepted: "全设备登出请求已确认",
  waiting_prepare: "等待准备时间", waiting_login: "等待计划时间或登出等待期结束",
  publish: "推送至 CPR", done: "本账号流程已结束",
};
function socks5(value) {
  try { const url = new URL(value); return ["socks5:", "socks5h:"].includes(url.protocol) && Boolean(url.hostname); }
  catch { return false; }
}

export function scheduledSecurityAction(rotate, logout) {
  return rotate && logout ? "rotate-totp-logout-all" : rotate ? "rotate-totp" : logout ? "logout-all" : null;
}

function securityLabel(action) {
  return ({ "rotate-totp": "更换并保存 2FA", "logout-all": "重置 Work 并登出所有设备", "rotate-totp-logout-all": "更换 2FA、重置 Work 并登出所有设备" })[action] || "无需登录前准备";
}

export function validateScheduleDraft(draft) {
  const planned = scheduleLocalToIso(draft.scheduledLocal);
  if (!planned || Date.parse(planned) <= Date.now()) return "请选择未来的北京时间。";
  for (const [key, label] of [["prepareLeadMinutes", "提前准备时长"], ["postLogoutDelayMinutes", "登出后等待时长"]]) {
    if (draft[key] === "" || !Number.isInteger(Number(draft[key])) || Number(draft[key]) < 0 || Number(draft[key]) > 1440) return `${label}须为 0–1440 分钟。`;
  }
  if (draft.concurrencyLimit === "" || !Number.isInteger(Number(draft.concurrencyLimit)) || Number(draft.concurrencyLimit) < 1 || Number(draft.concurrencyLimit) > 4294967295) return "CPR 账号并发须为大于 0 的整数。";
  if (draft.weight === "" || !Number.isInteger(Number(draft.weight)) || Number(draft.weight) < 1 || Number(draft.weight) > 100) return "账号优先级须为 1–100 的整数。";
  return "";
}

function newRequestId() {
  if (typeof globalThis.crypto?.randomUUID === "function") return globalThis.crypto.randomUUID();
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 15) | 64; bytes[8] = (bytes[8] & 63) | 128;
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function ScheduleStatus({ status }) {
  return <span className={`schedule-status schedule-status-${status || "scheduled"}`}>{STATUS_LABELS[status] || "等待执行"}</span>;
}

function WorkResetScope() {
  return <div className="schedule-work-warning"><CircleAlert size={17} /><div><strong>Work 重置会删除当前工作环境中的文件和其他本地数据。</strong><p>已保存到资料库的文件会保留，下次工作会创建新环境。随后登出所有设备，包含本次登录会话。</p></div></div>;
}

export function ScheduledTasksDialog({ request, proxyState, mailMethod, cprConfigured, onManageProxies, onClose, defaultOperationProxy }) {
  const [tab, setTab] = useState("create");
  const [step, setStep] = useState(0);
  const [text, setText] = useState("");
  const [recognized, setRecognized] = useState(null);
  const [assignments, setAssignments] = useState({});
  const [useStoredProxy, setUseStoredProxy] = useState(false);
  const [draft, setDraft] = useState(() => ({ scheduledLocal: defaultScheduleTime(), prepareLeadMinutes: 30, postLogoutDelayMinutes: 30, concurrencyLimit: 20, weight: 99, guardian: true, rotate: false, logout: false }));
  const [preview, setPreview] = useState(null);
  const [previewPayload, setPreviewPayload] = useState(null);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [schedules, setSchedules] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [details, setDetails] = useState(null);
  const [listLoading, setListLoading] = useState(true);
  const [listError, setListError] = useState("");
  const [cancelTarget, setCancelTarget] = useState(null);
  const requestId = useRef(null);
  const previewRequestIds = useRef(new Map());
  const refreshSequence = useRef(0);
  const dialogRef = useRef(null);
  const submitInFlight = useRef(false);
  const proxies = proxyState.proxies.filter((proxy) => socks5(proxy.url));
  const securityAction = scheduledSecurityAction(draft.rotate, draft.logout);
  const recognizedAccounts = (recognized?.accounts || []).filter((account, index, all) => account.email && all.findIndex((other) => other.email?.toLowerCase() === account.email.toLowerCase()) === index).map((account) => ({ key: account.email.toLowerCase(), email: account.email, currentEndpoint: account.proxyEndpoint }));
  const proxyError = !useStoredProxy && recognizedAccounts.some((account) => !(defaultOperationProxy?.configured && operationProxySelection(assignments[account.key], defaultOperationProxy) === DEFAULT_OPERATION_PROXY_ID) && !proxies.some((proxy) => proxy.id === assignments[account.key])) ? "请为每个账号分配 SOCKS5 代理。空代理、直连或其他协议不能提交。" : "";
  const lineCount = text.split(/\r?\n/).filter((line) => line.trim()).length;
  const previewValid = preview && preview.invalidCount === 0 && preview.validCount > 0 && Array.isArray(preview.accounts) && preview.accounts.length > 0 && preview.accounts.every((account) => account.valid === true);

  useEffect(() => {
    const previousFocus = document.activeElement;
    dialogRef.current?.focus();
    return () => previousFocus?.focus?.();
  }, []);

  useEffect(() => {
    const keydown = (event) => {
      if (event.key === "Escape" && !busy && !document.querySelector(".proxy-manager-backdrop")) {
        if (cancelTarget) setCancelTarget(null); else onClose();
      }
    };
    document.addEventListener("keydown", keydown);
    return () => document.removeEventListener("keydown", keydown);
  }, [busy, cancelTarget, onClose]);

  const refresh = useCallback(async (signal) => {
    const sequence = ++refreshSequence.current;
    try {
      const [list, detail] = await Promise.all([
        request("/api/schedules", { signal }),
        selectedId ? request(`/api/schedules/${encodeURIComponent(selectedId)}`, { signal }) : Promise.resolve(null),
      ]);
      if (signal?.aborted || sequence !== refreshSequence.current) return;
      setSchedules(Array.isArray(list.schedules) ? list.schedules : []);
      setDetails(detail);
      setListError("");
    } catch (failure) {
      if (!signal?.aborted && sequence === refreshSequence.current) setListError(failure.message || "计划列表加载失败");
    } finally {
      if (!signal?.aborted && sequence === refreshSequence.current) setListLoading(false);
    }
  }, [request, selectedId]);

  useEffect(() => {
    const controller = new AbortController();
    let timer;
    const poll = async () => {
      await refresh(controller.signal);
      if (!controller.signal.aborted && tab === "history") timer = window.setTimeout(poll, 4000);
    };
    void poll();
    return () => { controller.abort(); window.clearTimeout(timer); };
  }, [refresh, tab]);

  function invalidatePreview() {
    setPreview(null); setPreviewPayload(null); setConfirmed(false); requestId.current = null; setError("");
  }

  function updateDraft(values) {
    setDraft((current) => ({ ...current, ...values })); invalidatePreview();
  }

  function payload(includeProxies = true) {
    const value = {
      text, scheduledLocal: draft.scheduledLocal, timeZone: TIME_ZONE,
      prepareLeadMinutes: Number(draft.prepareLeadMinutes), postLogoutDelayMinutes: Number(draft.postLogoutDelayMinutes), securityAction,
      crsSettings: { concurrencyLimit: Number(draft.concurrencyLimit), weight: Number(draft.weight), credentialGuardian: { enabled: draft.guardian } },
    };
    if (includeProxies && (!useStoredProxy || defaultOperationProxy?.configured)) value.proxyAssignments = recognizedAccounts.map((account) => ({ email: account.email, proxyUrl: useStoredProxy ? { useStoredProxy: true } : selectedProxyUrl(assignments[account.key], proxies, defaultOperationProxy) }));
    return value;
  }

  async function recognize() {
    if (submitInFlight.current || !text.trim()) return;
    setBusy("recognize"); submitInFlight.current = true; setError("");
    try {
      const failure = validateScheduleDraft(draft);
      if (failure) throw new Error(failure);
      if (lineCount > 500) throw new Error("每个计划最多录入 500 个账号。");
      const data = await request("/api/schedules/preview", { method: "POST", body: JSON.stringify(payload(false)) });
      if (!Array.isArray(data.accounts)) throw new Error("服务器未返回账号识别结果。");
      setRecognized(data); setAssignments({}); invalidatePreview();
    } catch (failure) { setError(failure.message || "账号识别失败"); }
    finally { setBusy(""); submitInFlight.current = false; }
  }

  async function buildPreview() {
    if (submitInFlight.current) return;
    setBusy("preview"); submitInFlight.current = true; setError("");
    try {
      const failure = validateScheduleDraft(draft) || proxyError;
      if (failure) throw new Error(failure);
      const body = payload();
      const data = await request("/api/schedules/preview", { method: "POST", body: JSON.stringify(body) });
      if (!Array.isArray(data.accounts)) throw new Error("服务器未返回计划预览。");
      const payloadKey = JSON.stringify(body);
      if (!previewRequestIds.current.has(payloadKey)) previewRequestIds.current.set(payloadKey, newRequestId());
      setPreview(data); setPreviewPayload(body); setConfirmed(false); requestId.current = previewRequestIds.current.get(payloadKey); setStep(2);
    } catch (failure) { setError(failure.message || "计划预览失败"); }
    finally { setBusy(""); submitInFlight.current = false; }
  }

  async function createSchedule() {
    if (submitInFlight.current || !confirmed || !previewValid || !previewPayload || !requestId.current) return;
    setBusy("create"); submitInFlight.current = true; setError("");
    try {
      const data = await request("/api/schedules", { method: "POST", body: JSON.stringify({ ...previewPayload, clientRequestId: requestId.current }) });
      if (!data.schedule?.id) throw new Error("提交结果尚未确认，请重试同一预览；服务器会避免重复创建。");
      setSelectedId(data.schedule.id); setDetails(data.items ? data : null); setTab("history");
      setNotice(`计划已创建，共 ${preview.validCount} 个账号。计划上号时间为 ${formatScheduleBjt(preview.plannedAt)}${preview.securityAction?.includes("logout") ? "；登出等待期未结束时会顺延。" : "。"}`);
      setText(""); setRecognized(null); setAssignments({}); setStep(0); invalidatePreview();
      previewRequestIds.current.clear();
      setDraft((current) => ({ ...current, scheduledLocal: defaultScheduleTime() }));
    } catch (failure) { setError(failure.message || "提交未确认，请重试；不会重复创建同一计划。"); }
    finally { setBusy(""); submitInFlight.current = false; }
  }

  async function cancelSchedule() {
    if (!cancelTarget || submitInFlight.current) return;
    setBusy("cancel"); submitInFlight.current = true; setError("");
    try {
      await request(`/api/schedules/${encodeURIComponent(cancelTarget.scheduleId)}/cancel`, {
        method: "POST", body: JSON.stringify(cancelTarget.itemId ? { itemIds: [cancelTarget.itemId] } : {}),
      });
      setCancelTarget(null); setNotice("取消请求已处理。已完成的准备操作不会撤销，请查看各账号的最新状态。");
      await refresh();
    } catch (failure) { setError(failure.message || "取消计划失败"); }
    finally { setBusy(""); submitInFlight.current = false; }
  }

  const localPlanned = scheduleLocalToIso(draft.scheduledLocal);
  const lead = Number(draft.prepareLeadMinutes);
  const localPrepare = localPlanned && Number.isFinite(lead) && lead >= 0 && lead <= 1440 ? new Date(Date.parse(localPlanned) - (securityAction ? lead * 60_000 : 0)).toISOString() : null;
  const currentSchedule = details?.schedule;
  const currentItems = Array.isArray(details?.items) ? details.items : [];
  const selectedDetails = currentSchedule?.id === selectedId;

  return <div className="modal-backdrop schedule-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) onClose(); }}>
    <section className="batch-dialog schedule-dialog" role="dialog" aria-modal="true" aria-labelledby="schedule-title" tabIndex={-1} ref={dialogRef}>
      <div className="dialog-header schedule-header"><div><span className="schedule-title-icon"><CalendarClock size={21} /></span><div><h2 id="schedule-title">自动定时任务</h2><p>按北京时间安排准备、上号并推送至 CPR</p></div></div><button type="button" className="icon-button" onClick={onClose} disabled={Boolean(busy)} aria-label="关闭自动定时任务"><X size={18} /></button></div>
      <nav className="schedule-tabs" aria-label="定时任务页面"><button type="button" className={tab === "create" ? "is-selected" : ""} onClick={() => { setTab("create"); setError(""); }} disabled={Boolean(busy)}><Plus size={16} />新建计划</button><button type="button" className={tab === "history" ? "is-selected" : ""} onClick={() => { setTab("history"); setError(""); }} disabled={Boolean(busy)}><ListChecks size={16} />计划记录{Boolean(schedules.length) && <span>{schedules.length}</span>}</button><span className="schedule-timezone"><Clock3 size={14} />北京时间 · UTC+8</span></nav>
      {notice && <div className="schedule-notice" role="status"><Check size={16} /><span>{notice}</span><button type="button" className="icon-button" onClick={() => setNotice("")} aria-label="关闭提示"><X size={14} /></button></div>}
      {tab === "create" ? <fieldset className="schedule-fields" disabled={Boolean(busy)}>
        <ol className="schedule-steps" aria-label="创建步骤">{["账号与代理", "时间与操作", "预览确认"].map((label, index) => <li key={label} className={step === index ? "is-current" : step > index ? "is-done" : ""} aria-current={step === index ? "step" : undefined}><span>{step > index ? <Check size={13} /> : index + 1}</span>{label}</li>)}</ol>
        {step === 0 && <div className="schedule-step-content">
          {!recognized ? <><label className="batch-label" htmlFor="schedule-account-input">快速识别账号</label><p className="schedule-field-hint">{mailMethod === "POST" ? "每行一个账号，支持邮箱、密码和编码请求体。字段格式与批量添加一致。" : "每行一个账号，自动识别邮箱、密码、邮件 API 和 2FA，字段顺序不限。"} 已有账号也可只填邮箱。</p><textarea id="schedule-account-input" value={text} onChange={(event) => { setText(event.target.value); invalidatePreview(); }} disabled={Boolean(busy)} placeholder={mailMethod === "POST" ? "name@example.com----账号密码----编码请求体\nexisting@example.com" : "name@example.com----账号密码----BASE32二步验证密钥\nname2@example.com----https://mail.example/messages/name2\nexisting@example.com"} spellCheck={false} autoComplete="off" /><div className="schedule-input-meta"><span>已输入 {lineCount} 行 · 最多 500 个账号</span><span>识别与预览不会登录账号或创建计划</span></div></>
            : <><div className="proxy-batch-summary"><Check size={16} /><span>已识别 {recognizedAccounts.length} 个账号</span><button type="button" className="selection-text-button" onClick={() => { setRecognized(null); invalidatePreview(); }} disabled={Boolean(busy)}>修改账号</button></div>
              {(recognized.accounts || []).some((account) => !account.email) && <div className="schedule-validation-errors" role="alert"><strong>以下行尚未识别，请返回修改账号：</strong>{recognized.accounts.filter((account) => !account.email).map((account, index) => <p key={index}>第 {account.line || index + 1} 行：{account.error || "账号格式无法识别"}</p>)}</div>}
              <label className="schedule-checkbox schedule-stored-proxy"><input type="checkbox" checked={useStoredProxy} onChange={(event) => { setUseStoredProxy(event.target.checked); invalidatePreview(); }} /><span><strong>沿用每个账号在服务器保存的 SOCKS5 代理</strong><small>{defaultOperationProxy?.configured ? "勾选后明确沿用保存值；不勾选时使用默认美国动态住宅代理或下方另选代理。" : "最终预览会检查代理和登录资料；新账号需要在下方分配代理。"}</small></span></label>
              {!useStoredProxy && <ProxyAssignments accounts={recognizedAccounts} assignments={assignments} onChange={(next) => { setAssignments(next); invalidatePreview(); }} proxies={proxies} defaultProxyId={proxies.some((proxy) => proxy.id === proxyState.selectedId) ? proxyState.selectedId : ""} defaultOperationProxy={defaultOperationProxy} onManage={onManageProxies} />}
              <p className="schedule-field-hint"><Globe2 size={14} />所有准备操作和上号请求都必须走 SOCKS5；代理失效时会停止，不会直连回退。</p>
              {proxyError && <p className="schedule-inline-warning">{proxyError}</p>}
            </>}
        </div>}
        {step === 1 && <div className="schedule-step-content">
          <div className="schedule-config-grid"><section className="schedule-config-card"><h3><CalendarClock size={17} />上号时间</h3><label className="schedule-field"><span>计划上号时间（北京时间）</span><input type="datetime-local" value={draft.scheduledLocal} onChange={(event) => updateDraft({ scheduledLocal: event.target.value })} step="60" /></label><p className="schedule-field-hint">按北京时间保存，不受当前电脑时区影响。到时开始上号，授权成功后推送至 CPR。</p></section>
            <section className="schedule-config-card"><h3><Send size={17} />CPR 账号设置</h3><div className="schedule-two-fields"><label className="schedule-field"><span>账号并发</span><input type="number" min="1" max="4294967295" value={draft.concurrencyLimit} onChange={(event) => updateDraft({ concurrencyLimit: event.target.value })} /></label><label className="schedule-field"><span>账号优先级</span><input type="number" min="1" max="100" value={draft.weight} onChange={(event) => updateDraft({ weight: event.target.value })} /></label></div><label className="schedule-checkbox"><input type="checkbox" checked={draft.guardian} onChange={(event) => updateDraft({ guardian: event.target.checked })} /><span><strong>开启401 重登</strong><small>使用 CPR 当前配置及默认分组。</small></span></label></section></div>
          <section className="schedule-preparation"><div className="schedule-section-title"><h3><ShieldCheck size={17} />登录前准备</h3><span>可独立选择，也可同时执行</span></div><div className="schedule-preparation-options"><label className={`schedule-checkbox ${draft.rotate ? "is-selected" : ""}`}><input type="checkbox" checked={draft.rotate} onChange={(event) => updateDraft({ rotate: event.target.checked })} /><span><strong>先更换 2FA</strong><small>验证并保存新密钥后继续，密钥更新到账号详情。</small></span></label><label className={`schedule-checkbox ${draft.logout ? "is-selected" : ""}`}><input type="checkbox" checked={draft.logout} onChange={(event) => updateDraft({ logout: event.target.checked })} /><span><strong>重置 Work 并登出所有设备</strong><small>先重置当前 Work 环境，再退出全部设备。</small></span></label></div>
            {securityAction && <div className="schedule-two-fields schedule-timing-fields"><label className="schedule-field"><span>提前开始准备</span><div className="schedule-number-unit"><input type="number" min="0" max="1440" value={draft.prepareLeadMinutes} onChange={(event) => updateDraft({ prepareLeadMinutes: event.target.value })} /><span>分钟</span></div></label>{draft.logout && <label className="schedule-field"><span>登出确认后至少等待</span><div className="schedule-number-unit"><input type="number" min="0" max="1440" value={draft.postLogoutDelayMinutes} onChange={(event) => updateDraft({ postLogoutDelayMinutes: event.target.value })} /><span>分钟</span></div></label>}</div>}
            {draft.logout && <WorkResetScope />}
          </section>
          <div className="schedule-timeline"><div><span className="schedule-timeline-dot" /><strong>{securityAction ? "开始准备" : "等待计划时间"}</strong><span>{formatScheduleBjt(localPrepare)}</span><small>{securityLabel(securityAction)}</small></div><ArrowRight size={17} /><div><span className="schedule-timeline-dot" /><strong>开始上号并推送 CPR</strong><span>{formatScheduleBjt(localPlanned)}</span><small>{draft.logout ? "不早于计划时间，且满足登出后的等待时长" : "准备成功后，等待计划时间开始上号"}</small></div></div>
          {securityAction && localPrepare && Date.parse(localPrepare) < Date.now() && <p className="schedule-inline-warning">准备时间已经过去，创建计划后会立即开始准备。上号仍等待计划时间和必要的登出等待期。</p>}
          {draft.logout && <p className="schedule-field-hint">若登出确认较晚，上号会顺延至等待期结束，不会为了赶计划时间缩短等待。</p>}
          {!cprConfigured && <p className="schedule-inline-warning">CPR 尚未确认已配置。可以预览账号，创建前需在主页面完成 CPR 连接配置。</p>}
        </div>}
        {step === 2 && preview && <div className="schedule-step-content">
          <div className={`schedule-preview-banner ${previewValid ? "is-valid" : "has-errors"}`}>{previewValid ? <Check size={20} /> : <CircleAlert size={20} />}<div><strong>{previewValid ? `${preview.validCount} 个账号全部通过预览校验` : `${preview.invalidCount || 0} 个账号需要修正，尚不能创建计划`}</strong><p>预览不会登录账号。确认后保存计划，由服务器按北京时间执行。</p></div></div>
          <dl className="schedule-preview-summary"><div><dt>计划上号</dt><dd>{formatScheduleBjt(preview.plannedAt)}</dd></div><div><dt>开始准备</dt><dd>{preview.securityAction ? formatScheduleBjt(preview.prepareAt) : "未选择准备操作"}</dd></div><div><dt>准备操作</dt><dd>{securityLabel(preview.securityAction)}</dd></div><div><dt>CPR 设置</dt><dd>并发 {preview.crsSettings?.concurrencyLimit} · 优先级 {preview.crsSettings?.weight} · 401 重登{preview.crsSettings?.credentialGuardian?.enabled ? "开启" : "关闭"}</dd></div>{draft.logout && <div><dt>登出后等待</dt><dd>至少 {preview.postLogoutDelayMinutes} 分钟；晚于计划时间时顺延</dd></div>}</dl>
          {draft.logout && <WorkResetScope />}
          <div className="schedule-account-table"><table><thead><tr><th>账号</th><th>SOCKS5 代理</th><th>预览结果</th></tr></thead><tbody>{preview.accounts.map((account, index) => <tr key={`${account.line || index}-${account.email || "invalid"}`} className={account.valid ? "" : "has-error"}><td><strong>{account.email || "无法识别账号"}</strong><small>第 {account.line || index + 1} 行</small></td><td>{account.proxyEndpoint || "未确认"}</td><td><span className={account.valid ? "schedule-valid" : "schedule-invalid"}>{account.valid ? <Check size={14} /> : <CircleAlert size={14} />}{account.valid ? "通过" : account.error || "校验未通过"}</span></td></tr>)}</tbody></table></div>
          {!previewValid && <p className="schedule-inline-warning">不会提交错误账号，也不会创建部分计划。请返回修改，重新预览。</p>}
          <label className="schedule-checkbox schedule-confirmation"><input type="checkbox" checked={confirmed} disabled={!previewValid || Boolean(busy)} onChange={(event) => setConfirmed(event.target.checked)} /><span><strong>已核对账号、代理、北京时间及上述操作</strong><small>{draft.logout ? "确认执行已说明范围的 Work 重置和全设备登出。" : "确认按本次预览创建定时任务。"}</small></span></label>
        </div>}
      </fieldset> : <div className="schedule-history">
        <div className="schedule-history-heading"><p>计划保存在服务器，关闭页面后仍会按计划执行。</p><button type="button" className="secondary-button" onClick={() => void refresh()} disabled={Boolean(busy)}><RefreshCw size={14} />刷新</button></div>
        {listError && <div className="dialog-error" role="alert"><CircleAlert size={15} />{listError}</div>}
        {listLoading ? <div className="schedule-empty"><LoaderCircle className="spin" size={26} /><p>正在加载计划…</p></div> : !schedules.length ? <div className="schedule-empty"><CalendarClock size={32} /><strong>还没有定时计划</strong><p>添加账号，选择北京时间，先预览再确认。</p><button type="button" className="secondary-button" onClick={() => setTab("create")}><Plus size={15} />新建计划</button></div> : <div className="schedule-history-grid">
          <div className="schedule-list" aria-label="已保存的计划">{schedules.map((schedule) => { const total = Number(schedule.total || schedule.counts?.total || 0); const completed = Number(schedule.counts?.completed || 0); return <button type="button" key={schedule.id} className={`schedule-list-card ${schedule.id === selectedId ? "is-selected" : ""}`} onClick={() => { setSelectedId(schedule.id); setDetails(null); setCancelTarget(null); }}><div><strong>{formatScheduleBjt(schedule.plannedAt).replace(" 北京时间", "")}</strong><ScheduleStatus status={schedule.status} /></div><p>{total} 个账号 · {securityLabel(schedule.securityAction)}</p><div className="schedule-progress" role="progressbar" aria-label="已成功账号" aria-valuemin={0} aria-valuemax={total || 1} aria-valuenow={completed}><span style={{ width: `${total ? Math.min(100, completed / total * 100) : 0}%` }} /></div><small>成功 {completed} / {total} · 失败 {Number(schedule.counts?.failed || 0)} · 待核实 {Number(schedule.counts?.needs_attention || 0)}</small></button>; })}</div>
          <section className="schedule-detail" aria-label="计划账号进度">{!selectedId ? <div className="schedule-empty"><ListChecks size={28} /><p>选择左侧计划，查看每个账号的状态和原因。</p></div> : !selectedDetails ? <div className="schedule-empty"><LoaderCircle className="spin" size={24} /><p>正在读取账号进度…</p></div> : <>
            <div className="schedule-detail-heading"><div><h3>{formatScheduleBjt(currentSchedule.plannedAt)}</h3><p>{securityLabel(currentSchedule.securityAction)}{currentSchedule.securityAction && <> · 提前 {currentSchedule.prepareLeadMinutes} 分钟准备</>}</p></div>{!TERMINAL.has(currentSchedule.status) && <button type="button" className="schedule-cancel-button" onClick={() => setCancelTarget({ scheduleId: currentSchedule.id })} disabled={Boolean(busy)}><Ban size={14} />取消计划</button>}</div>
            <div className="schedule-item-list">{currentItems.map((item) => <article key={item.id} className="schedule-item"><div className="schedule-item-heading"><strong>{item.email || "账号"}</strong><ScheduleStatus status={item.status} /></div><p>{PHASE_LABELS[item.phase] || STATUS_LABELS[item.status] || "等待服务器更新"}</p>{item.error && <div className="schedule-item-error"><CircleAlert size={13} />{item.error}</div>}{item.crs?.message && <p className="schedule-item-cpr">CPR：{item.crs.message}</p>}<div className="schedule-item-meta">{item.loginNotBefore && <span>最早上号：{formatScheduleBjt(item.loginNotBefore)}</span>}{item.logoutAcceptedAt && <span>登出确认：{formatScheduleBjt(item.logoutAcceptedAt)}</span>}{item.attempts != null && <span>已尝试 {typeof item.attempts === "number" ? item.attempts : "—"} 次</span>}</div>{!TERMINAL.has(item.status) && <button type="button" className="selection-text-button schedule-item-cancel" onClick={() => setCancelTarget({ scheduleId: currentSchedule.id, itemId: item.id, email: item.email })} disabled={Boolean(busy)}>取消此账号</button>}</article>)}</div>
          </>}</section>
        </div>}
        {cancelTarget && <div className="schedule-cancel-confirm" role="alert"><strong>{cancelTarget.itemId ? `取消 ${cancelTarget.email || "此账号"} 的计划？` : "取消这个计划中尚未完成的账号？"}</strong><p>取消后停止后续步骤。已经完成的 2FA 更换、Work 重置和设备登出不会撤销；已发出的 CPR 推送可能仍会完成，需要核实结果。</p><div><button type="button" className="cancel-button" onClick={() => setCancelTarget(null)} disabled={Boolean(busy)}>返回</button><button type="button" className="schedule-cancel-button" onClick={cancelSchedule} disabled={Boolean(busy)}>{busy === "cancel" ? <LoaderCircle className="spin" size={14} /> : <Ban size={14} />}确认取消</button></div></div>}
      </div>}
      {error && <div className="dialog-error" role="alert"><CircleAlert size={15} />{error}</div>}
      <div className="dialog-footer schedule-footer"><span className="schedule-footer-note"><ShieldCheck size={14} />仅推送 CPR · 全程 SOCKS5</span>{tab === "history" ? <button type="button" className="cancel-button" onClick={onClose} disabled={Boolean(busy)}>关闭</button> : <>
        <button type="button" className="cancel-button" onClick={() => { if (step > 0) { setStep(step - 1); setError(""); setConfirmed(false); } else onClose(); }} disabled={Boolean(busy)}>{step > 0 ? <><ChevronLeft size={14} />返回修改</> : "取消"}</button>
        {step === 0 && <button type="button" className="primary-button" onClick={recognized ? () => { setStep(1); setError(""); } : recognize} disabled={Boolean(busy) || !text.trim() || lineCount > 500 || Boolean(recognized && (!recognizedAccounts.length || proxyError))}>{busy === "recognize" ? <LoaderCircle className="spin" size={16} /> : recognized ? <ArrowRight size={16} /> : <ListChecks size={16} />}{recognized ? "设置时间与操作" : "识别账号"}</button>}
        {step === 1 && <button type="button" className="primary-button" onClick={buildPreview} disabled={Boolean(busy)}>{busy === "preview" ? <LoaderCircle className="spin" size={16} /> : <ListChecks size={16} />}生成计划预览</button>}
        {step === 2 && <button type="button" className="primary-button" onClick={createSchedule} disabled={Boolean(busy) || !confirmed || !previewValid}>{busy === "create" ? <LoaderCircle className="spin" size={16} /> : <CalendarClock size={16} />}确认创建计划</button>}
      </>}</div>
    </section>
  </div>;
}
