import React, { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { X, Eye, EyeOff, RefreshCw, ShieldCheck, Copy, Check } from 'lucide-react';
import { accountTermLabel, RestingStatus, RetiredStatus } from './account-lifecycle.jsx';

const sources = { initial: '首次登录', login: '登录', manual_retry: '手动重试', manual_relogin: '重新登录', crs_bridge: 'CRS 自动登录', sub2api_monitor: 'Sub2API 自动登录', refresh_fallback: '令牌失效后登录', configuration_update: '配置更新后登录', token_refresh: '刷新授权' };
const statuses = { unknown: '未记录结束状态', running: '已启动', completed: '成功', failed: '失败', canceled: '已取消', reauth_required: '需直接授权 Codex', resume_available: '等待继续' };
function date(value) { return value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '未记录'; }

const credentialLabels = { email: '账号', password: '密码', totpSecret: '2FA 密钥', all: '账密 2FA' };

export function CopyCredentialsButton({ jobId, token, field = 'all', onError }) {
  const pending = useRef(null);
  const resetTimer = useRef(null);
  const [copying, setCopying] = useState(false);
  const [copied, setCopied] = useState(null);
  useEffect(() => {
    setCopying(false); setCopied(null);
    return () => { pending.current?.abort(); pending.current = null; window.clearTimeout(resetTimer.current); };
  }, [jobId, token, field]);

  async function copy() {
    if (pending.current) return;
    const controller = new AbortController();
    pending.current = controller;
    setCopying(true); setCopied(null); onError('');
    window.clearTimeout(resetTimer.current);
    let readError;
    try {
      if (!navigator.clipboard) throw new Error('浏览器不支持自动复制，请在账号详情中查看并手动复制');
      const value = (async () => {
        try {
          const response = await fetch(`/api/jobs/${jobId}/secrets`, { method: 'POST', headers: { 'x-console-token': token }, cache: 'no-store', signal: controller.signal });
          if (!response.ok) throw new Error('凭据读取失败，请刷新页面后重试');
          const body = await response.json();
          const fields = ['email', 'password', 'totpSecret'];
          if (typeof body.email !== 'string' || !body.email) throw new Error('账号资料不完整，请刷新页面后重试');
          const values = Object.fromEntries(fields.map((key) => [key, typeof body[key] === 'string' ? body[key] : '']));
          if (field !== 'all' && !values[field]) throw new Error(`未保存${credentialLabels[field]}，无法复制`);
          return { text: field === 'all' ? fields.map((key) => values[key]).join('----') : values[field], missing: field === 'all' ? fields.filter((key) => !values[key]).map((key) => credentialLabels[key]) : [] };
        } catch (error) { readError = error; throw error; }
      })();
      // Start the clipboard write during the click so Safari retains user activation.
      let result;
      if (navigator.clipboard.write && typeof ClipboardItem !== 'undefined') {
        const blob = value.then(({ text }) => new Blob([text], { type: 'text/plain' }));
        void blob.catch(() => {});
        [result] = await Promise.all([value, navigator.clipboard.write([new ClipboardItem({ 'text/plain': blob })])]);
      } else {
        result = await value;
        await navigator.clipboard.writeText(result.text);
      }
      if (!controller.signal.aborted) {
        setCopied(result.missing);
        resetTimer.current = window.setTimeout(() => setCopied(null), 2400);
      }
    } catch (error) {
      if (!controller.signal.aborted) onError(readError?.name === 'AbortError' ? '复制已取消，请重试' : readError?.message || (navigator.clipboard ? '复制失败，请允许剪贴板权限，或在账号详情中手动复制' : error.message));
    } finally {
      if (pending.current === controller) {
        controller.abort(); pending.current = null; setCopying(false);
      }
    }
  }

  const title = copied?.length ? `已复制；未保存${copied.join('、')}，对应字段已留空` : field === 'all' ? '复制格式：邮箱----密码----2FA密钥（未保存的字段留空）' : `复制已保存的${credentialLabels[field]}`;
  return <button type="button" className="secondary-button credential-copy-button" onClick={copy} disabled={copying || !token} title={title} aria-label={`复制${credentialLabels[field]}`} aria-live="polite" aria-busy={copying}>
    {copied ? <Check size={14} /> : <Copy size={14} />}{copying ? '复制中…' : copied ? copied.length ? '已复制（有空项）' : '已复制' : `复制${credentialLabels[field]}`}
  </button>;
}

export function securityActionLabel(action) { return ({ 'rotate-totp': '更换 2FA', 'logout-all': '重置 Work 并登出所有设备', 'rotate-totp-logout-all': '更换 2FA、重置 Work 并登出所有设备' })[action] || '账号安全操作'; }
export function securityStatusLabel(status) { return ({ queued: '已排队', running: '执行中', completed: '已完成', failed: '失败', needs_attention: '需要核实或恢复', canceled: '已取消' })[status] || '等待更新'; }
export function securityStageLabel(stage) { return ({ prepared: '准备验证账号', old_disabled: '旧 2FA 已关闭', enrolled: '新密钥已生成，等待激活', activated: '新密钥已激活', verified: '新 2FA 已确认', credentials_saved: '新 2FA 密钥已保存', work_reset_requested: '正在重置 Work 工作环境', work_reset_confirmed: 'Work 工作环境已重置', logout_requested: '全设备登出请求', logout_accepted: '全设备登出已提交' })[stage] || '处理中'; }
function isSecurityOperationActive(operation) { return ['queued', 'running'].includes(operation.status); }
function isLogoutOperation(operation) { return ['logout-all', 'rotate-totp-logout-all'].includes(operation.action); }
function isPartialSecurityOperation(operation) {
  return isLogoutOperation(operation) && !isSecurityOperationActive(operation)
    && Boolean(operation.credentialsUpdatedAt || operation.workResetSucceeded || operation.workResetUnavailable || operation.logoutAccepted)
    && !((operation.workResetSucceeded || operation.workResetUnavailable) && operation.logoutAccepted);
}
export function securityOperationSummary(operation) {
  if (isLogoutOperation(operation) && operation.workResetUnavailable) {
    const prefix = operation.action === 'rotate-totp-logout-all' && operation.credentialsUpdatedAt ? '2FA 已更新，' : '';
    return `${prefix}Work接口不可用，已跳过；${operation.logoutAccepted ? '退出已提交' : isSecurityOperationActive(operation) ? '正在退出所有设备' : '退出未确认'}`;
  }
  if (operation.action === 'rotate-totp-logout-all' && operation.credentialsUpdatedAt) {
    if (operation.workResetSucceeded && operation.logoutAccepted) return '2FA 已更新，Work 已重置，登出已提交';
    if (!operation.workResetSucceeded) return isSecurityOperationActive(operation) ? '2FA 已更新，正在重置 Work' : `2FA 已更新，Work 重置未确认，${operation.logoutAccepted ? '登出已提交' : '登出未确认'}`;
    return isSecurityOperationActive(operation) ? '2FA 已更新，Work 已重置，正在登出所有设备' : '2FA 已更新，Work 已重置，登出未确认';
  }
  if (operation.action === 'logout-all') {
    if (operation.workResetSucceeded && operation.logoutAccepted) return 'Work 已重置，全部设备登出已提交';
    if (operation.workResetSucceeded) return isSecurityOperationActive(operation) ? 'Work 已重置，正在登出所有设备' : 'Work 已重置，登出未确认';
    if (operation.logoutAccepted) return '全部设备登出已提交，Work 重置未确认';
  }
  return `${securityStatusLabel(operation.status)}${operation.stage ? ` · ${securityStageLabel(operation.stage)}` : ''}`;
}

function SecurityOperationProgress({ operation }) {
  if (!isLogoutOperation(operation)) return null;
  const combined = operation.action === 'rotate-totp-logout-all';
  const active = isSecurityOperationActive(operation);
  const resetReady = !combined || Boolean(operation.credentialsUpdatedAt);
  const stages = [];
  if (combined) stages.push({ done: Boolean(operation.credentialsUpdatedAt), title: operation.credentialsUpdatedAt ? '新 2FA 已验证并保存' : '更换并保存新 2FA', description: operation.credentialsUpdatedAt ? date(operation.credentialsUpdatedAt) : securityStageLabel(operation.stage) });
  stages.push({ done: Boolean(operation.workResetSucceeded), title: operation.workResetUnavailable ? 'Work接口不可用，已跳过' : operation.workResetSucceeded ? 'Work 工作环境已重置' : resetReady && !active ? 'Work 重置未确认' : '重置 Work 工作环境', description: operation.workResetUnavailable ? '本次未重置 Work，继续登出所有设备' : operation.workResetSucceeded ? '当前工作环境文件和本地数据已清理，资料库文件保留' : !resetReady ? '新密钥确认保存后才执行' : active ? '确认重置成功后才会登出' : '请核实重置结果，避免重复操作' });
  stages.push({ done: Boolean(operation.logoutAccepted), title: operation.logoutAccepted ? '全部设备登出已提交' : !active ? '登出未确认' : '登出所有设备', description: operation.logoutAccepted ? '包含当前会话，最多需要 30 分钟生效' : !operation.workResetSucceeded && !operation.workResetUnavailable ? 'Work 重置确认成功后才执行' : active ? '正在提交登出请求' : operation.workResetUnavailable ? 'Work 重置已跳过，请核实登出结果' : 'Work 已重置，请核实登出结果' });
  return <ol className="security-operation-stages" aria-label="安全操作进度">{stages.map((stage, index) => <li key={index} className={stage.done ? 'is-complete' : ''}><span>{index + 1}</span><div><strong>{stage.title}</strong><small>{stage.description}</small></div></li>)}</ol>;
}

export function AccountDetails({ jobId, token, refreshKey = '', onClose }) {
  const dialog = useRef(null);
  const revealEpoch = useRef(0);
  const [data, setData] = useState(null);
  const [secrets, setSecrets] = useState(null);
  const [error, setError] = useState('');
  const [page, setPage] = useState(1);
  const [revealing, setRevealing] = useState(false);
  const [recovering, setRecovering] = useState('');
  const [reload, setReload] = useState(0);
  useEffect(() => { dialog.current.showModal(); }, []);
  useEffect(() => {
    revealEpoch.current += 1;
    setSecrets(null);
    return () => { revealEpoch.current += 1; };
  }, [jobId, token, refreshKey, reload]);
  useEffect(() => {
    const controller = new AbortController();
    setData(null); setError('');
    fetch(`/api/jobs/${jobId}/details?page=${page}`, { headers: { 'x-console-token': token }, signal: controller.signal, cache: 'no-store' })
      .then(async (r) => { const body = await r.json(); if (!r.ok) throw new Error(body.error || '详情读取失败'); return body; })
      .then(setData).catch((e) => { if (e.name !== 'AbortError') setError(e.message); });
    return () => controller.abort();
  }, [jobId, token, page, refreshKey, reload]);
  async function reveal() {
    if (secrets) { setSecrets(null); return; }
    setRevealing(true); setError('');
    const epoch = revealEpoch.current;
    try {
      const r = await fetch(`/api/jobs/${jobId}/secrets`, { method: 'POST', headers: { 'x-console-token': token }, cache: 'no-store' });
      const body = await r.json();
      if (!r.ok) throw new Error(body.error || '凭据读取失败');
      if (epoch === revealEpoch.current) setSecrets(body);
    } catch (e) { if (epoch === revealEpoch.current) setError(e.message); }
    finally { setRevealing(false); }
  }
  async function recover(operationId) {
    if (recovering) return;
    setRecovering(operationId); setError('');
    try {
      const r = await fetch(`/api/jobs/${jobId}/security/recover`, { method: 'POST', headers: { 'x-console-token': token, 'content-type': 'application/json' }, body: JSON.stringify({ operationId }), cache: 'no-store' });
      const body = await r.json();
      if (!r.ok) throw new Error(body.error || '恢复保存失败');
      setSecrets(null);
      setReload((value) => value + 1);
    } catch (e) { setError(e.message); }
    finally { setRecovering(''); }
  }
  return createPortal(<dialog ref={dialog} className="batch-dialog account-details-dialog" aria-labelledby={`account-detail-${jobId}`} onCancel={onClose} onClick={(e) => { if (e.target === dialog.current) { const r = dialog.current.getBoundingClientRect(); if (e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom) onClose(); } }}>
    <div className="dialog-header"><h2 id={`account-detail-${jobId}`}>账号详情</h2><div className="account-detail-actions"><button type="button" className="icon-button" aria-label="刷新账号详情" onClick={() => setReload((value) => value + 1)} disabled={recovering}><RefreshCw size={16} /></button><button type="button" className="icon-button" aria-label="关闭账号详情" onClick={onClose}><X size={18} /></button></div></div>
    {error && <p role="alert" className="dialog-error">{error}</p>}
    {!data && !error && <p role="status">正在读取详情…</p>}
    {data && <>
      <dl className="account-detail-fields"><dt>账号</dt><dd className="credential-copy-field"><span>{data.email}</span><CopyCredentialsButton jobId={jobId} token={token} field="email" onError={setError} /></dd><dt>账号类型</dt><dd>{accountTermLabel(data.accountTerm)}</dd><dt>{data.firstAuthorizedAtSource === 'historical' ? '首次授权（历史可追溯）' : '首次授权时间'}</dt><dd>{date(data.firstAuthorizedAt)}</dd><dt>账号区域</dt><dd>{data.retired ? <RetiredStatus job={data} /> : data.resting ? <RestingStatus job={data} /> : '在用账号'}</dd><dt>首次添加时间</dt><dd>{date(data.history.firstAddedAt)}</dd><dt>最近操作时间</dt><dd>{date(data.lastOperationAt)}</dd></dl>
      <section aria-label="登录凭据"><div className="account-detail-heading"><h3>登录凭据</h3><div className="credential-copy-actions"><CopyCredentialsButton jobId={jobId} token={token} onError={setError} /><button type="button" className="secondary-button" onClick={reveal} disabled={revealing}>{secrets ? <EyeOff size={15}/> : <Eye size={15}/>} {revealing ? '读取中…' : secrets ? '隐藏账密和 2FA' : '查看账密和 2FA'}</button></div></div>
        <p className="dialog-hint">更换 2FA 成功后，这里显示保存的新密钥。安全操作有更新时会隐藏已显示的凭据，请重新查看。</p>
        <dl className="account-detail-fields"><dt>密码</dt><dd className="credential-copy-field"><span>{secrets ? <code>{secrets.password || '未保存'}</code> : '••••••••'}</span><CopyCredentialsButton jobId={jobId} token={token} field="password" onError={setError} /></dd><dt>2FA 密钥</dt><dd className="credential-copy-field"><span>{secrets ? <code>{secrets.totpSecret || '未保存'}</code> : '••••••••'}</span><CopyCredentialsButton jobId={jobId} token={token} field="totpSecret" onError={setError} /></dd></dl>
      </section>
      <section aria-label="账号安全操作" className="account-security-history"><h3>账号安全操作</h3>
        {!data.securityOperations?.length ? <p className="dialog-hint">暂无安全操作记录</p> : <ol>{data.securityOperations.map((operation) => <li key={operation.operationId}>
          <div className="account-detail-heading"><strong>{securityActionLabel(operation.action)}</strong><span>{isPartialSecurityOperation(operation) ? '部分完成' : securityStatusLabel(operation.status)}</span></div>
          <p className={isPartialSecurityOperation(operation) ? 'security-partial-result' : ''}>{securityOperationSummary(operation)}</p>
          <SecurityOperationProgress operation={operation} />
          <p className="dialog-hint">开始：{date(operation.startedAt)}{operation.completedAt ? ` · 结束：${date(operation.completedAt)}` : ''}</p>
          {operation.credentialsUpdatedAt && <p className="dialog-hint">新 2FA 密钥已保存：{date(operation.credentialsUpdatedAt)}</p>}
          {(operation.action === 'logout-all' || operation.action === 'rotate-totp-logout-all') && operation.logoutAccepted && <p className="dialog-hint">全设备登出已提交，包含当前会话，最多需要 30 分钟生效。已暂停自动重新登录，可在需要时手动重新登录。</p>}
          {operation.error && <p className="dialog-error" role="alert">{operation.error}</p>}
          {(operation.status === 'needs_attention' || operation.recoveryNeeded) && <p className="dialog-hint">{operation.action === 'rotate-totp' || operation.action === 'rotate-totp-logout-all' ? '请先核实本次各阶段结果，避免重复执行。已生成的新密钥会保留供恢复。' : '请先核实 Work 重置和登出结果，避免重复提交。'}</p>}
          {operation.canRecover && <button type="button" className="secondary-button" disabled={Boolean(recovering)} onClick={() => recover(operation.operationId)}><ShieldCheck size={15} />{recovering === operation.operationId ? '正在恢复保存…' : '恢复保存已验证的新密钥'}</button>}
        </li>)}</ol>}
      </section>
      <section aria-label="登录历史"><h3>登录与授权记录 <small>（{data.history.total} 条）</small></h3>
        <p className="dialog-hint">时间按当前浏览器时区显示。{data.history.legacy ? '历史账号：过去的重复登录时间未记录，以下仅展示功能启用后的记录。' : ''}“已启动”只表示发起过流程，不代表登录成功。</p>
        {!data.history.total ? <p>暂无登录记录</p> : <div className="account-history-scroll"><table><thead><tr><th>开始时间</th><th>类型</th><th>结果</th><th>结束时间</th></tr></thead><tbody>{data.history.events.map((event) => <tr key={event.id}><td>{date(event.startedAt)}</td><td>{event.mode === 'refresh' ? '刷新授权' : sources[event.source] || '登录'}</td><td>{statuses[event.status] || event.status}</td><td>{date(event.completedAt)}</td></tr>)}</tbody></table></div>}
        {data.history.pages > 1 && <div className="dialog-footer"><button className="secondary-button" disabled={page === 1} onClick={() => setPage(page - 1)}>上一页</button><span>{data.history.page} / {data.history.pages}</span><button className="secondary-button" disabled={page === data.history.pages} onClick={() => setPage(page + 1)}>下一页</button></div>}
      </section>
    </>}
  </dialog>, document.body);
}
