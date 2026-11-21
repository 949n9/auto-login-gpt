import React, { useEffect, useState } from "react";

const newProfile = () => ({ name: "", protocol: "", country: "US", state: "New York", city: "", ips: "", key: "", enabled: true });
const locationLabel = (profile) => [profile.country, profile.state, profile.city].filter(Boolean).join(" / ");

export function DynamicProxyEditor({ request, onAdded }) {
  const [profiles, setProfiles] = useState([]);
  const [bindings, setBindings] = useState([]);
  const [enabled, setEnabled] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [draft, setDraft] = useState(newProfile);
  const [editing, setEditing] = useState(null);
  const [reconciling, setReconciling] = useState(null);
  const [recoveredUrl, setRecoveredUrl] = useState("");
  const [notExtracted, setNotExtracted] = useState(false);
  const [historyChecked, setHistoryChecked] = useState(false);
  useEffect(() => { let active = true; request("/api/dynamic-proxies").then((data) => { if (active) { setProfiles(data.profiles); setBindings(data.bindings); setEnabled(data.extractionEnabled); } }).catch((e) => { if (active) setError(e.message); }); return () => { active = false; }; }, [request]);
  function field(name, value) { setDraft((current) => ({ ...current, [name]: value })); }
  async function save(event) {
    event.preventDefault(); setBusy(true); setError("");
    try {
      const id = editing?.id || crypto.randomUUID();
      const value = { ...draft, id };
      if (editing && !value.key) delete value.key;
      const profile = await request("/api/dynamic-proxies", { method: "POST", body: JSON.stringify({ action: "saveProfile", profile: value, revision: editing?.revision || 0 }) });
      setProfiles((current) => [...current.filter((p) => p.id !== id), profile]);
      onAdded({ id: `dyn_${id}`, name: profile.name, dynamicProfileId: id });
      setEditing(null); setDraft(newProfile());
    } catch (e) { setError(e.message); } finally { setBusy(false); }
  }
  async function reconcile(event) {
    event.preventDefault(); setBusy(true); setError("");
    try {
      const updated = await request("/api/dynamic-proxies", { method: "POST", body: JSON.stringify({ action: "reconcile", email: reconciling.email, revision: reconciling.revision, proxyUrl: notExtracted ? null : recoveredUrl.trim(), confirm: "checked_provider_history" }) });
      setBindings((current) => current.map((value) => value.id === updated.id ? updated : value));
      setReconciling(null); setRecoveredUrl("");
    } catch (e) { setError(e.message); } finally { setBusy(false); }
  }
  const states = { empty: "等待首次使用", ready: "可用", sent: "提取结果待核对", unknown: "提取结果待核对", candidate: "等待同步", unreachable: "代理不可达", verifying: "等待额度与质量检查" };
  const regionPreset = draft.country.toUpperCase() === "US" && draft.state === "New York" && !draft.city ? "new-york" : "custom";
  return <details className="proxy-bulk-import">
    <summary>动态住宅代理</summary>
    <p>每个账号独立绑定，使用时才提取，失效后检查额度与质量再恢复</p>
    {!enabled && <p role="status">真实提取尚未启用，保存配置不会提取 IP</p>}
    <div className="proxy-library-list">{profiles.map((profile) => <div className="proxy-library-row" key={profile.id}><div><strong>{profile.name}</strong><span>{locationLabel(profile)} · {profile.protocol} · {profile.enabled ? "已配置" : "已暂停"}</span></div><button type="button" className="selection-text-button" onClick={() => { setEditing(profile); setDraft({ ...profile, key: "" }); }}>编辑</button><button type="button" className="selection-text-button" onClick={() => onAdded({ id: `dyn_${profile.id}`, name: profile.name, dynamicProfileId: profile.id })}>加入列表</button></div>)}</div>
    <form className="proxy-editor" onSubmit={save}>
      <label>名称<input value={draft.name} onChange={(e) => field("name", e.target.value)} maxLength={80} required /></label>
      <label>协议<select className="proxy-select" value={draft.protocol} onChange={(e) => field("protocol", e.target.value)} required><option value="">选择供应商提供的协议</option><option value="http">HTTP</option><option value="https">HTTPS</option><option value="socks5h">SOCKS5（远程 DNS）</option></select></label>
      <label>提取地区<select className="proxy-select" value={regionPreset} onChange={(e) => setDraft((current) => ({ ...current, ...(e.target.value === "new-york" ? { country: "US", state: "New York", city: "" } : { state: "", city: "" }) }))}><option value="new-york">美国 · 纽约州（优先）</option><option value="custom">自定义国家／州／城市</option></select></label>
      <label>国家代码<input value={draft.country} onChange={(e) => field("country", e.target.value)} maxLength={2} placeholder="例如 US" required /></label>
      <label>州／地区（可选，英文名称）<input value={draft.state} onChange={(e) => field("state", e.target.value)} placeholder="例如 New York" maxLength={128} /></label>
      <label>城市（可选，英文名称）<input value={draft.city} onChange={(e) => field("city", e.target.value)} placeholder="留空表示州内不限城市" maxLength={128} /></label>
      <label>服务器出口白名单（可选）<input value={draft.ips} onChange={(e) => field("ips", e.target.value)} maxLength={256} /></label>
      <label>1024proxy 密钥<input type="password" value={draft.key} onChange={(e) => field("key", e.target.value)} autoComplete="new-password" placeholder={editing ? "留空保留原密钥" : ""} required={!editing} /></label>
      <label className="proxy-check-field"><input type="checkbox" checked={draft.enabled} onChange={(e) => field("enabled", e.target.checked)} />允许按需续换</label>
      <div className="proxy-editor-actions"><button type="submit" className="secondary-button" disabled={busy}>{busy ? "保存中…" : "保存动态配置"}</button></div>
    </form>
    <p>续换沿用所选地区，不自动放宽范围。修改地区从下次提取生效，已提取的代理继续复用；同一配置下的账号使用相同地区设置</p>
    {bindings.length > 0 && <div className="proxy-library-list">{bindings.map((binding) => <div className="proxy-library-row" key={binding.id}><div><strong>{binding.email}</strong><span>{binding.blockedReason || states[binding.status] || binding.status} · 提取请求 {binding.extractionCount} 次</span><span>{locationLabel(profiles.find((profile) => profile.id === binding.profileId) || {})}</span></div>{["sent", "unknown"].includes(binding.status) && <button type="button" className="selection-text-button" onClick={() => { setReconciling(binding); setRecoveredUrl(""); setNotExtracted(false); setHistoryChecked(false); }}>核对结果</button>}</div>)}</div>}
    {reconciling && <form className="proxy-editor" onSubmit={reconcile}>
      <h3>核对 {reconciling.email}</h3>
      <p>查看供应商提取记录；如果已经分配 IP，填入该代理以继续同步</p>
      <label className="proxy-check-field"><input type="checkbox" checked={notExtracted} onChange={(e) => setNotExtracted(e.target.checked)} />供应商确认本次未分配 IP</label>
      {!notExtracted && <label>已分配的代理地址<input type="password" value={recoveredUrl} onChange={(e) => setRecoveredUrl(e.target.value)} placeholder="协议://用户名:密码@主机:端口" autoComplete="new-password" required /></label>}
      <label className="proxy-check-field"><input type="checkbox" checked={historyChecked} onChange={(e) => setHistoryChecked(e.target.checked)} />已核对供应商记录</label>
      <div className="proxy-editor-actions"><button type="button" className="cancel-button" onClick={() => setReconciling(null)}>取消</button><button type="submit" className="secondary-button" disabled={busy || !historyChecked}>{busy ? "保存中…" : "保存核对结果"}</button></div>
    </form>}
    {error && <div className="dialog-error" role="alert">{error}</div>}
  </details>;
}
