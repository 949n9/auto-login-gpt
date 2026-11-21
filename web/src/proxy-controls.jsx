import { DynamicProxyEditor } from "./dynamic-proxy-controls.jsx";
import React, { useEffect, useState } from "react";
import { Check, CircleAlert, Globe2, LoaderCircle, Plus, Settings2, Trash2, X } from "lucide-react";

export const PROXY_LIBRARY_STORAGE_KEY = "chatgpt-onboarding.proxy-library-v1";
export const LEGACY_PROXY_STORAGE_KEY = "chatgpt-onboarding.account-proxy-v1";
export const DEFAULT_OPERATION_PROXY_ID = "__server_default__";

export function operationProxySelection(id, defaultOperationProxy) {
  return id || (defaultOperationProxy?.configured ? DEFAULT_OPERATION_PROXY_ID : "");
}
let proxyIdCounter = 0;

function createProxyId() {
  if (typeof globalThis.crypto?.randomUUID === "function") return globalThis.crypto.randomUUID();
  proxyIdCounter += 1;
  return `proxy-${Date.now().toString(36)}-${proxyIdCounter.toString(36)}-${Math.random().toString(36).slice(2)}`;
}

export function normalizeProxyAddress(value) {
  const text = String(value || "").trim();
  let parsed;
  try { parsed = new URL(text); } catch { throw new Error("请输入完整的代理地址"); }
  if (!["http:", "https:", "socks5:", "socks5h:"].includes(parsed.protocol) || !parsed.hostname) {
    throw new Error("代理地址只支持 http、https、socks5 和 socks5h");
  }
  return parsed.toString();
}

export function proxyEndpoint(value) {
  try {
    const parsed = new URL(value);
    return `${parsed.protocol}//${parsed.hostname}${parsed.port ? `:${parsed.port}` : ""}`;
  } catch { return "代理地址无效"; }
}

export function normalizeProxyState(stored) {
    if (stored && Array.isArray(stored.proxies)) {
      const ids = new Set();
      const proxies = stored.proxies.flatMap((entry) => {
        if (!entry || typeof entry.id !== "string" || !entry.id || entry.id === "direct" || ids.has(entry.id)) return [];
        if (typeof entry.dynamicProfileId === "string" && entry.dynamicProfileId) {
          ids.add(entry.id);
          return [{ id: entry.id, name: String(entry.name || "动态住宅代理"), dynamicProfileId: entry.dynamicProfileId }];
        }
        try {
          const url = normalizeProxyAddress(entry.url);
          ids.add(entry.id);
          return [{ id: entry.id, name: String(entry.name || "未命名代理"), url }];
        } catch { return []; }
      });
      return { proxies, selectedId: typeof stored.selectedId === "string" ? stored.selectedId : "" };
    }
  return { proxies: [], selectedId: "" };
}

export function readProxyState() {
  try {
    const stored = JSON.parse(localStorage.getItem(PROXY_LIBRARY_STORAGE_KEY) || "null");
    if (stored && Array.isArray(stored.proxies)) return normalizeProxyState(stored);
    let legacy = (localStorage.getItem(LEGACY_PROXY_STORAGE_KEY) || "").trim();
    for (let attempt = 0; attempt < 4 && legacy.startsWith('"') && legacy.endsWith('"'); attempt += 1) {
      try {
        const decoded = JSON.parse(legacy);
        if (typeof decoded !== "string") break;
        legacy = decoded.trim();
      } catch { break; }
    }
    if (legacy.trim()) {
      const proxy = { id: "migrated-proxy", name: "原代理", url: normalizeProxyAddress(legacy) };
      return { proxies: [proxy], selectedId: proxy.id };
    }
  } catch {}
  return { proxies: [], selectedId: "" };
}

export function selectedProxyUrl(id, proxies, defaultOperationProxy) {
  if (operationProxySelection(id, defaultOperationProxy) === DEFAULT_OPERATION_PROXY_ID && defaultOperationProxy?.configured) return { useDefaultProxy: true };
  if (id === "direct") return "";
  const proxy = proxies.find((entry) => entry.id === id);
  if (!proxy) throw new Error("请选择登录代理，或明确选择直连");
  return proxy.dynamicProfileId ? { dynamicProfileId: proxy.dynamicProfileId } : proxy.url;
}

export function ProxySelect({ proxies, value, onChange, label, disabled = false, id, defaultOperationProxy }) {
  const missing = value && value !== "direct" && !(value === DEFAULT_OPERATION_PROXY_ID && defaultOperationProxy?.configured) && !proxies.some((proxy) => proxy.id === value);
  return (
    <select id={id} className="proxy-select" value={value} onChange={(event) => onChange(event.target.value)} aria-label={label} aria-invalid={Boolean(missing)} disabled={disabled}>
      <option value="">请选择代理</option>
      {defaultOperationProxy?.configured && <option value={DEFAULT_OPERATION_PROXY_ID}>{defaultOperationProxy.label || "默认美国动态住宅代理"}</option>}
      {missing && <option value={value}>原代理已删除，请重新选择</option>}
      <option value="direct">直连（不使用代理）</option>
      {proxies.map((proxy) => <option key={proxy.id} value={proxy.id}>{proxy.name} · {proxy.dynamicProfileId ? "动态住宅 · 按账号分配" : proxyEndpoint(proxy.url)}</option>)}
    </select>
  );
}

export function ProxyAssignments({ accounts, assignments, onChange, proxies, defaultProxyId, onManage, defaultOperationProxy }) {
  const [applyId, setApplyId] = useState(defaultOperationProxy?.configured ? DEFAULT_OPERATION_PROXY_ID : defaultProxyId || "");
  const isResolved = (id) => operationProxySelection(id, defaultOperationProxy) === DEFAULT_OPERATION_PROXY_ID && defaultOperationProxy?.configured || id === "direct" || proxies.some((proxy) => proxy.id === id);
  const canApply = isResolved(applyId);
  const eligibleAccounts = accounts.filter((account) => !account.skipped);
  const resolved = eligibleAccounts.filter((account) => isResolved(assignments[account.key])).length;
  return (
    <section className="proxy-assignments" aria-label="逐个账号选择代理">
      <div className="proxy-assignment-heading">
        <div><h3>选择登录代理</h3><p>{defaultOperationProxy?.configured ? "未另行指定时使用默认美国动态住宅代理，也可逐个修改。" : "每个账号手动选择一条代理，也可以统一使用同一条。"}</p></div>
        <span>{resolved} / {eligibleAccounts.length} 已选择</span>
      </div>
      <div className="proxy-apply-all">
        <ProxySelect proxies={proxies} value={applyId} onChange={setApplyId} label="统一使用的代理" defaultOperationProxy={defaultOperationProxy} />
        <button type="button" className="secondary-button" disabled={!canApply} onClick={() => onChange(Object.fromEntries(accounts.map((account) => [account.key, account.skipped ? "direct" : applyId])))}>应用到全部</button>
        <button type="button" className="selection-text-button" onClick={onManage}><Settings2 size={14} />管理代理</button>
      </div>
      <div className="proxy-assignment-list">
        {accounts.map((account, index) => (
          <div className={`proxy-assignment-row ${account.skipped ? "is-skipped" : ""}`} key={account.key}>
            <div className="proxy-account-label"><span className="proxy-row-number">{index + 1}</span><div><strong>{account.email}</strong>{account.skipped ? <small>本次不符合条件，将跳过</small> : account.currentEndpoint ? <small>当前：{account.currentEndpoint}</small> : null}</div></div>
            {account.skipped ? <span className="proxy-skip-label">跳过此账号</span> : <ProxySelect proxies={proxies} value={operationProxySelection(assignments[account.key], defaultOperationProxy)} onChange={(value) => onChange({ ...assignments, [account.key]: value })} label={`为 ${account.email} 选择代理`} defaultOperationProxy={defaultOperationProxy} />}
          </div>
        ))}
      </div>
    </section>
  );
}

export function ProxyManager({ proxies, onSave, onClose, request }) {
  const [items, setItems] = useState(proxies);
  const [editingId, setEditingId] = useState(null);
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [showUrl, setShowUrl] = useState(false);
  const [bulkText, setBulkText] = useState("");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  useEffect(() => setItems(proxies), [proxies]);
  const resetEditor = () => { setEditingId(null); setName(""); setUrl(""); setShowUrl(false); setError(""); };
  function saveEntry(event) {
    event.preventDefault();
    try {
      const normalized = normalizeProxyAddress(url);
      if (items.some((entry) => entry.id !== editingId && entry.url === normalized)) throw new Error("这条代理已在列表中");
      if (!editingId && items.length >= 500) throw new Error("最多保存 500 条代理");
      const entry = { id: editingId || createProxyId(), name: name.trim() || `代理 ${items.length + 1}`, url: normalized };
      setItems((current) => editingId ? current.map((item) => item.id === editingId ? entry : item) : [...current, entry]);
      resetEditor();
    } catch (failure) { setError(failure.message); }
  }
  function importEntries() {
    try {
      const lines = bulkText.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
      if (!lines.length) throw new Error("请先输入代理地址，每行一条");
      if (items.length + lines.length > 500) throw new Error("最多保存 500 条代理");
      const known = new Set(items.map((entry) => entry.url));
      const imported = lines.map((line, index) => {
        const separator = /^(?:https?|socks5h?):\/\//i.test(line) ? -1 : line.indexOf("----");
        const normalized = normalizeProxyAddress(separator < 0 ? line : line.slice(separator + 4));
        if (known.has(normalized)) throw new Error(`第 ${index + 1} 行代理重复`);
        known.add(normalized);
        return { id: createProxyId(), name: (separator < 0 ? "" : line.slice(0, separator).trim()) || `代理 ${items.length + index + 1}`, url: normalized };
      });
      setItems((current) => [...current, ...imported]);
      setBulkText(""); setError("");
    } catch (failure) { setError(failure.message); }
  }
  async function saveList() {
    if (saving) return;
    if (url.trim() || bulkText.trim()) { setError("还有未添加的代理，请先添加到列表或清空输入"); return; }
    setSaving(true);
    setError("");
    try { await onSave(items); } catch (failure) { setError(failure.message || "保存代理列表失败，请重试"); }
    finally { setSaving(false); }
  }
  return (
    <div className="modal-backdrop proxy-manager-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !saving) onClose(); }}>
      <section className="batch-dialog proxy-manager-dialog" role="dialog" aria-modal="true" aria-labelledby="proxy-manager-title">
        <fieldset className="proxy-manager-fields" disabled={saving}>
        <div className="dialog-header"><div><h2 id="proxy-manager-title">代理列表</h2><span>{items.length} 条代理</span></div><button type="button" className="icon-button" onClick={onClose} title="关闭代理列表"><X size={18} /></button></div>
        <p className="proxy-manager-intro">先保存代理，登录时再按账号选择。列表保存在服务器，不同电脑共用。</p>
        <div className="proxy-library-list">
          {items.length ? items.map((proxy) => <div className="proxy-library-row" key={proxy.id}><Globe2 size={17} /><div><strong>{proxy.name}</strong><span>{proxy.dynamicProfileId ? "动态住宅 · 按账号分配" : proxyEndpoint(proxy.url)}</span></div><button type="button" className="selection-text-button" disabled={Boolean(proxy.dynamicProfileId)} onClick={() => { setEditingId(proxy.id); setName(proxy.name); setUrl(proxy.url); setShowUrl(false); setError(""); }}>编辑</button><button type="button" className="icon-button" aria-label={`删除代理 ${proxy.name}`} onClick={() => { setItems((current) => current.filter((entry) => entry.id !== proxy.id)); if (editingId === proxy.id) resetEditor(); }}><Trash2 size={16} /></button></div>) : <div className="proxy-library-empty"><Globe2 size={24} /><strong>还没有代理</strong><span>添加一条，或一次导入多条代理地址。</span></div>}
        </div>
        <form className="proxy-editor" onSubmit={saveEntry}>
          <h3>{editingId ? "编辑代理" : "添加代理"}</h3>
          <label>名称<input value={name} onChange={(event) => setName(event.target.value)} maxLength={80} placeholder="例如：香港 01" aria-label="代理名称" /></label>
          <label>代理地址<div className="proxy-url-editor"><input type={showUrl ? "text" : "password"} value={url} onChange={(event) => setUrl(event.target.value)} placeholder="socks5h://用户名:密码@主机:端口" aria-label="代理地址" autoComplete="new-password" spellCheck="false" /><button type="button" className="selection-text-button" onClick={() => setShowUrl((current) => !current)}>{showUrl ? "隐藏" : "显示"}</button></div></label>
          <div className="proxy-editor-actions">{editingId && <button type="button" className="cancel-button" onClick={resetEditor}>取消编辑</button>}<button type="submit" className="secondary-button" disabled={!url.trim()}><Plus size={15} />{editingId ? "更新代理" : "添加到列表"}</button></div>
        </form>
        <details className="proxy-bulk-import"><summary>批量导入代理</summary><label htmlFor="proxy-bulk-input">每行一条代理地址，也支持「名称----代理地址」。</label><textarea id="proxy-bulk-input" value={bulkText} onChange={(event) => setBulkText(event.target.value)} placeholder={"香港 01----socks5h://user:password@proxy.example.com:1080\nhttp://proxy.example.net:8080"} spellCheck="false" /><button type="button" className="secondary-button" onClick={importEntries} disabled={!bulkText.trim()}><Plus size={15} />导入到列表</button></details>
        <DynamicProxyEditor request={request} onAdded={(entry) => setItems((current) => [...current.filter((value) => value.id !== entry.id), entry])} />
        {error && <div className="dialog-error" role="alert"><CircleAlert size={15} />{error}</div>}
        <div className="dialog-footer"><button type="button" className="cancel-button" onClick={onClose}>取消</button><button type="button" className="primary-button" onClick={saveList}>{saving ? <LoaderCircle className="spin" size={16} /> : <Check size={16} />}{saving ? "正在保存…" : "保存列表"}</button></div>
        </fieldset>
      </section>
    </div>
  );
}
