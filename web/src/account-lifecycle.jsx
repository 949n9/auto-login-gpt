import React, { useEffect, useState } from "react";

export function accountTermLabel(value) {
  return value === "long" ? "长效" : value === "short" ? "短效" : "未设置";
}

export function formatRestingDuration(since, now = Date.now()) {
  if (!since) return "时间未记录";
  const timestamp = new Date(since).getTime();
  if (!Number.isFinite(timestamp)) return "时间未记录";
  const minutes = Math.max(0, Math.floor((now - timestamp) / 60_000));
  if (!minutes) return "不足 1 分钟";
  const days = Math.floor(minutes / 1440);
  const hours = Math.floor((minutes % 1440) / 60);
  const remaining = minutes % 60;
  return [days ? `${days} 天` : "", hours ? `${hours} 小时` : "", remaining ? `${remaining} 分钟` : ""].filter(Boolean).join(" ");
}

export function AccountTermSelect({ value, onChange, label, disabled = false, unknown = false, className = "" }) {
  return <label className={`account-term-control ${className}`}><span className="sr-only">{label}</span><select aria-label={label} value={value || ""} onChange={(event) => onChange(event.target.value)} disabled={disabled} className={`account-term-${value || "unknown"}`}>
    {unknown && !value && <option value="" disabled>未设置</option>}
    <option value="long">长效</option><option value="short">短效</option>
  </select></label>;
}

export function AccountAreaTabs({ area, counts, onChange, disabled = false }) {
  return <nav className="account-area-tabs" aria-label="账号区域">{[["active", "在用账号"], ["resting", "静置区"], ["retired", "废号区"], ["all", "全部账号"]].map(([value, label]) => <button type="button" key={value} aria-pressed={area === value} className={area === value ? "is-selected" : ""} onClick={() => onChange(value)} disabled={disabled}>{label}<span>{counts[value] || 0}</span></button>)}</nav>;
}

export function RestingStatus({ job }) {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 30_000);
    return () => window.clearInterval(timer);
  }, []);
  const uncertain = job.restingReason === "logout_requested";
  const manual = job.restingReason === "manual";
  const started = job.restingSince ? new Date(job.restingSince).toLocaleString("zh-CN", { hour12: false }) : "未记录";
  return <span className={`account-resting-status ${uncertain ? "is-uncertain" : ""}`} title={`${manual ? "手动静置时间" : "退出请求时间"}：${started}${uncertain ? "；请求结果待核实" : ""}`}>
    {manual ? "已静置" : uncertain ? "退出待核实" : "已退出"} · {formatRestingDuration(job.restingSince, now)}
    <time dateTime={job.restingSince || undefined}>{manual ? "静置时间" : "退出时间"}：{started}</time>
  </span>;
}

export function RetiredStatus({ job }) {
  const retiredAt = job.retiredAt ? new Date(job.retiredAt).toLocaleString("zh-CN", { hour12: false }) : "未记录";
  return <span className="account-retired-status">已作废<time dateTime={job.retiredAt || undefined}>作废时间：{retiredAt}</time><span className="account-retired-reason">原因：{job.retiredReason || "未记录"}</span></span>;
}
