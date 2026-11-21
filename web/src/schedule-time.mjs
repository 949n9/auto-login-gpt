const BJT_OFFSET_MS = 8 * 60 * 60_000;

// Scheduled tasks use fixed UTC+8. Format the shifted UTC components directly:
// browser locale/timezone overrides must not relabel a UTC instant as Beijing.
export function formatScheduleBjt(value) {
  if (!value) return "—";
  const instant = new Date(value).getTime();
  if (!Number.isFinite(instant)) return "时间待确认";
  const shifted = new Date(instant + BJT_OFFSET_MS);
  if (!Number.isFinite(shifted.getTime())) return "时间待确认";
  const iso = shifted.toISOString();
  return `${iso.slice(0, 10).replaceAll("-", "/")} ${iso.slice(11, 19)} 北京时间`;
}

export function scheduleLocalToIso(value) {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?$/.test(String(value))) return null;
  const date = new Date(`${value.length === 16 ? value + ":00" : value}+08:00`);
  if (!Number.isFinite(date.getTime())) return null;
  const local = new Date(date.getTime() + BJT_OFFSET_MS).toISOString().slice(0, value.length);
  return local === value ? date.toISOString() : null;
}

export function defaultScheduleTime() {
  return new Date(Date.now() + 2 * 60 * 60_000 + BJT_OFFSET_MS).toISOString().slice(0, 16);
}
