import assert from "node:assert/strict";
import test from "node:test";
import { formatScheduleBjt, scheduleLocalToIso } from "../web/src/schedule-time.mjs";
import { normalizeSchedule } from "../src/scheduled-tasks.mjs";

test("the user's 06:00 Beijing input displays 05:30 preparation and 06:00 execution", () => {
  const input = "2026-11-13T06:00";
  const schedule = normalizeSchedule({ scheduledLocal: input, securityAction: "logout-all", prepareLeadMinutes: 30 });
  assert.equal(scheduleLocalToIso(input), schedule.plannedAt);
  assert.equal(schedule.plannedAt, "2026-11-12T22:00:00.000Z");
  assert.equal(formatScheduleBjt(schedule.plannedAt), "2026/11/13 06:00:00 北京时间");
  assert.equal(formatScheduleBjt(schedule.prepareAt), "2026/11/13 05:30:00 北京时间");
});

test("display is unchanged across host timezones and midnight/year/leap-day boundaries", () => {
  const previous = process.env.TZ;
  try {
    for (const zone of ["UTC", "America/Detroit", "Asia/Shanghai", "Pacific/Auckland"]) {
      process.env.TZ = zone;
      for (const [local, expected] of [
        ["2026-11-13T06:00", "2026/11/13 06:00:00 北京时间"],
        ["2027-01-01T00:15", "2027/01/01 00:15:00 北京时间"],
        ["2028-02-29T00:00:01", "2028/02/29 00:00:01 北京时间"],
      ]) assert.equal(formatScheduleBjt(scheduleLocalToIso(local)), expected, zone);
    }
  } finally { if (previous === undefined) delete process.env.TZ; else process.env.TZ = previous; }
});

test("a browser override that ignores Intl timeZone cannot shift the displayed plan", () => {
  const Original = Intl.DateTimeFormat;
  try {
    Intl.DateTimeFormat = class extends Original {
      constructor(locale, options) { super(locale, { ...options, timeZone: "UTC" }); }
    };
    const instant = scheduleLocalToIso("2026-11-13T06:00");
    const oldFormatter = new Intl.DateTimeFormat("zh-CN", { timeZone: "Asia/Shanghai", hour: "2-digit", hourCycle: "h23" });
    assert.equal(oldFormatter.formatToParts(new Date(instant)).find((part) => part.type === "hour").value, "22", "fixture reproduces the wrong UTC hour");
    assert.equal(formatScheduleBjt(instant), "2026/11/13 06:00:00 北京时间");
  } finally { Intl.DateTimeFormat = Original; }
});

test("invalid input is rejected instead of rolling into another date", () => {
  for (const value of ["2026-02-29T06:00", "2026-11-13T25:00", "invalid", ""]) assert.equal(scheduleLocalToIso(value), null);
  assert.equal(formatScheduleBjt("invalid"), "时间待确认");
  assert.equal(formatScheduleBjt(null), "—");
});
