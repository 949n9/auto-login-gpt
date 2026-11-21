import test from "node:test";
import assert from "node:assert/strict";
import { pauseBeforeOperation } from "../src/operation-pacing.mjs";

test("pacing samples 2–5 seconds and awaits the timer before continuing", async () => {
  for (const duration of [2_000, 5_000]) {
    let release;
    let continued = false;
    const logs = [];
    const operation = pauseBeforeOperation("rotate_totp", {
      sample(min, max) { assert.equal(min, 2_000); assert.equal(max, 5_001); return duration; },
      wait(ms) { assert.equal(ms, duration); return new Promise((resolve) => { release = resolve; }); },
      log(line) { logs.push(line); },
    }).then(() => { continued = true; });
    await Promise.resolve();
    assert.equal(continued, false);
    release();
    await operation;
    assert.equal(continued, true);
    assert.deepEqual(logs, [`[step-delay] rotate_totp: ${duration}ms`]);
  }
});
