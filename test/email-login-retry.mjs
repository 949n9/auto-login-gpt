import assert from "node:assert/strict";
import readline from "node:readline/promises";
import { PassThrough } from "node:stream";
import test from "node:test";
import { createEmailLoginRetry, emailChallengeError } from "../src/email-login-retry.mjs";

const enabledEnv = { TOSUB2_EMAIL_CHALLENGE_RETRY: "1", TOSUB2_EMAIL_OTP_AVAILABLE: "1", TOSUB2_EMAIL_OTP_TIMEOUT_MS: "20" };
function fixture(options = {}) {
  const events = [], delays = [];
  const retry = createEmailLoginRetry({ totpSecret: "test-secret", env: enabledEnv, emit: (line) => events.push(line), wait: async (ms) => delays.push(ms), ...options });
  return { retry, events, delays, markers: (name) => events.filter((line) => line.startsWith(`[${name}]`)).map((line) => JSON.parse(line.slice(line.indexOf("]") + 1))) };
}

test("only a saved TOTP plus the explicit environment switch enables retries", async () => {
  for (const options of [{ totpSecret: "" }, { env: { ...enabledEnv, TOSUB2_EMAIL_CHALLENGE_RETRY: "0" } }]) {
    const f = fixture(options); let calls = 0;
    await assert.rejects(f.retry.run(async () => { calls += 1; throw emailChallengeError("EMAIL_OTP_REQUIRED"); }));
    assert.equal(calls, 1); assert.equal(f.retry.enabled, false); assert.equal(f.events.length, 0);
  }
});

test("exactly three fresh attempts share bounded delays and one final reason", async () => {
  const f = fixture(); let calls = 0; const previousAttempts = [];
  await assert.rejects(f.retry.run(async () => { calls += 1; throw emailChallengeError("EMAIL_OTP_REJECTED"); }, { beforeAttempt: async (previous) => previousAttempts.push(previous) }), { code: "EMAIL_OTP_REJECTED" });
  assert.equal(calls, 3);
  assert.deepEqual(previousAttempts, [0, 1, 2]);
  assert.deepEqual(f.delays, [1000, 2000]);
  assert.deepEqual(f.markers("email-login-attempt"), [1, 2, 3].map((attempt) => ({ attempt, maxAttempts: 3 })));
  assert.deepEqual(f.markers("email-login-failed"), [{ attempts: 3, reason: "EMAIL_OTP_REJECTED" }]);
  await assert.rejects(f.retry.run(async () => { calls += 1; }));
  assert.equal(calls, 3); assert.equal(f.markers("email-login-failed").length, 1);
});

test("success on attempt two leaves only one attempt for a later Codex fallback", async () => {
  const f = fixture(); let calls = 0;
  assert.equal(await f.retry.run(async () => { calls += 1; if (calls === 1) throw emailChallengeError("EMAIL_OTP_TIMEOUT"); return "session"; }), "session");
  assert.equal(calls, 2);
  await assert.rejects(f.retry.run(async () => { calls += 1; throw emailChallengeError("EMAIL_OTP_REQUIRED"); }), { code: "EMAIL_OTP_REQUIRED" });
  assert.equal(calls, 3);
  assert.deepEqual(f.markers("email-login-failed"), [{ attempts: 3, reason: "EMAIL_OTP_REQUIRED" }]);
});

test("non-email errors and 429 propagate without another attempt", async () => {
  for (const error of [new Error("HTTP 403 forbidden"), new Error("invalid password"), new Error("SOCKS connection failed"), Object.assign(emailChallengeError("EMAIL_OTP_REJECTED"), { httpStatus: 429 })]) {
    const f = fixture(); let calls = 0;
    await assert.rejects(f.retry.run(async () => { calls += 1; throw error; }), (received) => received === error);
    assert.equal(calls, 1); assert.equal(f.delays.length, 0); assert.equal(f.markers("email-login-retry").length, 0);
  }
});

test("missing mailbox API fails the challenge without asking for manual input", () => {
  const f = fixture({ env: { ...enabledEnv, TOSUB2_EMAIL_OTP_AVAILABLE: "0" } });
  assert.throws(() => f.retry.beginChallenge(), { code: "EMAIL_OTP_REQUIRED" });
});

test("readline timeout aborts its question and clears timers before a new prompt", async () => {
  const input = new PassThrough(), output = new PassThrough();
  const rl = readline.createInterface({ input, output });
  const timers = new Set();
  const f = fixture({
    setTimer(callback, ms) { const timer = setTimeout(callback, ms); timers.add(timer); return timer; },
    clearTimer(timer) { clearTimeout(timer); timers.delete(timer); },
  });
  try {
    await assert.rejects(f.retry.beginChallenge().question(rl, "first code: "), { code: "EMAIL_OTP_TIMEOUT" });
    assert.equal(timers.size, 0);
    const answer = f.retry.beginChallenge().question(rl, "second code: ");
    input.write("123456\n");
    assert.equal(await answer, "123456");
    assert.equal(timers.size, 0);
    // No abandoned first prompt may consume a third prompt's reply.
    const third = rl.question("third: "); input.write("fresh\n"); assert.equal(await third, "fresh");
  } finally { rl.close(); input.destroy(); output.destroy(); }
});

test("invalid input cannot reset the deadline and rejected codes end their attempt", async () => {
  let now = 0;
  const f = fixture({ now: () => now });
  const challenge = f.retry.beginChallenge();
  assert.equal(await challenge.question({ question: async () => "bad" }, "code: "), "bad");
  now = 21;
  await assert.rejects(challenge.question({ question: async () => "123456" }, "code: "), { code: "EMAIL_OTP_TIMEOUT" });
  assert.throws(() => challenge.reject(), { code: "EMAIL_OTP_REJECTED" });
});

test("a post-login security failure remains outside the login retry budget", async () => {
  const f = fixture(); let logins = 0, mutations = 0;
  const operation = async () => {
    await f.retry.run(async () => { logins += 1; if (logins === 1) throw emailChallengeError("EMAIL_OTP_REQUIRED"); return "session"; });
    mutations += 1;
    throw emailChallengeError("EMAIL_OTP_REJECTED");
  };
  await assert.rejects(operation(), { code: "EMAIL_OTP_REJECTED" });
  assert.equal(logins, 2); assert.equal(mutations, 1); assert.equal(f.retry.attempts, 2);
});
