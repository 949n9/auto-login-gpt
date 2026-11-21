const REASONS = new Set(["EMAIL_OTP_REQUIRED", "EMAIL_OTP_TIMEOUT", "EMAIL_OTP_REJECTED"]);

export function emailChallengeError(reason) {
  if (!REASONS.has(reason)) throw new Error("Unknown email challenge reason");
  return Object.assign(new Error(reason), { code: reason });
}

export function createEmailLoginRetry({ totpSecret, env = process.env, emit = console.log,
  wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms)), now = Date.now,
  setTimer = setTimeout, clearTimer = clearTimeout } = {}) {
  const enabled = env.TOSUB2_EMAIL_CHALLENGE_RETRY === "1" && Boolean(totpSecret);
  const available = env.TOSUB2_EMAIL_OTP_AVAILABLE === "1";
  const configuredTimeout = Number(env.TOSUB2_EMAIL_OTP_TIMEOUT_MS || 90000);
  const timeoutMs = Number.isSafeInteger(configuredTimeout) && configuredTimeout > 0 ? configuredTimeout : 90000;
  const maxAttempts = 3;
  let attempts = 0;
  let lastReason = null;
  let failureReported = false;
  const marker = (name, value) => emit(`[${name}] ${JSON.stringify(value)}`);
  const finalFailure = () => {
    if (!failureReported) { marker("email-login-failed", { attempts, reason: lastReason || "EMAIL_OTP_REQUIRED" }); failureReported = true; }
    return emailChallengeError(lastReason || "EMAIL_OTP_REQUIRED");
  };
  return {
    enabled,
    get attempts() { return attempts; },
    async run(login, { beforeAttempt = async () => {} } = {}) {
      if (!enabled) return login();
      if (attempts >= maxAttempts) throw finalFailure();
      for (;;) {
        await beforeAttempt(attempts);
        attempts += 1;
        marker("email-login-attempt", { attempt: attempts, maxAttempts });
        try { return await login(); }
        catch (error) {
          // Only these explicit challenge outcomes may restart login. HTTP 429,
          // password, network, MFA and all other errors propagate immediately.
          if (!REASONS.has(error?.code) || error?.httpStatus === 429 || error?.status === 429) throw error;
          lastReason = error.code;
          if (attempts >= maxAttempts) throw finalFailure();
          const delayMs = attempts * 1000;
          marker("email-login-retry", { attempt: attempts, maxAttempts, reason: lastReason, delayMs });
          await wait(delayMs);
        }
      }
    },
    beginChallenge() {
      if (!enabled) return null;
      if (!available) throw emailChallengeError("EMAIL_OTP_REQUIRED");
      const deadline = now() + timeoutMs;
      return {
        async question(rl, prompt) {
          const remaining = deadline - now();
          if (remaining <= 0) throw emailChallengeError("EMAIL_OTP_TIMEOUT");
          const controller = new AbortController();
          const timer = setTimer(() => controller.abort(), remaining);
          try { return String(await rl.question(prompt, { signal: controller.signal })).trim(); }
          catch (error) {
            if (controller.signal.aborted && error?.name === "AbortError") throw emailChallengeError("EMAIL_OTP_TIMEOUT");
            throw error;
          } finally { clearTimer(timer); }
        },
        reject() { throw emailChallengeError("EMAIL_OTP_REJECTED"); },
      };
    },
  };
}
