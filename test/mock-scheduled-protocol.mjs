import fs from "node:fs/promises";
import path from "node:path";
import assert from "node:assert/strict";
import { createServerDatabase } from "../src/server-database.mjs";
const arg = (name) => process.argv[process.argv.indexOf(name) + 1];
const email = arg("--email");
const action = process.argv.includes("--security-action") ? arg("--security-action") : null;
const now = new Date().toISOString();
assert.match(process.env.CHATGPT_PROXY_URL, /^socks5h?:\/\//);
assert.equal(process.env.TOSUB2_REQUIRE_SOCKS5, "1");
assert.equal(process.env.TOSUB2_PIN_PROXY_SESSION, "1");
assert.equal(process.env.TOSUB2_EMAIL_CHALLENGE_RETRY, "1");
await fs.appendFile(process.env.SCHEDULE_TEST_OBSERVATIONS, JSON.stringify({ email, action: action || "login", at: now, proxy: process.env.CHATGPT_PROXY_URL, tls: JSON.parse(process.env.TOSUB2_ACCOUNT_TLS) }) + "\n");
const database = createServerDatabase({ databasePath: process.env.ONBOARDING_DATABASE_PATH, outputRoot: process.env.ONBOARDING_OUTPUT_ROOT, mustExist: true });
try {
  if (action && email.startsWith("email-security-interrupt-")) {
    console.log('[email-login-attempt] {"attempt":3,"maxAttempts":3}');
    console.log('[email-login-failed] {"attempts":3,"reason":"EMAIL_OTP_REQUIRED"}');
    // Leave the operation running long enough to simulate the parent crashing
    // after persisting the pause but before consuming the child's close event.
    await new Promise((resolve) => setTimeout(resolve, 3000));
    process.exitCode = 1;
  } else if (action) {
    const result = { version: 1, operationId: arg("--security-operation-id"), email, action, status: "completed", stage: action === "rotate-totp" ? "verified" : "logout_requested", startedAt: now, updatedAt: now,
      ...(action !== "logout-all" ? { secret: "NB2W45DFOIZAQWER", activation_succeeded: true, mfa_verified: true, credentials_saved: true } : {}),
      ...(action !== "rotate-totp" ? { work_reset_succeeded: true, logout_accepted: true, logoutAcceptedAt: now } : {}) };
    if (email.startsWith("uncertain-")) Object.assign(result, { status: "needs_attention", logout_accepted: false, logoutAcceptedAt: null, error: "Synthetic logout response unknown" });
    database.put("security-operation-result", result.operationId, result);
    await fs.writeFile(arg("--security-result"), JSON.stringify(result), { mode: 0o600 });
  } else {
    const launches = (await fs.readFile(process.env.SCHEDULE_TEST_OBSERVATIONS, 'utf8')).trim().split('\n').map(JSON.parse).filter(entry => entry.email === email && entry.action === 'login').length;
    if (email.startsWith("email-retry-") && (!email.includes('recover') || launches < 4)) {
      for (let attempt = 1; attempt <= 3; attempt++) {
        console.log(`[email-login-attempt] ${JSON.stringify({ attempt, maxAttempts: 3 })}`);
        if (attempt < 3) console.log(`[email-login-retry] ${JSON.stringify({ attempt, maxAttempts: 3, reason: "EMAIL_OTP_REQUIRED", delayMs: 2 })}`);
      }
      console.log('[email-login-failed] {"attempts":3,"reason":"EMAIL_OTP_REQUIRED"}');
      process.exitCode = 1;
    } else {
      const output = arg("--sub2api-out");
      const data = { type: "sub2api-data", version: 1, accounts: [{ name: email, credentials: { email, access_token: `fake-access-${now}`, refresh_token: "fake-refresh" } }] };
      await fs.mkdir(path.dirname(output), { recursive: true });
      await fs.writeFile(output, JSON.stringify(data), { mode: 0o600 });
      database.saveArtifact(output, data);
      console.log(`[ok] Saved sub2api import: ${output}`);
    }
  }
} finally { database.close(); }
