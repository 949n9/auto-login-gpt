#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";

// No provider requests: every account, credential, proxy and result in this mock is synthetic.
const value = (flag) => {
  const index = process.argv.indexOf(flag);
  return index < 0 ? "" : process.argv[index + 1];
};
const email = value("--email");
const action = value("--security-action");
const resultPath = value("--security-result");
const operationId = value("--security-operation-id");
const rotates = action === "rotate-totp" || action === "rotate-totp-logout-all";
const logsOut = action === "logout-all" || action === "rotate-totp-logout-all";
const startedAt = new Date().toISOString();
const observation = {
  email, action: action || "login", operationId, resultPath,
  proxy: process.env.CHATGPT_PROXY_URL || "",
  pinProxySession: process.env.TOSUB2_PIN_PROXY_SESSION,
  requireSocks5: process.env.TOSUB2_REQUIRE_SOCKS5,
  tlsIdentity: JSON.parse(process.env.TOSUB2_ACCOUNT_TLS || "null"),
  pid: process.pid, startedAt,
};
await fs.appendFile(process.env.SECURITY_TEST_OBSERVATIONS, `${JSON.stringify(observation)}\n`, { mode: 0o600 });

if (!action) {
  const outputPath = value("--sub2api-out");
  await writeJson(outputPath, {
    type: "sub2api-data", version: 1, exported_at: startedAt, proxies: [],
    accounts: [{
      name: `oauth---${email}`, platform: "openai", type: "oauth",
      credentials: { email, access_token: `test-access-${email}`, refresh_token: `test-refresh-${email}`, id_token: `test-id-${email}`, chatgpt_account_id: `test-account-${email}` },
      extra: { email }, concurrency: 10, priority: 1, rate_multiplier: 1,
    }],
  });
  console.log(`[ok] Saved sub2api import: ${outputPath}`);
} else {
  assert.match(observation.proxy, /^socks5h?:\/\//, "security operation must use a SOCKS proxy");
  assert.equal(observation.pinProxySession, "1", "security operation must pin its proxy session");
  assert.equal(observation.requireSocks5, "1", "security operation must forbid a direct fallback");
  assert.ok(observation.tlsIdentity, "security operation must inherit the account TLS identity");
  assert.ok(operationId && resultPath, "security result must be bound to an operation");
  const result = {
    version: 1, operationId, email, action, status: "running", stage: "prepared",
    startedAt, updatedAt: startedAt,
    ...(rotates ? { secret: "NB2W45DFOIZAQWER", activation_succeeded: false, mfa_verified: false, credentials_saved: false } : {}),
    ...(logsOut ? { logout_accepted: false, work_reset_succeeded: false } : {}),
  };
  await writeJson(resultPath, result);
  if (email.startsWith("security-slow-") || email.startsWith("security-cancel-")) await delay(2000);
  if (email.startsWith("security-proxy-failure-")) {
    console.error("[proxy-risk-retry] PROXY_CONNECTION_RETRY: simulated SOCKS connection failure");
    process.exitCode = 1;
  } else if (email.startsWith("security-combined-logout-failure-")) {
    await writeJson(resultPath, { ...result, status: "needs_attention", stage: "logout_requested", activation_succeeded: true, mfa_verified: true, credentials_saved: true, work_reset_succeeded: true, logout_accepted: false, error: "Logout response was interrupted", updatedAt: new Date().toISOString() });
    process.exitCode = 1;
  } else if (email.startsWith("security-work-reset-unavailable-logout-failure-")) {
    await writeJson(resultPath, { ...result, status: "needs_attention", stage: "logout_requested", activation_succeeded: rotates, mfa_verified: rotates, credentials_saved: rotates, work_reset_succeeded: false, work_reset_unavailable: true, logout_accepted: false, error: "Logout response was interrupted after missing Work endpoint", updatedAt: new Date().toISOString() });
    process.exitCode = 1;
  } else if (email.startsWith("security-work-reset-failure-")) {
    await writeJson(resultPath, { ...result, status: "needs_attention", stage: "work_reset_requested", activation_succeeded: true, mfa_verified: true, credentials_saved: true, work_reset_succeeded: false, logout_accepted: false, error: "Work reset response was interrupted; logout was not requested", updatedAt: new Date().toISOString() });
    process.exitCode = 1;
  } else if (email.startsWith("security-partial-")) {
    await writeJson(resultPath, { ...result, status: "needs_attention", stage: "activated", activation_succeeded: true, error: "MFA confirmation was interrupted", updatedAt: new Date().toISOString() });
    process.exitCode = 1;
  } else if (email.startsWith("security-cancel-")) {
    // A canceled process must never reach this write.
    await finish();
  } else {
    await finish();
    if (email.startsWith("security-crash-ready-")) await delay(60000);
  }

  async function finish() {
    await writeJson(resultPath, {
      ...result,
      ...(email.startsWith("security-wrong-op-") ? { operationId: `wrong-${operationId}` } : {}),
      ...(email.startsWith("security-wrong-email-") ? { email: "different-account@example.invalid" } : {}),
      status: "completed", stage: logsOut ? "logout_requested" : "verified",
      ...(rotates ? { activation_succeeded: true, mfa_verified: true, credentials_saved: true } : {}),
      ...(logsOut ? { logout_accepted: true, work_reset_succeeded: !email.startsWith("security-work-reset-unavailable-"), work_reset_unavailable: email.startsWith("security-work-reset-unavailable-") } : {}),
      updatedAt: new Date().toISOString(),
    });
    console.log(`[ok] Mock account security action ${action} finished`);
  }
}

async function writeJson(filename, data) {
  await fs.mkdir(path.dirname(filename), { recursive: true });
  await fs.writeFile(filename, `${JSON.stringify(data)}\n`, { mode: 0o600 });
}
function delay(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }
