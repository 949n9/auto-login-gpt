import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { completeTotpMfaIfNeeded, ProtocolClient } from "../src/protocol-login.mjs";
import { CookieJar } from "../src/login-cookies.mjs";
import { generateTotp } from "../src/login-totp.mjs";
import { TlsFingerprintTransport } from "../src/tls-transport.mjs";

const originalNow = Date.now;
const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
let clock = 31_000;
const submissions = [];
const preparations = [];
try {
  Date.now = () => clock;
  const client = {
    pauseBeforeOperation: async () => { preparations.push("delay"); clock = 59_000; },
    transport: { enabled: true, generateSentinelTokens: async () => { preparations.push("sentinel"); clock = 61_000; return { token: "synthetic" }; } },
    getJson: async (method, url, options) => {
      if (url.endsWith("/verify")) { preparations.push("verify"); submissions.push(options); }
      return { data: { done: true } };
    },
  };
  await completeTotpMfaIfNeeded(client, {
    authBase: "https://example.test", deviceId: "synthetic", totpSecret: secret,
    payload: { page: { type: "mfa_challenge" }, "oai-client-auth-session": { mfa_factors: [{ id: "factor", factor_type: "totp" }] } },
  });
  assert.equal(submissions.length, 1);
  assert.equal(submissions[0].json.code, generateTotp(secret, 61_000), "generate the OTP after slow request preparation");
  assert.deepEqual(preparations, ["delay", "sentinel", "verify"], "pacing finishes before preparing and submitting a fresh OTP");
  assert.equal(submissions[0].retryRiskControl, false, "verification must not replay an old code");
} finally { Date.now = originalNow; }

const transport = new TlsFingerprintTransport({ enabled: true });
let requests = 0;
transport.send = async (message) => {
  if (message.operation === "configure") return { profile: "chrome146" };
  assert.equal(message.operation, "request");
  requests += 1;
  return { status: 403, headers: [["cf-mitigated", "challenge"], ["content-type", "text/html"]], body: Buffer.from("Just a moment _cf_chl_opt").toString("base64") };
};
transport.solveCloudflareChallenge = async () => { throw new Error("OTP requests must not be replayed"); };
const protocol = new ProtocolClient({ transport });
await assert.rejects(protocol.getJson("POST", "https://example.test/api/accounts/mfa/verify", { json: { code: "synthetic" }, retryRiskControl: false }), /PROXY_RISK_CONTROL/);
assert.equal(requests, 1);

const restored = new CookieJar([{ name: "session", value: "synthetic", domain: "example.test", path: "/", hostOnly: true }]);
let restores = 0;
const restoredClient = new ProtocolClient({ jar: restored, transport: {
  enabled: true,
  fetch: async (url, options) => {
    if (options.restoreCookies) restores += 1;
    assert.equal(options.headers.has("cookie"), false, "the native session owns the outgoing cookie header");
    const headers = new Headers();
    Object.defineProperty(headers, "transportCookies", { value: [] });
    return { status: 200, headers, text: async () => "{}" };
  },
} });
await restoredClient.getJson("GET", "https://example.test/");
await restoredClient.getJson("GET", "https://example.test/");
assert.equal(restores, 1);
assert.equal(restoredClient.jar.toJSON().length, 0, "deleted cookies must disappear from the checkpoint snapshot");

const temp = await fs.mkdtemp(path.join(os.tmpdir(), "checkpoint-account-"));
try {
  const checkpoint = path.join(temp, "checkpoint.json");
  const value = JSON.stringify({ version: 1, stage: "web_login", email: "alice@example.test", cookies: [], chatgpt_base: "https://chatgpt.com", auth_base: "https://auth.openai.com" });
  await fs.writeFile(checkpoint, value);
  const script = fileURLToPath(new URL("../src/protocol-login.mjs", import.meta.url));
  const env = { ...process.env };
  delete env.TOSUB2_ACCOUNT_TLS;
  delete env.ONBOARDING_DATABASE_PATH;
  const result = spawnSync(process.execPath, [script, "--email", "bob@example.test", "--resume-checkpoint", checkpoint], { env, encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /CHECKPOINT_ACCOUNT_MISMATCH/);
  assert.doesNotMatch(result.stdout, /Start ChatGPT/);
  assert.equal(await fs.readFile(checkpoint, "utf8"), value, "mismatched account must preserve original checkpoint");
} finally { await fs.rm(temp, { recursive: true, force: true }); }
console.log("OTP preparation/replay, native cookie synchronization and wrong-account checkpoint tests passed");
