import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { ProtocolClient, loginChatgptWeb } from "../src/protocol-login.mjs";
import { CookieJar } from "../src/login-cookies.mjs";
import { runAccountSecurity } from "../src/account-security.mjs";

const chatgptBase = "https://chatgpt.mock.invalid";
const authBase = "https://auth.mock.invalid";
const email = "retry-test@example.invalid";
const totpSecret = "JBSWY3DPEHPK3PXP";

test("website sign-in and password validation wait before their requests", async (t) => {
  const f = fixture(t, { mode: () => "password", mailbox: false });
  await loginChatgptWeb(f.client, f.options);
  assert.deepEqual(f.pauses.map((item) => item.stage), ["website_signin", "password_verify"]);
  assert.equal(f.pauses[0].requests, f.calls.findIndex((call) => call.pathname === "/api/auth/signin/openai"));
  assert.equal(f.pauses[1].requests, f.calls.findIndex((call) => call.pathname === "/api/accounts/password/verify"));
});

test("real website login exhausts exactly three attempts without mailbox API and retains only the device cookie", async (t) => {
  const f = fixture(t, { mode: () => "email", mailbox: false });
  await assert.rejects(loginChatgptWeb(f.client, f.options), { code: "EMAIL_OTP_REQUIRED" });
  assert.equal(f.signins.length, 3);
  assert.equal(f.questions(), 0);
  assert.equal(f.resets.length, 2);
  assert.equal(new Set(f.signins.map((item) => item.deviceId)).size, 1);
  for (const reset of f.resets) {
    assert.equal(reset.proxy, "socks5://127.0.0.1:1080");
    assert.equal(reset.profile, "chrome152_macos");
  }
  for (const restored of f.restores) assert.deepEqual(restored.map((cookie) => cookie.name), ["oai-did"]);
  assert.equal(f.markers("email-login-failed")[0].attempts, 3);
});

test("second website attempt succeeds and the same readline budget survives another fresh client", async (t) => {
  const f = fixture(t, { mode: (attempt) => attempt === 2 ? "password" : "email", mailbox: false });
  const result = await loginChatgptWeb(f.client, f.options);
  assert.equal(result.loginMethod, "password");
  assert.equal(f.signins.length, 2);
  const next = new ProtocolClient({ transport: f.transport, pauseBeforeOperation: f.client.pauseBeforeOperation });
  await assert.rejects(loginChatgptWeb(next, f.options), { code: "EMAIL_OTP_REQUIRED" });
  assert.equal(f.signins.length, 3, "Codex fallback cannot receive another independent three-attempt allowance");
  assert.equal(new Set(f.signins.map((item) => item.deviceId)).size, 1);
});

test("mailbox OTP is consumed normally, including a challenge returned after password verification", async (t) => {
  const f = fixture(t, { mode: () => "password-email", mailbox: true });
  const result = await loginChatgptWeb(f.client, f.options);
  assert.equal(result.emailVerified, true);
  assert.equal(f.signins.length, 1);
  assert.equal(f.questions(), 1);
  assert.equal(f.calls.filter((call) => call.pathname === "/api/accounts/email-otp/validate").length, 1);
});

test("password rejection and email HTTP 429 end without a new website attempt", async (t) => {
  for (const settings of [{ mode: () => "password", passwordStatus: 401 }, { mode: () => "email", emailStatus: 429 }]) {
    await t.test(`HTTP ${settings.passwordStatus || settings.emailStatus}`, async (subtest) => {
      const f = fixture(subtest, { ...settings, mailbox: true });
      await assert.rejects(loginChatgptWeb(f.client, f.options), { httpStatus: settings.passwordStatus || settings.emailStatus });
      assert.equal(f.signins.length, 1);
      assert.equal(f.markers("email-login-retry").length, 0);
    });
  }
});

test("a password response containing only an email continuation cannot be treated as completed login", async (t) => {
  const f = fixture(t, { mode: () => "password-email", mailbox: false, emailContinuationOnly: true });
  await assert.rejects(loginChatgptWeb(f.client, f.options), { code: "EMAIL_OTP_REQUIRED" });
  assert.equal(f.signins.length, 3);
  assert.equal(f.questions(), 0);
  assert.equal(f.calls.filter((call) => call.pathname === "/callback").length, 0);
});

test("a rejected email code fails each attempt once and stops after three validations", async (t) => {
  const f = fixture(t, { mode: () => "email", mailbox: true, emailStatus: 400 });
  await assert.rejects(loginChatgptWeb(f.client, f.options), { code: "EMAIL_OTP_REJECTED" });
  assert.equal(f.signins.length, 3);
  assert.equal(f.questions(), 3);
  assert.equal(f.calls.filter((call) => call.pathname === "/api/accounts/email-otp/validate").length, 3);
});

test("a security mutation after successful login is never replayed by email retry", async (t) => {
  const f = fixture(t, { mode: (attempt) => attempt === 1 ? "email" : "password", mailbox: false, failLogout: true });
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "email-retry-security-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const web = await loginChatgptWeb(f.client, f.options);
  await assert.rejects(runAccountSecurity({ client: f.client, chatgptBase, email, deviceId: web.deviceId, action: "logout-all", operationId: "test-no-replay", resultPath: path.join(directory, "result.json") }), /SECURITY_NETWORK_FAILED/);
  assert.equal(f.signins.length, 2);
  assert.equal(f.calls.filter((call) => call.pathname === "/backend-api/flora/workspace/reset").length, 1);
  assert.equal(f.calls.filter((call) => call.pathname === "/backend-api/accounts/logout_all").length, 1);
  assert.equal(f.markers("email-login-attempt").length, 2);
});

function fixture(t, settings) {
  const previousEnv = { ...process.env }, originalLog = console.log;
  const logs = [], calls = [], signins = [], resets = [], restores = [], pauses = [];
  let nativeCookies = new CookieJar(), questions = 0;
  Object.assign(process.env, { NODE_ENV: "test", TOSUB2_TEST_SENTINEL_TOKEN: "synthetic-proof", TOSUB2_EMAIL_CHALLENGE_RETRY: "1", TOSUB2_EMAIL_OTP_AVAILABLE: settings.mailbox ? "1" : "0", TOSUB2_EMAIL_OTP_TIMEOUT_MS: "30" });
  console.log = (line) => logs.push(String(line));
  t.after(() => { console.log = originalLog; for (const key of Object.keys(process.env)) if (!Object.hasOwn(previousEnv, key)) delete process.env[key]; Object.assign(process.env, previousEnv); });
  const cookie = (name, value) => ({ name, value, domain: "chatgpt.mock.invalid", path: "/", secure: true, hostOnly: true, httpOnly: false, expires: null });
  const transport = {
    enabled: true, requireSocks5: true, configuredProxy: "socks5://127.0.0.1:1080", profile: "chrome152_macos", identityProfile: "chrome152_macos",
    async resetSession() { resets.push({ proxy: this.configuredProxy, profile: this.profile }); nativeCookies = new CookieJar(); },
    async restoreCookies(values) { restores.push(structuredClone(values)); nativeCookies.merge(values); },
    async fetch(url, options) {
      if (options.restoreCookies) { restores.push(structuredClone(options.restoreCookies)); nativeCookies.merge(options.restoreCookies); }
      const parsed = new URL(url);
      assert.ok([new URL(chatgptBase).host, new URL(authBase).host].includes(parsed.host), "all requests must remain in this in-memory mock");
      const pathname = parsed.pathname;
      calls.push({ method: options.method, pathname });
      let status = 200, data = {};
      if (pathname === "/") {
        if (!nativeCookies.has("oai-did")) nativeCookies.merge([cookie("oai-did", "stable-device")]);
        nativeCookies.merge([cookie("__Host-next-auth.csrf-token", "synthetic-csrf"), cookie("prior-auth-state", `attempt-${signins.length}`)]);
        data = "homepage";
      } else if (pathname === "/api/auth/providers") data = {};
      else if (pathname === "/api/auth/csrf") data = { csrfToken: "synthetic-csrf" };
      else if (pathname === "/api/auth/signin/openai") {
        const attempt = signins.length + 1;
        signins.push({ attempt, deviceId: parsed.searchParams.get("ext-oai-did") });
        data = { url: `${authBase}/${settings.mode(attempt) === "email" ? "email-verification" : "log-in/password"}` };
      } else if (["/email-verification", "/log-in/password"].includes(pathname)) data = "login page";
      else if (pathname === "/api/accounts/password/verify") {
        status = settings.passwordStatus || 200;
        data = status !== 200 ? { error: { message: "invalid password" } } : settings.mode(signins.length) === "password-email"
          ? { ...(settings.emailContinuationOnly ? {} : { page: { type: "email_otp_send" } }), continue_url: `${authBase}/email-verification` }
          : { page: { type: "external_url" }, continue_url: `${chatgptBase}/callback` };
      } else if (pathname === "/api/accounts/email-otp/validate") {
        status = settings.emailStatus || 200;
        data = status !== 200 ? { error: { code: "wrong_email_otp_code" } } : { page: { type: "external_url" }, continue_url: `${chatgptBase}/callback` };
      } else if (pathname === "/callback") data = "authenticated";
      else if (pathname === "/api/auth/session") data = { user: { id: "user-test", email }, account: { id: "account-test" }, accessToken: `header.${Buffer.from(JSON.stringify({ pwd_auth_time: Date.now() })).toString("base64url")}.signature` };
      else if (pathname === "/backend-api/flora/workspace/reset") data = { success: true };
      else if (pathname === "/backend-api/accounts/logout_all") {
        if (settings.failLogout) throw new Error("synthetic mutation transport failure");
        data = { success: true };
      } else throw new Error(`Unexpected mock request ${options.method} ${pathname}`);
      const response = new Response(typeof data === "string" ? data : JSON.stringify(data), { status, headers: { "content-type": typeof data === "string" ? "text/html" : "application/json" } });
      response.headers.transportCookies = nativeCookies.toJSON();
      return response;
    },
  };
  const rl = { async question() { questions += 1; assert.equal(settings.mailbox, true, "missing mailbox must not prompt for input"); return "123456"; } };
  return { client: new ProtocolClient({ transport, pauseBeforeOperation: async (stage) => { pauses.push({ stage, requests: calls.length }); } }), transport, options: { chatgptBase, authBase, email, rl, password: "test-password", totpSecret }, calls, signins, resets, restores, pauses, questions: () => questions, markers: (name) => logs.filter((line) => line.startsWith(`[${name}]`)).map((line) => JSON.parse(line.slice(line.indexOf("]") + 1))) };
}
