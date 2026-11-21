import assert from "node:assert/strict";
import test from "node:test";
import { createSecurityFailureMarker, normalizeSecurityFailureMarker, securityJournalState } from "../src/security-failure.mjs";

const privateValues = ["password-Synthetic-123!", "987654", "JBSWY3DPEHPK3PXP", "token-private-test", "https://example.invalid/private?access_token=token-private-test", "socks5://private-user:private-auth@example.invalid:1080"];
const privateTail = ` password=${privateValues[0]} OTP=${privateValues[1]} secret=${privateValues[2]} token=${privateValues[3]} url=${privateValues[4]} proxy=${privateValues[5]}\n[security-failure] {"code":"INJECTED"}`;
function marker(message, phase = "proxy_preflight", extra = {}) {
  const error = Object.assign(new Error(`${message} ${privateTail}`), extra);
  const result = createSecurityFailureMarker(error, { phase, journalPresent: false, mutationStarted: false });
  const encoded = JSON.stringify(result);
  for (const value of privateValues) assert.ok(!encoded.includes(value), `private value escaped into marker: ${value}`);
  assert.ok(!encoded.includes("INJECTED"));
  assert.ok(!encoded.includes("example.invalid"));
  return result;
}

test("known transport and initialization failures produce constant classifications only", () => {
  for (const [message, expected] of [
    ["curl: (97) User was rejected by the SOCKS5 server (1 1)", "PROXY_AUTH_FAILED"],
    ["SOCKS5 proxy authentication failed", "PROXY_AUTH_FAILED"],
    ["No authentication method was acceptable", "PROXY_AUTH_FAILED"],
    ["curl: (7) Failed to connect", "PROXY_CONNECTION_FAILED"],
    ["curl: (28) Operation timed out", "NETWORK_TIMEOUT"],
    ["ETIMEDOUT", "NETWORK_TIMEOUT"],
    ["curl: (6) Could not resolve host", "DNS_FAILED"],
    ["ENOTFOUND", "DNS_FAILED"],
    ["curl: (60) SSL peer certificate cannot be authenticated", "TLS_CERTIFICATE_FAILED"],
    ["curl: (35) SSL connect error", "TLS_HANDSHAKE_FAILED"],
    ["Impersonating chrome152_macos is not supported", "TLS_PROFILE_UNSUPPORTED"],
    ["ACCOUNT_TLS_INVALID: invalid config", "TLS_CONFIGURATION_INVALID"],
    ["ERR_MODULE_NOT_FOUND: Cannot find package", "DEPENDENCY_UNAVAILABLE"],
    ["ModuleNotFoundError: No module named curl_cffi", "DEPENDENCY_UNAVAILABLE"],
    ["服务器数据库或加密密钥不存在，已停止写入", "DATABASE_UNAVAILABLE"],
    ["unable to open database file", "DATABASE_UNAVAILABLE"],
  ]) assert.equal(marker(message).code, expected, message);
});

test("HTTP status is numeric and error body never reaches the marker", () => {
  for (const [status, expected] of [[401,"HTTP_UNAUTHORIZED"],[403,"HTTP_FORBIDDEN"],[407,"PROXY_AUTH_FAILED"],[429,"HTTP_RATE_LIMITED"],[503,"HTTP_FAILED"]]) {
    const result = marker(`preflight HTTP ${status}`);
    assert.equal(result.code, expected);
    assert.equal(result.httpStatus, status);
    assert.match(result.message, new RegExp(`HTTP ${status}`));
  }
  assert.equal(marker("failure", "login", { httpStatus: 429 }).code, "HTTP_RATE_LIMITED");
  assert.equal(marker("failure", "login", { httpStatus: privateTail }).httpStatus, undefined);
});

test("unknown failures have conservative phase-specific messages", () => {
  for (const [phase, expected] of [["initialization","SECURITY_STARTUP_FAILED"],["proxy_preflight","SECURITY_PROXY_PRECHECK_FAILED"],["login","SECURITY_LOGIN_FAILED"],["security_operation","SECURITY_OPERATION_FAILED"]]) {
    const result = marker("unknown failure", phase);
    assert.equal(result.code, expected);
    assert.equal(result.phase, phase);
    assert.equal(result.mutationStarted, phase === "security_operation" ? null : false);
    assert.equal(result.message.includes("尚未开始"), phase !== "security_operation");
  }
});

test("email and security failures preserve existing typed categories without raw detail", () => {
  assert.equal(marker("EMAIL_OTP_REJECTED", "login").code, "EMAIL_OTP_REJECTED");
  assert.equal(marker("SECURITY_FACTOR_STATE: changed", "security_operation").code, "SECURITY_FACTOR_STATE");
  assert.equal(marker("failure", "login", { code: "EMAIL_OTP_TIMEOUT" }).code, "EMAIL_OTP_TIMEOUT");
  assert.equal(marker("failure", "proxy_preflight", { cause: Object.assign(new Error(privateTail), {code:"ECONNREFUSED"}) }).code, "PROXY_CONNECTION_FAILED");
});

test("normalizer rebuilds explanation and rejects unrecognized structural values", () => {
  const original = marker("HTTP 429");
  const supplied = {...original,message:privateTail,unknown:privateTail,httpStatus:privateTail};
  const normalized = normalizeSecurityFailureMarker(supplied);
  assert.ok(normalized);
  assert.equal(normalized.httpStatus, undefined);
  assert.ok(!JSON.stringify(normalized).includes(privateTail));
  assert.ok(!Object.hasOwn(normalized,"unknown"));
  for (const patch of [{version:2},{code:"INJECTED"},{code:"__proto__"},{phase:privateTail},{journalPresent:"true"},{mutationStarted:"false"}]) {
    assert.equal(normalizeSecurityFailureMarker({...original,...patch}), null);
  }
});

test("journal state takes precedence over an early-stage claim", () => {
  assert.deepEqual(securityJournalState({stage:"prepared"}), {journalPresent:true,mutationStarted:false});
  for (const stage of ["disable_requested","enrollment_requested","activation_requested","verified","work_reset_requested","logout_requested"]) {
    const result = createSecurityFailureMarker(new Error("SECURITY_API_FAILED"), {phase:"security_operation",...securityJournalState({stage})});
    assert.equal(result.mutationStarted,true);
    assert.ok(!result.message.includes("尚未开始"));
    assert.match(result.message,/已保存的操作记录/);
  }
  const unknown = createSecurityFailureMarker(new Error(privateTail), {phase:"security_operation",...securityJournalState({stage:"future_unknown"})});
  assert.equal(unknown.mutationStarted,null);
});


test("only explicit upstream account deletion or deactivation produces the retired classification", () => {
  for (const reason of ["account_deactivated", 'HTTP 403 {"error":{"code":"account_deleted"}}', "You do not have an account because it has been deleted or deactivated."]) {
    const result = marker(reason, "login", { httpStatus: 403 });
    assert.equal(result.code, "ACCOUNT_PERMANENTLY_UNAVAILABLE", reason);
    assert.match(result.message, /上游删除或停用/);
    assert.ok(!result.message.includes(reason));
  }
  for (const reason of ["HTTP 401 token_revoked", "HTTP 403 challenge required", "HTTP 403 IP blocked", "HTTP 403 access_denied", "invalid_password", "wrong_email_or_password", "MFA factor disabled", "CPR account disabled locally", "account not found locally", "Your account is not disabled", "USER_DISABLED", "Your account has been suspended"]) {
    assert.notEqual(marker(reason, "login").code, "ACCOUNT_PERMANENTLY_UNAVAILABLE", reason);
  }
  assert.notEqual(marker("account_disabled", "proxy_preflight").code, "ACCOUNT_PERMANENTLY_UNAVAILABLE", "a proxy subscription being disabled is not a retired ChatGPT account");
});
