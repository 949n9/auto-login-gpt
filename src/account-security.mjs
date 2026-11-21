import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { generateFreshTotp } from "./login-totp.mjs";
import { assertSocks5Proxy } from "./tls-transport.mjs";
import { pauseBeforeOperation } from "./operation-pacing.mjs";

const ACTIONS = new Set(["rotate-totp", "logout-all", "rotate-totp-logout-all"]);
const isoNow = () => new Date().toISOString();
const normalizeEmail = (value) => String(value || "").trim().toLowerCase();

export async function writeSecurityResult(filePath, result, persist) {
  // The database copy is encrypted. The private disk copy permits recovery even
  // when the parent exits before consuming the worker's last message.
  if (persist) await persist(result);
  await fs.mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const temporary = `${filePath}.${process.pid}.${crypto.randomUUID()}.tmp`;
  try {
    const file = await fs.open(temporary, "wx", 0o600);
    try { await file.writeFile(`${JSON.stringify(result, null, 2)}\n`); await file.sync(); }
    finally { await file.close(); }
    await fs.rename(temporary, filePath);
    const directory = await fs.open(path.dirname(filePath), "r");
    try { await directory.sync(); } finally { await directory.close(); }
  } catch (error) {
    await fs.rm(temporary, { force: true }).catch(() => {});
    throw error;
  }
}

function enforceProxy(client) {
  if (!client.transport?.enabled || !client.transport?.requireSocks5) {
    throw new Error("SOCKS5_REQUIRED: 安全操作未启用强制 SOCKS5 传输");
  }
  assertSocks5Proxy(client.transport.configuredProxy);
}

function safeError(error) {
  // Do not surface response bodies, tokens, user identifiers or proxy errors.
  const code = String(error?.message || "").match(/^[A-Z][A-Z0-9_]+/u)?.[0];
  const messages = {
    SOCKS5_REQUIRED: "必须使用 SOCKS5 代理，未进行直连回退",
    SECURITY_IDENTITY_MISMATCH: "官网会话与目标账号不一致，操作已停止",
    SECURITY_SESSION_INVALID: "官网会话无法验证，操作已停止",
    SECURITY_REAUTH_REQUIRED: "本次登录未满足近期密码和 2FA 验证要求，请重新认证",
    SECURITY_ADVANCED_PROTECTION: "账号已启用高级保护，需在官网管理验证方式",
    SECURITY_PROTECTION_UNKNOWN: "无法确认账号保护状态，尚未修改验证方式",
    SECURITY_FACTOR_STATE: "账号的 2FA 状态已变化，请核实后继续",
    SECURITY_ENROLLMENT_INVALID: "未获得有效的新 2FA 密钥，请继续完成验证方式设置",
    SECURITY_ACTIVATION_REJECTED: "新 2FA 验证码未被接受，已保留待激活密钥",
    SECURITY_VERIFY_FAILED: "新 2FA 的启用状态尚未确认，已保留密钥与操作记录",
    SECURITY_CREDENTIAL_SAVE_REQUIRED: "新 2FA 已验证，但账号详情尚未确认保存，因此未提交登出",
    SECURITY_ALREADY_STARTED: "该操作已有记录，禁止从头重复执行",
    SECURITY_API_FAILED: "官网接口拒绝了操作，请查看 HTTP 状态并核实账号状态",
    SECURITY_NETWORK_FAILED: "SOCKS5 请求失败或超时；已停止，不会直连或自动重复提交",
  };
  return { code: messages[code] ? code : "SECURITY_OPERATION_FAILED", message: messages[code] || "安全操作未完成，已保留可用的恢复记录" };
}

export async function runAccountSecurity({ client, chatgptBase = "https://chatgpt.com", email,
  deviceId, action, operationId, resultPath, persist, persistVerifiedCredentials, onStage = () => {}, now = Date.now,
  pause = client.pauseBeforeOperation || pauseBeforeOperation }) {
  if (!ACTIONS.has(action) || !operationId || !resultPath || !normalizeEmail(email)) throw new Error("Invalid account security operation");
  enforceProxy(client);
  try { await fs.access(resultPath); throw new Error("SECURITY_ALREADY_STARTED"); }
  catch (error) { if (error.code !== "ENOENT") throw error; }
  const result = { version: 1, operationId, email: normalizeEmail(email), action, status: "running", stage: "prepared", startedAt: isoNow(), updatedAt: isoNow(), activation_succeeded: false, mfa_verified: false, work_reset_succeeded: false, work_reset_unavailable: false, logout_accepted: false };
  const save = async (patch = {}) => {
    Object.assign(result, patch, { updatedAt: isoNow() });
    await writeSecurityResult(resultPath, result, persist);
    onStage(result.stage);
  };
  await save();
  let identity = null;
  let mutationSent = false;
  async function session() {
    enforceProxy(client);
    let response;
    try { response = await client.request("GET", `${chatgptBase}/api/auth/session`, { referer: `${chatgptBase}/`, retryRiskControl: false }); }
    catch { throw new Error("SECURITY_NETWORK_FAILED"); }
    let data;
    try { data = JSON.parse(response.text); } catch { throw new Error("SECURITY_SESSION_INVALID"); }
    if (response.res.status !== 200 || !data.accessToken || !data.user?.id || !data.account?.id) throw new Error("SECURITY_SESSION_INVALID");
    if (normalizeEmail(data.user.email) !== result.email || (identity && (identity.userId !== data.user.id || identity.accountId !== data.account.id))) throw new Error("SECURITY_IDENTITY_MISMATCH");
    let claims;
    try { claims = JSON.parse(Buffer.from(data.accessToken.split(".")[1], "base64url").toString()); }
    catch { throw new Error("SECURITY_SESSION_INVALID"); }
    identity = { accessToken: data.accessToken, userId: data.user.id, accountId: data.account.id, claims };
    return identity;
  }
  async function api(method, endpoint, body) {
    enforceProxy(client);
    const target = endpoint === "flora/workspace/reset" ? `/backend-api/${endpoint}` : `/backend-api/accounts/${endpoint}`;
    let response;
    try {
      response = await client.request(method, `${chatgptBase}${target}`, {
        headers: { authorization: `Bearer ${identity.accessToken}`, "ChatGPT-Account-ID": identity.accountId, "X-OpenAI-Expected-Account-Id": identity.accountId,
          "oai-device-id": deviceId, "oai-session-id": crypto.randomUUID(), "oai-language": "zh-CN",
          "x-openai-target-path": target, "x-openai-target-route": target },
        origin: chatgptBase, referer: `${chatgptBase}/settings/security`, json: body, retryRiskControl: false,
      });
    } catch { throw new Error("SECURITY_NETWORK_FAILED"); }
    result.lastHttpStatus = response.res.status;
    const rejected = () => Object.assign(new Error("SECURITY_API_FAILED"), { httpStatus: response.res.status, endpoint });
    let data;
    try { data = response.text ? JSON.parse(response.text) : {}; } catch { throw rejected(); }
    if (response.res.status < 200 || response.res.status >= 300 || data?.success === false) throw rejected();
    return data;
  }
  function assertRecentAuthentication(removingFactor) {
    const authenticatedAt = identity.claims.pwd_auth_time;
    const age = now() - authenticatedAt;
    if (typeof authenticatedAt !== "number" || !Number.isFinite(age) || age < 0 || age >= 240000
        || (removingFactor && identity.claims["https://api.openai.com/mfa"]?.required !== "yes")) {
      throw new Error("SECURITY_REAUTH_REQUIRED");
    }
  }
  const factors = (info) => {
    if (!info?.factors || !Array.isArray(info.factors.totp)) throw new Error("SECURITY_FACTOR_STATE");
    return info.factors.totp;
  };
  async function logoutAll() {
    await session();
    await pause("logout_all");
    await save({ stage: "work_reset_requested" });
    mutationSent = true;
    try {
      await api("POST", "flora/workspace/reset");
      await save({ stage: "work_reset_confirmed", work_reset_succeeded: true });
    } catch (error) {
      // A definite missing optional Work endpoint does not prevent the requested
      // global logout. Other rejections and uncertain requests remain terminal.
      if (error.httpStatus !== 404 || error.endpoint !== "flora/workspace/reset") throw error;
      await save({ work_reset_unavailable: true, work_reset_succeeded: false });
    }
    await save({ stage: "logout_requested" });
    mutationSent = true;
    await api("POST", "logout_all");
    await save({ status: "completed", logout_accepted: true, logoutAcceptedAt: isoNow(), completedAt: isoNow(), effectMayTakeMinutes: 30 });
    return result;
  }
  try {
    await session();
    await save({ accountId: identity.accountId, userId: identity.userId });
    if (action === "logout-all") {
      return await logoutAll();
    }

    const protection = await api("GET", "security_settings/info");
    if (protection.advanced_protection_mode_enabled === true) throw new Error("SECURITY_ADVANCED_PROTECTION");
    if (typeof protection.advanced_protection_mode_enabled !== "boolean") throw new Error("SECURITY_PROTECTION_UNKNOWN");
    const before = await api("GET", "mfa_info");
    const oldFactors = factors(before);
    if (oldFactors.length > 1 || oldFactors.some(f => typeof f.id !== "string" || !f.id)) throw new Error("SECURITY_FACTOR_STATE");
    const oldFactorId = oldFactors[0]?.id || null;
    await pause("rotate_totp");
    assertRecentAuthentication(Boolean(oldFactorId));
    await save({ oldFactorId, initialSetup: !oldFactorId });
    if (oldFactorId) {
      await save({ stage: "disable_requested" });
      mutationSent = true;
      await api("POST", "mfa/user/disable_in_house", { factor_id: oldFactorId });
      const disabled = await api("GET", "mfa_info");
      if (factors(disabled).length !== 0) throw new Error("SECURITY_FACTOR_STATE");
      await save({ stage: "old_disabled" });
    }
    // A new live identity check also prevents proceeding after an account switch.
    await session();
    assertRecentAuthentication(false);
    await save({ stage: "enrollment_requested" });
    mutationSent = true;
    const enrollment = await api("POST", "mfa/enroll", { factor_type: "totp", source: "settings" });
    const secret = String(enrollment.secret || "").replace(/[\s=]/g, "").toUpperCase();
    if (!/^[A-Z2-7]{16,128}$/.test(secret) || typeof enrollment.session_id !== "string" || !enrollment.session_id) throw new Error("SECURITY_ENROLLMENT_INVALID");
    await save({ stage: "enrolled", secret, session_id: enrollment.session_id,
      otpauth_uri: `otpauth://totp/${encodeURIComponent(`OpenAI:${result.email}`)}?${new URLSearchParams({secret, issuer:"OpenAI", algorithm:"SHA1", digits:"6", period:"30"})}` });
    const code = await generateFreshTotp(secret);
    await save({ stage: "activation_requested" });
    const activated = await api("POST", "mfa/user/activate_enrollment", { factor_type: "totp", session_id: enrollment.session_id, code, source: "settings" });
    if (activated.success !== true) throw new Error("SECURITY_ACTIVATION_REJECTED");
    await save({ stage: "activated", activation_succeeded: true, activatedAt: isoNow() });
    const after = await api("GET", "mfa_info");
    const newFactors = factors(after);
    if (after.mfa_enabled_v2 !== true || newFactors.length !== 1 || !newFactors[0].id || newFactors[0].id === oldFactorId) throw new Error("SECURITY_VERIFY_FAILED");
    await save({ stage: "verified", mfa_verified: true, newFactorId: newFactors[0].id });
    if (persistVerifiedCredentials) await persistVerifiedCredentials(result);
    else if (action === "rotate-totp-logout-all") throw new Error("SECURITY_CREDENTIAL_SAVE_REQUIRED");
    await save({ stage: "verified", credentials_saved: Boolean(persistVerifiedCredentials), status: action === "rotate-totp" ? "completed" : "running", ...(action === "rotate-totp" ? {completedAt: isoNow()} : {}) });
    if (action === "rotate-totp-logout-all") return await logoutAll();
    return result;
  } catch (error) {
    const safe = safeError(error);
    await save({ status: mutationSent ? "needs_attention" : "failed", error: safe.message, errorCode: safe.code }).catch(() => {});
    throw new Error(`${safe.code}: ${safe.message}`);
  }
}
