import { isRetiredAccountFailure } from "./account-lifecycle.mjs";

// This boundary never copies an exception, URL, response body or caller-supplied
// explanation into a public marker. Every displayed word comes from this table.
const MESSAGES = Object.freeze({
  ACCOUNT_PERMANENTLY_UNAVAILABLE: "账号已被上游删除或停用，请移入废号区",
  SOCKS5_REQUIRED: "必须配置有效的 SOCKS5 代理，未改为直连",
  PROXY_AUTH_FAILED: "SOCKS5 代理认证失败，请检查代理配置",
  PROXY_CONNECTION_FAILED: "SOCKS5 代理连接失败，未更换出口或改为直连",
  NETWORK_CONNECTION_FAILED: "网络连接失败，已停止本次操作",
  NETWORK_TIMEOUT: "网络请求超时，已停止本次操作",
  DNS_FAILED: "代理或目标地址解析失败，已停止本次操作",
  TLS_PROFILE_UNSUPPORTED: "TLS 组件不支持当前账号配置，已停止本次操作",
  TLS_CONFIGURATION_INVALID: "账号 TLS 配置校验失败，已停止本次操作",
  TLS_HANDSHAKE_FAILED: "TLS 连接建立失败，已停止本次操作",
  TLS_CERTIFICATE_FAILED: "TLS 证书验证失败，已停止本次操作",
  DEPENDENCY_UNAVAILABLE: "运行依赖无法加载，账号操作未能正常启动",
  DATABASE_UNAVAILABLE: "账号数据库无法打开或读取，已停止本次操作",
  HTTP_RATE_LIMITED: "服务端返回请求频率限制，未自动重复操作",
  HTTP_UNAUTHORIZED: "服务端未接受当前认证，已停止本次操作",
  HTTP_FORBIDDEN: "服务端拒绝当前请求，已停止本次操作",
  HTTP_FAILED: "服务端返回失败状态，已停止本次操作",
  EMAIL_OTP_REQUIRED: "自动登录仍需要邮箱验证码，未获得可用验证码",
  EMAIL_OTP_TIMEOUT: "自动获取邮箱验证码超时，已停止等待",
  EMAIL_OTP_REJECTED: "邮箱验证码未被接受，已停止本次登录",
  PASSWORD_REJECTED: "登录密码未被接受，请检查账号资料",
  SECURITY_IDENTITY_MISMATCH: "官网会话与目标账号不一致，已停止操作",
  SECURITY_SESSION_INVALID: "官网会话无法验证，已停止操作",
  SECURITY_REAUTH_REQUIRED: "本次登录未满足近期密码和 2FA 验证要求",
  SECURITY_ADVANCED_PROTECTION: "账号已启用高级保护，需在官网管理验证方式",
  SECURITY_PROTECTION_UNKNOWN: "无法确认账号保护状态，尚未修改验证方式",
  SECURITY_FACTOR_STATE: "账号的 2FA 状态已变化，需要核实",
  SECURITY_ENROLLMENT_INVALID: "未获得有效的新 2FA 密钥，需要核实操作记录",
  SECURITY_ACTIVATION_REJECTED: "新 2FA 验证码未被接受，需要核实待激活记录",
  SECURITY_VERIFY_FAILED: "新 2FA 的启用状态尚未确认，需要核实操作记录",
  SECURITY_CREDENTIAL_SAVE_REQUIRED: "新 2FA 已验证，但账号详情尚未确认保存，未提交登出",
  SECURITY_ALREADY_STARTED: "该操作已有记录，禁止从头重复执行",
  SECURITY_API_FAILED: "官网安全接口拒绝了操作，需要核实操作记录",
  SECURITY_NETWORK_FAILED: "安全操作网络请求失败，未自动重复提交",
  SECURITY_STARTUP_FAILED: "安全操作初始化失败",
  SECURITY_PROXY_PRECHECK_FAILED: "SOCKS5 代理预检查失败",
  SECURITY_LOGIN_FAILED: "官网登录未能完成",
  SECURITY_OPERATION_FAILED: "账号安全操作未能完成",
});
const PHASES = new Set(["initialization", "proxy_preflight", "login", "security_operation"]);
const FALLBACKS = Object.freeze({ initialization: "SECURITY_STARTUP_FAILED", proxy_preflight: "SECURITY_PROXY_PRECHECK_FAILED", login: "SECURITY_LOGIN_FAILED", security_operation: "SECURITY_OPERATION_FAILED" });
const MUTATION_STAGES = new Set(["disable_requested", "old_disabled", "enrollment_requested", "enrolled", "activation_requested", "activated", "verified", "work_reset_requested", "work_reset_confirmed", "logout_requested"]);

export function securityJournalState(journal) {
  return { journalPresent: true, mutationStarted: journal?.stage === "prepared" ? false : MUTATION_STAGES.has(journal?.stage) ? true : null };
}

export function normalizeSecurityFailureMarker(value) {
  if (!value || value.version !== 1 || !Object.hasOwn(MESSAGES, value.code) || !PHASES.has(value.phase)
    || typeof value.journalPresent !== "boolean"
    || ![true, false, null].includes(value.mutationStarted)) return null;
  const httpStatus = Number.isInteger(value.httpStatus) && value.httpStatus >= 100 && value.httpStatus <= 599 ? value.httpStatus : undefined;
  // Do not accept a claim of "not started" once journal state is unknown after
  // entering the security module. The parent still treats its journal as truth.
  const mutationStarted = value.phase === "security_operation" && !value.journalPresent ? null : value.mutationStarted;
  const suffix = mutationStarted === false ? "；本次进程尚未开始更换 2FA、重置 Work 或登出"
    : value.journalPresent ? "；请以已保存的操作记录为准，不要从头重复执行" : "；安全操作结果需要核实，未自动重复执行";
  return { version: 1, code: value.code, phase: value.phase,
    ...(httpStatus === undefined ? {} : { httpStatus }), journalPresent: value.journalPresent, mutationStarted,
    message: `${MESSAGES[value.code]}${httpStatus === undefined ? "" : `（HTTP ${httpStatus}）`}${suffix}` };
}

export function createSecurityFailureMarker(error, context = {}) {
  const phase = PHASES.has(context.phase) ? context.phase : "initialization";
  const chain = [];
  for (let current = error, index = 0; current && index < 3; current = current.cause, index += 1) {
    chain.push({ code: typeof current.code === "string" ? current.code : "", message: String(current.message || current).slice(0, 12000),
      status: current.httpStatus ?? current.status, name: typeof current.name === "string" ? current.name : "" });
  }
  const text = chain.map((item) => `${item.code} ${item.name} ${item.message}`).join("\n");
  const explicit = chain.map((item) => item.code || item.message.match(/^([A-Z][A-Z0-9_]+)(?::|\b)/)?.[1]).find((code) => Object.hasOwn(MESSAGES, code || ""));
  const suppliedStatus = chain.find((item) => Number.isInteger(item.status) && item.status >= 100 && item.status <= 599)?.status;
  const statusMatch = text.match(/\bHTTP(?:\/\d(?:\.\d)?)?\s*[:=]?\s*([1-5]\d{2})\b/i);
  const httpStatus = suppliedStatus ?? (statusMatch ? Number(statusMatch[1]) : undefined);
  let code = explicit;
  if (!code) {
    if (/ACCOUNT_TLS_INVALID/.test(text)) code = "TLS_CONFIGURATION_INVALID";
    else if (/ERR_MODULE_NOT_FOUND|MODULE_NOT_FOUND|ModuleNotFoundError|ImportError|No module named/.test(text)) code = "DEPENDENCY_UNAVAILABLE";
    else if (/SQLITE_(?:CANTOPEN|CORRUPT|NOTADB|BUSY|READONLY)|unable to open database file|database is locked|file is not a database|服务器数据库(?:或加密密钥不存在|加密密钥|内容无法解密|无法)|现有任务数据文件无法读取/i.test(text)) code = "DATABASE_UNAVAILABLE";
    else if (/(?:impersonat(?:e|ing|ion)|TLS profile|fingerprint profile).{0,90}(?:not supported|unsupported|not available|unavailable)|unsupported.{0,40}(?:impersonation|profile)|strict.*profile.*unavailable/i.test(text)) code = "TLS_PROFILE_UNSUPPORTED";
    else if (httpStatus === 407 || /(?:SOCKS|proxy).{0,80}(?:authentication (?:failed|rejected)|auth(?:entication)? failure|user(?:name)? was rejected|username\/password authentication failed)|user was rejected by the SOCKS5 server|No authentication method was acceptable/i.test(text)) code = "PROXY_AUTH_FAILED";
    else if (/\bETIMEDOUT\b|(?:curl:\s*\(?28\)?|operation timed out|connection timed out|TimeoutError)/i.test(text)) code = "NETWORK_TIMEOUT";
    else if (/\b(?:ENOTFOUND|EAI_AGAIN)\b|could not resolve (?:proxy|host)|couldn.t resolve (?:proxy|host)|curl:\s*\(?[56]\)?\b/i.test(text)) code = "DNS_FAILED";
    else if (/certificate verify failed|SSL peer certificate|curl:\s*\(?60\)?\b/i.test(text)) code = "TLS_CERTIFICATE_FAILED";
    else if (/SSL connect error|TLS handshake|curl:\s*\(?35\)?\b/i.test(text)) code = "TLS_HANDSHAKE_FAILED";
    else if (/\b(?:ECONNREFUSED|ECONNRESET|EHOSTUNREACH|ENETUNREACH)\b|failed to connect|cannot complete SOCKS5 connection|curl:\s*\(?7\)?\b/i.test(text)) code = phase === "proxy_preflight" ? "PROXY_CONNECTION_FAILED" : "NETWORK_CONNECTION_FAILED";
    else if (["login", "security_operation"].includes(phase) && isRetiredAccountFailure(text)) code = "ACCOUNT_PERMANENTLY_UNAVAILABLE";
    else if (httpStatus === 429) code = "HTTP_RATE_LIMITED";
    else if (httpStatus === 401) code = "HTTP_UNAUTHORIZED";
    else if (httpStatus === 403) code = "HTTP_FORBIDDEN";
    else if (httpStatus >= 400) code = "HTTP_FAILED";
    else if (/\b(?:invalid_password|wrong_email_or_password)\b/.test(text)) code = "PASSWORD_REJECTED";
  }
  return normalizeSecurityFailureMarker({ version: 1, code: code || FALLBACKS[phase], phase,
    ...(httpStatus === undefined ? {} : { httpStatus }), journalPresent: context.journalPresent === true,
    mutationStarted: typeof context.mutationStarted === "boolean" ? context.mutationStarted : phase === "security_operation" ? null : false });
}
