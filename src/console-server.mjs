#!/usr/bin/env node
import { createDynamicProxies, create1024Extractor } from "./dynamic-proxy.mjs";
import { createDynamicCrsAdapter } from "./dynamic-proxy-crs.mjs";
import { createAccountHistory } from "./account-history.mjs";
import { createOperationProxies } from "./operation-proxy.mjs";
import { createAccountLifecycle, normalizeAccountTerm, normalizeAccountArea, resolveAccountTerms, isRetiredAccountFailure } from "./account-lifecycle.mjs";
import { getAccountTls } from "./account-tls.mjs";
import { createSecurityOperationStore, isSecurityMode, securityActionMode, requireSocks5Proxy,
  publicSecurityOperation, safeSecurityError, validateSecurityResult } from "./security-operation-store.mjs";
import { normalizeSecurityFailureMarker } from "./security-failure.mjs";
import { createScheduledTaskStore, createScheduledTaskEngine, normalizeSchedule, publicSchedule, publicScheduleItem } from "./scheduled-tasks.mjs";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { authenticateBridge, createCrsLoginBridge } from "./crs-login-bridge.mjs";
import { awaitRuntimeActivation } from "./runtime-control.mjs";
import { fileURLToPath } from "node:url";

import { createConsoleWebServer } from "./web-server.mjs";
import { createServerDatabase } from "./server-database.mjs";
import { createCrsIntegration } from "./crs-integration.mjs";
import {
  fetchMailboxOtpCandidates,
  filterMailboxOtpCandidatesByRequestTime,
  validateMailApiUrl,
} from "./mail-otp.mjs";
import { createSmsProvider, publicSmsProviderDefinitions } from "./sms-providers.mjs";
import { proxySupportsSessionRotation } from "./tls-transport.mjs";

const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_PORT = 4399;
const MAX_ACTIVE_JOBS = 20;
const MAX_BATCH_JOBS = 500;
const MAX_PROXY_RISK_RETRIES = 10;
const MAX_PROXY_CONNECTION_FAILURES = 20;
const PROXY_CONNECTION_RETRY_BASE_MS = Math.max(1, Number(process.env.PROXY_CONNECTION_RETRY_BASE_MS || 1_000));
const PROXY_CONNECTION_RETRY_MAX_MS = 15_000;
const PAGE_SIZE = 20;
const MAX_LOG_CHARS = 80_000;
const JOB_META_FILENAME = "job-meta.json";
const LOGIN_CHECKPOINT_FILENAME = "login-checkpoint.json";
const TOTP_SETUP_RESULT_FILENAME = "totp-setup-result.json";
const PASSWORD_ADD_RESULT_FILENAME = "password-add-result.json";
const SUB2API_MONITOR_FILENAME = "sub2api-monitor.json";
const SUB2API_MONITOR_INTERVAL_MS = readDurationEnv("SUB2API_MONITOR_INTERVAL_MS", 5 * 60_000, 1_000);
const SUB2API_AUTO_REPAIR_COOLDOWN_MS = readDurationEnv("SUB2API_AUTO_REPAIR_COOLDOWN_MS", 5 * 60_000, 0);
const MAIL_POLL_INTERVAL_MS = 2_500;
const MAIL_POLL_TIMEOUT_MS = 10 * 60_000;
const MAX_MAIL_REQUEST_BODY_BYTES = 64 * 1024;
const MAX_MAIL_REQUEST_HEADERS = 64;
const FORBIDDEN_MAIL_REQUEST_HEADERS = new Set([
  "connection",
  "content-length",
  "host",
  "keep-alive",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);
const SMS_POLL_INTERVAL_MS = Number(process.env.SMS_POLL_INTERVAL_MS || process.env.LUBAN_SMS_POLL_INTERVAL_MS || 3_000);
const SMS_POLL_TIMEOUT_MS = Number(process.env.SMS_POLL_TIMEOUT_MS || process.env.LUBAN_SMS_POLL_TIMEOUT_MS || 10 * 60_000);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TOOL_ROOT = path.resolve(__dirname, "..");
const WEB_ROOT = path.join(TOOL_ROOT, "web");
const PROTOCOL_SCRIPT = path.resolve(process.env.ONBOARDING_PROTOCOL_SCRIPT || path.join(__dirname, "protocol-login.mjs"));
const WORKSPACE_ROOT = TOOL_ROOT;
const OUTPUT_ROOT = path.resolve(
  process.env.ONBOARDING_OUTPUT_ROOT || path.join(WORKSPACE_ROOT, "tmp", "chatgpt-onboarding-console"),
);
const SUB2API_MONITOR_PATH = path.join(OUTPUT_ROOT, SUB2API_MONITOR_FILENAME);
let serverDatabase;
let crsIntegration;
let crsLoginBridge;
let scheduledTasks;
let scheduledTaskStore;
let scheduleCreationTail = Promise.resolve();
let runtimeDraining = false;
let activeHttpMutations = 0;
const inheritedConsoleToken = process.env.TOSUB2_CONSOLE_TOKEN;
if (inheritedConsoleToken !== undefined && !/^[A-Za-z0-9_-]{32,128}$/.test(inheritedConsoleToken)) throw new Error("TOSUB2_CONSOLE_TOKEN 格式无效");
const consoleToken = inheritedConsoleToken || crypto.randomBytes(24).toString("base64url");
const jobs = new Map();
const customSmsPoolPositions = new Map();
const emailJobLocks = new Map();
let outputSyncPromise = null;
let lastOutputSyncAt = 0;
let shuttingDown = false;
let queueSchedulingPaused = false;
let shutdownPromise = null;
let sub2ApiMonitorConfig = null;
let sub2ApiMonitorTimer = null;
let sub2ApiMonitorPromise = null;
let mailRequestConfig = { method: "GET", url: null, headers: {} };
const sub2ApiRequestControllers = new Set();
const sub2ApiRequestPromises = new Set();
const sub2ApiAutoRepairPromises = new Set();
const sub2ApiUploadingEmails = new Set();
const sub2ApiMonitorState = {
  running: false,
  lastCheckAt: null,
  nextCheckAt: null,
  lastError: null,
  lastResult: null,
};

const hostArg = process.argv.find((item) => item.startsWith("--host="));
const hostIndex = process.argv.indexOf("--host");
const requestedHost = String(
  hostArg?.slice("--host=".length)
    || (hostIndex >= 0 ? process.argv[hostIndex + 1] : "")
    || process.env.ONBOARDING_HOST
    || DEFAULT_HOST,
).trim();
const portArg = process.argv.find((item) => item.startsWith("--port="));
const portIndex = process.argv.indexOf("--port");
const requestedPort = Number(
  portArg?.slice("--port=".length) || (portIndex >= 0 ? process.argv[portIndex + 1] : "") || DEFAULT_PORT,
);
const hmrPort = requestedPort <= 45_535 ? requestedPort + 20_000 : requestedPort - 20_000;

if (!requestedHost || requestedHost.startsWith("--")) {
  throw new Error("--host must be a valid hostname or IP address");
}

if (!Number.isInteger(requestedPort) || requestedPort < 1 || requestedPort > 65535) {
  throw new Error("--port must be an integer between 1 and 65535");
}

await awaitRuntimeActivation({ host: requestedHost, port: requestedPort, secret: process.env.CRS_LOGIN_BRIDGE_KEY, enabled: process.env.TOSUB2_STANDBY === "1" });
await fs.mkdir(OUTPUT_ROOT, { recursive: true });
serverDatabase = createServerDatabase({ outputRoot: OUTPUT_ROOT });
const accountHistory = createAccountHistory(serverDatabase);
const accountLifecycle = createAccountLifecycle(serverDatabase);
const operationProxies = createOperationProxies({ database: serverDatabase, enabled: process.env.TOSUB2_DEFAULT_OPERATION_PROXY_ENABLED === "1" });
const securityOperations = createSecurityOperationStore(serverDatabase);
scheduledTaskStore = createScheduledTaskStore(serverDatabase);
serverDatabase.migrateLegacy();
serverDatabase.restoreWorkspace();
for (const [poolKey, position] of Object.entries(serverDatabase.get("runtime", "sms-pool-positions") || {})) {
  if (Number.isSafeInteger(position) && position >= 0) customSmsPoolPositions.set(poolKey, position);
}
const savedSettings = serverDatabase.getSettings().settings;
if (savedSettings.mail) applySharedMailSettings(savedSettings.mail);
await loadSub2ApiMonitorConfiguration();
if (savedSettings.sub2api) {
  sub2ApiMonitorConfig = savedSettings.sub2api.monitorEnabled
    ? { ...normalizeSub2ApiConfig(savedSettings.sub2api), enabled: true }
    : null;
  await persistSub2ApiMonitorConfiguration();
} else if (sub2ApiMonitorConfig) {
  serverDatabase.migrateSettings({ sub2api: {
    ...sub2ApiMonitorConfig,
    groupIds: sub2ApiMonitorConfig.groupIds.map(String),
    modelWhitelist: sub2ApiMonitorConfig.modelWhitelist.join("\n"),
    monitorEnabled: sub2ApiMonitorConfig.enabled,
  } });
}
await syncCompletedOutputs(true);
await restoreSecurityOperations();
for (const job of jobs.values()) accountLifecycle.backfill(job, securityOperations.list(job));
crsIntegration = createCrsIntegration({
  database: serverDatabase,
  getJob: (id) => {
    const job = jobs.get(id);
    return job ? { ...job, ...accountLifecycle.public(job.email) } : null;
  },
  readExport: async (job) => {
    const value = serverDatabase.readArtifact(job.outputPath);
    if (!value) throw httpError(409, "账号授权文件尚未保存到服务器数据库");
    return value;
  },
});
const dynamicCrs = createDynamicCrsAdapter(crsIntegration);
const dynamicExtractionEnabled = process.env.TOSUB2_DYNAMIC_PROXY_EXTRACTION === "1";
const dynamicProxies = createDynamicProxies({
  database: serverDatabase, crs: dynamicCrs,
  allowExtraction: dynamicExtractionEnabled,
  extract: create1024Extractor({ allowExtraction: dynamicExtractionEnabled }),
  probe: (url) => dynamicCrs.probe(url),
  synchronize: async (record, { phase, intent }) => withEmailJobLock(record.email, async () => {
    const job = findJobByEmail(record.email);
    if (intent === "login" && (!job || !isActive(job.status))) throw httpError(409, "登录任务已结束，停止代理准备");
    if (job?.child || job && isActive(job.status) && !job.dynamicProxyPreparing) throw httpError(409, "账号正在登录，等待当前任务结束后切换代理");
    if (phase !== "isolate" && record.proxyUrl) {
      const stored = await loadStoredLoginCredentials(record.email);
      await saveStoredLoginCredentials(record.email, { ...stored, proxyUrl: record.proxyUrl });
      if (job) { job.proxyUrl = record.proxyUrl; await saveJobMetadata(job); }
    }
  }),
});
let dynamicCycleRunning = false;
let dynamicCyclePromise = null;
const dynamicTimer = setInterval(() => {
  if (dynamicCycleRunning || runtimeDraining || shuttingDown || !dynamicProxies.bindings().length) return;
  dynamicCycleRunning = true;
  dynamicCyclePromise = (async () => {
  try {
    const demands = await dynamicCrs.demands();
    for (const binding of dynamicProxies.bindings()) {
      const lifecycle = accountLifecycle.public(binding.email);
      if (lifecycle.resting || lifecycle.retired || scheduledTaskStore.owner(binding.email) || findJobByEmail(binding.email)?.loginDeferred) continue;
      try { if (await dynamicProxies.refreshManualSelection(binding.email)) continue; }
      catch { continue; /* 无法确认人工选择时不得续换 */ }
      const demand = demands.find((item) => item.bindingId === binding.id);
      if (!demand?.requestedAt || demand.requestedAt === binding.consumedDemandAt) continue;
      try {
        await dynamicProxies.ensure(binding.email, "business");
        dynamicProxies.acknowledgeDemand(binding.email, demand.requestedAt);
      } catch { /* 恢复状态保存在两边，周期任务不输出凭据或原始供应商错误 */ }
    }
  } catch { /* CRS 不可达时不提取 */ }
  finally { dynamicCycleRunning = false; }
  })();
}, 15000);
dynamicTimer.unref();

crsLoginBridge = createCrsLoginBridge({
  database: serverDatabase,
  inspect: (id) => jobs.get(id),
  isRetrying: loginRetryPending,
  readCredentials: async (job) => job.crsBridgeResultOperationId === job.crsBridgeOperationId ? serverDatabase.readArtifact(job.outputPath)?.accounts?.[0]?.credentials : null,
  start: async (input, bind) => {
    if (findJobByEmail(input.email)?.loginDeferred) throw httpError(409, "账号仅记录，自动登录已暂停；请手动上号或安排定时任务");
    if (scheduledTaskStore.owner(input.email)) throw httpError(409, "账号有定时任务，自动重新登录已暂停");
    await dynamicProxies.refreshManualSelection(input.email);
    await assertManagedReloginCurrent(input.email, input.operationId);
    return withEmailJobLock(input.email, async () => {
      if (runtimeDraining || shuttingDown) throw httpError(409, "实例正在排空登录任务");
      const existing = findJobByEmail(input.email);
      if (scheduledTaskStore.owner(input.email)) throw httpError(409, "账号有定时任务，自动重新登录已暂停");
      if (existing?.autoRepairBlocked) throw httpError(409, existing.autoRepairBlockedReason || "上次授权失败，自动登录已暂停，请手动重试");
      if (existing?.loginDeferred) throw httpError(409, "账号仅记录，自动登录已暂停；请手动上号或安排定时任务");
      if (existing?.emailLoginAutoPaused) throw httpError(409, "邮箱验证未完成，自动重新登录已暂停，请手动重新登录或更新资料");
      if (existing && !canForceRelogin(existing)) throw httpError(409, "该账号已有登录任务");
      if (existing && (existing.securityAutoLoginPaused || (accountLifecycle.public(existing.email).resting || accountLifecycle.public(existing.email).retired) || securityOperations.blockingRotation(existing))) {
        throw httpError(409, "账号安全操作已暂停自动登录，请先手动恢复并核实结果");
      }
      const stored = await loadStoredLoginCredentials(input.email);
      const credentials = normalizeLoginCredentials({
        password: input.password ?? stored.password,
        totpSecret: input.totpSecret ?? stored.totpSecret,
        mailApiUrl: existing?.mailApiUrl,
        mailRequestBody: existing?.mailRequestBody,
      });
      if (!credentials.password) throw httpError(409, "该账号没有已保存的登录密码");
      const proxyOptions = Object.hasOwn(input, "proxyUrl")
        ? { proxyUrl: input.proxyUrl === null && operationProxies.enabled ? { useDefaultProxy: true } : input.proxyUrl } : {};
      const proxyChoice = selectOperationProxy(input.email, proxyOptions);
      const proxyUrl = proxyChoice.proxyUrl;
      if (existing) {
        bind(existing.id);
        await updateJobCredentials(existing, credentials, { proxyUrl, hasProxyUpdate: true });
        await forceReloginJob(existing, proxyOptions, { crsBridgeOperationId: input.operationId });
        await saveJobMetadata(existing);
      } else {
        const id = crypto.randomUUID();
        bind(id);
        await startJob(input.email, credentials, proxyUrl, { id, crsBridgeOperationId: input.operationId, operationProxyChoice: proxyChoice });
      }
    });
  },
});
await restoreScheduledJobState();
scheduledTasks = createScheduledTaskEngine({ store: scheduledTaskStore, hooks: scheduledTaskHooks() });
scheduleQueuedJobs();
scheduleSub2ApiMonitor();
scheduledTasks.start();

const vite = await createConsoleWebServer({ root: WEB_ROOT, hmrPort });

const server = http.createServer(async (req, res) => {
  // Some reads persist reconciled results; count them during a handover too.
  const mutation = (req.url || "").startsWith("/api/") && !(req.url || "").startsWith("/api/integrations/crs/runtime/");
  if (mutation) activeHttpMutations += 1;
  try {
    enforceUtf8ContentType(res);
    const requestUrl = new URL(req.url || "/", `http://${req.headers.host || `${requestedHost}:${requestedPort}`}`);
    if (requestUrl.pathname.startsWith("/api/")) {
      await handleApi(req, res, requestUrl);
      return;
    }
    vite.middlewares(req, res, (error) => {
      if (error) sendJson(res, 500, { error: error.message || "Page rendering failed" });
    });
  } catch (error) {
    sendJson(res, error.status || 500, { error: error.message || "Internal server error" });
  } finally { if (mutation) activeHttpMutations -= 1; }
});

function runtimeStatus() {
  const queued = [...jobs.values()].filter((job) => job.status === "queued").length;
  const active = [...jobs.values()].filter((job) => isActive(job.status) && job.status !== "queued").length;
  const childProcesses = [...jobs.values()].filter((job) => job.child && job.child.exitCode === null && job.child.signalCode === null).length;
  const crs = crsIntegration?.runtimeStatus() || { pending: 0, running: 0, workerActive: false };
  const monitorRunning = Boolean(outputSyncPromise || sub2ApiMonitorState.running || sub2ApiMonitorPromise || sub2ApiRequestPromises.size || sub2ApiAutoRepairPromises.size);
  const loginStarts = crsLoginBridge?.activeStarts() || 0;
  const metadataWrites = [...jobs.values()].reduce((sum, job) => sum + (job.pendingMetadataWrites || 0), 0);
  const accountOperations = emailJobLocks.size;
  const schedulerRunning = scheduledTasks?.active() || false;
  return { mode: runtimeDraining ? "draining" : "active", ready: !shuttingDown, active, queued, childProcesses, crs, monitorRunning, loginStarts, activeHttpMutations, metadataWrites, accountOperations, schedulerRunning, readyToStop: runtimeDraining && !active && !queued && !childProcesses && !crs.pending && !crs.running && !crs.workerActive && !monitorRunning && !loginStarts && !activeHttpMutations && !metadataWrites && !accountOperations && !dynamicCycleRunning && !dynamicProxies.activeOperations() && !operationProxies.activeOperations() && !schedulerRunning };
}

function enforceUtf8ContentType(res) {
  const setHeader = res.setHeader;
  res.setHeader = function setUtf8Header(name, value) {
    if (String(name).toLowerCase() === "content-type") {
      value = addUtf8Charset(value);
    }
    return setHeader.call(this, name, value);
  };
}

function addUtf8Charset(value) {
  if (typeof value !== "string" || /;\s*charset=/i.test(value)) return value;
  if (/^(?:text\/(?:html|css|javascript|plain)|application\/(?:javascript|json))(?:\s*;|$)/i.test(value)) {
    return `${value}; charset=utf-8`;
  }
  return value;
}

server.listen(requestedPort, requestedHost, () => {
  const urls = getConsoleUrls(requestedHost, requestedPort);
  console.log(`[ok] ChatGPT onboarding console: ${urls[0]}`);
  for (const url of urls.slice(1)) console.log(`[ok] LAN access: ${url}`);
  console.log(`[info] Output directory: ${OUTPUT_ROOT}`);
  if (isWildcardHost(requestedHost)) {
    console.log("[note] LAN access is enabled without authentication. Keep downloaded OAuth files private.");
  } else {
    console.log("[note] This server only listens on the configured host. Keep downloaded OAuth files private.");
  }
});

function isWildcardHost(host) {
  return host === "0.0.0.0" || host === "::";
}

function getConsoleUrls(host, port) {
  if (!isWildcardHost(host)) return [`http://${host}:${port}`];
  const addresses = Object.values(os.networkInterfaces())
    .flatMap((entries) => entries || [])
    .filter((entry) => entry.family === "IPv4" && !entry.internal)
    .map((entry) => entry.address);
  return [
    `http://127.0.0.1:${port}`,
    ...[...new Set(addresses)].map((address) => `http://${address}:${port}`),
  ];
}

async function handleApi(req, res, requestUrl) {
  if (requestUrl.pathname.startsWith("/api/integrations/crs/")) {
    try {
      authenticateBridge(req.headers.authorization, process.env.CRS_LOGIN_BRIDGE_KEY);
      if (requestUrl.search) throw httpError(400, "桥接请求不能包含查询参数");
      const endpoint = requestUrl.pathname;
      if (endpoint === "/api/integrations/crs/runtime/status" && req.method === "GET") {
        sendJson(res, 200, runtimeStatus()); return;
      }
      if (endpoint === "/api/integrations/crs/runtime/drain" && req.method === "POST") {
        runtimeDraining = true;
        if (sub2ApiMonitorTimer) { clearInterval(sub2ApiMonitorTimer); sub2ApiMonitorTimer = null; }
        sendJson(res, 200, runtimeStatus()); return;
      }
      if (endpoint === "/api/integrations/crs/runtime/resume" && req.method === "POST") {
        runtimeDraining = false; scheduleSub2ApiMonitor();
        sendJson(res, 200, runtimeStatus()); return;
      }
      if (endpoint === "/api/integrations/crs/login" && req.method === "POST") {
        if (runtimeDraining || shuttingDown) throw httpError(409, "实例正在排空登录任务");
        const body = await readJson(req, 16 * 1024);
        sendJson(res, 202, await crsLoginBridge.submit(body)); return;
      }
      const match = endpoint.match(/^\/api\/integrations\/crs\/login\/([A-Za-z0-9][A-Za-z0-9:_-]{0,127})$/);
      if (match && req.method === "GET") { sendJson(res, 200, await crsLoginBridge.get(match[1])); return; }
      throw httpError(404, "桥接接口不存在");
    } catch (error) {
      sendJson(res, error.status || 500, { error: error.status ? error.message : "CRS 桥接请求失败" }); return;
    }
  }
  if (req.method === "GET" && requestUrl.pathname === "/api/bootstrap") {
    sendJson(res, 200, {
      token: consoleToken,
      features: {
        retry: true,
        regenerate: true,
        phoneContext: true,
        batchDownload: true,
        bulkActions: true,
        pagination: true,
        uniqueEmail: true,
        smsProviders: publicSmsProviderDefinitions(),
        queue: true,
        sourceExport: true,
        cancelAll: true,
        sub2apiUpload: true,
        sub2apiMonitor: true,
        tlsFingerprint: true,
        totpSetup: true,
        passwordAdd: true,
        forceRelogin: true,
        accountSecurity: true,
        defaultOperationProxy: { configured: operationProxies.enabled, provider: "1024-white", country: "US", label: "1024 美国动态代理" },
      },
    });
    return;
  }

  if (req.headers["x-console-token"] !== consoleToken) {
    sendJson(res, 403, { error: "Invalid console token" });
    return;
  }
  if (runtimeDraining && req.method !== "GET" && !/^\/api\/jobs\/[^/]+\/(input|cancel)$/.test(requestUrl.pathname)) {
    sendJson(res, 409, { error: "实例正在排空已接收的任务" }); return;
  }

  if (requestUrl.pathname === "/api/dynamic-proxies") {
    if (req.method === "GET") { sendJson(res, 200, { profiles: dynamicProxies.profiles(), bindings: dynamicProxies.bindings(), extractionEnabled: dynamicExtractionEnabled }); return; }
    if (req.method === "POST") {
      const body = await readJson(req, 16384);
      if (body.action === "saveProfile") { sendJson(res, 200, dynamicProxies.saveProfile(body.profile, body.revision)); return; }
      if (body.action === "reconcile" && body.confirm === "checked_provider_history") { sendJson(res, 200, dynamicProxies.reconcile(body.email, body.proxyUrl || null, body.revision)); return; }
      throw httpError(400, "动态代理操作无效");
    }
  }
  if (requestUrl.pathname === "/api/settings" && req.method === "GET") {
    sendJson(res, 200, serverDatabase.getSettings());
    return;
  }

  if (requestUrl.pathname === "/api/crs/config" && req.method === "GET") {
    sendJson(res, 200, crsIntegration.getConfiguration());
    return;
  }
  if (requestUrl.pathname === "/api/crs/groups" && req.method === "GET") {
    sendJson(res, 200, await crsIntegration.groups()); return;
  }
  if (requestUrl.pathname === "/api/crs/account-settings" && req.method === "GET") {
    sendJson(res, 200, crsIntegration.accountSettings()); return;
  }
  if (requestUrl.pathname === "/api/crs/account-settings" && req.method === "PUT") {
    const body = await readJson(req);
    sendJson(res, 200, await crsIntegration.saveAccountSettings(body.ids, body.settings)); return;
  }
  if (requestUrl.pathname === "/api/crs/config" && req.method === "PUT") {
    const body = await readJson(req);
    const result = crsIntegration.putConfiguration(body.config, body.revision);
    sendJson(res, result.conflict ? 409 : 200, { ...(result.conflict ? { error: "CRS 配置已在其他页面更新，请检查最新内容后重试" } : {}), config: result.config, revision: result.revision });
    return;
  }
  if (requestUrl.pathname === "/api/crs/test" && req.method === "POST") {
    const body = await readJson(req);
    sendJson(res, 200, await crsIntegration.testConfiguration(body.config));
    return;
  }
  if (requestUrl.pathname === "/api/crs/upload" && req.method === "POST") {
    const body = await readJson(req);
    sendJson(res, 200, await crsIntegration.enqueue(body.ids));
    return;
  }
  if (requestUrl.pathname === "/api/crs/status" && req.method === "GET") {
    sendJson(res, 200, crsIntegration.status());
    return;
  }
  if (requestUrl.pathname === "/api/crs/retry" && req.method === "POST") {
    const body = await readJson(req);
    sendJson(res, 200, crsIntegration.retry(body.ids));
    return;
  }

  if (requestUrl.pathname === "/api/settings" && req.method === "PUT") {
    const body = await readJson(req);
    const section = body.section;
    const value = normalizeSharedSettings(section, body.value);
    if (!Number.isSafeInteger(body.revision) || body.revision < 0) throw httpError(400, "配置版本无效，请刷新后重试");
    const result = serverDatabase.putSetting(section, value, body.revision);
    if (result.conflict) {
      sendJson(res, 409, { error: "配置已在其他页面更新，请检查最新内容后重试", settings: result.settings, revisions: result.revisions });
      return;
    }
    await applySharedSettings(section, value);
    sendJson(res, 200, { settings: result.settings, revisions: result.revisions });
    return;
  }

  if (requestUrl.pathname === "/api/settings/migrate" && req.method === "POST") {
    const body = await readJson(req);
    if (!isPlainObject(body.settings)) throw httpError(400, "迁移配置格式不正确");
    const values = {};
    for (const [section, value] of Object.entries(body.settings)) {
      const normalized = normalizeSharedSettings(section, value);
      if (section === "sub2api") normalized.monitorEnabled = false;
      if (hasSharedSettingsValue(section, normalized)) values[section] = normalized;
    }
    const before = serverDatabase.getSettings();
    const result = serverDatabase.migrateSettings(values);
    for (const section of Object.keys(values)) {
      if (!Object.hasOwn(before.settings, section)) await applySharedSettings(section, result.settings[section]);
    }
    sendJson(res, 200, result);
    return;
  }

  if (req.method === "GET" && requestUrl.pathname === "/api/jobs") {
    const requestedPage = Math.max(1, Number.parseInt(requestUrl.searchParams.get("page") || "1", 10) || 1);
    await sendJobsPage(res, requestedPage, null, "", normalizeAccountArea(requestUrl.searchParams.get("area") || "all"));
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/jobs/query") {
    const body = await readJson(req);
    const requestedPage = Math.max(1, Number.parseInt(body.page || "1", 10) || 1);
    const search = String(body.search || "").trim().toLowerCase().slice(0, 200);
    await sendJobsPage(res, requestedPage, body.emails === undefined ? null : normalizeEmailFilter(body.emails), search, normalizeAccountArea(body.area === undefined ? "all" : body.area));
    return;
  }

  if (requestUrl.pathname === "/api/schedules/preview" && req.method === "POST") {
    const preview = previewScheduledTask(await readJson(req));
    sendJson(res, 200, publicSchedulePreview(preview)); return;
  }
  if (requestUrl.pathname === "/api/schedules" && req.method === "GET") {
    sendJson(res, 200, { schedules: scheduledTaskStore.list().map(publicSchedule) }); return;
  }
  if (requestUrl.pathname === "/api/schedules" && req.method === "POST") {
    const body = await readJson(req);
    const operation = scheduleCreationTail.then(() => createScheduledTask(body));
    scheduleCreationTail = operation.catch(() => {});
    const value = await operation;
    sendJson(res, 201, scheduleDetail(value)); return;
  }
  const scheduleMatch = requestUrl.pathname.match(/^\/api\/schedules\/([a-f0-9-]{36})(?:\/(cancel))?$/i);
  if (scheduleMatch) {
    if (req.method === "GET" && !scheduleMatch[2]) {
      const value = scheduledTaskStore.read(scheduleMatch[1]);
      if (!value) throw httpError(404, "计划不存在");
      sendJson(res, 200, scheduleDetail(value)); return;
    }
    if (req.method === "POST" && scheduleMatch[2] === "cancel") {
      const body = await readJson(req);
      sendJson(res, 200, scheduleDetail(await scheduledTasks.cancel(scheduleMatch[1], body.itemIds))); return;
    }
    throw httpError(405, "Method not allowed");
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/mail-request-config") {
    const body = await readJson(req);
    mailRequestConfig = normalizeMailRequestConfig(body.config);
    const current = serverDatabase.getSettings();
    serverDatabase.putSetting("mail", { method: mailRequestConfig.method, url: mailRequestConfig.url || "", headersText: JSON.stringify(mailRequestConfig.headers, null, 2) }, current.revisions.mail || 0);
    sendJson(res, 200, {
      config: {
        method: mailRequestConfig.method,
        urlConfigured: Boolean(mailRequestConfig.url),
        headerCount: Object.keys(mailRequestConfig.headers).length,
      },
    });
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/jobs") {
    const body = await readJson(req);
    const startLogin = readStartLogin(body);
    const loginFlow = readLoginFlow(body);
    const email = String(body.email || "").trim();
    const accountTerms = resolveAccountTerms([{ email }], body);
    if (!isEmail(email)) {
      sendJson(res, 400, { error: "Please enter a valid email address" });
      return;
    }
    if (!startLogin) {
      const [result] = await saveOnlyAccounts([{ ...body, email }], body, { partialCredentials: true });
      sendJson(res, result.created ? 201 : 200, { ...result, job: publicJob(result.job) });
      return;
    }
    const hasCredentialUpdate = ["password", "mailApiUrl", "mailRequestBody", "totpSecret"].some((key) => Object.hasOwn(body, key));
    const credentials = normalizeLoginCredentials(body);
    const hasProxyUpdate = Object.hasOwn(body, "proxyUrl");
    const proxyChoice = selectOperationProxy(email, body);
    const proxyUrl = proxyChoice.proxyUrl;
    const result = await withEmailJobLock(email, async () => {
      const existing = findJobByEmail(email);
      if (existing) {
        if (hasCredentialUpdate) await updateJobCredentials(existing, credentials, { proxyUrl, hasProxyUpdate, operationProxyChoice: proxyChoice, loginFlow });
        else if (hasProxyUpdate) await updateJobProxy(existing, proxyUrl, { operationProxyChoice: proxyChoice });
        if (accountTerms.explicit(email)) accountLifecycle.setTerm(email, accountTerms.term(email));
        return { job: existing, created: false, updated: hasCredentialUpdate || hasProxyUpdate || accountTerms.explicit(email) };
      }
      return { job: await startJob(email, credentials, proxyUrl, { accountTerm: accountTerms.term(email), operationProxyChoice: proxyChoice, loginFlow }), created: true, updated: false };
    });
    sendJson(res, result.created ? 201 : 200, { ...result, job: publicJob(result.job) });
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/jobs/preview") {
    const body = await readJson(req);
    const entries = parseBatchEntries(body.text, mailRequestConfig);
    sendJson(res, 200, {
      accounts: entries.map(({ email }) => ({ email })),
      count: entries.length,
    });
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/jobs/batch") {
    const body = await readJson(req);
    const startLogin = readStartLogin(body);
    const loginFlow = readLoginFlow(body);
    const entries = parseBatchEntries(body.text, mailRequestConfig);
    const accountTerms = resolveAccountTerms(entries, body);
    if (!startLogin) {
      const results = await saveOnlyAccounts(entries, body);
      sendJson(res, 201, { jobs: results.map((item) => publicJob(item.job)),
        created: results.filter((item) => item.created).length, updated: results.filter((item) => !item.created).length });
      return;
    }
    const proxyAssignments = resolveBatchProxyAssignments(body, entries, "email");
    const hasProxyUpdate = Boolean(proxyAssignments) || Object.hasOwn(body, "proxyUrl");
    // Validate every default/specific selection before any account is written.
    for (const entry of entries) selectOperationProxy(entry.email, proxyAssignments ? { proxyUrl: proxyAssignments.get(entry.email.toLowerCase()) } : body, { preview: true });
    const results = await Promise.all(entries.map((entry) => withEmailJobLock(entry.email, async () => {
      const proxyChoice = selectOperationProxy(entry.email, proxyAssignments ? { proxyUrl: proxyAssignments.get(entry.email.toLowerCase()) } : body);
      const proxyUrl = proxyChoice.proxyUrl;
      const existing = findJobByEmail(entry.email);
      if (existing) {
        await updateJobCredentials(existing, entry, { proxyUrl, hasProxyUpdate, operationProxyChoice: proxyChoice, loginFlow });
        if (accountTerms.explicit(entry.email)) accountLifecycle.setTerm(entry.email, accountTerms.term(entry.email));
        return { job: existing, updated: true };
      }
      return { job: await startJob(entry.email, entry, proxyUrl, { accountTerm: accountTerms.term(entry.email), operationProxyChoice: proxyChoice, loginFlow }), updated: false };
    })));
    sendJson(res, 201, {
      jobs: results.map((item) => publicJob(item.job)),
      created: results.filter((item) => !item.updated).length,
      updated: results.filter((item) => item.updated).length,
    });
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/jobs/download-batch") {
    const body = await readJson(req);
    await downloadBatchResult(res, body.ids);
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/jobs/export-source") {
    const body = await readJson(req);
    await exportSourceAccounts(res, body.ids);
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/jobs/delete-batch") {
    const body = await readJson(req);
    const selected = resolveSelectedJobs(body.ids);
    const emails = [...new Set(selected.map((job) => job.email.toLowerCase()))];
    await Promise.all(emails.map((email) => withEmailJobLock(email, () => deleteJobsByEmail(email))));
    sendJson(res, 200, { deleted: emails.length });
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/jobs/reauthorize-batch") {
    const body = await readJson(req);
    readLoginFlow(body);
    const selected = resolveSelectedJobs(body.ids);
    const proxyAssignments = resolveBatchProxyAssignments(body, selected, "id");
    const unsupported = selected.find(
      (job) => !["completed", "failed", "canceled", "reauth_required", "resume_available"].includes(job.status) && !(job.loginDeferred && job.status === "ready"),
    );
    if (unsupported) throw httpError(409, `${unsupported.email} 当前仍在进行中，不能重新授权`);
    await Promise.all(selected.map((job) => withEmailJobLock(job.email, async () => {
      const options = batchProxyOptions(body, proxyAssignments, job.id);
      if (job.status === "completed") await regenerateJob(job, options);
      else await retryJob(job, options);
    })));
    sendJson(res, 200, { jobs: selected.map(publicJob), started: selected.length });
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/jobs/relogin-batch") {
    const body = await readJson(req);
    readLoginFlow(body);
    const selected = resolveSelectedJobs(body.ids);
    const proxyAssignments = resolveBatchProxyAssignments(body, selected, "id");
    const started = await Promise.all(selected.map((job) => withEmailJobLock(job.email, async () => {
      if (!canForceRelogin(job)) return null;
      await forceReloginJob(job, batchProxyOptions(body, proxyAssignments, job.id));
      return job;
    })));
    const eligible = started.filter(Boolean);
    if (!eligible.length) throw httpError(409, "选中的账号当前都不能重新登录");
    sendJson(res, 200, {
      jobs: eligible.map(publicJob),
      started: eligible.length,
      skipped: selected.length - eligible.length,
    });
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/jobs/security/batch") {
    const body = await readJson(req);
    securityActionMode(body.action);
    const selected = resolveSelectedJobs(body.ids);
    // Validate the assignment structure once, but report each account's eligibility separately.
    const assignments = resolveSecurityBatchProxyAssignments(body, selected);
    const results = await Promise.all(selected.map((job) => withEmailJobLock(job.email, async () => {
      try {
        if (!isTerminalStatus(job.status) || job.child) return { id: job.id, email: job.email, status: "skipped", error: "账号当前有任务正在执行" };
        const operation = await startSecurityOperation(job, body.action, batchProxyOptions(body, assignments, job.id));
        return { id: job.id, email: job.email, status: "started", operationId: operation.operationId };
      } catch (error) {
        return { id: job.id, email: job.email, status: "error", error: safeSecurityError(error.message, [job.password, job.totpSecret, job.proxyUrl]) };
      }
    })));
    const accepted = new Set(results.filter((item) => item.status === "started").map((item) => item.id));
    sendJson(res, 200, {
      jobs: selected.filter((job) => accepted.has(job.id)).map(publicJob),
      started: accepted.size, skipped: results.filter((item) => item.status === "skipped").length,
      errors: results.filter((item) => item.status === "error").map(({ id, email, error }) => ({ id, email, error })), results,
    });
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/jobs/setup-2fa-batch") {
    const body = await readJson(req);
    const selected = resolveSelectedJobs(body.ids);
    const proxyAssignments = resolveBatchProxyAssignments(body, selected, "id");
    const started = await Promise.all(selected.map((job) => withEmailJobLock(job.email, async () => {
      if (!canSetupTotp(job)) return null;
      await startTotpSetup(job, batchProxyOptions(body, proxyAssignments, job.id));
      return job;
    })));
    const eligible = started.filter(Boolean);
    if (!eligible.length) throw httpError(409, "选中的账号都不能设置 2FA");
    sendJson(res, 200, {
      jobs: eligible.map(publicJob),
      started: eligible.length,
      skipped: selected.length - eligible.length,
    });
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/jobs/add-password-batch") {
    const body = await readJson(req);
    const selected = resolveSelectedJobs(body.ids);
    const proxyAssignments = resolveBatchProxyAssignments(body, selected, "id");
    const started = await Promise.all(selected.map((job) => withEmailJobLock(job.email, async () => {
      if (!canAddPassword(job)) return null;
      await startPasswordAdd(job, batchProxyOptions(body, proxyAssignments, job.id));
      return job;
    })));
    const eligible = started.filter(Boolean);
    if (!eligible.length) throw httpError(409, "选中的账号当前都不能添加密码");
    sendJson(res, 200, {
      jobs: eligible.map(publicJob),
      started: eligible.length,
      skipped: selected.length - eligible.length,
    });
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/jobs/cancel-all") {
    const canceled = await cancelAllJobs();
    sendJson(res, 200, { canceled });
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/sub2api/groups") {
    const body = await readJson(req);
    const config = normalizeSub2ApiConfig(body.config);
    const payload = await requestSub2Api(config, "/api/v1/admin/groups/all?platform=openai");
    const groups = Array.isArray(payload) ? payload : Array.isArray(payload?.data) ? payload.data : [];
    sendJson(res, 200, {
      groups: groups
        .filter((group) => group && Number.isInteger(Number(group.id)))
        .map((group) => ({
          id: Number(group.id),
          name: String(group.name || `号池 ${group.id}`),
          status: String(group.status || "active"),
        })),
    });
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/sub2api/options") {
    const body = await readJson(req);
    const config = normalizeSub2ApiConfig(body.config);
    const [groupPayload, proxyPayload] = await Promise.all([
      requestSub2Api(config, "/api/v1/admin/groups/all?platform=openai"),
      requestSub2Api(config, "/api/v1/admin/proxies/all"),
    ]);
    const groups = Array.isArray(groupPayload) ? groupPayload : Array.isArray(groupPayload?.data) ? groupPayload.data : [];
    const proxies = Array.isArray(proxyPayload) ? proxyPayload : Array.isArray(proxyPayload?.data) ? proxyPayload.data : [];
    sendJson(res, 200, {
      groups: groups
        .filter((group) => group && Number.isInteger(Number(group.id)))
        .map((group) => ({ id: Number(group.id), name: String(group.name || `号池 ${group.id}`), status: String(group.status || "active") })),
      proxies: proxies
        .filter((proxy) => proxy && Number.isInteger(Number(proxy.id)))
        .map((proxy) => ({
          id: Number(proxy.id),
          name: String(proxy.name || `代理 ${proxy.id}`),
          protocol: String(proxy.protocol || ""),
          host: String(proxy.host || ""),
          port: Number(proxy.port || 0),
          ipAddress: String(proxy.ip_address || ""),
          status: String(proxy.status || "active"),
        })),
    });
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/sub2api/upload") {
    const body = await readJson(req);
    const config = normalizeSub2ApiConfig(body.config);
    const selected = resolveSelectedJobs(body.ids);
    const downloadable = selected.filter((job) => job.resultSaved);
    if (downloadable.length === 0) throw httpError(409, "选中的任务里没有已完成的导入文件");
    for (const job of downloadable) {
      const state = accountLifecycle.public(job.email);
      if (state.resting || state.retired) throw httpError(409, "静置区或废号区的账号不能推送，请先成功登录恢复在用");
      if (sub2ApiUploadingEmails.has(job.email.toLowerCase())) throw httpError(409, "账号正在推送，请等待当前操作结束");
    }
    for (const job of downloadable) sub2ApiUploadingEmails.add(job.email.toLowerCase());
    try {
      const payload = await buildSub2ApiUploadPayload(downloadable);
      const idempotencyKey = `tosub2-upload-${crypto.randomUUID()}`;

      const accounts = payload.accounts.map((account) => {
        const { proxy_key: _proxyKey, ...accountData } = account;
        const credentials = { ...(account.credentials || {}) };
        const extra = {
          ...(account.extra && typeof account.extra === "object" ? account.extra : {}),
          codex_fingerprint_mode: config.codexFingerprintMode,
        };
        if (config.modelWhitelist.length) {
          credentials.model_mapping = Object.fromEntries(config.modelWhitelist.map((model) => [model, model]));
        }
        return {
          ...accountData,
          credentials,
          extra,
          status: "active",
          schedulable: true,
          group_ids: config.groupIds.length ? config.groupIds : (account.group_ids || []),
          ...(config.proxyId ? { proxy_id: config.proxyId } : {}),
          ...(config.concurrency !== null ? { concurrency: config.concurrency } : {}),
          ...(config.loadFactor !== null ? { load_factor: config.loadFactor } : {}),
          ...(config.priority !== null ? { priority: config.priority } : {}),
        };
      });
      const result = await requestSub2Api(config, "/api/v1/admin/accounts/batch", {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey },
        body: JSON.stringify({ accounts }),
      });

      sendJson(res, 200, {
        selected: selected.length,
        uploaded: downloadable.length,
        skipped: selected.length - downloadable.length,
        groupIds: config.groupIds,
        result,
      });
    } finally {
      for (const job of downloadable) sub2ApiUploadingEmails.delete(job.email.toLowerCase());
    }
    return;
  }

  if (req.method === "GET" && requestUrl.pathname === "/api/sub2api/monitor") {
    sendJson(res, 200, publicSub2ApiMonitorState());
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/sub2api/monitor") {
    const body = await readJson(req);
    if (body.enabled) {
      const config = normalizeSub2ApiConfig(body.config);
      sub2ApiMonitorConfig = { ...config, enabled: true };
    } else {
      sub2ApiMonitorConfig = null;
    }
    sub2ApiMonitorState.lastError = null;
    await persistSub2ApiMonitorConfiguration();
    scheduleSub2ApiMonitor();
    sendJson(res, 200, publicSub2ApiMonitorState());
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/sub2api/monitor/check") {
    if (!sub2ApiMonitorConfig?.enabled) throw httpError(409, "请先启用 Sub2API 号池监控");
    const result = await runSub2ApiMonitor("manual");
    sendJson(res, 200, { ...publicSub2ApiMonitorState(), result });
    return;
  }

  const providerOptionsMatch = /^\/api\/sms-providers\/([a-z0-9_-]+)\/options$/.exec(requestUrl.pathname);
  if (req.method === "POST" && providerOptionsMatch) {
    const body = await readJson(req);
    let smsClient;
    try {
      smsClient = createSmsProvider(providerOptionsMatch[1], body.config, {
        lubanApiBase: process.env.LUBAN_SMS_API_BASE,
        smsBowerApiBase: process.env.SMSBOWER_API_BASE,
      });
      if (!smsClient.listNumberOptions) throw httpError(400, "该接码平台不支持价格查询");
      const options = await smsClient.listNumberOptions();
      sendJson(res, 200, { providerId: smsClient.id, options });
    } catch (error) {
      if (error?.status) throw error;
      throw httpError(502, safeSmsProviderError(error, body.config?.apiKey));
    }
    return;
  }

  const match = /^\/api\/jobs\/([a-f0-9-]+)(?:\/(input|cancel|retry|regenerate|relogin|setup-2fa|add-password|security(?:\/recover)?|details|secrets|proxy|account-term|rest|retire|logs|download|sms-number|luban-number))?$/.exec(requestUrl.pathname);
  if (!match) {
    sendJson(res, 404, { error: "Not found" });
    return;
  }

  const job = jobs.get(match[1]);
  if (!job) {
    sendJson(res, 404, { error: "Login flow not found" });
    return;
  }

  const action = match[2];
  if (req.method === "GET" && action === "details") {
    sendJson(res, 200, {
      id: job.id, email: job.email, status: job.status,
      ...accountLifecycle.public(job.email),
      loginDeferred: Boolean(job.loginDeferred),
    loginFlow: job.loginFlow === "legacy" ? "legacy" : "codex",
      lastError: job.lastError || null,
      emailLoginAttempt: job.emailLoginAttempt || 0,
      emailLoginReason: job.emailLoginReason || null,
      emailLoginAutoPaused: Boolean(job.emailLoginAutoPaused),
      scheduleItemId: scheduledTaskStore.owner(job.email)?.item.id || null,
      scheduleId: scheduledTaskStore.owner(job.email)?.schedule.id || null,
      history: accountHistory.detail(job, requestUrl.searchParams.get("page")),
      lastOperationAt: job.lastOperationAt, lastOperationType: job.lastOperationType,
      securityOperations: securityOperations.detail(job),
      securityOperation: publicSecurityOperation(securityOperations.latest(job)),
      securityAutoLoginPaused: Boolean(job.securityAutoLoginPaused),
      canRotateTotp: canRunAccountSecurity(job, "rotate-totp"),
      canLogoutAll: canRunAccountSecurity(job, "logout-all"),
      canRotateTotpLogoutAll: canRunAccountSecurity(job, "rotate-totp-logout-all"),
    });
    return;
  }
  if (req.method === "POST" && ["rest", "retire"].includes(action)) {
    const body = await readJson(req);
    if (action === "retire" && (typeof body.reason !== "string" || !body.reason.trim() || body.reason.length > 500)) throw httpError(400, "请输入作废原因（不超过 500 字）");
    await withEmailJobLock(job.email, async () => {
      if (job.deleted || jobs.get(job.id) !== job) throw httpError(409, "账号已删除，请刷新列表");
      if (scheduledTaskStore.owner(job.email)) throw httpError(409, "账号有未完成的定时任务，请先取消计划再移动");
      if (dynamicProxies.binding(job.email) && (dynamicCycleRunning || dynamicProxies.activeOperations())) throw httpError(409, "动态代理任务正在执行，请结束后再移动");
      if ([...jobs.values()].some((item) => item.email.toLowerCase() === job.email.toLowerCase()
        && (isActive(item.status) || item.child || item.autoRepairOperation))) throw httpError(409, "账号正在执行任务，请结束后再移动");
      if (securityOperations.blockingRotation(job)) throw httpError(409, "账号安全操作结果尚未确认，请先处理后再移动");
      if (job.autoRepairPendingAccountIds?.length || sub2ApiUploadingEmails.has(job.email.toLowerCase()) || crsIntegration.status().items.some((item) => item.email.toLowerCase() === job.email.toLowerCase() && ["pending", "running", "unknown"].includes(item.status))) throw httpError(409, "账号有未完成的推送，请核对结果后再移动");
      if (action === "rest") accountLifecycle.rest(job.email);
      else accountLifecycle.retire(job.email, safeSecurityError(body.reason.trim(), [job.password, job.totpSecret, job.proxyUrl]));
    });
    sendJson(res, 200, { job: publicJob(job) });
    return;
  }
  if (req.method === "POST" && action === "account-term") {
    const body = await readJson(req);
    const term = normalizeAccountTerm(body.accountTerm);
    await withEmailJobLock(job.email, () => {
      if (job.deleted || jobs.get(job.id) !== job) throw httpError(409, "账号已删除，请刷新列表");
      accountLifecycle.setTerm(job.email, term);
    });
    sendJson(res, 200, { job: publicJob(job) });
    return;
  }
  if (req.method === "POST" && action === "proxy") {
    const body = await readJson(req);
    if (typeof body.proxyUrl !== "string") throw httpError(400, "请明确选择代理或直连");
    await withEmailJobLock(job.email, async () => {
      const reason = proxyChangeBlockedReason(job);
      if (reason) throw httpError(409, reason);
      const proxyUrl = normalizeProxyUrl(body.proxyUrl);
      await updateJobProxy(job, proxyUrl, { preserveAutoPause: true, operationProxyChoice: { mode: "explicit", proxyUrl } });
    });
    sendJson(res, 200, { job: publicJob(job) });
    return;
  }
  if (req.method === "POST" && action === "secrets") {
    const stored = serverDatabase.loadCredentials(job.email);
    sendJson(res, 200, { email: job.email, password: stored.password || job.password || null,
      totpSecret: stored.totpSecret || job.totpSecret || null });
    return;
  }
  if (req.method === "GET" && action === "logs") {
    sendJson(res, 200, { id: job.id, logs: job.logs });
    return;
  }
  if (req.method === "GET" && action === "download") {
    await downloadResult(res, job);
    return;
  }
  if (req.method === "POST" && ["sms-number", "luban-number"].includes(action)) {
    const body = await readJson(req);
    const providerId = action === "luban-number" ? "luban" : body.providerId;
    const config = action === "luban-number"
      ? { apiKey: body.apiKey, serviceId: body.serviceId }
      : body.config;
    await withEmailJobLock(job.email, () => acquireSmsNumber(job, providerId, config));
    sendJson(res, 200, { job: publicJob(job) });
    return;
  }
  if (req.method === "POST" && action === "cancel") {
    await withEmailJobLock(job.email, () => cancelJob(job));
    sendJson(res, 200, { job: publicJob(job) });
    return;
  }
  if (req.method === "POST" && action === "retry") {
    const body = await readJson(req);
    await withEmailJobLock(job.email, () => retryJob(job, body));
    sendJson(res, 200, { job: publicJob(job) });
    return;
  }
  if (req.method === "POST" && action === "regenerate") {
    const body = await readJson(req);
    await withEmailJobLock(job.email, () => regenerateJob(job, body));
    sendJson(res, 200, { job: publicJob(job) });
    return;
  }
  if (req.method === "POST" && action === "relogin") {
    const body = await readJson(req);
    await withEmailJobLock(job.email, () => forceReloginJob(job, body));
    sendJson(res, 200, { job: publicJob(job) });
    return;
  }
  if (req.method === "POST" && action === "security") {
    const body = await readJson(req);
    const operation = await withEmailJobLock(job.email, () => startSecurityOperation(job, body.action, body));
    sendJson(res, 200, { job: publicJob(job), operation: publicSecurityOperation(operation) });
    return;
  }
  if (req.method === "POST" && action === "security/recover") {
    const body = await readJson(req);
    await withEmailJobLock(job.email, async () => {
      if (!isTerminalStatus(job.status) || job.child) throw httpError(409, "请等待当前任务结束再恢复结果");
      const operation = body.operationId ? securityOperations.list(job).find((item) => item.operationId === body.operationId)
        : securityOperations.blockingRotation(job) || securityOperations.latest(job);
      if (!operation || operation.status !== "needs_attention") throw httpError(409, "没有需要恢复的安全操作结果");
      job.securityOperationId = operation.operationId;
      await finishSecurityOperation(job, { restored: true });
    });
    sendJson(res, 200, { job: publicJob(job), operation: publicSecurityOperation(securityOperations.read(job.securityOperationId)) });
    return;
  }
  if (req.method === "POST" && action === "setup-2fa") {
    const body = await readJson(req);
    await withEmailJobLock(job.email, () => startTotpSetup(job, body));
    sendJson(res, 200, { job: publicJob(job) });
    return;
  }
  if (req.method === "POST" && action === "add-password") {
    const body = await readJson(req);
    await withEmailJobLock(job.email, () => startPasswordAdd(job, body));
    sendJson(res, 200, { job: publicJob(job) });
    return;
  }
  if (req.method === "POST" && action === "input") {
    const body = await readJson(req);
    await withEmailJobLock(job.email, () => submitJobInput(job, body));
    sendJson(res, 200, { job: publicJob(job) });
    return;
  }

  sendJson(res, 405, { error: "Method not allowed" });
}

async function sendJobsPage(res, requestedPage, emailFilter = null, search = "", area = "all") {
  await syncCompletedOutputs();
  const allJobs = listUniqueJobs();
  const emailSet = emailFilter?.length ? new Set(emailFilter) : null;
  const accountArea = (job) => { const state = accountLifecycle.public(job.email); return state.retired ? "retired" : state.resting ? "resting" : "active"; };
  const restingCount = allJobs.filter((job) => accountArea(job) === "resting").length;
  const retiredCount = allJobs.filter((job) => accountArea(job) === "retired").length;
  const areaCounts = { active: allJobs.length - restingCount - retiredCount, resting: restingCount, retired: retiredCount, all: allJobs.length };
  const visibleJobs = allJobs.filter((job) => (area === "all" || accountArea(job) === area)
    && (!emailSet || emailSet.has(job.email.toLowerCase()))
    && (!search || job.email.toLowerCase().includes(search) || job.id.toLowerCase().includes(search)));
  const total = visibleJobs.length;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const page = Math.min(requestedPage, totalPages);
  const start = (page - 1) * PAGE_SIZE;
  sendJson(res, 200, {
    jobs: visibleJobs.slice(start, start + PAGE_SIZE).map(publicJob),
    area, areaCounts,
    selection: visibleJobs.map(publicSelectionJob),
    pagination: { page, pageSize: PAGE_SIZE, total, totalPages, totalAll: allJobs.length },
    filter: { active: Boolean(emailSet || search || area !== "all"), requested: emailFilter?.length || 0, matched: total },
    stats: {
      active: allJobs.filter(occupiesActiveSlot).length,
      queued: allJobs.filter((job) => job.status === "queued").length,
      completed: allJobs.filter((job) => job.status === "completed").length,
    },
  });
}

function normalizeEmailFilter(value) {
  if (!Array.isArray(value) || value.length === 0) throw httpError(400, "请至少输入一个筛选邮箱");
  if (value.length > MAX_BATCH_JOBS) throw httpError(400, `一次最多筛选 ${MAX_BATCH_JOBS} 个邮箱`);
  const unique = new Set();
  value.forEach((item, index) => {
    const email = String(item || "").trim().toLowerCase();
    if (!isEmail(email)) throw httpError(400, `第 ${index + 1} 个筛选邮箱格式错误`);
    unique.add(email);
  });
  return [...unique];
}

function scheduleDetail(value) {
  return { schedule: publicSchedule(value), items: value.items.map(publicScheduleItem) };
}

function publicSchedulePreview(value) {
  return { ...value.config, accounts: value.accounts.map(({ email, line, jobId, proxyEndpoint, valid, error }) => ({ email, line, jobId, proxyEndpoint, valid, ...(error ? { error } : {}) })),
    validCount: value.accounts.filter((item) => item.valid).length, invalidCount: value.accounts.filter((item) => !item.valid).length };
}

function previewScheduledTask(body) {
  const config = normalizeSchedule(body);
  const lines = String(body.text || "").split(/\r?\n/).map((text, index) => ({ text: text.trim(), line: index + 1 })).filter((item) => item.text);
  if (!lines.length || lines.length > MAX_BATCH_JOBS) throw httpError(400, `请输入 1 至 ${MAX_BATCH_JOBS} 行账号`);
  const assignments = new Map();
  if (body.proxyAssignments !== undefined) {
    if (!Array.isArray(body.proxyAssignments)) throw httpError(400, "代理分配格式无效");
    for (const assignment of body.proxyAssignments) {
      const key = String(assignment?.email || "").trim().toLowerCase();
      if (!isEmail(key) || assignments.has(key) || (typeof assignment.proxyUrl !== "string" && !operationProxySentinel(assignment.proxyUrl))) throw httpError(400, "代理分配包含重复账号或无效代理");
      assignments.set(key, assignment.proxyUrl);
    }
  }
  const seen = new Set();
  const accounts = lines.map(({ text, line }) => {
    let email = null, jobId = null, proxyEndpoint = null;
    try {
      const entry = parseBatchEntries(text, mailRequestConfig)[0];
      email = entry.email.trim().toLowerCase();
      if (seen.has(email)) throw httpError(400, "同一计划不能重复填写邮箱");
      seen.add(email);
      const existing = findJobByEmail(email);
      jobId = existing?.id || null;
      if (existing && (!isTerminalStatus(existing.status) || existing.child)) throw httpError(409, "账号正在执行其他任务，请结束后再创建计划");
      if (scheduledTaskStore.owner(email)) throw httpError(409, "账号已有未结束的定时任务");
      const saved = serverDatabase.loadCredentials(email);
      const credentials = entry.preserveExistingCredentials
        ? normalizeLoginCredentials({ ...saved, mailApiUrl: existing?.mailApiUrl, mailRequestBody: existing?.mailRequestBody })
        : normalizeLoginCredentials(entry);
      if (!credentials.password && !credentials.mailApiUrl) throw httpError(400, "缺少密码或可自动收码的邮箱 API，请补全账号资料");
      if (config.securityAction && config.securityAction !== "logout-all" && !credentials.totpSecret) throw httpError(400, "更换 2FA 需要当前原始密钥");
      if (existing && securityOperations.blockingRotation(existing)) throw httpError(409, "上次安全变更尚未核实，请先恢复结果");
      if (body.proxyAssignments !== undefined && !assignments.has(email)) throw httpError(400, "尚未为该账号选择代理");
      const proxyOptions = assignments.has(email) ? { proxyUrl: assignments.get(email) } : Object.hasOwn(body, "proxyUrl") ? { proxyUrl: body.proxyUrl } : {};
      const proxyChoice = selectOperationProxy(email, proxyOptions, { preview: true });
      const proxyUrl = proxyChoice.mode === "default" ? proxyChoice.proxyUrl : requireSocks5Proxy(proxyChoice.proxyUrl);
      const proxySelection = proxyChoice.mode === "default" ? { useDefaultProxy: true } : operationProxySentinel(proxyOptions.proxyUrl) === "stored" ? { useStoredProxy: true } : proxyUrl;
      proxyEndpoint = proxyChoice.mode === "default" ? "1024 美国动态代理" : publicProxyEndpoint(proxyUrl);
      if (proxyChoice.mode !== "default" && dynamicProxies.binding(email) && existing?.proxyUrl !== proxyUrl) throw httpError(409, "动态代理绑定与计划选择不同，请先同步账号代理");
      return { line, email, jobId, proxyEndpoint, proxyUrl, proxySelection, credentials, valid: true };
    } catch (error) { return { line, email, jobId, proxyEndpoint, valid: false, error: safeSecurityError(error.message) }; }
  });
  if ([...assignments.keys()].some((email) => !seen.has(email))) throw httpError(400, "代理分配包含未录入的邮箱");
  return { config, accounts };
}

async function createScheduledTask(body) {
  const fingerprint = crypto.createHash("sha256").update(JSON.stringify(body)).digest("hex");
  const existing = scheduledTaskStore.request(body.clientRequestId, fingerprint);
  if (existing) return existing;
  const preview = previewScheduledTask(body);
  if (preview.accounts.some((item) => !item.valid)) throw httpError(400, "部分账号资料或代理校验失败，请按预览结果修正后创建");
  if (Date.parse(preview.config.plannedAt) < Date.now()) throw httpError(400, "计划登录时间必须晚于当前北京时间");
  const targetIdentity = crsIntegration.getTargetIdentity();
  if (!targetIdentity) throw httpError(409, "请先配置 CPR 服务器");
  const catalog = await crsIntegration.groups();
  const groupIds = preview.config.crsSettings.groupIds || catalog.defaultGroupIds;
  if (!Array.isArray(groupIds) || !groupIds.length || groupIds.some((id) => !catalog.items.some((group) => group.id === id))) throw httpError(400, "请选择可用的 CPR 分组");
  preview.config.crsSettings.groupIds = [...new Set(groupIds)];
  if (JSON.stringify(targetIdentity) !== JSON.stringify(crsIntegration.getTargetIdentity())) throw httpError(409, "CPR 目标已改变，请重新确认计划");
  const accounts = [];
  // Lock all selected accounts in sorted order until the plan and its ownership
  // are durable. No credential write can accidentally launch an imported job.
  const lockAll = async (items, index, operation) => index === items.length ? operation()
    : withEmailJobLock(items[index].email, () => lockAll(items, index + 1, operation));
  return lockAll([...preview.accounts].sort((a, b) => a.email.localeCompare(b.email)), 0, async () => {
    const lockedPreview = previewScheduledTask(body);
    if (lockedPreview.accounts.some((item) => !item.valid)) throw httpError(409, "账号资料已变化，请重新预览计划");
    preview.accounts = lockedPreview.accounts;
    if (JSON.stringify(targetIdentity) !== JSON.stringify(crsIntegration.getTargetIdentity())) throw httpError(409, "CPR 目标已改变，请重新确认计划");
    for (const account of preview.accounts) {
      const current = findJobByEmail(account.email);
      if (scheduledTaskStore.owner(account.email) || current && (!isTerminalStatus(current.status) || current.child)) throw httpError(409, `${account.email} 的任务状态已变化，请重新预览`);
    }
    const preparedJobs = new Map();
    for (const account of preview.accounts) {
      const current = findJobByEmail(account.email);
      if (current?.metadataWritePromise) await current.metadataWritePromise;
      const credentials = account.credentials;
      const job = current ? { ...current, ...credentials, proxyUrl: account.proxyUrl,
        hasPasswordCredential: Boolean(credentials.password), hasTotpCredential: Boolean(credentials.totpSecret),
        mailSeenCandidateKeys: new Set(), mailCandidateCounts: new Map(), mailStatus: credentials.mailApiUrl ? "baseline" : "manual", mailApiError: null }
        : await startJob(account.email, credentials, account.proxyUrl, { deferStart: true, prepareOnly: true });
      getAccountTls(serverDatabase, job.email);
      preparedJobs.set(job.id, job);
      accounts.push({ email: job.email, jobId: job.id, line: account.line, proxyUrl: account.proxyUrl, proxySelection: account.proxySelection });
    }
    // Plan, account metadata, credentials and ownership commit together. Work
    // directories are disposable caches; a failed transaction never imports a
    // half-created account or reserves an account without a plan.
    const value = scheduledTaskStore.create({ clientRequestId: body.clientRequestId, fingerprint, config: preview.config, targetIdentity, accounts,
      persistAccounts(plan) {
        for (const item of plan.items) {
          const job = preparedJobs.get(item.jobId);
          job.scheduleItemId = item.id; job.scheduleId = plan.id;
          serverDatabase.saveCredentials(job.email, { password: job.password, totpSecret: job.totpSecret, proxyUrl: job.proxyUrl });
          if (!serverDatabase.saveJob(job.id, jobMetadata(job))) throw httpError(409, "账号已删除，计划未创建");
          serverDatabase.saveLogs(job.id, job.logs || "");
          accountHistory.initialize(job);
        }
      },
    });
    for (const item of value.items) {
      const job = preparedJobs.get(item.jobId);
      jobs.set(job.id, job);
      // The transaction above is authoritative even if refreshing a work copy fails.
      await saveJobMetadata(job).catch(() => {});
    }
    return value;
  });
}

function restoreScheduledJobMetadata(job, metadata) {
  job.operationProxyMode = ["default", "explicit", "legacy", "dynamic"].includes(metadata.operation_proxy_mode) ? metadata.operation_proxy_mode : "legacy";
  job.operationProxyId = metadata.operation_proxy_id || null;
  job.operationProxyExpiresAt = metadata.operation_proxy_expires_at || null;
  job.operationProxyExitIp = metadata.operation_proxy_exit_ip || null;
  job.operationProxyExitCountry = metadata.operation_proxy_exit_country || null;
  job.loginDeferred = metadata.login_deferred === true;
  job.scheduleItemId = metadata.schedule_item_id || null;
  job.scheduleId = metadata.schedule_id || null;
  job.scheduleLoginAttemptId = metadata.schedule_login_attempt_id || null;
  job.scheduleResultAttemptId = metadata.schedule_result_attempt_id || null;
  job.emailLoginAttempt = Number(metadata.email_login_attempt || 0);
  job.emailLoginReason = metadata.email_login_reason || null;
  job.emailLoginAutoPaused = Boolean(metadata.email_login_auto_paused);
}

async function restoreScheduledJobState() {
  for (const job of jobs.values()) {
    const metadata = serverDatabase.getJob(job.id) || {};
    restoreScheduledJobMetadata(job, metadata);
    const owner = scheduledTaskStore.owner(job.email);
    job.scheduleItemId = owner?.item.jobId === job.id ? owner.item.id : null;
    job.scheduleId = job.scheduleItemId ? owner.schedule.id : null;
    // A queued login from a different generation cannot be resumed as this plan.
    if (job.scheduleItemId && job.status === "queued" && !isSecurityMode(metadata.queued_mode)
      && (owner.item.status !== "login_queued" && owner.item.status !== "logging_in" || job.scheduleLoginAttemptId !== owner.item.loginAttemptId)) {
      job.status = job.resultSaved ? "completed" : "ready";
      job.queuedMode = null;
      await saveJobMetadata(job);
    }
  }
}

async function overrideScheduledJob(job, reason) {
  const owner = scheduledTaskStore.owner(job.email);
  if (owner) {
    const remote = await crsIntegration.cancelScheduled(owner.item.id);
    scheduledTaskStore.updateItem(owner.schedule.id, owner.item.id, { status: "superseded", error: reason,
      ...(remote ? { crs: { status: remote.status, message: remote.message, accountIds: remote.accountIds || [] } } : {}) });
  }
  job.scheduleItemId = null;
  job.scheduleId = null;
  job.scheduleLoginAttemptId = null;
  job.scheduleResultAttemptId = null;
}

function scheduledTaskHooks() {
  return {
    getJob: (id) => jobs.get(id), withLock: withEmailJobLock,
    paused: () => runtimeDraining || shuttingDown,
    safeError: (message) => safeSecurityError(message),
    canStart: (job) => isTerminalStatus(job.status) && !job.child,
    updated(item) {
      const job = jobs.get(item.jobId);
      if (job?.scheduleItemId === item.id && !scheduledTaskStore.owner(item.email) && !job.child && isTerminalStatus(job.status)) {
        job.scheduleItemId = null; job.scheduleId = null;
        void saveJobMetadata(job).catch(() => {});
      }
    },
    readSecurity: (id) => securityOperations.read(id),
    async startSecurity(schedule, item, operationId) {
      const job = jobs.get(item.jobId);
      await startSecurityOperation(job, schedule.securityAction, { proxyUrl: item.proxySelection ?? item.proxyUrl, scheduleItemId: item.id, operationId });
    },
    async startLogin(schedule, item, loginAttemptId) {
      const job = jobs.get(item.jobId);
      const current = scheduledTaskStore.owner(job.email);
      if (current?.item.id !== item.id) throw httpError(409, "计划已被其他操作替代");
      const credentials = await loadStoredLoginCredentials(job.email);
      job.password = credentials.password; job.totpSecret = credentials.totpSecret;
      job.hasPasswordCredential = Boolean(job.password); job.hasTotpCredential = Boolean(job.totpSecret);
      if (!operationProxySentinel(item.proxySelection)) job.proxyUrl = requireSocks5Proxy(item.proxyUrl);
      job.scheduleItemId = item.id; job.scheduleId = schedule.id;
      job.scheduleLoginAttemptId = loginAttemptId; job.scheduleResultAttemptId = null;
      await saveJobMetadata(job);
      await forceReloginJob(job, { proxyUrl: item.proxySelection ?? item.proxyUrl }, { scheduleItemId: item.id });
    },
    loginState(item, job) {
      const attempts = Math.max(item.attempts, job.emailLoginAttempt || 0);
      if (job.scheduleItemId !== item.id || job.scheduleLoginAttemptId !== item.loginAttemptId) return { status: "failed", attempts, error: "登录已被其他操作替代，旧授权不会用于计划推送" };
      if (job.status === "completed" && job.scheduleResultAttemptId === item.loginAttemptId) return { status: "completed", attempts };
      if (loginRetryPending(job)) return { status: "running", attempts };
      if (isTerminalStatus(job.status)) return { status: "failed", attempts, error: job.lastError || "计划登录被中断，未使用旧授权推送" };
      return { status: job.status === "queued" ? "queued" : "running", attempts };
    },
    lookupPublish: (item) => crsIntegration.lookupScheduled(item.id),
    publish: (schedule, item) => crsIntegration.enqueueScheduled(item.jobId, { scheduleItemId: item.id, settings: schedule.crsSettings, targetIdentity: schedule.targetIdentity }),
    cancelPublish: (item) => crsIntegration.cancelScheduled(item.id),
    async cancelJob(item) {
      const job = jobs.get(item.jobId);
      if (job?.scheduleItemId === item.id && isActive(job.status)) await cancelJob(job, { scheduled: true });
    },
  };
}

function readLoginFlow(body = {}) {
  if (Object.hasOwn(body, "loginFlow") && !["codex", "legacy"].includes(body.loginFlow)) {
    throw httpError(400, "loginFlow 必须为 codex 或 legacy");
  }
  return body.loginFlow || "codex";
}

async function selectLoginFlow(job, options = {}) {
  const flow = readLoginFlow(options);
  if ((job.loginFlow || "codex") !== flow) {
    await removePrivateFile(job.checkpointPath);
    job.loginCheckpointAvailable = false;
  }
  job.loginFlow = flow;
  return flow;
}

function readStartLogin(body) {
  if (Object.hasOwn(body, "startLogin") && typeof body.startLogin !== "boolean") {
    throw httpError(400, "startLogin 必须为 true 或 false");
  }
  return body.startLogin !== false;
}

function saveOnlyProxy(email, value) {
  // Merely recording an account cannot bind, extract, probe or rotate a dynamic
  // proxy. The user can choose its login proxy when starting a later operation.
  if (operationProxySentinel(value)) return selectOperationProxy(email, { proxyUrl: value }, { preview: true }).proxyUrl;
  if (isPlainObject(value)) throw httpError(400, "仅记录时可不选代理，或选择静态代理；动态代理请在上号时选择");
  const normalized = normalizeProxyUrl(value);
  if (dynamicProxies.binding(email)) {
    const current = findJobByEmail(email)?.proxyUrl || serverDatabase.loadCredentials(email).proxyUrl || null;
    if (current !== normalized) throw httpError(409, "账号已有动态代理绑定，请保留当前代理后再记录");
  }
  return normalized;
}

async function saveOnlyAccounts(entries, body, { partialCredentials = false } = {}) {
  const accountTerms = resolveAccountTerms(entries, body);
  const assignments = new Map();
  if (Object.hasOwn(body, "proxyAssignments")) {
    if (!Array.isArray(body.proxyAssignments) || body.proxyAssignments.length !== entries.length) throw httpError(400, "请为每个账号明确选择代理，或省略代理分配");
    const expected = new Set(entries.map((entry) => entry.email.toLowerCase()));
    for (const assignment of body.proxyAssignments) {
      const email = typeof assignment?.email === "string" ? assignment.email.trim().toLowerCase() : "";
      if (!expected.has(email) || assignments.has(email) || !Object.hasOwn(assignment, "proxyUrl")) throw httpError(400, "代理选择包含重复账号或未录入的账号");
      assignments.set(email, assignment.proxyUrl);
    }
  }
  const sorted = [...entries].sort((a, b) => a.email.toLowerCase().localeCompare(b.email.toLowerCase()));
  const lockAll = (index, operation) => index === sorted.length ? operation()
    : withEmailJobLock(sorted[index].email, () => lockAll(index + 1, operation));
  return lockAll(0, async () => {
    const assertAvailable = (existing, email) => {
      if (scheduledTaskStore.owner(email)) throw httpError(409, `${email} 已有定时任务，请先明确取消计划后再改为仅记录`);
      if ([...jobs.values()].some((job) => job.email.toLowerCase() === email.toLowerCase() && (isActive(job.status) || job.child || job.autoRepairOperation))) {
        throw httpError(409, `${email} 当前有任务正在执行，请等待结束后再改为仅记录`);
      }
      if (existing && crsIntegration.status().items.some((item) => item.jobId === existing.id && ["pending", "running", "unknown"].includes(item.status))) {
        throw httpError(409, `${email} 已有尚未确认的 CPR 推送，请先核对结果后再改为仅记录`);
      }
    };
    // Validate every selected account before writing any of them. Active work
    // and owned schedules are never canceled as a side effect of importing.
    for (const entry of entries) assertAvailable(findJobByEmail(entry.email), entry.email);
    const prepared = [];
    for (const entry of entries) {
      const existing = findJobByEmail(entry.email);
      if (existing?.metadataWritePromise) await existing.metadataWritePromise;
      const saved = serverDatabase.loadCredentials(entry.email);
      const previous = { password: saved.password, totpSecret: saved.totpSecret,
        mailApiUrl: existing?.mailApiUrl, mailRequestBody: existing?.mailRequestBody };
      const credentials = normalizeLoginCredentials(partialCredentials
        ? { ...previous, ...Object.fromEntries(["password", "totpSecret", "mailApiUrl", "mailRequestBody"].filter((key) => Object.hasOwn(entry, key)).map((key) => [key, entry[key]])) }
        : entry.preserveExistingCredentials ? previous : entry);
      const hasProxy = assignments.has(entry.email.toLowerCase()) || Object.hasOwn(body, "proxyUrl");
      const proxyUrl = hasProxy ? saveOnlyProxy(entry.email, assignments.has(entry.email.toLowerCase()) ? assignments.get(entry.email.toLowerCase()) : body.proxyUrl)
        : existing?.proxyUrl || saved.proxyUrl || null;
      const job = existing ? { ...existing, ...credentials, proxyUrl }
        : await startJob(entry.email, credentials, proxyUrl, { deferStart: true, prepareOnly: true, loginDeferred: true });
      Object.assign(job, { loginDeferred: true, status: "ready", prompt: "账号资料已记录，等待手动上号或定时任务", queuedMode: null, queuedAt: null,
        hasPasswordCredential: Boolean(credentials.password), hasTotpCredential: Boolean(credentials.totpSecret),
        mailSeenCandidateKeys: new Set(), mailCandidateCounts: new Map(), mailStatus: credentials.mailApiUrl ? "baseline" : "manual", mailApiError: null,
        autoRepairPendingAccountIds: [], autoRepairPendingBackend: null, autoRepairOperation: null });
      recordJobOperation(job, "account_saved");
      job.updatedAt = new Date().toISOString();
      prepared.push({ job, created: !existing, updated: Boolean(existing) });
    }
    for (const { job } of prepared) assertAvailable(findJobByEmail(job.email), job.email);
    serverDatabase.transaction(() => {
      for (const { job, created } of prepared) {
        if (created) accountLifecycle.initialize(job.email, accountTerms.term(job.email));
        else if (accountTerms.explicit(job.email)) accountLifecycle.setTerm(job.email, accountTerms.term(job.email));
        serverDatabase.saveCredentials(job.email, { password: job.password, totpSecret: job.totpSecret, proxyUrl: job.proxyUrl });
        if (!serverDatabase.saveJob(job.id, jobMetadata(job))) throw httpError(409, "账号已删除，资料未保存");
        serverDatabase.saveLogs(job.id, job.logs || "");
        accountHistory.initialize(job);
      }
    });
    for (const item of prepared) {
      // Routes waiting on this email lock may already hold the existing object.
      // Preserve its identity so a later explicit action sees the committed pause.
      const current = jobs.get(item.job.id);
      if (current) { Object.assign(current, item.job); item.job = current; }
      const { job } = item;
      jobs.set(job.id, job);
      // The encrypted transaction is authoritative; disk copies are caches.
      await saveJobMetadata(job).catch(() => {});
    }
    return prepared;
  });
}

async function startJob(email, credentials = {}, proxyUrl = null, context = {}) {
  const { loginMode, mailApiUrl, mailRequestBody, password, totpSecret } = normalizeLoginCredentials(credentials);
  if (!context.prepareOnly) await saveStoredLoginCredentials(email, { password, totpSecret, proxyUrl });
  const id = context.id || crypto.randomUUID();
  const outputDir = path.join(OUTPUT_ROOT, id);
  const outputPath = path.join(outputDir, "sub2api-import-oauth.json");
  const checkpointPath = path.join(outputDir, LOGIN_CHECKPOINT_FILENAME);
  const totpResultPath = path.join(outputDir, TOTP_SETUP_RESULT_FILENAME);
  const passwordAddResultPath = path.join(outputDir, PASSWORD_ADD_RESULT_FILENAME);
  await fs.mkdir(outputDir, { recursive: true });

  const createdAt = new Date().toISOString();
  const job = {
    id,
    email,
    status: context.deferStart ? "ready" : "queued",
    loginDeferred: Boolean(context.loginDeferred),
    loginFlow: readLoginFlow(context),
    prompt: context.deferStart ? "账号资料已保存，等待定时任务" : "已加入任务队列",
    createdAt,
    updatedAt: createdAt,
    lastOperationAt: createdAt,
    lastOperationType: "initial_authorization",
    completedAt: null,
    outputPath,
    checkpointPath,
    totpResultPath,
    passwordAddResultPath,
    logs: "",
    lastError: null,
    child: null,
    parserTail: "",
    resultSaved: false,
    loginMode,
    password,
    totpSecret,
    hasPasswordCredential: Boolean(password),
    hasTotpCredential: Boolean(totpSecret),
    proxyUrl,
    mailApiUrl,
    mailRequestBody,
    mailSeenCandidateKeys: new Set(),
    mailCandidateCounts: new Map(),
    mailStatus: mailApiUrl ? "baseline" : "manual",
    mailApiError: null,
    mailPollRunning: false,
    mailPollToken: null,
    mailOtpRequestedAt: null,
    currentPhone: null,
    phoneError: null,
    restartRequired: false,
    attempt: 1,
    runId: null,
    runMode: null,
    queuedMode: context.deferStart ? null : "full",
    queuedAt: context.deferStart ? null : new Date().toISOString(),
    queuedStartPrompt: "正在建立登录会话",
    directTlsFallbackAttempted: false,
    fallbackInProgress: false,
    totpSetupSecret: null,
    totpSetupUri: null,
    totpSetupError: null,
    totpSetupResumesAuthorization: false,
    passwordAddError: null,
    passwordAddedAt: null,
    pendingNewPassword: null,
    passwordAddResumesAuthorization: false,
    loginCheckpointAvailable: false,
    totpKnownEnabled: false,
    totpSetupAttempt: 0,
    totpResultLoading: false,
    proxyRiskRetryCount: 0,
    proxyConnectionFailureCount: 0,
    proxyRiskRestarting: false,
    proxySessionAttemptIds: new Set(),
    proxyAttemptParserTail: "",
    queueRunId: null,
    lastAuthAutomated: false,
    lastAuthAutomationReason: "尚未完成可验证的全自动登录",
    lastAuthAutomatedAt: null,
    lastAuthRequirements: null,
    authAutomationAttempt: null,
    autoRepairBlocked: false,
    autoRepairBlockedReason: null,
    autoRepairBlockedAt: null,
    autoRepairLastAttemptAt: null,
    autoRepairLastSuccessAt: null,
    autoRepairLastError: null,
    autoRepairPendingAccountIds: [],
    autoRepairPendingBackend: null,
    autoRepairOperation: null,
    ...newSmsState(),
  };
  if (!context.prepareOnly) applyOperationProxyChoice(job, context.operationProxyChoice || selectOperationProxy(job.email, {}));
  if (!context.deferStart) beginAuthorizationAutomationAttempt(job, context.crsBridgeOperationId ? "crs_bridge" : "initial");
  job.crsBridgeOperationId = context.crsBridgeOperationId || null;
  job.crsBridgeResultOperationId = null;
  if (context.prepareOnly) return job;
  jobs.set(id, job);
  accountLifecycle.initialize(job.email, context.accountTerm ?? null);
  accountHistory.initialize(job);
  await saveJobMetadata(job);
  if (!context.deferStart) scheduleQueuedJobs();
  return job;
}

function scheduleQueuedJobs() {
  if (shuttingDown || queueSchedulingPaused) return;
  let availableSlots = MAX_ACTIVE_JOBS - [...jobs.values()].filter(occupiesActiveSlot).length;
  if (availableSlots <= 0) return;
  const queuedJobs = [...jobs.values()]
    .filter((job) => job.status === "queued" && (!job.loginRetryNotBefore || job.loginRetryNotBefore <= Date.now()))
    .sort((a, b) => String(a.queuedAt || a.createdAt).localeCompare(String(b.queuedAt || b.createdAt)));
  for (const job of queuedJobs.slice(0, availableSlots)) {
    const mode = job.queuedMode || "full";
    const queueRunId = crypto.randomUUID();
    job.queueRunId = queueRunId;
    job.status = mode === "refresh"
      ? "refreshing"
      : isSecurityMode(mode)
        ? "security_starting"
      : mode === "totp_setup"
        ? "totp_starting"
        : mode === "password_add"
          ? "password_add_starting"
          : "starting";
    job.prompt = job.queuedStartPrompt || (mode === "refresh"
      ? "正在使用已有刷新令牌直接生成新授权"
      : mode === "totp_setup"
        ? "正在重新验证账号并准备设置 2FA"
        : mode === "password_add"
          ? "正在重新验证账号并准备添加密码"
          : "正在建立登录会话");
    job.queuedAt = null;
    touch(job);
    void saveJobMetadata(job).catch(() => {});
    void prepareAndLaunchJob(job, mode, queueRunId);
    availableSlots -= 1;
    if (availableSlots <= 0) break;
  }
}

async function prepareAndLaunchJob(job, mode, queueRunId) {
  try {
    if (job.operationProxyMode === "default") {
      await saveJobMetadata(job);
      const issued = await operationProxies.ensure({ email: job.email, operationId: job.operationProxyId });
      if (job.deleted || !isActive(job.status) || job.status === "queued" || job.queueRunId !== queueRunId) return;
      job.proxyUrl = requireSocks5Proxy(issued.proxyUrl);
      job.operationProxyExpiresAt = issued.expiresAt;
      job.operationProxyExitIp = issued.exitIp;
      job.operationProxyExitCountry = issued.exitCountry;
      assertOperationProxyLease(job);
      const latest = serverDatabase.loadCredentials(job.email);
      serverDatabase.transaction(() => {
        serverDatabase.saveCredentials(job.email, { ...latest, proxyUrl: job.proxyUrl });
        serverDatabase.put("operation-proxy-selection", job.email.toLowerCase(), { operationId: job.operationProxyId, proxyUrl: job.proxyUrl, expiresAt: job.operationProxyExpiresAt });
      });
      await saveJobMetadata(job);
      if (job.mailApiUrl) await loadMailboxBaseline(job);
      if (job.deleted || !isActive(job.status) || job.status === "queued" || job.queueRunId !== queueRunId) return;
      if (job.crsBridgeOperationId) await assertManagedReloginCurrent(job.email, job.crsBridgeOperationId);
      if (job.deleted || !isActive(job.status) || job.status === "queued" || job.queueRunId !== queueRunId) return;
      armOperationProxyLease(job);
      launchJob(job, { mode });
      return;
    }
    if (isSecurityMode(mode) || job.scheduleItemId) {
      // A security operation keeps the selected account proxy and never rotates it.
      job.proxyUrl = requireSocks5Proxy(job.proxyUrl);
      if (job.mailApiUrl) await loadMailboxBaseline(job);
      if (!isActive(job.status) || job.status === "queued" || job.queueRunId !== queueRunId) return;
      launchJob(job, { mode });
      return;
    }
    job.dynamicProxyPreparing = true;
    try { await dynamicProxies.refreshManualSelection(job.email); }
    finally { job.dynamicProxyPreparing = false; }
    if (job.crsBridgeOperationId) await assertManagedReloginCurrent(job.email, job.crsBridgeOperationId);
    if (dynamicProxies.binding(job.email)) {
      job.dynamicProxyPreparing = true;
      try {
        if (!job.crsBridgeOperationId) {
          const result = await dynamicProxies.ensure(job.email, "login");
          job.proxyUrl = result.proxyUrl;
          const binding = dynamicProxies.binding(job.email);
          if (binding.accountId) await dynamicCrs.register(binding);
        }
      } finally { job.dynamicProxyPreparing = false; }
    }
    if (["full", "totp_setup", "password_add"].includes(mode) && job.mailApiUrl) await loadMailboxBaseline(job);
    if (!isActive(job.status) || job.status === "queued" || job.queueRunId !== queueRunId) return;
    launchJob(job, { mode });
  } catch (error) {
    // An older asynchronous preparation must not fail a newer queued operation.
    if (job.deleted || !isActive(job.status) || job.status === "queued" || job.queueRunId !== queueRunId) return;
    if (isSecurityMode(mode)) {
      await finishSecurityOperation(job, { error: `准备账号安全操作失败：${error.message}` });
    } else if (mode === "totp_setup") {
      restoreTotpSetupFailure(job, `准备 2FA 设置失败：${error.message}`);
    } else if (mode === "password_add") {
      restorePasswordAddFailure(job, `准备添加密码失败：${error.message}`);
    } else {
      failJob(job, `准备登录任务失败：${error.message}`);
    }
    scheduleQueuedJobs();
  }
}

async function assertManagedReloginCurrent(email, operationId) {
  // 退出动态模式后仍核对恢复代次，旧桥接请求不能覆盖人工同步的登录代理
  const binding = dynamicProxies.managedBinding(email);
  if (!binding) return;
  const status = await dynamicCrs.status(binding);
  if (status?.guardian.state.status !== "relogin" || status.guardian.state.operationId !== operationId) throw httpError(409, "CRS 重新上号任务已变化");
}

function enqueueJob(job, mode, startPrompt) {
  job.queueRunId = null;
  job.status = "queued";
  job.prompt = "已加入任务队列";
  job.queuedMode = mode;
  job.queuedAt = new Date().toISOString();
  job.queuedStartPrompt = startPrompt;
  touch(job);
  void saveJobMetadata(job).catch(() => {});
  scheduleQueuedJobs();
}

function launchJob(job, options = {}) {
  const mode = options.mode || "full";
  let accountTls;
  try {
    assertOperationProxyLease(job);
    accountTls = getAccountTls(serverDatabase, job.email);
    if (job.operationProxyMode === "default" || isSecurityMode(mode) || job.scheduleItemId) requireSocks5Proxy(job.proxyUrl);
  } catch (error) {
    if (isSecurityMode(mode)) {
      void finishSecurityOperation(job, { error: error.message }).then(scheduleQueuedJobs);
      return;
    }
    failJob(job, error.message);
    return;
  }
  if (mode === "full" && !job.authAutomationAttempt) {
    beginAuthorizationAutomationAttempt(job, "login", { preserveRetryBudget: true });
  }
  const runId = crypto.randomUUID();
  job.runId = runId;
  job.runMode = mode;
  job.loginResultRunId = null;
  job.emailLoginAttempt = 0;
  job.emailLoginReason = null;
  job.emailLoginMarkerTail = "";
  job.emailLoginMarkerSeen = new Set();
  const securityOperation = isSecurityMode(mode) ? securityOperations.read(job.securityOperationId) : null;
  if (isSecurityMode(mode)) {
    if (!securityOperation || securityActionMode(securityOperation.action) !== mode) {
      void finishSecurityOperation(job, { error: "安全操作记录丢失，已停止执行" }).then(scheduleQueuedJobs);
      return;
    }
    securityOperations.update(securityOperation.operationId, { status: "running" });
  }
  if (["full", "refresh"].includes(mode)) {
    accountHistory.start(job, runId, mode, job.authAutomationAttempt?.source || (mode === "refresh" ? "token_refresh" : "login"));
  }
  job.mailOtpRequestedAt = null;
  const args = securityOperation
    ? [PROTOCOL_SCRIPT, "--email", job.email, "--security-action", securityOperation.action,
      "--security-result", securityOperationResultPath(job, securityOperation),
      "--security-operation-id", securityOperation.operationId, "--verbose"]
    : mode === "refresh"
    ? [
        PROTOCOL_SCRIPT,
        "--refresh-sub2api",
        job.outputPath,
        "--email",
        job.email,
        "--sub2api-out",
        job.outputPath,
        "--verbose",
      ]
    : mode === "totp_setup"
      ? [
          PROTOCOL_SCRIPT,
          "--email",
          job.email,
          "--setup-totp",
          "--totp-result",
          job.totpResultPath,
          ...(job.totpSetupResumesAuthorization ? ["--resume-checkpoint", job.checkpointPath] : []),
          "--verbose",
        ]
    : mode === "password_add"
      ? [
          PROTOCOL_SCRIPT,
          "--email",
          job.email,
          "--add-password",
          "--password-add-result",
          job.passwordAddResultPath,
          ...(job.passwordAddResumesAuthorization ? ["--resume-checkpoint", job.checkpointPath] : []),
          "--verbose",
        ]
    : [
        PROTOCOL_SCRIPT,
        "--email",
        job.email,
        "--output-mode",
        "sub2api",
        "--sub2api-out",
        job.outputPath,
        "--checkpoint",
        job.checkpointPath,
        "--resume-checkpoint",
        job.checkpointPath,
        "--verbose",
      ];
  if (mode === "full" && job.loginFlow === "legacy") args.push("--legacy-web-login");
  const child = spawn(process.execPath, args, {
    cwd: WORKSPACE_ROOT,
    env: {
      ...process.env,
      ONBOARDING_DATABASE_PATH: serverDatabase.databasePath,
      ONBOARDING_OUTPUT_ROOT: OUTPUT_ROOT,
      TOSUB2_LOGIN_FLOW: job.loginFlow === "legacy" ? "legacy" : "codex",
      CHATGPT_LOGIN_PASSWORD: job.password || "",
      CHATGPT_TOTP_SECRET: job.totpSecret || "",
      CHATGPT_NEW_PASSWORD: mode === "password_add" ? job.pendingNewPassword || "" : "",
      CHATGPT_PROXY_URL: job.proxyUrl || "",
      TOSUB2_ACCOUNT_TLS: JSON.stringify(accountTls),
      // CPR 联动已指定出口，会话参数不能在登录时再次随机化
      TOSUB2_PIN_PROXY_SESSION: mode === "full" || job.operationProxyMode === "default" || securityOperation || job.scheduleItemId || job.crsBridgeOperationId || dynamicProxies.binding(job.email) ? "1" : process.env.TOSUB2_PIN_PROXY_SESSION || "0",
      TOSUB2_REQUIRE_SOCKS5: job.operationProxyMode === "default" || securityOperation || job.scheduleItemId ? "1" : process.env.TOSUB2_REQUIRE_SOCKS5 || "0",
      CHATGPT_PROXY_MAX_ATTEMPTS: mode === "full" || job.operationProxyMode === "default" || securityOperation || job.scheduleItemId ? "0" : String(Math.max(0, MAX_PROXY_RISK_RETRIES - (job.proxyRiskRetryCount || 0))),
      TOSUB2_EMAIL_CHALLENGE_RETRY: mode === "full" ? "0" : "1",
      TOSUB2_EMAIL_OTP_AVAILABLE: mailApiUrlForJob(job) ? "1" : "0",
      TOSUB2_EMAIL_OTP_TIMEOUT_MS: process.env.TOSUB2_EMAIL_OTP_TIMEOUT_MS || "90000",
      TOSUB2_TLS_PROFILE: accountTls.profile,
    },
    stdio: ["pipe", "pipe", "pipe"],
  });
  job.child = child;

  child.stdout.on("data", (chunk) => {
    if (job.runId === runId) consumeOutput(job, chunk.toString("utf8"));
  });
  child.stderr.on("data", (chunk) => {
    if (job.runId === runId) consumeOutput(job, chunk.toString("utf8"));
  });
  child.on("error", (error) => {
    void withEmailJobLock(job.email, async () => {
      if (job.runId !== runId) return;
      if (isSecurityMode(mode)) await finishSecurityOperation(job, { error: "无法启动账号安全操作进程" });
      else if (mode === "totp_setup") restoreTotpSetupFailure(job, `无法启动 2FA 设置进程：${error.message}`);
      else if (mode === "password_add") restorePasswordAddFailure(job, `无法启动添加密码进程：${error.message}`);
      else failJob(job, `无法启动登录进程：${error.message}`);
    });
  });
  child.on("close", (code, signal) => {
    void withEmailJobLock(job.email, () => handleChildClose(job, { code, signal, mode, runId }))
      .catch((error) => {
        handleChildCloseFailure(job, mode, runId, error);
      });
  });
}

async function handleChildClose(job, result) {
  if (job.runId !== result.runId) return;
  await handleChildCloseAttempt(job, result);
}

async function handleChildCloseAttempt(job, { code, signal, mode, runId }) {
  if (job.runId !== runId) return;
  // A final stderr marker need not end with a newline. Flush only after close,
  // so a split HTTP status or URL can never become a partial public diagnostic.
  if (mode === "full" && !isTerminalStatus(job.status) && job.parserTail?.includes("[proxy-risk-retry]")) consumeOutput(job, "\n");
  stopMailPolling(job);
  job.child = null;
  if (isSecurityMode(mode)) {
    await finishSecurityOperation(job, { code, signal });
    scheduleQueuedJobs();
    return;
  }
  if (mode === "totp_setup") {
    await finishTotpSetup(job, code, signal);
    scheduleQueuedJobs();
    return;
  }
  if (mode === "password_add") {
    await finishPasswordAdd(job, code, signal);
    scheduleQueuedJobs();
    return;
  }
  if (job.status === "canceled") {
    await finishSub2ApiAutoRepairFailure(job);
    scheduleQueuedJobs();
    return;
  }
  if (job.status !== "reauth_required" && code === 0 && job.resultSaved && (await fileExists(job.outputPath))
    && (mode !== "full" || job.loginResultRunId === runId)
    && (!job.scheduleItemId || job.scheduleResultAttemptId === job.scheduleLoginAttemptId)) {
    if (mode === "full") completeAuthorizationAutomationAttempt(job);
    job.loginCheckpointAvailable = false;
    job.status = "completed";
    job.prompt = "授权完成，可以下载导入文件";
    job.completedAt = new Date().toISOString();
    accountLifecycle.authorized(job.email, job.completedAt, mode);
    touch(job);
    await saveJobMetadata(job);
    if (job.scheduleItemId) { /* The scheduler owns publication and its durable outbox identity. */ }
    else if (job.crsBridgeOperationId) await crsLoginBridge?.complete(job);
    else if (!job.loginDeferred) await crsIntegration?.authorizationCompleted(job);
    await finishSub2ApiAutoRepairSuccess(job);
    scheduleQueuedJobs();
    return;
  }
  if (job.status !== "failed") {
    if (await fileExists(job.checkpointPath)) {
      markResumeAvailable(job, signal ? `登录进程被 ${signal} 终止` : "登录流程中断");
    } else {
      failJob(job, signal ? `登录进程被 ${signal} 终止` : `登录进程退出，代码 ${code ?? "未知"}`);
    }
  }
  if (mode === "full") {
    pauseFailedAuthorization(job);
    await saveJobMetadata(job);
  }
  await finishSub2ApiAutoRepairFailure(job);
  scheduleQueuedJobs();
}

function handleChildCloseFailure(job, mode, runId, error) {
  if (job.runId !== runId && !((["totp_setup", "password_add"].includes(mode) || isSecurityMode(mode)) && job.runId === null)) return;
  job.loginAutoRetryBlocked = true;
  const message = `收尾处理失败：${error.message}`;
  if (isSecurityMode(mode)) {
    const operation = securityOperations.read(job.securityOperationId);
    if (operation) {
      securityOperations.update(operation.operationId, { status: "needs_attention", error: safeSecurityError(message, [job.password, job.totpSecret]) });
      restoreSecurityJobStatus(job, operation, "安全操作结果需要恢复，已保留私有结果");
    }
  } else if (mode === "totp_setup") {
    job.status = "completed";
    job.prompt = "原授权文件仍然可用，2FA 密钥尚未完成安全保存";
    job.totpSetupError = `${message}；已保留 2FA 结果文件，请重试保存`;
    job.runMode = null;
    job.runId = null;
  } else if (mode === "password_add") {
    restorePasswordAddFailure(job, message);
  } else {
    failJob(job, message);
  }
  touch(job);
  void saveJobMetadata(job).catch(() => {});
  scheduleQueuedJobs();
}

async function retryJob(job, options = {}) {
  readLoginFlow(options);
  if (!["failed", "canceled", "reauth_required", "resume_available"].includes(job.status) && !(job.loginDeferred && job.status === "ready")) {
    throw httpError(409, "当前任务不需要重新授权");
  }
  await overrideScheduledJob(job, "人工重新授权替代了原定时任务");
  job.emailLoginAutoPaused = false;
  const retryingSecurityCheck = Boolean(job.securityCheckRequired);
  await configureOperationProxy(job, options);
  await selectLoginFlow(job, options);
  job.loginDeferred = false;
  const resumingCheckpoint = (job.status === "resume_available" || retryingSecurityCheck) && await fileExists(job.checkpointPath);
  stopMailPolling(job);
  if (resumingCheckpoint) stopSmsPolling(job);
  else releaseSmsNumber(job, "idle");
  job.runId = crypto.randomUUID();
  job.child?.kill("SIGTERM");
  job.child = null;
  const startPrompt = retryingSecurityCheck && resumingCheckpoint
    ? "正在使用已有登录状态重试手机号绑定"
    : "正在重新建立登录会话";
  job.lastError = null;
  job.parserTail = "";
  job.completedAt = null;
  job.currentPhone = resumingCheckpoint ? (job.currentPhone || job.smsNumber) : null;
  job.phoneError = null;
  job.securityCheckRequired = false;
  job.restartRequired = false;
  job.attempt += 1;
  job.proxyRiskRetryCount = 0;
  job.proxyConnectionFailureCount = 0;
  job.directTlsFallbackAttempted = false;
  job.proxyRiskRestarting = false;
  job.proxySessionAttemptIds.clear();
  job.proxyAttemptParserTail = "";
  job.mailCandidateCounts.clear();
  clearAutoRepairBlock(job);
  job.autoRepairOperation = null;
  job.autoRepairPendingAccountIds = [];
  job.autoRepairPendingBackend = null;
  beginAuthorizationAutomationAttempt(job, "manual_retry");
  recordJobOperation(job, resumingCheckpoint ? "resume" : "reauthorize");
  appendJobLog(
    job,
    retryingSecurityCheck
      ? `\n[retry] 开始第 ${job.attempt} 次手动重试；优先复用已有登录检查点。\n`
      : `\n[retry] 开始第 ${job.attempt} 次授权登录。\n`,
  );
  enqueueJob(job, "full", startPrompt);
}

async function regenerateJob(job, options = {}) {
  readLoginFlow(options);
  if (job.status !== "completed" || !job.resultSaved) {
    throw httpError(409, "只能为已经完成的任务重新生成授权");
  }
  await overrideScheduledJob(job, "人工重新生成授权替代了原定时任务");
  job.emailLoginAutoPaused = false;
  await configureOperationProxy(job, options);
  await selectLoginFlow(job, options);
  job.loginDeferred = false;
  job.lastError = null;
  job.parserTail = "";
  job.currentPhone = null;
  job.phoneError = null;
  releaseSmsNumber(job, "idle");
  job.restartRequired = false;
  job.completedAt = null;
  job.attempt += 1;
  job.proxyRiskRetryCount = 0;
  job.proxyConnectionFailureCount = 0;
  job.directTlsFallbackAttempted = false;
  job.proxyRiskRestarting = false;
  job.proxySessionAttemptIds.clear();
  job.proxyAttemptParserTail = "";
  recordJobOperation(job, "reauthorize");
  appendJobLog(job, `\n[refresh] 第 ${job.attempt} 次生成：优先使用已有刷新令牌。\n`);
  enqueueJob(job, "refresh", "正在使用已有刷新令牌直接生成新授权");
}

async function forceReloginJob(job, options = {}, context = {}) {
  const loginFlow = context.autoRepair || context.crsBridgeOperationId || context.scheduleItemId ? "codex" : readLoginFlow(options);
  if (job.autoRepairBlocked && (context.autoRepair || context.crsBridgeOperationId)) throw httpError(409, job.autoRepairBlockedReason || "上次授权失败，自动登录已暂停，请手动重试");
  if (job.loginDeferred && (context.autoRepair || context.crsBridgeOperationId)) throw httpError(409, "账号仅记录，自动登录已暂停；请手动上号或安排定时任务");
  const scheduleOwner = scheduledTaskStore.owner(job.email);
  if (scheduleOwner && (context.autoRepair || context.crsBridgeOperationId)) throw httpError(409, "账号有定时任务，自动重新登录已暂停");
  if (job.emailLoginAutoPaused && (context.autoRepair || context.crsBridgeOperationId)) throw httpError(409, "邮箱验证未完成，自动重新登录已暂停");
  if (context.scheduleItemId && scheduleOwner?.item.id !== context.scheduleItemId) throw httpError(409, "定时登录任务已变化，已停止启动");
  if ((job.securityAutoLoginPaused || (accountLifecycle.public(job.email).resting || accountLifecycle.public(job.email).retired) || securityOperations.blockingRotation(job)) && (context.autoRepair || context.crsBridgeOperationId)) {
    throw httpError(409, "账号安全操作已暂停自动登录，请先手动恢复并核实结果");
  }
  if (!canForceRelogin(job)) {
    throw httpError(409, "当前任务正在进行中，不能重新登录");
  }
  if (!scheduleOwner && job.scheduleItemId && !context.scheduleItemId) await overrideScheduledJob(job, "原定时任务已结束");
  if (!context.autoRepair && !context.crsBridgeOperationId && !context.scheduleItemId) await overrideScheduledJob(job, "人工重新登录替代了原定时任务");
  await reloadMissingJobCredentials(job);
  if (!canForceRelogin(job)) {
    throw httpError(409, "当前任务正在进行中，不能重新登录");
  }
  await configureOperationProxy(job, options);
  await selectLoginFlow(job, { loginFlow });
  if (!context.autoRepair && !context.crsBridgeOperationId) {
    job.loginDeferred = false;
    job.securityAutoLoginPaused = false;
    job.emailLoginAutoPaused = false;
    job.securityLoginResumedAt = new Date().toISOString();
  }
  stopMailPolling(job);
  releaseSmsNumber(job, "idle");
  job.queueRunId = null;
  job.runId = crypto.randomUUID();
  job.child?.kill("SIGTERM");
  job.child = null;
  await Promise.all([
    removePrivateFile(job.checkpointPath),
    removePrivateFile(job.totpResultPath),
  ]);
  job.loginCheckpointAvailable = false;
  job.lastError = null;
  job.parserTail = "";
  job.completedAt = null;
  job.currentPhone = null;
  job.phoneError = null;
  job.securityCheckRequired = false;
  job.restartRequired = false;
  job.totpSetupSecret = null;
  job.totpSetupUri = null;
  job.totpSetupError = null;
  job.proxyRiskRetryCount = 0;
  job.proxyConnectionFailureCount = 0;
  job.directTlsFallbackAttempted = false;
  job.proxyRiskRestarting = false;
  job.proxySessionAttemptIds.clear();
  job.proxyAttemptParserTail = "";
  job.mailCandidateCounts.clear();
  job.attempt += 1;
  if (!context.autoRepair) {
    clearAutoRepairBlock(job);
    job.autoRepairPendingAccountIds = [];
    job.autoRepairPendingBackend = null;
  }
  job.autoRepairOperation = context.autoRepair || null;
  if (context.autoRepair) {
    job.autoRepairLastAttemptAt = new Date().toISOString();
    job.autoRepairLastError = null;
    job.autoRepairPendingAccountIds = [...new Set(context.autoRepair.accountIds || [])];
    job.autoRepairPendingBackend = context.autoRepair.backend || null;
  }
  beginAuthorizationAutomationAttempt(job, context.scheduleItemId ? "scheduled_login" : context.crsBridgeOperationId ? "crs_bridge" : context.autoRepair ? "sub2api_monitor" : "manual_relogin");
  job.crsBridgeOperationId = context.crsBridgeOperationId || null;
  job.crsBridgeResultOperationId = null;
  recordJobOperation(job, context.crsBridgeOperationId ? "crs_bridge_login" : context.autoRepair ? "automatic_relogin" : "relogin");
  appendJobLog(job, `\n[relogin] 第 ${job.attempt} 次授权：跳过刷新令牌并强制重新登录。\n`);
  if (job.hasTotpCredential && !job.totpSecret) {
    appendJobLog(job, "[mfa] 本地未能读取已记录的 2FA 密钥，遇到 2FA 时需要手动输入验证码。\n");
  }
  enqueueJob(job, "full", "正在强制重新登录并完成授权");
}

async function reloadMissingJobCredentials(job) {
  if (
    (job.password || !job.hasPasswordCredential)
    && (job.totpSecret || !job.hasTotpCredential)
    && job.proxyUrl
  ) return;
  const stored = await loadStoredLoginCredentials(job.email);
  job.password ||= stored.password;
  job.totpSecret ||= stored.totpSecret;
  job.proxyUrl ||= stored.proxyUrl;
  if (job.password) job.hasPasswordCredential = true;
  if (job.totpSecret) job.hasTotpCredential = true;
  if (stored.password || stored.totpSecret || stored.proxyUrl) {
    await saveStoredLoginCredentials(job.email, job);
  }
}

function securityOperationResultPath(job, operation) {
  return path.join(path.dirname(job.outputPath), `security-${operation.operationId}.json`);
}

function canRunAccountSecurity(job, action) {
  if (!isTerminalStatus(job.status) || job.child || job.deleted) return false;
  if ([...jobs.values()].some((other) => other.id !== job.id && other.email.toLowerCase() === job.email.toLowerCase()
    && (isActive(other.status) || other.child))) return false;
  if (!(job.password || job.hasPasswordCredential || job.mailApiUrl)) return false;
  if (action !== "logout-all") {
    if (!(job.totpSecret || job.hasTotpCredential)) return false;
    if (securityOperations.blockingRotation(job)) return false;
  }
  return true;
}

async function startSecurityOperation(job, action, options = {}) {
  const mode = securityActionMode(action);
  if (!isTerminalStatus(job.status) || job.child) throw httpError(409, "账号当前有任务正在执行");
  if ([...jobs.values()].some((other) => other.id !== job.id && other.email.toLowerCase() === job.email.toLowerCase()
    && (isActive(other.status) || other.child))) throw httpError(409, "同一邮箱的另一条任务正在执行");
  if (action !== "logout-all" && securityOperations.blockingRotation(job)) {
    throw httpError(409, "上次更换 2FA 尚未核实，请先恢复并确认该操作，不能重复更换");
  }
  // The protocol worker may have saved a verified key before a later step failed.
  // Refresh all persisted credentials rather than overwriting them from stale memory.
  const latestCredentials = await loadStoredLoginCredentials(job.email);
  job.password = latestCredentials.password;
  job.totpSecret = latestCredentials.totpSecret;
  job.proxyUrl = latestCredentials.proxyUrl;
  job.hasPasswordCredential = Boolean(job.password);
  job.hasTotpCredential = Boolean(job.totpSecret);
  if (!(job.password || job.mailApiUrl)) throw httpError(409, "请先保存账号密码或邮箱收码配置");
  if (action !== "logout-all" && !job.totpSecret) throw httpError(409, "更换 2FA 需要账号当前的原始 2FA 密钥");
  const proxyChoice = selectOperationProxy(job.email, options);
  const proxyUrl = proxyChoice.mode === "default" ? proxyChoice.proxyUrl : requireSocks5Proxy(proxyChoice.proxyUrl);
  // Validate the existing persistent TLS identity before registering an operation.
  getAccountTls(serverDatabase, job.email);
  if (options.scheduleItemId) {
    if (scheduledTaskStore.owner(job.email)?.item.id !== options.scheduleItemId) throw httpError(409, "定时安全准备已被其他操作替代");
  } else await overrideScheduledJob(job, "人工安全操作替代了原定时任务");
  applyOperationProxyChoice(job, proxyChoice);
  await saveStoredLoginCredentials(job.email, job);
  const operation = securityOperations.begin(job, action, options.operationId);
  if (job.operationProxyMode === "default") job.operationProxyId = operation.operationId;
  stopMailPolling(job);
  releaseSmsNumber(job, "idle");
  job.securityOperationId = operation.operationId;
  job.securityFailureMessage = null;
  job.securityFailureMarkerSeen = null;
  job.securityOutputTail = "";
  job.securityCancelRequested = false;
  job.historyRunId = null;
  job.parserTail = "";
  job.lastError = null;
  job.proxyRiskRetryCount = 0;
  job.proxyConnectionFailureCount = 0;
  job.proxyRiskRestarting = false;
  recordJobOperation(job, action === "rotate-totp" ? "rotate_2fa" : action === "logout-all" ? "logout_all" : "rotate_2fa_logout_all");
  appendJobLog(job, action === "rotate-totp-logout-all" ? "[security] 已加入先更换 2FA 再登出所有设备队列，使用账号 SOCKS5 代理。\n" : action === "rotate-totp"
    ? "[security] 已加入更换 2FA 队列，使用账号 SOCKS5 代理。\n"
    : "[security] 已加入登出所有设备队列，使用账号 SOCKS5 代理。\n");
  enqueueJob(job, mode, action === "rotate-totp-logout-all" ? "正在先更换 2FA，再登出所有设备" : action === "rotate-totp" ? "正在验证账号并更换 2FA" : "正在验证账号并登出所有设备");
  await saveJobMetadata(job);
  return securityOperations.read(operation.operationId);
}

function restoreSecurityJobStatus(job, operation, prompt) {
  job.status = isTerminalStatus(operation.priorStatus) ? operation.priorStatus : (job.resultSaved ? "completed" : "failed");
  job.prompt = prompt;
  job.lastError = operation.status === "completed" ? operation.priorError : operation.error;
  job.runMode = null;
  job.runId = null;
  job.queueRunId = null;
  job.queuedMode = null;
  job.queuedAt = null;
  job.child = null;
  job.securityCancelRequested = false;
  job.securityOutputTail = "";
  touch(job);
}

async function readSecurityOperationResult(job, operation) {
  const filePath = securityOperationResultPath(job, operation);
  const candidates = [operation.result, serverDatabase.get("security-operation-result", operation.operationId)].filter(Boolean)
    .map((result) => validateSecurityResult(result, operation));
  try {
    const stat = await fs.lstat(filePath);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 1024 * 1024) throw new Error("安全操作结果文件格式不正确，已保留等待核实");
    await fs.chmod(filePath, 0o600);
    candidates.push(validateSecurityResult(JSON.parse(await fs.readFile(filePath, "utf8")), operation));
  } catch (error) {
    if (error.code === "ENOENT") { /* The encrypted journal may outlive the private work file. */ }
    else {
    if (error instanceof SyntaxError) throw new Error("安全操作结果无法读取，已保留等待核实");
    throw error;
    }
  }
  const stages = ["prepared", "disable_requested", "old_disabled", "enrollment_requested", "enrolled", "activation_requested", "activated", "verified", "work_reset_requested", "work_reset_confirmed", "logout_requested"];
  const result = candidates.sort((a, b) => Date.parse(a.updatedAt) - Date.parse(b.updatedAt)
    || stages.indexOf(a.stage) - stages.indexOf(b.stage)
    || Number(a.status === "completed") - Number(b.status === "completed")).at(-1) || null;
  if (result) securityOperations.update(operation.operationId, { result, stage: result.stage });
  return result;
}

async function finishSecurityOperation(job, { code, signal, error, restored = false, canceled = false } = {}) {
  let operation = securityOperations.read(job.securityOperationId);
  if (!operation) throw new Error("安全操作记录丢失，无法确认结果");
  stopMailPolling(job);
  let result = null;
  let resultError = null;
  try { result = await readSecurityOperationResult(job, operation); }
  catch (failure) { resultError = safeSecurityError(failure.message); }
  const now = new Date().toISOString();
  let status;
  const failureMarker = normalizeSecurityFailureMarker(operation.failureMarker);
  let message = error || resultError || result?.error || job.securityFailureMessage || failureMarker?.message || null;
  const rotationVerified = !resultError && operation.action !== "logout-all" && result?.secret
    && result.activation_succeeded && result.mfa_verified;
  const logoutAccepted = !resultError && operation.action !== "rotate-totp" && result?.logout_accepted;
  if (rotationVerified) {
    // A combined operation must retain the verified key even when logout fails.
    // The acknowledgement and credential update remain an atomic transaction.
    const currentCredentials = serverDatabase.loadCredentials(job.email);
    const newSecret = normalizeTotpSecret(result.secret);
    if (currentCredentials.totpSecret !== newSecret && operation.previousTotpFingerprint
      && crypto.createHash("sha256").update(String(currentCredentials.totpSecret || "")).digest("hex") !== operation.previousTotpFingerprint) {
      throw new Error("账号的 2FA 资料已在其他操作中更新，已保留结果，不能用旧操作覆盖当前密钥");
    }
    const nextCredentials = { ...currentCredentials, totpSecret: newSecret };
    serverDatabase.transaction(() => {
      serverDatabase.saveCredentials(job.email, nextCredentials);
      operation = securityOperations.update(operation.operationId, {
        stage: result.stage, result,
        credentialsUpdatedAt: operation.credentialsUpdatedAt || now,
      });
    });
    for (const accountJob of jobs.values()) {
      if (accountJob.email.toLowerCase() !== job.email.toLowerCase()) continue;
      accountJob.totpSecret = nextCredentials.totpSecret;
      accountJob.hasTotpCredential = true;
      accountJob.totpKnownEnabled = true;
    }
  }
  if (logoutAccepted || (operation.action !== "rotate-totp" && result?.stage === "logout_requested")) {
    // An accepted or uncertain global logout must not be undone by auto repair.
    job.securityAutoLoginPaused = true;
    accountLifecycle.logout(job.email, { ...operation, result });
  }
  const workResetSatisfied = result?.work_reset_succeeded || result?.work_reset_unavailable;
  const completed = !resultError && (operation.action === "rotate-totp" ? rotationVerified
    : operation.action === "logout-all" ? workResetSatisfied && logoutAccepted
      : rotationVerified && workResetSatisfied && logoutAccepted);
  if (completed) {
    operation = securityOperations.update(operation.operationId, {
      status: "completed", stage: result.stage, result, error: null, completedAt: now,
    });
    status = "completed";
    message = operation.action === "rotate-totp" ? "2FA 已更换并验证，新密钥已记录到账号详情"
      : operation.action === "logout-all" ? result?.work_reset_unavailable
        ? "ChatGPT Work 接口不可用（HTTP 404），已跳过重置并提交登出所有设备，自动重新登录已暂停；手动重新登录可恢复"
        : "ChatGPT Work 已重置，已提交登出所有设备，自动重新登录已暂停；手动重新登录可恢复"
      : result?.work_reset_unavailable
        ? "2FA 已更换、验证并记录到账号详情，ChatGPT Work 接口不可用（HTTP 404），已跳过重置并提交登出所有设备；自动重新登录已暂停"
        : "2FA 已更换、验证并记录到账号详情，ChatGPT Work 已重置，已提交登出所有设备；自动重新登录已暂停";
  } else {
    const uncertain = resultError || result?.status === "needs_attention"
      || (!result && failureMarker && failureMarker.mutationStarted !== false)
      || (result && ["disable_requested", "old_disabled", "enrollment_requested", "enrolled", "activation_requested", "activated", "verified", "work_reset_requested", "work_reset_confirmed", "logout_requested"].includes(result.stage));
    status = uncertain ? "needs_attention" : (canceled || job.securityCancelRequested ? "canceled" : "failed");
    message ||= uncertain ? "安全操作可能已修改远端状态，已保留结果，请先核实后恢复"
      : restored ? "服务重启中断了安全操作，未自动重新执行"
      : signal ? `安全操作进程被 ${signal} 终止`
      : canceled || job.securityCancelRequested ? "已取消安全操作"
      : `安全操作未完成${code === undefined ? "" : `（退出代码 ${code}）`}`;
    message = safeSecurityError(message, [job.password, job.totpSecret, job.proxyUrl, result?.secret]);
    if (rotationVerified && operation.action === "rotate-totp-logout-all") message = result?.work_reset_unavailable
      ? `新 2FA 密钥已验证并保存；Work 接口不可用（HTTP 404）已跳过，登出所有设备尚未确认：${message}`
      : result?.work_reset_succeeded
        ? `新 2FA 密钥已验证并保存；登出所有设备尚未确认：${message}`
        : `新 2FA 密钥已验证并保存；Work 重置尚未确认，未完成登出：${message}`;
    operation = securityOperations.update(operation.operationId, {
      status, stage: result?.stage || operation.stage, result: result || operation.result,
      completedAt: now, error: message,
    });
  }
  if (!completed && (failureMarker?.code === "ACCOUNT_PERMANENTLY_UNAVAILABLE" || isRetiredAccountFailure(message))) {
    accountLifecycle.retire(job.email, safeSecurityError(message || "账号已被上游删除或停用", [job.password, job.totpSecret, job.proxyUrl]), now);
  }
  restoreSecurityJobStatus(job, operation, message);
  appendJobLog(job, status === "completed" ? `[security] ${message}。\n`
    : status === "needs_attention" ? "[security] 操作结果需要核实，已保留私有恢复记录，未重复执行。\n"
      : "[security] 本次安全操作未完成，可在账号详情查看结果。\n");
  await saveJobMetadata(job);
  if (status === "completed") await fs.rm(securityOperationResultPath(job, operation), { force: true });
  return operation;
}

async function restoreSecurityOperations() {
  for (const job of jobs.values()) {
    const metadata = serverDatabase.getJob(job.id) || {};
    job.securityAutoLoginPaused = Boolean(metadata.security_auto_login_paused);
    job.securityLoginResumedAt = metadata.security_login_resumed_at || null;
    const operations = securityOperations.list(job);
    const unfinished = operations.filter((operation) => ["queued", "running", "needs_attention"].includes(operation.status));
    const recorded = operations.find((operation) => operation.operationId === metadata.security_operation_id);
    if (isSecurityMode(metadata.queued_mode) && recorded && !unfinished.includes(recorded)) unfinished.push(recorded);
    job.securityOperationId = operations.at(-1)?.operationId || null;
    for (const operation of unfinished) {
      job.securityOperationId = operation.operationId;
      // No network request is repeated after a restart. Only acknowledged results
      // may update credentials; partial results stay in the private recovery record.
      try { await finishSecurityOperation(job, { restored: true }); }
      catch (error) {
        const failed = securityOperations.update(operation.operationId, { status: "needs_attention", error: safeSecurityError(error.message, [job.password, job.totpSecret]) });
        restoreSecurityJobStatus(job, failed, "安全操作结果需要恢复，私有结果已保留");
        await saveJobMetadata(job);
      }
    }
    // A completed logout may precede a crash before its job metadata was written.
    const latestLogout = securityOperations.list(job).filter((item) => item.action !== "rotate-totp"
      && (item.result?.logout_accepted || item.result?.stage === "logout_requested")).at(-1);
    if (latestLogout
      && (!metadata.security_login_resumed_at || Date.parse(metadata.security_login_resumed_at) < Date.parse(latestLogout.startedAt))) {
      job.securityAutoLoginPaused = true;
    }
  }
}

async function startTotpSetup(job, options = {}) {
  if (canSetupTotp(job)) await overrideScheduledJob(job, "人工设置 2FA 替代了原定时任务");
  if (!canSetupTotp(job)) {
    throw httpError(409, "只能为已完成授权，或已保存邮箱登录检查点且尚未设置 2FA 的账号设置 2FA");
  }
  if (job.totpSecret || job.hasTotpCredential) {
    throw httpError(409, "该账号已经保存了 2FA 密钥，无需重复设置");
  }
  if (job.totpKnownEnabled) {
    throw httpError(409, "该账号已经启用 2FA，但本地没有它的原始密钥，无法重复创建");
  }
  const resumeAuthorization = !job.resultSaved;
  if (resumeAuthorization && !(await fileExists(job.checkpointPath))) {
    job.loginCheckpointAvailable = false;
    throw httpError(409, "邮箱登录检查点已丢失，请先重新登录");
  }
  await configureOperationProxy(job, options);
  stopMailPolling(job);
  releaseSmsNumber(job, "idle");
  job.queueRunId = null;
  job.runId = crypto.randomUUID();
  job.child?.kill("SIGTERM");
  job.child = null;
  job.currentPhone = null;
  job.phoneError = null;
  await removePrivateFile(job.totpResultPath);
  job.totpSetupSecret = null;
  job.totpSetupUri = null;
  job.totpSetupError = null;
  job.totpSetupAttempt = (job.totpSetupAttempt || 0) + 1;
  job.totpSetupResumesAuthorization = resumeAuthorization;
  job.proxyRiskRetryCount = 0;
  job.proxyConnectionFailureCount = 0;
  job.directTlsFallbackAttempted = false;
  job.proxyRiskRestarting = false;
  job.proxySessionAttemptIds.clear();
  job.proxyAttemptParserTail = "";
  job.lastError = null;
  job.parserTail = "";
  recordJobOperation(job, "setup_2fa");
  appendJobLog(job, `\n[2fa] 开始第 ${job.totpSetupAttempt} 次 2FA 设置，原授权文件保持不变。\n`);
  enqueueJob(job, "totp_setup", "正在重新验证账号并准备设置 2FA");
}

async function startPasswordAdd(job, options = {}) {
  if (canAddPassword(job)) await overrideScheduledJob(job, "人工添加密码替代了原定时任务");
  if (!canAddPassword(job)) {
    throw httpError(409, "只能为已完成授权，或已保存邮箱登录检查点且尚未保存密码的账号添加密码");
  }
  const resumeAuthorization = !job.resultSaved;
  if (resumeAuthorization && !(await fileExists(job.checkpointPath))) {
    job.loginCheckpointAvailable = false;
    throw httpError(409, "邮箱登录检查点已丢失，请先重新登录");
  }
  await configureOperationProxy(job, options);
  stopMailPolling(job);
  releaseSmsNumber(job, "idle");
  job.queueRunId = null;
  job.runId = crypto.randomUUID();
  job.child?.kill("SIGTERM");
  job.child = null;
  job.currentPhone = null;
  job.phoneError = null;
  await removePrivateFile(job.passwordAddResultPath);
  job.pendingNewPassword = generateStrongPassword();
  job.passwordAddResumesAuthorization = resumeAuthorization;
  job.passwordAddError = null;
  job.proxyRiskRetryCount = 0;
  job.proxyConnectionFailureCount = 0;
  job.directTlsFallbackAttempted = false;
  job.proxyRiskRestarting = false;
  job.proxySessionAttemptIds.clear();
  job.proxyAttemptParserTail = "";
  job.lastError = null;
  job.parserTail = "";
  recordJobOperation(job, "add_password");
  appendJobLog(job, "\n[password-add] 开始为无密码账号添加密码，新密码不会写入协议日志。\n");
  enqueueJob(job, "password_add", "正在重新验证账号并准备添加密码");
}

function generateStrongPassword() {
  const lower = "abcdefghijkmnopqrstuvwxyz";
  const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  const digits = "23456789";
  const symbols = "!@#%_";
  const all = `${lower}${upper}${digits}${symbols}`;
  const chars = [
    lower[crypto.randomInt(lower.length)],
    upper[crypto.randomInt(upper.length)],
    digits[crypto.randomInt(digits.length)],
    symbols[crypto.randomInt(symbols.length)],
  ];
  while (chars.length < 18) chars.push(all[crypto.randomInt(all.length)]);
  for (let index = chars.length - 1; index > 0; index -= 1) {
    const target = crypto.randomInt(index + 1);
    [chars[index], chars[target]] = [chars[target], chars[index]];
  }
  return chars.join("");
}

async function finishPasswordAdd(job, code, signal) {
  let result = null;
  try {
    result = JSON.parse(await fs.readFile(job.passwordAddResultPath, "utf8"));
  } catch (error) {
    if (error?.code !== "ENOENT") job.passwordAddError = `添加密码结果无法读取：${error.message}`;
  }

  if (
    result?.version === 1
    && String(result.email || "").toLowerCase() === job.email.toLowerCase()
    && typeof result.password === "string"
    && result.password === job.pendingNewPassword
  ) {
    job.password = result.password;
    job.hasPasswordCredential = true;
    job.loginMode = "password";
    job.passwordAddedAt = result.added_at || new Date().toISOString();
    const persisted = await saveStoredLoginCredentials(job.email, job);
    job.passwordAddError = persisted
      ? null
      : "当前系统不支持持久凭据存储，新密码仅在本次服务运行期间可用";
    job.prompt = persisted
      ? job.passwordAddResumesAuthorization
        ? "密码添加成功，可以继续未完成的 Codex 授权"
        : "密码添加成功，账号原始信息已经更新"
      : "密码添加成功，但新密码未能持久保存";
    appendJobLog(job, persisted
      ? "[password-add] 密码添加成功，新密码已安全保存，未写入协议日志。\n"
      : "[password-add] 密码添加成功，但当前系统不支持持久保存新密码。\n");
    if (persisted) await removePrivateFile(job.passwordAddResultPath);
  } else {
    job.prompt = job.passwordAddResumesAuthorization
      ? "本次添加密码未完成，原登录检查点仍可继续"
      : "原授权文件仍可使用，本次添加密码未完成";
    job.passwordAddError ||= signal
      ? `添加密码进程被 ${signal} 终止`
      : `添加密码进程退出，代码 ${code ?? "未知"}`;
    await removePrivateFile(job.passwordAddResultPath);
  }

  job.status = job.passwordAddResumesAuthorization ? "resume_available" : "completed";
  job.lastError = job.passwordAddResumesAuthorization
    ? "ChatGPT 登录状态已保留，点击继续流程即可重新开始 Codex 授权"
    : null;
  job.runMode = null;
  job.runId = null;
  job.pendingNewPassword = null;
  job.passwordAddResumesAuthorization = false;
  touch(job);
  await saveJobMetadata(job);
}

function restorePasswordAddFailure(job, message) {
  const resumeAuthorization = Boolean(job.passwordAddResumesAuthorization);
  job.status = resumeAuthorization ? "resume_available" : "completed";
  job.prompt = resumeAuthorization
    ? "本次添加密码未完成，原登录检查点仍可继续"
    : "原授权文件仍可使用，本次添加密码未完成";
  job.passwordAddError = message;
  job.lastError = resumeAuthorization ? "点击继续流程可恢复 Codex 授权" : null;
  job.runMode = null;
  job.runId = null;
  job.pendingNewPassword = null;
  job.passwordAddResumesAuthorization = false;
  job.child?.kill("SIGTERM");
  job.child = null;
  touch(job);
  void removePrivateFile(job.passwordAddResultPath).catch(() => {});
  void saveJobMetadata(job).catch(() => {});
}

async function loadTotpSetupResult(job) {
  const data = JSON.parse(await fs.readFile(job.totpResultPath, "utf8"));
  if (data?.version !== 1) throw new Error("2FA 设置结果文件格式不正确");
  if (data.already_enabled) {
    job.totpKnownEnabled = true;
    job.totpSetupSecret = null;
    job.totpSetupUri = null;
    return data;
  }
  const secret = normalizeTotpSecret(data.secret);
  const uri = String(data.otpauth_uri || "");
  if (!uri.startsWith("otpauth://totp/")) throw new Error("2FA 设置地址格式不正确");
  job.totpSetupSecret = secret;
  job.totpSetupUri = uri;
  if (data.activation_mode === "automatic") {
    if (job.status !== "totp_setup_otp") setStage(job, "working", "2FA 密钥已生成，正在自动激活");
  } else {
    setStage(job, "totp_setup_otp", "密钥已生成，请添加到验证器后输入当前 6 位验证码");
  }
  return data;
}

async function finishTotpSetup(job, code, signal) {
  const resumeAuthorization = Boolean(job.totpSetupResumesAuthorization);
  let result = null;
  try {
    result = await loadTotpSetupResult(job);
  } catch (error) {
    if (error?.code !== "ENOENT" && !job.totpSetupError) job.totpSetupError = error.message;
  }

  const activationSucceeded = result?.activation_succeeded === true;
  let removeResult = false;
  if (code === 0 && result?.already_enabled) {
    job.totpKnownEnabled = true;
    job.prompt = "账号已经启用 2FA，但服务端不会返回原始密钥";
    job.totpSetupError = "如需自动登录，请重新导入这个账号原有的 2FA 密钥";
    removeResult = true;
  } else if ((code === 0 || activationSucceeded) && result?.secret) {
    const secret = normalizeTotpSecret(result.secret);
    job.totpSecret = secret;
    job.hasTotpCredential = true;
    job.totpKnownEnabled = true;
    const persisted = await saveStoredLoginCredentials(job.email, job);
    job.prompt = activationSucceeded && code !== 0
      ? "2FA 已激活并保存，但最终状态确认未完成"
      : resumeAuthorization
        ? "2FA 已设置并安全保存，可以继续未完成的 Codex 授权"
        : "2FA 已设置并安全保存，可以继续下载或重新授权";
    job.totpSetupError = !persisted
      ? "当前系统不支持持久凭据存储，2FA 密钥已保留在私有结果文件中，请不要删除该任务目录"
      : activationSucceeded && code !== 0
      ? "激活接口已返回成功，但后续确认请求失败；密钥已保留"
      : null;
    appendJobLog(job, persisted
      ? "[2fa] 2FA 设置成功，密钥已写入系统凭据存储，未写入协议日志。\n"
      : "[2fa] 2FA 设置成功，但当前系统不支持持久凭据存储；密钥已保留在私有结果文件中。\n");
    removeResult = persisted;
  } else {
    job.prompt = resumeAuthorization
      ? "本次 2FA 设置未完成，原登录检查点仍可继续"
      : "授权文件仍然可用，本次 2FA 设置未完成";
    job.totpSetupError ||= signal
      ? `2FA 设置进程被 ${signal} 终止`
      : `2FA 设置进程退出，代码 ${code ?? "未知"}`;
  }

  job.status = resumeAuthorization ? "resume_available" : "completed";
  job.lastError = resumeAuthorization
    ? "ChatGPT 登录状态已保留，点击继续流程即可重新开始 Codex 授权"
    : null;
  job.runMode = null;
  job.runId = null;
  job.totpSetupSecret = null;
  job.totpSetupUri = null;
  job.totpSetupResumesAuthorization = false;
  if (removeResult || !result?.secret || result?.activation_succeeded === false) {
    await removePrivateFile(job.totpResultPath);
  }
  touch(job);
  await saveJobMetadata(job);
}

async function removePrivateFile(filePath) {
  if (!filePath) return;
  serverDatabase.removeArtifact(filePath);
  try {
    await fs.unlink(filePath);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

function restoreTotpSetupFailure(job, message) {
  const resumeAuthorization = Boolean(job.totpSetupResumesAuthorization);
  job.status = resumeAuthorization ? "resume_available" : "completed";
  job.prompt = resumeAuthorization
    ? "本次 2FA 设置未完成，原登录检查点仍可继续"
    : "授权文件仍然可用，本次 2FA 设置未完成";
  job.totpSetupError = message;
  job.totpSetupSecret = null;
  job.totpSetupUri = null;
  job.totpSetupResumesAuthorization = false;
  job.lastError = resumeAuthorization ? "点击继续流程可恢复 Codex 授权" : null;
  job.runMode = null;
  job.child?.kill("SIGTERM");
  job.child = null;
  void removePrivateFile(job.totpResultPath).catch(() => {});
  touch(job);
  void saveJobMetadata(job).catch(() => {});
}

async function fallbackFromRefresh(job) {
  if (job.runMode !== "refresh" || job.fallbackInProgress) return;
  job.fallbackInProgress = true;
  stopMailPolling(job);
  releaseSmsNumber(job, "idle");
  job.runId = crypto.randomUUID();
  job.child?.kill("SIGTERM");
  job.child = null;
  job.status = "starting";
  job.prompt = "已有授权状态已过期，正在重新进行邮箱登录";
  job.lastError = null;
  job.parserTail = "";
  job.currentPhone = null;
  job.phoneError = null;
  beginAuthorizationAutomationAttempt(job, "refresh_fallback");
  appendJobLog(job, "[refresh] 刷新令牌已失效，自动回退到邮箱验证码登录。\n");
  job.fallbackInProgress = false;
  if (job.status !== "canceled") {
    enqueueJob(job, "full", "刷新令牌已失效，正在重新登录并授权");
  }
  touch(job);
}

function consumeSecurityOutput(job, rawText) {
  // Security children can hold a newly enrolled secret before it is committed.
  // Their raw output is never copied to the general log or status API.
  const scan = `${job.parserTail || ""}${rawText}`.slice(-6_000);
  job.parserTail = scan;
  for (const match of scan.matchAll(/\[security-failure\]\s+(\{[^\r\n]*\})/g)) {
    let marker;
    try { marker = normalizeSecurityFailureMarker(JSON.parse(match[1])); } catch { continue; }
    if (!marker) continue;
    const operation = securityOperations.read(job.securityOperationId);
    if (!operation) continue;
    const key = JSON.stringify(marker);
    if (job.securityFailureMarkerSeen === key) continue;
    job.securityFailureMarkerSeen = key;
    job.securityFailureMessage = marker.message;
    securityOperations.update(operation.operationId, { failureMarker: marker });
  }
  const markers = [...scan.matchAll(/\[email-otp-requested-at\]\s+(\S+)/g)];
  const requestedAt = Date.parse(markers.at(-1)?.[1] || "");
  if (Number.isFinite(requestedAt)) job.mailOtpRequestedAt = requestedAt;
  if (scan.includes("[proxy-risk-retry]")) {
    job.securityFailureMessage = "SOCKS5 代理连接或验证失败，已停止本次操作，未改为直连";
    job.child?.kill("SIGTERM");
    return;
  }
  if (scan.includes("[security-check-required]") || scan.includes("[profile-security-check-required]")) {
    job.securityFailureMessage = "服务端要求额外安全验证，本次账号安全操作未完成";
    job.child?.kill("SIGTERM");
    return;
  }
  if (scan.includes("Email OTP (r=resend, q=quit):")) {
    setStage(job, "email_otp", job.mailApiUrl ? "正在等待邮箱验证码，可手动输入" : "请输入邮箱验证码");
    if (job.mailApiUrl) void beginMailPolling(job);
  }
  if (scan.includes("Password (q=quit):")) {
    stopMailPolling(job);
    setStage(job, "password", "请输入账号密码");
  }
  if (scan.includes("2FA OTP (6 digits, q=quit):")) setStage(job, "mfa_otp", "请输入当前 6 位 2FA 验证码");
  const operation = securityOperations.read(job.securityOperationId);
  const journal = operation && serverDatabase.get("security-operation-result", operation.operationId);
  if (journal) {
    try {
      const result = validateSecurityResult(journal, operation);
      securityOperations.update(operation.operationId, { result, stage: result.stage });
      accountLifecycle.logout(job.email, { ...operation, result });
      if (result.stage !== "prepared" && !job.securityCancelRequested) {
        setStage(job, "security_working", result.stage === "logout_requested" ? "正在登出所有设备"
          : result.stage.startsWith("work_reset") ? "正在重置 ChatGPT Work"
            : "正在更换并验证 2FA");
      }
    } catch {
      job.securityFailureMessage = "安全操作结果与当前账号不匹配，已停止等待核实";
      job.child?.kill("SIGTERM");
    }
  }
  touch(job);
}

function consumeEmailLoginMarkers(job, rawText) {
  const previous = job.emailLoginMarkerTail || "";
  const scan = `${previous}${rawText}`;
  job.emailLoginMarkerTail = scan.slice(-1000);
  job.emailLoginMarkerSeen ||= new Set();
  let discardThrough = 0;
  for (const match of scan.matchAll(/\[email-login-(attempt|retry|failed)\]\s+(\{[^\r\n]*\})/g)) {
    let value;
    try { value = JSON.parse(match[2]); } catch { continue; }
    const type = match[1];
    const attempt = Number(value.attempt ?? value.attempts);
    const reason = ["EMAIL_OTP_REQUIRED", "EMAIL_OTP_TIMEOUT", "EMAIL_OTP_REJECTED"].includes(value.reason) ? value.reason : null;
    if (!Number.isInteger(attempt) || attempt < 1 || attempt > 3) continue;
    const key = `${type}:${attempt}:${reason || ""}`;
    if (job.emailLoginMarkerSeen.has(key)) continue;
    job.emailLoginMarkerSeen.add(key);
    job.emailLoginAttempt = attempt;
    if (reason) job.emailLoginReason = reason;
    if (type === "retry" || type === "failed") {
      stopMailPolling(job);
      job.parserTail = "";
      job.mailOtpRequestedAt = null;
      discardThrough = Math.max(discardThrough, match.index + match[0].length - previous.length);
      if (type === "retry") setStage(job, "working", `本次登录仍需邮箱验证，准备第 ${Math.min(3, attempt + 1)}/3 次登录`);
      else {
        job.emailLoginAutoPaused = true;
        const message = `自动登录尝试 ${attempt} 次仍需邮箱验证：${reason === "EMAIL_OTP_TIMEOUT" ? "自动收码超时" : reason === "EMAIL_OTP_REJECTED" ? "邮箱验证码被拒绝" : "缺少可自动获取的邮箱验证码"}，已停止等待`;
        if (isSecurityMode(job.runMode)) job.securityFailureMessage = message;
        else failJob(job, message);
      }
    }
    touch(job);
    void saveJobMetadata(job).catch(() => {});
  }
  return rawText.slice(Math.max(0, discardThrough));
}

function consumeOutput(job, rawText) {
  rawText = consumeEmailLoginMarkers(job, rawText);
  if (isSecurityMode(job.runMode)) return consumeSecurityOutput(job, rawText);
  const proxyAttemptScan = `${job.proxyAttemptParserTail || ""}${rawText}`;
  job.proxyAttemptParserTail = proxyAttemptScan.slice(-160);
  let proxyAttemptNotices = "";
  for (const match of proxyAttemptScan.matchAll(/\[proxy-session-attempt\]\s+([a-f0-9-]{36})/gi)) {
    const attemptId = match[1].toLowerCase();
    if (job.proxySessionAttemptIds.has(attemptId)) continue;
    job.proxySessionAttemptIds.add(attemptId);
    job.proxyRiskRetryCount = Math.min(MAX_PROXY_RISK_RETRIES, (job.proxyRiskRetryCount || 0) + 1);
    job.proxyConnectionFailureCount = 0;
    proxyAttemptNotices += `[proxy] 正在检测第 ${job.proxyRiskRetryCount}/${MAX_PROXY_RISK_RETRIES} 个新代理会话。\n`;
    void saveJobMetadata(job).catch(() => {});
  }
  const text = `${proxyAttemptNotices}${sanitizeLog(rawText)}`
    .replace(/^\[proxy-session-attempt\][^\r\n]*(?:\r?\n)?/gim, "");
  job.logs = `${job.logs}${text}`.slice(-MAX_LOG_CHARS);
  if (!job.deleted) serverDatabase.saveLogs(job.id, job.logs);
  const scan = `${job.parserTail}${text}`;
  job.parserTail = scan.slice(-2_000);

  if (scan.includes("[3/5] Password login page reached.")) {
    markAuthorizationRequirement(job, "password");
    if (job.password) markAuthorizationAutomatic(job, "password");
  }
  if (scan.includes("[3/5] Email OTP page reached.")) {
    markAuthorizationRequirement(job, "emailOtp");
  }
  const mailRequestMarkers = [...scan.matchAll(/\[email-otp-requested-at\]\s+(\S+)/g)];
  const latestMailRequestAt = Date.parse(mailRequestMarkers.at(-1)?.[1] || "");
  if (Number.isFinite(latestMailRequestAt)) job.mailOtpRequestedAt = latestMailRequestAt;
  if (scan.includes("[checkpoint] Saved verified email login state.")
    || scan.includes("[checkpoint] Updated verified login state after adding the password.")
    || scan.includes("[checkpoint] Updated verified login state after setting 2FA.")) {
    job.loginCheckpointAvailable = true;
  }

  if (scan.includes("[proxy-risk-retry]")) {
    const failure = scan.match(/\[proxy-risk-retry\][ \t]*([^\r\n]*)(?:\r?\n|\r)/);
    // Keep an incomplete marker buffered until its complete line or child close.
    if (!failure && (job.runMode || job.queuedMode || "full") === "full") return;
    void restartAfterProxyRisk(job, {
      connectionFailure: scan.includes("PROXY_CONNECTION_RETRY"),
      failureDetail: failure?.[1],
    }).catch((error) => {
      finishProxyRiskRetries(job, `自动更换代理会话失败：${error.message}`);
    });
    return;
  }

  if (job.runMode === "refresh" && scan.includes("REFRESH_TOKEN_INVALID")) {
    void fallbackFromRefresh(job);
    return;
  }

  if (job.runMode === "totp_setup" && scan.includes("[2fa-setup-ready]") && !job.totpResultLoading && !job.totpSetupSecret) {
    job.totpResultLoading = true;
    setStage(job, "working", "2FA 密钥已经生成，正在安全读取");
    void loadTotpSetupResult(job)
      .catch((error) => {
        job.totpSetupError = `无法读取 2FA 密钥：${error.message}`;
        job.child?.kill("SIGTERM");
        touch(job);
      })
      .finally(() => {
        job.totpResultLoading = false;
      });
  }

  if (job.runMode === "totp_setup" && scan.includes("[2fa-already-enabled]")) {
    job.totpKnownEnabled = true;
    setStage(job, "working", "账号已经启用 2FA，正在收尾");
  }

  if (job.runMode === "totp_setup" && scan.includes("[ok] 2FA setup activated")) {
    setStage(job, "working", "2FA 已激活，正在安全保存密钥");
  }

  if (scan.includes("[security-check-required]")) {
    if (job.runMode === "totp_setup") {
      job.totpSetupError = "本次登录需要浏览器安全校验，2FA 尚未设置";
      touch(job);
      return;
    }
    if (job.runMode === "password_add") {
      job.passwordAddError = "添加密码需要浏览器安全校验，请稍后重试或更换代理 IP";
      touch(job);
      return;
    }
    requireBrowserSecurityCheck(job);
    return;
  }

  if (scan.includes("[profile-security-check-required]")) {
    if (job.runMode === "totp_setup") {
      job.totpSetupError = "账号资料校验未通过，2FA 尚未设置";
      touch(job);
      return;
    }
    if (job.runMode === "password_add") {
      job.passwordAddError = "账号资料校验未通过，密码尚未添加";
      touch(job);
      return;
    }
    requireProfileSecurityCheck(job);
    return;
  }

  if (scan.includes("ACCOUNT_PROFILE_REQUIRED")) {
    failAccountProfileRequired(job);
    return;
  }

  const sessionErrorLines = [...scan.matchAll(/^\[error\]\s*([^\r\n]+)/gim)];
  const latestSessionError = sessionErrorLines.at(-1)?.[1] || "";
  if (/Your sign-in session is no longer valid|["']code["']\s*:\s*["'](?:invalid_state|invalid_auth_step)["']|Invalid authorization step/i.test(latestSessionError)) {
    if (job.runMode === "totp_setup") {
      job.totpSetupError = "设置 2FA 时登录状态失效，请稍后重试";
      touch(job);
      return;
    }
    if (job.runMode === "password_add") {
      job.passwordAddError = "添加密码时登录状态失效，请稍后重试";
      touch(job);
      return;
    }
    requireReauthorization(job, "当前登录状态已经失效，继续更换手机号也无法发送验证码");
    return;
  }

  if (scan.includes("[auth-expired]")) {
    stopSmsPolling(job);
    releaseSmsNumber(job, "idle");
    job.currentPhone = null;
    job.phoneError = null;
    setStage(job, "starting", "新登录状态被服务端拒绝，正在自动重新获取邮箱验证码");
  }

  // Input prompts can follow one another within the same OAuth session. Apply
  // only the newest complete prompt from this chunk, never an older parserTail
  // marker that would overwrite a later prompt (for example MFA -> email OTP).
  const promptMarkers = [
    ["email", "Email OTP (r=resend, q=quit):"],
    ["password", "Password (q=quit):"],
    ["totp_setup", "2FA setup OTP (6 digits, q=quit):"],
    ["mfa_reached", "[mfa] TOTP 2FA challenge reached."],
    ["mfa_otp", "2FA OTP (6 digits, q=quit):"],
  ];
  const newOutputStart = scan.length - text.length;
  const latestPrompt = promptMarkers
    .map(([kind, marker]) => ({ kind, marker, index: scan.lastIndexOf(marker) }))
    .filter(({ marker, index }) => index >= 0 && index + marker.length > newOutputStart)
    .sort((left, right) => right.index - left.index)[0];
  if (latestPrompt?.kind === "email") {
    markAuthorizationRequirement(job, "emailOtp");
    const rejected = scan.includes("[email-otp-rejected]");
    setStage(
      job,
      "email_otp",
      rejected
        ? "邮箱验证码错误，请重新输入或重新发送"
        : job.mailApiUrl
          ? "正在等待收码接口返回新验证码，也可以手动输入"
          : "请输入邮箱验证码",
    );
    if (job.mailApiUrl) void beginMailPolling(job);
  } else if (latestPrompt?.kind === "password") {
    markAuthorizationRequirement(job, "password");
    stopMailPolling(job);
    setStage(job, "password", "请输入账号密码");
  } else if (latestPrompt?.kind === "totp_setup") {
    setStage(job, "totp_setup_otp", "请将密钥添加到验证器后输入当前 6 位验证码");
  } else if (latestPrompt?.kind === "mfa_reached") {
    markAuthorizationRequirement(job, "mfa");
    setStage(job, "working", job.totpSecret ? "正在自动完成 2FA 验证" : "正在准备 2FA 验证");
  } else if (latestPrompt?.kind === "mfa_otp") {
    markAuthorizationRequirement(job, "mfa");
    setStage(job, "mfa_otp", "请输入 6 位 2FA 验证码");
  }
  if (scan.includes("[mfa] Generated a 6-digit code from the configured 2FA key.")) {
    markAuthorizationAutomatic(job, "mfa");
  }
  const phoneNumberPromptIndex = scan.lastIndexOf("Phone number, E.164 format");
  const phoneOtpPromptIndex = scan.lastIndexOf("Phone OTP (r=resend, p=change phone, q=quit):");
  if (phoneNumberPromptIndex > phoneOtpPromptIndex) {
    stopMailPolling(job);
    setStage(job, "phone", "请输入需要绑定的手机号");
  } else if (phoneOtpPromptIndex > phoneNumberPromptIndex) {
    if (job.smsStatus !== "error") job.phoneError = null;
    setStage(
      job,
      "phone_otp",
      job.currentPhone ? `短信验证码已发送至 ${job.currentPhone}` : "请输入手机短信验证码",
    );
    if (job.smsOrderId && job.smsNumber === job.currentPhone) void beginSmsPolling(job);
  }

  const sendFailures = [...scan.matchAll(/\[warn\] Could not send SMS to (\+\d+):\s*([^\r\n]+)/g)];
  if (sendFailures.length) {
    const latest = sendFailures.at(-1);
    job.currentPhone = latest[1];
    job.phoneError = friendlyPhoneError(latest[2]);
    if (job.smsOrderId && job.smsNumber === job.currentPhone) {
      releaseSmsNumber(job, "error", "该平台手机号无法接收验证码，请重新取号或手动输入其他手机号");
    }
    setStage(job, "phone", `手机号 ${job.currentPhone} 无法接收验证码，请更换手机号`);
  }

  const validationFailures = [...scan.matchAll(/\[warn\] Phone OTP validation failed:\s*([^\r\n]+)/g)];
  if (validationFailures.length) {
    const validationMessage = validationFailures.at(-1)[1];
    job.phoneError = friendlyPhoneOtpError(validationMessage);
    stopSmsPolling(job);
    if (job.smsStatus === "submitted") {
      job.smsStatus = "error";
      job.smsError = "平台返回的验证码未通过验证，请重新发送或更换手机号";
    }
    setStage(
      job,
      "phone_otp",
      job.currentPhone ? `请重新输入发送至 ${job.currentPhone} 的验证码` : "请重新输入手机验证码",
    );
    if (shouldChangePhoneAfterOtpFailure(validationMessage)) {
      job.smsError = job.phoneError;
      appendJobLog(job, "[sms] 当前手机号已被服务端拒绝，停止提交旧验证码并自动返回换号步骤。\n");
      void submitJobInput(job, { action: "change_phone", value: "" }, {
        preservePhoneError: true,
      }).catch((error) => {
        failJob(job, `无法自动返回换号步骤：${error.message}`);
      });
      touch(job);
      return;
    }
  }
  if (scan.includes("[ok] Phone OTP validated")) {
    completeSmsNumber(job);
  }
  if (scan.includes("[5/5] Select workspace") || scan.includes("[6/6] Convert OAuth callback")) {
    setStage(job, "finalizing", "正在完成授权并生成文件");
  }
  if (scan.includes("[4/5] Existing workspace/session selected")) {
    setStage(job, "finalizing", "账号已绑定手机号，正在继续授权");
  }
  if (scan.includes("[ok] Saved sub2api import:")) {
    job.resultSaved = true;
    job.loginResultRunId = job.runId;
    if (job.scheduleItemId) job.scheduleResultAttemptId = job.scheduleLoginAttemptId;
    job.crsBridgeResultOperationId = job.crsBridgeOperationId || null;
    setStage(job, "finalizing", "导入文件已生成，正在收尾");
  }
  if (scan.includes("[ok] Account password added and saved securely")) {
    setStage(job, "finalizing", "密码已添加，正在安全保存新密码");
  }
  const errorMatches = [...scan.matchAll(/\[error\]\s*([^\r\n]+)/g)];
  if (errorMatches.length) {
    const errorMessage = extractResponseMessage(errorMatches.at(-1)[1]);
    if (job.runMode === "totp_setup") {
      job.totpSetupError = errorMessage;
    } else if (job.runMode === "password_add") {
      job.passwordAddError = errorMessage;
    } else {
      failJob(job, errorMessage);
    }
  }
  touch(job);
}

function codexAuthorizationFailureMessage(job, value) {
  // Only return known diagnostic fields. Never expose upstream response bodies,
  // arbitrary hosts/paths, URL queries, proxy credentials or token values.
  let text = String(value || "");
  for (const secret of [job.password, job.totpSecret, job.proxyUrl, job.mailApiUrl, job.pendingNewPassword]) {
    if (typeof secret === "string" && secret) {
      text = text.replaceAll(secret, "<redacted>");
      try { text = text.replaceAll(encodeURIComponent(secret), "<redacted>"); } catch {}
    }
  }
  const details = [];
  const request = text.match(/\b(GET|POST|PUT|PATCH|DELETE|HEAD)\s+(https?:\/\/[^\s<>"']+)/i);
  if (request) {
    try {
      const target = new URL(request[2]);
      const paths = new Set(["/", "/codex/desktop-auth", "/oauth/authorize", "/oauth/token",
        "/log-in", "/log-in/password", "/email-verification", "/choose-an-account",
        "/sign-in-with-chatgpt/codex/consent", "/api/accounts/authorize/continue",
        "/api/accounts/password/verify", "/api/accounts/email-otp/send", "/api/accounts/email-otp/validate",
        "/api/accounts/mfa/verify", "/api/accounts/session/select", "/api/accounts/workspace/select",
        "/api/accounts/add-phone/send", "/api/accounts/add-phone/validate"]);
      if (["https://auth.openai.com", "https://chatgpt.com"].includes(target.origin)) {
        details.push(`${request[1].toUpperCase()} ${target.origin}${paths.has(target.pathname) ? target.pathname : "/…"}`);
      }
    } catch {}
  }
  const http = text.match(/\bHTTP(?:\/\d(?:\.\d)?)?\s*[:=]?\s*([1-5]\d{2})\b/i);
  if (http) details.push(`HTTP ${http[1]}`);
  if (/\bETIMEDOUT\b|timed? out|TimeoutError|curl:\s*\(?28\)?\b/i.test(text)) details.push("连接超时");
  else if (/\b(?:ENOTFOUND|EAI_AGAIN)\b|could(?: not|n't) resolve|curl:\s*\(?[56]\)?\b/i.test(text)) details.push("DNS 解析失败");
  else if (/certificate verify failed|SSL peer certificate|curl:\s*\(?60\)?\b/i.test(text)) details.push("TLS 证书校验失败");
  else if (/SSL connect error|TLS handshake|curl:\s*\(?35\)?\b/i.test(text)) details.push("TLS 握手失败");
  else if (http?.[1] === "407" || /(?:proxy|SOCKS).{0,80}(?:authentication failed|authentication rejected|auth failure)|user was rejected by the SOCKS5 server/i.test(text)) details.push("代理认证失败");
  else if (/\bECONNRESET\b/.test(text)) details.push("连接被重置（ECONNRESET）");
  else if (/\bECONNREFUSED\b/.test(text)) details.push("连接被拒绝（ECONNREFUSED）");
  else if (/\b(?:EHOSTUNREACH|ENETUNREACH)\b|failed to connect|cannot complete SOCKS5 connection|curl:\s*\(?7\)?\b/i.test(text)) details.push("网络或代理连接失败");
  else if (/security-check|cf-mitigated|Cloudflare|安全校验/i.test(text)) details.push("服务端要求安全校验");
  return details.length
    ? `Codex 授权失败：${details.join("，")}；已停止本次登录，请检查后手动重试`
    : "Codex 授权连接或安全校验失败，已停止本次登录；请检查后手动重试";
}

async function restartAfterProxyRisk(job, options = {}) {
  if (job.proxyRiskRestarting || isTerminalStatus(job.status)) return;
  if ((job.runMode || job.queuedMode || "full") === "full") {
    finishProxyRiskRetries(job, codexAuthorizationFailureMessage(job, options.failureDetail));
    return;
  }
  if (isSecurityMode(job.runMode || job.queuedMode)) {
    job.securityFailureMessage = "SOCKS5 代理失败，已停止安全操作，不会更换出口或自动重试";
    job.child?.kill("SIGTERM");
    return;
  }
  if (job.operationProxyMode === "default" || job.scheduleItemId || job.crsBridgeOperationId || dynamicProxies.binding(job.email)) {
    finishProxyRiskRetries(job, "指定代理登录失败，保留当前绑定；请检查代理与账号状态");
    return;
  }
  job.proxyRiskRestarting = true;
  const mode = job.runMode || job.queuedMode || "full";
  try {
    if (!job.proxyUrl) {
      // Account TLS identities are persistent. Never probe a different browser
      // profile after a failed login and silently change this account's identity.
      finishProxyRiskRetries(job, "当前账号使用固定 TLS 配置，登录失败后保留配置；请检查网络与账号状态");
      return;
    } else if (!proxySupportsSessionRotation(job.proxyUrl)) {
      finishProxyRiskRetries(
        job,
        "当前代理没有可识别的会话编号，无法自动轮换；请更换代理配置后重试",
      );
      return;
    }
    if ((job.proxyRiskRetryCount || 0) >= MAX_PROXY_RISK_RETRIES) {
      finishProxyRiskRetries(job, `代理会话已自动更换 ${MAX_PROXY_RISK_RETRIES} 次，仍然触发安全校验`);
      return;
    }
    if (options.connectionFailure) {
      job.proxyConnectionFailureCount = (job.proxyConnectionFailureCount || 0) + 1;
      if (job.proxyConnectionFailureCount >= MAX_PROXY_CONNECTION_FAILURES) {
        finishProxyRiskRetries(
          job,
          `代理连接连续失败 ${MAX_PROXY_CONNECTION_FAILURES} 次，已停止自动重试`,
        );
        return;
      }
    }

    stopMailPolling(job);
    stopSmsPolling(job);
    releaseSmsNumber(job, "idle");
    job.queueRunId = null;
    job.runId = crypto.randomUUID();
    const restartRunId = job.runId;
    job.child?.kill("SIGTERM");
    job.child = null;
    if (mode === "full") await removePrivateFile(job.checkpointPath);
    job.parserTail = "";
    job.lastError = null;
    job.currentPhone = null;
    job.phoneError = null;
    job.securityCheckRequired = false;
    job.restartRequired = false;
    appendJobLog(
      job,
      options.connectionFailure
        ? `[proxy] 代理连接失败，HTTP 检测次数仍为 ${job.proxyRiskRetryCount}/${MAX_PROXY_RISK_RETRIES}；连接失败 ${job.proxyConnectionFailureCount}/${MAX_PROXY_CONNECTION_FAILURES}。\n`
        : `[proxy] 登录阶段触发安全校验，已使用 ${job.proxyRiskRetryCount}/${MAX_PROXY_RISK_RETRIES} 个代理会话，正在继续更换。\n`,
    );
    if (options.connectionFailure) {
      const retryDelay = Math.min(
        PROXY_CONNECTION_RETRY_MAX_MS,
        PROXY_CONNECTION_RETRY_BASE_MS * (2 ** Math.min(job.proxyConnectionFailureCount - 1, 4)),
      );
      job.status = "starting";
      job.prompt = `代理连接失败，${Math.ceil(retryDelay / 1_000)} 秒后更换会话`;
      touch(job);
      await saveJobMetadata(job);
      await delay(retryDelay);
      if (job.runId !== restartRunId || isTerminalStatus(job.status)) return;
    }
    job.proxyRiskRestarting = false;
    enqueueJob(
      job,
      mode,
      options.connectionFailure
        ? `代理连接失败，正在更换会话；HTTP 检测次数仍为 ${job.proxyRiskRetryCount}/${MAX_PROXY_RISK_RETRIES}`
        : `代理触发安全校验，已使用 ${job.proxyRiskRetryCount}/${MAX_PROXY_RISK_RETRIES} 个代理会话`,
    );
  } finally {
    job.proxyRiskRestarting = false;
  }
}

function finishProxyRiskRetries(job, message) {
  job.loginAutoRetryBlocked = true;
  job.proxyRiskRestarting = false;
  if (job.runMode === "totp_setup" || job.queuedMode === "totp_setup") {
    restoreTotpSetupFailure(job, message);
    return;
  }
  if (job.runMode === "password_add" || job.queuedMode === "password_add") {
    restorePasswordAddFailure(job, message);
    scheduleQueuedJobs();
    return;
  }
  if (job.resultSaved) {
    job.status = "completed";
    job.prompt = "原授权文件仍然可用，自动更换代理未能完成本次操作";
    job.lastError = message;
    job.runMode = null;
    job.child?.kill("SIGTERM");
    job.child = null;
    touch(job);
    void saveJobMetadata(job).catch(() => {});
    scheduleQueuedJobs();
    return;
  }
  failJob(job, message);
  job.child?.kill("SIGTERM");
  job.child = null;
  scheduleQueuedJobs();
}

function requireReauthorization(job, message) {
  if (isTerminalStatus(job.status)) return;
  stopMailPolling(job);
  releaseSmsNumber(job, "idle");
  job.status = "reauth_required";
  job.prompt = "登录状态已失效，需要重新授权";
  job.lastError = message;
  job.phoneError = null;
  job.restartRequired = true;
  job.child?.kill("SIGTERM");
  touch(job);
}

function requireBrowserSecurityCheck(job) {
  job.loginAutoRetryBlocked = true;
  if (isTerminalStatus(job.status)) return;
  stopMailPolling(job);
  releaseSmsNumber(job, "idle");
  job.status = "failed";
  job.prompt = "手机号绑定需要浏览器安全校验";
  job.lastError = "邮箱登录已经成功，但服务端拒绝了本次纯协议短信请求；可以手动重试，若仍被拒绝则需要稍后再试";
  job.phoneError = null;
  job.securityCheckRequired = true;
  job.child?.kill("SIGTERM");
  touch(job);
}

function requireProfileSecurityCheck(job) {
  if (isTerminalStatus(job.status)) return;
  stopMailPolling(job);
  releaseSmsNumber(job, "idle");
  job.status = "failed";
  job.prompt = "账号资料创建需要安全校验";
  job.lastError = "邮箱验证码已经通过，但账号资料创建仍被 Sentinel 安全校验拒绝；可以点击重新授权再次生成动态校验令牌";
  job.phoneError = null;
  job.securityCheckRequired = true;
  job.child?.kill("SIGTERM");
  touch(job);
  void saveJobMetadata(job).catch(() => {});
}

function failAccountProfileRequired(job) {
  if (isTerminalStatus(job.status)) return;
  stopMailPolling(job);
  releaseSmsNumber(job, "idle");
  job.status = "failed";
  job.prompt = "账号注册资料未完成";
  job.lastError = "邮箱验证已经成功，但该邮箱还没有完成账号资料填写。请先在官方页面完成姓名和出生日期后再重新授权。";
  job.phoneError = null;
  job.child?.kill("SIGTERM");
  touch(job);
  void saveJobMetadata(job).catch(() => {});
}

function markResumeAvailable(job, reason = "登录流程中断") {
  stopMailPolling(job);
  stopSmsPolling(job);
  job.status = "resume_available";
  job.prompt = "邮箱登录检查点仍然有效，可以继续手机号绑定";
  job.lastError = `${reason}，继续时会优先恢复已保存状态；状态失效才重新获取邮箱验证码`;
  job.child = null;
  job.currentPhone = null;
  job.loginCheckpointAvailable = true;
  touch(job);
}

function friendlyPhoneError(message) {
  const text = String(message || "");
  if (/suspicious behavior/i.test(text)) return "该手机号触发了风控，请更换手机号或稍后重试";
  if (/too many|rate.?limit|HTTP 429/i.test(text)) return "短信发送过于频繁，请稍后重试或更换手机号";
  if (/already|used|unsupported|invalid phone/i.test(text)) return "该手机号不可用或已被使用，请更换手机号";
  return "短信验证码发送失败，请更换手机号后重试";
}

function extractResponseMessage(value) {
  const text = String(value || "").trim();
  const jsonAt = text.indexOf("{");
  if (jsonAt >= 0) {
    try {
      const payload = JSON.parse(text.slice(jsonAt));
      const message = payload?.error?.message || payload?.message;
      if (typeof message === "string" && message.trim()) return message.trim();
    } catch {}
  }
  const match = text.match(/"message"\s*:\s*"((?:\\.|[^"\\])*)"/i);
  if (match) {
    try {
      return JSON.parse(`"${match[1]}"`).trim();
    } catch {
      return match[1].replace(/\\"/g, '"').replace(/\\n/g, "\n").trim();
    }
  }
  return text;
}

function friendlyPhoneOtpError(message) {
  const text = String(message || "");
  if (/phone_recently_used|phone number was recently used/i.test(text)) {
    return "该手机号近期已被使用，已停止重复提交，请更换手机号";
  }
  if (/phone_number_in_use|phone number already in use/i.test(text)) {
    return "该手机号已绑定其他账号，请更换手机号";
  }
  if (/expired/i.test(text)) return "手机验证码已过期，请重新发送或更换手机号";
  if (/too many|rate.?limit|HTTP 429/i.test(text)) {
    return "验证次数过多，已停止自动提交，请稍后更换手机号";
  }
  return "手机验证码不正确，请重新输入；也可以重新发送或更换手机号";
}

function shouldChangePhoneAfterOtpFailure(message) {
  return /phone_recently_used|phone number was recently used|phone_number_in_use|phone number already in use|too many|rate.?limit|HTTP 429/i
    .test(String(message || ""));
}

function acquireCustomSmsEntry(entries) {
  const poolKey = crypto.createHash("sha256")
    .update(JSON.stringify(entries))
    .digest("base64url");
  const nextIndex = customSmsPoolPositions.get(poolKey) || 0;
  if (nextIndex >= entries.length) return null;
  customSmsPoolPositions.set(poolKey, nextIndex + 1);
  serverDatabase.put("runtime", "sms-pool-positions", Object.fromEntries(customSmsPoolPositions));
  return entries[nextIndex];
}

async function acquireSmsNumber(job, providerId, config) {
  requireStage(job, "phone");
  if (job.smsStatus === "requesting") throw httpError(409, "正在获取手机号，请不要重复提交");

  let smsClient;
  try {
    smsClient = createSmsProvider(providerId, config, {
      lubanApiBase: process.env.LUBAN_SMS_API_BASE,
      smsBowerApiBase: process.env.SMSBOWER_API_BASE,
      acquireCustomSmsEntry,
    });
  } catch (error) {
    throw httpError(400, safeSmsProviderError(error, config?.apiKey));
  }

  releaseSmsNumber(job, "idle");
  job.smsClient = smsClient;
  job.smsProviderId = smsClient.id;
  job.smsProviderName = smsClient.name;
  job.smsServiceLabel = smsClient.serviceLabel;
  job.smsStatus = "requesting";
  job.smsError = null;
  touch(job);

  let order;
  try {
    order = await smsClient.getNumber();
    if (job.status !== "phone" || !job.child) {
      void smsClient.release(order.requestId).catch(() => {});
      throw httpError(409, "任务已经不在手机号输入步骤，平台号码已释放");
    }
    job.smsOrderId = order.requestId;
    job.smsNumber = order.number;
    job.smsStatus = "number_acquired";
    job.smsError = null;
    await saveJobMetadata(job);
    appendJobLog(job, `[sms] 已从 ${smsClient.name} 获取手机号并提交，等待短信发送结果。\n`);
    await submitJobInput(job, { action: "phone", value: order.number }, { source: "sms-provider" });
  } catch (error) {
    if (order?.requestId && job.smsOrderId === order.requestId) releaseSmsNumber(job, "error");
    if (job.status === "phone") {
      job.smsStatus = "error";
      job.smsError = safeSmsProviderError(error, smsClient.apiKey);
      if (!order) job.smsClient = null;
      touch(job);
    }
    if (error?.status) throw error;
    throw httpError(502, safeSmsProviderError(error, smsClient.apiKey));
  }
}

async function beginSmsPolling(job) {
  if (
    !job.smsClient
    || !job.smsOrderId
    || job.smsPollToken
    || job.status !== "phone_otp"
    || !["number_acquired", "waiting_sms"].includes(job.smsStatus)
  ) return;
  const pollToken = crypto.randomUUID();
  const requestId = job.smsOrderId;
  const smsClient = job.smsClient;
  const startedAt = Date.now();
  job.smsPollToken = pollToken;
  job.smsStatus = "waiting_sms";
  job.smsError = null;
  touch(job);

  try {
    if (smsClient.markReady) {
      await smsClient.markReady(requestId).catch((error) => {
        appendJobLog(job, `[sms] ${smsClient.name} 更新号码就绪状态失败：${safeSmsProviderError(error)}\n`);
      });
    }
    while (
      job.smsPollToken === pollToken &&
      job.smsOrderId === requestId &&
      job.status === "phone_otp" &&
      job.child &&
      Date.now() - startedAt < SMS_POLL_TIMEOUT_MS
    ) {
      try {
        const result = await smsClient.getSms(requestId);
        if (job.smsPollToken !== pollToken || job.status !== "phone_otp" || !job.child) return;
        if (result.status === "received") {
          if (job.smsLastSubmittedCode === result.code) {
            job.smsStatus = "error";
            job.smsError = "接码平台仍返回已提交过的验证码，已停止重复提交";
            appendJobLog(job, `[sms] ${smsClient.name} 返回了已提交过的验证码，已停止本次自动轮询。\n`);
            touch(job);
            return;
          }
          job.smsLastSubmittedCode = result.code;
          job.smsStatus = "submitting";
          job.smsError = null;
          appendJobLog(job, `[sms] 已从 ${smsClient.name} 获取短信验证码并自动提交。\n`);
          await submitJobInput(job, { action: "phone_otp", value: result.code }, { source: "sms-provider" });
          return;
        }
        job.smsStatus = "waiting_sms";
        job.smsError = null;
      } catch (error) {
        if (job.smsPollToken !== pollToken) return;
        if (error?.terminal) {
          job.smsStatus = "error";
          job.smsError = `${safeSmsProviderError(error)}，可以手动输入验证码或更换手机号`;
          touch(job);
          return;
        }
        job.smsStatus = "waiting_sms";
        job.smsError = `${safeSmsProviderError(error)}，正在自动重试`;
        touch(job);
      }
      await delay(SMS_POLL_INTERVAL_MS);
    }

    if (job.smsPollToken === pollToken && job.status === "phone_otp") {
      job.smsStatus = "error";
      job.smsError = "等待平台短信超时，可以手动输入验证码或更换手机号";
      touch(job);
    }
  } finally {
    if (job.smsPollToken === pollToken) {
      job.smsPollToken = null;
      touch(job);
    }
  }
}

function stopSmsPolling(job) {
  job.smsPollToken = null;
}

function releaseSmsNumber(job, nextStatus = "idle", errorMessage = null) {
  const requestId = job.smsOrderId;
  const smsClient = job.smsClient;
  const providerName = job.smsProviderName || smsClient?.name || "接码平台";
  stopSmsPolling(job);
  job.smsOrderId = null;
  job.smsNumber = null;
  job.smsClient = null;
  job.smsLastSubmittedCode = null;
  job.smsStatus = nextStatus;
  job.smsError = errorMessage;
  if (nextStatus === "idle") {
    job.smsProviderId = null;
    job.smsProviderName = null;
    job.smsServiceLabel = null;
  }
  if (requestId && smsClient) {
    void smsClient.release(requestId).catch(() => {
      appendJobLog(job, `[sms] ${providerName} 号码释放请求失败，请在平台控制台检查订单。\n`);
    });
  }
  if (job.outputPath) void saveJobMetadata(job).catch(() => {});
}

function completeSmsNumber(job) {
  const requestId = job.smsOrderId;
  const smsClient = job.smsClient;
  if (!requestId || !smsClient) return;
  stopSmsPolling(job);
  job.smsOrderId = null;
  job.smsClient = null;
  job.smsLastSubmittedCode = null;
  job.smsStatus = "completed";
  job.smsError = null;
  appendJobLog(job, `[sms] 手机验证码已通过，正在完成 ${smsClient.name} 订单。\n`);
  if (smsClient.complete) {
    void smsClient.complete(requestId).catch((error) => {
      appendJobLog(job, `[sms] ${smsClient.name} 完成订单失败：${safeSmsProviderError(error)}\n`);
      touch(job);
    });
  }
  touch(job);
  if (job.outputPath) void saveJobMetadata(job).catch(() => {});
}

function newSmsState() {
  return {
    smsProviderId: null,
    smsProviderName: null,
    smsServiceLabel: null,
    smsOrderId: null,
    smsNumber: null,
    smsClient: null,
    smsStatus: "idle",
    smsError: null,
    smsPollToken: null,
    smsLastSubmittedCode: null,
  };
}

function restoredSmsState(metadata = {}) {
  const orderId = metadata.sms_order_id || metadata.luban_request_id;
  const number = metadata.sms_number || metadata.luban_number;
  if (!orderId || !number) return newSmsState();
  return {
    smsProviderId: metadata.sms_provider_id || "luban",
    smsProviderName: metadata.sms_provider_name || (metadata.sms_provider_id === "smsbower" ? "SMSBower" : "LubanSMS"),
    smsServiceLabel: metadata.sms_service_label || metadata.luban_service_id || null,
    smsOrderId: String(orderId),
    smsNumber: String(number),
    smsClient: null,
    smsStatus: "error",
    smsError: "服务重启后已停止自动收短信，可手动输入验证码或换号",
    smsPollToken: null,
    smsLastSubmittedCode: null,
  };
}

function safeSmsProviderError(error, apiKey = "") {
  let message = String(error?.message || "接码平台请求失败");
  if (apiKey) message = message.replaceAll(apiKey, "<已隐藏密钥>");
  return message
    .replace(/apikey=[^&\s]+/gi, "apikey=<已隐藏>")
    .replace(/api_key=[^&\s]+/gi, "api_key=<已隐藏>")
    .replace(/https?:\/\/\S+/gi, "<已隐藏接口地址>")
    .replace(/[\r\n]+/g, " ")
    .slice(0, 220);
}

async function submitJobInput(job, body, options = {}) {
  if (!job.child || !isActive(job.status)) {
    throw httpError(409, "This login flow is not waiting for input");
  }
  assertOperationProxyLease(job);
  const action = String(body.action || "");
  const rawValue = String(body.value || "");
  const value = rawValue.trim();
  let inputValue = "";

  if (action === "password") {
    requireStage(job, "password");
    if (!rawValue) throw httpError(400, "密码不能为空");
    await saveStoredLoginCredentials(job.email, {
      password: rawValue,
      totpSecret: job.totpSecret,
      proxyUrl: job.proxyUrl,
    });
    job.loginMode = "password";
    job.password = rawValue;
    job.hasPasswordCredential = true;
    markAuthorizationManual(job, "password");
    await saveJobMetadata(job);
    inputValue = rawValue;
    setStage(job, "working", "正在验证账号密码");
  } else if (action === "mfa_otp") {
    requireStage(job, "mfa_otp");
    if (!/^\d{6}$/.test(value)) throw httpError(400, "2FA 验证码必须是 6 位数字");
    inputValue = value;
    markAuthorizationManual(job, "mfa");
    setStage(job, "working", "正在验证 2FA 验证码");
  } else if (action === "totp_setup_otp") {
    requireStage(job, "totp_setup_otp");
    if (!/^\d{6}$/.test(value)) throw httpError(400, "设置 2FA 的验证码必须是 6 位数字");
    inputValue = value;
    setStage(job, "working", "正在激活新的 2FA");
  } else if (action === "email_otp") {
    requireStage(job, "email_otp");
    if (!/^\d{6}$/.test(value)) throw httpError(400, "Email code must be 6 digits");
    stopMailPolling(job);
    job.parserTail = "";
    markAuthorizationManual(job, "emailOtp");
    inputValue = value;
    setStage(job, "working", "正在验证邮箱验证码");
  } else if (action === "resend_email") {
    requireStage(job, "email_otp");
    stopMailPolling(job);
    job.parserTail = "";
    inputValue = "r";
    setStage(job, "working", "正在重新发送邮箱验证码");
  } else if (action === "phone") {
    requireStage(job, "phone");
    if (!/^\+[1-9]\d{6,14}$/.test(value)) throw httpError(400, "Phone number must use E.164 format, for example +60123456789");
    if (options.source !== "sms-provider") releaseSmsNumber(job, "idle");
    job.currentPhone = value;
    job.phoneError = null;
    inputValue = value;
    setStage(job, "working", `正在向 ${value} 发送手机验证码`);
  } else if (action === "phone_otp") {
    requireStage(job, "phone_otp");
    if (!/^\d{4,8}$/.test(value)) throw httpError(400, "Phone code must be 4 to 8 digits");
    stopSmsPolling(job);
    if (job.smsOrderId) job.smsStatus = options.source === "sms-provider" ? "submitted" : "manual_submitted";
    job.phoneError = null;
    inputValue = value;
    setStage(job, "working", "正在验证手机验证码");
  } else if (action === "resend_phone") {
    requireStage(job, "phone_otp");
    stopSmsPolling(job);
    if (job.smsOrderId) job.smsStatus = "number_acquired";
    job.phoneError = null;
    inputValue = "r";
    setStage(job, "working", job.currentPhone ? `正在向 ${job.currentPhone} 重新发送验证码` : "正在重新发送手机验证码");
  } else if (action === "change_phone") {
    requireStage(job, "phone_otp");
    const preservedPhoneError = options.preservePhoneError ? job.phoneError : null;
    releaseSmsNumber(
      job,
      options.preservePhoneError ? "error" : "idle",
      options.preservePhoneError ? preservedPhoneError : null,
    );
    job.currentPhone = null;
    job.phoneError = preservedPhoneError;
    inputValue = "p";
    setStage(
      job,
      "working",
      options.preservePhoneError ? "当前手机号不可用，正在返回换号步骤" : "正在返回手机号输入",
    );
  } else {
    throw httpError(400, "Unsupported input action");
  }

  assertOperationProxyLease(job);
  job.parserTail = "";
  job.child.stdin.write(`${inputValue}\n`);
  touch(job);
}

async function cancelJob(job, context = {}) {
  if (!context.scheduled && !shuttingDown) await overrideScheduledJob(job, "人工取消账号任务替代了原定时任务");
  if (!isActive(job.status)) return;
  if (isSecurityMode(job.runMode || job.queuedMode)) {
    stopMailPolling(job);
    job.securityCancelRequested = true;
    job.queueRunId = null;
    const child = job.child;
    if (child && child.exitCode === null && child.signalCode === null) {
      // Read the final journal only after the process has stopped writing it.
      await new Promise((resolve, reject) => {
        let killTimer, failureTimer;
        const stopped = () => { clearTimeout(killTimer); clearTimeout(failureTimer); resolve(); };
        child.once("close", stopped);
        killTimer = setTimeout(() => child.kill("SIGKILL"), 3_000);
        failureTimer = setTimeout(() => { child.off("close", stopped); reject(new Error("安全操作进程尚未退出，已保留状态等待核实")); }, 8_000);
        child.kill("SIGTERM");
      });
    }
    await finishSecurityOperation(job, { canceled: true, signal: child ? "SIGTERM" : undefined });
    scheduleQueuedJobs();
    return;
  }
  if (job.runMode === "totp_setup" || job.queuedMode === "totp_setup") {
    stopMailPolling(job);
    job.runId = crypto.randomUUID();
    job.child?.kill("SIGTERM");
    job.child = null;
    await finishTotpSetup(job, 1, "SIGTERM");
    if (!job.totpKnownEnabled) {
      job.prompt = job.resultSaved
        ? "授权文件仍然可用，2FA 设置已取消"
        : "2FA 设置已取消，原登录检查点仍可继续";
      job.totpSetupError = "用户取消了本次 2FA 设置";
      touch(job);
      await saveJobMetadata(job);
    }
    scheduleQueuedJobs();
    return;
  }
  if (job.runMode === "password_add" || job.queuedMode === "password_add") {
    stopMailPolling(job);
    job.runId = crypto.randomUUID();
    job.child?.kill("SIGTERM");
    job.child = null;
    await finishPasswordAdd(job, 1, "SIGTERM");
    if (job.passwordAddError) {
      job.prompt = "原授权文件仍可使用，添加密码已取消";
      job.passwordAddError = "用户取消了本次添加密码";
      touch(job);
      await saveJobMetadata(job);
    }
    scheduleQueuedJobs();
    return;
  }
  stopMailPolling(job);
  releaseSmsNumber(job, "idle");
  job.status = "canceled";
  job.prompt = "流程已取消";
  job.child?.kill("SIGTERM");
  job.child = null;
  touch(job);
  void saveJobMetadata(job).catch(() => {});
  scheduleQueuedJobs();
}

async function cancelAllJobs() {
  const activeJobs = [...jobs.values()].filter((job) => isActive(job.status));
  if (!activeJobs.length) return 0;
  queueSchedulingPaused = true;
  try {
    await Promise.all(activeJobs.map((job) => withEmailJobLock(job.email, () => cancelJob(job))));
    await Promise.all(activeJobs.map((job) => saveJobMetadata(job)));
  } finally {
    queueSchedulingPaused = false;
  }
  scheduleQueuedJobs();
  return activeJobs.length;
}

async function downloadResult(res, job) {
  if (!job.resultSaved || !(await fileExists(job.outputPath))) {
    sendJson(res, 409, { error: "The sub2api import file is not ready" });
    return;
  }
  const safeEmail = job.email.replace(/[^a-zA-Z0-9@._+-]/g, "_");
  const data = await fs.readFile(job.outputPath);
  res.writeHead(200, {
    "content-type": "application/json; charset=utf-8",
    "content-disposition": `attachment; filename="${safeEmail}-sub2api-import-oauth-${downloadTimestamp()}.json"`,
    "content-length": data.length,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  res.end(data);
}

async function downloadBatchResult(res, ids) {
  if (!Array.isArray(ids) || ids.length === 0) {
    throw httpError(400, "请至少选择一个已完成任务");
  }
  const uniqueIds = [...new Set(ids.map((id) => String(id)))];
  if (uniqueIds.length > MAX_BATCH_JOBS) throw httpError(400, `一次最多下载 ${MAX_BATCH_JOBS} 个账号`);

  const selected = uniqueIds.map((id) => jobs.get(id));
  if (selected.some((job) => !job)) throw httpError(404, "部分任务不存在，请刷新页面后重试");
  const downloadable = selected.filter((job) => job.resultSaved);
  if (downloadable.length === 0) throw httpError(409, "选中的任务里没有已完成的导入文件");

  const accounts = [];
  const proxies = [];
  for (const job of downloadable) {
    if (!(await fileExists(job.outputPath))) throw httpError(409, `${job.email} 的导入文件不存在`);
    const data = JSON.parse(await fs.readFile(job.outputPath, "utf8"));
    if (data.type !== "sub2api-data" || !Array.isArray(data.accounts)) {
      throw httpError(409, `${job.email} 的导入文件格式不正确`);
    }
    accounts.push(...data.accounts);
    if (Array.isArray(data.proxies)) proxies.push(...data.proxies);
  }

  const payload = Buffer.from(`${JSON.stringify({
    type: "sub2api-data",
    version: 1,
    exported_at: new Date().toISOString(),
    proxies: uniqueByJson(proxies),
    accounts,
  }, null, 2)}\n`);
  res.writeHead(200, {
    "content-type": "application/json; charset=utf-8",
    "content-disposition": `attachment; filename="sub2api-import-oauth-${accounts.length}-accounts-${downloadTimestamp()}.json"`,
    "content-length": payload.length,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  res.end(payload);
}

async function buildSub2ApiUploadPayload(downloadable) {
  const accounts = [];
  const proxies = [];
  for (const job of downloadable) {
    if (!(await fileExists(job.outputPath))) throw httpError(409, `${job.email} 的导入文件不存在`);
    const data = JSON.parse(await fs.readFile(job.outputPath, "utf8"));
    if (data.type !== "sub2api-data" || !Array.isArray(data.accounts)) {
      throw httpError(409, `${job.email} 的导入文件格式不正确`);
    }
    accounts.push(...data.accounts);
    if (Array.isArray(data.proxies)) proxies.push(...data.proxies);
  }
  return {
    type: "sub2api-data",
    version: 1,
    exported_at: new Date().toISOString(),
    proxies: uniqueByJson(proxies),
    accounts,
  };
}

function normalizeSub2ApiConfig(value) {
  const config = value && typeof value === "object" ? value : {};
  const baseUrl = String(config.baseUrl || "").trim().replace(/\/+$/, "");
  const adminApiKey = String(config.adminApiKey || "").trim();
  if (!baseUrl) throw httpError(400, "请填写 Sub2API 后端地址");
  let parsed;
  try {
    parsed = new URL(baseUrl);
  } catch {
    throw httpError(400, "Sub2API 后端地址格式不正确");
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw httpError(400, "Sub2API 后端地址必须使用 HTTP 或 HTTPS");
  }
  if (!adminApiKey || adminApiKey.length > 512 || /[\r\n]/.test(adminApiKey)) {
    throw httpError(400, "请填写有效的 Sub2API 管理员 API Key");
  }
  const rawGroupIds = Array.isArray(config.groupIds)
    ? config.groupIds
    : String(config.groupId || "").trim() ? [config.groupId] : [];
  const groupIds = [...new Set(rawGroupIds.map((value) => String(value).trim()).filter(Boolean))].map((value) => {
    if (!/^\d+$/.test(value) || Number(value) <= 0 || Number(value) > Number.MAX_SAFE_INTEGER) {
      throw httpError(400, "目标号池 ID 无效");
    }
    return Number(value);
  });
  const proxyText = String(config.proxyId || "").trim();
  if (proxyText && (!/^\d+$/.test(proxyText) || Number(proxyText) <= 0 || Number(proxyText) > Number.MAX_SAFE_INTEGER)) {
    throw httpError(400, "代理 ID 无效");
  }
  const proxyId = proxyText ? Number(proxyText) : 0;
  const concurrency = parseOptionalSub2ApiInteger(config.concurrency, "并发数", 0, 10000);
  const loadFactor = parseOptionalSub2ApiInteger(config.loadFactor, "负载因子", 0, 10000);
  const priority = parseOptionalSub2ApiInteger(config.priority, "优先级", 0, 10000);
  const modelWhitelist = parseSub2ApiModelWhitelist(config.modelWhitelist);
  const codexFingerprintMode = String(config.codexFingerprintMode || "session").trim().toLowerCase();
  if (!["off", "device", "session", "full"].includes(codexFingerprintMode)) {
    throw httpError(400, "Codex 指纹收敛模式无效");
  }
  return { baseUrl, adminApiKey, groupIds, proxyId, concurrency, loadFactor, priority, modelWhitelist, codexFingerprintMode };
}

function readDurationEnv(name, fallback, minimum) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const value = Number(raw);
  return Number.isFinite(value) && value >= minimum ? value : fallback;
}

function parseOptionalSub2ApiInteger(value, label, min, max) {
  const text = String(value ?? "").trim();
  if (!text) return null;
  if (!/^\d+$/.test(text)) throw httpError(400, `${label}必须是数字`);
  const parsed = Number(text);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) throw httpError(400, `${label}范围必须是 ${min} 到 ${max}`);
  return parsed;
}

function parseSub2ApiModelWhitelist(value) {
  const models = String(value || "")
    .split(/[\r\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
  if (models.length > 200) throw httpError(400, "支持模型最多填写 200 个");
  if (models.some((model) => model.length > 200 || /[\r\n]/.test(model))) throw httpError(400, "支持模型名称格式不正确");
  return [...new Set(models)];
}

function requestSub2Api(config, endpoint, options = {}) {
  const requestPromise = performSub2ApiRequest(config, endpoint, options);
  sub2ApiRequestPromises.add(requestPromise);
  void requestPromise.then(
    () => sub2ApiRequestPromises.delete(requestPromise),
    () => sub2ApiRequestPromises.delete(requestPromise),
  );
  return requestPromise;
}

async function performSub2ApiRequest(config, endpoint, options = {}) {
  const controller = new AbortController();
  sub2ApiRequestControllers.add(controller);
  const timeout = setTimeout(() => controller.abort(), 120_000);
  try {
    const response = await fetch(`${config.baseUrl}${endpoint}`, {
      ...options,
      redirect: "manual",
      signal: controller.signal,
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        "x-api-key": config.adminApiKey,
        ...(options.headers || {}),
      },
    });
    const text = await response.text();
    let payload = null;
    try {
      payload = text ? JSON.parse(text) : null;
    } catch {
      payload = null;
    }
    if (!response.ok) {
      const message = sub2ApiResponseMessage(payload, text).slice(0, 500);
      const error = httpError(502, `Sub2API 返回 HTTP ${response.status}${message ? `：${message}` : ""}`);
      error.remoteStatus = response.status;
      throw error;
    }
    return payload;
  } catch (error) {
    if (error?.status) throw error;
    if (error?.name === "AbortError") {
      throw httpError(shuttingDown ? 503 : 504, shuttingDown ? "Sub2API 请求已因服务关闭而取消" : "Sub2API 请求超时");
    }
    throw httpError(502, `无法连接 Sub2API 后端：${error.message}`);
  } finally {
    clearTimeout(timeout);
    sub2ApiRequestControllers.delete(controller);
  }
}

function sub2ApiResponseMessage(payload, text) {
  const message = payload?.error?.message || payload?.message || payload?.error || "";
  return typeof message === "string" && message.trim()
    ? message.trim()
    : extractResponseMessage(text);
}

async function loadSub2ApiMonitorConfiguration() {
  try {
    const saved = serverDatabase.get("runtime", "sub2api-monitor");
    if (!saved) return;
    const config = normalizeSub2ApiConfig(saved.config);
    sub2ApiMonitorConfig = { ...config, enabled: saved.enabled === true };
    sub2ApiMonitorState.lastCheckAt = saved.state?.lastCheckAt || null;
    sub2ApiMonitorState.lastError = saved.state?.lastError || null;
    sub2ApiMonitorState.lastResult = saved.state?.lastResult && typeof saved.state.lastResult === "object"
      ? saved.state.lastResult
      : null;
  } catch (error) {
    if (error?.code !== "ENOENT") {
      console.warn(`[warn] Sub2API 号池监控配置无法读取：${String(error?.message || error).slice(0, 180)}`);
    }
    sub2ApiMonitorConfig = null;
  }
}

async function persistSub2ApiMonitorConfiguration() {
  if (!sub2ApiMonitorConfig) {
    serverDatabase.remove("runtime", "sub2api-monitor");
    await fs.rm(SUB2API_MONITOR_PATH, { force: true });
    return;
  }
  const payload = {
    version: 1,
    enabled: Boolean(sub2ApiMonitorConfig.enabled),
    config: {
      baseUrl: sub2ApiMonitorConfig.baseUrl,
      adminApiKey: sub2ApiMonitorConfig.adminApiKey,
      groupIds: sub2ApiMonitorConfig.groupIds,
      proxyId: sub2ApiMonitorConfig.proxyId,
      concurrency: sub2ApiMonitorConfig.concurrency,
      loadFactor: sub2ApiMonitorConfig.loadFactor,
      priority: sub2ApiMonitorConfig.priority,
      modelWhitelist: sub2ApiMonitorConfig.modelWhitelist,
      codexFingerprintMode: sub2ApiMonitorConfig.codexFingerprintMode,
    },
    state: {
      lastCheckAt: sub2ApiMonitorState.lastCheckAt,
      lastError: sub2ApiMonitorState.lastError,
      lastResult: sub2ApiMonitorState.lastResult,
    },
    updatedAt: new Date().toISOString(),
  };
  serverDatabase.put("runtime", "sub2api-monitor", payload);
  const tempPath = `${SUB2API_MONITOR_PATH}.${process.pid}.${crypto.randomUUID()}.tmp`;
  await fs.writeFile(tempPath, `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600 });
  await fs.rename(tempPath, SUB2API_MONITOR_PATH);
}

function publicSub2ApiMonitorState() {
  return {
    configured: Boolean(sub2ApiMonitorConfig?.baseUrl && sub2ApiMonitorConfig?.adminApiKey),
    enabled: Boolean(sub2ApiMonitorConfig?.enabled),
    baseUrl: sub2ApiMonitorConfig?.baseUrl || null,
    groupIds: sub2ApiMonitorConfig?.groupIds || [],
    intervalMinutes: Math.max(1, Math.round(SUB2API_MONITOR_INTERVAL_MS / 60_000)),
    cooldownMinutes: Math.max(1, Math.round(SUB2API_AUTO_REPAIR_COOLDOWN_MS / 60_000)),
    running: sub2ApiMonitorState.running,
    lastCheckAt: sub2ApiMonitorState.lastCheckAt,
    nextCheckAt: sub2ApiMonitorState.nextCheckAt,
    lastError: sub2ApiMonitorState.lastError,
    lastResult: sub2ApiMonitorState.lastResult,
  };
}

function scheduleSub2ApiMonitor() {
  if (sub2ApiMonitorTimer) {
    clearInterval(sub2ApiMonitorTimer);
    sub2ApiMonitorTimer = null;
  }
  sub2ApiMonitorState.nextCheckAt = null;
  if (!sub2ApiMonitorConfig?.enabled || shuttingDown || runtimeDraining) return;
  const interval = Number.isFinite(SUB2API_MONITOR_INTERVAL_MS) && SUB2API_MONITOR_INTERVAL_MS >= 1_000
    ? SUB2API_MONITOR_INTERVAL_MS
    : 5 * 60_000;
  sub2ApiMonitorState.nextCheckAt = new Date(Date.now() + interval).toISOString();
  sub2ApiMonitorTimer = setInterval(() => {
    sub2ApiMonitorState.nextCheckAt = new Date(Date.now() + interval).toISOString();
    void runSub2ApiMonitor("scheduled").catch((error) => {
      console.warn(`[warn] Sub2API 号池巡检失败：${String(error?.message || error).slice(0, 180)}`);
    });
  }, interval);
  sub2ApiMonitorTimer.unref?.();
}

async function runSub2ApiMonitor(trigger = "scheduled") {
  if (!sub2ApiMonitorConfig?.enabled) throw httpError(409, "Sub2API 号池监控未启用");
  if (sub2ApiMonitorPromise) return sub2ApiMonitorPromise;
  const config = { ...sub2ApiMonitorConfig, groupIds: [...sub2ApiMonitorConfig.groupIds] };
  sub2ApiMonitorPromise = (async () => {
    sub2ApiMonitorState.running = true;
    sub2ApiMonitorState.lastError = null;
    const summary = {
      trigger,
      checked: 0,
      matched: 0,
      started: 0,
      updated: 0,
      missingTask: 0,
      ineligible: 0,
      blocked: 0,
      busy: 0,
      cooldown: 0,
      outsideGroups: 0,
      missingEmail: 0,
    };
    try {
      await syncCompletedOutputs(true);
      await retryPendingSub2ApiUploads(config, summary);
      if (shuttingDown) throw httpError(503, "服务正在关闭，已停止号池巡检");
      const remoteAccounts = await listSub2ApiErrorAccounts(config);
      summary.checked = remoteAccounts.length;
      const grouped = new Map();
      for (const account of remoteAccounts) {
        if (!isSub2ApiAccountInMonitoredGroups(account, config.groupIds)) {
          summary.outsideGroups += 1;
          continue;
        }
        const email = sub2ApiAccountEmail(account);
        if (!email) {
          summary.missingEmail += 1;
          continue;
        }
        if (!grouped.has(email)) grouped.set(email, []);
        grouped.get(email).push(account);
      }

      for (const [email, accounts] of grouped) {
        await withEmailJobLock(email, async () => {
          const job = findJobByEmail(email);
          if (!job) {
            summary.missingTask += accounts.length;
            return;
          }
          summary.matched += accounts.length;
          if (job.autoRepairBlocked) {
            summary.blocked += accounts.length;
            return;
          }
          if (isActive(job.status) || job.autoRepairOperation) {
            summary.busy += accounts.length;
            return;
          }
          if (isAutoRepairCoolingDown(job)) {
            summary.cooldown += accounts.length;
            return;
          }
          await reloadMissingJobCredentials(job);
          const eligibility = getAutoRepairEligibility(job);
          if (!eligibility.eligible) {
            summary.ineligible += accounts.length;
            return;
          }

          const operation = createSub2ApiAutoRepairOperation(config, accounts);
          await forceReloginJob(job, {}, { autoRepair: operation });
          appendJobLog(job, `[monitor] Sub2API 号池发现 ${accounts.length} 条异常记录，已自动加入重新登录并授权队列。\n`);
          await saveJobMetadata(job);
          summary.started += accounts.length;
        });
      }

      sub2ApiMonitorState.lastCheckAt = new Date().toISOString();
      sub2ApiMonitorState.lastResult = summary;
      await persistSub2ApiMonitorConfiguration();
      return summary;
    } catch (error) {
      sub2ApiMonitorState.lastCheckAt = new Date().toISOString();
      sub2ApiMonitorState.lastError = String(error?.message || error).slice(0, 500);
      await persistSub2ApiMonitorConfiguration().catch(() => {});
      throw error;
    } finally {
      sub2ApiMonitorState.running = false;
    }
  })().finally(() => {
    sub2ApiMonitorPromise = null;
  });
  return sub2ApiMonitorPromise;
}

function createSub2ApiAutoRepairOperation(config, accounts) {
  const validAccounts = accounts.filter((account) => {
    const id = Number(account?.id);
    return Number.isSafeInteger(id) && id > 0;
  });
  return {
    accountIds: validAccounts.map((account) => Number(account.id)),
    accounts: validAccounts,
    backend: monitorBackendIdentity(config),
    config,
    startedAt: new Date().toISOString(),
  };
}

async function retryPendingSub2ApiUploads(config, summary) {
  const backend = monitorBackendIdentity(config);
  for (const candidate of listUniqueJobs()) {
    await withEmailJobLock(candidate.email, async () => {
      const job = findJobByEmail(candidate.email);
      const pendingIds = [...new Set(job?.autoRepairPendingAccountIds || [])]
        .map(Number)
        .filter((id) => Number.isSafeInteger(id) && id > 0);
      if (
        !job
        || job.loginDeferred
        || accountLifecycle.public(job.email).resting
        || accountLifecycle.public(job.email).retired
        || pendingIds.length === 0
        || job.autoRepairPendingBackend !== backend
        || !job.resultSaved
        || job.status !== "completed"
        || job.autoRepairOperation
        || isAutoRepairCoolingDown(job)
      ) return;

      const accounts = [];
      const missingIds = [];
      try {
        for (const accountId of pendingIds) {
          const account = await getSub2ApiAccount(config, accountId);
          if (account) accounts.push(account);
          else missingIds.push(accountId);
        }
      } catch (error) {
        job.autoRepairLastAttemptAt = new Date().toISOString();
        job.autoRepairLastError = String(error?.message || error).slice(0, 500);
        appendJobLog(job, `[monitor] 读取待重传的 Sub2API 账号失败：${job.autoRepairLastError}。\n`);
        touch(job);
        await saveJobMetadata(job);
        return;
      }

      if (missingIds.length) {
        const missing = new Set(missingIds);
        job.autoRepairPendingAccountIds = pendingIds.filter((id) => !missing.has(id));
        appendJobLog(job, `[monitor] ${missingIds.length} 条待重传账号已从 Sub2API 删除，已停止重试。\n`);
      }
      if (!accounts.length) {
        job.autoRepairPendingBackend = null;
        job.autoRepairLastError = null;
        touch(job);
        await saveJobMetadata(job);
        return;
      }

      job.autoRepairOperation = createSub2ApiAutoRepairOperation(config, accounts);
      job.autoRepairLastAttemptAt = new Date().toISOString();
      appendJobLog(job, `[monitor] 正在重传 ${accounts.length} 条上次未完成的 Sub2API 更新，不重复登录。\n`);
      if (await finishSub2ApiAutoRepairSuccess(job)) summary.updated += accounts.length;
    });
  }
}

async function getSub2ApiAccount(config, accountId) {
  try {
    const payload = await requestSub2Api(config, `/api/v1/admin/accounts/${accountId}`);
    const account = payload?.data && typeof payload.data === "object" ? payload.data : payload;
    if (!account || Number(account.id) !== Number(accountId)) {
      throw new Error(`Sub2API 账号 ${accountId} 返回数据不完整`);
    }
    return account;
  } catch (error) {
    if (error?.remoteStatus === 404) return null;
    throw error;
  }
}

async function listSub2ApiErrorAccounts(config) {
  const accounts = [];
  let page = 1;
  let pages = 1;
  do {
    const query = new URLSearchParams({
      page: String(page),
      page_size: "100",
      platform: "openai",
      status: "error",
    });
    const payload = await requestSub2Api(config, `/api/v1/admin/accounts?${query}`);
    const data = payload?.data && typeof payload.data === "object" ? payload.data : payload;
    const items = Array.isArray(data?.items) ? data.items : Array.isArray(data) ? data : [];
    accounts.push(...items.filter((account) => account && String(account.platform || "openai") === "openai" && String(account.status || "error") === "error"));
    const reportedPages = Number(data?.pages);
    pages = Number.isSafeInteger(reportedPages) && reportedPages > 0
      ? reportedPages
      : items.length >= 100 ? page + 1 : page;
    page += 1;
  } while (page <= pages && page <= 1_000);
  return accounts;
}

function sub2ApiAccountEmail(account) {
  const direct = [account?.credentials?.email, account?.extra?.email]
    .map((value) => String(value || "").trim().toLowerCase())
    .find(isEmail);
  if (direct) return direct;
  const match = String(account?.name || "").toLowerCase().match(/[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}/i);
  return match && isEmail(match[0]) ? match[0] : null;
}

function isSub2ApiAccountInMonitoredGroups(account, groupIds) {
  if (!groupIds.length) return true;
  const accountGroupIds = [
    ...(Array.isArray(account?.group_ids) ? account.group_ids : []),
    ...(Array.isArray(account?.account_groups) ? account.account_groups.map((item) => item?.group_id) : []),
  ].map(Number).filter(Number.isSafeInteger);
  return groupIds.some((id) => accountGroupIds.includes(Number(id)));
}

function monitorBackendIdentity(config) {
  return crypto.createHash("sha256").update(String(config?.baseUrl || "")).digest("hex").slice(0, 24);
}

function isAutoRepairCoolingDown(job) {
  if (!job.autoRepairLastAttemptAt || !Number.isFinite(SUB2API_AUTO_REPAIR_COOLDOWN_MS) || SUB2API_AUTO_REPAIR_COOLDOWN_MS <= 0) return false;
  return Date.now() - new Date(job.autoRepairLastAttemptAt).getTime() < SUB2API_AUTO_REPAIR_COOLDOWN_MS;
}

function getAutoRepairEligibility(job) {
  if (job.loginDeferred) return { eligible: false, reason: "账号仅记录，等待手动上号或定时任务，不会自动登录" };
  if (job.emailLoginAutoPaused) return { eligible: false, reason: "邮箱验证未完成，自动重新登录已暂停；手动重新登录或更新资料可恢复" };
  if (scheduledTaskStore.owner(job.email)) return { eligible: false, reason: "账号由定时任务管理，计划执行前暂停自动重新登录" };
  if (accountLifecycle.public(job.email).retired) return { eligible: false, reason: "账号已移入废号区，自动重新登录已暂停" };
  if (job.securityAutoLoginPaused || accountLifecycle.public(job.email).resting) return { eligible: false, reason: "账号已静置或退出设备，手动成功登录后恢复自动登录" };
  if (securityOperations.blockingRotation(job)) return { eligible: false, reason: "上次更换 2FA 结果尚未核实，自动登录已暂停" };
  if (job.autoRepairBlocked) return { eligible: false, reason: job.autoRepairBlockedReason || "自动登录已暂停，请手动重试" };
  if (!job.lastAuthAutomated) return { eligible: false, reason: job.lastAuthAutomationReason || "上次授权不是全自动完成" };
  const requirements = job.lastAuthRequirements || {};
  if (requirements.password && !job.password) return { eligible: false, reason: "已保存的密码无法读取" };
  if (requirements.emailOtp && !job.mailApiUrl) return { eligible: false, reason: "缺少可自动收取邮箱验证码的 API" };
  if (requirements.mfa && !job.totpSecret) return { eligible: false, reason: "已保存的 2FA 密钥无法读取" };
  if (!job.password && !job.mailApiUrl) return { eligible: false, reason: "缺少可自动登录的密码或邮件收码 API" };
  if (job.hasTotpCredential && !job.totpSecret) return { eligible: false, reason: "2FA 密钥在当前系统上无法恢复" };
  return { eligible: true, reason: "上次完整登录全自动完成，所需资料仍可用" };
}

function finishSub2ApiAutoRepairSuccess(job) {
  const operationPromise = performSub2ApiAutoRepairSuccess(job);
  sub2ApiAutoRepairPromises.add(operationPromise);
  void operationPromise.then(
    () => sub2ApiAutoRepairPromises.delete(operationPromise),
    () => sub2ApiAutoRepairPromises.delete(operationPromise),
  );
  return operationPromise;
}

async function performSub2ApiAutoRepairSuccess(job) {
  const operation = job.autoRepairOperation;
  if (!operation) return false;
  job.autoRepairPendingAccountIds = [...new Set(operation.accountIds)];
  job.autoRepairPendingBackend = operation.backend;
  try {
    const payload = await buildSub2ApiUploadPayload([job]);
    const localAccount = payload.accounts.find((account) => sub2ApiAccountEmail(account) === job.email.toLowerCase())
      || payload.accounts[0];
    if (!localAccount?.credentials) throw new Error("新授权文件中没有可更新的账号凭据");

    const pendingIds = new Set(job.autoRepairPendingAccountIds);
    for (const remoteAccount of operation.accounts) {
      const accountId = Number(remoteAccount.id);
      if (!Number.isSafeInteger(accountId) || accountId <= 0) continue;
      const credentials = {
        ...(remoteAccount.credentials && typeof remoteAccount.credentials === "object" ? remoteAccount.credentials : {}),
        ...localAccount.credentials,
      };
      const extra = {
        ...(remoteAccount.extra && typeof remoteAccount.extra === "object" ? remoteAccount.extra : {}),
        codex_fingerprint_mode: operation.config.codexFingerprintMode,
      };
      await requestSub2Api(operation.config, `/api/v1/admin/accounts/${accountId}`, {
        method: "PUT",
        body: JSON.stringify({ credentials, extra }),
      });
      await requestSub2Api(operation.config, `/api/v1/admin/accounts/${accountId}/clear-error`, {
        method: "POST",
        body: "{}",
      });
      await requestSub2Api(operation.config, `/api/v1/admin/accounts/${accountId}/schedulable`, {
        method: "POST",
        body: JSON.stringify({ schedulable: true }),
      });
      pendingIds.delete(accountId);
      job.autoRepairPendingAccountIds = [...pendingIds];
    }

    job.autoRepairLastSuccessAt = new Date().toISOString();
    job.autoRepairLastError = null;
    job.autoRepairPendingAccountIds = [];
    job.autoRepairPendingBackend = null;
    job.autoRepairOperation = null;
    clearAutoRepairBlock(job);
    appendJobLog(job, `[monitor] 已用新授权覆盖更新 Sub2API 中的 ${operation.accountIds.length} 条账号记录。\n`);
    touch(job);
    await saveJobMetadata(job);
    return true;
  } catch (error) {
    job.autoRepairLastAttemptAt = new Date().toISOString();
    job.autoRepairLastError = String(error?.message || error).slice(0, 500);
    job.autoRepairOperation = null;
    appendJobLog(job, `[monitor] 新授权已生成，但更新 Sub2API 失败：${job.autoRepairLastError}。下次巡检会优先重传，不会重复登录。\n`);
    touch(job);
    await saveJobMetadata(job);
    return false;
  }
}

async function finishSub2ApiAutoRepairFailure(job) {
  if (!job.autoRepairOperation) return;
  const operation = job.autoRepairOperation;
  job.autoRepairOperation = null;
  job.autoRepairLastAttemptAt = new Date().toISOString();
  job.autoRepairLastError = job.autoRepairBlockedReason || job.lastError || "自动重新登录并授权未完成";
  appendJobLog(job, "[monitor] 本次自动授权未完成，已暂停后续自动登录，请检查后手动重试。\n");
  if (!job.autoRepairBlocked) {
    job.autoRepairPendingAccountIds = [];
    job.autoRepairPendingBackend = operation.backend;
  }
  touch(job);
  await saveJobMetadata(job);
}

async function exportSourceAccounts(res, ids) {
  const selected = resolveSelectedJobs(ids);
  const lines = [];
  for (const job of selected) {
    let password = job.password || "";
    let totpSecret = job.totpSecret || "";
    if ((!password && job.hasPasswordCredential) || (!totpSecret && job.hasTotpCredential)) {
      const storedCredentials = await loadStoredLoginCredentials(job.email);
      password ||= storedCredentials.password;
      totpSecret ||= storedCredentials.totpSecret;
    }
    if ((job.loginMode === "password" || job.hasPasswordCredential) && !password) {
      throw httpError(409, `${job.email} 的密码未能从服务器数据库读取，请重新导入该账号资料`);
    }
    if (job.hasTotpCredential && !totpSecret) {
      throw httpError(409, `${job.email} 的 2FA 密钥未能从服务器数据库读取，请重新导入该账号资料`);
    }
    if (password) {
      const parts = [job.email, password];
      if (job.mailRequestBody) parts.push(job.mailRequestBody);
      else if (job.mailApiUrl) parts.push(job.mailApiUrl);
      if (totpSecret) parts.push(totpSecret);
      lines.push(parts.join("----"));
      continue;
    }
    if (job.mailRequestBody) {
      lines.push(totpSecret
        ? `${job.email}----${job.mailRequestBody}----${totpSecret}`
        : `${job.email}----${job.mailRequestBody}`);
      continue;
    }
    if (job.mailApiUrl) {
      lines.push(totpSecret
        ? `${job.email}----${job.mailApiUrl}----${totpSecret}`
        : `${job.email}----${job.mailApiUrl}`);
      continue;
    }
    if (job.loginMode === "manual") {
      throw httpError(409, `${job.email} 是旧版本任务，原始登录资料未保存，请重新导入该账号资料后再导出`);
    }
    lines.push(totpSecret ? `${job.email}--------${totpSecret}` : job.email);
  }
  const payload = Buffer.from(`\uFEFF${lines.join("\n")}\n`, "utf8");
  res.writeHead(200, {
    "content-type": "text/plain; charset=utf-8",
    "content-disposition": `attachment; filename="chatgpt-account-source-${lines.length}-accounts-${downloadTimestamp()}.txt"`,
    "content-length": payload.length,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  res.end(payload);
}

function proxyChangeBlockedReason(job) {
  if (job.deleted || jobs.get(job.id) !== job) return "账号已删除，请刷新列表";
  if (scheduledTaskStore.owner(job.email)) return "账号有未完成的定时任务，请先取消计划再更换代理";
  if ([...jobs.values()].some((other) => other.email.toLowerCase() === job.email.toLowerCase()
    && (isActive(other.status) || other.child || other.autoRepairOperation))) return "账号正在执行任务，请结束后再更换代理";
  if (securityOperations.blockingRotation(job)) return "账号安全操作结果尚未确认，请先处理后再更换代理";
  if (dynamicProxies.binding(job.email)) return "账号已绑定动态代理，请在动态代理配置中管理";
  if (crsIntegration.status().items.some((item) => item.jobId === job.id && ["pending", "running", "unknown"].includes(item.status))) return "账号有未完成的 CRS 推送，请确认结果后再更换代理";
  return "";
}

function publicJob(job) {
  const autoRepair = getAutoRepairEligibility(job);
  return {
    id: job.id,
    ...accountLifecycle.public(job.email),
    loginDeferred: Boolean(job.loginDeferred),
    loginFlow: job.loginFlow === "legacy" ? "legacy" : "codex",
    loginAutoRetryCount: job.loginAutoRetryCount || 0,
    loginAutoRetryLimit: 0,
    scheduleItemId: scheduledTaskStore.owner(job.email)?.item.id || null,
    scheduleId: scheduledTaskStore.owner(job.email)?.schedule.id || null,
    emailLoginAttempt: job.emailLoginAttempt || 0,
    emailLoginReason: job.emailLoginReason || null,
    emailLoginAutoPaused: Boolean(job.emailLoginAutoPaused),
    email: job.email,
    status: job.status,
    prompt: job.status === "queued"
      ? `排队中，前方还有 ${Math.max(0, getQueuePosition(job) - 1)} 条任务`
      : job.prompt,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt,
    lastOperationAt: job.lastOperationAt || job.createdAt,
    lastOperationType: job.lastOperationType || "initial_authorization",
    completedAt: job.completedAt,
    lastError: job.lastError,
    canDownload: Boolean(job.resultSaved),
    loginMode: job.loginMode || (job.mailApiUrl ? "email_otp" : "manual"),
    hasTotpKey: Boolean(job.totpSecret || job.hasTotpCredential),
    autoEmailOtp: Boolean(job.mailApiUrl),
    mailStatus: job.mailStatus,
    mailApiError: job.mailApiError,
    currentPhone: job.currentPhone,
    phoneError: job.phoneError,
    totpSetupSecret: job.status === "totp_setup_otp" ? job.totpSetupSecret : null,
    totpSetupUri: job.status === "totp_setup_otp" ? job.totpSetupUri : null,
    totpSetupError: job.totpSetupError || null,
    passwordAddError: job.passwordAddError || null,
    passwordAddedAt: job.passwordAddedAt || null,
    securityOperation: publicSecurityOperation(securityOperations.latest(job)),
    securityAutoLoginPaused: Boolean(job.securityAutoLoginPaused),
    canRotateTotp: canRunAccountSecurity(job, "rotate-totp"),
    canLogoutAll: canRunAccountSecurity(job, "logout-all"),
    canRotateTotpLogoutAll: canRunAccountSecurity(job, "rotate-totp-logout-all"),
    smsProviderId: job.smsProviderId,
    smsProviderName: job.smsProviderName,
    smsServiceLabel: job.smsServiceLabel,
    smsStatus: job.smsStatus,
    smsError: job.smsError,
    securityCheckRequired: Boolean(job.securityCheckRequired),
    canRetry: ["failed", "canceled", "reauth_required", "resume_available"].includes(job.status) || Boolean(job.loginDeferred && job.status === "ready"),
    canResume: job.status === "resume_available",
    canRegenerate: job.status === "completed" && job.resultSaved,
    canForceRelogin: canForceRelogin(job),
    canSetupTotp: canSetupTotp(job),
    canAddPassword: canAddPassword(job),
    restartRequired: job.restartRequired,
    canChangeProxy: !proxyChangeBlockedReason(job),
    proxyChangeBlockedReason: proxyChangeBlockedReason(job),
    proxyConfigured: Boolean(job.proxyUrl),
    proxyEndpoint: publicProxyEndpoint(job.proxyUrl),
    autoRepairEligible: autoRepair.eligible,
    autoRepairEligibilityReason: autoRepair.reason,
    autoRepairBlocked: Boolean(job.autoRepairBlocked),
    autoRepairBlockedReason: job.autoRepairBlockedReason || null,
    autoRepairLastAttemptAt: job.autoRepairLastAttemptAt || null,
    autoRepairLastSuccessAt: job.autoRepairLastSuccessAt || null,
    autoRepairLastError: job.autoRepairLastError || null,
    attempt: job.attempt,
    queuePosition: job.status === "queued" ? getQueuePosition(job) : 0,
  };
}

function publicSelectionJob(job) {
  return {
    id: job.id,
    ...accountLifecycle.public(job.email),
    loginDeferred: Boolean(job.loginDeferred),
    loginFlow: job.loginFlow === "legacy" ? "legacy" : "codex",
    email: job.email,
    status: job.status,
    canDownload: Boolean(job.resultSaved),
    canRetry: ["failed", "canceled", "reauth_required", "resume_available"].includes(job.status) || Boolean(job.loginDeferred && job.status === "ready"),
    canRegenerate: job.status === "completed" && job.resultSaved,
    canForceRelogin: canForceRelogin(job),
    canSetupTotp: canSetupTotp(job),
    canAddPassword: canAddPassword(job),
    canRotateTotp: canRunAccountSecurity(job, "rotate-totp"),
    canLogoutAll: canRunAccountSecurity(job, "logout-all"),
    canRotateTotpLogoutAll: canRunAccountSecurity(job, "rotate-totp-logout-all"),
    proxyConfigured: Boolean(job.proxyUrl),
    proxyEndpoint: publicProxyEndpoint(job.proxyUrl),
  };
}

function canForceRelogin(job) {
  return ["ready", "completed", "failed", "canceled", "reauth_required", "resume_available"].includes(job.status);
}

function canSetupTotp(job) {
  if (job.totpSecret || job.hasTotpCredential || job.totpKnownEnabled) return false;
  if (job.status === "completed" && job.resultSaved) return true;
  return Boolean(job.loginCheckpointAvailable)
    && ["phone", "phone_otp", "resume_available", "failed", "canceled", "reauth_required"].includes(job.status);
}

function canAddPassword(job) {
  if (job.password || job.hasPasswordCredential) return false;
  if (job.status === "completed" && job.resultSaved) return true;
  return Boolean(job.loginCheckpointAvailable)
    && ["phone", "phone_otp", "resume_available", "failed", "canceled", "reauth_required"].includes(job.status);
}

function setStage(job, status, prompt) {
  if (isTerminalStatus(job.status)) return;
  job.status = status;
  job.prompt = prompt;
  job.lastError = null;
  touch(job);
}

function loginRetryPending() {
  // A failed OAuth session is terminal. Only an explicit new operation may
  // start another login; bridge polling must not wait for hidden retries.
  return false;
}

function failJob(job, message) {
  if (isTerminalStatus(job.status)) return;
  stopMailPolling(job);
  releaseSmsNumber(job, "idle");
  job.status = "failed";
  job.prompt = "流程失败";
  job.lastError = message;
  if (isPermanentAccountFailure(message)) markAutoRepairBlocked(job, message);
  else if (job.runMode === "full") pauseFailedAuthorization(job);
  if (isRetiredAccountFailure(message)) accountLifecycle.retire(job.email, safeSecurityError(message, [job.password, job.totpSecret, job.proxyUrl]));
  touch(job);
  void saveJobMetadata(job).catch(() => {});
}

function beginAuthorizationAutomationAttempt(job, source, { preserveRetryBudget = false } = {}) {
  if (!preserveRetryBudget) job.loginAutoRetryCount = 0;
  job.loginRetryNotBefore = null;
  job.loginAutoRetryBlocked = false;
  if (!["crs_bridge", "login", "refresh_fallback"].includes(source)) job.crsBridgeOperationId = null;
  job.authAutomationAttempt = {
    source,
    startedAt: new Date().toISOString(),
    requirements: { password: false, emailOtp: false, mfa: false },
    automatic: { password: false, emailOtp: false, mfa: false },
    manual: { password: false, emailOtp: false, mfa: false },
  };
}

function markAuthorizationRequirement(job, field) {
  if (!job.authAutomationAttempt?.requirements || !Object.hasOwn(job.authAutomationAttempt.requirements, field)) return;
  job.authAutomationAttempt.requirements[field] = true;
}

function markAuthorizationAutomatic(job, field) {
  if (!job.authAutomationAttempt?.automatic || !Object.hasOwn(job.authAutomationAttempt.automatic, field)) return;
  job.authAutomationAttempt.automatic[field] = true;
}

function markAuthorizationManual(job, field) {
  if (!job.authAutomationAttempt?.manual || !Object.hasOwn(job.authAutomationAttempt.manual, field)) return;
  job.authAutomationAttempt.manual[field] = true;
}

function completeAuthorizationAutomationAttempt(job) {
  const attempt = job.authAutomationAttempt;
  if (!attempt) return;
  const reasons = [];
  for (const [field, label] of [["password", "密码"], ["emailOtp", "邮箱验证码"], ["mfa", "登录 2FA 验证码"]]) {
    if (attempt.manual[field]) reasons.push(`${label}由用户手动输入`);
    else if (attempt.requirements[field] && !attempt.automatic[field]) reasons.push(`${label}未记录为自动完成`);
  }
  const hasAutomaticLoginSource = attempt.requirements.password
    || attempt.requirements.emailOtp
    || Boolean(job.password || job.mailApiUrl);
  if (!hasAutomaticLoginSource) reasons.push("没有可用于下次自动登录的密码或邮件收码接口");

  job.lastAuthAutomated = reasons.length === 0;
  job.lastAuthAutomationReason = reasons.length ? reasons.join("；") : "上次完整登录未需要人工输入密码、邮箱码或登录 2FA";
  job.lastAuthAutomatedAt = new Date().toISOString();
  job.lastAuthRequirements = { ...attempt.requirements };
  job.authAutomationAttempt = null;
  appendJobLog(job, job.lastAuthAutomated
    ? "[automation] 本次完整登录已记录为可自动修复。\n"
    : `[automation] 本次完整登录不可自动修复：${job.lastAuthAutomationReason}。\n`);
}

function pauseFailedAuthorization(job) {
  if (job.autoRepairBlocked) return;
  job.autoRepairBlocked = true;
  job.autoRepairBlockedReason = "上次 Codex 授权未完成，已暂停自动登录；请检查后手动重试";
  job.autoRepairBlockedAt = new Date().toISOString();
  appendJobLog(job, "[auth-paused] 本次 Codex 授权失败，已停止自动重登并保留当前检查点。\n");
}

function clearAutoRepairBlock(job) {
  job.autoRepairBlocked = false;
  job.autoRepairBlockedReason = null;
  job.autoRepairBlockedAt = null;
}

function markAutoRepairBlocked(job, reason) {
  job.autoRepairBlocked = true;
  job.autoRepairBlockedReason = String(reason || "账号已被永久停用").slice(0, 500);
  job.autoRepairBlockedAt = new Date().toISOString();
  job.autoRepairLastError = job.autoRepairBlockedReason;
  job.autoRepairPendingAccountIds = [];
  job.autoRepairPendingBackend = null;
  job.autoRepairOperation = null;
  appendJobLog(job, "[monitor] 已确认账号被封禁、删除或永久停用，后续号池巡检将直接跳过。\n");
}

function isPermanentAccountFailure(message) {
  const text = String(message || "");
  return /(?:account|user)_(?:deactivated|deleted|suspended|disabled)|(?:your|this) account (?:has been|is) (?:deleted|deactivated|suspended|disabled)|account has been (?:deleted|deactivated|suspended|disabled)|deleted or deactivated|do not have an account because it has been deleted/i.test(text);
}

function requireStage(job, expected) {
  if (job.status !== expected) {
    throw httpError(409, `The flow is currently at ${job.status}, not ${expected}`);
  }
}

function touch(job) {
  accountHistory.finish(job);
  job.updatedAt = new Date().toISOString();
}

function recordJobOperation(job, type, at = new Date().toISOString()) {
  if (type !== "crs_bridge_login") job.crsBridgeOperationId = null;
  job.lastOperationAt = at;
  job.lastOperationType = type;
}

function sanitizeLog(text) {
  return String(text)
    .replace(/([?&](?:code|token|state|csrf|nonce|otp|login_hint|code_challenge)=)[^&\s]+/gi, "$1<redacted>")
    .replace(/(access_token|refresh_token|id_token|password|totp_secret|2fa_key)\s*[=:]\s*[^\s,}]+/gi, "$1=<redacted>");
}

function isActive(status) {
  return !isTerminalStatus(status);
}

function occupiesActiveSlot(job) {
  return isActive(job.status) && job.status !== "queued";
}

function getQueuePosition(job) {
  if (job.status !== "queued") return 0;
  return [...jobs.values()]
    .filter((item) => item.status === "queued")
    .sort((a, b) => String(a.queuedAt || a.createdAt).localeCompare(String(b.queuedAt || b.createdAt)))
    .findIndex((item) => item.id === job.id) + 1;
}

function isTerminalStatus(status) {
  return ["ready", "completed", "failed", "canceled", "reauth_required", "resume_available"].includes(status);
}

function uniqueByJson(items) {
  const seen = new Set();
  return items.filter((item) => {
    const key = JSON.stringify(item);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function listUniqueJobs() {
  const seen = new Set();
  return [...jobs.values()].sort(sortNewestFirst).filter((job) => {
    const key = job.email.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function findJobByEmail(email) {
  const key = String(email || "").toLowerCase();
  return listUniqueJobs().find((job) => job.email.toLowerCase() === key) || null;
}

async function withEmailJobLock(email, operation) {
  const key = String(email || "").trim().toLowerCase();
  const previous = emailJobLocks.get(key) || Promise.resolve();
  let release;
  const current = new Promise((resolve) => {
    release = resolve;
  });
  emailJobLocks.set(key, current);
  await previous.catch(() => {});
  try {
    return await operation();
  } finally {
    release();
    if (emailJobLocks.get(key) === current) emailJobLocks.delete(key);
  }
}

function resolveSelectedJobs(ids) {
  if (!Array.isArray(ids) || ids.length === 0) throw httpError(400, "请至少选择一条任务");
  const uniqueIds = [...new Set(ids.map((id) => String(id)))];
  if (uniqueIds.length > MAX_BATCH_JOBS) throw httpError(400, `一次最多操作 ${MAX_BATCH_JOBS} 条任务`);
  const selected = uniqueIds.map((id) => jobs.get(id));
  if (selected.some((job) => !job)) throw httpError(404, "部分任务不存在，请刷新页面后重试");
  return selected;
}

async function deleteJobsByEmail(email) {
  const matching = [...jobs.values()].filter((job) => job.email.toLowerCase() === email);
  if (matching.some((job) => isSecurityMode(job.runMode || job.queuedMode) && isActive(job.status))) {
    throw httpError(409, "账号安全操作正在执行，请先取消并核实结果后再删除账号");
  }
  for (const job of matching) await overrideScheduledJob(job, "账号已删除，定时任务停止");
  const directories = new Set();
  matching.forEach((job) => {
    job.deleted = true;
    stopMailPolling(job);
    releaseSmsNumber(job, "idle");
    job.runId = crypto.randomUUID();
    job.child?.kill("SIGTERM");
    job.child = null;
    directories.add(path.dirname(job.outputPath));
    jobs.delete(job.id);
  });
  matching.forEach((job) => { securityOperations.delete(job); serverDatabase.deleteJob(job.id); });
  accountLifecycle.remove(email);
  await Promise.allSettled(matching.map((job) => job.metadataWritePromise).filter(Boolean));
  await Promise.all([
    ...[...directories].map((directory) => fs.rm(directory, { recursive: true, force: true })),
    deleteStoredLoginCredentials(email),
  ]);
  scheduleQueuedJobs();
}

function downloadTimestamp(date = new Date()) {
  const pad = (value) => String(value).padStart(2, "0");
  return `${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}-${pad(date.getHours())}${pad(date.getMinutes())}${pad(date.getSeconds())}`;
}

async function syncCompletedOutputs(force = false) {
  if (runtimeDraining) return outputSyncPromise;
  if (!force && Date.now() - lastOutputSyncAt < 2_000) return;
  if (outputSyncPromise) return outputSyncPromise;
  outputSyncPromise = (async () => {
    lastOutputSyncAt = Date.now();
    let entries = [];
    try {
      entries = await fs.readdir(OUTPUT_ROOT, { withFileTypes: true });
    } catch {
      return;
    }
    const storedJobIds = new Set(serverDatabase.jobIds());
    await Promise.all(entries.filter((entry) => entry.isDirectory() && storedJobIds.has(entry.name)).map(async (entry) => {
      if (jobs.has(entry.name)) return;
      const outputDir = path.join(OUTPUT_ROOT, entry.name);
      const outputPath = path.join(outputDir, "sub2api-import-oauth.json");
      const checkpointPath = path.join(outputDir, LOGIN_CHECKPOINT_FILENAME);
      const totpResultPath = path.join(outputDir, TOTP_SETUP_RESULT_FILENAME);
      const passwordAddResultPath = path.join(outputDir, PASSWORD_ADD_RESULT_FILENAME);
      let metadata = {};
      try {
        metadata = serverDatabase.getJob(entry.name) || {};
      } catch {}

      try {
        const [raw, stat] = await Promise.all([fs.readFile(outputPath, "utf8"), fs.stat(outputPath)]);
        const data = JSON.parse(raw);
        if (data.type !== "sub2api-data" || !Array.isArray(data.accounts) || !data.accounts.length) throw new Error("invalid output");
        const account = data.accounts[0];
        const email = metadata.email || account?.credentials?.email || account?.extra?.email || account?.name || `restored-${entry.name}`;
        const mailApiUrl = validateMailApiUrl(metadata.mail_api_url) ? metadata.mail_api_url : null;
        let storedCredentials = await loadStoredLoginCredentials(email);
        const completedAt = stat.mtime.toISOString();
        const updatedAt = metadata.updated_at || completedAt;
        const passwordRecovery = await recoverAddedPasswordCredential({
          email,
          resultPath: passwordAddResultPath,
          credentials: storedCredentials,
        });
        storedCredentials = passwordRecovery.credentials;
        const totpRecovery = await recoverActivatedTotpCredential({
          email,
          resultPath: totpResultPath,
          credentials: storedCredentials,
        });
        storedCredentials = totpRecovery.credentials;
        const restoredOperation = restoredOutputOperationState(metadata, completedAt, totpRecovery, passwordRecovery);
        jobs.set(entry.name, {
          id: entry.name,
          email,
          status: restoredOperation.status,
          prompt: restoredOperation.prompt,
          createdAt: metadata.created_at || completedAt,
          updatedAt,
          lastOperationAt: metadata.last_operation_at || metadata.created_at || completedAt,
          lastOperationType: metadata.last_operation_type || "initial_authorization",
          completedAt: metadata.completed_at || completedAt,
          outputPath,
          checkpointPath,
          totpResultPath,
          passwordAddResultPath,
          logs: restoredOperation.log,
          lastError: restoredOperation.lastError,
          child: null,
          parserTail: "",
          resultSaved: true,
          loginFlow: metadata.login_flow === "legacy" ? "legacy" : "codex",
          loginMode: metadata.login_mode === "password" || storedCredentials.password ? "password" : (mailApiUrl ? "email_otp" : metadata.login_mode || "manual"),
          password: storedCredentials.password,
          totpSecret: storedCredentials.totpSecret,
          ...restoredCredentialFlags(metadata, storedCredentials),
          mailApiUrl,
          mailRequestBody: typeof metadata.mail_request_body === "string" ? metadata.mail_request_body : "",
          proxyUrl: storedCredentials.proxyUrl,
          mailSeenCandidateKeys: new Set(),
          mailCandidateCounts: new Map(),
          mailStatus: mailApiUrl ? "ready" : "manual",
          mailApiError: null,
          mailPollRunning: false,
          mailPollToken: null,
          currentPhone: metadata.sms_number || metadata.luban_number || null,
          phoneError: null,
          restartRequired: false,
          attempt: Math.max(1, Number(metadata.attempt || 1)),
          runId: null,
          runMode: null,
          fallbackInProgress: false,
          ...restoredTotpSetupState(metadata, storedCredentials),
          ...restoredProxyRiskState(metadata),
          ...restoredAutoRepairState(metadata),
          totpSetupError: restoredOperation.totpSetupError,
          passwordAddError: restoredOperation.passwordAddError,
          passwordAddedAt: metadata.password_added_at || passwordRecovery.addedAt || null,
          pendingNewPassword: null,
          totpSetupResumesAuthorization: false,
          passwordAddResumesAuthorization: false,
          loginCheckpointAvailable: false,
          securityCheckRequired: Boolean(metadata.security_check_required),
          ...newSmsState(),
        });
        return;
      } catch {}

      try {
        const [raw, stat] = await Promise.all([fs.readFile(checkpointPath, "utf8"), fs.stat(checkpointPath)]);
        const checkpoint = JSON.parse(raw);
        if (checkpoint?.version !== 1 || typeof checkpoint.email !== "string" || !checkpoint.email) return;
        const mailApiUrl = validateMailApiUrl(metadata.mail_api_url) ? metadata.mail_api_url : null;
        const email = metadata.email || checkpoint.email;
        let storedCredentials = await loadStoredLoginCredentials(email);
        const passwordRecovery = await recoverAddedPasswordCredential({
          email,
          resultPath: passwordAddResultPath,
          credentials: storedCredentials,
        });
        storedCredentials = passwordRecovery.credentials;
        const totpRecovery = await recoverActivatedTotpCredential({
          email,
          resultPath: totpResultPath,
          credentials: storedCredentials,
        });
        storedCredentials = totpRecovery.credentials;
        const restoredAt = stat.mtime.toISOString();
        const savedStatus = String(metadata.status || "");
        const restoredStatus = passwordRecovery.recovered || totpRecovery.recovered
          ? "resume_available"
          : isTerminalStatus(savedStatus) ? savedStatus : "resume_available";
        jobs.set(entry.name, {
          id: entry.name,
          email,
          status: restoredStatus,
          prompt: totpRecovery.recovered
            ? "已恢复成功激活的 2FA 密钥，可以继续未完成的 Codex 授权"
            : passwordRecovery.recovered
              ? "已恢复成功添加的新密码，可以继续未完成的 Codex 授权"
            : metadata.prompt || (restoredStatus === "resume_available"
              ? "检测到邮箱登录检查点，可以继续手机号绑定"
              : "已恢复上次操作状态，登录检查点仍然保留"),
          createdAt: metadata.created_at || restoredAt,
          updatedAt: metadata.updated_at || restoredAt,
          lastOperationAt: metadata.last_operation_at || metadata.created_at || restoredAt,
          lastOperationType: metadata.last_operation_type || "initial_authorization",
          completedAt: null,
          outputPath,
          checkpointPath,
          totpResultPath,
          passwordAddResultPath,
          logs: totpRecovery.recovered
            ? "[restore] 已从中断的 2FA 设置流程恢复并安全保存密钥。\n"
            : passwordRecovery.recovered
              ? "[restore] 已从中断的添加密码流程恢复并安全保存新密码。\n"
            : `[restore] 已恢复 ${checkpoint.stage || "unknown"} 阶段的登录检查点。\n`,
          lastError: passwordRecovery.recovered || totpRecovery.recovered
            ? "ChatGPT 登录状态已保留，点击继续流程即可重新开始 Codex 授权"
            : metadata.last_error || (restoredStatus === "resume_available"
              ? "上次流程在生成授权文件前中断"
              : null),
          child: null,
          parserTail: "",
          resultSaved: false,
          loginFlow: metadata.login_flow === "legacy" ? "legacy" : "codex",
          loginMode: metadata.login_mode === "password" || storedCredentials.password ? "password" : (mailApiUrl ? "email_otp" : metadata.login_mode || "manual"),
          password: storedCredentials.password,
          totpSecret: storedCredentials.totpSecret,
          ...restoredCredentialFlags(metadata, storedCredentials),
          mailApiUrl,
          mailRequestBody: typeof metadata.mail_request_body === "string" ? metadata.mail_request_body : "",
          proxyUrl: storedCredentials.proxyUrl,
          mailSeenCandidateKeys: new Set(),
          mailCandidateCounts: new Map(),
          mailStatus: mailApiUrl ? "ready" : "manual",
          mailApiError: null,
          mailPollRunning: false,
          mailPollToken: null,
          currentPhone: checkpoint.oauth?.phone || metadata.sms_number || metadata.luban_number || null,
          phoneError: null,
          restartRequired: false,
          attempt: Math.max(1, Number(metadata.attempt || 1)),
          runId: null,
          runMode: null,
          fallbackInProgress: false,
          ...restoredTotpSetupState(metadata, storedCredentials),
          ...restoredProxyRiskState(metadata),
          ...restoredAutoRepairState(metadata),
          totpSetupError: totpRecovery.error || null,
          passwordAddError: passwordRecovery.error || metadata.password_add_error || null,
          passwordAddedAt: metadata.password_added_at || passwordRecovery.addedAt || null,
          pendingNewPassword: null,
          totpSetupResumesAuthorization: false,
          passwordAddResumesAuthorization: false,
          loginCheckpointAvailable: true,
          securityCheckRequired: Boolean(metadata.security_check_required),
          ...restoredSmsState(metadata),
        });
      } catch {
        if (
          !metadata.email
          || !isEmail(metadata.email)
        ) return;
        const storedCredentials = await loadStoredLoginCredentials(metadata.email);
        const mailApiUrl = validateMailApiUrl(metadata.mail_api_url) ? metadata.mail_api_url : null;
        const restoredAt = metadata.updated_at || new Date().toISOString();
        const missingStoredCredentials = restoredMissingCredentials(metadata, storedCredentials);
        const storedCredentialsMissing = missingStoredCredentials.length > 0;
        const savedStatus = String(metadata.status || "");
        const restartable = ["queued", "starting"].includes(savedStatus);
        const interrupted = Boolean(savedStatus) && !isTerminalStatus(savedStatus) && !restartable;
        const restoredStatus = storedCredentialsMissing && restartable
          ? "reauth_required"
          : restartable
            ? "queued"
            : interrupted || !savedStatus
              ? "failed"
              : savedStatus;
        const restoredPrompt = storedCredentialsMissing && restartable
          ? "登录资料需要重新确认"
          : restartable
            ? "服务重启后已恢复，等待任务槽位"
            : interrupted || !savedStatus
              ? "上次流程因服务重启中断，可以重新授权"
              : metadata.prompt || "已恢复上次任务状态";
        const restoredError = storedCredentialsMissing && restartable
          ? `请重新导入或填写${missingStoredCredentials.join("、")}后重试，任务不会使用缺失的资料自动登录`
          : interrupted || !savedStatus
            ? metadata.last_error || `上次 ${savedStatus || "未知"} 阶段未完成`
            : metadata.last_error || null;
        jobs.set(entry.name, {
          id: entry.name,
          email: metadata.email,
          status: restoredStatus,
          prompt: restoredPrompt,
          createdAt: metadata.created_at || restoredAt,
          updatedAt: restoredAt,
          lastOperationAt: metadata.last_operation_at || metadata.created_at || restoredAt,
          lastOperationType: metadata.last_operation_type || "initial_authorization",
          completedAt: metadata.completed_at || null,
          outputPath,
          checkpointPath,
          totpResultPath,
          passwordAddResultPath,
          logs: storedCredentialsMissing && restartable
            ? `[restore] 服务器数据库中无法恢复${missingStoredCredentials.join("、")}，已停止自动启动。\n`
            : restartable
              ? "[restore] 已恢复排队任务，等待可用任务槽位。\n"
              : interrupted || !savedStatus
                ? "[restore] 上次任务在生成授权文件前中断，已恢复为可重试状态。\n"
                : "[restore] 已恢复上次任务状态。\n",
          lastError: restoredError,
          child: null,
          parserTail: "",
          resultSaved: false,
          loginFlow: metadata.login_flow === "legacy" ? "legacy" : "codex",
          loginMode: metadata.login_mode === "password" || storedCredentials.password ? "password" : (mailApiUrl ? "email_otp" : metadata.login_mode || "manual"),
          password: storedCredentials.password,
          totpSecret: storedCredentials.totpSecret,
          ...restoredCredentialFlags(metadata, storedCredentials),
          mailApiUrl,
          mailRequestBody: typeof metadata.mail_request_body === "string" ? metadata.mail_request_body : "",
          proxyUrl: storedCredentials.proxyUrl,
          mailSeenCandidateKeys: new Set(),
          mailCandidateCounts: new Map(),
          mailStatus: mailApiUrl ? "baseline" : "manual",
          mailApiError: null,
          mailPollRunning: false,
          mailPollToken: null,
          currentPhone: metadata.sms_number || null,
          phoneError: null,
          restartRequired: restoredStatus === "reauth_required",
          attempt: Math.max(1, Number(metadata.attempt || 1)),
          runId: null,
          runMode: null,
          queuedMode: restoredStatus === "queued" && metadata.queued_mode === "refresh" ? "refresh" : "full",
          queuedAt: restoredStatus === "queued" ? metadata.queued_at || restoredAt : null,
          queuedStartPrompt: metadata.queued_mode === "refresh"
            ? "正在使用已有刷新令牌直接生成新授权"
            : "正在建立登录会话",
          fallbackInProgress: false,
          ...restoredTotpSetupState(metadata, storedCredentials),
          ...restoredProxyRiskState(metadata),
          ...restoredAutoRepairState(metadata),
          passwordAddError: metadata.password_add_error || null,
          passwordAddedAt: metadata.password_added_at || null,
          pendingNewPassword: null,
          totpSetupResumesAuthorization: false,
          passwordAddResumesAuthorization: false,
          loginCheckpointAvailable: Boolean(metadata.login_checkpoint_available),
          securityCheckRequired: Boolean(metadata.security_check_required),
          ...newSmsState(),
        });
      }
    }));
    for (const id of storedJobIds) {
      const restored = jobs.get(id);
      if (restored) {
        // Security reconciliation can immediately write job metadata. Restore
        // its login pause and schedule generation before any such write.
        restoreScheduledJobMetadata(restored, serverDatabase.getJob(id) || {});
        const savedLogs = serverDatabase.get("job-logs", id);
        if (typeof savedLogs === "string") restored.logs = savedLogs;
      }
    }
  })().finally(() => {
    outputSyncPromise = null;
  });
  return outputSyncPromise;
}

async function recoverActivatedTotpCredential({ email, resultPath, credentials }) {
  let result;
  try {
    result = JSON.parse(await fs.readFile(resultPath, "utf8"));
  } catch (error) {
    if (error?.code === "ENOENT") return { credentials, recovered: false, error: null };
    return { credentials, recovered: false, error: `2FA 结果文件无法读取：${error.message}` };
  }
  if (result?.activation_succeeded !== true || !result?.secret) {
    return { credentials, recovered: false, error: null };
  }
  try {
    const secret = normalizeTotpSecret(result.secret);
    const nextCredentials = { ...credentials, totpSecret: secret };
    const persisted = await saveStoredLoginCredentials(email, nextCredentials);
    if (!persisted) {
      return {
        credentials: nextCredentials,
        recovered: false,
        error: "2FA 已激活，但当前系统不支持持久凭据存储；结果文件已保留",
      };
    }
    await removePrivateFile(resultPath);
    return { credentials: nextCredentials, recovered: true, error: null };
  } catch (error) {
    return {
      credentials,
      recovered: false,
      error: `2FA 已激活，但密钥恢复失败：${error.message}；结果文件已保留`,
    };
  }
}

async function recoverAddedPasswordCredential({ email, resultPath, credentials }) {
  let result;
  try {
    result = JSON.parse(await fs.readFile(resultPath, "utf8"));
  } catch (error) {
    if (error?.code === "ENOENT") return { credentials, recovered: false, error: null, addedAt: null };
    return { credentials, recovered: false, error: `添加密码结果文件无法读取：${error.message}`, addedAt: null };
  }
  if (
    result?.version !== 1
    || String(result.email || "").toLowerCase() !== email.toLowerCase()
    || typeof result.password !== "string"
    || result.password.length < 12
  ) {
    return { credentials, recovered: false, error: "添加密码结果文件格式不正确", addedAt: null };
  }
  const nextCredentials = { ...credentials, password: result.password };
  try {
    const persisted = await saveStoredLoginCredentials(email, nextCredentials);
    if (!persisted) {
      return {
        credentials: nextCredentials,
        recovered: false,
        error: "密码已经添加，但当前系统不支持持久凭据存储；结果文件已保留",
        addedAt: result.added_at || null,
      };
    }
    await removePrivateFile(resultPath);
    return { credentials: nextCredentials, recovered: true, error: null, addedAt: result.added_at || null };
  } catch (error) {
    return {
      credentials,
      recovered: false,
      error: `密码已经添加，但新密码恢复失败：${error.message}；结果文件已保留`,
      addedAt: result.added_at || null,
    };
  }
}

function restoredOutputOperationState(metadata, completedAt, totpRecovery, passwordRecovery) {
  const savedStatus = String(metadata.status || "");
  const interrupted = savedStatus && !isTerminalStatus(savedStatus);
  const status = !savedStatus || savedStatus === "completed"
    ? "completed"
    : interrupted ? "failed" : savedStatus;
  if (passwordRecovery.recovered) {
    return {
      status: "completed",
      prompt: "已恢复上次成功添加的新密码，原授权文件仍可下载",
      lastError: null,
      totpSetupError: null,
      passwordAddError: null,
      log: "[restore] 已从中断的添加密码流程恢复并安全保存新密码。\n",
    };
  }
  if (passwordRecovery.error) {
    return {
      status: "completed",
      prompt: "原授权文件仍可下载，新密码需要重试恢复",
      lastError: null,
      totpSetupError: null,
      passwordAddError: passwordRecovery.error,
      log: `[restore] ${passwordRecovery.error}\n`,
    };
  }
  if (savedStatus.startsWith("password_add") || metadata.queued_mode === "password_add") {
    return {
      status: "completed",
      prompt: "服务重启中断了添加密码，原授权文件仍可下载",
      lastError: null,
      totpSetupError: null,
      passwordAddError: "添加密码尚未完成，请重新点击添加密码",
      log: "[restore] 添加密码被服务重启中断，旧授权文件未受影响。\n",
    };
  }
  if (totpRecovery.recovered) {
    return {
      status: "completed",
      prompt: "已恢复上次成功激活的 2FA 密钥，原授权文件仍可下载",
      lastError: null,
      totpSetupError: null,
      passwordAddError: null,
      log: "[restore] 已从中断的 2FA 设置流程恢复并安全保存密钥。\n",
    };
  }
  if (totpRecovery.error) {
    return {
      status: "completed",
      prompt: "原授权文件仍可下载，2FA 密钥需要重试恢复",
      lastError: metadata.last_error || null,
      totpSetupError: totpRecovery.error,
      passwordAddError: null,
      log: `[restore] ${totpRecovery.error}\n`,
    };
  }
  if (interrupted) {
    return {
      status,
      prompt: "上次操作因服务重启中断，旧授权文件仍可下载",
      lastError: metadata.last_error || `上次 ${savedStatus} 阶段未完成`,
      totpSetupError: savedStatus.startsWith("totp_") ? "服务重启时 2FA 设置未完成" : null,
      passwordAddError: savedStatus.startsWith("password_add") ? "服务重启时添加密码未完成，请重新发起" : null,
      log: "[restore] 检测到旧授权文件，同时保留了上次中断的操作状态。\n",
    };
  }
  return {
    status,
    prompt: metadata.prompt || (status === "completed"
      ? "已从本地输出目录恢复，可以下载导入文件"
      : "旧授权文件仍可下载，已恢复最近一次操作状态"),
    lastError: metadata.last_error || null,
    totpSetupError: savedStatus.startsWith("totp_") ? "服务重启时 2FA 设置未完成" : null,
    passwordAddError: metadata.password_add_error || null,
    log: `[restore] 已恢复任务状态，旧授权文件时间 ${completedAt}。\n`,
  };
}

function isEmail(value) {
  const text = String(value || "");
  if (!text || text.length > 254 || /\s/.test(text)) return false;
  const at = text.lastIndexOf("@");
  if (at <= 0 || at !== text.indexOf("@")) return false;
  const local = text.slice(0, at);
  const domain = text.slice(at + 1);
  if (local.length > 64 || local.startsWith(".") || local.endsWith(".") || local.includes("..")) return false;
  if (!/^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+$/i.test(local)) return false;
  const labels = domain.split(".");
  if (labels.length < 2 || labels.some((label) => (
    !label
    || label.length > 63
    || label.startsWith("-")
    || label.endsWith("-")
    || !/^[A-Z0-9-]+$/i.test(label)
  ))) return false;
  const topLevelDomain = labels.at(-1);
  if (!/^(?:[A-Z]{2,63}|XN--[A-Z0-9-]{2,59})$/i.test(topLevelDomain)) return false;
  return true;
}

function normalizeProxyUrl(value) {
  const text = String(value || "").trim();
  if (!text) return null;
  let parsed;
  try {
    parsed = new URL(text);
  } catch {
    throw httpError(400, "账号代理必须是完整的 http://、https://、socks5:// 或 socks5h:// 地址");
  }
  if (!["http:", "https:", "socks5:", "socks5h:"].includes(parsed.protocol) || !parsed.hostname) {
    throw httpError(400, "账号代理只支持 http、https、socks5 和 socks5h 协议");
  }
  return parsed.toString();
}

function resolveBatchProxyAssignments(body, selected, key) {
  if (!Object.hasOwn(body, "proxyAssignments")) return null;
  if (!Array.isArray(body.proxyAssignments) || body.proxyAssignments.length !== selected.length) {
    throw httpError(400, "请为每个选中的账号明确选择代理");
  }
  const normalizeKey = (value) => key === "email" ? value.trim().toLowerCase() : value;
  const expected = new Set(selected.map((item) => normalizeKey(item[key])));
  const assignments = new Map();
  for (const assignment of body.proxyAssignments) {
    if (!assignment || typeof assignment !== "object" || Array.isArray(assignment)
      || typeof assignment[key] !== "string" || !Object.hasOwn(assignment, "proxyUrl")
      || (assignment.proxyUrl !== null && typeof assignment.proxyUrl !== "string" && !isPlainObject(assignment.proxyUrl))) {
      throw httpError(400, "代理选择格式错误，每个账号必须提供标识和代理地址");
    }
    const identifier = normalizeKey(assignment[key]);
    if (!expected.has(identifier) || assignments.has(identifier)) {
      throw httpError(400, "代理选择包含重复账号或未选中的账号，请重新确认");
    }
    const entry = selected.find((value) => normalizeKey(value[key]) === identifier);
    selectOperationProxy(entry.email, { proxyUrl: assignment.proxyUrl }, { preview: true });
    assignments.set(identifier, assignment.proxyUrl);
  }
  return assignments;
}

function resolveSecurityBatchProxyAssignments(body, selected) {
  if (!Object.hasOwn(body, "proxyAssignments")) return null;
  if (!Array.isArray(body.proxyAssignments) || body.proxyAssignments.length !== selected.length) {
    throw httpError(400, "请为每个选中的账号明确选择代理");
  }
  const expected = new Set(selected.map((job) => job.id));
  const assignments = new Map();
  for (const assignment of body.proxyAssignments) {
    if (!assignment || typeof assignment !== "object" || typeof assignment.id !== "string"
      || !Object.hasOwn(assignment, "proxyUrl") || !expected.has(assignment.id) || assignments.has(assignment.id)) {
      throw httpError(400, "代理选择包含重复账号或未选中的账号，请重新确认");
    }
    // Resolution may fail for one account; do it inside that account's lock so the
    // remaining valid accounts still receive individual started/error results.
    assignments.set(assignment.id, assignment.proxyUrl);
  }
  return assignments;
}

function operationProxySentinel(value) {
  if (!isPlainObject(value)) return null;
  if (Object.hasOwn(value, "useDefaultProxy") || Object.hasOwn(value, "useStoredProxy")) {
    if (Object.keys(value).length !== 1 || (value.useDefaultProxy !== true && value.useStoredProxy !== true)) throw httpError(400, "默认或已保存代理选择无效");
    return value.useDefaultProxy === true ? "default" : "stored";
  }
  return null;
}

function selectOperationProxy(email, options = {}, { preview = false } = {}) {
  const current = findJobByEmail(email);
  const saved = serverDatabase.loadCredentials(email);
  const specified = Object.hasOwn(options, "proxyUrl");
  const value = options.proxyUrl;
  const sentinel = operationProxySentinel(value);
  if (sentinel === "default" || !specified && operationProxies.enabled) {
    if (!operationProxies.enabled) throw httpError(409, "默认美国动态代理未启用");
    return { mode: "default", proxyUrl: current?.proxyUrl || saved.proxyUrl || null };
  }
  if (sentinel === "stored") {
    const provenance = serverDatabase.get("operation-proxy-selection", String(email).trim().toLowerCase());
    const savedProxy = normalizeProxyUrl(saved.proxyUrl);
    if (!savedProxy) throw httpError(409, "该账号没有已保存的代理，请明确选择默认代理或直连");
    if (savedProxy && (provenance?.proxyUrl === savedProxy || current?.operationProxyMode === "default" && normalizeProxyUrl(current.proxyUrl) === savedProxy)) {
      throw httpError(409, "已保存的代理属于限时操作，不能作为静态代理沿用；请使用默认代理开启新操作");
    }
    return { mode: "explicit", proxyUrl: savedProxy };
  }
  if (!specified) {
    if (current?.operationProxyMode === "default") throw httpError(409, "默认动态代理已暂停，请明确选择新的代理");
    return { mode: "legacy", proxyUrl: current?.proxyUrl || saved.proxyUrl || null };
  }
  if (preview && isPlainObject(value) && typeof value.dynamicProfileId === "string") {
    if (!dynamicProxies.profiles().some((profile) => profile.id === value.dynamicProfileId)) throw httpError(400, "动态代理配置不存在");
    return { mode: "dynamic", proxyUrl: current?.proxyUrl || saved.proxyUrl || null };
  }
  return { mode: isPlainObject(value) && value.dynamicProfileId ? "dynamic" : "explicit", proxyUrl: resolveJobProxySelection(email, value) };
}

function applyOperationProxyChoice(job, choice, operationId = null) {
  if (job.operationProxyLeaseTimer) clearTimeout(job.operationProxyLeaseTimer);
  job.operationProxyLeaseTimer = null;
  job.operationProxyMode = choice.mode;
  job.operationProxyId = choice.mode === "default" ? operationId || crypto.randomUUID() : null;
  job.operationProxyExpiresAt = null;
  job.operationProxyExitIp = null;
  job.operationProxyExitCountry = null;
  job.proxyUrl = choice.proxyUrl;
}

async function configureOperationProxy(job, options = {}) {
  const choice = selectOperationProxy(job.email, options);
  applyOperationProxyChoice(job, choice);
  if (Object.hasOwn(options, "proxyUrl") && choice.mode !== "default") await saveStoredLoginCredentials(job.email, job);
  return choice;
}

function assertOperationProxyLease(job) {
  if (job.operationProxyMode !== "default") return;
  if (!job.operationProxyId || !job.operationProxyExpiresAt || Date.parse(job.operationProxyExpiresAt) <= Date.now()) throw httpError(409, "美国动态代理租期已结束，本次操作停止；请明确开启新操作");
  if (job.operationProxyExitCountry !== "US") throw httpError(409, "动态代理美国出口尚未确认，本次操作已停止");
}

function armOperationProxyLease(job) {
  if (job.operationProxyMode !== "default") return;
  assertOperationProxyLease(job);
  if (job.operationProxyLeaseTimer) clearTimeout(job.operationProxyLeaseTimer);
  const operationId = job.operationProxyId;
  job.operationProxyLeaseTimer = setTimeout(() => {
    void withEmailJobLock(job.email, async () => {
      if (job.deleted || job.operationProxyId !== operationId || !isActive(job.status)) return;
      job.loginAutoRetryBlocked = true;
      if (isSecurityMode(job.runMode || job.queuedMode)) job.securityFailureMessage = "美国动态代理租期已结束，已停止本次操作并保留结果，请核实后再开启新操作";
      else failJob(job, "美国动态代理租期已结束，本次操作已停止，请明确开启新操作");
      job.child?.kill("SIGTERM");
      await saveJobMetadata(job);
    }).catch(() => {});
  }, Math.max(1, Date.parse(job.operationProxyExpiresAt) - Date.now()));
  job.operationProxyLeaseTimer.unref?.();
}

function resolveJobProxySelection(email, value) {
  if (isPlainObject(value) && typeof value.dynamicProfileId === "string") {
    const current = findJobByEmail(email);
    const stored = serverDatabase.loadCredentials(email);
    const target = crsIntegration.dynamicTarget();
    if (!target) throw httpError(409, "请先配置 CRS 服务器");
    dynamicProxies.bind(email, value.dynamicProfileId, { target, proxyUrl: current?.proxyUrl || stored.proxyUrl || null });
    return current?.proxyUrl || stored.proxyUrl || null;
  }
  if (dynamicProxies.binding(email)) {
    const current = findJobByEmail(email)?.proxyUrl || serverDatabase.loadCredentials(email).proxyUrl || null;
    if (value === current) return current;
    throw httpError(409, "账号已绑定动态代理，请继续选择原动态配置");
  }
  return normalizeProxyUrl(value);
}

function batchProxyOptions(body, assignments, id) {
  return assignments ? { ...body, proxyUrl: assignments.get(id) } : body;
}

function publicProxyEndpoint(value) {
  if (!value) return null;
  try {
    const proxy = new URL(value);
    const port = proxy.port || ({ "http:": "80", "https:": "443", "socks5:": "1080", "socks5h:": "1080" })[proxy.protocol];
    return `${proxy.protocol}//${proxy.hostname}${port ? `:${port}` : ""}`;
  } catch {
    return null;
  }
}

function normalizeLoginCredentials(value = {}) {
  const password = typeof value.password === "string" ? value.password : "";
  const mailRequestBody = typeof value.mailRequestBody === "string" ? value.mailRequestBody : "";
  const configuredPostUrl = mailRequestConfig.method === "POST" && validateMailApiUrl(mailRequestConfig.url)
    ? mailRequestConfig.url
    : null;
  const mailApiUrl = validateMailApiUrl(value.mailApiUrl)
    ? String(value.mailApiUrl).trim()
    : mailRequestBody && configuredPostUrl
      ? configuredPostUrl
      : null;
  const totpSecret = value.totpSecret ? normalizeTotpSecret(value.totpSecret) : "";
  const loginMode = password ? "password" : "email_otp";
  return { loginMode, mailApiUrl, mailRequestBody, password, totpSecret };
}

function restoredCredentialFlags(metadata = {}, credentials = {}) {
  const hasExplicitPasswordFlag = Object.hasOwn(metadata, "has_password");
  const hasExplicitTotpFlag = Object.hasOwn(metadata, "has_totp_key");
  return {
    hasPasswordCredential: Boolean(
      credentials.password
      || (hasExplicitPasswordFlag ? metadata.has_password : metadata.login_mode === "password" && metadata.has_stored_credentials),
    ),
    hasTotpCredential: Boolean(
      credentials.totpSecret
      || (hasExplicitTotpFlag ? metadata.has_totp_key : metadata.has_stored_credentials),
    ),
  };
}

function restoredTotpSetupState(metadata = {}, credentials = {}) {
  return {
    totpSetupSecret: null,
    totpSetupUri: null,
    totpSetupError: null,
    totpKnownEnabled: Boolean(metadata.totp_known_enabled || credentials.totpSecret),
    totpSetupAttempt: 0,
    totpResultLoading: false,
  };
}

function restoredProxyRiskState(metadata = {}) {
  const count = Number(metadata.proxy_risk_retry_count || 0);
  const connectionFailures = Number(metadata.proxy_connection_failure_count || 0);
  return {
    loginAutoRetryCount: Math.max(0, Math.min(3, Number(metadata.login_auto_retry_count) || 0)),
    proxyRiskRetryCount: Number.isInteger(count) && count >= 0 ? Math.min(count, MAX_PROXY_RISK_RETRIES) : 0,
    proxyConnectionFailureCount: Number.isInteger(connectionFailures) && connectionFailures >= 0
      ? Math.min(connectionFailures, MAX_PROXY_CONNECTION_FAILURES)
      : 0,
    proxyRiskRestarting: false,
    proxySessionAttemptIds: new Set(),
    proxyAttemptParserTail: "",
  };
}

function restoredAutoRepairState(metadata = {}) {
  const requirements = metadata.last_auth_requirements;
  const pendingIds = Array.isArray(metadata.auto_repair_pending_account_ids)
    ? metadata.auto_repair_pending_account_ids.map(Number).filter((id) => Number.isSafeInteger(id) && id > 0)
    : [];
  return {
    crsBridgeOperationId: typeof metadata.crs_bridge_operation_id === "string" ? metadata.crs_bridge_operation_id : null,
    crsBridgeResultOperationId: typeof metadata.crs_bridge_result_operation_id === "string" ? metadata.crs_bridge_result_operation_id : null,
    lastAuthAutomated: metadata.last_auth_automated === true,
    lastAuthAutomationReason: String(metadata.last_auth_automation_reason || "旧任务没有自动化参与记录"),
    lastAuthAutomatedAt: metadata.last_auth_automated_at || null,
    lastAuthRequirements: requirements && typeof requirements === "object"
      ? {
          password: Boolean(requirements.password),
          emailOtp: Boolean(requirements.emailOtp),
          mfa: Boolean(requirements.mfa),
        }
      : null,
    authAutomationAttempt: null,
    autoRepairBlocked: metadata.auto_repair_blocked === true,
    autoRepairBlockedReason: metadata.auto_repair_blocked_reason || null,
    autoRepairBlockedAt: metadata.auto_repair_blocked_at || null,
    autoRepairLastAttemptAt: metadata.auto_repair_last_attempt_at || null,
    autoRepairLastSuccessAt: metadata.auto_repair_last_success_at || null,
    autoRepairLastError: metadata.auto_repair_last_error || null,
    autoRepairPendingAccountIds: [...new Set(pendingIds)],
    autoRepairPendingBackend: metadata.auto_repair_pending_backend || null,
    autoRepairOperation: null,
  };
}

function restoredMissingCredentials(metadata = {}, credentials = {}) {
  const missing = [];
  const passwordRequired = Object.hasOwn(metadata, "has_password")
    ? metadata.has_password
    : metadata.login_mode === "password" && metadata.has_stored_credentials;
  const totpRequired = Object.hasOwn(metadata, "has_totp_key")
    ? metadata.has_totp_key
    : metadata.has_stored_credentials && !passwordRequired;
  if (passwordRequired && !credentials.password) missing.push("密码");
  if (totpRequired && !credentials.totpSecret) missing.push("2FA 密钥");
  if (metadata.proxy_configured && !credentials.proxyUrl) missing.push("代理 IP");
  return missing;
}

function normalizeTotpSecret(value, lineNumber = null) {
  const normalized = String(value || "").toUpperCase().replace(/[\s=]/g, "");
  if (!/^[A-Z2-7]{16,128}$/.test(normalized)) {
    const prefix = lineNumber ? `第 ${lineNumber} 行` : "";
    throw httpError(400, `${prefix}2FA 密钥格式错误，只能包含 Base32（基础三十二进制）的 A-Z 和 2-7`);
  }
  return normalized;
}

function parseBatchEntries(value, requestConfig = {}) {
  const lines = String(value || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  if (!lines.length) throw httpError(400, "请至少输入一行账号信息");
  if (lines.length > MAX_BATCH_JOBS) throw httpError(400, `一次最多添加 ${MAX_BATCH_JOBS} 条任务`);

  const entries = lines.map((line, index) => (
    requestConfig.method === "POST" && !isEmail(line)
      ? parsePostMailAccountLine(line, index + 1, requestConfig)
      : parseSmartAccountLine(line, index + 1)
  ));

  const unique = new Map();
  entries.forEach((entry) => unique.set(entry.email.toLowerCase(), entry));
  return [...unique.values()];
}

function parsePostMailAccountLine(line, lineNumber, requestConfig) {
  if (!validateMailApiUrl(requestConfig.url)) {
    throw httpError(400, "POST 邮件接码模式需要先在控制台配置统一请求 URL");
  }
  const fields = line.split("----").map((value) => value.trim());
  if (fields.length < 2) {
    throw httpError(400, `第 ${lineNumber} 行格式错误，POST 邮件接码请使用 邮箱----编码请求体`);
  }
  const emailFields = fields.map((value, index) => ({ value, index })).filter((field) => isEmail(field.value));
  if (emailFields.length !== 1) throw httpError(400, `第 ${lineNumber} 行必须包含一个独立邮箱`);
  const emailField = emailFields[0];
  const remaining = fields
    .map((value, index) => ({ value, index }))
    .filter((field) => field.index !== emailField.index && field.value);
  if (!remaining.length) throw httpError(400, `第 ${lineNumber} 行缺少 POST 请求体`);

  let totpField = null;
  if (remaining.length >= 2) {
    const totpCandidates = remaining.filter((field) => isTotpSecretCandidate(field.value));
    if (totpCandidates.length === 1) totpField = totpCandidates[0];
  }
  const bodyAndPassword = remaining.filter((field) => field !== totpField);
  const recognizableBodies = bodyAndPassword.filter((field) => looksLikeEncodedMailRequestBody(field.value));
  const bodyField = recognizableBodies.length === 1 ? recognizableBodies[0] : bodyAndPassword.at(-1);
  const passwordFields = bodyAndPassword.filter((field) => field !== bodyField);
  if (passwordFields.length > 1) {
    throw httpError(400, `第 ${lineNumber} 行无法区分密码和 POST 请求体，请将编码请求体放在最后`);
  }
  const mailRequestBody = bodyField?.value || "";
  const password = passwordFields[0]?.value || "";
  if (Buffer.byteLength(mailRequestBody) > MAX_MAIL_REQUEST_BODY_BYTES) {
    throw httpError(400, `第 ${lineNumber} 行 POST 请求体不能超过 64 KB`);
  }
  return {
    email: emailField.value,
    loginMode: password ? "password" : "email_otp",
    mailApiUrl: requestConfig.url,
    mailRequestBody,
    password,
    totpSecret: totpField ? normalizeTotpSecret(totpField.value, lineNumber) : "",
  };
}

function looksLikeEncodedMailRequestBody(value) {
  const text = String(value || "").trim();
  if (!text) return false;
  if (/^[{\[]/.test(text)) {
    try {
      JSON.parse(text);
      return true;
    } catch {}
  }
  if (/(?:^|&)[^=&\s]+=[^&]*(?:&|$)/.test(text) || /%[0-9A-F]{2}/i.test(text)) return true;
  const compact = text.replace(/\s+/g, "");
  if (/^[A-Za-z0-9+/_-]+={0,2}$/.test(compact) && compact.length >= 12) {
    try {
      const decoded = Buffer.from(compact.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8").trim();
      return /^[{\[]/.test(decoded) || /(?:^|&)[^=&\s]+=[^&]*(?:&|$)/.test(decoded);
    } catch {}
  }
  return false;
}

function parseSmartAccountLine(line, lineNumber) {
  if (isEmail(line)) {
    return {
      email: line,
      loginMode: "email_otp",
      mailApiUrl: null,
      password: "",
      totpSecret: "",
      preserveExistingCredentials: true,
    };
  }

  const parsed = accountDelimiterCandidates(line)
    .map((delimiter) => parseAccountLineWithDelimiter(line, delimiter, lineNumber))
    .filter(Boolean);
  const ambiguity = parsed.find((candidate) => candidate.ambiguity);
  if (ambiguity) throw httpError(400, `第 ${lineNumber} 行${ambiguity.ambiguity}`);

  const candidates = parsed
    .sort(compareAccountParseCandidates);
  if (!candidates.length) {
    const unsupportedHyphenRun = [...line.matchAll(/-+/g)].find((match) => (
      match[0].length === 5 || match[0].length > 8
    ));
    if (unsupportedHyphenRun) {
      throw httpError(400, `第 ${lineNumber} 行存在 ${unsupportedHyphenRun[0].length} 个连续短横线，无法确定是分隔符还是字段内容，请改用 | 或 Tab 分隔`);
    }
    throw httpError(400, `第 ${lineNumber} 行无法识别出独立邮箱和账号字段`);
  }
  const best = candidates[0];
  const conflicting = candidates.find((candidate) => (
    candidate.recognizedCount === best.recognizedCount
    && accountParseSignature(candidate) !== accountParseSignature(best)
  ));
  if (conflicting) {
    throw httpError(400, `第 ${lineNumber} 行存在多种可能的字段分隔方式，请改用 ---- 明确分隔`);
  }
  if (passwordContainsStructuredField(best.entry.password)) {
    throw httpError(400, `第 ${lineNumber} 行似乎混用了多种分隔符，密码中又识别到 URL 或 2FA 密钥，请统一改用 ---- 分隔`);
  }
  return best.entry;
}

function accountDelimiterCandidates(line) {
  const candidates = [
    { id: "hyphen-4", split: (value) => splitHyphenDelimitedLine(value, 4), priority: 110 },
    { id: "hyphen-3", split: (value) => splitHyphenDelimitedLine(value, 3), priority: 105 },
    { id: "hyphen-mixed", split: (value) => splitMixedHyphenDelimitedLine(value), priority: 100 },
    { id: "tab", pattern: /\t+/g, priority: 80 },
    { id: "pipe", pattern: /\|+/g, priority: 70 },
    { id: "double-colon", pattern: /:{2,}/g, priority: 65 },
    { id: "semicolon", pattern: /[;；]+/g, priority: 60 },
    { id: "comma", pattern: /[,，]+/g, priority: 55 },
    { id: "spaces", pattern: / {2,}/g, priority: 40 },
  ];
  const repeated = line.match(/([#~^*])\1+/g) || [];
  for (const delimiter of new Set(repeated)) {
    candidates.push({
      id: `repeated-${delimiter[0].codePointAt(0)}`,
      pattern: new RegExp(escapeRegExp(delimiter), "g"),
      priority: 35 + delimiter.length,
    });
  }
  return candidates;
}

function parseAccountLineWithDelimiter(line, delimiter, lineNumber) {
  const split = delimiter.split ? delimiter.split(line) : splitPreservingDelimiters(line, delimiter.pattern);
  if (split.separators.length === 0) return null;
  if (split.segments.length > 64) return null;
  const fields = split.segments.map((raw, index) => ({ raw, value: raw.trim(), index, type: "plain" }));
  if (fields.filter((field) => isEmail(field.value)).length > 1) {
    return { ambiguity: "中识别到多个完整邮箱，无法确定哪个是账号" };
  }
  const emailRange = findLongestEmailRange(split);
  if (!emailRange) return null;
  for (let index = emailRange.start; index <= emailRange.end; index += 1) fields[index].type = "email";

  const urls = fields.filter((field) => field.type === "plain" && validateMailApiUrl(field.value));
  if (urls.length > 1) return null;
  if (["comma", "semicolon"].includes(delimiter.id) && urls.some((field) => (
    adjacentPlainFieldCanExtendUrl(fields, split, field)
  ))) {
    return { ambiguity: "中的 URL 可能包含逗号或分号，请改用 ---- 分隔字段" };
  }
  for (const field of urls) field.type = "mail_api";

  const remaining = fields.filter((field) => field.type === "plain" && field.value);
  const totpCandidates = remaining.filter((field) => isTotpSecretCandidate(field.value));
  const emptyFieldPresent = fields.some((field) => !field.value);
  let totp = null;
  let totpValue = "";
  if (totpCandidates.length === 1) {
    const candidate = totpCandidates[0];
    const otherPlain = remaining.filter((field) => field !== candidate);
    const followsMailApi = urls.some((field) => field.index < candidate.index);
    if (otherPlain.length > 0 || followsMailApi || emptyFieldPresent) {
      totp = candidate;
      totp.type = "totp";
      totpValue = totp.value;
    }
  } else if (totpCandidates.length > 1) {
    const conventionalPasswordTotp = delimiter.id.startsWith("hyphen-")
      && split.separators.length === 2
      && fields.length === 3
      && emailRange.start === 0
      && emailRange.end === 0
      && urls.length === 0
      && totpCandidates.length === 2
      && totpCandidates[0].index === 1
      && totpCandidates[1].index === 2;
    if (!conventionalPasswordTotp) return null;
    // A 16-character password can also look like Base32; in email----password----2FA, the final field is 2FA.
    totp = totpCandidates[1];
    totp.type = "totp";
    totpValue = totp.value;
  }
  if (!totp && delimiter.id === "spaces") {
    const groupedTotp = findGroupedTotpCandidate(fields, split);
    if (groupedTotp) {
      const outsidePlain = remaining.filter((field) => (
        field.index < groupedTotp.start || field.index > groupedTotp.end
      ));
      if (outsidePlain.length > 0 || urls.length > 0 || emptyFieldPresent) {
        for (let index = groupedTotp.start; index <= groupedTotp.end; index += 1) fields[index].type = "totp";
        totp = fields[groupedTotp.start];
        totpValue = groupedTotp.value;
      }
    }
  }

  const passwordFields = fields.filter((field) => field.type === "plain" && field.value);
  if (passwordFields.length && !indexesAreContiguous(passwordFields.map((field) => field.index))) return null;
  const password = passwordFields.length
    ? reconstructSegmentRange(split, passwordFields[0].index, passwordFields.at(-1).index).trim()
    : "";
  if (!password && !urls.length && !totp) return null;

  const recognizedCount = 1 + urls.length + Number(Boolean(totp));
  const score = recognizedCount * 1_000
    + Number(Boolean(password)) * 100
    + delimiter.priority
    - Math.max(0, split.separators.length - 3);
  return {
    score,
    recognizedCount,
    delimiter: delimiter.id,
    entry: {
      email: emailRange.value,
      loginMode: password ? "password" : "email_otp",
      mailApiUrl: urls[0]?.value || null,
      password,
      totpSecret: totp ? normalizeTotpSecret(totpValue, lineNumber) : "",
    },
  };
}

function splitHyphenDelimitedLine(line, width) {
  return splitWithSelectedMatches(line, [...line.matchAll(/-+/g)].flatMap((match) => {
    if (match[0].length === width) return [{ index: match.index, value: match[0] }];
    if (match[0].length === width * 2) {
      return [
        { index: match.index, value: "-".repeat(width) },
        { index: match.index + width, value: "-".repeat(width) },
      ];
    }
    return [];
  }));
}

function splitMixedHyphenDelimitedLine(line) {
  return splitWithSelectedMatches(line, [...line.matchAll(/-+/g)].flatMap((match) => {
    const length = match[0].length;
    if (length === 3 || length === 4) return [{ index: match.index, value: match[0] }];
    if (length >= 6 && length <= 8) {
      const firstLength = length === 6 ? 3 : 4;
      return [
        { index: match.index, value: "-".repeat(firstLength) },
        { index: match.index + firstLength, value: "-".repeat(length - firstLength) },
      ];
    }
    return [];
  }));
}

function splitWithSelectedMatches(line, matches) {
  const segments = [];
  const separators = [];
  let cursor = 0;
  for (const match of matches) {
    segments.push(line.slice(cursor, match.index));
    separators.push(match.value);
    cursor = match.index + match.value.length;
  }
  segments.push(line.slice(cursor));
  return { segments, separators };
}

function splitPreservingDelimiters(line, pattern) {
  const segments = [];
  const separators = [];
  pattern.lastIndex = 0;
  let cursor = 0;
  for (const match of line.matchAll(pattern)) {
    segments.push(line.slice(cursor, match.index));
    separators.push(match[0]);
    cursor = match.index + match[0].length;
  }
  segments.push(line.slice(cursor));
  return { segments, separators };
}

function reconstructSegmentRange(split, start, end) {
  let result = split.segments[start];
  for (let index = start; index < end; index += 1) {
    result += split.separators[index] + split.segments[index + 1];
  }
  return result;
}

function findLongestEmailRange(split) {
  const candidates = [];
  for (let start = 0; start < split.segments.length; start += 1) {
    for (let end = start; end < split.segments.length; end += 1) {
      const value = reconstructSegmentRange(split, start, end).trim();
      const atCount = (value.match(/@/g) || []).length;
      if (atCount > 1) break;
      if (atCount === 1 && isEmail(value)) candidates.push({ start, end, value });
    }
  }
  if (!candidates.length) return null;
  const leadingCandidates = candidates.filter((candidate) => candidate.start === 0);
  const standaloneCandidates = candidates.filter((candidate) => candidate.start === candidate.end);
  // A complete segment is a stronger signal than a longer range. Otherwise a
  // dotted password can be appended to a valid email and still look like a
  // valid domain (for example, email----r7.UjRUWVVS).
  const preferred = standaloneCandidates.length ? standaloneCandidates : leadingCandidates;
  if (!preferred.length) return null;
  preferred.sort((left, right) => (
    right.value.length - left.value.length
    || (right.end - right.start) - (left.end - left.start)
    || left.start - right.start
  ));
  const best = preferred[0];
  const conflicting = preferred.find((candidate) => (
    candidate.value.length === best.value.length && candidate.value.toLowerCase() !== best.value.toLowerCase()
  ));
  return conflicting ? null : best;
}

function adjacentPlainFieldCanExtendUrl(fields, split, urlField) {
  for (const adjacentIndex of [urlField.index - 1, urlField.index + 1]) {
    const adjacent = fields[adjacentIndex];
    if (!adjacent || adjacent.type !== "plain" || !adjacent.value) continue;
    const start = Math.min(urlField.index, adjacentIndex);
    const end = Math.max(urlField.index, adjacentIndex);
    if (validateMailApiUrl(reconstructSegmentRange(split, start, end).trim())) return true;
  }
  return false;
}

function findGroupedTotpCandidate(fields, split) {
  const candidates = [];
  for (let start = 0; start < fields.length; start += 1) {
    if (fields[start].type !== "plain" || !/^[A-Z2-7=]{4,8}$/i.test(fields[start].value)) continue;
    for (let end = start + 1; end < fields.length; end += 1) {
      if (fields[end].type !== "plain" || !/^[A-Z2-7=]{4,8}$/i.test(fields[end].value)) break;
      const value = reconstructSegmentRange(split, start, end);
      if (isTotpSecretCandidate(value)) candidates.push({ start, end, value });
    }
  }
  if (!candidates.length) return null;
  candidates.sort((left, right) => (right.end - right.start) - (left.end - left.start));
  const best = candidates[0];
  return candidates.some((candidate) => (
    candidate !== best
    && candidate.end - candidate.start === best.end - best.start
    && (candidate.start !== best.start || candidate.end !== best.end)
  )) ? null : best;
}

function isTotpSecretCandidate(value) {
  const normalized = String(value || "").toUpperCase().replace(/[\s=]/g, "");
  return /^[A-Z2-7]{16,128}$/.test(normalized);
}

function passwordContainsStructuredField(password) {
  const text = String(password || "");
  if (!text) return false;
  const patterns = [/-{3,4}/g, /\|+/g, /:{2,}/g, /[;；]+/g, /[,，]+/g, / {2,}/g];
  return patterns.some((pattern) => {
    const split = splitPreservingDelimiters(text, pattern);
    return split.separators.length > 0 && split.segments.some((segment) => (
      validateMailApiUrl(segment.trim()) || isTotpSecretCandidate(segment.trim())
    ));
  });
}

function indexesAreContiguous(indexes) {
  return indexes.every((value, index) => index === 0 || value === indexes[index - 1] + 1);
}

function compareAccountParseCandidates(left, right) {
  return right.score - left.score || left.delimiter.localeCompare(right.delimiter);
}

function accountParseSignature(candidate) {
  const { email, mailApiUrl, mailRequestBody, password, totpSecret } = candidate.entry;
  return JSON.stringify({ email: email.toLowerCase(), mailApiUrl, mailRequestBody, password, totpSecret });
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function updateJobCredentials(job, credentials, options = {}) {
  if (isSecurityMode(job.runMode || job.queuedMode) && isActive(job.status)) throw httpError(409, "账号安全操作正在执行，请等待结束后再更新资料");
  if (credentials.preserveExistingCredentials) await reloadMissingJobCredentials(job);
  const normalized = credentials.preserveExistingCredentials
    ? normalizeLoginCredentials({
        password: job.password,
        mailApiUrl: job.mailApiUrl,
        mailRequestBody: job.mailRequestBody,
        totpSecret: job.totpSecret,
      })
    : normalizeLoginCredentials(credentials);
  const nextProxyUrl = options.hasProxyUpdate ? normalizeProxyUrl(options.proxyUrl) : job.proxyUrl;
  const changed = job.loginMode !== normalized.loginMode
    || job.mailApiUrl !== normalized.mailApiUrl
    || job.mailRequestBody !== normalized.mailRequestBody
    || job.password !== normalized.password
    || job.totpSecret !== normalized.totpSecret
    || job.proxyUrl !== nextProxyUrl;
  if (changed) await overrideScheduledJob(job, "人工更新账号资料替代了原定时任务");
  if (changed) job.emailLoginAutoPaused = false;
  await saveStoredLoginCredentials(job.email, { ...normalized, proxyUrl: nextProxyUrl });
  if (!changed) {
    if (options.operationProxyChoice && !isActive(job.status)) {
      applyOperationProxyChoice(job, options.operationProxyChoice);
      await saveJobMetadata(job);
    }
    return;
  }
  if (options.operationProxyChoice) applyOperationProxyChoice(job, options.operationProxyChoice);
  stopMailPolling(job);
  job.loginMode = normalized.loginMode;
  job.mailApiUrl = normalized.mailApiUrl;
  job.mailRequestBody = normalized.mailRequestBody;
  job.password = normalized.password;
  job.totpSecret = normalized.totpSecret;
  job.hasPasswordCredential = Boolean(normalized.password);
  job.hasTotpCredential = Boolean(normalized.totpSecret);
  job.proxyUrl = nextProxyUrl;
  job.mailSeenCandidateKeys.clear();
  job.mailCandidateCounts.clear();
  job.mailStatus = job.mailApiUrl ? "baseline" : "manual";
  job.mailApiError = null;
  recordJobOperation(job, "account_update");
  appendJobLog(job, "[account] 登录方式与验证资料已按邮箱唯一键更新，敏感字段未写入日志。\n");
  if (isActive(job.status) && job.status !== "queued") {
    restartJobAfterConfigurationUpdate(job);
  } else {
    touch(job);
    await saveJobMetadata(job);
  }
}

async function updateJobProxy(job, proxyUrl, { preserveAutoPause = false, operationProxyChoice = null } = {}) {
  if (isSecurityMode(job.runMode || job.queuedMode) && isActive(job.status)) {
    throw httpError(409, "账号安全操作正在执行，请等待结束后再更新代理");
  }
  if (job.proxyUrl !== normalizeProxyUrl(proxyUrl)) await overrideScheduledJob(job, "人工更换代理替代了原定时任务");
  if (!preserveAutoPause && job.proxyUrl !== normalizeProxyUrl(proxyUrl)) job.emailLoginAutoPaused = false;
  const nextProxyUrl = normalizeProxyUrl(proxyUrl);
  const previousProxyUrl = job.proxyUrl;
  // A worker can have committed a verified key before its parent consumed the
  // final result. A proxy-only edit must preserve the latest database credential.
  const latest = serverDatabase.transaction(() => {
    const stored = serverDatabase.loadCredentials(job.email);
    const password = typeof stored.password === "string" ? stored.password : "";
    const totpSecret = stored.totpSecret ? normalizeTotpSecret(stored.totpSecret) : "";
    serverDatabase.saveCredentials(job.email, { ...stored, proxyUrl: nextProxyUrl || "" });
    return { password, totpSecret };
  });
  job.password = latest.password;
  job.totpSecret = latest.totpSecret;
  job.hasPasswordCredential = Boolean(latest.password);
  job.hasTotpCredential = Boolean(latest.totpSecret);
  job.proxyUrl = nextProxyUrl;
  if (previousProxyUrl === nextProxyUrl) {
    if (operationProxyChoice && !isActive(job.status)) {
      applyOperationProxyChoice(job, operationProxyChoice);
      await saveJobMetadata(job);
    }
    return;
  }
  if (operationProxyChoice) applyOperationProxyChoice(job, operationProxyChoice);
  recordJobOperation(job, "proxy_update");
  appendJobLog(job, "[proxy] 账号代理配置已更新。\n");
  if (isActive(job.status) && job.status !== "queued") {
    restartJobAfterConfigurationUpdate(job);
  } else {
    touch(job);
    await saveJobMetadata(job);
  }
}

function restartJobAfterConfigurationUpdate(job) {
  stopMailPolling(job);
  releaseSmsNumber(job, "idle");
  job.queueRunId = null;
  job.runId = crypto.randomUUID();
  job.child?.kill("SIGTERM");
  job.child = null;
  job.lastError = null;
  job.parserTail = "";
  job.currentPhone = null;
  job.phoneError = null;
  job.securityCheckRequired = false;
  job.restartRequired = false;
  job.attempt += 1;
  beginAuthorizationAutomationAttempt(job, "configuration_update");
  appendJobLog(job, "[account] 已停止使用旧配置的登录进程，并使用新配置重新排队。\n");
  enqueueJob(job, "full", "账号资料已更新，正在重新建立登录会话");
}

function jobMetadata(job) {
  return {
        version: 1,
        operation_proxy_mode: job.operationProxyMode || "legacy",
        operation_proxy_id: job.operationProxyId || null,
        operation_proxy_expires_at: job.operationProxyExpiresAt || null,
        operation_proxy_exit_ip: job.operationProxyExitIp || null,
        operation_proxy_exit_country: job.operationProxyExitCountry || null,
        login_deferred: Boolean(job.loginDeferred),
        login_flow: job.loginFlow === "legacy" ? "legacy" : "codex",
        schedule_item_id: job.scheduleItemId || null,
        schedule_id: job.scheduleId || null,
        schedule_login_attempt_id: job.scheduleLoginAttemptId || null,
        schedule_result_attempt_id: job.scheduleResultAttemptId || null,
        email_login_attempt: job.emailLoginAttempt || 0,
        email_login_reason: job.emailLoginReason || null,
        email_login_auto_paused: Boolean(job.emailLoginAutoPaused),
        crs_bridge_operation_id: job.crsBridgeOperationId || null,
        crs_bridge_result_operation_id: job.crsBridgeResultOperationId || null,
        email: job.email,
        status: job.status,
        prompt: job.prompt || null,
        last_error: job.lastError || null,
        result_saved: Boolean(job.resultSaved),
        completed_at: job.completedAt || null,
        attempt: Number(job.attempt || 1),
        security_check_required: Boolean(job.securityCheckRequired),
        queued_mode: job.queuedMode || null,
        queued_at: job.queuedAt || null,
        created_at: job.createdAt,
        last_operation_at: job.lastOperationAt || job.createdAt,
        last_operation_type: job.lastOperationType || "initial_authorization",
        login_mode: job.loginMode || null,
        mail_api_url: job.mailApiUrl || null,
        mail_request_body: job.mailRequestBody || null,
        has_stored_credentials: Boolean(job.password || job.totpSecret),
        has_password: Boolean(job.password || job.hasPasswordCredential),
        has_totp_key: Boolean(job.totpSecret || job.hasTotpCredential),
        totp_known_enabled: Boolean(job.totpKnownEnabled || job.totpSecret || job.hasTotpCredential),
        password_add_error: job.passwordAddError || null,
        password_added_at: job.passwordAddedAt || null,
        security_operation_id: job.securityOperationId || null,
        security_auto_login_paused: Boolean(job.securityAutoLoginPaused),
        security_login_resumed_at: job.securityLoginResumedAt || null,
        login_checkpoint_available: Boolean(job.loginCheckpointAvailable),
        login_auto_retry_count: Number(job.loginAutoRetryCount || 0),
        proxy_risk_retry_count: Number(job.proxyRiskRetryCount || 0),
        proxy_connection_failure_count: Number(job.proxyConnectionFailureCount || 0),
        proxy_configured: Boolean(job.proxyUrl),
        sms_provider_id: job.smsProviderId || null,
        sms_provider_name: job.smsProviderName || null,
        sms_service_label: job.smsServiceLabel || null,
        sms_order_id: job.smsOrderId || null,
        sms_number: job.smsNumber || null,
        sms_status: job.smsStatus || null,
        last_auth_automated: Boolean(job.lastAuthAutomated),
        last_auth_automation_reason: job.lastAuthAutomationReason || null,
        last_auth_automated_at: job.lastAuthAutomatedAt || null,
        last_auth_requirements: job.lastAuthRequirements || null,
        auto_repair_blocked: Boolean(job.autoRepairBlocked),
        auto_repair_blocked_reason: job.autoRepairBlockedReason || null,
        auto_repair_blocked_at: job.autoRepairBlockedAt || null,
        auto_repair_last_attempt_at: job.autoRepairLastAttemptAt || null,
        auto_repair_last_success_at: job.autoRepairLastSuccessAt || null,
        auto_repair_last_error: job.autoRepairLastError || null,
        auto_repair_pending_account_ids: job.autoRepairPendingAccountIds || [],
        auto_repair_pending_backend: job.autoRepairPendingBackend || null,
        updated_at: new Date().toISOString(),
      };
}

async function saveJobMetadata(job) {
  if (job.deleted) return;
  job.pendingMetadataWrites = (job.pendingMetadataWrites || 0) + 1;
  job.metadataWritePromise = (job.metadataWritePromise || Promise.resolve())
    .catch(() => {})
    .then(async () => {
      if (job.deleted) return;
      const metadataPath = path.join(path.dirname(job.outputPath), JOB_META_FILENAME);
      const data = jobMetadata(job);
      if (!serverDatabase.saveJob(job.id, data)) return;
      serverDatabase.saveLogs(job.id, job.logs || "");
      const tempPath = `${metadataPath}.${process.pid}.${crypto.randomUUID()}.tmp`;
      await fs.writeFile(tempPath, `${JSON.stringify(data, null, 2)}\n`, { mode: 0o600 });
      await fs.rename(tempPath, metadataPath);
    }).finally(() => { job.pendingMetadataWrites -= 1; });
  return job.metadataWritePromise;
}

async function saveStoredLoginCredentials(email, credentials = {}) {
  const password = typeof credentials.password === "string" ? credentials.password : "";
  const totpSecret = credentials.totpSecret ? normalizeTotpSecret(credentials.totpSecret) : "";
  const proxyUrl = credentials.proxyUrl ? normalizeProxyUrl(credentials.proxyUrl) : "";
  if (!password && !totpSecret && !proxyUrl) {
    await deleteStoredLoginCredentials(email);
    return true;
  }
  try {
    serverDatabase.saveCredentials(email, { password, totpSecret, proxyUrl });
  } catch (error) {
    if (error?.status === 501) return false;
    throw error;
  }
  return true;
}

async function loadStoredLoginCredentials(email) {
  try {
    const data = serverDatabase.loadCredentials(email);
    return {
      password: typeof data.password === "string" ? data.password : "",
      totpSecret: data.totpSecret ? normalizeTotpSecret(data.totpSecret) : "",
      proxyUrl: data.proxyUrl ? normalizeProxyUrl(data.proxyUrl) : null,
    };
  } catch {
    throw new Error("登录凭据无法从服务器数据库恢复，已停止操作");
  }
}

async function deleteStoredLoginCredentials(email) {
  serverDatabase.deleteCredentials(email);
}

async function loadMailboxBaseline(job) {
  try {
    const candidates = await fetchMailboxOtpCandidates(mailApiUrlForJob(job), {
      request: mailRequestForJob(job),
    });
    candidates.forEach((candidate) => job.mailSeenCandidateKeys.add(candidate.key));
    job.mailStatus = "ready";
    job.mailApiError = null;
    appendJobLog(job, `[mail] 已记录收码接口中的 ${candidates.length} 个旧邮件验证码标识，等待新邮件。\n`);
  } catch (error) {
    job.mailStatus = "error";
    job.mailApiError = safeMailError(error);
    appendJobLog(job, `[mail] 首次读取收码接口失败：${job.mailApiError}\n`);
  }
  touch(job);
}

async function beginMailPolling(job) {
  if (!mailApiUrlForJob(job) || job.mailPollRunning || job.status !== "email_otp") return;
  job.mailPollRunning = true;
  job.mailStatus = "polling";
  job.mailApiError = null;
  const pollToken = crypto.randomUUID();
  const startedAt = Date.now();
  job.mailPollToken = pollToken;
  touch(job);

  try {
    while (
      job.mailPollToken === pollToken &&
      job.status === "email_otp" &&
      job.child &&
      Date.now() - startedAt < MAIL_POLL_TIMEOUT_MS
    ) {
      try {
        const candidates = filterMailboxOtpCandidatesByRequestTime(
          await fetchMailboxOtpCandidates(mailApiUrlForJob(job), {
            request: mailRequestForJob(job),
          }),
          job.mailOtpRequestedAt,
        );
        if (job.mailPollToken !== pollToken || job.status !== "email_otp" || !job.child) return;
        const unseen = candidates.filter((candidate) => !job.mailSeenCandidateKeys.has(candidate.key));
        let fresh = unseen.find((candidate) => candidate.score >= 12);
        if (!fresh) {
          unseen.forEach((candidate) => {
            job.mailCandidateCounts.set(candidate.key, (job.mailCandidateCounts.get(candidate.key) || 0) + 1);
          });
          fresh = unseen.find((candidate) => (job.mailCandidateCounts.get(candidate.key) || 0) >= 2);
        }
        job.mailApiError = null;
        if (fresh) {
          job.mailSeenCandidateKeys.add(fresh.key);
          job.mailCandidateCounts.delete(fresh.key);
          job.mailStatus = "found";
          markAuthorizationRequirement(job, "emailOtp");
          markAuthorizationAutomatic(job, "emailOtp");
          job.parserTail = "";
          appendJobLog(job, "[mail] 已从收码接口自动取得新验证码并提交。\n");
          setStage(job, "working", "已自动获取邮箱验证码，正在验证");
          job.child.stdin.write(`${fresh.code}\n`);
          return;
        }
      } catch (error) {
        if (job.mailPollToken !== pollToken) return;
        job.mailStatus = "error";
        job.mailApiError = safeMailError(error);
        touch(job);
      }
      await delay(MAIL_POLL_INTERVAL_MS);
    }

    if (job.mailPollToken === pollToken && job.status === "email_otp") {
      job.mailStatus = "timeout";
      job.mailApiError = "自动收码等待超时，请手动输入或重新发送";
      job.prompt = "自动收码等待超时，请手动输入邮箱验证码";
      touch(job);
    }
  } finally {
    if (job.mailPollToken === pollToken) {
      job.mailPollRunning = false;
      job.mailPollToken = null;
      touch(job);
    }
  }
}

function stopMailPolling(job) {
  if (!job.mailApiUrl) return;
  job.mailPollToken = null;
  job.mailPollRunning = false;
  if (job.mailStatus === "polling") job.mailStatus = "stopped";
}

function appendJobLog(job, text) {
  job.logs = `${job.logs}${sanitizeLog(text)}`.slice(-MAX_LOG_CHARS);
  if (!job.deleted) serverDatabase.saveLogs(job.id, job.logs);
}

function safeMailError(error) {
  const message = String(error?.message || "读取收码接口失败");
  return message.replace(/https?:\/\/\S+/gi, "<已隐藏接口地址>").slice(0, 180);
}

function isPlainObject(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function sharedText(value, maximum = 4096) {
  if (typeof value !== "string" && typeof value !== "number" && value != null) throw httpError(400, "配置字段必须是文本");
  const text = String(value ?? "");
  if (text.length > maximum) throw httpError(400, "配置字段过长");
  return text;
}

function normalizeSharedSettings(section, value) {
  if (!["proxyLibrary", "sms", "mail", "sub2api"].includes(section)) throw httpError(400, "配置类型无效");
  if (!isPlainObject(value) || Buffer.byteLength(JSON.stringify(value)) > 512 * 1024) throw httpError(400, "配置内容格式不正确或超过大小限制");
  if (section === "proxyLibrary") {
    if (!Array.isArray(value.proxies) || value.proxies.length > 500) throw httpError(400, "代理列表最多保存 500 条");
    const ids = new Set();
    const proxies = value.proxies.map((entry) => {
      if (!isPlainObject(entry)) throw httpError(400, "代理列表格式不正确");
      const id = sharedText(entry.id, 128);
      if (!id || id === "direct" || !/^[a-zA-Z0-9_-]+$/.test(id) || ids.has(id)) throw httpError(400, "代理标识无效或重复");
      ids.add(id);
      if (entry.dynamicProfileId) {
        const profile = dynamicProxies.profiles().find((value) => value.id === entry.dynamicProfileId);
        if (!profile) throw httpError(400, "动态代理配置不存在");
        return { id, name: profile.name, dynamicProfileId: profile.id };
      }
      const url = normalizeProxyUrl(sharedText(entry.url, 8192));
      if (!url) throw httpError(400, "代理地址不能为空");
      return { id, name: sharedText(entry.name, 80).trim() || "未命名代理", url };
    });
    const selectedId = sharedText(value.selectedId, 128);
    if (selectedId && selectedId !== "direct" && !ids.has(selectedId)) throw httpError(400, "所选代理已删除，请重新选择");
    return { proxies, selectedId };
  }
  if (section === "sms") {
    if (!isPlainObject(value.configs)) throw httpError(400, "接码平台配置格式不正确");
    const definitions = publicSmsProviderDefinitions();
    const selectedProviderId = sharedText(value.selectedProviderId, 40);
    if (!definitions.some((provider) => provider.id === selectedProviderId)) throw httpError(400, "接码平台无效");
    const configs = {};
    for (const [providerId, config] of Object.entries(value.configs)) {
      const definition = definitions.find((provider) => provider.id === providerId);
      if (!definition || !isPlainObject(config)) throw httpError(400, "接码平台配置格式不正确");
      configs[providerId] = {};
      for (const [field, text] of Object.entries(config)) {
        if (!definition.fields.some((entry) => entry.key === field)) throw httpError(400, "接码平台配置字段无效");
        configs[providerId][field] = sharedText(text, field === "entries" ? 400_000 : 8192);
      }
    }
    return { selectedProviderId, configs };
  }
  if (section === "mail") {
    const headersText = typeof value.headersText === "string" ? sharedText(value.headersText, 65536) : JSON.stringify(value.headers || {});
    let headers;
    try { headers = JSON.parse(headersText || "{}"); } catch { throw httpError(400, "邮件请求头必须是有效的 JSON 对象"); }
    const method = sharedText(value.method || "GET", 10).toUpperCase();
    const url = sharedText(value.url, 8192).trim();
    const normalized = normalizeMailRequestConfig({ method, url, headers });
    return { method: normalized.method, url, headersText: JSON.stringify(normalized.headers, null, 2) };
  }
  const result = {};
  for (const field of ["baseUrl", "adminApiKey", "proxyId", "concurrency", "loadFactor", "priority", "modelWhitelist"]) {
    result[field] = sharedText(value[field], field === "modelWhitelist" ? 42000 : 8192);
  }
  if (!Array.isArray(value.groupIds) || value.groupIds.length > 500) throw httpError(400, "目标号池列表格式不正确");
  result.groupIds = [...new Set(value.groupIds.map((id) => sharedText(id, 20)))];
  result.codexFingerprintMode = sharedText(value.codexFingerprintMode || "session", 20);
  result.monitorEnabled = value.monitorEnabled === true;
  if (result.baseUrl || result.adminApiKey || result.monitorEnabled) normalizeSub2ApiConfig(result);
  else if (!["off", "device", "session", "full"].includes(result.codexFingerprintMode)) throw httpError(400, "Codex 指纹收敛模式无效");
  return result;
}

function hasSharedSettingsValue(section, value) {
  if (section === "proxyLibrary") return value.proxies.length > 0 || value.selectedId === "direct";
  if (section === "sms") return Object.values(value.configs).some((config) => Boolean(config.apiKey?.trim() || config.entries?.trim()));
  if (section === "mail") return Boolean(value.url || Object.keys(JSON.parse(value.headersText)).length || value.method === "POST");
  return Boolean(value.baseUrl || value.adminApiKey);
}

function applySharedMailSettings(value) {
  mailRequestConfig = normalizeMailRequestConfig({ method: value.method, url: value.url, headers: JSON.parse(value.headersText || "{}") });
}

async function applySharedSettings(section, value) {
  if (section === "mail") applySharedMailSettings(value);
  if (section === "sub2api") {
    sub2ApiMonitorConfig = value.monitorEnabled ? { ...normalizeSub2ApiConfig(value), enabled: true } : null;
    sub2ApiMonitorState.lastError = null;
    await persistSub2ApiMonitorConfiguration();
    scheduleSub2ApiMonitor();
  }
}

function normalizeMailRequestConfig(value) {
  const config = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const method = String(config.method || "GET").trim().toUpperCase();
  if (!["GET", "POST"].includes(method)) throw httpError(400, "邮件接码请求方式只支持 GET 或 POST");

  const sourceHeaders = config.headers == null ? {} : config.headers;
  if (!sourceHeaders || typeof sourceHeaders !== "object" || Array.isArray(sourceHeaders)) {
    throw httpError(400, "邮件接码请求头必须是 JSON 对象");
  }
  const entries = Object.entries(sourceHeaders);
  if (entries.length > MAX_MAIL_REQUEST_HEADERS) {
    throw httpError(400, `邮件接码请求头最多配置 ${MAX_MAIL_REQUEST_HEADERS} 项`);
  }
  const headers = {};
  for (const [rawName, rawValue] of entries) {
    const name = String(rawName || "").trim().toLowerCase();
    if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name)) throw httpError(400, `无效的请求头名称：${rawName}`);
    if (FORBIDDEN_MAIL_REQUEST_HEADERS.has(name)) throw httpError(400, `请求头 ${rawName} 由请求库自动管理，不能手动配置`);
    if (typeof rawValue !== "string" && typeof rawValue !== "number" && typeof rawValue !== "boolean") {
      throw httpError(400, `请求头 ${rawName} 的值必须是文本或数字`);
    }
    const headerValue = String(rawValue);
    if (/\r|\n/.test(headerValue)) throw httpError(400, `请求头 ${rawName} 不能包含换行符`);
    if (Buffer.byteLength(headerValue) > 8 * 1024) throw httpError(400, `请求头 ${rawName} 的值过长`);
    headers[name] = headerValue;
  }

  const url = String(config.url || "").trim();
  if (method === "POST" && !validateMailApiUrl(url)) {
    throw httpError(400, "POST 邮件接码模式必须配置有效的 HTTP 或 HTTPS 请求 URL");
  }
  return { method, url: validateMailApiUrl(url) ? url : null, headers };
}

function mailRequestForJob(job) {
  return {
    method: mailRequestConfig.method,
    headers: mailRequestConfig.headers,
    body: mailRequestConfig.method === "POST" ? job.mailRequestBody || "" : "",
  };
}

function mailApiUrlForJob(job) {
  return mailRequestConfig.method === "POST" && validateMailApiUrl(mailRequestConfig.url)
    ? mailRequestConfig.url
    : job.mailApiUrl;
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function sortNewestFirst(a, b) {
  return b.createdAt.localeCompare(a.createdAt);
}

async function fileExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function readJson(req, maximum = 1_000_000) {
  const chunks = [];
  let size = 0;
  if (Number(req.headers["content-length"]) > maximum) throw httpError(413, "Request body is too large");
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maximum) throw httpError(413, "Request body is too large");
    chunks.push(chunk);
  }
  try {
    const raw = Buffer.concat(chunks).toString("utf8");
    return raw ? JSON.parse(raw) : {};
  } catch {
    throw httpError(400, "Invalid JSON body");
  }
}

function sendJson(res, status, data) {
  if (res.headersSent) return;
  const body = JSON.stringify(data);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  res.end(body);
}

function httpError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

process.on("SIGINT", () => void shutdown().catch(reportShutdownFailure));
process.on("SIGTERM", () => void shutdown().catch(reportShutdownFailure));

async function shutdown() {
  if (shutdownPromise) return shutdownPromise;
  shutdownPromise = (async () => {
    shuttingDown = true;
    queueSchedulingPaused = true;
    await scheduledTasks?.close();
    clearInterval(dynamicTimer);
    await Promise.allSettled([dynamicProxies.close(), operationProxies.close(), dynamicCyclePromise]);
    await crsIntegration?.close();
    crsLoginBridge?.close();
    if (sub2ApiMonitorTimer) {
      clearInterval(sub2ApiMonitorTimer);
      sub2ApiMonitorTimer = null;
    }
    for (const controller of sub2ApiRequestControllers) controller.abort();
    await Promise.allSettled([
      sub2ApiMonitorPromise,
      ...sub2ApiRequestPromises,
      ...sub2ApiAutoRepairPromises,
    ].filter(Boolean));
    const activeJobs = [...jobs.values()].filter((job) => isActive(job.status));
    const childWaits = activeJobs
      .map((job) => job.child)
      .filter(Boolean)
      .map((child) => waitForChildExit(child, 3_000));
    await Promise.allSettled(activeJobs.map((job) => cancelJob(job)));
    await Promise.allSettled([
      ...childWaits,
      ...[...jobs.values()].map((job) => job.metadataWritePromise).filter(Boolean),
    ]);
    await vite.close();
    await closeHttpServer(server);
    serverDatabase.close();
  })();
  return shutdownPromise;
}

function waitForChildExit(child, timeoutMs) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolve) => {
    let timer;
    const finish = () => {
      clearTimeout(timer);
      resolve();
    };
    child.once("close", finish);
    timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish();
    }, timeoutMs);
  });
}

function closeHttpServer(httpServer) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      httpServer.closeAllConnections?.();
      resolve();
    }, 3_000);
    httpServer.close(() => {
      clearTimeout(timer);
      resolve();
    });
  });
}

function reportShutdownFailure(error) {
  console.error(`[shutdown] ${error.message}`);
  process.exitCode = 1;
}
