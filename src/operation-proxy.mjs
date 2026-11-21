import https from "node:https";
import { isIP } from "node:net";
import { TlsFingerprintTransport } from "./tls-transport.mjs";

const KIND = "operation-proxy";
const TTL_MS = 10 * 60_000;
const MAX_BODY_BYTES = 4096;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
export const WHITE_OPERATION_PROXY_ENDPOINT = process.env.TOSUB2_OPERATION_PROXY_URL || "https://white.1024proxy.com/white/api?region=US&num=1&time=10&format=1&type=txt";
const TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace";
const messages = Object.freeze({
  OPERATION_PROXY_DISABLED: "默认操作代理未启用",
  OPERATION_PROXY_INVALID: "操作代理的账号或操作编号无效",
  OPERATION_PROXY_BOUND: "该代理操作编号已绑定其他账号",
  OPERATION_PROXY_EXTRACT_FAILED: "默认代理提取失败，已停止本次操作",
  OPERATION_PROXY_PROBE_FAILED: "默认代理未通过美国 SOCKS5 出口验证，已停止本次操作",
  OPERATION_PROXY_UNKNOWN: "本次代理提取结果需要核实，未重复提取或更换出口",
  OPERATION_PROXY_EXPIRED: "本次操作代理已过期，未自动更换出口",
  OPERATION_PROXY_CLOSED: "操作代理服务正在关闭",
});
const failure = (code, status = 409) => Object.assign(new Error(messages[code]), { code, status });

function identity(email, operationId) {
  if (typeof email !== "string" || email.length > 320 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())
      || typeof operationId !== "string" || !UUID.test(operationId)) throw failure("OPERATION_PROXY_INVALID", 400);
  return { email: email.trim().toLowerCase(), operationId: operationId.toLowerCase() };
}

function publicIpv4(value) {
  if (isIP(value) !== 4) return false;
  const [a, b] = value.split(".").map(Number);
  return a !== 0 && a !== 10 && a !== 127 && a < 224
    && !(a === 169 && b === 254) && !(a === 172 && b >= 16 && b <= 31)
    && !(a === 192 && b === 168) && !(a === 100 && b >= 64 && b <= 127)
    && !(a === 198 && (b === 18 || b === 19));
}

export function parseOperationProxy(body) {
  if (typeof body !== "string" || Buffer.byteLength(body) > MAX_BODY_BYTES) throw failure("OPERATION_PROXY_EXTRACT_FAILED", 502);
  const match = /^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/.exec(body.trim());
  if (!match || !publicIpv4(match[1]) || Number(match[2]) < 1 || Number(match[2]) > 65535) {
    throw failure("OPERATION_PROXY_EXTRACT_FAILED", 502);
  }
  return `socks5h://${match[1]}:${Number(match[2])}`;
}

// Node HTTPS with a fresh direct agent never follows redirects or inherits an
// HTTP_PROXY/HTTPS_PROXY transport. The one request consumes at most one lease.
export function createWhiteOperationExtractor({ requestImpl = https.request,
  setTimeoutImpl = setTimeout, clearTimeoutImpl = clearTimeout } = {}) {
  return () => new Promise((resolve, reject) => {
    const agent = new https.Agent({ keepAlive: false });
    let settled = false;
    let deadline;
    const finish = (error, body) => {
      if (settled) return;
      settled = true;
      clearTimeoutImpl(deadline);
      agent.destroy();
      if (error) reject(failure("OPERATION_PROXY_EXTRACT_FAILED", 502));
      else resolve(body);
    };
    let request;
    try {
      deadline = setTimeoutImpl(() => { finish(true); request?.destroy(); }, 20_000);
      const endpoint = new URL(WHITE_OPERATION_PROXY_ENDPOINT);
      if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password || endpoint.hash) throw new Error("Invalid extraction endpoint");
      request = requestImpl(endpoint, {
        method: "GET", agent, headers: { accept: "text/plain", "accept-encoding": "identity" },
      }, (response) => {
        if (response.statusCode !== 200 || Number(response.headers["content-length"] || 0) > MAX_BODY_BYTES) {
          finish(true); response.destroy(); return;
        }
        let bytes = 0;
        const chunks = [];
        response.on("data", (chunk) => {
          bytes += chunk.length;
          if (bytes > MAX_BODY_BYTES) { finish(true); response.destroy(); return; }
          chunks.push(Buffer.from(chunk));
        });
        response.once("error", () => finish(true));
        response.once("aborted", () => finish(true));
        response.once("end", () => finish(false, Buffer.concat(chunks).toString("utf8")));
      });
      request.once("error", () => finish(true));
      request.setTimeout(20_000, () => { finish(true); request.destroy(); });
      request.end();
    } catch { finish(true); request?.destroy(); }
  });
}

export function createOperationExitProbe({ transportFactory = (options) => new TlsFingerprintTransport(options) } = {}) {
  return async (proxyUrl) => {
    const transport = transportFactory({ enabled: true, requireSocks5: true, pinProxySession: true,
      maxProxySessionAttempts: 0, sameProxyRiskRetries: 0, cloudflareSolver: false });
    try {
      if (!/^socks5h:\/\//.test(proxyUrl)) throw failure("OPERATION_PROXY_PROBE_FAILED", 502);
      await transport.configure(proxyUrl);
      const response = await transport.request("GET", TRACE_URL, { timeoutMs: 20_000, retryRiskControl: false });
      if (response.status !== 200 || response.headers.get("cf-mitigated") || response.headers.get("x-cf-mitigated")) {
        throw failure("OPERATION_PROXY_PROBE_FAILED", 502);
      }
      const body = await response.text();
      if (Buffer.byteLength(body) > MAX_BODY_BYTES) throw failure("OPERATION_PROXY_PROBE_FAILED", 502);
      const ips = [...body.matchAll(/^ip=([^\r\n]+)$/gm)];
      const countries = [...body.matchAll(/^loc=([^\r\n]+)$/gm)];
      if (ips.length !== 1 || countries.length !== 1 || !isIP(ips[0][1]) || countries[0][1] !== "US") {
        throw failure("OPERATION_PROXY_PROBE_FAILED", 502);
      }
      return { success: true, country: "US", ip: ips[0][1] };
    } catch { throw failure("OPERATION_PROXY_PROBE_FAILED", 502); }
    finally { await Promise.resolve().then(() => transport.close()).catch(() => {}); }
  };
}

export function createOperationProxies({ database, enabled = false,
  extract = createWhiteOperationExtractor(), probe = createOperationExitProbe(), now = Date.now } = {}) {
  const pending = new Map();
  let closed = false;
  const read = (id) => database.get(KIND, id);
  const write = (record) => database.put(KIND, record.operationId, record);
  function assertBinding(record, requested) {
    if (record.email !== requested.email || record.operationId !== requested.operationId) throw failure("OPERATION_PROXY_BOUND");
  }
  function reusable(record, requested) {
    assertBinding(record, requested);
    if (record.status !== "ready") throw failure("OPERATION_PROXY_UNKNOWN");
    if (!Number.isFinite(Date.parse(record.expiresAt)) || Date.parse(record.expiresAt) <= now()) throw failure("OPERATION_PROXY_EXPIRED");
    if (!/^socks5h:\/\//.test(record.proxyUrl || "") || record.exitCountry !== "US" || !isIP(record.exitIp || "")) {
      throw failure("OPERATION_PROXY_UNKNOWN");
    }
    return { email: record.email, operationId: record.operationId, proxyUrl: record.proxyUrl,
      expiresAt: record.expiresAt, exitIp: record.exitIp, exitCountry: record.exitCountry };
  }
  async function perform(requested) {
    if (closed) throw failure("OPERATION_PROXY_CLOSED", 503);
    const claim = database.transaction(() => {
      const existing = read(requested.operationId);
      if (existing) return { record: existing, owned: false };
      const createdAt = new Date(now()).toISOString();
      const record = { version: 1, ...requested, status: "sent", extractionCount: 1, createdAt,
        expiresAt: new Date(now() + TTL_MS).toISOString(), proxyUrl: null, exitIp: null, exitCountry: null, errorCode: null };
      write(record);
      return { record, owned: true };
    });
    if (!claim.owned) return reusable(claim.record, requested);
    let stage = "extract";
    try {
      const proxyUrl = parseOperationProxy(await extract({ ...requested }));
      database.transaction(() => {
        const current = read(requested.operationId);
        if (!current || current.status !== "sent") throw failure("OPERATION_PROXY_UNKNOWN");
        assertBinding(current, requested);
        write({ ...current, proxyUrl });
      });
      stage = "probe";
      const result = await probe(proxyUrl, { ...requested, expiresAt: claim.record.expiresAt });
      if (result?.success !== true || result.country !== "US" || !isIP(result.ip || "")) throw failure("OPERATION_PROXY_PROBE_FAILED", 502);
      if (Date.parse(claim.record.expiresAt) <= now()) throw failure("OPERATION_PROXY_EXPIRED");
      if (closed) throw failure("OPERATION_PROXY_CLOSED", 503);
      const ready = database.transaction(() => {
        const current = read(requested.operationId);
        if (!current || current.status !== "sent") throw failure("OPERATION_PROXY_UNKNOWN");
        assertBinding(current, requested);
        const next = { ...current, status: "ready", proxyUrl, exitIp: result.ip, exitCountry: "US", errorCode: null };
        write(next);
        return next;
      });
      return reusable(ready, requested);
    } catch (error) {
      const code = Object.hasOwn(messages, error?.code) ? error.code
        : stage === "probe" ? "OPERATION_PROXY_PROBE_FAILED" : "OPERATION_PROXY_EXTRACT_FAILED";
      try {
        database.transaction(() => {
          const current = read(requested.operationId);
          if (current?.status === "sent" && current.email === requested.email) write({ ...current, status: "unknown", errorCode: code });
        });
      } catch { /* A durable sent record still prohibits another extraction. */ }
      throw failure(code, error?.status === 409 ? 409 : 502);
    }
  }
  return {
    enabled: enabled === true,
    async ensure(input) {
      const requested = identity(input?.email, input?.operationId);
      if (enabled !== true) throw failure("OPERATION_PROXY_DISABLED");
      if (closed) throw failure("OPERATION_PROXY_CLOSED", 503);
      const existing = pending.get(requested.operationId);
      if (existing) { assertBinding(existing, requested); return existing.promise; }
      const promise = Promise.resolve().then(() => perform(requested));
      pending.set(requested.operationId, { ...requested, promise });
      try { return await promise; }
      catch (error) {
        if (Object.hasOwn(messages, error?.code)) throw failure(error.code, error.status || 409);
        throw failure("OPERATION_PROXY_UNKNOWN", 503);
      } finally { pending.delete(requested.operationId); }
    },
    status(email, operationId) {
      const requested = identity(email, operationId);
      const record = read(requested.operationId);
      if (!record) return null;
      assertBinding(record, requested);
      const expired = !Number.isFinite(Date.parse(record.expiresAt)) || Date.parse(record.expiresAt) <= now();
      return { operationId: record.operationId, status: record.status,
        usable: enabled === true && !closed && record.status === "ready" && !expired
          && /^socks5h:\/\//.test(record.proxyUrl || "") && record.exitCountry === "US" && Boolean(isIP(record.exitIp || "")),
        expiresAt: record.expiresAt, exitIp: record.exitIp || null, exitCountry: record.exitCountry || null,
        errorCode: record.errorCode || (expired ? "OPERATION_PROXY_EXPIRED" : null) };
    },
    activeOperations: () => pending.size,
    async close() {
      closed = true;
      await Promise.allSettled([...pending.values()].map((operation) => operation.promise));
    },
  };
}
