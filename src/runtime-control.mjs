import http from "node:http";
import { readFileSync, writeFileSync, renameSync, openSync, closeSync, fsyncSync } from "node:fs";
import path from "node:path";
import { authenticateBridge } from "./crs-login-bridge.mjs";

// Standby never opens the database or restores the shared working directory.
export async function awaitRuntimeActivation({ host, port, secret, enabled, activationFile = process.env.TOSUB2_ACTIVATION_FILE }) {
  if (!enabled) return;
  if (!secret) throw new Error("待命启动需要 CRS_LOGIN_BRIDGE_KEY");
  if (!activationFile || !path.isAbsolute(activationFile)) throw new Error("待命启动需要独立的绝对激活标记路径");
  const marker = "tosub2-runtime-activated-v1\n";
  try {
    if (readFileSync(activationFile, "utf8") !== marker) throw new Error("激活标记无效");
    return;
  } catch (error) { if (error.code !== "ENOENT") throw error; }
  await new Promise((resolve, reject) => {
    let activating = false;
    const server = http.createServer((req, res) => {
      try {
        authenticateBridge(req.headers.authorization, secret);
        const url = new URL(req.url, "http://localhost");
        if (url.pathname === "/api/integrations/crs/runtime/status" && req.method === "GET") return send(200, { mode: "standby", ready: true, databaseOpened: false });
        if (url.pathname === "/api/integrations/crs/runtime/activate" && req.method === "POST" && !activating) {
          // The deployment owns a unique control directory for this candidate.
          // Persist before acknowledging so the same container can restart active.
          writeFileSync(`${activationFile}.tmp`, marker, { mode: 0o600 });
          const file = openSync(`${activationFile}.tmp`, "r");
          try { fsyncSync(file); } finally { closeSync(file); }
          renameSync(`${activationFile}.tmp`, activationFile);
          const directory = openSync(path.dirname(activationFile), "r");
          try { fsyncSync(directory); } finally { closeSync(directory); }
          activating = true;
          send(202, { mode: "activating" });
          server.close(resolve);
          server.closeIdleConnections?.();
          return;
        }
        send(409, { error: "实例尚未激活" });
      } catch (error) { send(error.status || 500, { error: error.status ? error.message : "待命请求失败" }); }
      function send(status, value) { res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", connection: "close" }); res.end(JSON.stringify(value)); }
    });
    server.once("error", reject);
    server.listen(port, host);
  });
}
