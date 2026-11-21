// Disposable local QA fixture: synthetic accounts, credentials and CRS only.
import http from "node:http";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
const root = await fs.mkdtemp(path.join(os.tmpdir(), "tosub2-guardian-ui-"));
const port = 43927;
const base = `http://127.0.0.1:${port}`;
const mock = http.createServer(async (req, res) => {
  for await (const chunk of req) { void chunk; }
  const groups = [{ id: "openai", name: "OpenAI", enabled: true }, { id: "special", name: "专用账号", enabled: true }];
  const data = req.url.startsWith("/api/admin/account-groups/options") ? { items: groups, page: { totalPages: 1 } } : req.method === "POST" ? { taskId: "local-qa-task" } : { items: [{ status: "succeeded", accountIds: ["synthetic-crs-account"] }], finishedAt: new Date().toISOString() };
  res.writeHead(req.method === "POST" ? 202 : 200, { "content-type": "application/json" }); res.end(JSON.stringify({ code: 200, data }));
});
await new Promise((resolve) => mock.listen(0, "127.0.0.1", resolve));
const child = spawn(process.execPath, ["src/console-server.mjs", "--port", String(port)], { env: { ...process.env, ONBOARDING_OUTPUT_ROOT: root, ONBOARDING_PROTOCOL_SCRIPT: path.resolve("test/mock-crs-bridge-protocol.mjs"), TOSUB2_TLS_PROFILE: "chrome142", TOSUB2_CONSOLE_TOKEN: "test-stable-console-token-123456789", CRS_LOGIN_BRIDGE_KEY: "local-ui-service-key" }, stdio: ["ignore", "ignore", "pipe"] });
const headers = { "content-type": "application/json", "x-console-token": "test-stable-console-token-123456789" };
for (let n = 0; n < 100; n += 1) {
  try { if ((await fetch(`${base}/api/bootstrap`)).ok) break; } catch {}
  await new Promise((resolve) => setTimeout(resolve, 100));
}
await fetch(`${base}/api/crs/config`, { method: "PUT", headers, body: JSON.stringify({ revision: 0, config: { baseUrl: `http://127.0.0.1:${mock.address().port}`, authType: "apiKey", apiKey: "local-ui-mock-key", autoUpload: false } }) });
for (const email of ["account-one@example.com", "account-two@example.com"]) await fetch(`${base}/api/jobs`, { method: "POST", headers, body: JSON.stringify({ email, password: "test-password" }) });
console.log(`Synthetic UI fixture ready: ${base}`);
let stopping = false;
async function stop() {
  if (stopping) return; stopping = true;
  if (child.exitCode === null) { const exited = new Promise((resolve) => child.once("exit", resolve)); child.kill("SIGTERM"); await exited; }
  await new Promise((resolve) => mock.close(resolve));
  await fs.rm(root, { recursive: true, force: true });
  process.exit(0);
}
process.on("SIGTERM", () => void stop());
process.on("SIGINT", () => void stop());
