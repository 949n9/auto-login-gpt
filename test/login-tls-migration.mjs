import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// Exercise the real CLI resolver, stopping at worker configuration before any
// request or credential submission can occur. Run in the offline test container.
const root = await fs.mkdtemp(path.join(os.tmpdir(), "login-tls-migration-"));
try {
  const capture = path.join(root, "configure.json");
  const fakePython = path.join(root, "fake-python");
  await fs.writeFile(fakePython, `#!/usr/bin/env python3
import json, os, sys
if len(sys.argv) > 1 and sys.argv[1] == "-c":
    sys.exit(0)
for line in sys.stdin:
    message = json.loads(line)
    with open(os.environ["TLS_TEST_CAPTURE"], "w") as stream:
        json.dump(message, stream)
    print(json.dumps({"id": message["id"], "error": "SYNTHETIC_CONFIGURE_STOP"}), flush=True)
    break
`, { mode: 0o700 });
  const script = fileURLToPath(new URL("../src/protocol-login.mjs", import.meta.url));
  const email = "migration@example.test";
  for (const profile of ["chrome146", "chrome152"]) {
    const extensions = [0, 5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51, 17613, 65037, 65281];
    if (profile === "chrome152") extensions.push(51764);
    const extensionOrder = extensions.join("-");
    const identity = { version: 1, account: email, profile, extensionOrder,
      id: crypto.createHash("sha256").update(`${profile}:${extensionOrder}`).digest("hex") };
    const env = { ...process.env, TOSUB2_PYTHON: fakePython, TLS_TEST_CAPTURE: capture,
      TOSUB2_ACCOUNT_TLS: JSON.stringify(identity), TOSUB2_TLS_PROFILE: profile,
      ONBOARDING_OUTPUT_ROOT: root, CHATGPT_PROXY_URL: "", CHATGPT_LOGIN_PASSWORD: "" };
    delete env.ONBOARDING_DATABASE_PATH;
    const result = spawnSync(process.execPath, [script, "--email", email], { env, encoding: "utf8", timeout: 15000 });
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, /SYNTHETIC_CONFIGURE_STOP/);
    const message = JSON.parse(await fs.readFile(capture, "utf8"));
    assert.equal(message.operation, "configure");
    assert.equal(message.impersonate, "chrome152_macos");
    assert.equal(message.strictProfile, true);
    assert.equal(Object.hasOwn(message, "extensionOrder"), false);
    await fs.rm(capture);
    const conflict = spawnSync(process.execPath, [script, "--email", email, "--tls-profile", "chrome152"], { env, encoding: "utf8", timeout: 15000 });
    assert.equal(conflict.status, 1);
    assert.match(conflict.stderr, /profile conflicts/);
    await assert.rejects(fs.stat(capture), { code: "ENOENT" });
    const bypass = spawnSync(process.execPath, [script, "--email", email, "--native-http"], { env, encoding: "utf8", timeout: 15000 });
    assert.equal(bypass.status, 1);
    assert.match(bypass.stderr, /requires the macOS TLS transport/);
    await assert.rejects(fs.stat(capture), { code: "ENOENT" });
  }
  console.log("CLI legacy identity migration, conflicting profile and native-HTTP bypass checks passed; no requests sent");
} finally { await fs.rm(root, { recursive: true, force: true }); }
