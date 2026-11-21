import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { createServerDatabase } from "../src/server-database.mjs";
import { getAccountTls } from "../src/account-tls.mjs";
import { TlsFingerprintTransport } from "../src/tls-transport.mjs";

function parseHello(record) {
  let i = 9;
  const version = record.readUInt16BE(i); i += 34;
  i += 1 + record[i];
  const cipherLength = record.readUInt16BE(i); i += 2;
  const ciphers = [];
  for (const end = i + cipherLength; i < end; i += 2) ciphers.push(record.readUInt16BE(i));
  i += 1 + record[i];
  const length = record.readUInt16BE(i); i += 2;
  const extensions = [], groups = [], formats = [];
  for (const end = i + length; i < end;) {
    const type = record.readUInt16BE(i), size = record.readUInt16BE(i + 2); i += 4;
    extensions.push(type);
    if (type === 10) for (let j = i + 2; j < i + size; j += 2) groups.push(record.readUInt16BE(j));
    if (type === 11) formats.push(...record.subarray(i + 1, i + size));
    i += size;
  }
  const noGrease = (values) => values.filter((v) => (v & 0x0f0f) !== 0x0a0a);
  const order = noGrease(extensions);
  const ja3 = [version, noGrease(ciphers).join("-"), order.join("-"), noGrease(groups).join("-"), formats.join("-")].join(",");
  const normalized = [version, noGrease(ciphers).join("-"), [...order].sort((a, b) => a - b).join("-"), noGrease(groups).join("-"), formats.join("-")].join(",");
  return { order, normalized, hash: crypto.createHash("md5").update(ja3).digest("hex") };
}

const outputRoot = await fs.mkdtemp(path.join(os.tmpdir(), "tls-wire-"));
const database = createServerDatabase({ outputRoot });
const captures = [];
const server = net.createServer((socket) => {
  let bytes = Buffer.alloc(0);
  socket.on("data", (chunk) => {
    bytes = Buffer.concat([bytes, chunk]);
    if (bytes.length >= 5 && bytes.length >= 5 + bytes.readUInt16BE(3)) {
      captures.push(parseHello(bytes));
      socket.destroy();
    }
  });
  socket.on("error", () => {});
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
try {
  const results = [];
  let baseline;
  for (const account of [null, "alice", "bob", "carol"]) {
    const accountTls = account ? getAccountTls(database, `${account}@example.test`) : null;
    const samples = [];
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const transport = new TlsFingerprintTransport({ profile: "chrome152_macos", accountTls, cloudflareSolver: false });
      try {
        const before = captures.length;
        await assert.rejects(transport.request("GET", `https://localhost:${server.address().port}/`, { timeoutMs: 3000 }), /SSL|connect|reset|EOF|closed/i);
        assert.equal(captures.length, before + 1, "capture exactly one real ClientHello");
        const hello = captures.at(-1);
        baseline ||= hello.normalized;
        assert.equal(hello.normalized, baseline, "account configuration must retain the native template handshake parameters");
        samples.push(hello.hash);
      } finally { await transport.close(); }
    }
    assert.ok(new Set(samples).size > 1, "native Chrome must permute extensions across fresh connections");
    if (accountTls) assert.deepEqual(getAccountTls(database, `${account}@example.test`), accountTls, "browser configuration remains persistent while handshake order varies");
    results.push({ account: account || "native-template", distinctJa3: new Set(samples).size });
  }
  console.log(JSON.stringify({ fullClientHelloCaptures: captures.length, nativeTemplateMatch: true, persistentBrowserConfiguration: true, results }));
} finally {
  await new Promise((resolve) => server.close(resolve));
  database.close();
  await fs.rm(outputRoot, { recursive: true, force: true });
}
