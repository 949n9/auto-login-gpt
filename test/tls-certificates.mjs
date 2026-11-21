import assert from "node:assert/strict";
import fs from "node:fs/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { TlsFingerprintTransport } from "../src/tls-transport.mjs";
import { ProtocolClient } from "../src/protocol-login.mjs";

const temp = await fs.mkdtemp(path.join(os.tmpdir(), "tls-certificate-"));
const key = path.join(temp, "key.pem"), cert = path.join(temp, "cert.pem");
const generated = spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-keyout", key, "-out", cert], { encoding: "utf8" });
assert.equal(generated.status, 0, generated.stderr);
const tls = https.createServer({ key: await fs.readFile(key), cert: await fs.readFile(cert) }, (req, res) => res.end("ok"));
const proxy = http.createServer();
const sockets = new Set();
proxy.on("connect", (req, client, head) => {
  const upstream = net.connect(tls.address().port, "127.0.0.1", () => {
    client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (head.length) upstream.write(head);
    upstream.pipe(client); client.pipe(upstream);
  });
  for (const socket of [client, upstream]) {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => { client.destroy(); upstream.destroy(); });
  }
});
const cookies = http.createServer((req, res) => {
  if (req.url === "/set") res.setHeader("set-cookie", "session=synthetic; Path=/");
  if (req.url === "/delete") res.setHeader("set-cookie", "session=deleted; Max-Age=0; Path=/");
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify({ cookie: req.headers.cookie || "" }));
});
const transports = [];
const previousCa = process.env.TOSUB2_CA_BUNDLE;
try {
  for (const server of [tls, proxy, cookies]) await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const target = `https://localhost:${tls.address().port}/`;
  const proxyUrl = `http://127.0.0.1:${proxy.address().port}`;
  delete process.env.TOSUB2_CA_BUNDLE;
  const untrusted = new TlsFingerprintTransport({ cloudflareSolver: false }); transports.push(untrusted);
  await untrusted.configure(proxyUrl);
  await assert.rejects(untrusted.request("GET", target), /certificate|self.signed|SSL peer/i);
  process.env.TOSUB2_CA_BUNDLE = cert;
  const trusted = new TlsFingerprintTransport({ cloudflareSolver: false }); transports.push(trusted);
  await trusted.configure(proxyUrl);
  assert.equal(await (await trusted.request("GET", target)).text(), "ok", "explicit CA is supported through local CONNECT proxy");
  const native = new TlsFingerprintTransport({ cloudflareSolver: false }); transports.push(native);
  const protocol = new ProtocolClient({ transport: native });
  const base = `http://127.0.0.1:${cookies.address().port}`;
  await protocol.getJson("GET", `${base}/set`);
  assert.equal((await protocol.getJson("GET", `${base}/echo`)).data.cookie, "session=synthetic");
  await protocol.getJson("GET", `${base}/delete`);
  assert.equal(protocol.jar.toJSON().length, 0);
  assert.equal((await protocol.getJson("GET", `${base}/echo`)).data.cookie, "", "deleted native cookies must not reappear");
  console.log("Local CONNECT certificate verification, explicit CA and native cookie deletion tests passed");
} finally {
  if (previousCa === undefined) delete process.env.TOSUB2_CA_BUNDLE;
  else process.env.TOSUB2_CA_BUNDLE = previousCa;
  for (const transport of transports) await transport.close();
  for (const socket of sockets) socket.destroy();
  for (const server of [tls, proxy, cookies]) await new Promise((resolve) => server.close(resolve));
  await fs.rm(temp, { recursive: true, force: true });
}
