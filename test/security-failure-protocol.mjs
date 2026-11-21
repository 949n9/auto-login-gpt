import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const privateValue = "synthetic-private-value-do-not-log";
const account = "synthetic-security@example.invalid";
const tls = {version:2,account,profile:"chrome152_macos",mode:"native",id:crypto.createHash("sha256").update(`account-tls-v2:${account}:chrome152_macos:native`).digest("hex")};
const temporary = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),"security-failure-cli-")));

async function fixture(name, {missingDependency = false} = {}) {
  const directory = path.join(temporary,name);
  await fs.mkdir(directory);
  for (const file of ["protocol-login.mjs","security-failure.mjs",...(missingDependency ? [] : ["account-tls.mjs","login-totp.mjs","account-security.mjs","email-login-retry.mjs","operation-pacing.mjs","server-database.mjs"])]) {
    await fs.copyFile(path.join(root,"src",file),path.join(directory,file));
  }
  if (!missingDependency) {
    // Protocol control flow remains real. The cookie and transport seams cannot
    // touch the network, making both preflight and login failures deterministic.
    await fs.writeFile(path.join(directory,"login-cookies.mjs"),'export class CookieJar { toJSON() { return []; } headerFor() { return ""; } static fromJSON() { return new CookieJar(); } }\n');
    await fs.writeFile(path.join(directory,"tls-transport.mjs"),`
export { assertSocks5Proxy, browserIdentityForTlsProfile } from ${JSON.stringify(path.join(root,"src/tls-transport.mjs"))};
export function shouldUseTlsTransport() { return true; }
export class TlsFingerprintTransport {
  constructor() { this.enabled=true; this.profile=this.identityProfile="chrome152_macos"; }
  async prepareProxy() { if(process.env.SYNTHETIC_PHASE === "proxy_preflight") throw new Error("curl: (97) User was rejected by the SOCKS5 server: " + process.env.SYNTHETIC_PRIVATE); }
  async fetch() { throw Object.assign(new Error("HTTP 429 " + process.env.SYNTHETIC_PRIVATE),{httpStatus:429}); }
  async close() {}
}
`);
  }
  return directory;
}

function invoke(directory, overrides={}) {
  const env={...process.env};
  for (const key of Object.keys(env)) if (/^(?:ONBOARDING_|CHATGPT_|TOSUB2_|AUTH_BASE$)/.test(key)) delete env[key];
  Object.assign(env,{CHATGPT_PROXY_URL:"socks5://127.0.0.1:9",TOSUB2_ACCOUNT_TLS:JSON.stringify(tls),CHATGPT_LOGIN_PASSWORD:privateValue,CHATGPT_TOTP_SECRET:"JBSWY3DPEHPK3PXP",SYNTHETIC_PRIVATE:privateValue,...overrides});
  const result=spawnSync(process.execPath,[path.join(directory,"protocol-login.mjs"),"--email",account,"--security-action","rotate-totp-logout-all","--security-result",path.join(directory,"private-result.json"),"--security-operation-id","11111111-1111-4111-8111-111111111111"],{encoding:"utf8",env,timeout:10000});
  assert.equal(result.status,1,result.stderr);
  const combined=result.stdout+result.stderr;
  assert.ok(!combined.includes(privateValue),"raw exception or environment credential was printed");
  assert.ok(!combined.includes("[error]"),"generic raw-error path must not run for security operations");
  const lines=combined.split(/\r?\n/).filter(line=>line.startsWith("[security-failure] "));
  assert.equal(lines.length,1,combined);
  return JSON.parse(lines[0].slice("[security-failure] ".length));
}

try {
  const normal=await fixture("normal");
  const missing=await fixture("missing",{missingDependency:true});
  await test("missing imports use the security marker without an uncaught raw stack",()=>{
    const result=invoke(missing);
    assert.equal(result.code,"DEPENDENCY_UNAVAILABLE");
    assert.equal(result.phase,"initialization");
    assert.equal(result.mutationStarted,false);
  });
  await test("database initialization failure is classified before any transport is started",()=>{
    const result=invoke(normal,{ONBOARDING_DATABASE_PATH:path.join(temporary,"missing-db","test.sqlite3"),ONBOARDING_OUTPUT_ROOT:path.join(temporary,"missing-db")});
    assert.equal(result.code,"DATABASE_UNAVAILABLE");
    assert.equal(result.phase,"initialization");
    assert.equal(result.journalPresent,false);
  });
  await test("invalid SOCKS configuration stops before preflight",()=>{
    const result=invoke(normal,{CHATGPT_PROXY_URL:"http://127.0.0.1:9"});
    assert.equal(result.code,"SOCKS5_REQUIRED");
    assert.equal(result.phase,"initialization");
  });
  await test("TLS identity failure never prints the supplied identity",()=>{
    const result=invoke(normal,{TOSUB2_ACCOUNT_TLS:JSON.stringify({...tls,profile:privateValue})});
    assert.equal(result.code,"TLS_CONFIGURATION_INVALID");
    assert.equal(result.phase,"initialization");
  });
  await test("SOCKS preflight exception is retained as a safe authentication category",()=>{
    const result=invoke(normal,{SYNTHETIC_PHASE:"proxy_preflight"});
    assert.equal(result.code,"PROXY_AUTH_FAILED");
    assert.equal(result.phase,"proxy_preflight");
    assert.equal(result.mutationStarted,false);
    assert.equal(result.journalPresent,false);
  });
  await test("website login error remains distinct from the security mutation phase",()=>{
    const result=invoke(normal,{SYNTHETIC_PHASE:"login"});
    assert.equal(result.code,"HTTP_RATE_LIMITED");
    assert.equal(result.phase,"login");
    assert.equal(result.httpStatus,429);
    assert.equal(result.mutationStarted,false);
    assert.equal(result.journalPresent,false);
  });
  assert.equal(await fs.stat(path.join(normal,"private-result.json")).catch(()=>null),null,"no security mutation result should have been created");
} finally {
  await fs.rm(temporary,{recursive:true,force:true});
}
