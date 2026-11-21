import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { runAccountSecurity } from "../src/account-security.mjs";
import { TlsFingerprintTransport } from "../src/tls-transport.mjs";

const secret = "JBSWY3DPEHPK3PXP";
const account = "security-test@example.invalid";
async function fixture(options = {}) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "security-protocol-test-"));
  const resultPath = path.join(directory, "result.json");
  let factor = "old-factor", credentialSaved = false, counter = 0;
  const calls = [], journal = [];
  const token = () => `header.${Buffer.from(JSON.stringify({pwd_auth_time:Date.now()-(options.stale?300000:0),"https://api.openai.com/mfa":{required:"yes"}})).toString("base64url")}.signature`;
  const client = {
    transport:{enabled:true,requireSocks5:true,configuredProxy:"socks5://127.0.0.1:1080"},
    async pauseBeforeOperation(stage) { calls.push({method:"WAIT",endpoint:stage}); await options.onPause?.(stage); },
    async request(method,url,requestOptions) {
      const endpoint = new URL(url).pathname;
      calls.push({method,endpoint,body:requestOptions.json});
      assert.equal(requestOptions.retryRiskControl,false,"mutations must never be automatically replayed");
      let data, status = 200;
      if(endpoint==="/api/auth/session") data={user:{id:"user-test",email:options.wrongAccount?"other@example.invalid":account},account:{id:"account-test"},accessToken:token()};
      else {
        assert.equal(requestOptions.headers["ChatGPT-Account-ID"],"account-test");
        if(endpoint.endsWith("security_settings/info")) { data={advanced_protection_mode_enabled:Boolean(options.protection)}; status=options.protectionStatus||200; }
        else if(endpoint.endsWith("mfa_info")) data={mfa_enabled_v2:Boolean(factor),factors:{totp:factor?[{id:factor,factor_type:"totp"}]:[]}};
        else if(endpoint.endsWith("disable_in_house")) { factor=null; data={success:true}; }
        else if(endpoint.endsWith("mfa/enroll")) {
          if(options.enrollFailure) throw new Error("timeout token=do-not-echo");
          data={secret,session_id:"enrollment-test"};
        } else if(endpoint.endsWith("activate_enrollment")) {
          const durable=JSON.parse(await fs.readFile(resultPath,"utf8"));
          assert.equal(durable.secret,secret);
          assert.equal(durable.stage,"activation_requested");
          assert(journal.some(r=>r.secret===secret&&r.stage==="enrolled"));
          assert.match(requestOptions.json.code,/^\d{6}$/);
          factor="new-factor";
          if(options.activationTimeout)throw new Error("timeout bearer=do-not-echo");
          data={success:true};
        } else if(endpoint.endsWith("flora/workspace/reset")) {
          assert.equal(requestOptions.headers["X-OpenAI-Expected-Account-Id"],"account-test");
          assert.equal(requestOptions.json,undefined);
          if(options.action!=="logout-all")assert.equal(credentialSaved,true);
          if(options.workResetFailure)throw new Error(typeof options.workResetFailure === "string" ? options.workResetFailure : "timeout sensitive=do-not-echo");
          status=options.workResetStatus||200;
          if(Object.hasOwn(options,"workResetText"))return {res:{status},text:options.workResetText};
          data=Object.hasOwn(options,"workResetBody")?options.workResetBody:{success:true};
        } else if(endpoint.endsWith("logout_all")) {
          const durable=JSON.parse(await fs.readFile(resultPath,"utf8"));
          assert.equal(durable.work_reset_succeeded || durable.work_reset_unavailable,true);
          if(options.workResetStatus===404){
            assert.equal(durable.work_reset_succeeded,false,"a missing Work endpoint must not be recorded as a successful reset");
            assert.equal(durable.work_reset_unavailable,true);
            assert(journal.some(r=>r.work_reset_unavailable===true),"the unavailable record must be durable before logout");
          }
          if(options.action!=="logout-all")assert.equal(credentialSaved,true,"new key must be saved before logout");
          assert.equal(requestOptions.json,undefined);
          counter++;
          if(options.logoutTimeout) throw new Error("timeout proxy=do-not-echo");
          status=options.logoutStatus||200;
          data=Object.hasOwn(options,"logoutBody")?options.logoutBody:{success:true};
        } else throw new Error(`Unexpected path ${endpoint}`);
      }
      return {res:{status},text:JSON.stringify(data)};
    },
  };
  const args={client,email:account,action:options.action||"rotate-totp",operationId:crypto.randomUUID(),resultPath,deviceId:"device-test",persist:r=>journal.push(structuredClone(r)),persistVerifiedCredentials:async r=>{assert.equal(r.mfa_verified,true);if(options.saveFailure)throw new Error("database unavailable");credentialSaved=true;}};
  return {args,calls,journal,read:async()=>JSON.parse(await fs.readFile(resultPath,"utf8")),countLogout:()=>counter,cleanup:()=>fs.rm(directory,{recursive:true,force:true})};
}
test("SOCKS5 enforcement blocks missing/HTTP/native transport before any network",async()=>{
  assert.throws(()=>new TlsFingerprintTransport({enabled:false,requireSocks5:true}),/SOCKS5_REQUIRED/);
  const transport=new TlsFingerprintTransport({requireSocks5:true});
  for(const proxy of [null,"","http://127.0.0.1:8080"]){await assert.rejects(()=>transport.configure(proxy),/SOCKS5_REQUIRED/);await assert.rejects(()=>transport.prepareProxy(proxy,"https://chatgpt.com"),/SOCKS5_REQUIRED/);}
  await assert.rejects(()=>transport.send({operation:"request",url:"https://chatgpt.com"}),/SOCKS5_REQUIRED/);
  transport.configuredProxy="socks5://127.0.0.1:1080";
  await assert.rejects(()=>transport.send({operation:"probe_profiles",url:"https://chatgpt.com"}),/SOCKS5_REQUIRED/);
  assert.equal(transport.child,null);
});
for(const [label,options,pattern] of [["wrong account",{wrongAccount:true},/IDENTITY_MISMATCH/],["stale authentication",{stale:true},/REAUTH_REQUIRED/],["advanced protection",{protection:true},/ADVANCED_PROTECTION/]]){
  test(`${label} blocks all mutations`,async()=>{const f=await fixture(options);try{await assert.rejects(()=>runAccountSecurity(f.args),pattern);assert.equal(f.calls.filter(c=>c.method==="POST").length,0);assert.equal((await f.read()).status,"failed");}finally{await f.cleanup();}});
}
test("rotate verifies and durably stores a new key without logging out",async()=>{const f=await fixture();try{const r=await runAccountSecurity(f.args);assert.equal(r.status,"completed");assert.equal(r.secret,secret);assert.equal(r.mfa_verified,true);assert.equal(r.credentials_saved,true);assert.equal(f.countLogout(),0);assert.deepEqual(f.calls.filter(c=>c.method==="POST").map(c=>c.endpoint.split("/").at(-1)),["disable_in_house","enroll","activate_enrollment"]);assert.equal((await fs.stat(f.args.resultPath)).mode&0o777,0o600);await assert.rejects(()=>runAccountSecurity(f.args),/ALREADY_STARTED/);}finally{await f.cleanup();}});
test("logout action resets Work first, never changes MFA and records accepted revocation",async()=>{const f=await fixture({action:"logout-all"});try{const r=await runAccountSecurity(f.args);assert.equal(r.logout_accepted,true);assert.equal(r.work_reset_succeeded,true);assert.equal(r.effectMayTakeMinutes,30);assert.deepEqual(f.calls.filter(c=>c.method==="POST").map(c=>c.endpoint),["/backend-api/flora/workspace/reset","/backend-api/accounts/logout_all"]);assert.equal(f.countLogout(),1);}finally{await f.cleanup();}});
test("combined action saves verified credentials before the one logout request",async()=>{const f=await fixture({action:"rotate-totp-logout-all"});try{const r=await runAccountSecurity(f.args);assert.equal(r.logout_accepted,true);assert.equal(r.credentials_saved,true);assert.equal(r.mfa_verified,true);assert.equal(f.countLogout(),1);}finally{await f.cleanup();}});
test("pacing stays before rotation and after saved credentials, outside the unprotected MFA window",async()=>{
  const f=await fixture({action:"rotate-totp-logout-all",onPause:async(stage)=>{
    if(stage==="logout_all"){
      const saved=await f.read();
      assert.equal(saved.mfa_verified,true);
      assert.equal(saved.credentials_saved,true);
      assert.equal(saved.stage,"verified");
    }
  }});
  try{
    await runAccountSecurity(f.args);
    const actions=f.calls.filter(c=>c.method!=="GET").map(c=>c.endpoint.split("/").at(-1));
    assert.deepEqual(actions,["rotate_totp","disable_in_house","enroll","activate_enrollment","logout_all","reset","logout_all"]);
    assert.equal(f.calls.at(-1).endpoint,"/backend-api/accounts/logout_all");
  }finally{await f.cleanup();}
});
test("rotation rechecks authentication freshness after the pacing delay",async()=>{
  let elapsed=0;
  const f=await fixture({onPause:async()=>{elapsed=240001;}});
  f.args.now=()=>Date.now()+elapsed;
  try{
    await assert.rejects(()=>runAccountSecurity(f.args),/SECURITY_REAUTH_REQUIRED/);
    assert.equal(f.calls.filter(c=>c.method==="POST").length,0);
  }finally{await f.cleanup();}
});
test("HTTP 200 with JSON null completes logout without any subsequent account request",async()=>{const f=await fixture({action:"rotate-totp-logout-all",logoutBody:null});try{const r=await runAccountSecurity(f.args);assert.equal(r.status,"completed");assert.equal(r.logout_accepted,true);assert(Number.isFinite(Date.parse(r.logoutAcceptedAt)));assert.equal(f.calls.at(-1).endpoint,"/backend-api/accounts/logout_all");assert.equal(f.countLogout(),1);}finally{await f.cleanup();}});
test("HTTP 200 with explicit failure still fails closed",async()=>{const f=await fixture({action:"logout-all",logoutBody:{success:false}});try{await assert.rejects(()=>runAccountSecurity(f.args),/SECURITY_API_FAILED/);assert.equal((await f.read()).logout_accepted,false);assert.equal(f.countLogout(),1);}finally{await f.cleanup();}});
test("combined credential-save failure never logs out",async()=>{const f=await fixture({action:"rotate-totp-logout-all",saveFailure:true});try{await assert.rejects(()=>runAccountSecurity(f.args));assert.equal(f.countLogout(),0);const r=await f.read();assert.equal(r.status,"needs_attention");assert.equal(r.mfa_verified,true);assert.equal(r.secret,secret);}finally{await f.cleanup();}});
test("failed Work reset prevents logout while preserving the already verified new 2FA",async()=>{const f=await fixture({action:"rotate-totp-logout-all",workResetFailure:true});try{await assert.rejects(()=>runAccountSecurity(f.args));assert.equal(f.countLogout(),0);const r=await f.read();assert.equal(r.mfa_verified,true);assert.equal(r.credentials_saved,true);assert.equal(r.work_reset_succeeded,false);assert.equal(r.stage,"work_reset_requested");}finally{await f.cleanup();}});
for(const options of [{enrollFailure:true},{activationTimeout:true},{action:"rotate-totp-logout-all",logoutTimeout:true}]){
  test(`uncertain mutation retains journal and is never retried: ${Object.keys(options).join(",")}`,async()=>{const f=await fixture(options);try{await assert.rejects(()=>runAccountSecurity(f.args));const r=await f.read();assert.equal(r.status,"needs_attention");assert(!r.error.includes("do-not-echo"));if(!options.enrollFailure)assert.equal(r.secret,secret);if(options.logoutTimeout){assert.equal(r.mfa_verified,true);assert.equal(r.credentials_saved,true);assert.equal(f.countLogout(),1);}await assert.rejects(()=>runAccountSecurity(f.args),/ALREADY_STARTED/);}finally{await f.cleanup();}});
}

for (const action of ["logout-all", "rotate-totp-logout-all"]) {
  for (const workResetText of [JSON.stringify({ detail: "Not Found" }), "<html>Not Found</html>", ""]) {
    test(`definite Work HTTP 404 continues ${action} without claiming reset success: ${workResetText ? "body" : "empty"}`, async () => {
      const f = await fixture({ action, workResetStatus: 404, workResetText });
      try {
        const result = await runAccountSecurity(f.args);
        assert.equal(result.status, "completed");
        assert.equal(result.work_reset_succeeded, false);
        assert.equal(result.work_reset_unavailable, true);
        assert.equal(result.logout_accepted, true);
        assert.equal(f.countLogout(), 1);
        assert.equal(f.calls.at(-1).endpoint, "/backend-api/accounts/logout_all");
        if (action !== "logout-all") { assert.equal(result.credentials_saved, true); assert.equal(result.mfa_verified, true); assert.equal(result.secret, secret); }
      } finally { await f.cleanup(); }
    });
  }
}
for (const options of [{ workResetStatus: 403 }, { workResetStatus: 500 }, { workResetBody: { success: false } }, { workResetText: "invalid json" }, { workResetFailure: "HTTP 404 from an uncertain failed connection" }]) {
  test(`Work failures other than an actual 404 still stop before logout: ${JSON.stringify(options)}`, async () => {
    const f = await fixture({ action: "rotate-totp-logout-all", ...options });
    try {
      await assert.rejects(() => runAccountSecurity(f.args));
      const result = await f.read();
      assert.equal(result.status, "needs_attention"); assert.equal(result.stage, "work_reset_requested");
      assert.equal(result.work_reset_unavailable, false); assert.equal(result.work_reset_succeeded, false);
      assert.equal(result.mfa_verified, true); assert.equal(result.credentials_saved, true); assert.equal(result.secret, secret);
      assert.equal(f.countLogout(), 0);
    } finally { await f.cleanup(); }
  });
}
test("HTTP 404 on a different security endpoint does not activate Work compatibility", async () => {
  const f = await fixture({ action: "rotate-totp-logout-all", protectionStatus: 404 });
  try {
    await assert.rejects(() => runAccountSecurity(f.args), /SECURITY_API_FAILED/);
    assert.equal((await f.read()).work_reset_unavailable, false);
    assert.equal(f.calls.filter(c=>c.method==="POST").length, 0);
  } finally { await f.cleanup(); }
});
for (const options of [{ logoutStatus: 404 }, { logoutTimeout: true }, { logoutBody: { success: false } }]) {
  test(`skipping missing Work does not hide an unsuccessful logout: ${JSON.stringify(options)}`, async () => {
    const f = await fixture({ action: "rotate-totp-logout-all", workResetStatus: 404, ...options });
    try {
      await assert.rejects(() => runAccountSecurity(f.args));
      const result = await f.read();
      assert.equal(result.status, "needs_attention"); assert.equal(result.stage, "logout_requested");
      assert.equal(result.work_reset_unavailable, true); assert.equal(result.work_reset_succeeded, false); assert.equal(result.logout_accepted, false);
      assert.equal(result.mfa_verified, true); assert.equal(result.credentials_saved, true); assert.equal(result.secret, secret); assert.equal(f.countLogout(), 1);
      await assert.rejects(() => runAccountSecurity(f.args), /ALREADY_STARTED/);
      assert.equal(f.countLogout(), 1);
    } finally { await f.cleanup(); }
  });
}
