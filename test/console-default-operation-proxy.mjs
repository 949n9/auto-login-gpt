import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { pathToFileURL } from "node:url";
import { createServerDatabase } from "../src/server-database.mjs";

const projectRoot = path.resolve(import.meta.dirname, "..");
const temporary = await fs.mkdtemp(path.join(os.tmpdir(), "console-default-proxy-"));
const outputRoot = path.join(temporary, "jobs");
const observationsPath = path.join(temporary, "workers.jsonl");
const extractionPath = path.join(temporary, "extractions.jsonl");
const loader = path.join(temporary, "loader.mjs");
const preload = path.join(temporary, "preload.mjs");
const protocol = path.join(temporary, "protocol.mjs");
const operationUrl = pathToFileURL(path.join(projectRoot, "src/operation-proxy.mjs")).href;
const selectedProxy = "socks5h://8.8.8.8:1080";
const staticProxy = "socks5h://synthetic-user:synthetic-secret@proxy.example.invalid:1080";
const fixtureModule = `
import fs from "node:fs/promises";
import {createOperationProxies as actual} from ${JSON.stringify(`${operationUrl}?fixture-actual`)};
export function createOperationProxies(options) {
  const instance = actual({...options,
    extract: async ({email,operationId}) => {
      await fs.appendFile(process.env.PROXY_FIXTURE_EXTRACTIONS, JSON.stringify({email,operationId})+"\\n");
      if (email.startsWith("unknown-")) throw new Error("synthetic provider failure");
      return "8.8.8.8:1080";
    },
    probe: async (_proxy,{email}) => ({success:true,country:email.startsWith("wrong-country-")?"GB":"US",ip:"8.8.4.4"})
  });
  const ensure = instance.ensure.bind(instance);
  instance.ensure = async (input) => {
    const result = await ensure(input);
    // Shorten only this fixture lease so the real console expiry timer is exercised.
    if (input.email.startsWith("expiring-")) return {...result,expiresAt:new Date(Date.now()+1800).toISOString()};
    return result;
  };
  return instance;
}
`;
await fs.writeFile(loader, `export async function load(url,context,nextLoad) {
  if(url===${JSON.stringify(operationUrl)}) return {format:"module",shortCircuit:true,source:${JSON.stringify(fixtureModule)}};
  return nextLoad(url,context);
}`);
await fs.writeFile(preload, `import {register} from "node:module";register(${JSON.stringify(pathToFileURL(loader).href)},import.meta.url);`);
await fs.writeFile(protocol, `
import fs from "node:fs/promises";
import {createServerDatabase} from ${JSON.stringify(pathToFileURL(path.join(projectRoot,"src/server-database.mjs")).href)};
const args=process.argv.slice(2), email=args[args.indexOf("--email")+1];
const action=args.includes("--security-action")?args[args.indexOf("--security-action")+1]:args.includes("--refresh-sub2api")?"refresh":args.includes("--setup-totp")?"totp":"login";
const entry={email,action,proxy:process.env.CHATGPT_PROXY_URL,pin:process.env.TOSUB2_PIN_PROXY_SESSION,requireSocks:process.env.TOSUB2_REQUIRE_SOCKS5,maxAttempts:process.env.CHATGPT_PROXY_MAX_ATTEMPTS};
await fs.appendFile(process.env.PROXY_FIXTURE_OBSERVATIONS,JSON.stringify(entry)+"\\n");
if(email==="schedule-phases@example.invalid" && action==="logout-all") {
  const now=new Date().toISOString();
  const result={version:1,operationId:args[args.indexOf("--security-operation-id")+1],email,action,status:"completed",stage:"logout_requested",startedAt:now,updatedAt:now,work_reset_succeeded:true,logout_accepted:true,logoutAcceptedAt:now};
  const db=createServerDatabase({databasePath:process.env.ONBOARDING_DATABASE_PATH,outputRoot:process.env.ONBOARDING_OUTPUT_ROOT,mustExist:true});
  try{db.put("security-operation-result",result.operationId,result);await fs.writeFile(args[args.indexOf("--security-result")+1],JSON.stringify(result));}finally{db.close();}
  process.exit(0);
}
if(email.startsWith("auto-retry-")) {
  const rows=(await fs.readFile(process.env.PROXY_FIXTURE_OBSERVATIONS,"utf8")).trim().split("\\n").map(JSON.parse).filter(row=>row.email===email);
  if(rows.length===1) {console.log("[error] temporary upstream connection failure");process.exit(1);}
}
if(action==="refresh") {console.log("REFRESH_TOKEN_INVALID");}
else console.log("Email OTP (r=resend, q=quit):");
await new Promise(resolve=>{const timer=setTimeout(resolve,60000);process.once("SIGTERM",()=>{clearTimeout(timer);resolve();});});
`);
const socket = net.createServer();
await new Promise(resolve => socket.listen(0, "127.0.0.1", resolve));
const port = socket.address().port;
await new Promise(resolve => socket.close(resolve));
const base = `http://127.0.0.1:${port}`;
let child, exited, headers, logs = "";
const remote=http.createServer((req,res)=>{res.writeHead(200,{"content-type":"application/json"});res.end(JSON.stringify({code:200,data:{items:[{id:"synthetic-group",name:"OpenAI",enabled:true}],page:{totalPages:1}}}));});
await new Promise(resolve=>remote.listen(0,"127.0.0.1",resolve));
try {
  await start(true);
  const boot = await get("/api/bootstrap");
  assert.deepEqual(boot.features.defaultOperationProxy, {configured:true,provider:"1024-white",country:"US",label:"1024 美国动态代理"});
  await post("/api/jobs/preview", {text:"preview@example.invalid"});
  const recorded = (await post("/api/jobs", {email:"recorded@example.invalid",password:"synthetic-password",proxyUrl:{useDefaultProxy:true},startLogin:false},201)).job;
  const configured=await fetch(`${base}/api/crs/config`,{method:"PUT",headers,body:JSON.stringify({revision:0,config:{baseUrl:`http://127.0.0.1:${remote.address().port}`,authType:"apiKey",apiKey:"synthetic-key",autoUpload:false}})});
  assert.equal(configured.status,200);
  const scheduled = scheduleInput("schedule@example.invalid");
  assert.equal((await post("/api/schedules/preview",scheduled)).validCount,1);
  const plan = await post("/api/schedules",scheduled,201);
  assert.equal((await extracts()).length,0,"preview, save-only and future schedule must not consume a lease");
  await post(`/api/schedules/${plan.schedule.id}/cancel`,{});

  const phasesInput={...scheduleInput("schedule-phases@example.invalid",4000),securityAction:"logout-all",prepareLeadMinutes:30};
  const phases=await post("/api/schedules",phasesInput,201);
  await worker("schedule-phases@example.invalid","logout-all");
  await worker("schedule-phases@example.invalid","login");
  const phaseExtractions=(await extracts()).filter(row=>row.email==="schedule-phases@example.invalid");
  assert.equal(phaseExtractions.length,2,"scheduled safety preparation and later login are distinct operations");
  assert.notEqual(phaseExtractions[0].operationId,phaseExtractions[1].operationId);
  await post(`/api/schedules/${phases.schedule.id}/cancel`,{});

  const first = (await post("/api/jobs", {email:"default@example.invalid",password:"synthetic-password"},201)).job;
  await worker(first.email);
  const firstMetadata = metadata(first.id);
  assert.equal(firstMetadata.operation_proxy_mode,"default");
  assert.match(firstMetadata.operation_proxy_id,/^[a-f0-9-]{36}$/);
  const observed = (await workers()).find(row=>row.email===first.email);
  assert.deepEqual([observed.proxy,observed.pin,observed.requireSocks,observed.maxAttempts],[selectedProxy,"1","1","0"]);
  await post("/api/jobs", {email:first.email,password:"synthetic-password",proxyUrl:{useDefaultProxy:true}});
  await post("/api/jobs/batch", {text:first.email,proxyUrl:{useDefaultProxy:true}},201);
  assert.equal(metadata(first.id).operation_proxy_id,firstMetadata.operation_proxy_id,"duplicate active import must retain the lease identity");
  assert.equal(metadata(first.id).operation_proxy_expires_at,firstMetadata.operation_proxy_expires_at);
  assert.equal((await extracts()).filter(row=>row.email===first.email).length,1);
  await cancel(first);
  await post(`/api/jobs/${first.id}/relogin`,{proxyUrl:{useStoredProxy:true}},409);
  await post(`/api/jobs/${first.id}/relogin`,{});
  await waitFor(async()=> (await workers()).filter(row=>row.email===first.email).length===2);
  assert.notEqual(metadata(first.id).operation_proxy_id,firstMetadata.operation_proxy_id,"an explicit new login must create a new operation");
  await cancel(first);

  const mixed = await post("/api/jobs/batch",{text:"mixed-default@example.invalid\nmixed-static@example.invalid\nmixed-direct@example.invalid",proxyAssignments:[
    {email:"mixed-default@example.invalid",proxyUrl:{useDefaultProxy:true}},
    {email:"mixed-static@example.invalid",proxyUrl:staticProxy},
    {email:"mixed-direct@example.invalid",proxyUrl:""}
  ]},201);
  for(const job of mixed.jobs) await worker(job.email);
  const mixedRows = await workers();
  assert.equal(mixedRows.find(row=>row.email==="mixed-static@example.invalid").proxy,staticProxy);
  assert.equal(mixedRows.find(row=>row.email==="mixed-direct@example.invalid").proxy,"");
  assert.equal((await extracts()).filter(row=>row.email.startsWith("mixed-")).length,1);
  for(const job of mixed.jobs) await cancel(job);

  const retry = (await post("/api/jobs",{email:"auto-retry-once@example.invalid",password:"synthetic-password"},201)).job;
  await waitFor(async()=> (await workers()).filter(row=>row.email===retry.email).length===2);
  assert.equal((await extracts()).filter(row=>row.email===retry.email).length,1,"automatic login retry must reuse one extraction");
  const retryRows=(await workers()).filter(row=>row.email===retry.email);
  assert.equal(retryRows[0].proxy,retryRows[1].proxy);
  await cancel(retry);

  const failed = (await post("/api/jobs",{email:"wrong-country-failure@example.invalid",password:"synthetic-password"},201)).job;
  await waitFor(async()=> (await job(failed.id)).status==="failed");
  assert.equal((await workers()).some(row=>row.email===failed.email),false,"wrong-country result must stop before worker launch");
  const unknown=(await post("/api/jobs",{email:"unknown-failure@example.invalid",password:"synthetic-password"},201)).job;
  await waitFor(async()=> (await job(unknown.id)).status==="failed");
  assert.equal((await extracts()).filter(row=>row.email===unknown.email).length,1);
  assert.equal((await workers()).some(row=>row.email===unknown.email),false);

  const expiring = (await post("/api/jobs",{email:"expiring-running@example.invalid",password:"synthetic-password"},201)).job;
  await worker(expiring.email);
  const expiryIdentity=metadata(expiring.id).operation_proxy_id;
  await post("/api/jobs",{email:expiring.email,password:"synthetic-password",proxyUrl:{useDefaultProxy:true}});
  await waitFor(async()=> (await job(expiring.id)).status==="failed");
  assert.match((await job(expiring.id)).lastError,/租期/);
  assert.equal(metadata(expiring.id).operation_proxy_id,expiryIdentity);
  assert.equal((await extracts()).filter(row=>row.email===expiring.email).length,1,"expired operation must not rotate silently");

  const security = await post(`/api/jobs/${recorded.id}/security`,{action:"logout-all"});
  await worker(recorded.email,"logout-all");
  const securityMetadata=metadata(recorded.id);
  assert.equal(securityMetadata.operation_proxy_id,security.operation.operationId);
  await post("/api/jobs",{email:recorded.email,password:"changed",proxyUrl:{useDefaultProxy:true}},409);
  assert.equal(metadata(recorded.id).operation_proxy_id,securityMetadata.operation_proxy_id,"rejected update must preserve security lease");
  assert.equal(metadata(recorded.id).operation_proxy_expires_at,securityMetadata.operation_proxy_expires_at);
  await cancel(recorded);

  await post(`/api/jobs/${first.id}/proxy`,{proxyUrl:staticProxy});
  assert.equal(metadata(first.id).operation_proxy_mode,"explicit");
  await post(`/api/jobs/${first.id}/relogin`,{proxyUrl:{useStoredProxy:true}});
  await waitFor(async()=> (await workers()).filter(row=>row.email===first.email&&row.proxy===staticProxy).length===1);
  await cancel(first);

  const completed=await seedCompleted("refresh@example.invalid");
  await waitFor(async()=> (await job(completed.id)));
  await post(`/api/jobs/${completed.id}/regenerate`,{});
  await worker(completed.email,"login");
  assert.deepEqual((await workers()).filter(row=>row.email===completed.email).map(row=>row.action),["refresh","login"]);
  assert.equal((await extracts()).filter(row=>row.email===completed.email).length,1,"refresh fallback must keep the same lease");
  await cancel(completed);

  const bridgeHeaders={authorization:"Bearer synthetic-bridge-key","content-type":"application/json"};
  for(const [suffix,proxyUrl,expected] of [["default",null,selectedProxy],["direct","",""],["static",staticProxy,staticProxy]]) {
    const email=`bridge-${suffix}@example.invalid`;
    const response=await request("/api/integrations/crs/login",{operationId:`bridge-${suffix}`,email,password:"synthetic-password",proxyUrl},202,bridgeHeaders);
    await worker(email);
    assert.equal((await workers()).find(row=>row.email===email).proxy,expected);
    await post(`/api/jobs/${response.jobId}/cancel`,{});
  }
  assert.equal((await extracts()).filter(row=>row.email.startsWith("bridge-")).length,1,"bridge null alone must resolve to default");
  const beforeRestart=(await extracts()).length;
  await stop();
  await start(true);
  await post(`/api/jobs/${expiring.id}/relogin`,{proxyUrl:{useStoredProxy:true}},409);
  await post(`/api/jobs/${unknown.id}/relogin`,{proxyUrl:{useStoredProxy:true}},409);
  assert.equal((await extracts()).length,beforeRestart,"restart must not extract or replay unknown operations");
  await stop();
  await start(false);
  assert.equal((await get("/api/bootstrap")).features.defaultOperationProxy.configured,false);
  await post(`/api/jobs/${first.id}/relogin`,{proxyUrl:{useDefaultProxy:true}},409);
  console.log("console default operation proxy: import, preview, schedules, pinned login, retry/fallback, lease expiry, security, bridge, explicit overrides and restart passed");
} catch(error) {error.message+=`\nConsole output:\n${logs}`;throw error;}
finally {await stop();await new Promise(resolve=>remote.close(resolve));await fs.rm(temporary,{recursive:true,force:true});}

async function start(enabled) {
  child=spawn(process.execPath,["--import",preload,path.join(projectRoot,"src/console-server.mjs"),"--host","127.0.0.1","--port",String(port)],{cwd:projectRoot,env:{...process.env,ONBOARDING_OUTPUT_ROOT:outputRoot,ONBOARDING_PROTOCOL_SCRIPT:protocol,TOSUB2_MAC_CREDENTIAL_ROOT:path.join(temporary,"credentials"),TOSUB2_TLS_PROFILE:"chrome142",TOSUB2_LOGIN_RETRY_DELAY_MS:"10",TOSUB2_DEFAULT_OPERATION_PROXY_ENABLED:enabled?"1":"0",PROXY_FIXTURE_EXTRACTIONS:extractionPath,PROXY_FIXTURE_OBSERVATIONS:observationsPath,CRS_LOGIN_BRIDGE_KEY:"synthetic-bridge-key"},stdio:["ignore","pipe","pipe"]});
  exited=new Promise(resolve=>child.once("exit",resolve));
  child.stdout.on("data",chunk=>{logs=`${logs}${chunk}`.slice(-12000);});child.stderr.on("data",chunk=>{logs=`${logs}${chunk}`.slice(-12000);});
  const bootstrap=await waitFor(async()=>{try{const response=await fetch(`${base}/api/bootstrap`);return response.ok?response.json():null;}catch{return null;}});
  headers={"content-type":"application/json","x-console-token":bootstrap.token};
}
async function stop(){if(!child||child.exitCode!==null||child.signalCode!==null)return;child.kill("SIGTERM");const timer=setTimeout(()=>child.kill("SIGKILL"),5000);await exited;clearTimeout(timer);}
async function get(endpoint){const response=await fetch(`${base}${endpoint}`,{headers});assert.equal(response.status,200);return response.json();}
async function request(endpoint,body,status=200,requestHeaders=headers){const response=await fetch(`${base}${endpoint}`,{method:"POST",headers:requestHeaders,body:JSON.stringify(body)});const value=await response.json();assert.equal(response.status,status,`${endpoint}: ${JSON.stringify(value)}`);return value;}
async function post(...args){return request(...args);}
async function job(id){return(await get("/api/jobs")).jobs.find(entry=>entry.id===id);}
async function cancel(value){await post(`/api/jobs/${value.id}/cancel`,{});await waitFor(async()=>["canceled","failed","completed","ready"].includes((await job(value.id)).status));}
async function rows(file){return(await fs.readFile(file,"utf8").catch(()=>"")).trim().split("\n").filter(Boolean).map(JSON.parse);}
async function workers(){return rows(observationsPath);}
async function extracts(){return rows(extractionPath);}
async function worker(email,action="login"){return waitFor(async()=> (await workers()).find(row=>row.email===email&&row.action===action));}
function metadata(id){const db=createServerDatabase({outputRoot,mustExist:true});try{return db.getJob(id);}finally{db.close();}}
async function waitFor(probe){const deadline=Date.now()+12000;while(Date.now()<deadline){if(child?.exitCode!==null&&child?.exitCode!==undefined)throw new Error("console exited early");const value=await probe();if(value)return value;await new Promise(resolve=>setTimeout(resolve,40));}throw new Error("condition timed out");}
function scheduleInput(email,ahead=3600_000){const future=new Date(Date.now()+ahead+8*3600_000).toISOString().slice(0,19);return{clientRequestId:crypto.randomUUID(),name:"synthetic future schedule",text:`${email}----synthetic-password`,scheduledLocal:future,prepareLeadMinutes:0,postLogoutDelayMinutes:0,securityAction:null,proxyUrl:{useDefaultProxy:true}};}
async function seedCompleted(email){const id=crypto.randomUUID(),directory=path.join(outputRoot,id);await fs.mkdir(directory);const value={version:1,email,status:"completed"};const artifact={type:"sub2api-data",version:1,accounts:[{credentials:{email,refresh_token:"synthetic-refresh"}}]};const db=createServerDatabase({outputRoot,mustExist:true});try{db.saveJob(id,value);db.saveCredentials(email,{password:"synthetic-password",totpSecret:"",proxyUrl:""});db.saveArtifact(path.join(directory,"sub2api-import-oauth.json"),artifact);}finally{db.close();}await fs.writeFile(path.join(directory,"job-meta.json"),JSON.stringify(value));await fs.writeFile(path.join(directory,"sub2api-import-oauth.json"),JSON.stringify(artifact));return{id,email};}
