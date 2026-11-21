// Browser regression uses only synthetic local accounts; login/security are blocked.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import http from 'node:http';
import {spawn} from 'node:child_process';

const root = path.resolve(import.meta.dirname, '..');
await fs.access(path.join(root, 'web/dist/index.html'));
const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'cpr-save-only-ui-'));
const pictures = path.join(root, 'ui-review-default-operation-proxy');
await fs.mkdir(pictures, {recursive: true});
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const prohibitedCalls = [];
const remote = http.createServer(async (request, response) => {
  for await (const _ of request) {}
  const pathname = new URL(request.url, 'http://127.0.0.1').pathname;
  let data;
  if (request.method === 'GET' && pathname === '/api/admin/account-groups/options') data = {items: [{id: 'openai', name: 'OpenAI', enabled: true}], page: {totalPages: 1}};
  else if (request.method === 'GET' && pathname === '/api/admin/proxies') data = {items: [], page: {page: 1, totalPages: 1}};
  else if (request.method === 'GET' && pathname === '/api/admin/system/version') data = {version: 'local-save-only-fixture'};
  else prohibitedCalls.push({method: request.method, pathname});
  response.writeHead(data ? 200 : 403, {'content-type': 'application/json'});
  response.end(JSON.stringify({code: data ? 200 : 403, data: data || {}}));
});
await new Promise(resolve => remote.listen(0, '127.0.0.1', resolve));
const listener = net.createServer();
await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
const port = listener.address().port;
await new Promise(resolve => listener.close(resolve));
const base = `http://127.0.0.1:${port}`;
const observations = path.join(temporary, 'prohibited-operations.jsonl');
const networkEvents = path.join(temporary, 'external-network.jsonl');
let server, browser, socket, serverLog = '', browserLog = '';
const results = {};
try {
  // An accidental scheduler start can only execute this no-network failure stub.
  const blockedProtocol = path.join(temporary, 'blocked-protocol.mjs');
  await fs.writeFile(blockedProtocol, `import fs from 'node:fs'; fs.appendFileSync(${JSON.stringify(observations)}, 'unexpected protocol execution\\n'); process.exitCode=91;\n`);
  // Even an unexpected background path cannot reach an upstream host.
  const networkGuard = path.join(temporary, 'local-network-only.mjs');
  await fs.writeFile(networkGuard, `import fs from 'node:fs'; import net from 'node:net';
const original=net.Socket.prototype.connect;
net.Socket.prototype.connect=function(...args){
 const first=Array.isArray(args[0])?args[0][0]:args[0];
 const host=first&&typeof first==='object'?first.host||first.hostname||'localhost':typeof args[1]==='string'?args[1]:'localhost';
 const isPipe=first&&typeof first==='object'?Boolean(first.path):typeof first==='string';
 if(isPipe||!['127.0.0.1','localhost','::1'].includes(host)){fs.appendFileSync(${JSON.stringify(networkEvents)},'blocked non-loopback connect\\n');throw Error('LOCAL_FIXTURE_EXTERNAL_NETWORK_BLOCKED');}
 return original.apply(this,args);
};\n`);
  const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(ONBOARDING_|CHATGPT_|TOSUB2_|CPR_|CRS_|SCHEDULE_|NODE_OPTIONS$|(?:ALL|HTTP|HTTPS|NO)_PROXY$|(?:all|http|https|no)_proxy$)/.test(key)));
  server = spawn(process.execPath, ['--import', networkGuard, 'src/console-server.mjs', '--host', '127.0.0.1', '--port', String(port)], {
    cwd: root,
    env: {...environment, NODE_ENV: 'production', ONBOARDING_OUTPUT_ROOT: path.join(temporary, 'data'), ONBOARDING_DATABASE_PATH: path.join(temporary, 'data/tosub2.sqlite3'), ONBOARDING_PROTOCOL_SCRIPT: blockedProtocol, CRS_LOGIN_BRIDGE_KEY: 'local-save-only-fixture'},
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  for (const stream of [server.stdout, server.stderr]) stream.on('data', bytes => {serverLog += bytes.toString();});
  let token;
  for (let attempt = 0; attempt < 120; attempt++) {
    try {token = (await (await fetch(base + '/api/bootstrap')).json()).token; if (token) break;} catch {}
    if (server.exitCode !== null) break;
    await wait(50);
  }
  assert.ok(token, 'Local fixture server unavailable: ' + serverLog.slice(-1200));
  const api = async (endpoint, body, method = body === undefined ? 'GET' : 'POST') => {
    assert.ok(endpoint.startsWith('/api/'));
    const response = await fetch(base + endpoint, {method, headers: {'x-console-token': token, 'content-type': 'application/json'}, ...(body === undefined ? {} : {body: JSON.stringify(body)})});
    const data = await response.json();
    assert.ok(response.ok, endpoint + ': ' + JSON.stringify(data));
    return data;
  };
  await api('/api/crs/config', {config: {baseUrl: `http://127.0.0.1:${remote.address().port}`, authType: 'apiKey', apiKey: 'fake-local-save-only-key', autoUpload: true}, revision: 0}, 'PUT');
  const settings = await api('/api/settings');
  await api('/api/settings', {section: 'proxyLibrary', revision: settings.revisions.proxyLibrary || 0, value: {selectedId: '', proxies: []}}, 'PUT');

  const profile = path.join(temporary, 'chrome');
  const executable = process.env.CHROME_BIN || '/usr/bin/chromium';
  browser = spawn(executable, ['--headless', '--disable-background-networking', '--disable-component-update', '--disable-sync', '--no-first-run', '--no-default-browser-check', '--no-proxy-server', '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost', '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'], {stdio: ['ignore', 'ignore', 'pipe']});
  browser.stderr.on('data', bytes => {browserLog += bytes.toString();});
  let debugPort;
  for (let attempt = 0; attempt < 300; attempt++) {
    try {debugPort = (await fs.readFile(path.join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]; if (debugPort) break;} catch {}
    if (browser.exitCode !== null) break;
    await wait(50);
  }
  assert.ok(debugPort, 'Isolated browser unavailable: ' + browserLog.slice(-1000));
  const targets = await (await fetch(`http://127.0.0.1:${debugPort}/json/list`)).json();
  socket = new WebSocket(targets.find(target => target.type === 'page').webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {socket.onopen = resolve; socket.onerror = reject;});
  let nextId = 0;
  const pending = new Map(), browserBlocked = [];
  const command = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++nextId;
    const timeout = setTimeout(() => {pending.delete(id); reject(Error('CDP timeout: ' + method));}, 15000);
    pending.set(id, {resolve, reject, timeout});
    socket.send(JSON.stringify({id, method, params}));
  });
  socket.onmessage = event => {
    const message = JSON.parse(event.data);
    if (message.id) {
      const request = pending.get(message.id);
      if (request) {clearTimeout(request.timeout); pending.delete(message.id); message.error ? request.reject(Error(JSON.stringify(message.error))) : request.resolve(message.result);}
    } else if (message.method === 'Fetch.requestPaused') {
      const request = message.params;
      const allowed = request.request.url.startsWith(base + '/') || /^(data:|about:)/.test(request.request.url);
      if (!allowed) browserBlocked.push(new URL(request.request.url).origin);
      void command(allowed ? 'Fetch.continueRequest' : 'Fetch.failRequest', {requestId: request.requestId, ...(!allowed ? {errorReason: 'BlockedByClient'} : {})}).catch(() => {});
    }
  };
  const evaluate = async expression => {
    const result = await command('Runtime.evaluate', {expression, returnByValue: true, awaitPromise: true});
    assert.ok(!result.exceptionDetails, 'Browser evaluation failed: ' + JSON.stringify(result.exceptionDetails));
    return result.result.value;
  };
  const until = async (expression, label) => {
    for (let attempt = 0; attempt < 100; attempt++) {if (await evaluate(expression)) return; await wait(70);}
    const page = await evaluate("({url:location.href,text:document.body?.innerText.slice(0,1200),html:document.documentElement.outerHTML.slice(0,300)})");
    throw Error('UI wait failed: ' + label + ': ' + JSON.stringify({page,browserBlocked}));
  };
  const click = async text => {
    const expression = `(()=>{const button=[...document.querySelectorAll('button')].find(button=>button.textContent.trim()===${JSON.stringify(text)}&&!button.disabled);if(!button)return false;button.click();return true;})()`;
    await until(expression, 'enabled button ' + text);
  };
  const input = async (selector, value, textarea = false) => {
    await evaluate(`(()=>{const element=document.querySelector(${JSON.stringify(selector)});if(!element)throw Error('Input missing');Object.getOwnPropertyDescriptor(${textarea ? 'HTMLTextAreaElement' : 'HTMLInputElement'}.prototype,'value').set.call(element,${JSON.stringify(value)});element.dispatchEvent(new Event('input',{bubbles:true}));})()`);
    await wait(90);
  };
  const screenshot = async name => {
    const result = await command('Page.captureScreenshot', {format: 'png'});
    await fs.writeFile(path.join(pictures, name), Buffer.from(result.data, 'base64'));
  };
  const choose = async (label, value) => {
    await evaluate(`(()=>{const element=document.querySelector('select[aria-label=${JSON.stringify(label)}]');if(!element)throw Error('Select missing');Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,'value').set.call(element,${JSON.stringify(value)});element.dispatchEvent(new Event('change',{bubbles:true}));})()`);
    await wait(100);
  };
  const viewport = async mobile => {
    await command('Emulation.setDeviceMetricsOverride', {width: mobile ? 390 : 1440, height: mobile ? 844 : 1000, deviceScaleFactor: 1, mobile});
    await wait(150);
  };
  const assertLayout = async (selector, label) => {
    const layout = await evaluate(`(()=>{const element=document.querySelector(${JSON.stringify(selector)});if(!element)return null;const rect=element.getBoundingClientRect();return {x:rect.x,width:rect.width,viewport:innerWidth,pageWidth:document.documentElement.scrollWidth};})()`);
    assert.ok(layout, label + ' is rendered');
    assert.ok(layout.x >= -1 && layout.x + layout.width <= layout.viewport + 1, label + ' fits viewport: ' + JSON.stringify(layout));
    assert.ok(layout.pageWidth <= layout.viewport + 1, label + ' must not cause page horizontal overflow: ' + JSON.stringify(layout));
    return layout;
  };
  const staticProxy = 'socks5h://fixture-user:fixture-password@static-proxy.example.invalid:1080';
  await api('/api/dynamic-proxies',{action:'saveProfile',profile:{id:'fake-legacy-profile',name:'Fixture legacy dynamic',key:'FAKE-local-only-key',protocol:'socks5h',country:'US',enabled:false},revision:0});
  await api('/api/settings', {section:'proxyLibrary', revision:(await api('/api/settings')).revisions.proxyLibrary || 0, value:{selectedId:'old-static',proxies:[{id:'old-static',name:'已有静态代理',url:staticProxy},{id:'legacy-dynamic',name:'原动态配置',dynamicProfileId:'fake-legacy-profile'}]}}, 'PUT');
  const fixtureJobs=[];
  for (const [index,email] of ['stored-proxy@example.invalid','no-proxy@example.invalid'].entries()) fixtureJobs.push((await api('/api/jobs',{email,startLogin:false,accountTerm:'long',password:'FAKE-local-password',totpSecret:'JBSWY3DPEHPK3PXP',...(index===0?{proxyUrl:staticProxy}:{})})).job);
  await command('Page.enable');
  await command('Fetch.enable', {patterns:[{urlPattern:'*',requestStage:'Request'}]});
  await command('Page.addScriptToEvaluateOnNewDocument', {source:String.raw`
    window.__proxyRequests=[];
    const nativeFetch=window.fetch.bind(window);
    const json=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{'content-type':'application/json'}});
    const fakeSchedule={id:'00000000-0000-4000-8000-000000000001',status:'scheduled',plannedAt:new Date(Date.now()+3600000).toISOString(),counts:{total:1},total:1};
    window.fetch=async(input,options)=>{
      const url=new URL(typeof input==='string'?input:input.url,location.href),method=options?.method||'GET';
      let body=options?.body?JSON.parse(options.body):null,response;
      if(url.pathname==='/api/bootstrap'){
        const bootstrap=await(await nativeFetch(input,options)).json();
        bootstrap.features.defaultOperationProxy={configured:true,provider:'1024-white',country:'US',label:'1024 美国动态代理'};
        return json(bootstrap);
      }
      if(method==='POST' && (url.pathname==='/api/jobs'||url.pathname==='/api/jobs/batch')){
        const saved={...body,startLogin:false};delete saved.proxyUrl;delete saved.proxyAssignments;
        response=await nativeFetch(input,{...options,body:JSON.stringify(saved)});
      } else if(method==='POST' && (/^\/api\/jobs\/[^/]+\/(security|relogin|regenerate|retry|setup-2fa|add-password)$/.test(url.pathname)||/^\/api\/jobs\/(security\/batch|reauthorize-batch|relogin-batch|setup-2fa-batch|add-password-batch)$/.test(url.pathname))){
        response=json({started:body.ids?.length||1,skipped:0,errors:[],results:(body.ids||[]).map(id=>({id,status:'started'}))});
      } else if(url.pathname==='/api/schedules/preview' && method==='POST'){
        const accounts=body.text.split(/\r?\n/).filter(Boolean).map((email,index)=>({email:email.split('----')[0],line:index+1,valid:true,proxyEndpoint:'1024 美国动态代理'}));
        response=json({accounts,validCount:accounts.length,invalidCount:0,plannedAt:fakeSchedule.plannedAt,prepareAt:fakeSchedule.plannedAt,crsSettings:body.crsSettings,securityAction:body.securityAction});
      } else if(url.pathname==='/api/schedules' && method==='POST') response=json({schedule:fakeSchedule,items:[]},201);
      else if(url.pathname==='/api/schedules' && method==='GET') response=json({schedules:[]});
      else if(url.pathname==='/api/schedules/'+fakeSchedule.id) response=json({schedule:fakeSchedule,items:[]});
      else response=await nativeFetch(input,options);
      if(method==='POST'&&(url.pathname.startsWith('/api/jobs')||url.pathname.startsWith('/api/schedules')))window.__proxyRequests.push({path:url.pathname,request:body,status:response.status,response:await response.clone().json()});
      return response;
    };
    window.confirm=()=>true;
  `});
  await viewport(false);await command('Page.navigate',{url:base});
  await until("document.querySelectorAll('.job-row').length===2 && Boolean(document.querySelector('select[aria-label=单个任务登录代理]'))",'ready default operation proxy');
  assert.equal(await evaluate("document.querySelector('select[aria-label=单个任务登录代理]').value"),'__server_default__','Persisted static selectedId must not override the operation default');
  const requests=async()=>evaluate('window.__proxyRequests');
  const submitSingle=async(email,selection)=>{
    if(selection)await choose('单个任务登录代理',selection);
    await choose('添加方式','login');await input('input[aria-label=邮箱地址]',email);await click('添加并上号');
    await until(`window.__proxyRequests.some(request=>request.path==='/api/jobs'&&request.request.email===${JSON.stringify(email)})`,'single proxy selection '+email);
    return (await requests()).find(request=>request.path==='/api/jobs'&&request.request.email===email);
  };
  const defaultSingle=await submitSingle('default-new@example.invalid');
  assert.deepEqual(defaultSingle.request.proxyUrl,{useDefaultProxy:true});
  const explicitSingle=await submitSingle('explicit-new@example.invalid','old-static');assert.equal(explicitSingle.request.proxyUrl,staticProxy);
  const directSingle=await submitSingle('direct-new@example.invalid','direct');assert.equal(directSingle.request.proxyUrl,'');
  const legacyDynamic=await submitSingle('legacy-dynamic@example.invalid','legacy-dynamic');assert.deepEqual(legacyDynamic.request.proxyUrl,{dynamicProfileId:'fake-legacy-profile'});
  await choose('单个任务登录代理','__server_default__');
  await click('批量添加');await until("Boolean(document.querySelector('#batch-input'))",'batch entry');
  await input('#batch-input','batch-default@example.invalid\nbatch-static@example.invalid',true);await click('下一步：选择代理');
  await until("document.querySelectorAll('.proxy-assignment-row').length===2",'default batch assignments');
  assert.equal(await evaluate("document.querySelector('[aria-labelledby=batch-title] button[type=submit]').disabled"),false);
  assert.deepEqual(await evaluate("[...document.querySelectorAll('.proxy-assignment-row select')].map(select=>select.value)"),['__server_default__','__server_default__']);
  await choose('为 batch-static@example.invalid 选择代理','old-static');
  await screenshot('batch-mixed-default-and-static.png');await click('创建 2 条任务并上号');
  await until("window.__proxyRequests.some(request=>request.path==='/api/jobs/batch')",'batch submitted');
  const batch=(await requests()).find(request=>request.path==='/api/jobs/batch');
  assert.deepEqual(batch.request.proxyAssignments,[{email:'batch-default@example.invalid',proxyUrl:{useDefaultProxy:true}},{email:'batch-static@example.invalid',proxyUrl:staticProxy}]);
  await until("!document.querySelector('[aria-labelledby=batch-title]')",'batch closed');
  const row=email=>`[...document.querySelectorAll('.job-row')].find(row=>row.querySelector('.account-details strong')?.textContent===${JSON.stringify(email)})`;
  await until(`Boolean(${row(fixtureJobs[1].email)})`,'fixture row available');
  await evaluate(`(${row(fixtureJobs[1].email)}).querySelector('.relogin-button').click()`);
  await until(`window.__proxyRequests.some(request=>request.path==='/api/jobs/${fixtureJobs[1].id}/relogin')`,'relogin default');
  assert.deepEqual((await requests()).find(request=>request.path===`/api/jobs/${fixtureJobs[1].id}/relogin`).request.proxyUrl,{useDefaultProxy:true});
  const openSecurity=async(email,label)=>{
    await evaluate(`(${row(email)}).querySelector('.account-security-button').click()`);
    await until("Boolean(document.querySelector('.security-choice-dialog'))",'security choice');
    await evaluate(`(()=>{const button=[...document.querySelectorAll('.security-choice')].find(button=>button.querySelector('strong').textContent===${JSON.stringify(label)});button.click();})()`);
    await until("Boolean(document.querySelector('.proxy-action-dialog'))",'security proxy dialog');
  };
  await openSecurity(fixtureJobs[1].email,'更换 2FA');
  assert.equal(await evaluate("document.querySelector('.security-proxy-choice input').checked"),false);
  assert.equal(await evaluate("document.querySelector('.proxy-action-dialog button[type=submit]').disabled"),false,'No stored static proxy is required for the default');
  await click('确认并开始');await until("Boolean(document.querySelector('.security-batch-results'))",'security default submitted');
  let security=(await requests()).find(request=>request.path===`/api/jobs/${fixtureJobs[1].id}/security`);
  assert.deepEqual(security.request.proxyUrl,{useDefaultProxy:true});await click('关闭');
  await openSecurity(fixtureJobs[0].email,'重置 Work 并登出所有设备');
  await evaluate("document.querySelector('.security-proxy-choice input').click()");
  await click('确认并开始');await until("Boolean(document.querySelector('.security-batch-results'))",'explicit stored proxy submitted');
  security=(await requests()).find(request=>request.path===`/api/jobs/${fixtureJobs[0].id}/security`);
  assert.deepEqual(security.request.proxyUrl,{useStoredProxy:true});await click('关闭');
  await click('自动定时任务');await until("Boolean(document.querySelector('#schedule-account-input'))",'scheduled proxy default');
  await input('#schedule-account-input',fixtureJobs[1].email,true);await click('识别账号');
  await until("Boolean(document.querySelector('.schedule-stored-proxy'))",'scheduled recognized');
  assert.equal(await evaluate("document.querySelector('.schedule-stored-proxy input').checked"),false);
  assert.equal(await evaluate("document.querySelector('.schedule-dialog .proxy-assignment-row select').value"),'__server_default__');
  await click('设置时间与操作');await click('生成计划预览');
  await until("Boolean(document.querySelector('.schedule-confirmation'))",'scheduled default preview');
  const previews=(await requests()).filter(request=>request.path==='/api/schedules/preview');
  assert.equal(Object.hasOwn(previews[0].request,'proxyAssignments'),false,'Recognition does not send operation selections');
  assert.deepEqual(previews[1].request.proxyAssignments,[{email:fixtureJobs[1].email,proxyUrl:{useDefaultProxy:true}}]);
  await evaluate("document.querySelector('.schedule-confirmation input').click()");await click('确认创建计划');
  await until("window.__proxyRequests.some(request=>request.path==='/api/schedules')",'scheduled default saved');
  const schedule=(await requests()).find(request=>request.path==='/api/schedules');assert.deepEqual(schedule.request.proxyAssignments,previews[1].request.proxyAssignments);
  await screenshot('scheduled-default-preview.png');
  assert.deepEqual(prohibitedCalls,[]);assert.deepEqual(browserBlocked,[]);
  assert.equal(await fs.stat(observations).then(()=>true,()=>false),false,'No real login/security worker may start');
  assert.equal(await fs.stat(networkEvents).then(()=>true,()=>false),false,'No external extraction or account request may occur');
  const report={passed:true,syntheticUiOnly:true,persistedStaticDoesNotOverrideDefault:true,singleDefault:true,explicitStaticAndDirect:true,legacyDynamicSelection:true,mixedBatch:true,reloginDefault:true,securityWithoutStoredProxy:true,explicitStoredProxy:true,scheduledDefaultPreviewAndSave:true,realAccountOperations:0,realProxyExtractions:0,screenshots:pictures};
  await fs.writeFile(path.join(pictures,'result.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
} finally {
  socket?.close();browser?.kill('SIGTERM');server?.kill('SIGTERM');await wait(400);await new Promise(resolve=>remote.close(resolve));await fs.rm(temporary,{recursive:true,force:true});
}
