// Local-only save-only UI regression. Temporary records only; login/security are blocked.
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
const pictures = path.join(root, 'ui-review-save-only');
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
  const singleEmail = 'saved-single@example.invalid';
  const batchEmails = ['saved-batch-one@example.invalid', 'saved-batch-two@example.invalid'];
  const fakePassword = 'UI-FAKE-password-123';
  const fakeTotp = 'JBSWY3DPEHPK3PXP';
  const batchText = batchEmails.map(email => `${email}----${fakePassword}----${fakeTotp}`).join('\n');
  await command('Page.enable');
  await command('Fetch.enable', {patterns: [{urlPattern: '*', requestStage: 'Request'}]});
  await command('Page.addScriptToEvaluateOnNewDocument', {source: `
    window.__saveOnlyRequests=[];const nativeFetch=window.fetch.bind(window);
    window.fetch=async (...args)=>{const response=await nativeFetch(...args);const url=new URL(typeof args[0]==='string'?args[0]:args[0].url,location.href);if(url.pathname.startsWith('/api/jobs')&&args[1]?.method==='POST'){window.__saveOnlyRequests.push({path:url.pathname,request:args[1].body?JSON.parse(args[1].body):null,response:await response.clone().json(),status:response.status});}return response;};
  `});
  await viewport(false);
  await command('Page.navigate', {url: base});
  await until("Boolean(document.querySelector('select[aria-label=添加方式]')) && !document.querySelector('.add-form button[type=submit]').disabled", 'ready default save mode');
  assert.equal(await evaluate("document.querySelector('select[aria-label=添加方式]').value"), 'save');
  assert.equal(await evaluate("document.querySelector('select[aria-label=单个任务登录代理]').value"), '');
  assert.equal((await api('/api/settings')).settings.proxyLibrary.proxies.length, 0);
  results.desktopHeader = await assertLayout('.add-form', 'desktop add form');
  await screenshot('save-only-desktop-empty.png');
  await viewport(true);
  results.mobileHeader = await assertLayout('.add-form', 'mobile add form');
  await screenshot('save-only-mobile-empty.png');
  await viewport(false);

  await input('input[aria-label=邮箱地址]', singleEmail);
  await click('保存账号');
  await until("window.__saveOnlyRequests.some(request=>request.path==='/api/jobs')", 'single save response');
  const single = await evaluate("window.__saveOnlyRequests.find(request=>request.path==='/api/jobs')");
  assert.deepEqual(single.request, {email: singleEmail, accountTerm: 'long', startLogin: false});
  assert.equal(single.status, 201);
  assert.equal(single.response.created, true);
  assert.equal(single.response.job.loginDeferred, true);
  assert.equal(single.response.job.status, 'ready');
  assert.equal(single.response.job.canRotateTotp, false);
  assert.equal(single.response.job.canDownload, false);
  assert.equal(single.response.job.proxyConfigured, false);
  await until("document.querySelectorAll('.job-row').length===1 && document.querySelector('.job-row').innerText.includes('仅保存')", 'saved-only single row');
  await screenshot('save-only-single-saved.png');

  await click('批量添加');
  await until("Boolean(document.querySelector('#batch-input'))", 'batch input');
  assert.equal(await evaluate("document.querySelector('select[aria-label=批量添加方式]').value"), 'save');
  await input('#batch-input', batchText, true);
  await screenshot('save-only-batch-input-desktop.png');
  await viewport(true);
  results.mobileBatchInput = await assertLayout('[aria-labelledby=batch-title]', 'mobile batch input dialog');
  await screenshot('save-only-batch-input-mobile.png');
  await click('识别账号并预览');
  await until("document.querySelectorAll('.save-only-preview li').length===2", 'batch account preview');
  const preview = await evaluate("window.__saveOnlyRequests.find(request=>request.path==='/api/jobs/preview')");
  assert.equal(preview.request.text, batchText);
  assert.deepEqual(preview.response.accounts.map(account => account.email), batchEmails);
  assert.equal(preview.response.count, 2);
  assert.equal((await api('/api/jobs')).jobs.length, 1, 'Preview must not save accounts');
  assert.equal(await evaluate("Boolean(document.querySelector('.proxy-assignments'))"), false, 'Save-only preview must not require proxy assignment');
  results.mobileBatchPreview = await assertLayout('[aria-labelledby=batch-title]', 'mobile batch preview dialog');
  await screenshot('save-only-batch-preview-mobile.png');
  await viewport(false);
  await screenshot('save-only-batch-preview-desktop.png');

  // Switching the already-recognized batch to immediate mode must require a selection.
  await choose('批量添加方式', 'login');
  assert.equal(await evaluate("document.querySelector('[aria-labelledby=batch-title] button[type=submit]').disabled"), true);
  assert.equal(await evaluate("Boolean(document.querySelector('.proxy-assignments'))"), true);
  await evaluate("document.querySelector('[aria-labelledby=batch-title] button[type=submit]').click()");
  await wait(200);
  assert.equal(await evaluate("window.__saveOnlyRequests.filter(request=>request.path==='/api/jobs/batch').length"), 0);
  await screenshot('immediate-batch-proxy-required.png');
  await choose('批量添加方式', 'save');
  await click('仅保存 2 个账号');
  await until("window.__saveOnlyRequests.some(request=>request.path==='/api/jobs/batch')", 'batch save response');
  const batch = await evaluate("window.__saveOnlyRequests.find(request=>request.path==='/api/jobs/batch')");
  assert.deepEqual(batch.request, {text: batchText, accountTerm: 'long', accountTerms: batchEmails.map(email => ({email, accountTerm: 'long'})), startLogin: false});
  assert.equal(batch.status, 201);
  assert.equal(batch.response.created, 2);
  assert.equal(batch.response.updated, 0);
  assert.equal(batch.response.jobs.length, 2);
  for (const job of batch.response.jobs) {
    assert.equal(job.loginDeferred, true);
    assert.equal(job.status, 'ready');
    assert.equal(job.canRotateTotp, true);
    assert.equal(job.canDownload, false);
    assert.equal(job.proxyConfigured, false);
    assert.equal(job.hasTotpKey, true);
  }
  await until("document.querySelectorAll('.job-row').length===3 && !document.querySelector('[aria-labelledby=batch-title]')", 'all saved rows');
  assert.equal(await evaluate("[...document.querySelectorAll('.job-row')].filter(row=>row.innerText.includes('仅保存')).length"), 3);
  assert.equal(await evaluate("[...document.querySelectorAll('.account-security-button')].filter(button=>!button.disabled).length"), 2);
  await screenshot('save-only-saved-desktop.png');
  await viewport(true);
  results.mobileSaved = await assertLayout('.add-form', 'mobile saved account header');
  await screenshot('save-only-saved-mobile.png');
  await viewport(false);

  // Security remains an independent, available action; no-proxy execution is blocked.
  await evaluate(`(()=>{const row=[...document.querySelectorAll('.job-row')].find(row=>row.querySelector('.account-details strong')?.textContent===${JSON.stringify(batchEmails[0])});if(!row)throw Error('Saved row missing');row.querySelector('.account-security-button').click();})()`);
  await until("Boolean(document.querySelector('.security-choice-dialog'))", 'independent security choices');
  assert.equal(await evaluate("[...document.querySelectorAll('.security-choice')].find(button=>button.querySelector('strong')?.textContent==='更换 2FA').disabled"), false);
  await screenshot('save-only-security-available.png');
  await evaluate("[...document.querySelectorAll('.security-choice')].find(button=>button.querySelector('strong')?.textContent==='更换 2FA').click()");
  await until("Boolean(document.querySelector('.proxy-action-dialog'))", 'security proxy confirmation');
  assert.equal(await evaluate("document.querySelector('.proxy-action-dialog button[type=submit]').disabled"), true);
  assert.match(await evaluate("document.querySelector('.proxy-action-dialog').innerText"), /SOCKS5/);
  await screenshot('save-only-security-proxy-required.png');
  await click('取消');

  await choose('添加方式', 'login');
  await input('input[aria-label=邮箱地址]', 'never-login@example.invalid');
  assert.equal(await evaluate("document.querySelector('.add-form button[type=submit]').disabled"), true);
  await evaluate("document.querySelector('.add-form button[type=submit]').click()");
  await wait(200);
  assert.equal(await evaluate("window.__saveOnlyRequests.filter(request=>request.path==='/api/jobs').length"), 1);
  await screenshot('immediate-single-proxy-required.png');
  await choose('添加方式', 'save');
  const requests = await evaluate('window.__saveOnlyRequests');
  assert.deepEqual(requests.map(request => request.path), ['/api/jobs', '/api/jobs/preview', '/api/jobs/batch']);
  assert.ok(requests.every(request => !Object.hasOwn(request.request, 'proxyUrl') && !Object.hasOwn(request.request, 'proxyAssignments')));

  await command('Page.reload', {ignoreCache: true});
  await until("document.querySelectorAll('.job-row').length===3 && Boolean(document.querySelector('select[aria-label=添加方式]'))", 'saved accounts after page refresh');
  assert.equal(await evaluate("document.querySelector('select[aria-label=添加方式]').value"), 'save');
  assert.equal(await evaluate("[...document.querySelectorAll('.job-row')].filter(row=>row.innerText.includes('仅保存')).length"), 3);
  const persisted = await api('/api/jobs');
  assert.equal(persisted.jobs.length, 3);
  assert.ok(persisted.jobs.every(job => job.loginDeferred && job.status === 'ready' && !job.canDownload && !job.proxyConfigured));
  for (const job of persisted.jobs) {
    const details = await api(`/api/jobs/${job.id}/details`);
    assert.equal(details.loginDeferred, true);
    assert.equal(details.status, 'ready');
    assert.equal(details.history.total, 0);
    assert.deepEqual(details.securityOperations, []);
    assert.equal(details.canRotateTotp, batchEmails.includes(job.email));
    // Inspect only synthetic fixture credentials, without emitting them or taking screenshots.
    const saved = await api(`/api/jobs/${job.id}/secrets`, {});
    assert.equal(saved.password, batchEmails.includes(job.email) ? fakePassword : null);
    assert.equal(saved.totpSecret, batchEmails.includes(job.email) ? fakeTotp : null);
  }
  await screenshot('save-only-after-refresh.png');
  const statusResponse = await fetch(base + '/api/integrations/crs/runtime/status', {headers: {authorization: 'Bearer local-save-only-fixture'}});
  assert.equal(statusResponse.status, 200);
  const runtime = await statusResponse.json();
  for (const field of ['active', 'queued', 'childProcesses', 'loginStarts', 'accountOperations']) assert.equal(runtime[field], 0, 'Runtime must remain idle: ' + field);
  assert.equal(runtime.crs.pending, 0);
  assert.equal(runtime.crs.running, 0);
  assert.equal(runtime.crs.workerActive, false);
  assert.deepEqual(prohibitedCalls, [], 'No CPR write, login, or proxy test is allowed');
  assert.deepEqual(browserBlocked, [], 'Application must make no external browser requests');
  assert.equal(await fs.stat(observations).then(() => true, () => false), false, 'No login/security protocol may start');
  assert.equal(await fs.stat(networkEvents).then(() => true, () => false), false, 'Server must make no external connections');
  const report = {passed: true, localFixtureOnly: true, recordsSaved: 3, singleSaved: 1, batchSaved: 2, pageRefreshPreserved: true, savedCredentialsVerified: true, proxyConfigured: false, immediateWithoutProxyBlocked: {single: true, batch: true}, independentSecurityAvailable: 2, securityWithoutSocks5Blocked: true, accountOperations: 0, realCprRequests: 0, proxyTests: 0, screenshots: pictures, layout: results};
  await fs.writeFile(path.join(pictures, 'result.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report));
} finally {
  socket?.close();
  browser?.kill('SIGTERM');
  server?.kill('SIGTERM');
  await wait(400);
  await new Promise(resolve => remote.close(resolve));
  await fs.rm(temporary, {recursive: true, force: true});
}
