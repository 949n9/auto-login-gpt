// Browser regression uses only synthetic local accounts; login/security are blocked.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import http from 'node:http';
import {spawn} from 'node:child_process';
import { createServerDatabase } from '../src/server-database.mjs';

const root = path.resolve(import.meta.dirname, '..');
await fs.access(path.join(root, 'web/dist/index.html'));
const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'cpr-save-only-ui-'));
const pictures = path.join(root, 'ui-review-account-lifecycle');
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
  const seeded = [];
  for (const email of ['active-long@example.invalid', 'active-legacy@example.invalid', 'resting-short@example.invalid', 'retired-upstream@example.invalid']) {
    seeded.push((await api('/api/jobs', {email, accountTerm: email.startsWith('resting') ? 'short' : 'long', startLogin: false})).job);
  }
  const database = createServerDatabase({outputRoot: path.join(temporary, 'data'), mustExist: true});
  const firstAuthorizedAt = new Date(Date.now() - 7 * 86400000).toISOString();
  const restingSince = new Date(Date.now() - 2 * 86400000 - 3 * 3600000 - 4 * 60000).toISOString();
  const retiredAt = new Date(Date.now() - 86400000).toISOString();
  for (const job of seeded) {
    const value = database.get('account-lifecycle', job.email);
    database.put('account-lifecycle', job.email, {...value,
      accountTerm: job.email.includes('legacy') ? null : value.accountTerm,
      firstAuthorizedAt: job.email.includes('legacy') ? null : firstAuthorizedAt,
      firstAuthorizedAtSource: job.email.startsWith('resting') ? 'historical' : job.email.includes('legacy') ? null : 'recorded',
      ...(job.email.startsWith('resting') ? {lastLogoutAt: restingSince, restingSince, restingReason: 'logout_accepted'} : {}),
      ...(job.email.startsWith('retired') ? {retired:true, retiredAt, retiredReason:'上游账号已永久禁用'} : {}),
    });
  }
  database.close();
  const area = async value => {
    await evaluate(`(()=>{const button=[...document.querySelectorAll('.account-area-tabs button')].find(button=>button.textContent.startsWith(${JSON.stringify(value)}));if(!button)throw Error('Area missing');button.click();})()`);
  };
  const row = email => `[...document.querySelectorAll('.job-row')].find(row=>row.querySelector('.account-details strong')?.textContent===${JSON.stringify(email)})`;
  await command('Page.enable');
  await command('Fetch.enable', {patterns: [{urlPattern: '*', requestStage: 'Request'}]});
  await command('Page.addScriptToEvaluateOnNewDocument', {source: `
    window.confirm=()=>true;window.__saveOnlyRequests=[];const nativeFetch=window.fetch.bind(window);
    window.fetch=async (...args)=>{const response=await nativeFetch(...args);const url=new URL(typeof args[0]==='string'?args[0]:args[0].url,location.href);if(url.pathname.startsWith('/api/jobs')&&args[1]?.method==='POST'){window.__saveOnlyRequests.push({path:url.pathname,request:args[1].body?JSON.parse(args[1].body):null,response:await response.clone().json(),status:response.status});}return response;};
  `});
  await viewport(false);
  await command('Page.navigate', {url: base});
  await until("document.querySelectorAll('.job-row').length===2 && Boolean(document.querySelector('.account-area-tabs'))", 'active accounts only');
  assert.equal(await evaluate("document.querySelector('.account-area-tabs button[aria-pressed=true]').textContent"), '在用账号2');
  assert.equal(await evaluate(`Boolean(${row(seeded[2].email)})`), false);
  assert.equal(await evaluate(`Boolean(${row(seeded[3].email)})`), false);
  assert.equal(await evaluate("document.querySelectorAll('.account-area-tabs button').length"), 4);
  assert.equal(await evaluate("document.querySelector('select[aria-label=新增账号类型]').value"), 'long');
  assert.equal(await evaluate(`(${row(seeded[1].email)}).querySelector('.row-account-term select').value`), '');
  assert.equal(await evaluate(`(${row(seeded[1].email)}).querySelector('.row-account-term select option:checked').textContent`), '未设置');
  assert.match(await evaluate(`(${row(seeded[0].email)}).innerText`), /首次授权/);
  await choose(`${seeded[0].email} 的账号类型`, 'short');
  await until(`(${row(seeded[0].email)}).querySelector('.row-account-term select').value==='short'`, 'saved account classification');
  assert.equal((await api(`/api/jobs/${seeded[0].id}/details`)).accountTerm, 'short');
  await evaluate(`(${row(seeded[0].email)}).querySelector('input[type=checkbox]').click()`);
  await area('静置区');
  await until("document.querySelectorAll('.job-row').length===1 && Boolean(document.querySelector('.account-resting-status'))", 'resting account view');
  assert.equal(await evaluate(`Boolean(${row(seeded[0].email)})`), false);
  assert.equal(await evaluate("document.querySelector('.job-row input[type=checkbox]').checked"), false, 'Switching areas clears selection');
  assert.match(await evaluate("document.querySelector('.account-resting-status').innerText"), /2 天 3 小时/);
  assert.match(await evaluate("document.querySelector('.account-resting-status time').innerText"), /退出时间/);
  assert.match(await evaluate("document.querySelector('.account-first-authorization').title"), /历史可追溯/);
  await evaluate("[...document.querySelectorAll('.job-row button')].find(button=>button.textContent.trim()==='详情').click()");
  await until("Boolean(document.querySelector('.account-detail-fields'))", 'account lifecycle details');
  const details = await evaluate("document.querySelector('.account-detail-fields').innerText");
  assert.match(details, /账号类型/); assert.match(details, /短效/); assert.match(details, /首次授权（历史可追溯）/); assert.match(details, /已退出/);
  await screenshot('resting-details-desktop.png');
  await evaluate("document.querySelector('[aria-label=关闭账号详情]').click()");
  results.desktopTabs = await assertLayout('.account-area-tabs', 'desktop account areas');
  await screenshot('resting-desktop.png');
  await viewport(true);
  results.mobileTabs = await assertLayout('.account-area-tabs', 'mobile account areas');
  results.mobileHeader = await assertLayout('.add-form', 'mobile classified account form');
  await screenshot('resting-mobile.png');
  await viewport(false);
  await evaluate("document.querySelector('.job-row input[type=checkbox]').click()");
  await area('废号区');
  await until("document.querySelectorAll('.job-row').length===1 && Boolean(document.querySelector('.account-retired-status'))", 'retired account view');
  assert.equal(await evaluate(`Boolean(${row(seeded[2].email)})`), false);
  assert.equal(await evaluate("document.querySelector('.job-row input[type=checkbox]').checked"), false, 'Retired area clears selection');
  assert.match(await evaluate("document.querySelector('.account-retired-status').innerText"), /上游账号已永久禁用/);
  assert.match(await evaluate("document.querySelector('.account-retired-status time').innerText"), /作废时间/);
  await evaluate("[...document.querySelectorAll('.job-row button')].find(button=>button.textContent.trim()==='详情').click()");
  await until("Boolean(document.querySelector('.account-detail-fields .account-retired-status'))", 'retired account details');
  assert.match(await evaluate("document.querySelector('.account-detail-fields').innerText"), /上游账号已永久禁用/);
  await screenshot('retired-details-desktop.png');
  await evaluate("document.querySelector('[aria-label=关闭账号详情]').click()");
  await screenshot('retired-desktop.png');
  await viewport(true);
  results.mobileRetiredTabs = await assertLayout('.account-area-tabs', 'mobile four account areas');
  const tabLayout = await evaluate("[...document.querySelectorAll('.account-area-tabs button')].map(button=>{const r=button.getBoundingClientRect();return {x:r.x,width:r.width,right:r.right};})");
  assert.ok(tabLayout.every(tab => tab.x >= 0 && tab.right <= 390), 'Every mobile area tab fits the viewport');
  await evaluate("document.querySelector('.account-area-tabs').scrollIntoView({block:'start'})");
  await screenshot('retired-mobile.png');
  await viewport(false);
  await input('input[aria-label=搜索账号]', 'absent-account');
  await until("Boolean(document.querySelector('.empty-state'))", 'empty retired search');
  await input('input[aria-label=搜索账号]', '');
  await until("document.querySelectorAll('.job-row').length===1", 'clear retired search');
  await area('全部账号');
  await until("document.querySelectorAll('.job-row').length===4", 'all accounts');
  await input('input[aria-label=搜索账号]', 'resting-short');
  await until("document.querySelectorAll('.job-row').length===1", 'search in all area');
  assert.ok((await evaluate('window.__saveOnlyRequests')).some(request => request.path === '/api/jobs/query' && request.request.area === 'all'));
  await input('input[aria-label=搜索账号]', '');
  await until("document.querySelectorAll('.job-row').length===4", 'clear area search');
  await area('静置区');
  await until("document.querySelectorAll('.job-row').length===1", 'return to resting');
  await choose('新增账号类型', 'short');
  await input('input[aria-label=邮箱地址]', 'new-short@example.invalid');
  await click('保存账号');
  await until("document.querySelector('.account-area-tabs button[aria-pressed=true]').textContent.startsWith('在用账号') && document.querySelectorAll('.job-row').length===3", 'new account returns to active area');
  const single = (await evaluate('window.__saveOnlyRequests')).find(request => request.path === '/api/jobs');
  assert.equal(single.request.accountTerm, 'short'); assert.equal(single.response.job.accountTerm, 'short');
  await click('批量添加');
  await until("Boolean(document.querySelector('#batch-input'))", 'classified batch entry');
  await choose('批量账号默认类型', 'short');
  await input('#batch-input', 'batch-one@example.invalid\nbatch-two@example.invalid', true);
  await click('识别账号并预览');
  await until("document.querySelectorAll('.batch-term-preview li').length===2", 'per account classification preview');
  await choose('batch-two@example.invalid 的账号类型', 'long');
  await viewport(true);
  results.mobileBatch = await assertLayout('[aria-labelledby=batch-title]', 'mobile account classification preview');
  await screenshot('batch-classification-mobile.png');
  await viewport(false);
  await screenshot('batch-classification-desktop.png');
  await click('仅保存 2 个账号');
  await until("document.querySelectorAll('.job-row').length===5 && !document.querySelector('[aria-labelledby=batch-title]')", 'classified batch saved');
  const batch = (await evaluate('window.__saveOnlyRequests')).find(request => request.path === '/api/jobs/batch');
  assert.equal(batch.request.accountTerm, 'short');
  assert.deepEqual(batch.request.accountTerms, [{email:'batch-one@example.invalid',accountTerm:'short'},{email:'batch-two@example.invalid',accountTerm:'long'}]);
  assert.deepEqual(batch.response.jobs.map(job => job.accountTerm), ['short', 'long']);
  await screenshot('classified-accounts-desktop.png');
  // Public labels and actual account settings saved from the rendered form.
  const labels = await evaluate(`(${row(seeded[0].email)}).innerText`);
  assert.match(labels, /直接授权 Codex/);
  assert.match(labels, /登录账号后授权 Codex/);
  assert.match(labels, /401 重登/);
  assert.doesNotMatch(labels, /凭证守护|重新授权（旧）/);
  await evaluate(`(${row(seeded[0].email)}).id='settings-target'`);
  await input('#settings-target input[aria-label="CRS 账号并发"]', '11');
  await input('#settings-target input[aria-label="CRS 账号优先级"]', '23');
  await evaluate("[...document.querySelectorAll('#settings-target button')].find(button=>button.textContent.trim()==='保存设置').click()");
  await until("document.querySelector('#settings-target [role=status]')?.textContent==='已保存'", 'single CRS settings saved');
  let savedSettings = (await api('/api/crs/account-settings')).settings;
  assert.equal(savedSettings[seeded[0].id].concurrencyLimit, 11);
  assert.equal(savedSettings[seeded[0].id].weight, 23);
  for (const job of seeded.slice(0, 2)) await evaluate(`(${row(job.email)}).querySelector('input[type=checkbox]').click()`);
  await click('批量设置 CRS');
  await until("Boolean(document.querySelector('.crs-batch-settings'))", 'batch CRS form');
  await input('.crs-batch-settings input[aria-label="CRS 账号并发"]', '9');
  await input('.crs-batch-settings input[aria-label="CRS 账号优先级"]', '37');
  await evaluate("document.querySelector('.crs-batch-settings .crs-guard-toggle input').click()");
  await viewport(true);
  results.mobileCrs = await assertLayout('.crs-batch-settings', 'mobile CRS settings');
  await screenshot('crs-settings-mobile.png');
  await evaluate("[...document.querySelectorAll('.crs-batch-settings button')].find(button=>button.textContent.trim()==='保存设置').click()");
  await until("!document.querySelector('.crs-batch-settings')", 'batch CRS saved');
  savedSettings = (await api('/api/crs/account-settings')).settings;
  for (const job of seeded.slice(0, 2)) {
    assert.equal(savedSettings[job.id].concurrencyLimit, 9);
    assert.equal(savedSettings[job.id].weight, 37);
    assert.equal(savedSettings[job.id].credentialGuardian.enabled, true);
  }
  await viewport(false);
  await area('全部账号'); await until("document.querySelectorAll('.job-row').length===7", 'clear selection before movement');
  await area('在用账号'); await until("document.querySelectorAll('.job-row').length===5", 'return to active accounts');
  const clickRow = async (email, label) => {
    await evaluate(`(()=>{const button=[...(${row(email)}).querySelectorAll('button')].find(button=>button.textContent.trim()===${JSON.stringify(label)});if(!button||button.disabled)throw Error('Row action unavailable');button.click();})()`);
  };
  await clickRow(seeded[0].email, '移到静置区');
  await until(`!(${row(seeded[0].email)})`, 'single account moved to rest');
  assert.equal((await api(`/api/jobs/${seeded[0].id}/details`)).restingReason, 'manual');
  await clickRow(seeded[1].email, '移到废号区');
  await until(`!(${row(seeded[1].email)})`, 'single account retired');
  assert.equal((await api(`/api/jobs/${seeded[1].id}/details`)).retired, true);
  for (const email of ['batch-one@example.invalid','batch-two@example.invalid']) await evaluate(`(${row(email)}).querySelector('input[type=checkbox]').click()`);
  await click('移到静置区');
  await until("document.querySelectorAll('.job-row').length===1", 'batch moved to rest');
  await area('静置区');
  await until("document.querySelectorAll('.job-row').length===4", 'resting partition includes moved accounts');
  assert.match(await evaluate(`(${row(seeded[0].email)}).innerText`), /已静置|静置时间/);
  for (const email of ['batch-one@example.invalid','batch-two@example.invalid']) await evaluate(`(${row(email)}).querySelector('input[type=checkbox]').click()`);
  await click('移到废号区');
  await until("document.querySelectorAll('.job-row').length===2", 'batch retired');
  await area('废号区');
  await until("document.querySelectorAll('.job-row').length===4", 'retired partition includes moved accounts');
  await screenshot('moved-accounts-desktop.png');
  await viewport(true);
  results.mobileMoved = await assertLayout('.account-area-tabs', 'mobile moved partitions');
  await screenshot('moved-accounts-mobile.png');
  await viewport(false);
  await command('Page.reload', {ignoreCache:true});
  await until("document.querySelectorAll('.job-row').length===1", 'active partition after browser refresh');
  await area('废号区');
  await until("document.querySelectorAll('.job-row').length===4", 'moved accounts survive browser refresh');
  assert.equal((await api(`/api/jobs/${seeded[0].id}/details`)).firstAuthorizedAt, firstAuthorizedAt);
  assert.deepEqual(prohibitedCalls, []); assert.deepEqual(browserBlocked, []);
  assert.equal(await fs.stat(observations).then(() => true, () => false), false, 'No account login/security protocol may start');
  assert.equal(await fs.stat(networkEvents).then(() => true, () => false), false, 'No external server network is allowed');
  const report = {passed:true, singleAndBatchMovement:true, crsConcurrencyAndPriority:true, publicLabels:true, syntheticLocalFixture:true, areaFiltering:true, searchWithinArea:true, selectionCleared:true, retiredArea:true, retiredDetails:true, mobileFourAreas:true, restingDuration:true, lifecycleDetails:true, singleTerm:true, batchDefaultAndOverride:true, existingTermEditable:true, pageRefreshPreserved:true, accountOperations:0, screenshots:pictures, layout:results};
  await fs.writeFile(path.join(pictures,'result.json'),JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify(report));
} finally {
  socket?.close(); browser?.kill('SIGTERM'); server?.kill('SIGTERM'); await wait(400);
  await new Promise(resolve => remote.close(resolve));
  await fs.rm(temporary,{recursive:true,force:true});
}
