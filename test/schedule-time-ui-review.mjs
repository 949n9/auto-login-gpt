// Local-only timezone regression: private temporary DB, fake CPR, no protocol execution.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import http from 'node:http';
import {spawn} from 'node:child_process';

const root = path.resolve(import.meta.dirname, '..');
await fs.access(path.join(root, 'web/dist/index.html'));
const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'cpr-schedule-time-ui-'));
const pictures = path.join(root, 'ui-review-time');
await fs.mkdir(pictures, {recursive: true});
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const futureDay = new Date(Date.now() + 7 * 86400_000 + 8 * 3600_000).toISOString().slice(0, 10);
const scheduledLocal = `${futureDay}T06:00`;
const plannedAt = new Date(`${scheduledLocal}:00+08:00`).toISOString();
const prepareAt = new Date(Date.parse(plannedAt) - 30 * 60_000).toISOString();
assert.ok(Date.parse(prepareAt) > Date.now() + 86400_000, 'Fixture preparation must remain safely in the future');
const scenarios = [
  {name: 'utc', timezone: 'UTC'},
  {name: 'detroit', timezone: 'America/Detroit'},
  {name: 'shanghai', timezone: 'Asia/Shanghai'},
  {name: 'intl-forced-utc', timezone: 'America/Detroit', brokenIntl: true},
];
const prohibitedCalls = [];
const remote = http.createServer(async (request, response) => {
  for await (const _ of request) {}
  const pathname = new URL(request.url, 'http://127.0.0.1').pathname;
  let data;
  if (request.method === 'GET' && pathname === '/api/admin/account-groups/options') data = {items: [{id: 'openai', name: 'OpenAI', enabled: true}], page: {totalPages: 1}};
  else if (request.method === 'GET' && pathname === '/api/admin/proxies') data = {items: [{id: 'time-ui-proxy', endpoint: 'socks5://time-ui.example.invalid:1080', hasAuthentication: false, enabled: true}], page: {page: 1, totalPages: 1}};
  else if (request.method === 'GET' && pathname === '/api/admin/system/version') data = {version: 'local-time-fixture'};
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
const results = [];
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
    env: {...environment, NODE_ENV: 'production', ONBOARDING_OUTPUT_ROOT: path.join(temporary, 'data'), ONBOARDING_DATABASE_PATH: path.join(temporary, 'data/tosub2.sqlite3'), ONBOARDING_PROTOCOL_SCRIPT: blockedProtocol, CRS_LOGIN_BRIDGE_KEY: 'local-time-fixture-only'},
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
  await api('/api/crs/config', {config: {baseUrl: `http://127.0.0.1:${remote.address().port}`, authType: 'apiKey', apiKey: 'fake-local-time-key', autoUpload: true}, revision: 0}, 'PUT');
  const settings = await api('/api/settings');
  await api('/api/settings', {section: 'proxyLibrary', revision: settings.revisions.proxyLibrary || 0, value: {selectedId: 'time-ui-proxy', proxies: [{id: 'time-ui-proxy', name: '本地时间测试 SOCKS5', url: 'socks5://time-ui.example.invalid:1080'}]}}, 'PUT');

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
  const assertBjt = (value, time, label) => {
    assert.match(value, new RegExp(`\\b${time}:00\\b`), label + ' must show ' + time + ', got ' + value);
    const [year, month, day] = futureDay.split('-');
    assert.match(value, new RegExp(`${year}[-/]0?${Number(month)}[-/]0?${Number(day)}\\b`), label + ' must show the input date');
  };
  await command('Page.enable');
  await command('Fetch.enable', {patterns: [{urlPattern: '*', requestStage: 'Request'}]});
  await command('Emulation.setDeviceMetricsOverride', {width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false});
  let injectedScript;
  for (const scenario of scenarios) {
    await command('Emulation.setTimezoneOverride', {timezoneId: scenario.timezone});
    if (injectedScript) await command('Page.removeScriptToEvaluateOnNewDocument', {identifier: injectedScript});
    const source = `
      ${scenario.brokenIntl ? `const NativeDateTimeFormat=Intl.DateTimeFormat;Intl.DateTimeFormat=new Proxy(NativeDateTimeFormat,{construct(target,args){return Reflect.construct(target,[args[0],{...(args[1]||{}),timeZone:'UTC'}]);},apply(target,thisArg,args){return Reflect.apply(target,thisArg,[args[0],{...(args[1]||{}),timeZone:'UTC'}]);}});` : ''}
      window.__scheduleTimeRequests=[];const nativeFetch=window.fetch.bind(window);
      window.fetch=async (...args)=>{const response=await nativeFetch(...args);const url=new URL(typeof args[0]==='string'?args[0]:args[0].url,location.href);if(url.pathname.startsWith('/api/schedules')&&args[1]?.method==='POST'){window.__scheduleTimeRequests.push({path:url.pathname,request:JSON.parse(args[1].body),response:await response.clone().json()});}return response;};
    `;
    injectedScript = (await command('Page.addScriptToEvaluateOnNewDocument', {source})).identifier;
    await command('Page.navigate', {url: base});
    await until("[...document.querySelectorAll('button')].some(button=>button.textContent.trim()==='自动定时任务')", 'main page');
    const resolved = await evaluate("({offset:new Date().getTimezoneOffset(),timezone:new Intl.DateTimeFormat('en',{timeZone:'Asia/Shanghai'}).resolvedOptions().timeZone})");
    if (scenario.timezone === 'UTC') assert.equal(resolved.offset, 0);
    if (scenario.timezone === 'Asia/Shanghai') assert.equal(resolved.offset, -480);
    if (scenario.timezone === 'America/Detroit') assert.notEqual(resolved.offset, 0);
    assert.equal(resolved.timezone, scenario.brokenIntl ? 'UTC' : 'Asia/Shanghai');
    if (scenario.brokenIntl) {
      const legacy = await evaluate(`new Intl.DateTimeFormat('zh-CN',{timeZone:'Asia/Shanghai',hour:'2-digit',minute:'2-digit',hourCycle:'h23'}).format(new Date(${JSON.stringify(plannedAt)}))`);
      assert.equal(legacy, '22:00', 'Fault injection must reproduce the original UTC display symptom');
    }
    await click('自动定时任务');
    await until("Boolean(document.querySelector('#schedule-account-input'))", 'account input');
    await input('#schedule-account-input', `time-${scenario.name}@example.invalid----FAKE-password----JBSWY3DPEHPK3PXP`, true);
    await click('识别账号');
    await click('应用到全部');
    await click('设置时间与操作');
    await until("Boolean(document.querySelector('.schedule-dialog input[type=datetime-local]'))", 'time input');
    await input('.schedule-dialog input[type=datetime-local]', scheduledLocal);
    for (const text of ['先更换 2FA', '重置 Work 并登出所有设备']) {
      await evaluate(`(()=>{const label=[...document.querySelectorAll('label')].find(label=>label.querySelector('strong')?.textContent===${JSON.stringify(text)});if(!label)throw Error('Preparation option missing');label.querySelector('input').click();})()`);
    }
    await wait(100);
    assert.equal(await evaluate("document.querySelector('input[type=datetime-local]').value"), scheduledLocal);
    const timeline = await evaluate("[...document.querySelectorAll('.schedule-timeline > div')].map(element=>element.innerText)");
    assert.equal(timeline.length, 2);
    assertBjt(timeline[0], '05:30', scenario.name + ' preparation timeline');
    assertBjt(timeline[1], '06:00', scenario.name + ' login timeline');
    await screenshot(`${scenario.name}-settings.png`);
    await click('生成计划预览');
    await until("Boolean(document.querySelector('.schedule-preview-summary'))", 'server preview');
    const preview = await evaluate("window.__scheduleTimeRequests.filter(request=>request.path==='/api/schedules/preview').at(-1)");
    assert.equal(preview.request.scheduledLocal, scheduledLocal);
    assert.equal(preview.request.timeZone, 'Asia/Shanghai');
    assert.equal(preview.response.plannedAt, plannedAt);
    assert.equal(preview.response.prepareAt, prepareAt);
    assert.equal(preview.response.validCount, 1);
    assert.equal(preview.response.invalidCount, 0);
    const summary = await evaluate("Object.fromEntries([...document.querySelectorAll('.schedule-preview-summary > div')].map(element=>[element.querySelector('dt').textContent,element.querySelector('dd').textContent]))");
    assertBjt(summary['计划上号'], '06:00', scenario.name + ' preview login');
    assertBjt(summary['开始准备'], '05:30', scenario.name + ' preview preparation');
    await screenshot(`${scenario.name}-preview.png`);
    await evaluate("document.querySelector('.schedule-confirmation input').click()");
    await click('确认创建计划');
    await until("Boolean(window.__scheduleTimeRequests.find(request=>request.path==='/api/schedules'))", 'created schedule response');
    const created = await evaluate("window.__scheduleTimeRequests.find(request=>request.path==='/api/schedules')");
    assert.equal(created.request.scheduledLocal, scheduledLocal);
    assert.equal(created.request.timeZone, 'Asia/Shanghai');
    assert.equal(created.response.schedule.plannedAt, plannedAt);
    assert.equal(created.response.schedule.prepareAt, prepareAt);
    const detail = await api(`/api/schedules/${created.response.schedule.id}`);
    assert.equal(detail.schedule.timeZone, 'Asia/Shanghai');
    assert.equal(detail.schedule.scheduledLocal.slice(0, 16), scheduledLocal);
    assert.equal(detail.schedule.status, 'scheduled');
    assert.equal(detail.items.length, 1);
    assert.equal(detail.items[0].plannedAt, plannedAt);
    assert.equal(detail.items[0].prepareAt, prepareAt);
    assert.equal(detail.items[0].loginNotBefore, plannedAt);
    assert.equal(detail.items[0].attempts, 0);
    await until("Boolean(document.querySelector('.schedule-detail-heading h3'))", 'saved history detail');
    assertBjt(await evaluate("document.querySelector('.schedule-detail-heading h3').textContent"), '06:00', scenario.name + ' saved history');
    assertBjt(await evaluate("document.querySelector('.schedule-list-card.is-selected strong').textContent"), '06:00', scenario.name + ' saved list');
    assertBjt(await evaluate("document.querySelector('.schedule-item-meta').textContent"), '06:00', scenario.name + ' earliest login');
    await screenshot(`${scenario.name}-history.png`);
    results.push({scenario: scenario.name, browserTimezone: scenario.timezone, forcedUtcIntl: Boolean(scenario.brokenIntl), input: scheduledLocal, displayedPreparation: '05:30:00', displayedLogin: '06:00:00', storedPrepareAt: prepareAt, storedPlannedAt: plannedAt});
  }
  const saved = await api('/api/schedules');
  assert.equal(saved.schedules.length, scenarios.length);
  assert.ok(saved.schedules.every(schedule => schedule.status === 'scheduled'));
  assert.deepEqual(prohibitedCalls, [], 'No CPR write, login, or proxy test is allowed');
  assert.deepEqual(browserBlocked, [], 'Application must make no external browser requests');
  assert.equal(await fs.stat(observations).then(() => true, () => false), false, 'No login/security protocol may start');
  assert.equal(await fs.stat(networkEvents).then(() => true, () => false), false, 'Server must make no external connections');
  const report = {passed: true, localFixtureOnly: true, scenarios: results, screenshots: pictures, createdFutureLocalPlans: scenarios.length, accountOperations: 0, realCprRequests: 0, proxyTests: 0};
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
