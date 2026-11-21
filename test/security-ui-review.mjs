// Visual review uses only temporary data, fake accounts and the offline mock.
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import {spawn} from 'node:child_process';
const root=path.resolve(import.meta.dirname,'..');
const temporary=await fs.mkdtemp(path.join(os.tmpdir(),'cpr-security-ui-'));
const pictures=path.join(root,'ui-review');await fs.mkdir(pictures,{recursive:true});
const listener=net.createServer();await new Promise(r=>listener.listen(0,'127.0.0.1',r));const port=listener.address().port;await new Promise(r=>listener.close(r));
let server,browser,socket;let serverLog='',browserLog='';
const wait=ms=>new Promise(r=>setTimeout(r,ms));
try {
 server=spawn(process.execPath,['src/console-server.mjs','--host','127.0.0.1','--port',String(port)],{cwd:root,env:{...process.env,NODE_ENV:'production',ONBOARDING_OUTPUT_ROOT:path.join(temporary,'data'),ONBOARDING_PROTOCOL_SCRIPT:path.join(root,'test/mock-security-protocol.mjs'),SECURITY_TEST_OBSERVATIONS:path.join(temporary,'observations.jsonl')},stdio:['ignore','pipe','pipe']});
 for(const stream of [server.stdout,server.stderr])stream.on('data',b=>{serverLog+=b.toString();});
 const base=`http://127.0.0.1:${port}`;let token;
 for(let i=0;i<100;i++){try{token=(await(await fetch(base+'/api/bootstrap')).json()).token;if(token)break;}catch{}await wait(50);}
 if(!token)throw Error('Fixture server unavailable: '+serverLog.slice(-1000));
 const api=async(endpoint,body)=>{const r=await fetch(base+endpoint,{method:body===undefined?'GET':'POST',headers:{'x-console-token':token,'content-type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});const d=await r.json();if(!r.ok)throw Error(endpoint+': '+JSON.stringify(d));return d;};
 const ids=[];
 for(let i=1;i<=5;i++){const r=await api('/api/jobs',{email:`demo-account-${i}@example.invalid`,password:'FAKE-only-ui-password',totpSecret:'JBSWY3DPEHPK3PXP',proxyUrl:'socks5://ui-proxy.example.invalid:1080'});ids.push(r.job.id);}
 for(let i=0;i<80;i++){const jobs=(await api('/api/jobs')).jobs;if(jobs.every(j=>j.status==='completed'))break;await wait(100);}
 await api(`/api/jobs/${ids[0]}/security`,{action:'rotate-totp-logout-all'});
 for(let i=0;i<80;i++){const d=await api(`/api/jobs/${ids[0]}/details`);if(d.securityOperation?.status==='completed')break;await wait(100);}
 const profile=path.join(temporary,'chrome');
 browser=spawn(process.env.CHROME_BIN || '/usr/bin/chromium',['--headless','--disable-background-networking','--disable-component-update','--disable-sync','--no-first-run','--no-default-browser-check','--remote-debugging-port=0',`--user-data-dir=${profile}`,'about:blank'],{stdio:['ignore','ignore','pipe']});
 browser.stderr.on('data',b=>{browserLog+=b.toString();});
 let debugPort;
 for(let i=0;i<300;i++){try{debugPort=(await fs.readFile(path.join(profile,'DevToolsActivePort'),'utf8')).split('\n')[0];if(debugPort)break;}catch{}if(browser.exitCode!==null)break;await wait(50);}
 if(!debugPort)throw Error('Isolated headless Chrome did not start: '+browserLog.slice(-1200));
 const targets=await(await fetch(`http://127.0.0.1:${debugPort}/json/list`)).json();
 socket=new WebSocket(targets.find(t=>t.type==='page').webSocketDebuggerUrl);await new Promise((r,j)=>{socket.onopen=r;socket.onerror=j;});
 let nextId=0;const pending=new Map();socket.onmessage=e=>{const m=JSON.parse(e.data);if(m.id){const p=pending.get(m.id);if(p){pending.delete(m.id);m.error?p.reject(Error(JSON.stringify(m.error))):p.resolve(m.result);}}};
 const command=(method,params={})=>new Promise((resolve,reject)=>{const id=++nextId;pending.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params}));});
 const evaluate=async expression=>(await command('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true})).result.value;
 const screenshot=async name=>{const r=await command('Page.captureScreenshot',{format:'png'});await fs.writeFile(path.join(pictures,name),Buffer.from(r.data,'base64'));};
 await command('Page.enable');await command('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false});await command('Page.navigate',{url:base});await wait(1500);
 await evaluate("document.querySelector('.task-table')?.scrollIntoView({block:'start'})");
 await screenshot('desktop-list.png');
 await evaluate("[...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='账号安全'&&!b.disabled)?.click()");await wait(150);
 await screenshot('desktop-actions.png');
 const actions=await evaluate("document.querySelector('.security-choice-dialog')?.innerText || document.querySelector('[role=dialog]')?.innerText");
 await evaluate("[...document.querySelectorAll('button')].find(b=>b.textContent.includes('更换 2FA、重置 Work')&&!b.disabled)?.click()");await wait(150);
 await screenshot('desktop-confirmation.png');
 await command('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});await screenshot('mobile-confirmation.png');
 await command('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false});await command('Page.navigate',{url:base});await wait(600);
 await evaluate("[...document.querySelectorAll('tr')].find(r=>r.textContent.includes('demo-account-1@'))?.querySelectorAll('button').forEach(b=>{if(b.textContent.trim()==='详情')b.click()})");await wait(300);await screenshot('desktop-details.png');
 const details=await evaluate("document.querySelector('[role=dialog]')?.innerText || document.body.innerText");
 if(!details.includes('新 2FA 已验证并保存')||!details.includes('Work 工作环境已重置')||!details.includes('全部设备登出已提交'))throw Error('Completed security steps missing from account details');
 console.log(JSON.stringify({uiFixture:true,screenshots:pictures,actions,details}));
} finally {
 socket?.close();browser?.kill('SIGTERM');server?.kill('SIGTERM');await wait(400);await fs.rm(temporary,{recursive:true,force:true});
}
