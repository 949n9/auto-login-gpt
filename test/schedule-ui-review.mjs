// Local-only visual review. All accounts, proxies and CPR responses are fixtures.
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import http from 'node:http';
import {spawn} from 'node:child_process';
const root=path.resolve(import.meta.dirname,'..');
const temporary=await fs.mkdtemp(path.join(os.tmpdir(),'cpr-schedule-ui-'));
const pictures=path.join(root,'ui-review');await fs.mkdir(pictures,{recursive:true});
const wait=ms=>new Promise(r=>setTimeout(r,ms));
const remote=http.createServer(async(req,res)=>{
 for await(const _ of req){}
 const url=new URL(req.url,'http://127.0.0.1');
 let data={};
 if(url.pathname==='/api/admin/account-groups/options')data={items:[{id:'openai',name:'OpenAI',enabled:true}],page:{totalPages:1}};
 else if(url.pathname==='/api/admin/proxies')data={items:[{id:'ui-proxy',endpoint:'socks5://ui-proxy.example.invalid:1080',hasAuthentication:false,enabled:true}],page:{page:1,totalPages:1}};
 else if(url.pathname==='/api/admin/system/version')data={version:'UI-fixture'};
 res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({code:200,data}));
});
await new Promise(r=>remote.listen(0,'127.0.0.1',r));
const listener=net.createServer();await new Promise(r=>listener.listen(0,'127.0.0.1',r));const port=listener.address().port;await new Promise(r=>listener.close(r));
let server,browser,socket;let serverLog='',browserLog='';
try {
 server=spawn(process.execPath,['src/console-server.mjs','--host','127.0.0.1','--port',String(port)],{cwd:root,env:{...process.env,NODE_ENV:'production',ONBOARDING_OUTPUT_ROOT:path.join(temporary,'data'),ONBOARDING_PROTOCOL_SCRIPT:path.join(root,'test/mock-scheduled-protocol.mjs'),SCHEDULE_TEST_OBSERVATIONS:path.join(temporary,'observations.jsonl')},stdio:['ignore','pipe','pipe']});
 for(const stream of [server.stdout,server.stderr])stream.on('data',b=>{serverLog+=b.toString();});
 const base=`http://127.0.0.1:${port}`;let token;
 for(let i=0;i<100;i++){try{token=(await(await fetch(base+'/api/bootstrap')).json()).token;if(token)break;}catch{}await wait(50);}
 if(!token)throw Error('Fixture server unavailable: '+serverLog.slice(-1000));
 const api=async(endpoint,body,method=body===undefined?'GET':'POST')=>{const r=await fetch(base+endpoint,{method,headers:{'x-console-token':token,'content-type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});const d=await r.json();if(!r.ok)throw Error(endpoint+': '+JSON.stringify(d));return d;};
 await api('/api/crs/config',{config:{baseUrl:`http://127.0.0.1:${remote.address().port}`,authType:'apiKey',apiKey:'fake-ui-only-key',autoUpload:true},revision:0},'PUT');
 const settings=await api('/api/settings');
 await api('/api/settings',{section:'proxyLibrary',revision:settings.revisions.proxyLibrary||0,value:{selectedId:'ui-proxy',proxies:[{id:'ui-proxy',name:'演示 SOCKS5 代理',url:'socks5://ui-proxy.example.invalid:1080'}]}},'PUT');
 const profile=path.join(temporary,'chrome');
 browser=spawn(process.env.CHROME_BIN || '/usr/bin/chromium',['--headless','--disable-background-networking','--disable-component-update','--disable-sync','--no-first-run','--no-default-browser-check','--remote-debugging-port=0',`--user-data-dir=${profile}`,'about:blank'],{stdio:['ignore','ignore','pipe']});
 browser.stderr.on('data',b=>{browserLog+=b.toString();});let debugPort;
 for(let i=0;i<300;i++){try{debugPort=(await fs.readFile(path.join(profile,'DevToolsActivePort'),'utf8')).split('\n')[0];if(debugPort)break;}catch{}if(browser.exitCode!==null)break;await wait(50);}
 if(!debugPort)throw Error('Isolated headless browser unavailable: '+browserLog.slice(-1000));
 const targets=await(await fetch(`http://127.0.0.1:${debugPort}/json/list`)).json();
 socket=new WebSocket(targets.find(t=>t.type==='page').webSocketDebuggerUrl);await new Promise((r,j)=>{socket.onopen=r;socket.onerror=j;});
 let nextId=0;const pending=new Map();socket.onmessage=e=>{const m=JSON.parse(e.data);if(m.id){const p=pending.get(m.id);if(p){pending.delete(m.id);m.error?p.reject(Error(JSON.stringify(m.error))):p.resolve(m.result);}}};
 const command=(method,params={})=>new Promise((resolve,reject)=>{const id=++nextId;pending.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params}));});
 const evaluate=async expression=>{const r=await command('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw Error(r.exceptionDetails.text);return r.result.value;};
 const click=async text=>{const result=await evaluate(`(()=>{const b=[...document.querySelectorAll('button')].find(b=>b.textContent.trim()===${JSON.stringify(text)}&&!b.disabled);if(!b)return false;b.click();return true;})()`);if(!result)throw Error('Missing enabled button: '+text);await wait(180);};
 const screenshot=async name=>{const r=await command('Page.captureScreenshot',{format:'png'});await fs.writeFile(path.join(pictures,name),Buffer.from(r.data,'base64'));};
 await command('Page.enable');await command('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false});await command('Page.navigate',{url:base});await wait(1200);
 await click('自动定时任务');await screenshot('schedule-input.png');
 const text='demo-schedule-1@example.invalid----FAKE-password----JBSWY3DPEHPK3PXP\ndemo-schedule-2@example.invalid----FAKE-password----JBSWY3DPEHPK3PXP';
 await evaluate(`(()=>{const e=document.querySelector('#schedule-account-input');Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set.call(e,${JSON.stringify(text)});e.dispatchEvent(new Event('input',{bubbles:true}));})()`);
 await wait(120);await click('识别账号');await wait(300);await screenshot('schedule-accounts.png');
 await click('应用到全部');await click('设置时间与操作');
 for(const text of ['先更换 2FA','重置 Work 并登出所有设备'])await evaluate(`(()=>{const l=[...document.querySelectorAll('label')].find(l=>l.querySelector('strong')?.textContent===${JSON.stringify(text)});if(!l)throw Error('Missing option');l.querySelector('input').click();})()`);
 await wait(150);await screenshot('schedule-settings.png');
 await command('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});await screenshot('schedule-mobile.png');
 await command('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false});await click('生成计划预览');await wait(350);await screenshot('schedule-preview.png');
 const preview=await evaluate("document.querySelector('.schedule-dialog')?.innerText || document.querySelector('[role=dialog]')?.innerText || document.body.innerText");
 if(!preview.includes('北京时间')||!preview.includes('99')||!preview.includes('20'))throw Error('Preview defaults or BJT missing');
 await evaluate("document.querySelector('.schedule-confirmation input').click()");await wait(120);await click('确认创建计划');await wait(450);await screenshot('schedule-history.png');
 const result=await api('/api/schedules');
 if(result.schedules.length!==1||result.schedules[0].total!==2||result.schedules[0].status!=='scheduled')throw Error('Fixture schedule not saved as expected');
 if(await fs.stat(path.join(temporary,'observations.jsonl')).then(()=>true,()=>false))throw Error('Future-only UI review started a login unexpectedly');
 console.log(JSON.stringify({uiFixture:true,screenshots:pictures,createdFuturePlans:1,accounts:2,noAccountOperations:true}));
} finally {
 socket?.close();browser?.kill('SIGTERM');server?.kill('SIGTERM');await wait(400);await new Promise(r=>remote.close(r));await fs.rm(temporary,{recursive:true,force:true});
}
