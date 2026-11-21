import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { spawn } from 'node:child_process';
const root = path.resolve(import.meta.dirname, '..');
const output = await fs.mkdtemp(path.join(os.tmpdir(), 'details-api-'));
const sock = net.createServer(); await new Promise(r => sock.listen(0, '127.0.0.1', r)); const port = sock.address().port; await new Promise(r => sock.close(r));
const url = `http://127.0.0.1:${port}`;
let child, token;
async function start() {
  child = spawn(process.execPath, ['src/console-server.mjs', '--host', '127.0.0.1', '--port', String(port)], { cwd: root, env: { ...process.env, ONBOARDING_OUTPUT_ROOT: output, ONBOARDING_PROTOCOL_SCRIPT: path.join(root,'test/mock-protocol-login.mjs'), TOSUB2_TLS_PROFILE: 'chrome142' }, stdio: 'ignore' });
  for(let i=0;i<100;i++) { try { token = (await (await fetch(url+'/api/bootstrap')).json()).token; if(token) return; } catch {} await new Promise(r=>setTimeout(r,50)); }
  throw Error('server startup failed');
}
async function stop() { const done = new Promise(r=>child.once('exit',r));child.kill('SIGTERM');await done; }
async function api(p, body) { const r = await fetch(url+p, { method: body === undefined ? 'GET' : 'POST', headers: {'x-console-token':token,'content-type':'application/json'}, ...(body===undefined?{}:{body:JSON.stringify(body)}) }); assert.equal(r.ok,true,`${p}: ${r.status}`); assert.equal(r.headers.get('cache-control'),'no-store');return r.json(); }
async function completed(id) { for(let i=0;i<100;i++) { const j=await api('/api/jobs/'+id+'/details');if(j.status==='completed')return;await new Promise(r=>setTimeout(r,50)); }throw Error('job did not finish'); }
try {
 await start();
 const created=await api('/api/jobs',{email:'details-test@example.com',password:'TEST-only-password',totpSecret:'JBSWY3DPEHPK3PXP'}); const id=created.job.id;
 await completed(id);
 assert.equal((await fetch(url+'/api/jobs/'+id+'/details')).status,403);
 assert.equal((await fetch(url+'/api/jobs/'+id+'/secrets',{method:'POST'})).status,403);
 let detail=await api('/api/jobs/'+id+'/details');assert.equal(detail.history.total,1);assert.equal(detail.history.events[0].status,'completed');assert.equal(JSON.stringify(detail).includes('TEST-only-password'),false);
 const first=detail.history.firstAddedAt;
 const secrets=await api('/api/jobs/'+id+'/secrets',{});assert.equal(secrets.password,'TEST-only-password');assert.equal(secrets.totpSecret,'JBSWY3DPEHPK3PXP');
 await api('/api/jobs/'+id+'/relogin',{});await completed(id);
 detail=await api('/api/jobs/'+id+'/details');assert.equal(detail.history.total,2);assert.equal(detail.history.firstAddedAt,first);
 await stop();await start(); detail=await api('/api/jobs/'+id+'/details');assert.equal(detail.history.total,2);assert.equal(detail.history.firstAddedAt,first);
 const listing=await api('/api/jobs');assert.equal(JSON.stringify(listing).includes('TEST-only-password'),false);assert.equal(JSON.stringify(listing).includes('JBSWY3DPEHPK3PXP'),false);
 console.log('details API: authentication, no-store, masked list, saved secrets, relogin and restart passed');
} finally { if(child?.exitCode===null)await stop(); await fs.rm(output,{recursive:true,force:true}); }
