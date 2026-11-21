// Component checks only; no server, account operation or external request.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { JSDOM } from 'jsdom';
import { build } from 'esbuild';

const root = path.resolve(import.meta.dirname, '..');
const source = await fs.readFile(path.join(root, 'web/src/account-details.jsx'), 'utf8');
const output = await build({
  stdin: { contents: source + '\nexport { isPartialSecurityOperation, SecurityOperationProgress };', resolveDir: path.join(root, 'web/src'), sourcefile: 'account-details.jsx', loader: 'jsx' },
  bundle: true, write: false, platform: 'node', format: 'cjs', packages: 'external',
});
const module = { exports: {} };
new Function('require', 'module', 'exports', output.outputFiles[0].text)(createRequire(import.meta.url), module, module.exports);
const { securityOperationSummary, isPartialSecurityOperation, SecurityOperationProgress } = module.exports;

for (const action of ['logout-all', 'rotate-totp-logout-all']) {
  const operation = {
    action, status: 'completed', workResetSucceeded: false, workResetUnavailable: true, logoutAccepted: true,
    ...(action === 'rotate-totp-logout-all' ? { credentialsUpdatedAt: '2026-11-13T12:00:00.000Z' } : {}),
  };
  const summary = securityOperationSummary(operation);
  assert.match(summary, /Work接口不可用，已跳过；退出已提交/);
  assert.doesNotMatch(summary, /Work 已重置|Work 重置未确认/);
  assert.equal(isPartialSecurityOperation(operation), false, 'Accepted logout with explicitly skipped unavailable reset is complete');
  const markup = renderToStaticMarkup(React.createElement(SecurityOperationProgress, { operation }));
  assert.match(markup, /本次未重置 Work，继续登出所有设备/);
  assert.doesNotMatch(markup, /Work 工作环境已重置|资料库文件保留|请核实重置结果/);
  const document = new JSDOM(markup).window.document;
  const resetStep = [...document.querySelectorAll('li')].find(step => step.textContent.includes('Work接口不可用'));
  assert.ok(resetStep);
  assert.equal(resetStep.classList.contains('is-complete'), false, 'Skipped reset must not be shown as reset success');
  const logoutStep = [...document.querySelectorAll('li')].find(step => step.textContent.includes('全部设备登出已提交'));
  assert.equal(logoutStep.classList.contains('is-complete'), true);

  const pending = { ...operation, status: 'running', logoutAccepted: false };
  assert.match(securityOperationSummary(pending), /已跳过；正在退出所有设备/);
  assert.doesNotMatch(renderToStaticMarkup(React.createElement(SecurityOperationProgress, { operation: pending })), /Work 重置确认成功后才执行/);
  const failed = { ...operation, status: 'needs_attention', logoutAccepted: false };
  assert.match(securityOperationSummary(failed), /已跳过；退出未确认/);
  assert.equal(isPartialSecurityOperation(failed), true, 'Unconfirmed logout still needs review');
  const otherResetError = { ...operation, workResetUnavailable: false };
  assert.equal(isPartialSecurityOperation(otherResetError), true, 'Other reset failure must not be treated as skipped');
}
assert.equal(securityOperationSummary({ action: 'logout-all', status: 'completed', workResetSucceeded: true, logoutAccepted: true }), 'Work 已重置，全部设备登出已提交');
assert.equal(securityOperationSummary({ action: 'rotate-totp-logout-all', status: 'completed', credentialsUpdatedAt: '2026-11-13T12:00:00.000Z', workResetSucceeded: true, logoutAccepted: true }), '2FA 已更新，Work 已重置，登出已提交');
console.log('Account security UI: unavailable reset skip, accurate summary/progress, completed vs partial, unchanged normal success passed');
