'use strict';

(() => {
  const root = document.documentElement;
  const themeToggle = document.getElementById('theme-toggle');
  const preferredDark = window.matchMedia('(prefers-color-scheme: dark)');
  let savedTheme = null;
  try {
    const value = localStorage.getItem('tosub2-login-theme');
    if (value === 'light' || value === 'dark') savedTheme = value;
  } catch { /* Theme persistence is optional. */ }

  function applyTheme() {
    const dark = savedTheme ? savedTheme === 'dark' : preferredDark.matches;
    root.dataset.theme = dark ? 'dark' : 'light';
    themeToggle.setAttribute('aria-label', dark ? '切换浅色主题' : '切换深色主题');
    themeToggle.title = dark ? '切换浅色主题' : '切换深色主题';
  }
  applyTheme();
  preferredDark.addEventListener('change', applyTheme);
  themeToggle.addEventListener('click', () => {
    savedTheme = root.dataset.theme === 'dark' ? 'light' : 'dark';
    try { localStorage.setItem('tosub2-login-theme', savedTheme); } catch { /* Optional preference. */ }
    applyTheme();
  });

  const password = document.getElementById('password');
  const passwordToggle = document.getElementById('password-toggle');
  passwordToggle.addEventListener('click', () => {
    const visible = password.type === 'password';
    password.type = visible ? 'text' : 'password';
    passwordToggle.setAttribute('aria-pressed', String(visible));
    passwordToggle.setAttribute('aria-label', visible ? '隐藏密码' : '显示密码');
  });

  const form = document.getElementById('login-form');
  const submit = document.getElementById('login-submit');
  const submitLabel = submit.querySelector('span');
  let submitting = false;
  form.addEventListener('submit', (event) => {
    if (submitting) {
      event.preventDefault();
      return;
    }
    // Native required validation and the actual input values include browser autofill.
    // Let the browser POST normally, preserving its password-save flow and 303 redirect.
    submitting = true;
    submit.disabled = true;
    submitLabel.textContent = '正在登录';
    form.setAttribute('aria-busy', 'true');
  });
  window.addEventListener('pageshow', () => {
    submitting = false;
    submit.disabled = false;
    submitLabel.textContent = '登录';
    form.removeAttribute('aria-busy');
    password.type = 'password';
    passwordToggle.setAttribute('aria-pressed', 'false');
    passwordToggle.setAttribute('aria-label', '显示密码');
  });

  const messages = new Map([
    ['credentials', '账号或密码不正确，请重新输入。'],
    ['rate_limited', '尝试次数较多，请稍后再试。'],
    ['session_expired', '登录已过期，请重新登录。'],
    ['unavailable', '暂时无法登录，请稍后再试。'],
    ['bad_request', '登录请求无效，请重新提交。'],
  ]);
  const error = document.getElementById('login-error');
  const code = new URLSearchParams(window.location.search).get('error');
  if (messages.has(code)) {
    error.textContent = messages.get(code);
    error.hidden = false;
  }

  async function checkSession() {
    try {
      const response = await fetch('/auth/status', {
        method: 'GET', credentials: 'same-origin', cache: 'no-store',
        headers: { Accept: 'application/json' },
      });
      if (!response.ok) return;
      const status = await response.json();
      if (status.authenticated !== true || submitting) return;
      form.hidden = true;
      error.hidden = true;
      document.getElementById('login-description').textContent = '您已登录，可以直接进入控制台。';
      document.getElementById('authenticated-panel').hidden = false;
    } catch { /* An unavailable status endpoint must not prevent native sign-in. */ }
  }
  void checkSession();
})();
