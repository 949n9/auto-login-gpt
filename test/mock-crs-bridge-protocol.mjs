import fs from "node:fs/promises";
import path from "node:path";
import readline from "node:readline/promises";
import { createServerDatabase } from "../src/server-database.mjs";

if (process.env.CPR_PROXY_CAPTURE) await fs.appendFile(process.env.CPR_PROXY_CAPTURE, JSON.stringify({proxy: process.env.CHATGPT_PROXY_URL, totp: process.env.CHATGPT_TOTP_SECRET, pin: process.env.TOSUB2_PIN_PROXY_SESSION, tls: JSON.parse(process.env.TOSUB2_ACCOUNT_TLS || "null")}) + "\n");
const args = process.argv.slice(2);
const email = args[args.indexOf("--email") + 1];
const outputPath = args[args.indexOf("--sub2api-out") + 1];
if (email.startsWith('auto-retry-')) {
  const counter = path.join(process.env.ONBOARDING_OUTPUT_ROOT, email + '.attempts');
  const attempt = Number(await fs.readFile(counter, 'utf8').catch(() => '0')) + 1;
  await fs.writeFile(counter, String(attempt));
  if (email.includes('permanent') || email.includes('always') || email.includes('cancel') || attempt <= 3) {
    if (email.includes('email')) {
      console.log('[email-login-attempt] {"attempt":3,"maxAttempts":3}');
      console.log('[email-login-failed] {"attempts":3,"reason":"EMAIL_OTP_REQUIRED"}');
    }
    console.log(email.includes('permanent') ? '[error] account_deactivated' : '[error] temporary upstream connection failure');
    // Give bridge polling a chance to observe the transient failed status.
    await new Promise(resolve => setTimeout(resolve, 200));
    process.exit(1);
  }
}
if (process.env.CHATGPT_LOGIN_PASSWORD === "test-no-result") process.exit(0);
if (process.env.CHATGPT_LOGIN_PASSWORD !== "test-password") throw new Error("expected saved password");
if (email === "proxy-risk@example.com") {
  console.log("[proxy-risk-retry] PROXY_RISK_CONTROL");
  await new Promise(resolve => setTimeout(resolve, 1000));
  process.exit(1);
}
if (email === "mfa-prompt@example.com") {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  await rl.question("2FA OTP (6 digits, q=quit): ");
  rl.close();
}
const database = createServerDatabase({ outputRoot: process.env.ONBOARDING_OUTPUT_ROOT, databasePath: process.env.ONBOARDING_DATABASE_PATH, mustExist: true });
const value = { type: "sub2api-data", version: 1, accounts: [{ name: email, credentials: { access_token: `test-access-${email}`, refresh_token: `test-refresh-${email}`, email } }] };
try {
  database.saveArtifact(outputPath, value);
  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(outputPath, JSON.stringify(value));
  console.log(`[ok] Saved sub2api import: ${outputPath}`);
} finally { database.close(); }
