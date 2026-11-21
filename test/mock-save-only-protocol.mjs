// This fixture uses only synthetic credentials and local database state.
if (process.argv.includes("hold-active@example.invalid")) {
  const fs = await import("node:fs/promises");
  await fs.appendFile(process.env.SCHEDULE_TEST_OBSERVATIONS, JSON.stringify({ email: "hold-active@example.invalid", action: "login", at: new Date().toISOString() }) + "\n");
  await new Promise(() => setInterval(() => {}, 10000));
} else if (process.argv.includes("fail-proxy@example.invalid")) {
  const fs = await import("node:fs/promises");
  await fs.appendFile(process.env.SCHEDULE_TEST_OBSERVATIONS, JSON.stringify({ email: "fail-proxy@example.invalid", action: "failed-security", at: new Date().toISOString() }) + "\n");
  const value = { version: 1, code: "PROXY_AUTH_FAILED", phase: "proxy_preflight", journalPresent: false, mutationStarted: false, httpStatus: 407,
    message: "DO-NOT-EXPOSE synthetic-account-password socks5://user:secret@proxy.invalid" };
  const marker = "[security-failure] " + JSON.stringify(value) + "\n";
  process.stdout.write(marker.slice(0, 30));
  await new Promise((resolve) => setTimeout(resolve, 15));
  process.stderr.write(marker.slice(30));
  process.exitCode = 1;
} else {
  await import("./mock-scheduled-protocol.mjs");
}
