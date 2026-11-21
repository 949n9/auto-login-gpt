#!/usr/bin/env node

const emailIndex = process.argv.indexOf("--email");
const email = emailIndex >= 0 ? process.argv[emailIndex + 1] : "unknown@example.invalid";
console.log(`[1/5] Mock queued login started for ${email}`);
console.log("Email OTP (r=resend, q=quit):");

await new Promise((resolve) => {
  const timer = setTimeout(resolve, 60_000);
  process.once("SIGTERM", async () => {
    clearTimeout(timer);
    if (email === "delete-late-writer@example.invalid") {
      const fs = await import("node:fs/promises");
      const path = await import("node:path");
      const output = process.argv[process.argv.indexOf("--sub2api-out") + 1];
      await new Promise(done => setTimeout(done, 150));
      await fs.mkdir(path.dirname(output), { recursive: true });
      await fs.writeFile(output, JSON.stringify({ accounts: [{ credentials: { email } }] }));
    }
    resolve();
  });
});
