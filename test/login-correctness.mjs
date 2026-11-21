import assert from "node:assert/strict";
import { CookieJar } from "../src/login-cookies.mjs";
import { generateFreshTotp, generateTotp } from "../src/login-totp.mjs";

const jar = new CookieJar();
const set = (line, url = "https://example.test/auth/login") => jar.setFromResponse(url, { rawSetCookie: [line] });
set("host=one; Secure");
assert.equal(jar.headerFor("https://sub.example.test/auth/"), "");
assert.equal(jar.headerFor("https://example.test/"), "", "default cookie path is /auth");
assert.equal(jar.headerFor("https://example.test/authentication"), "");
assert.equal(jar.headerFor("https://example.test/auth/"), "host=one");
set("domain=two; Domain=example.test; Path=/; Secure");
assert.equal(jar.headerFor("https://sub.example.test/"), "domain=two");
assert.equal(jar.headerFor("http://example.test/"), "");
set("foreign=bad; Domain=other.test; Path=/");
assert.equal(jar.headerFor("https://other.test/"), "", "reject unrelated cookie domains");
set("public=bad; Domain=test; Path=/");
assert.equal(jar.headerFor("https://other.test/"), "", "reject public suffix cookies");
const restored = CookieJar.fromJSON(jar.toJSON());
assert.equal(restored.headerFor("https://sub.example.test/auth/"), "domain=two");
set("host=gone; Max-Age=0; Path=/auth");
assert.equal(jar.value("host", "https://example.test/auth/"), null);
jar.replace([]);
assert.equal(jar.toJSON().length, 0, "a complete native snapshot must remove deleted cookies");

// RFC 6238 SHA-1 vector, truncated to the six digits used by this login flow.
const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
assert.equal(generateTotp(secret, 59_000), "287082");
let now = 59_000;
let waits = [];
const code = await generateFreshTotp(secret, { now: () => now, wait: async (ms) => { waits.push(ms); now += ms; } });
assert.deepEqual(waits, [1050]);
assert.equal(code, generateTotp(secret, 60_050));
await generateFreshTotp(secret, { now: () => 61_000, wait: async () => { throw new Error("unnecessary wait"); } });
console.log("Cookie host/path/expiry/checkpoint and TOTP clock-boundary tests passed");
