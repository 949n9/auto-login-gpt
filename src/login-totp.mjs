import crypto from "node:crypto";

export function generateTotp(secret, timestamp = Date.now()) {
  const key = decodeBase32Secret(secret);
  const counter = BigInt(Math.floor(timestamp / 30_000));
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(counter);
  const digest = crypto.createHmac("sha1", key).update(counterBuffer).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24)
    | ((digest[offset + 1] & 0xff) << 16)
    | ((digest[offset + 2] & 0xff) << 8)
    | (digest[offset + 3] & 0xff);
  return String(binary % 1_000_000).padStart(6, "0");
}

function decodeBase32Secret(value) {
  const normalized = String(value || "").toUpperCase().replace(/[\s=]/g, "");
  if (!/^[A-Z2-7]{16,128}$/.test(normalized)) {
    throw new Error("2FA key must be a Base32 string containing only A-Z and 2-7");
  }
  let bits = "";
  for (const char of normalized) {
    const index = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(char);
    bits += index.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let offset = 0; offset + 8 <= bits.length; offset += 8) {
    bytes.push(Number.parseInt(bits.slice(offset, offset + 8), 2));
  }
  return Buffer.from(bytes);
}

// Leave enough time to submit; never reuse a code generated before slow work.
export async function generateFreshTotp(secret, {
  now = Date.now,
  wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  minimumRemainingMs = 5_000,
} = {}) {
  let timestamp = now();
  const remaining = 30_000 - (timestamp % 30_000);
  if (remaining < minimumRemainingMs) {
    await wait(remaining + 50);
    timestamp = now();
  }
  return generateTotp(secret, timestamp);
}
