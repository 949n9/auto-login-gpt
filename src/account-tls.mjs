import crypto from "node:crypto";

export const DEFAULT_ACCOUNT_TLS_PROFILE = "chrome152_macos";

// Retained only to validate legacy records before migration. Native profiles
// control their own ClientHello extensions and permutation.
export const ACCOUNT_TLS_EXTENSIONS = Object.freeze([
  0, 5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51, 17613, 51764, 65037, 65281,
]);
const KIND = "account-tls-v2";
const LEGACY_KIND = "account-tls-v1";
const LEGACY_RESERVATION = "account-tls-order-v1";

export function normalizeTlsAccount(email) {
  const value = String(email || "").trim().toLowerCase();
  if (!value || value.length > 320 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
    throw new Error("ACCOUNT_TLS_INVALID: a valid account email is required");
  }
  return value;
}

function orderId(order, profile = "chrome152") {
  return crypto.createHash("sha256").update(`${profile}:${order}`).digest("hex");
}

export function validateAccountTls(identity, email) {
  const account = normalizeTlsAccount(email);
  if (identity?.version === 2) {
    if (identity.account !== account || identity.profile !== DEFAULT_ACCOUNT_TLS_PROFILE
        || identity.mode !== "native" || Object.hasOwn(identity, "extensionOrder")
        || identity.id !== nativeIdentity(account).id) {
      throw new Error("ACCOUNT_TLS_INVALID: saved account TLS configuration is invalid");
    }
    return identity;
  }
  const order = String(identity?.extensionOrder || "");
  const values = order.split("-").map(Number);
  const expected = identity?.profile === "chrome146" ? ACCOUNT_TLS_EXTENSIONS.filter((value) => value !== 51764) : ACCOUNT_TLS_EXTENSIONS;
  if (identity?.version !== 1 || !["chrome146", "chrome152"].includes(identity.profile)
      || identity.account !== account || typeof identity.extensionOrder !== "string"
      || values.length !== expected.length
      || new Set(values).size !== values.length
      || !values.every((value) => expected.includes(value))
      || values.join("-") !== order || identity.id !== orderId(order, identity.profile)) {
    throw new Error("ACCOUNT_TLS_INVALID: saved account TLS configuration is invalid");
  }
  return identity;
}

function nativeIdentity(account) {
  const profile = DEFAULT_ACCOUNT_TLS_PROFILE;
  // This ID identifies the saved account configuration, not a wire fingerprint.
  const id = crypto.createHash("sha256")
    .update(`${KIND}:${account}:${profile}:native`).digest("hex");
  return { version: 2, account, profile, mode: "native", id };
}

export function upgradeAccountTlsIdentity(identity, email) {
  validateAccountTls(identity, email);
  return identity.version === 2 ? identity : nativeIdentity(normalizeTlsAccount(email));
}

export function getAccountTls(database, email) {
  const account = normalizeTlsAccount(email);
  return database.transaction(() => {
    const existing = database.get(KIND, account);
    if (existing !== null) {
      if (existing.version !== 2) {
        throw new Error("ACCOUNT_TLS_INVALID: unexpected account TLS record version");
      }
      validateAccountTls(existing, account);
      return existing;
    }
    const legacy = database.get(LEGACY_KIND, account);
    if (legacy !== null) {
      if (legacy.version !== 1) {
        throw new Error("ACCOUNT_TLS_INVALID: unexpected legacy TLS record version");
      }
      validateAccountTls(legacy, account);
      if (database.get(LEGACY_RESERVATION, legacy.id)?.account !== account) {
        throw new Error("ACCOUNT_TLS_INVALID: TLS reservation does not match account");
      }
    }
    const identity = legacy !== null ? upgradeAccountTlsIdentity(legacy, account) : nativeIdentity(account);
    database.put(KIND, account, identity);
    return identity;
  });
}
