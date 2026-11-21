import { Cookie, CookieJar as StandardCookieJar } from "tough-cookie";

// Keep the checkpoint format compatible, adding hostOnly where older versions
// discarded it. Old ambiguous cookies are restored conservatively as host-only.
export class CookieJar {
  constructor(cookies = []) {
    this.jar = new StandardCookieJar();
    this.merge(cookies);
  }

  setFromResponse(url, headers) {
    const lines = headers.rawSetCookie || headers.getSetCookie?.() || [];
    for (const line of lines) this.jar.setCookieSync(line, url, { ignoreError: true });
  }

  matching(url) { return this.jar.getCookiesSync(url); }
  headerFor(url) { return this.jar.getCookieStringSync(url); }
  namesFor(url) { return this.matching(url).map((cookie) => cookie.key); }
  has(name) { return this.toJSON().some((cookie) => cookie.name === name); }
  value(name, url = null) {
    if (url) return this.matching(url).find((cookie) => cookie.key === name)?.value || null;
    return this.toJSON().find((cookie) => cookie.name === name)?.value || null;
  }

  merge(cookies) {
    for (const raw of Array.isArray(cookies) ? cookies : []) {
      if (!raw || typeof raw.name !== "string" || typeof raw.value !== "string"
          || typeof raw.domain !== "string" || !raw.domain) continue;
      const domain = raw.domain.replace(/^\./, "").toLowerCase();
      const hostOnly = typeof raw.hostOnly === "boolean" ? raw.hostOnly : !raw.domain.startsWith(".");
      const cookie = new Cookie({
        key: raw.name, value: raw.value, domain, hostOnly,
        path: raw.path?.startsWith("/") ? raw.path : "/",
        secure: Boolean(raw.secure), httpOnly: Boolean(raw.httpOnly),
        expires: raw.expires == null ? "Infinity" : new Date(raw.expires),
      });
      const protocol = raw.secure ? "https" : "http";
      this.jar.setCookieSync(cookie, `${protocol}://${domain}${cookie.path}`, { ignoreError: true });
    }
  }

  replace(cookies) {
    this.jar = new StandardCookieJar();
    this.merge(cookies);
  }

  toJSON() {
    return this.jar.serializeSync().cookies.map((raw) => Cookie.fromJSON(raw))
      .filter((cookie) => cookie && cookie.expiryTime() > Date.now())
      .map((cookie) => ({
        name: cookie.key, value: cookie.value, domain: cookie.domain,
        path: cookie.path, hostOnly: cookie.hostOnly, secure: cookie.secure,
        httpOnly: cookie.httpOnly,
        expires: Number.isFinite(cookie.expiryTime()) ? cookie.expiryTime() : null,
      }));
  }

  static fromJSON(cookies) { return new CookieJar(cookies); }
}
