#!/usr/bin/env python3
"""Small NDJSON bridge around curl_cffi for browser-like TLS requests."""

import base64
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from http.cookiejar import Cookie
from pathlib import Path
import re
import sys
from typing import get_args
from urllib.parse import urljoin, urlparse

try:
    from curl_cffi import requests, Curl, CurlOpt, CurlInfo, CurlHttpVersion
    from curl_cffi.requests.cookies import CurlMorsel
    from curl_cffi.requests.impersonate import BrowserTypeLiteral
    IMPORT_ERROR = None
except Exception as error:  # pragma: no cover - exercised on missing local dependency
    requests = None
    BrowserTypeLiteral = None
    IMPORT_ERROR = f"{type(error).__name__}: {error}"


SOLVER_PATH = Path(__file__).resolve().parent / "cloudflare-ctf" / "cloudflare_solver.py"
SENTINEL_DIR = Path(__file__).resolve().parent / "cloudflare-ctf"
if str(SENTINEL_DIR) not in sys.path:
    sys.path.insert(0, str(SENTINEL_DIR))
from sentinel_client import SentinelClient
SOLVER_SPEC = importlib.util.spec_from_file_location("tosub2_cloudflare_solver", SOLVER_PATH)
if SOLVER_SPEC is not None and SOLVER_SPEC.loader is not None:
    CLOUDFLARE_SOLVER = importlib.util.module_from_spec(SOLVER_SPEC)
    SOLVER_SPEC.loader.exec_module(CLOUDFLARE_SOLVER)
else:  # pragma: no cover - installation corruption
    CLOUDFLARE_SOLVER = None


def write_message(payload):
    sys.stdout.write(json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()


class Worker:
    def __init__(self):
        self.session = None
        self.proxy = None
        self.impersonate = "chrome152_macos"
        self.verify_tls = True
        self.strict_profile = False
        self.extension_order = None
        self.sentinel_client = None
        self.fallback_profiles = ("chrome146", "chrome145", "chrome142", "chrome136")

    def configure(self, proxy, impersonate, allow_fallback=True, verify_tls=True,
                  extension_order=None, strict_profile=False):
        if IMPORT_ERROR:
            raise RuntimeError(
                "Python curl_cffi is unavailable. Run: python -m pip install -r requirements.txt "
                f"({IMPORT_ERROR})"
            )
        self.close_sentinel()
        if self.session is not None:
            self.session.close()
            self.session = None
        self.proxy = proxy or None
        if verify_tls is not True:
            raise RuntimeError("TLS certificate verification cannot be disabled")
        self.verify_tls = True
        self.strict_profile = bool(strict_profile)
        self.extension_order = extension_order
        requested_profile = impersonate or "chrome152_macos"
        if requested_profile == "chrome152_macos" and extension_order is not None:
            raise RuntimeError("ACCOUNT_TLS_INVALID: macOS profile requires native TLS extension ordering")
        if extension_order is not None:
            expected = {0, 5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51, 17613, 65037, 65281}
            if requested_profile == "chrome152":
                expected.add(51764)
            parts = str(extension_order).split("-")
            if (requested_profile not in ("chrome146", "chrome152") or not strict_profile
                    or len(parts) != len(expected) or not all(p.isdigit() for p in parts)
                    or set(map(int, parts)) != expected):
                raise RuntimeError("ACCOUNT_TLS_INVALID: invalid pinned extension order")
        profiles = [requested_profile]
        if allow_fallback and not self.strict_profile:
            profiles.extend(
                profile for profile in self.fallback_profiles if profile != requested_profile
            )

        last_error = None
        for profile in profiles:
            try:
                # requests.Session delays impersonation until the first request.
                # Check the native library here, before headers or credentials
                # are prepared, so Node receives the actual profile up front.
                probe = Curl()
                try:
                    if probe.impersonate(profile) != 0:
                        raise RuntimeError(f"Impersonating {profile} is not supported")
                finally:
                    probe.close()
                session_options = {"impersonate": profile}
                if self._uses_local_http_proxy():
                    session_options["proxies"] = {
                        "http": self.proxy,
                        "https": self.proxy,
                    }
                else:
                    session_options["proxy"] = self.proxy
                ca_bundle = os.environ.get("TOSUB2_CA_BUNDLE")
                if ca_bundle:
                    if not Path(ca_bundle).is_file():
                        raise RuntimeError("TOSUB2_CA_BUNDLE does not identify a CA file")
                    session_options["verify"] = ca_bundle
                curl_options = {}
                if self.proxy:
                    # An explicitly selected proxy must also cover hosts in
                    # inherited NO_PROXY/no_proxy, including the wildcard '*'.
                    # Keep environment behavior unchanged for direct sessions.
                    curl_options[CurlOpt.NOPROXY] = ""
                if self.proxy and urlparse(self.proxy).scheme == "socks5":
                    # SOCKS5 resolves targets locally. Some IPv4 proxy exits
                    # cannot connect to AAAA answers and close during TLS.
                    # Keep local DNS and the same proxy; socks5h still resolves
                    # remotely and must retain its original address handling.
                    curl_options[CurlOpt.IPRESOLVE] = 1  # CURL_IPRESOLVE_V4
                if extension_order:
                    session_options["http_version"] = CurlHttpVersion.V2_0
                    curl_options.update({
                        CurlOpt.SSL_PERMUTE_EXTENSIONS: 0,
                        CurlOpt.TLS_EXTENSION_ORDER: extension_order,
                    })
                if curl_options:
                    session_options["curl_options"] = curl_options
                self.session = requests.Session(**session_options)
                self.impersonate = profile
                if profile != requested_profile:
                    sys.stderr.write(
                        f"[tls] 指纹 {requested_profile} 不受当前 curl_cffi 支持，已降级为 {profile}\n"
                    )
                return
            except Exception as error:
                last_error = error
                self.session = None
                if not self._is_unsupported_impersonate(error):
                    raise
        raise last_error

    def _uses_local_http_proxy(self):
        if not self.proxy:
            return False
        parsed = urlparse(self.proxy)
        hostname = (parsed.hostname or "").lower()
        return parsed.scheme == "http" and hostname in {"localhost", "127.0.0.1", "::1"}

    def probe_profiles(self, url, profiles=None, timeout_ms=15000, concurrency=4):
        if IMPORT_ERROR:
            raise RuntimeError(
                "Python curl_cffi is unavailable. Run: python -m pip install -r requirements.txt "
                f"({IMPORT_ERROR})"
            )
        candidates = profiles or self._supported_chrome_profiles()
        if not candidates:
            raise RuntimeError("No desktop Chrome fingerprints are available in the installed curl_cffi")

        if self.session is not None:
            self.session.close()
        self.session = None
        failures = []
        attempts = 0
        batch_size = max(1, min(4, int(concurrency or 4)))
        for offset in range(0, len(candidates), batch_size):
            batch = candidates[offset:offset + batch_size]
            with ThreadPoolExecutor(max_workers=len(batch)) as executor:
                results = list(executor.map(
                    lambda profile: self._probe_profile(profile, url, timeout_ms),
                    batch,
                ))
            attempts += len(batch)

            selected_index = next(
                (index for index, result in enumerate(results) if result[1] is not None),
                None,
            )
            if selected_index is not None:
                selected_profile = batch[selected_index]
                selected_session = results[selected_index][0]
                for index, (session, _, _) in enumerate(results):
                    if index != selected_index and session is not None:
                        session.close()
                self.session = selected_session
                self.proxy = None
                self.impersonate = selected_profile
                return {"profile": selected_profile, "attempts": attempts}

            for profile, (session, _, failure) in zip(batch, results):
                if session is not None:
                    session.close()
                failures.append(f"{profile}={failure}")

        summary = ", ".join(failures[-8:])
        raise RuntimeError(
            "No supported desktop Chrome fingerprint reached ChatGPT without a security-check page"
            + (f": {summary}" if summary else "")
        )

    @classmethod
    def _probe_profile(cls, profile, url, timeout_ms):
        session = None
        try:
            session = requests.Session(impersonate=profile, proxy=None)
            response = session.get(
                url,
                timeout=max(1, int(timeout_ms)) / 1000,
                allow_redirects=False,
            )
            if cls._is_usable_probe_response(response, url):
                return session, response, None
            return session, None, f"HTTP {int(response.status_code)}"
        except Exception as error:
            return session, None, type(error).__name__

    @staticmethod
    def _supported_chrome_profiles():
        values = get_args(BrowserTypeLiteral) if BrowserTypeLiteral is not None else ()
        profiles = {
            value for value in values
            if isinstance(value, str) and re.fullmatch(r"chrome\d+[a-z]?(?:_macos)?", value)
        }

        def sort_key(profile):
            match = re.fullmatch(r"chrome(\d+)([a-z]?)(_macos)?", profile)
            return (int(match.group(1)), bool(match.group(3)), match.group(2))

        return sorted(profiles, key=sort_key, reverse=True)

    @staticmethod
    def _is_usable_probe_response(response, request_url="https://chatgpt.com/"):
        status = int(response.status_code)
        headers = {str(name).lower(): str(value) for name, value in response.headers.items()}
        if not 200 <= status < 400:
            return False
        if "challenge" in (headers.get("cf-mitigated") or headers.get("x-cf-mitigated") or "").lower():
            return False
        if 300 <= status < 400:
            location = headers.get("location") or ""
            if not location:
                return False
            target = urlparse(urljoin(request_url, location))
            source = urlparse(request_url)
            if target.hostname != source.hostname:
                return False
            if re.search(r"cdn-cgi|challenge|captcha|security-check|verify", target.path + "?" + target.query, re.I):
                return False
        body = bytes(response.content or b"")[:200000].decode("utf-8", errors="ignore")
        return re.search(r"Just a moment|cdn-cgi|challenge-platform|cf-challenge", body, re.I) is None

    @staticmethod
    def _is_unsupported_impersonate(error):
        message = str(error or "")
        return "impersonat" in message.lower() and "not supported" in message.lower()

    def _request_with_profile_fallback(self, method, url, headers, body_bytes, timeout_ms):
        try:
            return self.session.request(
                method,
                url,
                headers=headers,
                data=body_bytes,
                timeout=timeout_ms / 1000,
                allow_redirects=False,
            )
        except Exception as error:
            if not self._is_unsupported_impersonate(error):
                raise

            raise RuntimeError("TLS_PROFILE_UNAVAILABLE: active profile is unsupported; request was not replayed") from error

    def request(self, message):
        if self.session is None:
            self.configure(message.get("proxy"), message.get("impersonate"))

        if "restoreCookies" in message:
            self.restore_cookies(message["restoreCookies"])

        method = str(message.get("method") or "GET").upper()
        url = str(message.get("url") or "")
        headers = {}
        for pair in message.get("headers") or []:
            if isinstance(pair, list) and len(pair) == 2:
                headers[str(pair[0])] = str(pair[1])

        body = message.get("body")
        body_bytes = base64.b64decode(body) if body else None
        timeout_ms = max(1, int(message.get("timeoutMs") or 30000))
        response = self._request_with_profile_fallback(
            method, url, headers, body_bytes, timeout_ms
        )
        # curl_cffi merges the native cookie list into its Python jar. Replace
        # it with the authoritative native snapshot so deleted cookies cannot
        # be re-imported on the next request. curl_easy_reset retains cookies.
        morsels = [CurlMorsel.from_curl_format(value)
                   for value in self.session.curl.getinfo(CurlInfo.COOKIELIST)]
        self.session.cookies.clear()
        self.session.cookies.update_cookies_from_curl(morsels)
        header_items = list(response.headers.multi_items()) if hasattr(response.headers, "multi_items") else list(response.headers.items())
        cookies = []
        cookie_jar = getattr(self.session.cookies, "jar", None)
        if cookie_jar is not None:
            for cookie in cookie_jar:
                cookies.append({
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain.lstrip("."),
                    "path": cookie.path or "/",
                    "secure": bool(cookie.secure),
                    "hostOnly": not cookie.domain_specified,
                    "httpOnly": cookie.has_nonstandard_attr("HttpOnly") or
                                cookie.get_nonstandard_attr("http_only") == "True",
                    # JavaScript Date.now() and the Node cookie jar use milliseconds.
                    "expires": cookie.expires * 1000 if cookie.expires else None,
                })
        return {
            "status": int(response.status_code),
            "headers": [[str(name), str(value)] for name, value in header_items],
            "body": "" if message.get("discardBody") else base64.b64encode(response.content).decode("ascii"),
            "cookies": cookies,
        }

    def restore_cookies(self, cookies):
        # Merge a checkpoint once; subsequent requests use this native jar.
        # Explicit host-only flags must survive the Node/Python boundary.
        for value in cookies:
            domain = value["domain"].lstrip(".")
            host_only = value.get("hostOnly", True)
            expires = value.get("expires")
            cookie = Cookie(
                version=0, name=value["name"], value=value["value"],
                port=None, port_specified=False,
                domain=domain if host_only else "." + domain,
                domain_specified=not host_only, domain_initial_dot=not host_only,
                path=value.get("path") or "/", path_specified=True,
                secure=bool(value.get("secure")),
                expires=int(expires / 1000) if expires is not None else None,
                discard=expires is None, comment=None, comment_url=None,
                rest={"HttpOnly": None} if value.get("httpOnly") else {}, rfc2109=False,
            )
            self.session.cookies.jar.set_cookie(cookie)
        self.session.cookies.jar.clear_expired_cookies()

    def solve_cloudflare(self, message):
        if self.session is None:
            raise RuntimeError("TLS session must be configured before solving Cloudflare")
        if CLOUDFLARE_SOLVER is None:
            raise RuntimeError("Cloudflare solver module could not be loaded")
        challenge_body = message.get("challengeBody") or ""
        challenge_html = base64.b64decode(challenge_body).decode("utf-8", errors="ignore")
        challenge_url = str(message.get("url") or "")
        parsed = urlparse(challenge_url)
        verification_url = f"{parsed.scheme}://{parsed.netloc}/"
        return CLOUDFLARE_SOLVER.solve_challenge(
            self.session,
            challenge_url=challenge_url,
            challenge_html=challenge_html,
            challenge_size=len(challenge_html.encode("utf-8")),
            user_agent=str(message.get("userAgent") or "Mozilla/5.0"),
            browser_identity=message.get("browserIdentity") or {},
            verification_url=verification_url,
            node_command=str(message.get("nodeCommand") or "node"),
            timeout_seconds=max(10, int(message.get("solverTimeoutMs") or 70000) // 1000),
        )

    def generate_sentinel_tokens(self, message):
        if self.session is None:
            raise RuntimeError("TLS session must be configured before generating Sentinel tokens")
        identity = message.get("browserIdentity") or {}
        user_agent = str(message.get("userAgent") or identity.get("userAgent") or "Mozilla/5.0")
        page_url = str(message.get("pageUrl") or "https://auth.openai.com/create-account/password")
        device_id = str(message.get("deviceID") or "") or None
        sentinel = SentinelClient(
            page_url=page_url,
            client=self.session,
            user_agent=user_agent,
            browser_identity=identity,
            node_command=str(message.get("nodeCommand") or "node"),
            device_id=device_id,
        )
        try:
            flow = str(message.get("flow") or "default")
            token = sentinel.token(flow)
            so_token = None
            if message.get("includeSessionObserver", True):
                try:
                    so_token = sentinel.session_observer_token(flow)
                except RuntimeError as error:
                    if "returned no value" not in str(error):
                        raise
            return {"token": token, "soToken": so_token}
        finally:
            sentinel.close()

    def close_sentinel(self):
        if self.sentinel_client is None:
            return
        self.sentinel_client.close()
        self.sentinel_client = None


def main():
    worker = Worker()
    for raw_line in sys.stdin:
        try:
            message = json.loads(raw_line)
            request_id = message.get("id")
            operation = message.get("operation", "request")
            if operation == "configure":
                worker.configure(
                    message.get("proxy"),
                    message.get("impersonate"),
                    verify_tls=message.get("verifyTls", True),
                    extension_order=message.get("extensionOrder"),
                    strict_profile=message.get("strictProfile", False),
                )
                result = {
                    "configured": True,
                    "profile": worker.impersonate,
                    "identityProfile": worker.impersonate,
                }
            elif operation == "probe_profiles":
                result = worker.probe_profiles(
                    str(message.get("url") or "https://chatgpt.com/"),
                    message.get("profiles"),
                    message.get("probeTimeoutMs") or 15000,
                    message.get("concurrency") or 4,
                )
            elif operation == "solve_cloudflare":
                result = worker.solve_cloudflare(message)
            elif operation == "generate_sentinel_tokens":
                result = worker.generate_sentinel_tokens(message)
            elif operation == "restore_cookies":
                if worker.session is None:
                    raise RuntimeError("TLS session must be configured before restoring cookies")
                worker.restore_cookies(message.get("cookies") or [])
                result = {"restored": True}
            elif operation == "close":
                worker.close_sentinel()
                write_message({"id": request_id, "ok": True, "result": {"closed": True}})
                return
            else:
                result = worker.request(message)
            write_message({"id": request_id, "ok": True, "result": result})
        except Exception as error:
            write_message({
                "id": locals().get("request_id"),
                "ok": False,
                "error": f"{type(error).__name__}: {error}",
            })


if __name__ == "__main__":
    main()
