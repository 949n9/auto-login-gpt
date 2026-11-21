import importlib.util
from pathlib import Path
import socketserver
import threading
import unittest

spec = importlib.util.spec_from_file_location("worker", Path(__file__).resolve().parents[1] / "src/tls_transport.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
ORDER = "0-5-10-11-13-16-18-23-27-35-43-45-51-17613-51764-65037-65281"
ORDER_146 = ORDER.replace("-51764", "")


class LocalSocksHandler(socketserver.BaseRequestHandler):
    """An IPv4-only SOCKS exit; all traffic stays on loopback."""

    def read_exact(self, size):
        value = b""
        while len(value) < size:
            chunk = self.request.recv(size - len(value))
            if not chunk:
                raise EOFError("SOCKS client closed early")
            value += chunk
        return value

    def handle(self):
        try:
            self.request.settimeout(5)
            version, count = self.read_exact(2)
            methods = self.read_exact(count)
            assert version == 5 and 2 in methods
            self.request.sendall(b"\x05\x02")
            auth_version, user_length = self.read_exact(2)
            username = self.read_exact(user_length)
            password = self.read_exact(self.read_exact(1)[0])
            assert auth_version == 1
            self.server.authentication.append((username, password))
            self.request.sendall(b"\x01\x00")
            version, command, reserved, address_type = self.read_exact(4)
            assert (version, command, reserved) == (5, 1, 0)
            if address_type == 1:
                address = self.read_exact(4)
            elif address_type == 3:
                address = self.read_exact(self.read_exact(1)[0])
            elif address_type == 4:
                address = self.read_exact(16)
            else:
                raise AssertionError(f"Unexpected SOCKS address type {address_type}")
            port = int.from_bytes(self.read_exact(2), "big")
            self.server.targets.append((address_type, address, port))
            # Reproduce exits which cannot route IPv6. No upstream connection
            # is made: successful IPv4/domain requests get a synthetic response.
            reply = 8 if address_type == 4 else 0
            self.request.sendall(bytes([5, reply, 0, 1, 127, 0, 0, 1, 0, 80]))
            if reply:
                return
            headers = b""
            while b"\r\n\r\n" not in headers:
                headers += self.read_exact(1)
                assert len(headers) < 65536
            self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        except Exception as error:
            self.server.errors.append(error)


class WorkerTests(unittest.TestCase):
    def test_macos_native_profile_and_no_pinned_order(self):
        worker = module.Worker()
        worker.configure(None, "chrome152_macos", strict_profile=True)
        self.addCleanup(worker.session.close)
        self.assertEqual(worker.session.impersonate, "chrome152_macos")
        self.assertNotIn(module.CurlOpt.TLS_EXTENSION_ORDER, worker.session.curl_options)
        self.assertNotIn(module.CurlOpt.SSL_PERMUTE_EXTENSIONS, worker.session.curl_options)
        self.assertIs(worker.session.verify, True)
        with self.assertRaisesRegex(RuntimeError, "native TLS extension ordering"):
            module.Worker().configure(None, "chrome152_macos", extension_order=ORDER, strict_profile=True)
        with self.assertRaisesRegex(RuntimeError, "not supported"):
            module.Worker().configure(None, "chrome999_macos", strict_profile=True)

    def test_socks5_address_family_scope_and_reconfigure(self):
        worker = module.Worker()
        for proxy in (
            "socks5://user:synthetic@127.0.0.1:1080",
            "socks5h://user:synthetic@127.0.0.1:1080",
            "http://proxy.example.test:8080",
            "http://127.0.0.1:8080",
            "https://proxy.example.test:8443",
            None,
        ):
            with self.subTest(proxy=proxy):
                worker.configure(proxy, "chrome146", extension_order=ORDER_146, strict_profile=True)
                self.addCleanup(worker.session.close)
                expected = 1 if proxy and proxy.startswith("socks5://") else None
                self.assertEqual(worker.session.curl_options.get(module.CurlOpt.IPRESOLVE), expected)
                self.assertEqual(worker.session.curl_options[module.CurlOpt.TLS_EXTENSION_ORDER], ORDER_146)
                self.assertEqual(worker.session.curl_options[module.CurlOpt.SSL_PERMUTE_EXTENSIONS], 0)
                self.assertEqual(worker.session.impersonate, "chrome146")
                self.assertEqual(worker.proxy, proxy)
                self.assertIs(worker.session.verify, True)
        worker.configure("socks5://user:synthetic@127.0.0.1:1080", "chrome146")
        self.addCleanup(worker.session.close)
        self.assertEqual(worker.session.curl_options[module.CurlOpt.IPRESOLVE], 1)
        with self.assertRaisesRegex(RuntimeError, "cannot be disabled"):
            module.Worker().configure(worker.proxy, "chrome146", verify_tls=False)

    def test_socks5_local_ipv4_and_socks5h_remote_dns_on_wire(self):
        for scheme, expected_type, expected_address in (
            ("socks5", 1, b"\x7f\x00\x00\x01"),
            ("socks5h", 3, b"dualstack.test"),
        ):
            with self.subTest(scheme=scheme), socketserver.TCPServer(("127.0.0.1", 0), LocalSocksHandler) as server:
                server.targets, server.authentication, server.errors = [], [], []
                thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
                thread.start()
                worker = module.Worker()
                try:
                    proxy = f"{scheme}://user:synthetic@127.0.0.1:{server.server_address[1]}"
                    worker.configure(proxy, "chrome146", extension_order=ORDER_146, strict_profile=True)
                    # Deterministic dual-stack DNS, deliberately listing IPv6
                    # first. No network DNS or external service is required.
                    worker.session.curl_options[module.CurlOpt.RESOLVE] = [
                        "dualstack.test:80:[::1],127.0.0.1",
                    ]
                    worker.session.curl_options[module.CurlOpt.NOPROXY] = ""
                    response = worker._request_with_profile_fallback(
                        "GET", "http://dualstack.test/", {}, None, 3000,
                    )
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.content, b"ok")
                    self.assertEqual(server.targets, [(expected_type, expected_address, 80)])
                    self.assertEqual(server.authentication, [(b"user", b"synthetic")])
                    self.assertEqual(server.errors, [])
                    self.assertEqual(worker.proxy, proxy)
                finally:
                    if worker.session is not None:
                        worker.session.close()
                    server.shutdown()
                    thread.join(timeout=6)

    def test_real_profile_and_pinned_options(self):
        worker = module.Worker()
        worker.configure(None, "chrome152", extension_order=ORDER, strict_profile=True)
        self.addCleanup(worker.session.close)
        self.assertEqual(worker.session.impersonate, "chrome152")
        self.assertEqual(worker.session.curl_options[module.CurlOpt.TLS_EXTENSION_ORDER], ORDER)
        self.assertEqual(worker.session.curl_options[module.CurlOpt.SSL_PERMUTE_EXTENSIONS], 0)

    def test_no_silent_downgrade(self):
        worker = module.Worker()
        with self.assertRaisesRegex(RuntimeError, "not supported"):
            worker.configure(None, "chrome999", strict_profile=True)
        self.assertIsNone(worker.session)
        worker.configure(None, "chrome999")
        self.addCleanup(worker.session.close)
        self.assertEqual(worker.impersonate, "chrome146")
        original = worker.session
        def fail(*args, **kwargs):
            raise RuntimeError("Impersonating chrome146 is not supported")
        original.request = fail
        with self.assertRaisesRegex(RuntimeError, "not replayed"):
            worker._request_with_profile_fallback("POST", "https://example.test", {}, b"", 1000)
        self.assertIs(worker.session, original)

    def test_local_proxy_does_not_disable_verification(self):
        worker = module.Worker()
        worker.configure("http://127.0.0.1:8080", "chrome146")
        self.addCleanup(worker.session.close)
        self.assertIs(worker.session.verify, True)
        with self.assertRaisesRegex(RuntimeError, "cannot be disabled"):
            module.Worker().configure(None, "chrome146", verify_tls=False)

    def test_cookie_restore_flags_and_expiration(self):
        worker = module.Worker()
        worker.configure(None, "chrome146")
        self.addCleanup(worker.session.close)
        worker.restore_cookies([
            {"name": "host", "value": "synthetic", "domain": "example.test", "path": "/auth", "hostOnly": True},
            {"name": "domain", "value": "synthetic", "domain": "example.test", "path": "/", "hostOnly": False},
            {"name": "expired", "value": "synthetic", "domain": "example.test", "expires": 1},
        ])
        cookies = {c.name: c for c in worker.session.cookies.jar}
        self.assertFalse(cookies["host"].domain_specified)
        self.assertTrue(cookies["domain"].domain_specified)
        self.assertEqual(cookies["host"].path, "/auth")
        self.assertNotIn("expired", cookies)


if __name__ == "__main__":
    unittest.main()
