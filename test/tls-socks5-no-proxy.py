#!/usr/bin/env python3
"""Offline regression: NO_PROXY must not bypass an explicitly selected SOCKS proxy.

Run with the project's existing curl_cffi environment:
    /usr/bin/env python3 test/tls-socks5-no-proxy.py

Both listeners and every request destination are loopback. The SOCKS listener
rejects authentication-method negotiation and never connects to a target.
"""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import os
from pathlib import Path
import socketserver
import threading
import unittest
from unittest.mock import patch


WORKER_PATH = Path(__file__).resolve().parents[1] / "src" / "tls_transport.py"
SPEC = importlib.util.spec_from_file_location("test_tls_transport_no_proxy", WORKER_PATH)
WORKER_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WORKER_MODULE)
Worker = WORKER_MODULE.Worker


class CountingTarget(BaseHTTPRequestHandler):
    def do_GET(self):
        with self.server.observation_lock:
            self.server.requests_received += 1
        body = b"Direct access must not happen in this test."
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class RejectingSocks5(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        try:
            greeting = self.receive_exactly(2)
            methods = self.receive_exactly(greeting[1]) if len(greeting) == 2 else b""
            with self.server.observation_lock:
                self.server.handshakes.append((greeting, methods))
            # RFC 1928: no acceptable authentication methods. Never CONNECT.
            self.request.sendall(b"\x05\xff")
        except (OSError, ValueError) as error:
            with self.server.observation_lock:
                self.server.handshake_errors.append(type(error).__name__)

    def receive_exactly(self, length):
        value = b""
        while len(value) < length:
            chunk = self.request.recv(length - len(value))
            if not chunk:
                raise ValueError("SOCKS greeting ended early")
            value += chunk
        return value


class LocalSocksServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


@contextmanager
def running_server(server_class, handler_class):
    server = server_class(("127.0.0.1", 0), handler_class)
    server.observation_lock = threading.Lock()
    server.requests_received = 0
    server.handshakes = []
    server.handshake_errors = []
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class ExplicitSocksIgnoresNoProxyTest(unittest.TestCase):
    def test_rejected_proxy_never_reaches_direct_target(self):
        # Remove inherited proxy settings, retaining normal runtime variables.
        # All proxy endpoints used below are explicitly assigned loopback URLs.
        environment = {
            key: value for key, value in os.environ.items()
            if key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}
        }
        with running_server(ThreadingHTTPServer, CountingTarget) as target:
            target_url = f"http://127.0.0.1:{target.server_address[1]}/must-not-be-reached"
            for scheme in ("socks5", "socks5h"):
                for overrides in ({"NO_PROXY": "*"}, {"no_proxy": "*"}, {"NO_PROXY": "*", "no_proxy": "*"}):
                    with self.subTest(scheme=scheme, environment=overrides):
                        with running_server(LocalSocksServer, RejectingSocks5) as proxy:
                            proxy_url = f"{scheme}://127.0.0.1:{proxy.server_address[1]}"
                            worker = Worker()
                            request_error = None
                            try:
                                with patch.dict(os.environ, {**environment, **overrides}, clear=True):
                                    worker.configure(
                                        proxy=proxy_url,
                                        impersonate="chrome152_macos",
                                        strict_profile=True,
                                    )
                                    try:
                                        worker.request({"method": "GET", "url": target_url, "timeoutMs": 3000})
                                    except Exception as error:
                                        request_error = error
                            finally:
                                worker.close_sentinel()
                                if worker.session is not None:
                                    worker.session.close()

                            with proxy.observation_lock:
                                handshakes = list(proxy.handshakes)
                                handshake_errors = list(proxy.handshake_errors)
                            with target.observation_lock:
                                direct_requests = target.requests_received
                            self.assertEqual(direct_requests, 0, "NO_PROXY bypassed the explicit SOCKS proxy")
                            self.assertIsNotNone(request_error, "rejected SOCKS negotiation must fail the request")
                            self.assertTrue(handshakes, "the explicit SOCKS listener received no handshake")
                            self.assertEqual(handshake_errors, [], "SOCKS handshake could not be read")
                            for greeting, methods in handshakes:
                                self.assertEqual(greeting[0], 5, "expected SOCKS version 5")
                                self.assertGreater(greeting[1], 0, "SOCKS greeting must offer at least one method")
                                self.assertEqual(len(methods), greeting[1], "incomplete SOCKS methods list")
                                self.assertIn(0, methods, "unauthenticated loopback proxy must offer no-auth method")


if __name__ == "__main__":
    unittest.main(verbosity=2)
