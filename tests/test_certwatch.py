"""Tests for certwatch — live checks against real TLS endpoints plus
a local self-signed server for controlled scenarios."""

import ssl
import socket
import sys
import threading
import unittest
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from certwatch import analyze_cert  # noqa: E402


def _make_self_signed_ctx() -> ssl.SSLContext:
    """Create a throwaway self-signed cert + SSLContext (temp files)."""
    import tempfile
    import subprocess
    import os

    tmp = tempfile.mkdtemp()
    key = os.path.join(tmp, "key.pem")
    crt = os.path.join(tmp, "crt.pem")
    # openssl is present on virtually every dev box; skip suite if absent
    if subprocess.call(["which", "openssl"], stdout=subprocess.DEVNULL) != 0:
        raise unittest.SkipTest("openssl binary not available")
    subprocess.check_call(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", crt, "-days", "365",
         "-subj", "/CN=localhost"], stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    return ctx


class _TLSHTTPServer(HTTPServer):
    def __init__(self, ctx):
        super().__init__(("127.0.0.1", 0), BaseHTTPRequestHandler)
        self.ctx = ctx

    def get_request(self):
        sock, addr = super().get_request()
        try:
            ssock = self.ctx.wrap_socket(sock, server_side=True)
        except (ssl.SSLError, OSError):
            raise
        return ssock, addr

    def handle_error(self, request, client_address):
        pass  # silence client disconnects


def _start_local_tls():
    try:
        ctx = _make_self_signed_ctx()
    except unittest.SkipTest:
        raise
    srv = _TLSHTTPServer(ctx)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv


class TestLiveInternet(unittest.TestCase):
    """Real network checks — skipped automatically when offline."""

    def setUp(self):
        try:
            sock = socket.create_connection(("github.com", 443), timeout=5)
            sock.close()
        except OSError:
            raise unittest.SkipTest("no internet connection")

    def test_github_is_ok(self):
        rep = analyze_cert("github.com", 443, timeout=15, warn_days=7)
        self.assertTrue(rep.connected)
        self.assertEqual(rep.status, "ok")
        self.assertIs(rep.self_signed, False)
        self.assertTrue(rep.hostname_ok)
        self.assertGreater(rep.days_left, 7)

    def test_github_expires_covered_by_san(self):
        rep = analyze_cert("github.com", 443, timeout=15)
        self.assertIn("github.com", rep.san)


class TestSelfSignedLocal(unittest.TestCase):
    """Controlled scenario: local HTTPS server with a self-signed cert."""

    @classmethod
    def setUpClass(cls):
        try:
            cls.server = _start_local_tls()
        except unittest.SkipTest:
            raise unittest.SkipTest("openssl unavailable")

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "server"):
            cls.server.shutdown()

    def test_self_signed_detected(self):
        port = self.server.server_address[1]
        rep = analyze_cert("127.0.0.1", port, timeout=10, warn_days=30)
        self.assertTrue(rep.connected)
        self.assertTrue(rep.self_signed)
        self.assertEqual(rep.status, "warn")
        self.assertTrue(any("self-signed" in f for f in rep.findings))


class TestConnectionFailures(unittest.TestCase):
    def test_refused(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        # port now free — nothing listening
        rep = analyze_cert("127.0.0.1", port, timeout=5)
        self.assertEqual(rep.status, "error")
        self.assertFalse(rep.connected)
        self.assertIsNotNone(rep.error)

    def test_garbage_host(self):
        rep = analyze_cert("nonexistent.invalid", 443, timeout=5)
        self.assertEqual(rep.status, "error")


if __name__ == "__main__":
    unittest.main(verbosity=2)
