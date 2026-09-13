from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl
import tempfile
import threading
import unittest
from unittest.mock import patch

from securescope.scanner import Report, Finding, ScanError, Cancelled, normalize_url, scan, analyze, demo_report
from securescope.reports import export_html, export_json


class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/loop":
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.end_headers()
            return
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/page?token=secret-value")
            self.end_headers()
            return
        self.send_response(404 if self.path == "/missing" else 200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "session=super-secret; Path=/")
        self.end_headers()
        self.wfile.write(b"<html><h1>Fixture website</h1></html>")


class ScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join()

    def test_normalization(self):
        self.assertEqual(normalize_url("example.com"), "https://example.com/")
        self.assertEqual(normalize_url("http://[::1]:8000/a#fragment"), "http://[::1]:8000/a")
        self.assertEqual(normalize_url("https://example.com/café"), "https://example.com/caf%C3%A9")

    def test_invalid_inputs(self):
        for target in ("", "ftp://example.com", "https://user:pass@example.com", "https://example.com:0", "https://example.com:99999", "https://example.com/\r\nfoo", "https://example.com/a b"):
            with self.subTest(target=target), self.assertRaises(ScanError):
                normalize_url(target)

    def test_local_scan_and_redaction(self):
        report = scan(self.base + "/redirect")
        self.assertEqual(report.status, 200)
        self.assertEqual(len(report.redirects), 1)
        self.assertIn("[redacted]", report.final_url)
        serialized = str(report.to_dict())
        self.assertNotIn("super-secret", serialized)
        self.assertNotIn("secret-value", serialized)
        self.assertTrue(any(f.title == "Cookie lacks Secure" for f in report.findings))
        self.assertTrue(any(f.severity == "High" for f in report.findings))

    def test_redirect_loop(self):
        with self.assertRaisesRegex(ScanError, "loop"):
            scan(self.base + "/loop")

    def test_http_error_is_inspected(self):
        report = scan(self.base + "/missing")
        self.assertEqual(report.status, 404)
        self.assertTrue(any("error response" in n for n in report.notes))

    def test_cancellation(self):
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(Cancelled):
            scan(self.base, cancel)

    def test_tls_failure_is_not_bypassed(self):
        with patch("securescope.scanner.HTTPSConnection") as connection:
            connection.return_value.connect.side_effect = ssl.SSLCertVerificationError("bad cert")
            with self.assertRaisesRegex(ScanError, "did not bypass"):
                scan("https://example.invalid")
            connection.return_value.request.assert_not_called()
            connection.return_value.close.assert_called_once()

    def test_json_response_skips_html_checks(self):
        report = Report("https://example.invalid", "now", final_url="https://example.invalid", status=200)
        analyze(report, [("Content-Type", "application/json")], b"{}")
        self.assertFalse(any("Content Security Policy" in f.title or "Frame embedding" in f.title for f in report.findings))

    def test_hardened_response(self):
        report = Report("https://example.invalid", "now", final_url="https://example.invalid", status=200, tls={"days_remaining": 90})
        headers = [("Content-Type", "text/html"), ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"), ("X-Content-Type-Options", "nosniff"), ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"), ("Referrer-Policy", "no-referrer"), ("Set-Cookie", "session=secret; Secure; HttpOnly; SameSite=Strict")]
        analyze(report, headers, b"<html></html>")
        self.assertFalse(any(f.severity in ("High", "Medium", "Low") for f in report.findings))

    def test_mixed_content_and_forms(self):
        report = Report("https://example.invalid", "now", final_url="https://example.invalid", status=200)
        analyze(report, [("Content-Type", "text/html")], b'<base href="http://example.invalid/"><script src="app.js"></script><form action="submit">')
        self.assertTrue(any(f.title == "HTML references HTTP resources" for f in report.findings))
        self.assertTrue(any(f.title == "Form submits to HTTP" for f in report.findings))

    def test_exports_escape_untrusted_content(self):
        report = demo_report()
        report.findings.append(Finding("Info", "<script>alert(1)</script>", '<img src=x onerror="alert(1)">', "Fix"))
        with tempfile.TemporaryDirectory() as folder:
            html = Path(folder) / "report.html"
            js = Path(folder) / "report.json"
            export_html(report, html)
            export_json(report, js)
            self.assertNotIn("<script>", html.read_text(encoding="utf-8"))
            self.assertIn("&lt;script&gt;", html.read_text(encoding="utf-8"))
            import json
            self.assertTrue(json.loads(js.read_text(encoding="utf-8"))["demo"])


if __name__ == "__main__":
    unittest.main()
