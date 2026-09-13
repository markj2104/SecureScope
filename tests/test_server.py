from http.client import HTTPConnection
import json
import threading
import unittest
from securescope.server import make_server


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = make_server()
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join()

    def request(self, path, method="GET", headers=None, body=None):
        c = HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        c.request(method, path, headers=headers or {}, body=body)
        r = c.getresponse()
        result = r.status, r.read()
        c.close()
        return result

    def test_page_contains_no_session_secret(self):
        status, body = self.request("/")
        self.assertEqual(status, 200)
        self.assertNotIn(self.server.state.token.encode(), body)

    def test_api_requires_secret(self):
        self.assertEqual(self.request("/api/status")[0], 403)

    def test_host_is_validated(self):
        self.assertEqual(self.request("/", headers={"Host": "attacker.invalid"})[0], 403)

    def test_foreign_origin_rejected(self):
        self.assertEqual(self.request("/api/demo", "POST", {"X-SecureScope-Token": self.server.state.token, "Origin": "https://attacker.invalid"}, "{}")[0], 403)

    def test_authorized_demo(self):
        status, body = self.request("/api/demo", "POST", {"X-SecureScope-Token": self.server.state.token}, "{}")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["demo"])

    def test_invalid_scan_rejected(self):
        status, body = self.request("/api/scan", "POST", {"X-SecureScope-Token": self.server.state.token}, '{"target":"file:///etc/passwd"}')
        self.assertEqual(status, 400)
        self.assertFalse(self.server.state.running)
