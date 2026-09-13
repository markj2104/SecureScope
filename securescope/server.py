"""Loopback-only GUI server with a per-launch secret and no external assets."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
import json
import secrets
import threading
import time
import webbrowser

from .scanner import scan, demo_report, normalize_url, ScanError, Cancelled

PAGE = Path(__file__).with_name("ui.html")


class State:
    def __init__(self):
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.cancel = threading.Event()
        self.running = False
        self.message = "Ready"
        self.result = None
        self.error = None
        self.job = 0

    def snapshot(self):
        with self.lock:
            return {"running": self.running, "message": self.message, "result": self.result, "error": self.error, "job": self.job}

    def start(self, target):
        target = normalize_url(target)
        with self.lock:
            if self.running:
                raise ScanError("A scan is already running.")
            self.running, self.error, self.result = True, None, None
            self.message = "Connecting…"
            self.cancel = threading.Event()
            self.job += 1
        def progress(message):
            with self.lock:
                if not self.cancel.is_set():
                    self.message = message
        def worker():
            try:
                report = scan(target, self.cancel, progress)
                with self.lock:
                    if self.cancel.is_set():
                        self.message = "Scan cancelled."
                    else:
                        self.result = report.to_dict()
                        self.message = "Scan complete"
            except Cancelled:
                with self.lock:
                    self.message = "Scan cancelled."
            except Exception as exc:
                with self.lock:
                    self.error = str(exc)
                    self.message = "Scan could not complete"
            finally:
                with self.lock:
                    self.running = False
        threading.Thread(target=worker, daemon=True).start()


def make_server(port=0):
    state = State()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def send(self, status, body, mime="application/json"):
            if not isinstance(body, bytes):
                body = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", mime + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            self.end_headers()
            self.wfile.write(body)

        def valid_host(self):
            return self.headers.get("Host") == f"127.0.0.1:{self.server.server_port}"

        def authenticated(self):
            return self.valid_host() and secrets.compare_digest(self.headers.get("X-SecureScope-Token", ""), state.token)

        def do_GET(self):
            if not self.valid_host():
                return self.send(403, {"error": "Invalid host"})
            if self.path == "/":
                return self.send(200, PAGE.read_bytes(), "text/html")
            if not self.authenticated():
                return self.send(403, {"error": "Open the app using its launcher."})
            if self.path == "/api/status":
                return self.send(200, state.snapshot())
            self.send(404, {"error": "Not found"})

        def do_POST(self):
            if not self.authenticated():
                return self.send(403, {"error": "Invalid session"})
            origin = self.headers.get("Origin")
            if origin and origin != f"http://127.0.0.1:{self.server.server_port}":
                return self.send(403, {"error": "Invalid origin"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 <= length <= 8192:
                    return self.send(413, {"error": "Request too large"})
                self.connection.settimeout(5)
                payload = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(payload, dict):
                    raise ValueError()
                if self.path == "/api/scan":
                    if not isinstance(payload.get("target"), str):
                        raise ValueError()
                    state.start(payload["target"])
                    return self.send(202, {"ok": True})
                if self.path == "/api/cancel":
                    with state.lock:
                        state.cancel.set()
                        if state.running:
                            state.message = "Cancelling… waiting for the current network operation."
                    return self.send(200, {"ok": True})
                if self.path == "/api/demo":
                    return self.send(200, demo_report().to_dict())
                if self.path == "/api/quit":
                    state.cancel.set()
                    self.send(200, {"ok": True})
                    threading.Thread(target=self.server.shutdown, daemon=True).start()
                    return
                return self.send(404, {"error": "Not found"})
            except (ValueError, TypeError, ScanError) as exc:
                self.send(400, {"error": str(exc) or "Invalid request"})
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.state = state
    server.daemon_threads = True
    return server


def main():
    server = make_server()
    url = f"http://127.0.0.1:{server.server_port}/#{server.state.token}"
    print("Secure Scope is running locally. Use Quit app in the interface to stop it.")
    # The fragment stays in the browser; it is never part of an HTTP request URL.
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.state.cancel.set()
        server.server_close()


if __name__ == "__main__":
    main()
