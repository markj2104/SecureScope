"""Bounded HTTP inspection. No crawling, payload injection, or authentication."""
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.client import HTTPConnection, HTTPSConnection
from http.cookies import SimpleCookie
from urllib.parse import urlsplit, urlunsplit, urljoin, quote
import json
import re
import ssl
import threading
import time

REFERENCE = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
MAX_BODY = 512 * 1024
MAX_REDIRECTS = 5


class ScanError(Exception):
    pass


class Cancelled(ScanError):
    pass


@dataclass
class Finding:
    severity: str
    title: str
    evidence: str
    recommendation: str
    reference: str = REFERENCE


@dataclass
class Report:
    target: str
    started: str
    final_url: str = ""
    status: int = 0
    duration: float = 0
    redirects: list = field(default_factory=list)
    headers: list = field(default_factory=list)
    tls: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    demo: bool = False

    def to_dict(self):
        return asdict(self)


def normalize_url(value):
    value = value.strip()
    if not value or len(value) > 4096:
        raise ScanError("Enter a hostname or HTTP/HTTPS URL (up to 4,096 characters).")
    if any(ord(c) < 33 or ord(c) == 127 for c in value) or "\\" in value:
        raise ScanError("URLs cannot contain spaces, control characters, or backslashes.")
    if "://" not in value:
        value = "https://" + value
    try:
        p = urlsplit(value)
        if p.scheme.lower() not in ("http", "https") or not p.hostname:
            raise ValueError()
        if p.username is not None or p.password is not None:
            raise ScanError("Do not include usernames or passwords in the URL.")
        port = p.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError()
        host = p.hostname.encode("idna").decode("ascii")
        if ":" in host:
            host = "[" + host + "]"
        netloc = host + (":" + str(port) if port else "")
        return urlunsplit((p.scheme.lower(), netloc, quote(p.path or "/", safe="/%:@!$&'()*+,;=-._~"), quote(p.query, safe="%=&?/:@!$'()*+,;~-._"), ""))
    except (ValueError, UnicodeError):
        raise ScanError("That URL has an invalid hostname, scheme, or port.") from None


def public_url(url):
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path, "[redacted]" if p.query else "", ""))


def check_cancel(event):
    if event.is_set():
        raise Cancelled("Scan cancelled.")


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.resources = []
        self.forms = []
        self.base = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "base" and self.base is None:
            self.base = attrs.get("href")
        resource_attr = {"script": "src", "iframe": "src", "img": "src", "audio": "src", "video": "src", "source": "src", "object": "data"}.get(tag)
        if tag == "link" and "stylesheet" in attrs.get("rel", "").lower().split():
            resource_attr = "href"
        if resource_attr and attrs.get(resource_attr):
            self.resources.append((tag, attrs[resource_attr]))
        if tag == "form":
            self.forms.append(attrs.get("action", ""))


def analyze(report, raw_headers, body):
    h = {}
    for key, value in raw_headers:
        h.setdefault(key.lower(), []).append(value)
    get = lambda name: ", ".join(h.get(name, []))
    def add(severity, title, evidence, fix):
        report.findings.append(Finding(severity, title, evidence, fix))
    secure = urlsplit(report.final_url).scheme == "https"
    html = "text/html" in get("content-type").lower() or "application/xhtml+xml" in get("content-type").lower()
    if not secure:
        add("High", "Final response uses unencrypted HTTP", public_url(report.final_url), "Serve the page over HTTPS and redirect HTTP traffic to HTTPS.")
    elif report.tls:
        add("Pass", "TLS certificate verified", "The certificate chain and hostname were accepted by the local trust store.", "Keep automated certificate renewal enabled.")
        days = report.tls.get("days_remaining")
        if days is not None and days < 30:
            add("Medium", "TLS certificate expires soon", f"{days} days remaining.", "Renew the certificate before it expires and verify automatic renewal.")
    if any(urlsplit(x["url"]).scheme == "https" and urlsplit(x["destination"]).scheme == "http" for x in report.redirects):
        add("High", "Redirect downgrades HTTPS to HTTP", "An observed redirect sends the browser to unencrypted HTTP.", "Keep every redirect destination on HTTPS.")
    if secure:
        age = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)", get("strict-transport-security"), re.I)
        if not age or int(age.group(1)) <= 0:
            add("Medium", "HSTS is missing or disabled", "No positive Strict-Transport-Security max-age was observed.", "After confirming HTTPS works across the intended scope, deploy HSTS with a positive max-age. Review subdomain coverage before enabling includeSubDomains.")
        else:
            add("Pass", "HSTS is enabled", f"max-age={age.group(1)}", "Review duration and subdomain coverage for your deployment.")
    if get("x-content-type-options").strip().lower() != "nosniff":
        add("Low", "MIME sniffing protection is missing", "X-Content-Type-Options is not nosniff.", "Return X-Content-Type-Options: nosniff with correct Content-Type values.")
    else:
        add("Pass", "MIME sniffing protection is enabled", "X-Content-Type-Options: nosniff", "Retain this header.")
    if html:
        csp = get("content-security-policy")
        directives = {}
        for part in csp.split(";"):
            tokens = part.strip().split()
            if tokens:
                directives.setdefault(tokens[0].lower(), tokens[1:])
        if not csp:
            add("Medium", "No enforced Content Security Policy", "No Content-Security-Policy response header. Meta policies are not evaluated.", "Develop an application-specific CSP, test it in report-only mode, then enforce it. Prefer script nonces or hashes.")
        else:
            scripts = directives.get("script-src-elem", directives.get("script-src", directives.get("default-src", [])))
            if "'unsafe-inline'" in scripts or "'unsafe-eval'" in directives.get("script-src", directives.get("default-src", [])) or "*" in scripts or "data:" in scripts:
                add("Low", "Review permissive CSP script sources", "The policy contains an unsafe-inline, unsafe-eval, wildcard, or data source. Nonces, hashes, and multiple policies may change effective behavior.", "Review the effective browser policy; replace broad script permissions with specific sources, nonces, or hashes.")
            else:
                add("Info", "Content Security Policy is present", "A CSP header was observed; its complete effectiveness was not verified.", "Review source lists, directive coverage, and browser behavior.")
        frame = directives.get("frame-ancestors", [])
        if (frame and "*" not in frame) or get("x-frame-options").upper().strip() in ("DENY", "SAMEORIGIN"):
            add("Info", "Frame embedding policy is present", "frame-ancestors or a recognized X-Frame-Options value was observed.", "Verify that the allowed framing origins match the application's needs.")
        else:
            add("Medium", "Frame embedding restriction not observed", "No restrictive frame-ancestors or recognized X-Frame-Options value.", "Use CSP frame-ancestors 'none' or an explicit set of trusted origins when framing is not intended to be public.")
        referrer = get("referrer-policy").lower()
        if not referrer:
            add("Info", "Referrer policy uses browser defaults", "No Referrer-Policy header was observed.", "Consider explicitly setting strict-origin-when-cross-origin or a stricter policy to document your intent.")
        elif referrer.split(",")[-1].strip() == "unsafe-url":
            add("Low", "Referrer policy can disclose URL paths", "Referrer-Policy: unsafe-url", "Use strict-origin-when-cross-origin, same-origin, or no-referrer as appropriate.")
        parser = PageParser()
        parser.feed(body.decode("utf-8", errors="replace"))
        base = urljoin(report.final_url, parser.base) if parser.base else report.final_url
        if secure:
            mixed = [tag for tag, src in parser.resources if urlsplit(urljoin(base, src)).scheme == "http"]
            if mixed:
                add("Medium", "HTML references HTTP resources", "Resource types: " + ", ".join(sorted(set(mixed))) + ". Browser blocking or automatic upgrades were not tested.", "Change embedded resource URLs to HTTPS. Check CSS and runtime-generated resources separately.")
            if any(urlsplit(urljoin(base, action)).scheme == "http" for action in parser.forms):
                add("High", "Form submits to HTTP", "An HTML form action resolves to an unencrypted HTTP URL.", "Submit all form data to HTTPS endpoints.")
    else:
        report.notes.append("HTML-specific checks skipped: response Content-Type is not HTML.")
    cookie_count = 0
    for line in h.get("set-cookie", []):
        jar = SimpleCookie()
        try:
            jar.load(line)
        except Exception:
            jar = {}
        if not jar:
            report.notes.append("A Set-Cookie header could not be parsed; its attributes were not assessed.")
        for name, cookie in jar.items():
            cookie_count += 1
            label = name[:80]
            if not cookie["secure"]:
                add("Medium", "Cookie lacks Secure", f"Cookie: {label} (value redacted)", "Use Secure for cookies that should only travel over HTTPS.")
            if not cookie["httponly"]:
                add("Low", "Review cookie JavaScript access", f"Cookie: {label} lacks HttpOnly (value redacted). Its purpose is unknown.", "Set HttpOnly for session or sensitive cookies that JavaScript does not need to read.")
            if cookie["samesite"].lower() not in ("lax", "strict", "none"):
                add("Low", "Cookie SameSite is not explicit", f"Cookie: {label} (value redacted)", "Choose an explicit SameSite policy appropriate to cross-site flows.")
            if cookie["samesite"].lower() == "none" and not cookie["secure"]:
                add("Medium", "SameSite=None cookie lacks Secure", f"Cookie: {label} (value redacted)", "Use Secure with SameSite=None; current browsers may reject this cookie otherwise.")
    if not cookie_count:
        report.notes.append("No parseable response cookies observed. Cookies set by JavaScript or other pages were not assessed.")
    if get("server") or get("x-powered-by"):
        add("Info", "Server technology is disclosed", "Server or X-Powered-By response header is present.", "Consider suppressing unnecessary product/version details. Disclosure alone is not proof of a vulnerability.")
    if get("access-control-allow-origin") == "*":
        add("Info", "CORS permits public cross-origin reads", "Access-Control-Allow-Origin: *", "Confirm this response is intended to be publicly readable. This header alone does not establish a data leak.")
    if report.status >= 400:
        report.notes.append(f"HTTP {report.status}: findings describe this error response, which may differ from normal application pages.")
    report.notes.append("Single-page configuration review, not a penetration test or security certification. No login, crawling, JavaScript execution, port scan, or exploit attempts.")
    order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3, "Pass": 4}
    report.findings.sort(key=lambda f: order[f.severity])


def scan(target, cancel=None, progress=None, timeout=8):
    cancel = cancel or threading.Event()
    progress = progress or (lambda message: None)
    url = normalize_url(target)
    report = Report(public_url(url), datetime.now(timezone.utc).isoformat(timespec="seconds"))
    started = time.monotonic()
    visited = set()
    for hop in range(MAX_REDIRECTS + 1):
        check_cancel(cancel)
        if url in visited:
            raise ScanError("Redirect loop detected. No further requests were made.")
        visited.add(url)
        p = urlsplit(url)
        progress(f"Inspecting {p.hostname}" + (f" · redirect {hop}" if hop else ""))
        connection = None
        try:
            if p.scheme == "https":
                connection = HTTPSConnection(p.hostname, p.port or 443, timeout=timeout, context=ssl.create_default_context())
            else:
                connection = HTTPConnection(p.hostname, p.port or 80, timeout=timeout)
            connection.connect()
            tls = {}
            if p.scheme == "https":
                sock = connection.sock
                cert = sock.getpeercert()
                tls = {"version": sock.version(), "cipher": sock.cipher()[0], "expires": cert.get("notAfter", ""), "issuer": ", ".join(v for group in cert.get("issuer", []) for k, v in group)}
                if cert.get("notAfter"):
                    tls["days_remaining"] = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) // 86400)
            check_cancel(cancel)
            path = urlunsplit(("", "", p.path or "/", p.query, ""))
            connection.request("GET", path, headers={"User-Agent": "SecureScope/1.0 (configuration review)", "Accept": "text/html,application/xhtml+xml,*/*;q=0.5", "Accept-Encoding": "identity", "Connection": "close"})
            response = connection.getresponse()
            headers = response.getheaders()
            location = response.getheader("Location")
            if response.status in (301, 302, 303, 307, 308) and location:
                if hop == MAX_REDIRECTS:
                    raise ScanError("Redirect limit reached (5). Try the final destination directly.")
                destination = normalize_url(urljoin(url, location))
                report.redirects.append({"url": public_url(url), "status": response.status, "destination": public_url(destination)})
                url = destination
                continue
            chunks = []
            total = 0
            deadline = time.monotonic() + 15
            while total <= MAX_BODY:
                check_cancel(cancel)
                if time.monotonic() > deadline:
                    raise ScanError("Response body took too long to read.")
                chunk = response.read1(min(16384, MAX_BODY + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            body = b"".join(chunks)
            if len(body) > MAX_BODY:
                report.notes.append("HTML inspection limited to the first 512 KiB of the response.")
            if response.getheader("Content-Encoding", "identity").lower() != "identity":
                report.notes.append("Server returned compressed content despite the identity request; HTML body checks were skipped.")
                body = b""
            report.final_url, report.status, report.tls = public_url(url), response.status, tls
            report.headers = [(k, "[redacted]" if k.lower() == "set-cookie" else public_url(urljoin(url, v)) if k.lower() == "location" else v) for k, v in headers]
            progress("Analyzing configuration and preparing findings…")
            analyze(report, headers, body[:MAX_BODY])
            report.duration = round(time.monotonic() - started, 2)
            check_cancel(cancel)
            return report
        except ssl.SSLCertVerificationError:
            raise ScanError("TLS certificate validation failed. The certificate may be expired, untrusted, or for a different hostname. Secure Scope did not bypass verification; no HTTP findings are available.") from None
        except ScanError:
            raise
        except Exception as exc:
            raise ScanError(f"Connection failed ({type(exc).__name__}). Check the hostname, port, network access, and whether the service is running.") from None
        finally:
            if connection:
                connection.close()


def demo_report():
    report = Report("https://demo.securescope.invalid/", datetime.now(timezone.utc).isoformat(timespec="seconds"), final_url="https://demo.securescope.invalid/", status=200, duration=0.12, demo=True)
    headers = [("Content-Type", "text/html"), ("X-Content-Type-Options", "nosniff"), ("Server", "ExampleServer"), ("Set-Cookie", "session=demo; Path=/; SameSite=Lax")]
    report.headers = [(k, "[redacted]" if k == "Set-Cookie" else v) for k, v in headers]
    report.tls = {"version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "days_remaining": 18, "expires": "Simulated", "issuer": "Demo certificate authority"}
    analyze(report, headers, b'<html><script src="http://assets.invalid/app.js"></script></html>')
    report.notes.insert(0, "DEMO: simulated data. No network requests were made.")
    return report
