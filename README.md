# Secure Scope

A local app with a browser GUI for a focused website security configuration review. Built with Python and browser-native HTML/CSS/JavaScript; no third-party packages, account, API key, or hosted backend required.

## Start

Install Python 3.11 or later, download or clone this repository, and run `python main.py` from the project folder. The app opens in your default browser. No third-party packages are required.

On Windows, you can also right-click **Start Secure Scope.ps1** and select **Run with PowerShell**. In VS Code, open this folder, choose a Python interpreter, and run `main.py`; the included launch configuration works with the Python Debugger extension. Use **Quit app** to stop the local server when finished. Closing a browser tab alone does not stop it.

## Use

1. Enter a hostname or HTTP/HTTPS URL for a site you own or have permission to assess. Hostnames default to HTTPS. Localhost and custom ports work.
2. Select **Scan website**. The app sends ordinary GET requests and follows up to five redirects, including redirects to other hostnames.
3. Select a finding for evidence and a suggested action. Filter by severity or inspect the response headers, TLS details, and scope notes.
4. Export HTML for a readable report or JSON for further processing. **Explore demo** provides clearly marked simulated findings with no network requests.

The last 30 reports are kept in the page's memory for the current session. Closing or refreshing the page discards this history unless exported. The server retains the latest report until the next scan or shutdown. Cancel stops between network operations; an in-progress operation must finish or time out first. DNS resolution can take longer than the socket timeout on some systems.

## Checks

- HTTP versus HTTPS and redirect downgrades.
- TLS trust and hostname verification, negotiated protocol/cipher, and certificate expiry.
- HSTS and MIME sniffing protection.
- For HTML: presence of enforced CSP, permissive script-source indicators, framing policy, referrer policy, HTTP resources, and HTTP form actions.
- Response cookie Secure, HttpOnly, and SameSite attributes, with context-dependent wording.
- Informational technology disclosure and public CORS observations.

Guidance reference: [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html). Findings are independent heuristics, not a complete implementation of OWASP guidance.

## Important limits

This is version 1 of a **website configuration scanner**, not an antivirus, network vulnerability scanner, or penetration testing suite. It does not crawl, execute JavaScript, authenticate, inject payloads, enumerate ports, detect CVEs, or prove exploitability. Only the final response is analyzed; intermediate response cookies and headers are not assessed. HTML checks inspect at most 512 KiB and do not inspect external CSS, dynamically created elements, every CSP rule, or all resource attributes. Certificate failure stops the scan without bypassing verification. No whole-site security score is invented.

It makes direct connections; proxy environment settings are not used. The runtime's trust store may differ from a browser's. A TLS handshake only shows the negotiated connection, not every protocol or cipher offered by the server. Cookie purpose is unknown, so HttpOnly observations require human review. Missing headers can be intentional. Error-page findings may not represent normal application pages.

No telemetry or automatic disk history. Exported query strings and Set-Cookie values are redacted; URL paths and other headers may still contain sensitive data. Review reports before sharing. Exported HTML escapes website content and has no scripts or remote assets. Browser downloads go to your configured downloads folder. The interface server binds to 127.0.0.1 on a random port, validates Host, and requires a random per-launch token for API requests; it does not expose a network-accessible scanning service. Keep the launch URL private.

## Development

`python -m unittest discover -s tests -v`

The tests use local fixture servers and mocks, so no external targets are required. The scanner and exporters are separate from the GUI for reuse and testing.

Files: `scanner.py` handles bounded network requests and analysis, `server.py` serves the local interface, `ui.html` implements the GUI, and `reports.py` provides Python report exporters. The browser interface also exports reports directly without writing them on the server.
