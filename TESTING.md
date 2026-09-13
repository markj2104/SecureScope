# Verification

Verified on this computer on September 12, 2026 (local date):

- 17 automated tests passed using Python's unittest runner.
- Real local HTTP requests: response inspection, redirect handling, loop detection, error pages, query/cookie-value redaction.
- Analysis fixtures: hardened headers, JSON response scope, HTTP resource references and form actions.
- Cancellation before network access and TLS certificate rejection without bypass (mocked certificate failure).
- Report escaping and parseable JSON export.
- Local GUI API rejects missing tokens, unexpected Host headers, foreign Origin headers, and invalid scan targets.
- Browser GUI manually exercised: demo, real scan of the local app, severity filtering, and restoring a report from session history. HTML and JSON download controls were exercised.
- GUI visually inspected at the browser's desktop viewport.

External websites, real certificate renewal/expiry scenarios, and mobile browsers were not tested. No security audit or penetration test of the application has been performed.

Run again from this folder with `python -m unittest discover -s tests -v`.
