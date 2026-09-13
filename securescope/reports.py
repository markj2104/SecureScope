"""Portable reports; untrusted website strings are always escaped in HTML."""
from html import escape
import json


def export_json(report, path):
    path.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")


def export_html(report, path):
    e = lambda v: escape(str(v), quote=True)
    cards = "".join(f'<article><span class="badge">{e(f.severity)}</span><h2>{e(f.title)}</h2><p>{e(f.evidence)}</p><h3>Suggested action</h3><p>{e(f.recommendation)}</p><a href="{e(f.reference)}">Reference</a></article>' for f in report.findings)
    notes = "".join(f"<li>{e(n)}</li>" for n in report.notes)
    headers = "".join(f"<tr><td>{e(k)}</td><td>{e(v)}</td></tr>" for k, v in report.headers)
    path.write_text(f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Secure Scope report</title>
<style>body{{font:16px/1.6 system-ui;background:#101721;color:#e8eef6;max-width:980px;margin:40px auto;padding:0 24px}}h1{{font-size:38px;margin-bottom:4px}}h2{{font-size:20px}}h3{{font-size:14px;color:#63ddba}}article{{background:#1b2635;padding:24px;margin:16px 0;border-radius:12px}}.badge{{color:#63ddba;font-weight:700}}a{{color:#80baff}}td{{padding:10px;border-bottom:1px solid #354154;overflow-wrap:anywhere}}table{{width:100%;table-layout:fixed}}p{{overflow-wrap:anywhere}}</style>
<h1>Secure Scope</h1><p>{'DEMO · ' if report.demo else ''}Website configuration report · {e(report.started)}</p><p><strong>{e(report.target)}</strong><br>Final URL: {e(report.final_url)}<br>HTTP {e(report.status)} · {e(report.duration)} seconds</p>
{cards}<h2>Scope & limitations</h2><ul>{notes}</ul><h2>Response headers</h2><table>{headers}</table></html>''', encoding="utf-8")
