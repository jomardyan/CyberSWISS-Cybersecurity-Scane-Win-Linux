#!/usr/bin/env python3
"""
CyberSWISS – HTML/JSON/CSV/Text Report Generator
==================================================
Reads one or more JSON result files produced by runner.py and generates:
  - A consolidated JSON report
  - A self-contained HTML report with summary tables
  - A CSV report for spreadsheet analysis
  - A plain-text report for terminals/email

Usage
-----
    python report_generator.py results/*.json --html reports/audit_report.html
    python report_generator.py results/audit.json --json reports/audit_report.json
    python report_generator.py results/audit.json --csv  reports/audit_report.csv
    python report_generator.py results/audit.json --text reports/audit_report.txt
"""
from __future__ import annotations

import argparse
import csv
import html
import io
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from utils import SEVERITY_ORDER, filter_findings, load_json_report, save_json_report  # noqa: E402


# ── HTML Template ──────────────────────────────────────────────────────────────
_HTML_HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CyberSWISS Audit Report – {host}</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; background:#1a1a2e; color:#e0e0e0; margin:0; padding:20px; }}
h1,h2,h3 {{ color:#00d4ff; }}
.banner {{ background:#0f3460; border-left:5px solid #00d4ff; padding:15px 20px; margin-bottom:20px; border-radius:4px; }}
.stats {{ display:flex; gap:20px; flex-wrap:wrap; margin-bottom:20px; }}
.stat-card {{ background:#16213e; padding:15px 25px; border-radius:8px; text-align:center; min-width:100px; }}
.stat-card .num {{ font-size:2em; font-weight:bold; }}
.fail-num {{ color:#ff4757; }} .warn-num {{ color:#ffa502; }}
.pass-num {{ color:#2ed573; }} .info-num {{ color:#1e90ff; }}
table {{ border-collapse:collapse; width:100%; margin-bottom:20px; font-size:0.9em; }}
th {{ background:#0f3460; padding:8px 12px; text-align:left; position:sticky; top:0; }}
td {{ padding:7px 12px; border-bottom:1px solid #2a2a4a; vertical-align:top; }}
tr:hover td {{ background:#1e2a4a; }}
.badge {{ padding:2px 8px; border-radius:4px; font-size:0.8em; font-weight:bold; }}
.FAIL {{ background:#ff4757; color:#fff; }}
.WARN {{ background:#ffa502; color:#000; }}
.PASS {{ background:#2ed573; color:#000; }}
.INFO {{ background:#1e90ff; color:#fff; }}
.Critical {{ color:#ff6b81; font-weight:bold; }}
.High {{ color:#ff7f50; font-weight:bold; }}
.Med {{ color:#ffd700; }}
.Low {{ color:#90ee90; }}
.Info {{ color:#87ceeb; }}
details summary {{ cursor:pointer; padding:8px; background:#0f3460; border-radius:4px; margin:4px 0; }}
details[open] summary {{ background:#1a3a5c; }}
pre {{ background:#0d0d1a; padding:10px; border-radius:4px; overflow-x:auto; font-size:0.8em; }}
footer {{ color:#666; font-size:0.8em; margin-top:40px; text-align:center; }}
</style>
</head>
<body>
<div class="banner">
  <h1>🔒 CyberSWISS Security Audit Report</h1>
  <p>Host: <strong>{host}</strong> &nbsp;|&nbsp; Generated: <strong>{timestamp}</strong> &nbsp;|&nbsp; Internal Use Only</p>
</div>
"""

_HTML_TAIL = """
<footer><p>CyberSWISS – Internal Defensive Security Audit Platform | Authorised Use Only</p></footer>
</body></html>
"""


def severity_badge(sev: str) -> str:
    return f'<span class="{sev}">{sev}</span>'


def status_badge(status: str) -> str:
    return f'<span class="badge {status}">{status}</span>'


def escape_html(value: object) -> str:
    """Escape values rendered into the HTML report."""
    return html.escape("" if value is None else str(value), quote=True)


def generate_html(consolidated: dict) -> str:
    all_findings: list[dict] = []
    for result in consolidated.get("results", []):
        for f in result.get("findings", []):
            f.setdefault("script", result.get("script", "unknown"))
            all_findings.append(f)

    host = consolidated.get("host", "unknown")
    ts = consolidated.get("generated_at", consolidated.get("timestamp", ""))

    total = len(all_findings)
    fails = sum(1 for f in all_findings if f.get("status") == "FAIL")
    warns = sum(1 for f in all_findings if f.get("status") == "WARN")
    passes = sum(1 for f in all_findings if f.get("status") == "PASS")
    infos = sum(1 for f in all_findings if f.get("status") == "INFO")
    scripts_run = consolidated.get("scripts_run", len(consolidated.get("results", [])))

    parts: list[str] = [_HTML_HEAD.format(host=escape_html(host), timestamp=escape_html(ts))]

    # Stats
    parts.append('<div class="stats">')
    parts.append(f'<div class="stat-card"><div class="num">{scripts_run}</div><div>Scripts Run</div></div>')
    parts.append(f'<div class="stat-card"><div class="num fail-num">{fails}</div><div>FAIL</div></div>')
    parts.append(f'<div class="stat-card"><div class="num warn-num">{warns}</div><div>WARN</div></div>')
    parts.append(f'<div class="stat-card"><div class="num pass-num">{passes}</div><div>PASS</div></div>')
    parts.append(f'<div class="stat-card"><div class="num info-num">{infos}</div><div>INFO</div></div>')
    parts.append(f'<div class="stat-card"><div class="num">{total}</div><div>Total Findings</div></div>')
    parts.append("</div>")

    # Per-script summary
    parts.append("<h2>Script Summary</h2>")
    parts.append('<table><tr><th>Script</th><th>Host</th><th>FAIL</th><th>WARN</th><th>PASS</th><th>Total</th></tr>')
    for result in consolidated.get("results", []):
        f_list = result.get("findings", [])
        s_fail = sum(1 for f in f_list if f.get("status") == "FAIL")
        s_warn = sum(1 for f in f_list if f.get("status") == "WARN")
        s_pass = sum(1 for f in f_list if f.get("status") == "PASS")
        s_name = result.get("script", "unknown")
        s_host = result.get("host", host)
        fail_td = f'<td style="color:#ff4757">{s_fail}</td>' if s_fail else f"<td>{s_fail}</td>"
        warn_td = f'<td style="color:#ffa502">{s_warn}</td>' if s_warn else f"<td>{s_warn}</td>"
        parts.append(
            f"<tr><td>{escape_html(s_name)}</td><td>{escape_html(s_host)}</td>"
            f"{fail_td}{warn_td}<td>{s_pass}</td><td>{len(f_list)}</td></tr>"
        )
    parts.append("</table>")

    # All findings table (sorted by severity desc, then status FAIL first)
    sorted_findings = sorted(
        all_findings,
        key=lambda f: (
            -SEVERITY_ORDER.get(f.get("severity", ""), 0),
            0 if f.get("status") == "FAIL" else 1 if f.get("status") == "WARN" else 2,
        ),
    )

    parts.append("<h2>All Findings</h2>")
    parts.append(
        "<table><tr>"
        "<th>ID</th><th>Name</th><th>Status</th><th>Severity</th>"
        "<th>Script</th><th>Detail</th><th>Remediation</th>"
        "</tr>"
    )
    for f in sorted_findings:
        detail = escape_html(f.get("detail", ""))
        remedy = escape_html(f.get("remediation", ""))
        parts.append(
            f"<tr>"
            f"<td>{escape_html(f.get('id', ''))}</td>"
            f"<td>{escape_html(f.get('name', ''))}</td>"
            f"<td>{status_badge(f.get('status', ''))}</td>"
            f"<td>{severity_badge(f.get('severity', ''))}</td>"
            f"<td>{escape_html(f.get('script', ''))}</td>"
            f"<td>{detail}</td>"
            f"<td>{remedy}</td>"
            f"</tr>"
        )
    parts.append("</table>")

    parts.append(_HTML_TAIL)
    return "\n".join(parts)


# ── CSV Generator ──────────────────────────────────────────────────────────────
def generate_csv(consolidated: dict) -> str:
    """Generate a CSV report from consolidated scan data.

    Columns: Script, FindingID, Name, Status, Severity, Detail, Remediation, Timestamp
    """
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(["Script", "FindingID", "Name", "Status", "Severity", "Detail", "Remediation", "Timestamp"])

    for result in consolidated.get("results", []):
        script_name = result.get("script", "unknown")
        for f in result.get("findings", []):
            writer.writerow([
                script_name,
                f.get("id", ""),
                f.get("name", ""),
                f.get("status", ""),
                f.get("severity", ""),
                f.get("detail", "").replace("\n", " ").replace("\r", ""),
                f.get("remediation", "").replace("\n", " ").replace("\r", ""),
                f.get("timestamp", ""),
            ])
    return output.getvalue()


# ── Plain-Text Generator ───────────────────────────────────────────────────────
_STATUS_ICONS = {"PASS": "✓", "FAIL": "✗", "WARN": "⚠", "INFO": "ℹ"}


def generate_text(consolidated: dict) -> str:
    """Generate a plain-text report for terminals, email, or log files."""
    lines: list[str] = []
    host = consolidated.get("host", "unknown")
    ts = consolidated.get("generated_at", consolidated.get("timestamp", ""))
    total = consolidated.get("total_findings", 0)
    fails = consolidated.get("fail_count", 0)
    warns = consolidated.get("warn_count", 0)

    sep = "=" * 70
    lines.append(sep)
    lines.append("  CyberSWISS Security Audit Report")
    lines.append(f"  Host: {host}   Generated: {ts}")
    lines.append(sep)
    lines.append(f"  Scripts Run: {consolidated.get('scripts_run', 0)}   "
                 f"Total Findings: {total}   FAIL: {fails}   WARN: {warns}")
    lines.append(sep)
    lines.append("")

    for result in consolidated.get("results", []):
        script_name = result.get("script", "unknown")
        findings = result.get("findings", [])
        if not findings:
            continue
        lines.append(f"── {script_name} " + "─" * max(0, 65 - len(script_name)))
        for f in findings:
            icon = _STATUS_ICONS.get(f.get("status", ""), "?")
            lines.append(
                f"  {icon} [{f.get('status', '?'):4s}] [{f.get('severity', '?'):8s}] "
                f"{f.get('id', '')}: {f.get('name', '')}"
            )
            if f.get("detail"):
                lines.append(f"         Detail : {f['detail']}")
            if f.get("status") not in ("PASS", "INFO") and f.get("remediation"):
                lines.append(f"         Remedy : {f['remediation']}")
        lines.append("")

    lines.append(sep)
    lines.append("  END OF REPORT \u2013 CyberSWISS | Authorised Use Only")
    lines.append(sep)
    return "\n".join(lines) + "\n"


# ── Argument Parsing ───────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="CyberSWISS Report Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("inputs", nargs="+", metavar="JSON_FILE", help="Input JSON result files")
    p.add_argument("--html", metavar="FILE", help="Write HTML report to FILE")
    p.add_argument("--json", metavar="FILE", help="Write consolidated JSON report to FILE")
    p.add_argument("--csv",  metavar="FILE", help="Write CSV report to FILE")
    p.add_argument("--text", metavar="FILE", help="Write plain-text report to FILE (use - for stdout)")
    p.add_argument("--min-severity", choices=list(SEVERITY_ORDER.keys()), default=None)
    return p.parse_args()


def main() -> int:
    args = parse_args()

    all_results: list[dict] = []
    host = "unknown"

    for input_path in args.inputs:
        try:
            data = load_json_report(input_path)
        except Exception as exc:
            print(f"ERROR loading {input_path}: {exc}", file=sys.stderr)
            continue

        # Support both single-script results and consolidated reports
        if "results" in data:
            all_results.extend(data["results"])
            host = data.get("host", host)
        else:
            all_results.append(data)
            host = data.get("host", host)

    if not all_results:
        print("No results loaded.", file=sys.stderr)
        return 1

    # Apply severity filter
    if args.min_severity:
        for r in all_results:
            r["findings"] = filter_findings(r.get("findings", []), min_severity=args.min_severity)

    all_findings = [f for r in all_results for f in r.get("findings", [])]

    consolidated = {
        "cyberswiss_report": True,
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "host": host,
        "scripts_run": len(all_results),
        "total_findings": len(all_findings),
        "fail_count": sum(1 for f in all_findings if f.get("status") == "FAIL"),
        "warn_count": sum(1 for f in all_findings if f.get("status") == "WARN"),
        "results": all_results,
    }

    any_output = False

    if args.json:
        save_json_report(consolidated, args.json)
        print(f"JSON report saved to: {args.json}")
        any_output = True

    if args.html:
        html_content = generate_html(consolidated)
        Path(args.html).parent.mkdir(parents=True, exist_ok=True)
        Path(args.html).write_text(html_content, encoding="utf-8")
        print(f"HTML report saved to: {args.html}")
        any_output = True

    if args.csv:
        csv_content = generate_csv(consolidated)
        if args.csv == "-":
            sys.stdout.write(csv_content)
        else:
            Path(args.csv).parent.mkdir(parents=True, exist_ok=True)
            Path(args.csv).write_text(csv_content, encoding="utf-8")
            print(f"CSV report saved to: {args.csv}")
        any_output = True

    if args.text:
        text_content = generate_text(consolidated)
        if args.text == "-":
            sys.stdout.write(text_content)
        else:
            Path(args.text).parent.mkdir(parents=True, exist_ok=True)
            Path(args.text).write_text(text_content, encoding="utf-8")
            print(f"Text report saved to: {args.text}")
        any_output = True

    if not any_output:
        print(json.dumps(consolidated, indent=2, default=str))

    return 0


if __name__ == "__main__":
    sys.exit(main())
