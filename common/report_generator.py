#!/usr/bin/env python3
"""
CyberSWISS – HTML/JSON/CSV/Text/SARIF/Markdown Report Generator
================================================================
Reads one or more JSON result files produced by runner.py and generates:
  - A consolidated JSON report
  - A self-contained HTML report with summary tables
  - A CSV report for spreadsheet analysis
  - A plain-text report for terminals/email
  - A SARIF 2.1.0 report for GitHub code scanning and SAST dashboards
  - A Markdown report for pull-request comments and CI job summaries

Usage
-----
    python report_generator.py results/*.json --html reports/audit_report.html
    python report_generator.py results/audit.json --json reports/audit_report.json
    python report_generator.py results/audit.json --csv  reports/audit_report.csv
    python report_generator.py results/audit.json --text reports/audit_report.txt
    python report_generator.py results/audit.json --sarif reports/audit.sarif
    python report_generator.py results/audit.json --markdown - >> "$GITHUB_STEP_SUMMARY"
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
.banner {{ background:#0f3460; border-left:5px solid #00d4ff; padding:15px 20px;
           margin-bottom:20px; border-radius:4px; }}
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
  <p>Host: <strong>{host}</strong> &nbsp;|&nbsp;
     Generated: <strong>{timestamp}</strong> &nbsp;|&nbsp; Internal Use Only</p>
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


# ── SARIF Generator ────────────────────────────────────────────────────────────
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_INFORMATION_URI = "https://github.com/jomardyan/CyberSWISS-Cybersecurity-Scane-Win-Linux"

#: CyberSWISS status → SARIF result level.  PASS findings are emitted as
#: ``kind: pass`` with level ``none`` so evidence of a passing control is not
#: lost, without raising an alert.
_SARIF_LEVELS = {"FAIL": "error", "WARN": "warning", "INFO": "note", "PASS": "none"}

#: Severity → the numeric ``security-severity`` GitHub code scanning uses to
#: bucket alerts (Critical/High/Medium/Low).
_SECURITY_SEVERITY = {
    "Critical": "9.5",
    "High": "8.0",
    "Med": "5.5",
    "Low": "3.0",
    "Info": "1.0",
}


def _iter_findings(consolidated: dict):
    """Yield ``(script_name, finding)`` pairs across every result."""
    for result in consolidated.get("results", []):
        script_name = result.get("script", "unknown")
        for finding in result.get("findings", []):
            yield script_name, finding


def _script_uri(script_name: str) -> str:
    """
    Map a script name (e.g. ``L07_ssh_posture``) to its repo-relative path.

    SARIF consumers such as GitHub code scanning anchor every result to a
    file, so findings are attributed to the check script that produced them.
    """
    if not script_name or script_name == "unknown":
        return "common/runner.py"
    if script_name.upper().startswith("W"):
        return f"windows/{script_name}.ps1"
    if script_name.upper().startswith("L"):
        return f"linux/{script_name}.sh"
    return f"common/{script_name}"


def _sarif_timestamp(value: object) -> str:
    """Normalise an ISO timestamp to the ``...Z`` form SARIF requires."""
    text = str(value or "").strip()
    if not text:
        text = datetime.now(tz=timezone.utc).isoformat()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        parsed = datetime.now(tz=timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_sarif(consolidated: dict, include_passed: bool = False) -> str:
    """
    Render a consolidated report as SARIF 2.1.0 JSON.

    SARIF is the interchange format consumed by GitHub code scanning, Azure
    DevOps, and most SAST dashboards — uploading it surfaces CyberSWISS
    findings alongside the repository's other security alerts.

    Findings suppressed by a baseline are emitted with a SARIF ``suppressions``
    entry, so downstream tools show them as accepted risk rather than as new
    alerts.

    Parameters
    ----------
    consolidated:
        Consolidated report dict as produced by ``runner.py``.
    include_passed:
        When ``True``, PASS findings are included as ``kind: pass`` results.
    """
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for script_name, finding in _iter_findings(consolidated):
        status = str(finding.get("status", "")).upper()
        if status == "PASS" and not include_passed:
            continue

        finding_id = str(finding.get("id") or f"{script_name}-unknown")
        severity = str(finding.get("severity", "Info"))
        name = str(finding.get("name", finding_id))
        remediation = str(finding.get("remediation", ""))
        detail = str(finding.get("detail", ""))
        level = _SARIF_LEVELS.get(status, "note")

        if finding_id not in rules:
            rule: dict = {
                "id": finding_id,
                "name": name or finding_id,
                "shortDescription": {"text": name or finding_id},
                "fullDescription": {"text": detail or name or finding_id},
                "defaultConfiguration": {"level": level},
                "properties": {
                    "tags": ["security", "cyberswiss", script_name],
                    "security-severity": _SECURITY_SEVERITY.get(severity, "1.0"),
                    "severity": severity,
                },
            }
            if remediation:
                rule["help"] = {
                    "text": remediation,
                    "markdown": f"**Remediation:** {remediation}",
                }
            rules[finding_id] = rule

        message = f"[{severity}] {name}"
        if detail:
            message = f"{message}: {detail}"
        if remediation and status in ("FAIL", "WARN"):
            message = f"{message} — Remediation: {remediation}"

        result: dict = {
            "ruleId": finding_id,
            "level": level,
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": _script_uri(script_name)},
                        "region": {"startLine": 1},
                    },
                    "logicalLocations": [{"name": script_name, "kind": "module"}],
                }
            ],
            "partialFingerprints": {"cyberswissFindingId": f"{script_name}/{finding_id}"},
            "properties": {
                "script": script_name,
                "status": status,
                "severity": severity,
                "host": consolidated.get("host", "unknown"),
            },
        }
        if status == "PASS":
            result["kind"] = "pass"
        if finding.get("suppressed"):
            result["suppressions"] = [
                {
                    "kind": "external",
                    "justification": str(
                        finding.get("suppression_reason", "Accepted risk (CyberSWISS baseline)")
                    ),
                }
            ]

        results.append(result)

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CyberSWISS",
                        "fullName": "CyberSWISS Security Audit Platform",
                        "informationUri": TOOL_INFORMATION_URI,
                        "version": consolidated.get("version", "1.0.0"),
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": _sarif_timestamp(
                            consolidated.get("generated_at", consolidated.get("timestamp"))
                        ),
                    }
                ],
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, default=str)


# ── Markdown Generator ─────────────────────────────────────────────────────────
def _md_escape(value: object) -> str:
    """Escape the characters that would break a Markdown table cell."""
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ").replace("\r", "").strip()


def generate_markdown(consolidated: dict, max_findings: int = 100) -> str:
    """
    Render a consolidated report as Markdown.

    Sized for a pull-request comment or a GitHub Actions job summary
    (``$GITHUB_STEP_SUMMARY``): a verdict line, headline counts, a per-script
    breakdown, and the actionable findings ordered by severity.

    Parameters
    ----------
    consolidated:
        Consolidated report dict as produced by ``runner.py``.
    max_findings:
        Maximum number of findings to tabulate; the remainder are summarised
        as a count so the output stays within comment size limits.
    """
    all_findings = [dict(f, script=f.get("script", s)) for s, f in _iter_findings(consolidated)]
    live = [f for f in all_findings if not f.get("suppressed")]

    fails = sum(1 for f in live if f.get("status") == "FAIL")
    warns = sum(1 for f in live if f.get("status") == "WARN")
    passes = sum(1 for f in all_findings if f.get("status") == "PASS")
    infos = sum(1 for f in all_findings if f.get("status") == "INFO")
    suppressed = [f for f in all_findings if f.get("suppressed")]

    host = consolidated.get("host", "unknown")
    ts = consolidated.get("generated_at", consolidated.get("timestamp", ""))
    scripts_run = consolidated.get("scripts_run", len(consolidated.get("results", [])))

    if fails:
        verdict = f"❌ **Audit failed** — {fails} failing control(s) require action."
    elif warns:
        verdict = f"⚠️ **Audit passed with warnings** — {warns} control(s) need review."
    else:
        verdict = "✅ **Audit passed** — no failing controls detected."

    lines: list[str] = [
        "## 🔒 CyberSWISS Security Audit",
        "",
        verdict,
        "",
        f"`Host: {_md_escape(host)}` · `Generated: {_md_escape(ts)}` · `Scripts: {scripts_run}`",
        "",
        "| FAIL | WARN | PASS | INFO | Suppressed | Total |",
        "|-----:|-----:|-----:|-----:|-----------:|------:|",
        f"| {fails} | {warns} | {passes} | {infos} | {len(suppressed)} | {len(all_findings)} |",
        "",
    ]

    # Per-script breakdown
    lines.append("### Script summary")
    lines.append("")
    lines.append("| Script | FAIL | WARN | PASS | Total |")
    lines.append("|---|-----:|-----:|-----:|------:|")
    for result in consolidated.get("results", []):
        script_findings = [f for f in result.get("findings", []) if not f.get("suppressed")]
        lines.append(
            f"| `{_md_escape(result.get('script', 'unknown'))}` "
            f"| {sum(1 for f in script_findings if f.get('status') == 'FAIL')} "
            f"| {sum(1 for f in script_findings if f.get('status') == 'WARN')} "
            f"| {sum(1 for f in script_findings if f.get('status') == 'PASS')} "
            f"| {len(result.get('findings', []))} |"
        )
    lines.append("")

    # Actionable findings, worst first
    actionable = sorted(
        (f for f in live if f.get("status") in ("FAIL", "WARN")),
        key=lambda f: (
            -SEVERITY_ORDER.get(f.get("severity", ""), 0),
            0 if f.get("status") == "FAIL" else 1,
            str(f.get("id", "")),
        ),
    )
    if actionable:
        lines.append(f"### Findings requiring action ({len(actionable)})")
        lines.append("")
        lines.append("| Status | Severity | ID | Finding | Script | Remediation |")
        lines.append("|---|---|---|---|---|---|")
        for f in actionable[:max_findings]:
            icon = "❌" if f.get("status") == "FAIL" else "⚠️"
            lines.append(
                f"| {icon} {_md_escape(f.get('status'))} "
                f"| {_md_escape(f.get('severity'))} "
                f"| `{_md_escape(f.get('id'))}` "
                f"| {_md_escape(f.get('name'))} "
                f"| `{_md_escape(f.get('script'))}` "
                f"| {_md_escape(f.get('remediation'))} |"
            )
        if len(actionable) > max_findings:
            lines.append("")
            lines.append(f"_…and {len(actionable) - max_findings} further finding(s) — see the full report._")
        lines.append("")

    if suppressed:
        lines.append("<details>")
        lines.append(f"<summary>Accepted risk – {len(suppressed)} baselined finding(s)</summary>")
        lines.append("")
        lines.append("| ID | Finding | Severity | Reason |")
        lines.append("|---|---|---|---|")
        for f in suppressed:
            lines.append(
                f"| `{_md_escape(f.get('id'))}` | {_md_escape(f.get('name'))} "
                f"| {_md_escape(f.get('severity'))} | {_md_escape(f.get('suppression_reason'))} |"
            )
        lines.append("")
        lines.append("</details>")
        lines.append("")

    lines.append("---")
    lines.append("<sub>CyberSWISS – Internal Defensive Security Audit Platform | Authorised Use Only</sub>")
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
    p.add_argument("--sarif", metavar="FILE", help="Write SARIF 2.1.0 report to FILE (use - for stdout)")
    p.add_argument("--markdown", metavar="FILE", help="Write Markdown report to FILE (use - for stdout)")
    p.add_argument(
        "--sarif-include-passed",
        action="store_true",
        help="Include PASS findings in the SARIF output as 'kind: pass' results.",
    )
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

    if args.sarif:
        sarif_content = generate_sarif(consolidated, include_passed=args.sarif_include_passed)
        if args.sarif == "-":
            sys.stdout.write(sarif_content + "\n")
        else:
            Path(args.sarif).parent.mkdir(parents=True, exist_ok=True)
            Path(args.sarif).write_text(sarif_content, encoding="utf-8")
            print(f"SARIF report saved to: {args.sarif}")
        any_output = True

    if args.markdown:
        md_content = generate_markdown(consolidated)
        if args.markdown == "-":
            sys.stdout.write(md_content)
        else:
            Path(args.markdown).parent.mkdir(parents=True, exist_ok=True)
            Path(args.markdown).write_text(md_content, encoding="utf-8")
            print(f"Markdown report saved to: {args.markdown}")
        any_output = True

    if not any_output:
        print(json.dumps(consolidated, indent=2, default=str))

    return 0


if __name__ == "__main__":
    sys.exit(main())
