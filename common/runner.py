#!/usr/bin/env python3
"""
CyberSWISS – Orchestrator / Runner
===================================
Central runner that discovers and executes audit scripts filtered by OS,
severity, tag, or explicit script IDs. Produces a consolidated JSON report
and human-readable summary.

Usage examples
--------------
# Run all scripts for the current OS:
    python runner.py

# Run only Linux scripts with severity >= High:
    python runner.py --os linux --min-severity High

# Run specific scripts by ID:
    python runner.py --scripts W01 W07 L15

# Run and save JSON + HTML + CSV reports:
    python runner.py --output reports/audit.json --html reports/audit.html --csv reports/audit.csv

# Dry-run (list scripts that would run):
    python runner.py --dry-run

# Save to scan history DB and show drift vs last run:
    python runner.py --save-db --diff

# Rate-limit between scripts (evasion / IDS avoidance):
    python runner.py --delay 2

# Apply automatic remediations:
    python runner.py --fix
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import sys
import time
from pathlib import Path

# Ensure common/ is importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

from utils import (  # noqa: E402
    SEVERITY_ORDER,
    coloured,
    current_host,
    current_os,
    discover_scripts,
    expected_exit_code,
    filter_findings,
    now_iso,
    run_script,
    save_json_report,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def non_negative_float(value: str) -> float:
    parsed = float(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be zero or greater")
    return parsed


# ── CLI Argument Parsing ───────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="runner.py",
        description="CyberSWISS Security Audit Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--os",
        dest="os_filter",
        choices=["windows", "linux", "both"],
        default=None,
        help="Filter scripts by OS. Default: auto-detect current OS.",
    )
    parser.add_argument(
        "--scripts",
        nargs="+",
        metavar="ID",
        default=None,
        help="Run only the specified script IDs (e.g. W01 L07 W15).",
    )
    parser.add_argument(
        "--min-severity",
        choices=list(SEVERITY_ORDER.keys()),
        default=None,
        metavar="SEV",
        help="Only report findings at or above this severity.",
    )
    parser.add_argument(
        "--status",
        nargs="+",
        choices=["PASS", "FAIL", "WARN", "INFO"],
        default=None,
        help="Filter output to specific finding statuses.",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        metavar="FILE",
        help="Write consolidated JSON report to FILE.",
    )
    parser.add_argument(
        "--timeout",
        type=positive_int,
        default=300,
        metavar="SEC",
        help="Per-script timeout in seconds (default: 300).",
    )
    parser.add_argument(
        "--parallel",
        type=positive_int,
        default=1,
        metavar="N",
        help="Number of scripts to run in parallel (default: 1).",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Pass --fix to each script to apply automatic remediation where available.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List scripts that would run without executing them.",
    )
    parser.add_argument(
        "--no-colour",
        action="store_true",
        help="Disable ANSI colour output.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print consolidated report as JSON to stdout instead of human-readable.",
    )
    parser.add_argument(
        "--html",
        metavar="FILE",
        default=None,
        help="Write HTML report to FILE.",
    )
    parser.add_argument(
        "--csv",
        metavar="FILE",
        default=None,
        help="Write CSV report to FILE.",
    )
    parser.add_argument(
        "--text",
        metavar="FILE",
        default=None,
        help="Write plain-text report to FILE (use - for stdout).",
    )
    parser.add_argument(
        "--delay",
        type=non_negative_float,
        default=0.0,
        metavar="SEC",
        help="Seconds to wait between script executions (rate limiting / evasion). Default: 0.",
    )
    parser.add_argument(
        "--save-db",
        action="store_true",
        help="Save scan results to the SQLite scan history database.",
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help="Show drift report comparing current scan vs last saved scan (implies --save-db).",
    )
    return parser.parse_args()


# ── Helpers ────────────────────────────────────────────────────────────────────
def print_banner() -> None:
    print(
        "\n"
        "╔══════════════════════════════════════════════════════╗\n"
        "║          CyberSWISS Security Audit Platform          ║\n"
        "║     Internal Defensive Audit – Authorised Use Only   ║\n"
        "╚══════════════════════════════════════════════════════╝"
    )


def select_scripts(args: argparse.Namespace) -> list[dict]:
    """Apply OS and ID filters to discover scripts."""
    os_filter: str | None = None
    if args.os_filter == "both":
        os_filter = None
    elif args.os_filter:
        os_filter = args.os_filter
    else:
        os_filter = current_os()

    all_scripts = discover_scripts(os_filter=os_filter)

    if args.scripts:
        upper_ids = {s.upper() for s in args.scripts}
        all_scripts = [s for s in all_scripts if s["id"].upper() in upper_ids]

    return all_scripts


def print_finding(finding: dict, no_colour: bool = False) -> None:
    status = finding.get("status", "?")
    sev = finding.get("severity", "?")
    fid = finding.get("id", "?")
    name = finding.get("name", "?")
    detail = finding.get("detail", "")
    remedy = finding.get("remediation", "")

    line = f"[{status}] [{sev}] {fid}: {name}"
    if not no_colour:
        line = coloured(line, status)
    print(line)
    if detail:
        print(f"       Detail : {detail}")
    if status not in ("PASS", "INFO") and remedy:
        rem_line = f"       Remedy : {remedy}"
        if not no_colour:
            rem_line = f"\033[0;36m{rem_line}\033[0m"
        print(rem_line)


def print_script_result(
    result: dict,
    min_severity: str | None,
    status_filter: list[str] | None,
    no_colour: bool,
) -> tuple[int, int, int]:
    """Print findings for one script result. Returns (total, fails, warns)."""
    script_name = result.get("script", "unknown")
    host = result.get("host", os.environ.get("COMPUTERNAME", "localhost"))
    if not host or host == "localhost":
        host = current_host()
    findings = result.get("findings", [])

    if result.get("error"):
        err_line = f"\n[ERROR] {script_name}: {result['error']}"
        print(coloured(err_line, "FAIL") if not no_colour else err_line)
        return 0, 0, 0

    # Apply filters
    filtered = filter_findings(
        findings,
        min_severity=min_severity,
        status_filter=status_filter,
    )

    if filtered:
        hdr = f"\n── {script_name} ({host}) {'─' * max(0, 50 - len(script_name) - len(host))}"
        print(hdr)
        for f in filtered:
            print_finding(f, no_colour=no_colour)

    fix_report = result.get("fix_report")
    if isinstance(fix_report, dict):
        if fix_report.get("verification_error"):
            print(f"       Fix verification failed: {fix_report['verification_error']}")
        else:
            print(
                "       Fix verification: "
                f"fixed {fix_report.get('fixed_count', 0)}, "
                f"remaining {fix_report.get('remaining_count', 0)}, "
                f"new issues {fix_report.get('new_issue_count', 0)}"
            )

    total = len(findings)
    fails = sum(1 for f in findings if f.get("status") == "FAIL")
    warns = sum(1 for f in findings if f.get("status") == "WARN")
    return total, fails, warns


def build_consolidated_report(results: list[dict]) -> dict:
    """Build the canonical consolidated report for all output modes."""
    all_findings_flat = [finding for result in results for finding in result.get("findings", [])]
    return {
        "cyberswiss_report": True,
        "generated_at": now_iso(),
        "host": current_host(),
        "scripts_run": len(results),
        "total_findings": len(all_findings_flat),
        "fail_count": sum(1 for finding in all_findings_flat if finding.get("status") == "FAIL"),
        "warn_count": sum(1 for finding in all_findings_flat if finding.get("status") == "WARN"),
        "results": results,
    }


def _index_findings_by_id(findings: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    return {
        str(finding.get("id", f"row-{idx}")): finding
        for idx, finding in enumerate(findings)
    }


def _summarize_fix_outcome(
    audit_findings: list[dict[str, object]],
    verification_findings: list[dict[str, object]],
) -> dict[str, object]:
    before = _index_findings_by_id(audit_findings)
    after = _index_findings_by_id(verification_findings)

    actionable_before = {
        finding_id: finding
        for finding_id, finding in before.items()
        if finding.get("status") in {"FAIL", "WARN"}
    }
    actionable_after = {
        finding_id: finding
        for finding_id, finding in after.items()
        if finding.get("status") in {"FAIL", "WARN"}
    }

    fixed_items: list[dict[str, object]] = []
    remaining_items: list[dict[str, object]] = []
    new_issues: list[dict[str, object]] = []

    for finding_id, finding in actionable_before.items():
        verified = after.get(finding_id)
        verified_status = verified.get("status") if verified else "MISSING"
        if verified and verified_status in {"PASS", "INFO"}:
            fixed_items.append(
                {
                    "id": finding_id,
                    "name": finding.get("name", ""),
                    "before_status": finding.get("status", ""),
                    "after_status": verified_status,
                }
            )
        else:
            remaining_items.append(
                {
                    "id": finding_id,
                    "name": finding.get("name", ""),
                    "before_status": finding.get("status", ""),
                    "after_status": verified_status,
                    "detail": (verified or finding).get("detail", ""),
                }
            )

    for finding_id, finding in actionable_after.items():
        if finding_id not in actionable_before:
            new_issues.append(
                {
                    "id": finding_id,
                    "name": finding.get("name", ""),
                    "status": finding.get("status", ""),
                    "detail": finding.get("detail", ""),
                }
            )

    return {
        "verified": True,
        "fixed_count": len(fixed_items),
        "remaining_count": len(remaining_items),
        "new_issue_count": len(new_issues),
        "fixed_items": fixed_items,
        "remaining_items": remaining_items,
        "new_issues": new_issues,
        "audit_actionable_count": len(actionable_before),
        "verification_actionable_count": len(actionable_after),
    }


# ── Main ───────────────────────────────────────────────────────────────────────
def main() -> int:
    args = parse_args()

    if args.no_colour:
        # Disable colour globally
        os.environ["NO_COLOR"] = "1"

    if not args.json:
        print_banner()

    scripts = select_scripts(args)

    if not scripts:
        print("No scripts match the specified filters.", file=sys.stderr)
        return 1

    if args.dry_run:
        if args.json:
            dry_report = {
                "cyberswiss_report": True,
                "dry_run": True,
                "timestamp": now_iso(),
                "scripts": [
                    {"id": s["id"], "os": s["os"], "lang": s["lang"], "path": str(s["path"]), "name": s.get("name", "")}
                    for s in scripts
                ],
            }
            print(json.dumps(dry_report, indent=2, default=str))
        else:
            print(f"\nDry-run: {len(scripts)} script(s) would run:\n")
            for s in scripts:
                print(f"  {s['id']:6s}  {s['os']:8s}  {s['lang']:12s}  {s['path']}")
        return 0

    if not args.json:
        print(f"\nStarting audit: {len(scripts)} script(s) | OS={args.os_filter or current_os()} | {now_iso()}\n")

    # ── Execute scripts ────────────────────────────────────────────────────────
    all_results: list[dict] = []
    _script_count = len(scripts)

    def run_one(index: int, s: dict) -> dict:
        if args.delay > 0 and args.parallel > 1 and index > 0:
            time.sleep(args.delay * index)
        if not args.json:
            print(f"  → Running {s['id']:6s}  {s['name']} ...", flush=True)
        result = run_script(s["path"], json_mode=True, timeout=args.timeout, fix_mode=args.fix)
        if args.fix and not result.get("error"):
            audit_findings = list(result.get("findings", []))
            verification = run_script(s["path"], json_mode=True, timeout=args.timeout, fix_mode=False)
            result["audit_findings"] = audit_findings
            result["verification_result"] = verification
            if verification.get("error"):
                result["fix_report"] = {
                    "verified": False,
                    "verification_error": verification["error"],
                }
            else:
                verification_findings = list(verification.get("findings", []))
                result["findings"] = verification_findings
                result["exit_code"] = verification.get("exit_code", result.get("exit_code"))
                if verification.get("stderr"):
                    result["stderr"] = verification.get("stderr")
                result["fix_report"] = _summarize_fix_outcome(audit_findings, verification_findings)
        result.setdefault("script_meta", {"id": s["id"], "os": s["os"]})
        return result

    try:
        if args.parallel > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as pool:
                ordered_results: list[dict | None] = [None] * _script_count
                futures = {
                    pool.submit(run_one, idx, script): idx
                    for idx, script in enumerate(scripts)
                }
                for fut in concurrent.futures.as_completed(futures):
                    ordered_results[futures[fut]] = fut.result()
                all_results = [result for result in ordered_results if result is not None]
        else:
            for idx, s in enumerate(scripts):
                all_results.append(run_one(idx, s))
                # Rate limiting between scripts (evasion / IDS avoidance)
                if args.delay > 0 and idx < _script_count - 1:
                    time.sleep(args.delay)
    except KeyboardInterrupt:
        if args.json:
            interrupted_report = build_consolidated_report(all_results)
            interrupted_report["interrupted"] = True
            interrupted_report["message"] = "Audit interrupted by user"
            print(json.dumps(interrupted_report, indent=2, default=str))
        else:
            print(
                f"\nAudit interrupted by user after {len(all_results)}/{_script_count} script(s).",
                file=sys.stderr,
            )
        return 130

    # ── Consolidate ────────────────────────────────────────────────────────────
    consolidated = build_consolidated_report(all_results)
    grand_total = consolidated["total_findings"]
    grand_fails = consolidated["fail_count"]
    grand_warns = consolidated["warn_count"]

    if args.json:
        print(json.dumps(consolidated, indent=2, default=str))
    else:
        print("\n" + "═" * 60)
        print("  AUDIT RESULTS")
        print("═" * 60)
        for result in all_results:
            print_script_result(
                result,
                min_severity=args.min_severity,
                status_filter=args.status,
                no_colour=args.no_colour,
            )

        print("\n" + "═" * 60)
        print(f"  SUMMARY  |  Scripts: {len(all_results)}  |  Findings: {grand_total}  |  FAIL: {grand_fails}  |  WARN: {grand_warns}")
        print("═" * 60)

    # ── Save report ────────────────────────────────────────────────────────────
    if args.output or args.html or args.csv or args.text or args.save_db or args.diff:
        report = consolidated

        if args.output:
            save_json_report(report, args.output)
            if not args.json:
                print(f"\nJSON report saved to: {args.output}")

        if args.html:
            try:
                from report_generator import generate_html  # noqa: PLC0415
                html_content = generate_html(report)
                Path(args.html).parent.mkdir(parents=True, exist_ok=True)
                Path(args.html).write_text(html_content, encoding="utf-8")
                if not args.json:
                    print(f"HTML report saved to: {args.html}")
            except Exception as exc:  # noqa: BLE001
                print(f"WARNING: HTML generation failed: {exc}", file=sys.stderr)

        if args.csv:
            try:
                from report_generator import generate_csv  # noqa: PLC0415
                csv_content = generate_csv(report)
                if args.csv == "-":
                    sys.stdout.write(csv_content)
                else:
                    Path(args.csv).parent.mkdir(parents=True, exist_ok=True)
                    Path(args.csv).write_text(csv_content, encoding="utf-8")
                    if not args.json:
                        print(f"CSV report saved to: {args.csv}")
            except Exception as exc:  # noqa: BLE001
                print(f"WARNING: CSV generation failed: {exc}", file=sys.stderr)

        if args.text:
            try:
                from report_generator import generate_text  # noqa: PLC0415
                text_content = generate_text(report)
                if args.text == "-":
                    sys.stdout.write(text_content)
                else:
                    Path(args.text).parent.mkdir(parents=True, exist_ok=True)
                    Path(args.text).write_text(text_content, encoding="utf-8")
                    if not args.json:
                        print(f"Text report saved to: {args.text}")
            except Exception as exc:  # noqa: BLE001
                print(f"WARNING: Text generation failed: {exc}", file=sys.stderr)

        # ── Scan history DB & drift detection ─────────────────────────────────
        if args.save_db or args.diff:
            try:
                from db import ScanDatabase, format_drift_report  # noqa: PLC0415
                db = ScanDatabase()
                if args.diff:
                    # Capture drift BEFORE saving the current scan
                    drift = db.detect_drift(report)
                    if drift["has_drift"]:
                        drift_text = format_drift_report(drift, no_colour=args.no_colour or args.json)
                        if args.json:
                            report["drift"] = drift
                        else:
                            print("\n" + drift_text)
                    elif not args.json:
                        print("\nDrift detection: No changes detected vs last scan.")
                scan_id = db.save_scan(report)
                if not args.json:
                    print(f"Scan saved to history DB (scan_id={scan_id}).")
            except Exception as exc:  # noqa: BLE001
                print(f"WARNING: DB operation failed: {exc}", file=sys.stderr)

    # Exit code: 0=all pass, 1=warnings, 2=failures
    return expected_exit_code([finding for result in all_results for finding in result.get("findings", [])])


if __name__ == "__main__":
    sys.exit(main())
