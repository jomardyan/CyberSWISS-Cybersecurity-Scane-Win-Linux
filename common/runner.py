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
import itertools
import json
import os
import sys
import threading
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
        "--tags",
        nargs="+",
        metavar="TAG",
        default=None,
        help="Run only scripts whose category matches one of the given tags (case-insensitive, e.g. 'network' 'logging').",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print additional detail per script (stderr output, raw exit code).",
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

    if getattr(args, "tags", None):
        lower_tags = {t.lower() for t in args.tags}
        all_scripts = [
            s for s in all_scripts
            if any(t in s.get("category", "").lower() for t in lower_tags)
        ]

    return all_scripts


# ── Terminal width helper ─────────────────────────────────────────────────────
def _term_width() -> int:
    try:
        import shutil
        return max(80, shutil.get_terminal_size((120, 40)).columns)
    except Exception:  # pylint: disable=broad-except
        return 120


# ── Colour / badge helpers ─────────────────────────────────────────────────────
_STATUS_STYLE: dict[str, str] = {
    "FAIL": "\033[1;31m",   # bold red
    "WARN": "\033[1;33m",   # bold yellow
    "PASS": "\033[0;32m",   # green
    "INFO": "\033[0;36m",   # cyan
}
_SEV_STYLE: dict[str, str] = {
    "Critical": "\033[1;35m",  # bold magenta
    "High":     "\033[1;31m",  # bold red
    "Med":      "\033[0;33m",  # yellow
    "Low":      "\033[0;32m",  # green
    "Info":     "\033[0;36m",  # cyan
}
_RESET = "\033[0m"
_DIM   = "\033[2m"
_BOLD  = "\033[1m"


def _c(text: str, code: str, no_colour: bool) -> str:
    """Wrap text in an ANSI code, or return plain text when colour is off."""
    return text if no_colour else f"{code}{text}{_RESET}"


def _badge(label: str, code: str, width: int, no_colour: bool) -> str:
    """Fixed-width padded badge."""
    padded = label.center(width)
    return _c(padded, code, no_colour)


def _truncate(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


# ── Per-script table printer ───────────────────────────────────────────────────
_STATUS_ORDER = {"FAIL": 0, "WARN": 1, "INFO": 2, "PASS": 3}
_STATUS_ICON  = {"FAIL": "✗", "WARN": "⚠", "PASS": "✓", "INFO": "ℹ"}


def print_finding(finding: dict, no_colour: bool = False) -> None:
    """Legacy single-finding printer (used outside the table path)."""
    status = finding.get("status", "?")
    sev    = finding.get("severity", "?")
    fid    = finding.get("id", "?")
    name   = finding.get("name", "?")
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


def _print_findings_table(
    script_name: str,
    host: str,
    findings: list[dict],
    min_severity: str | None,
    status_filter: list[str] | None,
    no_colour: bool,
    verbose: bool,
) -> tuple[int, int, int]:
    """
    Print one script's findings as a compact aligned table.
    Returns (total, fails, warns).
    """
    W = _term_width()

    total = len(findings)
    fails = sum(1 for f in findings if f.get("status") == "FAIL")
    warns = sum(1 for f in findings if f.get("status") == "WARN")

    # Apply display filters
    filtered = filter_findings(findings, min_severity=min_severity, status_filter=status_filter)
    # Sort: FAIL first, then WARN, INFO, PASS; then by severity desc
    filtered.sort(key=lambda f: (
        _STATUS_ORDER.get(f.get("status", "?"), 9),
        -SEVERITY_ORDER.get(f.get("severity", ""), 0),
    ))

    pass_count = sum(1 for f in findings if f.get("status") == "PASS")
    actionable = [f for f in filtered if f.get("status") not in ("PASS",)]

    # Script header line
    icon_txt = ""
    if fails:
        icon_txt = _c("✗ FAIL", _STATUS_STYLE["FAIL"], no_colour)
    elif warns:
        icon_txt = _c("⚠ WARN", _STATUS_STYLE["WARN"], no_colour)
    else:
        icon_txt = _c("✓ PASS", _STATUS_STYLE["PASS"], no_colour)

    header_label = f" {script_name}"
    passes_txt   = _c(f"{pass_count} ✓", _STATUS_STYLE["PASS"], no_colour) if pass_count else ""
    fails_txt    = _c(f"{fails} ✗", _STATUS_STYLE["FAIL"], no_colour)    if fails else ""
    warns_txt    = _c(f"{warns} ⚠", _STATUS_STYLE["WARN"], no_colour)    if warns else ""
    counts       = "  ".join(x for x in [fails_txt, warns_txt, passes_txt] if x)

    sep = _c("─" * W, _DIM, no_colour)
    print(f"\n{sep}")
    script_line = f"{_c('│', _DIM, no_colour)} {icon_txt}  {_BOLD if not no_colour else ''}{header_label}{_RESET if not no_colour else ''}  {_c(f'({host})', _DIM, no_colour)}  {counts}"
    print(script_line)

    if not actionable:
        return total, fails, warns

    # Column widths  (ID | Status | Sev | Name | Detail)
    id_w   = min(12, max((len(f.get("id","")) for f in actionable), default=4))
    st_w   = 4
    sv_w   = 8
    name_w = 28
    # Remaining space for detail (leave 5 for separators)
    detail_w = max(20, W - id_w - st_w - sv_w - name_w - 10)

    # Table header
    def _col(t: str, w: int) -> str:
        return t.ljust(w)[:w]

    bar = _c("│", _DIM, no_colour)
    hdr = (
        f"  {_c(_col('ID',     id_w),   _DIM, no_colour)}  "
        f"{_c(_col('ST',    st_w),   _DIM, no_colour)}  "
        f"{_c(_col('SEV',   sv_w),   _DIM, no_colour)}  "
        f"{_c(_col('Finding Name', name_w), _DIM, no_colour)}  "
        f"{_c('Detail / Remediation', _DIM, no_colour)}"
    )
    print(hdr)
    print(_c("  " + "─" * (W - 2), _DIM, no_colour))

    for f in actionable:
        status  = f.get("status", "?")
        sev     = f.get("severity", "?")
        fid     = f.get("id", "")
        name    = f.get("name", "")
        detail  = f.get("detail", "")
        remedy  = f.get("remediation", "")

        st_code  = _STATUS_STYLE.get(status, "")
        sv_code  = _SEV_STYLE.get(sev, "")
        icon     = _STATUS_ICON.get(status, "?")

        # Primary row
        detail_text = _truncate(detail, detail_w) if detail else ""
        row = (
            f"  {_c(_col(fid, id_w), st_code, no_colour)}  "
            f"{_c(f'{icon} {_col(status, st_w-2)}', st_code, no_colour)}  "
            f"{_c(_col(sev, sv_w), sv_code, no_colour)}  "
            f"{_col(_truncate(name, name_w), name_w)}  "
            f"{_c(detail_text, _DIM, no_colour)}"
        )
        print(row)

        # Remedy row (indented, only for FAIL/WARN)
        if remedy and status in ("FAIL", "WARN"):
            remedy_prefix = "    ↳ Remedy: "
            avail = W - len(remedy_prefix) - 2
            remedy_text = _truncate(remedy, avail)
            print(_c(f"{remedy_prefix}{remedy_text}", "\033[0;36m", no_colour))

        if verbose and f.get("detail") and detail_text != detail:
            # Full detail on overflow
            print(_c(f"    ↳ Full detail: {detail}", _DIM, no_colour))

    return total, fails, warns


def print_script_result(
    result: dict,
    min_severity: str | None,
    status_filter: list[str] | None,
    no_colour: bool,
    verbose: bool = False,
) -> tuple[int, int, int]:
    """Print findings for one script result. Returns (total, fails, warns)."""
    script_name = result.get("script", "unknown")
    host = result.get("host", os.environ.get("COMPUTERNAME", "localhost"))
    if not host or host == "localhost":
        host = current_host()
    findings = result.get("findings", [])

    if result.get("error"):
        W = _term_width()
        print(_c(f"\n{'─' * W}", _DIM, no_colour))
        print(_c(f"  ✗ ERROR  {script_name}: {result['error']}", _STATUS_STYLE['FAIL'], no_colour))
        if verbose and result.get("stderr"):
            print(_c(f"    stderr: {result['stderr']}", _DIM, no_colour))
        return 0, 0, 0

    total, fails, warns = _print_findings_table(
        script_name, host, findings,
        min_severity, status_filter, no_colour, verbose
    )

    fix_report = result.get("fix_report")
    if isinstance(fix_report, dict):
        if fix_report.get("verification_error"):
            print(_c(f"    ⚠ Fix verification failed: {fix_report['verification_error']}", _STATUS_STYLE['WARN'], no_colour))
        else:
            n_fixed     = fix_report.get("fixed_count", 0)
            n_remaining = fix_report.get("remaining_count", 0)
            n_new       = fix_report.get("new_issue_count", 0)

            fixed_badge  = _c(f"✓ {n_fixed} fixed",     "\033[1;32m" if n_fixed     else _DIM, no_colour)
            remain_badge = _c(f"⚠ {n_remaining} remaining", "\033[1;33m" if n_remaining else _DIM, no_colour)
            new_badge    = _c(f"✗ {n_new} new",          "\033[1;31m" if n_new       else _DIM, no_colour)

            label = _c("    ↳ Fix result:", "\033[0;36m", no_colour)
            print(f"{label}  {fixed_badge}   {remain_badge}   {new_badge}")
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


# ── Spinner ────────────────────────────────────────────────────────────────────
_SPINNER_FRAMES = ["⠋", "⠙", "⠸", "⠴", "⠦", "⠇"]
_SPINNER_INTERVAL = 0.1  # seconds between frames


def _run_with_spinner(s: dict, timeout: int, fix_mode: bool, no_colour: bool) -> dict:
    """
    Run a single audit script while displaying an animated spinner on stdout.

    The spinner line is overwritten in-place and replaced with a tick/cross
    summary once the script finishes.
    """
    is_tty = sys.stdout.isatty()
    label = f"  → {s['id']:6s}  {s['name']}"
    done_event = threading.Event()
    result_holder: list[dict] = []
    exc_holder:    list[BaseException] = []

    def _worker() -> None:
        try:
            result_holder.append(
                run_script(s["path"], json_mode=True, timeout=timeout, fix_mode=fix_mode)
            )
        except BaseException as exc:  # pylint: disable=broad-except
            exc_holder.append(exc)
        finally:
            done_event.set()

    worker = threading.Thread(target=_worker, daemon=True)
    worker.start()

    if is_tty and not no_colour:
        spinner = itertools.cycle(_SPINNER_FRAMES)
        while not done_event.is_set():
            frame = next(spinner)
            sys.stdout.write(f"\r\033[0;36m{frame}\033[0m {label} ")
            sys.stdout.flush()
            done_event.wait(_SPINNER_INTERVAL)

        worker.join()

        if exc_holder:
            raise exc_holder[0]

        # Clear the spinner line and print final status
        result = result_holder[0]
        findings = result.get("findings", [])
        has_fail = any(f.get("status") == "FAIL" for f in findings)
        has_warn = any(f.get("status") == "WARN" for f in findings)
        has_err  = bool(result.get("error"))
        if has_err or has_fail:
            icon = "\033[0;31m✗\033[0m"
        elif has_warn:
            icon = "\033[0;33m⚠\033[0m"
        else:
            icon = "\033[0;32m✓\033[0m"
        sys.stdout.write(f"\r{icon} {label}   \n")
        sys.stdout.flush()
    else:
        # Non-TTY / --no-colour: plain static line, no spinner
        print(f"  → {label.strip()} ...", flush=True)
        worker.join()
        if exc_holder:
            raise exc_holder[0]

    return result_holder[0]


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
            result = _run_with_spinner(s, args.timeout, args.fix, args.no_colour)
        else:
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
        # ── Per-script tables ──────────────────────────────────────────────────
        for result in all_results:
            print_script_result(
                result,
                min_severity=args.min_severity,
                status_filter=args.status,
                no_colour=args.no_colour,
                verbose=args.verbose,
            )

        # ── Summary dashboard ──────────────────────────────────────────────────
        W = _term_width()
        nc = args.no_colour
        all_findings_flat = [
            f for r in all_results for f in r.get("findings", [])
        ]
        count_crit = sum(1 for f in all_findings_flat if f.get("severity") == "Critical" and f.get("status") == "FAIL")
        count_high = sum(1 for f in all_findings_flat if f.get("severity") == "High"     and f.get("status") == "FAIL")
        count_med  = sum(1 for f in all_findings_flat if f.get("severity") == "Med"      and f.get("status") in ("FAIL", "WARN"))
        count_warn = sum(1 for f in all_findings_flat if f.get("status") == "WARN")
        count_pass = sum(1 for f in all_findings_flat if f.get("status") == "PASS")
        count_info = sum(1 for f in all_findings_flat if f.get("status") == "INFO")

        dbl = "═" * W
        print(f"\n{_c(dbl, _DIM, nc)}")
        title = "  AUDIT SUMMARY"
        print(f"{_BOLD if not nc else ''}{title}{_RESET if not nc else ''}")
        print(_c("─" * W, _DIM, nc))

        # Stat cards row
        card_w = 12
        cards = [
            ("Scripts",  str(len(all_results)),  "\033[1;37m"),
            ("Findings", str(grand_total),        "\033[1;37m"),
            ("FAIL",     str(grand_fails),         _STATUS_STYLE["FAIL"]),
            ("WARN",     str(grand_warns),         _STATUS_STYLE["WARN"]),
            ("PASS",     str(count_pass),          _STATUS_STYLE["PASS"]),
            ("INFO",     str(count_info),          _STATUS_STYLE["INFO"]),
        ]
        row_nums   = ""
        row_labels = ""
        for label, value, code in cards:
            row_nums   += _c(value.center(card_w), code, nc)
            row_labels += _c(label.center(card_w), _DIM, nc)
        print(f"  {row_nums}")
        print(f"  {row_labels}")

        # Severity breakdown bar (only when there are findings)
        if grand_fails or grand_warns:
            print(_c("─" * W, _DIM, nc))
            sev_items = [
                ("Critical", count_crit, "\033[1;35m"),
                ("High",     count_high, "\033[1;31m"),
                ("Warn",     count_warn, "\033[1;33m"),
                ("Med",      count_med,  "\033[0;33m"),
            ]
            bar_parts = []
            for sev_label, cnt, code in sev_items:
                if cnt:
                    bar_parts.append(_c(f"  {sev_label}: {cnt}", code, nc))
            if bar_parts:
                print("  " + "   ".join(bar_parts))

        # Overall verdict
        print(_c("─" * W, _DIM, nc))
        if grand_fails:
            verdict = _c("  ✗  AUDIT FAILED  — action required", _STATUS_STYLE["FAIL"], nc)
        elif grand_warns:
            verdict = _c("  ⚠  AUDIT PASSED WITH WARNINGS", _STATUS_STYLE["WARN"], nc)
        else:
            verdict = _c("  ✓  AUDIT PASSED  — no failures detected", _STATUS_STYLE["PASS"], nc)
        print(f"{_BOLD if not nc else ''}{verdict}")
        print(_c(dbl, _DIM, nc))

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
