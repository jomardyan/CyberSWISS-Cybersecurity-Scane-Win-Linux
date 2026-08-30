#!/usr/bin/env python3
"""
CyberSWISS – Baseline / Accepted-Risk Waivers
==============================================
Some findings are known, reviewed, and formally accepted (compensating
control in place, legacy application, risk signed off by the business).
Re-reporting them on every run buries genuinely new problems and makes a
CI/CD gate unusable.

A *baseline* is a JSON file listing those accepted findings. When a scan is
run with ``--baseline``, matched findings stay in the report but are marked
``suppressed`` and no longer contribute to the FAIL/WARN counts or the exit
code — so the pipeline only breaks on findings that are genuinely new.

Baseline file format
--------------------
.. code-block:: json

    {
      "cyberswiss_baseline": true,
      "version": 1,
      "created_at": "2026-01-01T00:00:00+00:00",
      "host": "web-prod-01",
      "entries": [
        {
          "id": "L01-C1",
          "script": "L01_password_policy",
          "name": "Password Max Age",
          "severity": "High",
          "status": "FAIL",
          "reason": "Accepted – legacy payroll app cannot rotate",
          "owner": "security@example.com",
          "expires": "2026-12-31"
        }
      ]
    }

``id`` and ``script`` accept shell-style wildcards (``L01-*``, ``W2?_*``), so a
whole script or family of checks can be waived with a single entry.

Entries with an ``expires`` date in the past stop suppressing anything: the
finding reappears and the expired entry is listed in the summary. This keeps
waivers from silently becoming permanent.

Usage
-----
    # Record the current findings as accepted risk
    python runner.py --write-baseline baseline.json

    # Gate CI on new findings only
    python runner.py --baseline baseline.json

    # Inspect a baseline file
    python baseline.py show baseline.json
    python baseline.py apply baseline.json --report reports/audit.json
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

# Ensure common/ is importable when run directly
sys.path.insert(0, str(Path(__file__).resolve().parent))

from utils import now_iso  # noqa: E402

BASELINE_VERSION = 1

#: Statuses that are meaningful to waive.  PASS/INFO findings never break a
#: build, so recording them would only add noise.
WAIVABLE_STATUSES = ("FAIL", "WARN")


# ── Errors ─────────────────────────────────────────────────────────────────────
class BaselineError(Exception):
    """Raised when a baseline file is missing, unreadable, or malformed."""


# ── Date helpers ───────────────────────────────────────────────────────────────
def _parse_expiry(value: object) -> date | None:
    """
    Parse an ``expires`` value into a :class:`datetime.date`.

    Accepts ``YYYY-MM-DD`` and full ISO-8601 timestamps. Returns ``None`` when
    the value is absent or unparseable — an unparseable date is treated as
    "no expiry" rather than silently expiring a waiver.
    """
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        return None


def is_expired(entry: dict[str, Any], today: date | None = None) -> bool:
    """Return ``True`` when *entry* carries an ``expires`` date in the past."""
    expiry = _parse_expiry(entry.get("expires"))
    if expiry is None:
        return False
    reference = today or datetime.now(tz=timezone.utc).date()
    return expiry < reference


# ── Matching ───────────────────────────────────────────────────────────────────
def _matches(pattern: object, value: object) -> bool:
    """Case-insensitive shell-style match; an empty pattern matches anything."""
    if pattern in (None, "", "*"):
        return True
    return fnmatch.fnmatch(str(value or "").lower(), str(pattern).lower())


def entry_matches_finding(entry: dict[str, Any], finding: dict[str, Any], script: str) -> bool:
    """
    Return ``True`` when *entry* waives *finding* (belonging to *script*).

    An entry matches when every field it specifies matches. ``id`` and
    ``script`` support wildcards; ``status`` and ``severity`` must match
    exactly (case-insensitively) when present.
    """
    if not _matches(entry.get("id"), finding.get("id")):
        return False
    if not _matches(entry.get("script"), finding.get("script", script)):
        return False
    for field in ("status", "severity"):
        expected = entry.get(field)
        if expected and str(expected).lower() != str(finding.get(field, "")).lower():
            return False
    return True


# ── Load / save ────────────────────────────────────────────────────────────────
def load_baseline(path: str | Path) -> dict[str, Any]:
    """
    Read and validate a baseline file.

    Raises
    ------
    BaselineError
        When the file is missing, is not valid JSON, or does not contain a
        list of entry objects.
    """
    file_path = Path(path)
    try:
        raw = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BaselineError(f"Cannot read baseline file {file_path}: {exc}") from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BaselineError(f"Baseline file {file_path} is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise BaselineError(f"Baseline file {file_path} must contain a JSON object.")

    entries = data.get("entries", [])
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        raise BaselineError(f"Baseline file {file_path}: 'entries' must be a list of objects.")

    data.setdefault("cyberswiss_baseline", True)
    data.setdefault("version", BASELINE_VERSION)
    data["entries"] = entries
    return data


def save_baseline(baseline: dict[str, Any], path: str | Path) -> None:
    """Write *baseline* to *path*, creating parent directories as needed."""
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(json.dumps(baseline, indent=2, default=str) + "\n", encoding="utf-8")


def build_baseline(
    report: dict[str, Any],
    reason: str = "Accepted risk – recorded from baseline scan",
    expires: str | None = None,
    statuses: tuple[str, ...] = WAIVABLE_STATUSES,
) -> dict[str, Any]:
    """
    Build a baseline from the FAIL/WARN findings of a consolidated *report*.

    Parameters
    ----------
    report:
        Consolidated report as produced by ``runner.py``.
    reason:
        Text stored on every generated entry; edit the file afterwards to
        record the real per-finding justification.
    expires:
        Optional ``YYYY-MM-DD`` expiry applied to every entry.
    statuses:
        Finding statuses to record. Defaults to FAIL and WARN.
    """
    wanted = {s.upper() for s in statuses}
    entries: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for result in report.get("results", []):
        script = result.get("script", "unknown")
        for finding in result.get("findings", []):
            if str(finding.get("status", "")).upper() not in wanted:
                continue
            finding_id = str(finding.get("id", ""))
            if not finding_id:
                continue
            key = (script, finding_id)
            if key in seen:
                continue
            seen.add(key)
            entry: dict[str, Any] = {
                "id": finding_id,
                "script": finding.get("script", script),
                "name": finding.get("name", ""),
                "severity": finding.get("severity", ""),
                "status": finding.get("status", ""),
                "reason": reason,
            }
            if expires:
                entry["expires"] = expires
            entries.append(entry)

    return {
        "cyberswiss_baseline": True,
        "version": BASELINE_VERSION,
        "created_at": now_iso(),
        "host": report.get("host", "unknown"),
        "entries": entries,
    }


# ── Application ────────────────────────────────────────────────────────────────
def apply_baseline(
    report: dict[str, Any],
    baseline: dict[str, Any],
    today: date | None = None,
) -> dict[str, Any]:
    """
    Mark findings waived by *baseline* and recompute the report's counts.

    Matched findings keep their original ``status`` and ``severity`` but gain
    ``suppressed: true`` plus ``suppression_reason`` / ``suppressed_by``, so
    reports can still show them as accepted risk. ``fail_count`` and
    ``warn_count`` are recomputed excluding suppressed findings — that is what
    drives the exit code and the CI gate.

    The *report* is modified in place. The returned summary is also stored on
    the report under the ``baseline`` key.
    """
    reference = today or datetime.now(tz=timezone.utc).date()
    entries = baseline.get("entries", [])

    active: list[dict[str, Any]] = []
    expired: list[dict[str, Any]] = []
    for entry in entries:
        (expired if is_expired(entry, reference) else active).append(entry)

    used: set[int] = set()
    suppressed: list[dict[str, Any]] = []

    for result in report.get("results", []):
        script = result.get("script", "unknown")
        for finding in result.get("findings", []):
            if str(finding.get("status", "")).upper() not in {"FAIL", "WARN"}:
                continue
            for index, entry in enumerate(active):
                if not entry_matches_finding(entry, finding, script):
                    continue
                used.add(index)
                finding["suppressed"] = True
                finding["suppression_reason"] = entry.get("reason", "Accepted risk")
                finding["suppressed_by"] = entry.get("id", "*")
                suppressed.append(
                    {
                        "id": finding.get("id", ""),
                        "script": finding.get("script", script),
                        "name": finding.get("name", ""),
                        "status": finding.get("status", ""),
                        "severity": finding.get("severity", ""),
                        "reason": entry.get("reason", "Accepted risk"),
                        "expires": entry.get("expires", ""),
                    }
                )
                break

    all_findings = [f for r in report.get("results", []) for f in r.get("findings", [])]
    live = [f for f in all_findings if not f.get("suppressed")]
    report["fail_count"] = sum(1 for f in live if f.get("status") == "FAIL")
    report["warn_count"] = sum(1 for f in live if f.get("status") == "WARN")
    report["suppressed_count"] = len(suppressed)

    summary = {
        "applied": True,
        "entry_count": len(entries),
        "suppressed_count": len(suppressed),
        "suppressed": suppressed,
        "expired_entries": expired,
        "unused_entries": [e for i, e in enumerate(active) if i not in used],
        "baseline_host": baseline.get("host", ""),
        "baseline_created_at": baseline.get("created_at", ""),
    }
    report["baseline"] = summary
    return summary


def format_baseline_summary(summary: dict[str, Any], no_colour: bool = False) -> str:
    """Render a short human-readable summary of an applied baseline."""
    dim = "" if no_colour else "\033[2m"
    yellow = "" if no_colour else "\033[1;33m"
    cyan = "" if no_colour else "\033[1;36m"
    reset = "" if no_colour else "\033[0m"

    lines = [f"{cyan}Baseline:{reset} {summary.get('suppressed_count', 0)} finding(s) suppressed "
             f"of {summary.get('entry_count', 0)} waiver(s)."]

    expired = summary.get("expired_entries", [])
    if expired:
        lines.append(f"{yellow}  ⚠ {len(expired)} waiver(s) expired – findings are reported again:{reset}")
        for entry in expired[:10]:
            lines.append(f"      {entry.get('id', '*')} (expired {entry.get('expires', '?')})")
        if len(expired) > 10:
            lines.append(f"      … and {len(expired) - 10} more")

    unused = summary.get("unused_entries", [])
    if unused:
        lines.append(f"{dim}  {len(unused)} waiver(s) matched nothing – candidates for removal.{reset}")

    return "\n".join(lines)


# ── CLI ────────────────────────────────────────────────────────────────────────
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="baseline.py",
        description="CyberSWISS baseline / accepted-risk waiver management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_create = sub.add_parser("create", help="Create a baseline from a consolidated JSON report")
    p_create.add_argument("report", metavar="REPORT_JSON", help="Consolidated report produced by runner.py")
    p_create.add_argument("--output", "-o", required=True, metavar="FILE", help="Baseline file to write")
    p_create.add_argument("--reason", default="Accepted risk – recorded from baseline scan")
    p_create.add_argument("--expires", default=None, metavar="YYYY-MM-DD", help="Expiry date for every entry")

    p_show = sub.add_parser("show", help="Summarise the contents of a baseline file")
    p_show.add_argument("baseline", metavar="BASELINE_JSON")

    p_apply = sub.add_parser("apply", help="Apply a baseline to a report and print the filtered result")
    p_apply.add_argument("baseline", metavar="BASELINE_JSON")
    p_apply.add_argument("--report", required=True, metavar="REPORT_JSON")
    p_apply.add_argument("--output", "-o", default=None, metavar="FILE", help="Write the annotated report to FILE")

    return parser.parse_args(argv)


def _load_report(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        if args.command == "create":
            report = _load_report(args.report)
            baseline = build_baseline(report, reason=args.reason, expires=args.expires)
            save_baseline(baseline, args.output)
            print(f"Baseline written to {args.output} ({len(baseline['entries'])} entries).")
            return 0

        if args.command == "show":
            baseline = load_baseline(args.baseline)
            entries = baseline["entries"]
            expired = [e for e in entries if is_expired(e)]
            print(f"Baseline   : {args.baseline}")
            print(f"Host       : {baseline.get('host', 'unknown')}")
            print(f"Created    : {baseline.get('created_at', 'unknown')}")
            print(f"Entries    : {len(entries)} ({len(expired)} expired)")
            for entry in entries:
                marker = "EXPIRED" if is_expired(entry) else "active "
                print(f"  [{marker}] {entry.get('id', '*'):<14} {entry.get('script', '*'):<28} "
                      f"{entry.get('reason', '')}")
            return 0

        if args.command == "apply":
            report = _load_report(args.report)
            baseline = load_baseline(args.baseline)
            summary = apply_baseline(report, baseline)
            print(format_baseline_summary(summary, no_colour=True), file=sys.stderr)
            if args.output:
                save_baseline(report, args.output)
                print(f"Annotated report written to {args.output}", file=sys.stderr)
            else:
                print(json.dumps(report, indent=2, default=str))
            return 2 if report.get("fail_count") else 1 if report.get("warn_count") else 0

    except (BaselineError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    return 1


if __name__ == "__main__":
    sys.exit(main())
