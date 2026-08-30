#!/usr/bin/env python3
"""
CyberSWISS – Scan History Database & Drift Detection
=====================================================
SQLite-backed persistence layer for storing audit scan results and detecting
changes between runs (drift detection). Useful for CI/CD pipelines to track
new vulnerabilities or changes in the security posture over time.

Usage (from runner.py)
----------------------
    from db import ScanDatabase
    db = ScanDatabase()
    db.save_scan(consolidated_report)
    drift = db.detect_drift(consolidated_report)
"""
from __future__ import annotations

import json
import logging
import sqlite3
import sys
from pathlib import Path
from typing import Any

# Ensure common/ is importable when run directly
sys.path.insert(0, str(Path(__file__).resolve().parent))

from utils import now_iso, REPO_ROOT  # noqa: E402

logger = logging.getLogger(__name__)

# Default database location relative to repo root
_DEFAULT_DB_PATH = REPO_ROOT / "reports" / "cyberswiss.db"


# ── Schema ─────────────────────────────────────────────────────────────────────
_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY,
    host            TEXT,
    timestamp       TEXT,
    scripts_run     INTEGER,
    fail_count      INTEGER,
    warn_count      INTEGER,
    total_findings  INTEGER,
    json_data       TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY,
    scan_id     INTEGER,
    script      TEXT,
    finding_id  TEXT,
    name        TEXT,
    severity    TEXT,
    status      TEXT,
    detail      TEXT,
    remediation TEXT,
    timestamp   TEXT,
    FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS scan_tags (
    id      INTEGER PRIMARY KEY,
    scan_id INTEGER,
    tag     TEXT
);
"""


# ── ScanDatabase ───────────────────────────────────────────────────────────────
class ScanDatabase:
    """SQLite-backed store for CyberSWISS scan results and drift detection."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        """
        Initialise the database at *db_path*.

        Parameters
        ----------
        db_path:
            Path to the SQLite file.  Defaults to
            ``<repo_root>/reports/cyberswiss.db``.
        """
        resolved = Path(db_path) if db_path else _DEFAULT_DB_PATH
        resolved.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = resolved
        self._init_schema()

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _connect(self) -> sqlite3.Connection:
        """Return a new SQLite connection with row_factory set."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_schema(self) -> None:
        """Create tables if they do not already exist."""
        try:
            with self._connect() as conn:
                conn.executescript(_SCHEMA)
        except sqlite3.Error as exc:
            print(f"[db] Schema init error: {exc}", file=sys.stderr)
            logger.error("Schema init error: %s", exc)

    def _extract_findings(self, report: dict) -> list[dict[str, Any]]:
        """Flatten all findings from a consolidated report dict."""
        findings: list[dict[str, Any]] = []
        timestamp = report.get("generated_at", report.get("timestamp", now_iso()))
        for result in report.get("results", []):
            script_name = result.get("script", "unknown")
            for f in result.get("findings", []):
                findings.append(
                    {
                        "script": f.get("script", script_name),
                        "finding_id": f.get("id", ""),
                        "name": f.get("name", ""),
                        "severity": f.get("severity", ""),
                        "status": f.get("status", ""),
                        "detail": f.get("detail", ""),
                        "remediation": f.get("remediation", ""),
                        "timestamp": timestamp,
                    }
                )
        return findings

    # ── Public API ─────────────────────────────────────────────────────────────

    def save_scan(self, report: dict) -> int:
        """
        Persist a consolidated scan report.

        Parameters
        ----------
        report:
            Consolidated report dict as produced by ``runner.py`` or
            ``report_generator.py``.

        Returns
        -------
        int
            The newly created scan row ID, or ``-1`` on error.
        """
        try:
            host = report.get("host", "unknown")
            timestamp = report.get("generated_at", report.get("timestamp", now_iso()))
            scripts_run = report.get("scripts_run", 0)
            fail_count = report.get("fail_count", 0)
            warn_count = report.get("warn_count", 0)
            total_findings = report.get("total_findings", 0)
            json_data = json.dumps(report, default=str)

            findings = self._extract_findings(report)

            with self._connect() as conn:
                cur = conn.execute(
                    """
                    INSERT INTO scans
                        (host, timestamp, scripts_run, fail_count, warn_count,
                         total_findings, json_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (host, timestamp, scripts_run, fail_count, warn_count,
                     total_findings, json_data),
                )
                scan_id: int = cur.lastrowid  # type: ignore[assignment]

                conn.executemany(
                    """
                    INSERT INTO findings
                        (scan_id, script, finding_id, name, severity, status,
                         detail, remediation, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            scan_id,
                            f["script"],
                            f["finding_id"],
                            f["name"],
                            f["severity"],
                            f["status"],
                            f["detail"],
                            f["remediation"],
                            f["timestamp"],
                        )
                        for f in findings
                    ],
                )

            logger.info("Saved scan id=%d host=%s findings=%d", scan_id, host, len(findings))
            return scan_id

        except sqlite3.Error as exc:
            print(f"[db] save_scan error: {exc}", file=sys.stderr)
            logger.error("save_scan error: %s", exc)
            return -1

    def get_last_scan(self, host: str | None = None) -> dict | None:
        """
        Return the most recent scan row, including its parsed findings.

        Parameters
        ----------
        host:
            Restrict lookup to a specific hostname.  ``None`` returns the
            most recent scan regardless of host.
        """
        try:
            with self._connect() as conn:
                if host:
                    row = conn.execute(
                        "SELECT * FROM scans WHERE host = ? ORDER BY id DESC LIMIT 1",
                        (host,),
                    ).fetchone()
                else:
                    row = conn.execute(
                        "SELECT * FROM scans ORDER BY id DESC LIMIT 1"
                    ).fetchone()

                if row is None:
                    return None

                scan = dict(row)
                scan["findings"] = [
                    dict(r)
                    for r in conn.execute(
                        "SELECT * FROM findings WHERE scan_id = ?", (scan["id"],)
                    ).fetchall()
                ]
                return scan

        except sqlite3.Error as exc:
            print(f"[db] get_last_scan error: {exc}", file=sys.stderr)
            logger.error("get_last_scan error: %s", exc)
            return None

    def get_previous_scan(self, scan_id: int, host: str | None = None) -> dict | None:
        """Return the most recent scan older than *scan_id*."""
        try:
            with self._connect() as conn:
                if host:
                    row = conn.execute(
                        """
                        SELECT * FROM scans
                        WHERE host = ? AND id < ?
                        ORDER BY id DESC
                        LIMIT 1
                        """,
                        (host, scan_id),
                    ).fetchone()
                else:
                    row = conn.execute(
                        """
                        SELECT * FROM scans
                        WHERE id < ?
                        ORDER BY id DESC
                        LIMIT 1
                        """,
                        (scan_id,),
                    ).fetchone()

                if row is None:
                    return None

                previous_scan = dict(row)
                previous_scan["findings"] = [
                    dict(r)
                    for r in conn.execute(
                        "SELECT * FROM findings WHERE scan_id = ?", (previous_scan["id"],)
                    ).fetchall()
                ]
                return previous_scan
        except sqlite3.Error as exc:
            print(f"[db] get_previous_scan error: {exc}", file=sys.stderr)
            logger.error("get_previous_scan error: %s", exc)
            return None

    def detect_drift(
        self,
        current_report: dict,
        baseline_scan_id: int | None = None,
        current_scan_id: int | None = None,
    ) -> dict:
        """
        Compare *current_report* against the most recent saved scan (or a
        specific scan identified by *baseline_scan_id*).

        If *current_scan_id* is provided, the comparison baseline becomes the
        immediately preceding saved scan for the same host instead of the most
        recent scan overall. This avoids comparing a stored scan to itself.

        Returns a dict with:

        ``has_drift`` – ``True`` if any changes were detected.
        ``new_findings`` – findings present in current but absent in baseline.
        ``resolved_findings`` – findings in baseline absent in current.
        ``changed_findings`` – findings with the same ``id`` but different
            ``status`` or ``severity``.
        ``baseline_scan_id`` – the scan used for comparison (or ``None``).
        ``current_timestamp`` – ISO timestamp of *current_report*.
        """
        current_timestamp = current_report.get(
            "generated_at", current_report.get("timestamp", now_iso())
        )
        empty: dict[str, Any] = {
            "has_drift": False,
            "new_findings": [],
            "resolved_findings": [],
            "changed_findings": [],
            "baseline_scan_id": None,
            "current_timestamp": current_timestamp,
        }

        try:
            if baseline_scan_id is not None:
                baseline = self.get_scan(baseline_scan_id)
            elif current_scan_id is not None:
                host = current_report.get("host")
                baseline = self.get_previous_scan(current_scan_id, host)
            else:
                host = current_report.get("host")
                baseline = self.get_last_scan(host)

            if baseline is None:
                return empty

            baseline_findings: dict[str, dict] = {
                f["finding_id"]: f
                for f in baseline.get("findings", [])
                if f.get("finding_id")
            }
            current_findings: dict[str, dict] = {
                f.get("id", ""): f
                for result in current_report.get("results", [])
                for f in result.get("findings", [])
                if f.get("id")
            }

            new_findings = [
                current_findings[fid]
                for fid in current_findings
                if fid not in baseline_findings
            ]
            resolved_findings = [
                baseline_findings[fid]
                for fid in baseline_findings
                if fid not in current_findings
            ]
            changed_findings: list[dict] = []
            for fid, curr in current_findings.items():
                if fid in baseline_findings:
                    base = baseline_findings[fid]
                    if (
                        curr.get("status") != base.get("status")
                        or curr.get("severity") != base.get("severity")
                    ):
                        changed_findings.append(
                            {
                                "finding_id": fid,
                                "name": curr.get("name", ""),
                                "baseline_status": base.get("status"),
                                "current_status": curr.get("status"),
                                "baseline_severity": base.get("severity"),
                                "current_severity": curr.get("severity"),
                            }
                        )

            has_drift = bool(new_findings or resolved_findings or changed_findings)
            return {
                "has_drift": has_drift,
                "new_findings": new_findings,
                "resolved_findings": resolved_findings,
                "changed_findings": changed_findings,
                "baseline_scan_id": baseline["id"],
                "current_timestamp": current_timestamp,
            }

        except sqlite3.Error as exc:
            print(f"[db] detect_drift error: {exc}", file=sys.stderr)
            logger.error("detect_drift error: %s", exc)
            return empty

    def list_scans(
        self, limit: int = 20, host: str | None = None
    ) -> list[dict]:
        """
        Return a list of scan summaries (without full findings), most recent
        first.

        Parameters
        ----------
        limit:
            Maximum number of rows to return.
        host:
            Restrict to a specific hostname.
        """
        try:
            with self._connect() as conn:
                if host:
                    rows = conn.execute(
                        """
                        SELECT id, host, timestamp, scripts_run, fail_count,
                               warn_count, total_findings
                        FROM scans
                        WHERE host = ?
                        ORDER BY id DESC
                        LIMIT ?
                        """,
                        (host, limit),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        """
                        SELECT id, host, timestamp, scripts_run, fail_count,
                               warn_count, total_findings
                        FROM scans
                        ORDER BY id DESC
                        LIMIT ?
                        """,
                        (limit,),
                    ).fetchall()
                return [dict(r) for r in rows]
        except sqlite3.Error as exc:
            print(f"[db] list_scans error: {exc}", file=sys.stderr)
            logger.error("list_scans error: %s", exc)
            return []

    def get_scan(self, scan_id: int) -> dict | None:
        """
        Return full scan data (including findings) for a specific *scan_id*.
        """
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM scans WHERE id = ?", (scan_id,)
                ).fetchone()
                if row is None:
                    return None
                scan = dict(row)
                scan["findings"] = [
                    dict(r)
                    for r in conn.execute(
                        "SELECT * FROM findings WHERE scan_id = ?", (scan_id,)
                    ).fetchall()
                ]
                return scan
        except sqlite3.Error as exc:
            print(f"[db] get_scan error: {exc}", file=sys.stderr)
            logger.error("get_scan error: %s", exc)
            return None

    def delete_old_scans(
        self, keep_last: int = 50, host: str | None = None
    ) -> int:
        """
        Delete scans older than the *keep_last* most recent ones.

        Parameters
        ----------
        keep_last:
            Number of most-recent scans to retain.
        host:
            If supplied, only consider scans for this host.

        Returns
        -------
        int
            Number of scans deleted.
        """
        try:
            with self._connect() as conn:
                if host:
                    ids_to_keep = conn.execute(
                        """
                        SELECT id FROM scans WHERE host = ?
                        ORDER BY id DESC LIMIT ?
                        """,
                        (host, keep_last),
                    ).fetchall()
                else:
                    ids_to_keep = conn.execute(
                        "SELECT id FROM scans ORDER BY id DESC LIMIT ?",
                        (keep_last,),
                    ).fetchall()

                keep_set = {r["id"] for r in ids_to_keep}
                if not keep_set:
                    return 0

                if host:
                    # .format() here only generates the correct number of '?' placeholders;
                    # all actual values are parameterized to prevent SQL injection.
                    to_delete = conn.execute(
                        "SELECT id FROM scans WHERE host = ? AND id NOT IN ({})".format(
                            ",".join("?" * len(keep_set))
                        ),
                        (host, *keep_set),
                    ).fetchall()
                else:
                    # Same: .format() is used solely for placeholder count, not for value injection.
                    to_delete = conn.execute(
                        "SELECT id FROM scans WHERE id NOT IN ({})".format(
                            ",".join("?" * len(keep_set))
                        ),
                        tuple(keep_set),
                    ).fetchall()

                delete_ids = [r["id"] for r in to_delete]
                if not delete_ids:
                    return 0

                # '?' placeholder list built from integer DB IDs; values are parameterized.
                placeholder = ",".join("?" * len(delete_ids))
                conn.execute(
                    f"DELETE FROM findings WHERE scan_id IN ({placeholder})",
                    delete_ids,
                )
                conn.execute(
                    f"DELETE FROM scan_tags WHERE scan_id IN ({placeholder})",
                    delete_ids,
                )
                conn.execute(
                    f"DELETE FROM scans WHERE id IN ({placeholder})",
                    delete_ids,
                )
                return len(delete_ids)

        except sqlite3.Error as exc:
            print(f"[db] delete_old_scans error: {exc}", file=sys.stderr)
            logger.error("delete_old_scans error: %s", exc)
            return 0

    def delete_scan(self, scan_id: int) -> bool:
        """Delete a scan and its related findings/tags."""
        try:
            with self._connect() as conn:
                conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
                conn.execute("DELETE FROM scan_tags WHERE scan_id = ?", (scan_id,))
                deleted = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
                return deleted.rowcount > 0
        except sqlite3.Error as exc:
            print(f"[db] delete_scan error: {exc}", file=sys.stderr)
            logger.error("delete_scan error: %s", exc)
            return False

    # ── Trend analytics ────────────────────────────────────────────────────────

    def get_trend(self, limit: int = 10, host: str | None = None) -> dict:
        """
        Return a chronological posture trend across the most recent scans.

        Drift answers "what changed since last time?"; a trend answers "are we
        getting better or worse?" — the question a security programme is
        actually judged on.

        Parameters
        ----------
        limit:
            Number of recent scans to include (oldest → newest in the output).
        host:
            Restrict the trend to a single hostname.

        Returns
        -------
        dict
            ``points``
                One entry per scan, oldest first, each with ``scan_id``,
                ``timestamp``, ``fail_count``, ``warn_count``,
                ``total_findings``, ``scripts_run``, and per-severity FAIL
                counts under ``severity``.
            ``delta``
                Change in FAIL/WARN counts between the first and last point.
            ``direction``
                ``improving``, ``degrading``, ``stable``, or ``unknown``
                (fewer than two scans).
            ``worst_scripts``
                Scripts with the most FAIL findings in the latest scan.
        """
        empty: dict[str, Any] = {
            "points": [],
            "delta": {"fail_count": 0, "warn_count": 0, "total_findings": 0},
            "direction": "unknown",
            "scan_count": 0,
            "host": host,
            "worst_scripts": [],
        }
        if limit < 1:
            return empty

        try:
            with self._connect() as conn:
                params: list[Any] = []
                where = ""
                if host:
                    where = "WHERE host = ?"
                    params.append(host)
                params.append(limit)
                rows = conn.execute(
                    f"""
                    SELECT id, host, timestamp, scripts_run, fail_count,
                           warn_count, total_findings
                    FROM scans
                    {where}
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    params,
                ).fetchall()

                if not rows:
                    return empty

                points: list[dict[str, Any]] = []
                for row in reversed(rows):  # oldest → newest
                    point = dict(row)
                    severity_rows = conn.execute(
                        """
                        SELECT severity, COUNT(*) AS count
                        FROM findings
                        WHERE scan_id = ? AND status = 'FAIL'
                        GROUP BY severity
                        """,
                        (point["id"],),
                    ).fetchall()
                    point["scan_id"] = point.pop("id")
                    point["severity"] = {r["severity"]: r["count"] for r in severity_rows}
                    points.append(point)

                latest_id = points[-1]["scan_id"]
                worst_rows = conn.execute(
                    """
                    SELECT script, COUNT(*) AS fail_count
                    FROM findings
                    WHERE scan_id = ? AND status = 'FAIL'
                    GROUP BY script
                    ORDER BY fail_count DESC, script ASC
                    LIMIT 5
                    """,
                    (latest_id,),
                ).fetchall()

            first, last = points[0], points[-1]
            delta = {
                "fail_count": last["fail_count"] - first["fail_count"],
                "warn_count": last["warn_count"] - first["warn_count"],
                "total_findings": last["total_findings"] - first["total_findings"],
            }

            if len(points) < 2:
                direction = "unknown"
            elif delta["fail_count"] < 0 or (delta["fail_count"] == 0 and delta["warn_count"] < 0):
                direction = "improving"
            elif delta["fail_count"] > 0 or delta["warn_count"] > 0:
                direction = "degrading"
            else:
                direction = "stable"

            return {
                "points": points,
                "delta": delta,
                "direction": direction,
                "scan_count": len(points),
                "host": host,
                "worst_scripts": [dict(r) for r in worst_rows],
            }

        except sqlite3.Error as exc:
            print(f"[db] get_trend error: {exc}", file=sys.stderr)
            logger.error("get_trend error: %s", exc)
            return empty


# ── Drift Report Formatting ────────────────────────────────────────────────────

# ANSI colour codes (same palette as utils.py)
_GREEN = "\033[0;32m"
_RED = "\033[0;31m"
_YELLOW = "\033[0;33m"
_CYAN = "\033[0;36m"
_RESET = "\033[0m"


def format_drift_report(drift: dict, no_colour: bool = False) -> str:
    """
    Format the dict returned by :meth:`ScanDatabase.detect_drift` into a
    human-readable string.

    Parameters
    ----------
    drift:
        Dict as returned by ``ScanDatabase.detect_drift()``.
    no_colour:
        When ``True`` ANSI escape codes are omitted.

    Returns
    -------
    str
        Multi-line formatted drift summary.
    """

    def _c(text: str, code: str) -> str:
        return text if no_colour else f"{code}{text}{_RESET}"

    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("  DRIFT DETECTION REPORT")
    lines.append("=" * 60)
    lines.append(f"  Timestamp  : {drift.get('current_timestamp', '')}")
    lines.append(f"  Baseline   : scan #{drift.get('baseline_scan_id', 'N/A')}")

    if not drift.get("has_drift"):
        lines.append(_c("\n  ✔  No drift detected – security posture unchanged.", _GREEN))
        lines.append("=" * 60)
        return "\n".join(lines)

    new_f = drift.get("new_findings", [])
    resolved_f = drift.get("resolved_findings", [])
    changed_f = drift.get("changed_findings", [])

    lines.append("")

    # ── New findings ──
    if new_f:
        lines.append(_c(f"  ▲  NEW FINDINGS ({len(new_f)})", _RED))
        for f in new_f:
            fid = f.get("id", f.get("finding_id", "?"))
            name = f.get("name", "")
            sev = f.get("severity", "")
            status = f.get("status", "")
            lines.append(f"     [{status}] [{sev}] {fid}: {name}")

    # ── Resolved findings ──
    if resolved_f:
        lines.append(_c(f"\n  ✔  RESOLVED FINDINGS ({len(resolved_f)})", _GREEN))
        for f in resolved_f:
            fid = f.get("finding_id", "?")
            name = f.get("name", "")
            sev = f.get("severity", "")
            status = f.get("status", "")
            lines.append(f"     [{status}] [{sev}] {fid}: {name}")

    # ── Changed findings ──
    if changed_f:
        lines.append(_c(f"\n  ↔  CHANGED FINDINGS ({len(changed_f)})", _YELLOW))
        for f in changed_f:
            fid = f.get("finding_id", "?")
            name = f.get("name", "")
            b_st = f.get("baseline_status", "?")
            c_st = f.get("current_status", "?")
            b_sv = f.get("baseline_severity", "?")
            c_sv = f.get("current_severity", "?")
            lines.append(
                f"     {fid}: {name}  "
                f"status {b_st}→{c_st}  severity {b_sv}→{c_sv}"
            )

    lines.append("\n" + "=" * 60)
    return "\n".join(lines)


# ── Trend Report Formatting ────────────────────────────────────────────────────
_SPARK_LEVELS = "▁▂▃▄▅▆▇█"


def _sparkline(values: list[int]) -> str:
    """Render a list of counts as a compact unicode sparkline."""
    if not values:
        return ""
    peak = max(values)
    if peak == 0:
        return _SPARK_LEVELS[0] * len(values)
    step = len(_SPARK_LEVELS) - 1
    return "".join(_SPARK_LEVELS[round(v / peak * step)] for v in values)


def format_trend_report(trend: dict, no_colour: bool = False) -> str:
    """
    Format the dict returned by :meth:`ScanDatabase.get_trend` for a terminal.

    Parameters
    ----------
    trend:
        Dict as returned by ``ScanDatabase.get_trend()``.
    no_colour:
        When ``True`` ANSI escape codes are omitted.
    """

    def _c(text: str, code: str) -> str:
        return text if no_colour else f"{code}{text}{_RESET}"

    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("  POSTURE TREND REPORT")
    lines.append("=" * 60)

    points = trend.get("points", [])
    if not points:
        lines.append("  No scan history available – run with --save-db first.")
        lines.append("=" * 60)
        return "\n".join(lines)

    host = trend.get("host") or points[-1].get("host", "all hosts")
    lines.append(f"  Host       : {host}")
    lines.append(f"  Scans      : {len(points)}")
    lines.append("")
    lines.append("  Scan    Timestamp                        FAIL  WARN  Total")
    lines.append("  " + "-" * 56)
    for point in points:
        lines.append(
            f"  #{str(point.get('scan_id', '?')):<6} {str(point.get('timestamp', ''))[:30]:<32} "
            f"{point.get('fail_count', 0):>4}  {point.get('warn_count', 0):>4}  "
            f"{point.get('total_findings', 0):>5}"
        )

    fail_series = [int(p.get("fail_count", 0)) for p in points]
    warn_series = [int(p.get("warn_count", 0)) for p in points]
    lines.append("")
    lines.append(f"  FAIL trend : {_sparkline(fail_series)}  (oldest → newest)")
    lines.append(f"  WARN trend : {_sparkline(warn_series)}")

    delta = trend.get("delta", {})
    direction = trend.get("direction", "unknown")
    fail_delta = delta.get("fail_count", 0)
    warn_delta = delta.get("warn_count", 0)
    arrow = {"improving": "▼", "degrading": "▲", "stable": "=", "unknown": "?"}.get(direction, "?")
    colour = {"improving": _GREEN, "degrading": _RED}.get(direction, _YELLOW)
    lines.append("")
    lines.append(
        _c(
            f"  {arrow}  Posture is {direction.upper()}: "
            f"FAIL {fail_delta:+d}, WARN {warn_delta:+d} across the window.",
            colour,
        )
    )

    worst = trend.get("worst_scripts", [])
    if worst:
        lines.append("")
        lines.append(_c("  Top failing scripts (latest scan):", _CYAN))
        for entry in worst:
            lines.append(f"     {entry.get('fail_count', 0):>3} FAIL  {entry.get('script', '?')}")

    lines.append("=" * 60)
    return "\n".join(lines)
