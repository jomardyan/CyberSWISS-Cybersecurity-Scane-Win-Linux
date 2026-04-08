#!/usr/bin/env python3
"""
CyberSWISS – REST API Server
=============================
Lightweight REST API built on Python's built-in http.server.
Provides programmatic access to scan management, history, and reporting.

Endpoints
---------
    GET  /api/v1/health           – Health check and version info
    GET  /api/v1/scripts          – List available audit scripts
    POST /api/v1/scan             – Start a scan (async, returns job_id)
    GET  /api/v1/scan/{id}        – Get scan status and results
    GET  /api/v1/history          – List past scans
    GET  /api/v1/report/{id}      – Get HTML report for a scan
    GET  /api/v1/drift/{id}       – Get drift report vs previous scan
    DELETE /api/v1/scan/{id}      – Delete a scan from history

Usage
-----
    python api.py                    # Start on 0.0.0.0:8080
    python api.py --port 9090        # Custom port
    python api.py --host 127.0.0.1   # Localhost only (recommended)

Security Note: This API is for internal/trusted networks only.
               No authentication is built in by design; use network
               controls or a reverse proxy with auth for production.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# Ensure common/ is importable when run directly
sys.path.insert(0, str(Path(__file__).resolve().parent))

from db import ScanDatabase  # noqa: E402
from report_generator import generate_html  # noqa: E402
from utils import current_host, discover_scripts, now_iso, run_script  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
)
logger = logging.getLogger("cyberswiss.api")

# ── Constants ──────────────────────────────────────────────────────────────────
VERSION = "1.0.0"
API_PREFIX = "/api/v1"

# In-memory job registry: job_id → job dict
# Each job dict holds: status, job_id, started_at, finished_at,
#                      scripts_total, scripts_done, results, error
_jobs: dict[str, dict[str, Any]] = {}
_jobs_lock = threading.Lock()


def validate_scan_request(body: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    """Validate and normalise the POST /scan request body."""
    os_filter = body.get("os")
    if os_filter is not None:
        if not isinstance(os_filter, str) or os_filter not in {"linux", "windows", "both"}:
            return None, "Field 'os' must be one of: linux, windows, both."
        if os_filter == "both":
            os_filter = None

    fix_mode = body.get("fix", False)
    if not isinstance(fix_mode, bool):
        return None, "Field 'fix' must be a boolean."

    timeout = body.get("timeout", 300)
    if isinstance(timeout, bool):
        return None, "Field 'timeout' must be an integer."
    try:
        timeout = int(timeout)
    except (TypeError, ValueError):
        return None, "Field 'timeout' must be an integer."
    if timeout < 1 or timeout > 3600:
        return None, "Field 'timeout' must be between 1 and 3600 seconds."

    script_ids = body.get("scripts")
    if script_ids is not None:
        if not isinstance(script_ids, list) or not all(isinstance(item, str) and item.strip() for item in script_ids):
            return None, "Field 'scripts' must be a list of non-empty script IDs."
        script_ids = sorted({item.strip().upper() for item in script_ids})
        available_ids = {script["id"].upper() for script in discover_scripts(os_filter=os_filter)}
        unknown_ids = sorted(set(script_ids) - available_ids)
        if unknown_ids:
            return None, f"Unknown script IDs: {', '.join(unknown_ids)}"

    return {
        "os_filter": os_filter,
        "script_ids": script_ids,
        "fix_mode": fix_mode,
        "timeout": timeout,
    }, None


# ── Background Scan Execution ──────────────────────────────────────────────────

def _run_scan_job(
    job_id: str,
    os_filter: str | None,
    script_ids: list[str] | None,
    fix_mode: bool,
    timeout: int,
    db: ScanDatabase,
) -> None:
    """
    Execute the requested audit scripts in a background thread, update the
    in-memory job entry, and persist the consolidated report to the database.
    """
    try:
        # Discover scripts matching the requested OS / IDs
        scripts = discover_scripts(os_filter=os_filter)
        if script_ids:
            upper_ids = {sid.upper() for sid in script_ids}
            scripts = [s for s in scripts if s["id"].upper() in upper_ids]

        with _jobs_lock:
            _jobs[job_id]["scripts_total"] = len(scripts)
            _jobs[job_id]["status"] = "running"

        results: list[dict] = []
        for script in scripts:
            result = run_script(
                script["path"],
                json_mode=True,
                timeout=timeout,
                fix_mode=fix_mode,
            )
            result.setdefault("script_meta", {"id": script["id"], "os": script["os"]})
            results.append(result)

            with _jobs_lock:
                _jobs[job_id]["scripts_done"] += 1

        # Build a consolidated report dict (same structure as runner.py)
        all_findings = [f for r in results for f in r.get("findings", [])]
        consolidated: dict[str, Any] = {
            "cyberswiss_report": True,
            "generated_at": now_iso(),
            "host": current_host(),
            "scripts_run": len(results),
            "total_findings": len(all_findings),
            "fail_count": sum(1 for f in all_findings if f.get("status") == "FAIL"),
            "warn_count": sum(1 for f in all_findings if f.get("status") == "WARN"),
            "results": results,
        }

        # Persist to database
        scan_id = db.save_scan(consolidated)

        with _jobs_lock:
            _jobs[job_id]["status"] = "complete"
            _jobs[job_id]["finished_at"] = now_iso()
            _jobs[job_id]["scan_id"] = scan_id
            _jobs[job_id]["report"] = consolidated

    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("Job %s failed: %s", job_id, exc)
        with _jobs_lock:
            _jobs[job_id]["status"] = "error"
            _jobs[job_id]["error"] = str(exc)
            _jobs[job_id]["finished_at"] = now_iso()


# ── Request Handler ────────────────────────────────────────────────────────────

class CyberSWISSHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the CyberSWISS REST API."""

    # Shared database instance (set by main() before starting the server)
    db: ScanDatabase

    # ── Logging override ───────────────────────────────────────────────────────

    def log_message(self, fmt: str, *args: Any) -> None:  # type: ignore[override]
        """Route access logs through the standard logging module."""
        logger.info("%s – %s", self.address_string(), fmt % args)

    # ── Low-level helpers ──────────────────────────────────────────────────────

    def _send_json(self, data: Any, status: int = 200) -> None:
        """Serialise *data* to JSON and send with the given HTTP *status*."""
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # CORS – allow browser-based tooling on the same machine
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, content: str, status: int = 200) -> None:
        """Send an HTML string response."""
        body = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, msg: str, status: int = 400) -> None:
        """Send a JSON error response."""
        self._send_json({"error": msg}, status=status)

    def _parse_body(self) -> tuple[dict[str, Any] | None, str | None]:
        """Read and JSON-decode the request body."""
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0:
                return None, "Content-Length must not be negative."
            if length == 0:
                return {}, None
            raw = self.rfile.read(length)
        except ValueError:
            return None, "Invalid Content-Length header."
        except OSError as exc:
            return None, f"Failed to read request body: {exc}"

        try:
            decoded = json.loads(raw.decode("utf-8"))
        except UnicodeDecodeError:
            return None, "Request body must be valid UTF-8 JSON."
        except json.JSONDecodeError as exc:
            return None, f"Malformed JSON body: {exc.msg}."

        if not isinstance(decoded, dict):
            return None, "Request body must be a JSON object."
        return decoded, None

    def _path_parts(self) -> list[str]:
        """Return the non-empty path segments of the request URL."""
        parsed = urlparse(self.path)
        return [p for p in parsed.path.split("/") if p]

    # ── Routing ────────────────────────────────────────────────────────────────

    def do_OPTIONS(self) -> None:  # noqa: N802
        """Handle pre-flight CORS requests."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        """Route GET requests to the appropriate handler."""
        parts = self._path_parts()
        # Expected structure: ['api', 'v1', '<resource>', ...]
        if len(parts) < 3 or parts[0] != "api" or parts[1] != "v1":
            self._send_error("Not found", 404)
            return

        resource = parts[2]

        if resource == "health":
            self.handle_health()
        elif resource == "scripts":
            self.handle_scripts()
        elif resource == "scan" and len(parts) == 4:
            self.handle_scan_get(parts[3])
        elif resource == "history":
            self.handle_history()
        elif resource == "report" and len(parts) == 4:
            self.handle_report(parts[3])
        elif resource == "drift" and len(parts) == 4:
            self.handle_drift(parts[3])
        else:
            self._send_error("Not found", 404)

    def do_POST(self) -> None:  # noqa: N802
        """Route POST requests to the appropriate handler."""
        parts = self._path_parts()
        if len(parts) < 3 or parts[0] != "api" or parts[1] != "v1":
            self._send_error("Not found", 404)
            return

        resource = parts[2]

        if resource == "scan" and len(parts) == 3:
            self.handle_scan_post()
        else:
            self._send_error("Not found", 404)

    def do_DELETE(self) -> None:  # noqa: N802
        """Route DELETE requests to the appropriate handler."""
        parts = self._path_parts()
        if len(parts) < 3 or parts[0] != "api" or parts[1] != "v1":
            self._send_error("Not found", 404)
            return

        resource = parts[2]

        if resource == "scan" and len(parts) == 4:
            self.handle_delete(parts[3])
        else:
            self._send_error("Not found", 404)

    # ── Endpoint handlers ──────────────────────────────────────────────────────

    def handle_health(self) -> None:
        """GET /api/v1/health – return service health and version."""
        scripts = discover_scripts()
        self._send_json({
            "status": "ok",
            "version": VERSION,
            "scripts_available": len(scripts),
        })

    def handle_scripts(self) -> None:
        """GET /api/v1/scripts – list all discovered audit scripts."""
        scripts = discover_scripts()
        self._send_json({"scripts": scripts, "count": len(scripts)})

    def handle_scan_post(self) -> None:
        """
        POST /api/v1/scan – kick off a background scan and return a job_id.

        Expected request body (all fields optional):
            {
                "os":      "linux",   // "linux" | "windows" | null
                "scripts": ["L01"],   // subset of script IDs, or null for all
                "fix":     false,
                "timeout": 300
            }
        """
        body, parse_error = self._parse_body()
        if parse_error is not None or body is None:
            self._send_error(parse_error or "Malformed request body", 400)
            return

        scan_request, validation_error = validate_scan_request(body)
        if validation_error is not None or scan_request is None:
            self._send_error(validation_error or "Invalid scan request", 400)
            return

        os_filter = scan_request["os_filter"]
        script_ids = scan_request["script_ids"]
        fix_mode = scan_request["fix_mode"]
        timeout = scan_request["timeout"]

        job_id = str(uuid.uuid4())
        started_at = now_iso()

        with _jobs_lock:
            _jobs[job_id] = {
                "job_id": job_id,
                "status": "queued",
                "started_at": started_at,
                "finished_at": None,
                "scripts_total": 0,
                "scripts_done": 0,
                "scan_id": None,
                "report": None,
                "error": None,
            }

        # Launch the scan in a daemon thread so the server remains responsive
        thread = threading.Thread(
            target=_run_scan_job,
            args=(job_id, os_filter, script_ids, fix_mode, timeout, self.db),
            daemon=True,
        )
        thread.start()

        self._send_json(
            {"job_id": job_id, "status": "queued", "started_at": started_at},
            status=202,
        )

    def handle_scan_get(self, job_id: str) -> None:
        """
        GET /api/v1/scan/{id} – return current status and results for a job.

        The response includes a progress ratio (scripts_done / scripts_total)
        while the scan is running, and full findings once complete.
        """
        with _jobs_lock:
            job = _jobs.get(job_id)

        if job is None:
            self._send_error(f"Job '{job_id}' not found", 404)
            return

        response: dict[str, Any] = {
            "job_id": job["job_id"],
            "status": job["status"],
            "started_at": job["started_at"],
            "finished_at": job["finished_at"],
            "progress": {
                "completed": job["scripts_done"],
                "total": job["scripts_total"],
            },
        }

        if job["status"] == "complete" and job["report"]:
            response["scan_id"] = job["scan_id"]
            response["findings"] = [
                f
                for r in job["report"].get("results", [])
                for f in r.get("findings", [])
            ]

        if job["status"] == "error":
            response["error"] = job["error"]

        self._send_json(response)

    def handle_history(self) -> None:
        """GET /api/v1/history – list stored scan summaries."""
        scans = self.db.list_scans(limit=50)
        self._send_json({"scans": scans, "count": len(scans)})

    def handle_report(self, scan_id_str: str) -> None:
        """GET /api/v1/report/{id} – return an HTML report for a stored scan."""
        try:
            scan_id = int(scan_id_str)
        except ValueError:
            self._send_error("scan_id must be an integer")
            return

        scan = self.db.get_scan(scan_id)
        if scan is None:
            self._send_error(f"Scan {scan_id} not found", 404)
            return

        # Rebuild the consolidated dict expected by generate_html()
        try:
            consolidated = json.loads(scan["json_data"])
        except (KeyError, json.JSONDecodeError):
            # Fall back to reconstructing from what we have
            consolidated = {
                "host": scan.get("host", "unknown"),
                "generated_at": scan.get("timestamp", ""),
                "scripts_run": scan.get("scripts_run", 0),
                "results": [],
            }

        html = generate_html(consolidated)
        self._send_html(html)

    def handle_drift(self, scan_id_str: str) -> None:
        """
        GET /api/v1/drift/{id} – return drift analysis for a stored scan
        compared to its predecessor.
        """
        try:
            scan_id = int(scan_id_str)
        except ValueError:
            self._send_error("scan_id must be an integer")
            return

        scan = self.db.get_scan(scan_id)
        if scan is None:
            self._send_error(f"Scan {scan_id} not found", 404)
            return

        # Reconstruct current_report from stored data
        try:
            current_report = json.loads(scan["json_data"])
        except (KeyError, json.JSONDecodeError):
            self._send_error("Stored scan data is corrupt", 500)
            return

        drift = self.db.detect_drift(current_report, current_scan_id=scan_id)
        self._send_json(drift)

    def handle_delete(self, scan_id_str: str) -> None:
        """DELETE /api/v1/scan/{id} – remove a scan from the database."""
        try:
            scan_id = int(scan_id_str)
        except ValueError:
            self._send_error("scan_id must be an integer")
            return

        scan = self.db.get_scan(scan_id)
        if scan is None:
            self._send_error(f"Scan {scan_id} not found", 404)
            return

        if not self.db.delete_scan(scan_id):
            self._send_error("Database error while deleting scan", 500)
            return

        self._send_json({"deleted": True, "scan_id": scan_id})


# ── CLI Argument Parsing ───────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for the API server."""
    p = argparse.ArgumentParser(
        prog="api.py",
        description="CyberSWISS REST API Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--host",
        default="0.0.0.0",
        help="Interface to bind to (default: 0.0.0.0).  Use 127.0.0.1 for "
             "local-only access.",
    )
    p.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port to listen on (default: 8080).",
    )
    p.add_argument(
        "--db-path",
        default=None,
        metavar="FILE",
        help="Path to the SQLite database file.  Defaults to "
             "<repo_root>/reports/cyberswiss.db.",
    )
    return p.parse_args()


# ── Entry Point ────────────────────────────────────────────────────────────────

def main() -> None:
    """Initialise the database and start the HTTP server."""
    args = parse_args()

    # Attach shared DB instance to the handler class so all requests share it
    CyberSWISSHandler.db = ScanDatabase(db_path=args.db_path)

    server_address = (args.host, args.port)
    httpd = ThreadingHTTPServer(server_address, CyberSWISSHandler)

    logger.info(
        "CyberSWISS API v%s listening on http://%s:%d",
        VERSION, args.host, args.port,
    )
    logger.info("Database: %s", CyberSWISSHandler.db.db_path)
    logger.info("Press Ctrl+C to stop.")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down.")
        httpd.server_close()


if __name__ == "__main__":
    main()
