"""
CyberSWISS – HTTP-level tests for the REST API (common/api.py).

These exercise a real ThreadingHTTPServer over a loopback socket, so routing,
status codes, content types, query-parameter validation, and CORS headers are
covered end to end rather than by import smoke tests.
"""
from __future__ import annotations

import json
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "common"))


SAMPLE_REPORT = {
    "cyberswiss_report": True,
    "generated_at": "2026-01-01T00:00:00+00:00",
    "host": "apihost",
    "scripts_run": 1,
    "total_findings": 2,
    "fail_count": 1,
    "warn_count": 1,
    "results": [
        {
            "script": "L01_password_policy",
            "script_meta": {"id": "L01", "os": "linux"},
            "findings": [
                {
                    "id": "L01-C1",
                    "name": "Password Max Age",
                    "severity": "High",
                    "status": "FAIL",
                    "detail": "Max age 99 days",
                    "remediation": "Set PASS_MAX_DAYS 90",
                },
                {
                    "id": "L01-C2",
                    "name": "Password Min Length",
                    "severity": "Med",
                    "status": "WARN",
                    "detail": "Min length 8",
                    "remediation": "Set PASS_MIN_LEN 14",
                },
            ],
        }
    ],
}


# ── Server fixture ────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def api_server(tmp_path_factory):
    """Start the real API server on an ephemeral port with an isolated DB."""
    import api
    from db import ScanDatabase

    db_path = tmp_path_factory.mktemp("api") / "api.db"
    database = ScanDatabase(db_path=db_path)
    database.save_scan(SAMPLE_REPORT)

    second = dict(SAMPLE_REPORT)
    second["generated_at"] = "2026-01-02T00:00:00+00:00"
    second["fail_count"] = 0
    database.save_scan(second)

    api.CyberSWISSHandler.db = database
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), api.CyberSWISSHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}/api/v1"
    finally:
        httpd.shutdown()
        httpd.server_close()


def _get(url: str, method: str = "GET"):
    """Return (status, body_bytes, headers) without raising on 4xx/5xx."""
    request = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


def _post(url: str, payload, raw: bytes | None = None):
    body = raw if raw is not None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, method="POST", headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raw_body = exc.read()
        try:
            return exc.code, json.loads(raw_body)
        except json.JSONDecodeError:
            return exc.code, {"raw": raw_body.decode("utf-8", "replace")}


# ── Health & discovery ────────────────────────────────────────────────────────

class TestHealthAndScripts:
    def test_health_reports_version_and_script_count(self, api_server):
        status, body, _ = _get(f"{api_server}/health")
        data = json.loads(body)
        assert status == 200
        assert data["status"] == "ok"
        assert data["scripts_available"] == 66

    def test_scripts_lists_every_script_with_metadata(self, api_server):
        status, body, _ = _get(f"{api_server}/scripts")
        data = json.loads(body)
        assert status == 200
        assert data["count"] == len(data["scripts"]) == 66
        assert {"id", "name", "os", "lang", "category"} <= set(data["scripts"][0])

    def test_cors_headers_present(self, api_server):
        _, _, headers = _get(f"{api_server}/health")
        assert headers["Access-Control-Allow-Origin"] == "*"

    def test_options_preflight_returns_204(self, api_server):
        status, _, headers = _get(f"{api_server}/health", method="OPTIONS")
        assert status == 204
        assert "GET" in headers["Access-Control-Allow-Methods"]

    def test_unknown_route_is_404(self, api_server):
        status, _, _ = _get(f"{api_server}/nope")
        assert status == 404

    def test_non_api_path_is_404(self, api_server):
        base = api_server.rsplit("/api/v1", 1)[0]
        status, _, _ = _get(f"{base}/")
        assert status == 404


# ── History ───────────────────────────────────────────────────────────────────

class TestHistory:
    def test_lists_stored_scans(self, api_server):
        status, body, _ = _get(f"{api_server}/history")
        data = json.loads(body)
        assert status == 200
        assert data["count"] >= 2

    def test_limit_query_parameter_is_honoured(self, api_server):
        _, body, _ = _get(f"{api_server}/history?limit=1")
        assert json.loads(body)["count"] == 1

    def test_host_query_parameter_filters(self, api_server):
        _, body, _ = _get(f"{api_server}/history?host=apihost")
        assert json.loads(body)["count"] >= 2
        _, body, _ = _get(f"{api_server}/history?host=nosuchhost")
        assert json.loads(body)["count"] == 0

    def test_tag_query_parameter_filters(self, api_server):
        _, body, _ = _get(f"{api_server}/history?tag=L01")
        assert json.loads(body)["count"] >= 2
        _, body, _ = _get(f"{api_server}/history?tag=W99")
        assert json.loads(body)["count"] == 0

    def test_invalid_limit_is_rejected(self, api_server):
        status, body, _ = _get(f"{api_server}/history?limit=abc")
        assert status == 400
        assert "limit" in json.loads(body)["error"]

    def test_out_of_range_limit_is_rejected(self, api_server):
        status, _, _ = _get(f"{api_server}/history?limit=99999")
        assert status == 400


# ── Reports ───────────────────────────────────────────────────────────────────

class TestReportFormats:
    def test_html_is_the_default(self, api_server):
        status, body, headers = _get(f"{api_server}/report/1")
        assert status == 200
        assert headers["Content-Type"].startswith("text/html")
        assert b"CyberSWISS Security Audit Report" in body

    def test_json_format(self, api_server):
        status, body, headers = _get(f"{api_server}/report/1?format=json")
        assert status == 200
        assert headers["Content-Type"].startswith("application/json")
        assert json.loads(body)["host"] == "apihost"

    def test_sarif_format_is_valid_sarif(self, api_server):
        status, body, headers = _get(f"{api_server}/report/1?format=sarif")
        assert status == 200
        assert headers["Content-Type"].startswith("application/sarif+json")
        doc = json.loads(body)
        assert doc["version"] == "2.1.0"
        assert doc["runs"][0]["tool"]["driver"]["name"] == "CyberSWISS"

    def test_markdown_format(self, api_server):
        status, body, headers = _get(f"{api_server}/report/1?format=markdown")
        assert status == 200
        assert headers["Content-Type"].startswith("text/markdown")
        assert b"CyberSWISS Security Audit" in body

    def test_csv_format_has_a_header_row(self, api_server):
        status, body, headers = _get(f"{api_server}/report/1?format=csv")
        assert status == 200
        assert headers["Content-Type"].startswith("text/csv")
        assert body.splitlines()[0].startswith(b"Script,FindingID")

    def test_text_format(self, api_server):
        status, body, headers = _get(f"{api_server}/report/1?format=text")
        assert status == 200
        assert headers["Content-Type"].startswith("text/plain")
        assert b"END OF REPORT" in body

    def test_unsupported_format_is_rejected(self, api_server):
        status, body, _ = _get(f"{api_server}/report/1?format=xml")
        assert status == 400
        assert "sarif" in json.loads(body)["error"]

    def test_missing_scan_is_404(self, api_server):
        status, _, _ = _get(f"{api_server}/report/99999")
        assert status == 404

    def test_non_numeric_scan_id_is_400(self, api_server):
        status, _, _ = _get(f"{api_server}/report/abc")
        assert status == 400


# ── Drift & trend ─────────────────────────────────────────────────────────────

class TestDriftAndTrend:
    def test_drift_compares_against_the_predecessor(self, api_server):
        status, body, _ = _get(f"{api_server}/drift/2")
        data = json.loads(body)
        assert status == 200
        assert data["baseline_scan_id"] == 1

    def test_drift_for_missing_scan_is_404(self, api_server):
        status, _, _ = _get(f"{api_server}/drift/99999")
        assert status == 404

    def test_trend_returns_points_oldest_first(self, api_server):
        status, body, _ = _get(f"{api_server}/trend?limit=5")
        data = json.loads(body)
        assert status == 200
        assert [p["scan_id"] for p in data["points"]] == sorted(p["scan_id"] for p in data["points"])

    def test_trend_host_filter(self, api_server):
        _, body, _ = _get(f"{api_server}/trend?host=nosuchhost")
        assert json.loads(body)["points"] == []

    def test_trend_rejects_a_bad_limit(self, api_server):
        status, _, _ = _get(f"{api_server}/trend?limit=0")
        assert status == 400


# ── Scan submission ───────────────────────────────────────────────────────────

class TestScanSubmission:
    def test_rejects_unknown_os(self, api_server):
        status, body = _post(f"{api_server}/scan", {"os": "solaris"})
        assert status == 400
        assert "os" in body["error"]

    def test_rejects_unknown_script_id(self, api_server):
        status, body = _post(f"{api_server}/scan", {"os": "linux", "scripts": ["L99"]})
        assert status == 400
        assert "L99" in body["error"]

    def test_rejects_non_boolean_fix(self, api_server):
        status, body = _post(f"{api_server}/scan", {"fix": "yes"})
        assert status == 400

    def test_rejects_out_of_range_timeout(self, api_server):
        status, _ = _post(f"{api_server}/scan", {"timeout": 99999})
        assert status == 400

    def test_rejects_bad_tags(self, api_server):
        status, body = _post(f"{api_server}/scan", {"tags": [""]})
        assert status == 400
        assert "tags" in body["error"]

    def test_rejects_bad_min_severity(self, api_server):
        status, body = _post(f"{api_server}/scan", {"min_severity": "Catastrophic"})
        assert status == 400
        assert "min_severity" in body["error"]

    def test_rejects_malformed_json_body(self, api_server):
        status, body = _post(f"{api_server}/scan", None, raw=b"{not json")
        assert status == 400
        assert "JSON" in body["error"]

    def test_rejects_non_object_body(self, api_server):
        status, _ = _post(f"{api_server}/scan", [1, 2, 3])
        assert status == 400

    def test_unknown_job_is_404(self, api_server):
        status, _, _ = _get(f"{api_server}/scan/does-not-exist")
        assert status == 404

    def test_post_to_unknown_resource_is_404(self, api_server):
        status, _ = _post(f"{api_server}/nope", {})
        assert status == 404


# ── Deletion ──────────────────────────────────────────────────────────────────

class TestDeletion:
    def test_delete_removes_the_scan(self, api_server):
        import api

        scan_id = api.CyberSWISSHandler.db.save_scan(SAMPLE_REPORT)
        status, body, _ = _get(f"{api_server}/scan/{scan_id}", method="DELETE")
        assert status == 200
        assert json.loads(body)["deleted"] is True
        assert api.CyberSWISSHandler.db.get_scan(scan_id) is None

    def test_delete_missing_scan_is_404(self, api_server):
        status, _, _ = _get(f"{api_server}/scan/99999", method="DELETE")
        assert status == 404

    def test_delete_non_numeric_is_400(self, api_server):
        status, _, _ = _get(f"{api_server}/scan/abc", method="DELETE")
        assert status == 400


# ── Job registry hygiene ──────────────────────────────────────────────────────

class TestJobRegistry:
    def test_finished_jobs_are_pruned_to_the_cap(self):
        import api

        with api._jobs_lock:
            api._jobs.clear()
            for index in range(api.MAX_FINISHED_JOBS + 25):
                api._jobs[f"job-{index:04d}"] = {
                    "status": "complete",
                    "finished_at": f"2026-01-01T00:00:{index:02d}+00:00",
                }
            api._prune_finished_jobs()
            remaining = len(api._jobs)
            oldest_evicted = "job-0000" not in api._jobs
            api._jobs.clear()

        assert remaining == api.MAX_FINISHED_JOBS
        assert oldest_evicted

    def test_running_jobs_are_never_pruned(self):
        import api

        with api._jobs_lock:
            api._jobs.clear()
            api._jobs["running"] = {"status": "running", "finished_at": None}
            for index in range(api.MAX_FINISHED_JOBS + 5):
                api._jobs[f"done-{index:04d}"] = {
                    "status": "complete",
                    "finished_at": f"2026-01-01T00:00:{index:02d}+00:00",
                }
            api._prune_finished_jobs()
            running_kept = "running" in api._jobs
            api._jobs.clear()

        assert running_kept
