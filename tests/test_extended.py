"""
CyberSWISS – Tests for extended features:
  - common/db.py  (ScanDatabase, drift detection)
  - common/report_generator.py  (CSV, plain-text output)
  - common/runner.py  (new flags: --html, --csv, --delay, --save-db, --diff)
  - common/api.py  (REST API import smoke test)
"""
from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "common"))


# ── Fixtures ──────────────────────────────────────────────────────────────────

SAMPLE_REPORT = {
    "cyberswiss_report": True,
    "generated_at": "2026-01-01T00:00:00+00:00",
    "host": "testhost",
    "scripts_run": 2,
    "total_findings": 3,
    "fail_count": 1,
    "warn_count": 1,
    "results": [
        {
            "script": "L01_password_policy",
            "host": "testhost",
            "timestamp": "2026-01-01T00:00:00Z",
            "findings": [
                {
                    "id": "L01-C1",
                    "name": "Password Max Age",
                    "severity": "High",
                    "status": "FAIL",
                    "detail": "Max age 99 days",
                    "remediation": "Set PASS_MAX_DAYS 90",
                    "timestamp": "2026-01-01T00:00:00Z",
                },
                {
                    "id": "L01-C2",
                    "name": "Password Min Length",
                    "severity": "Med",
                    "status": "WARN",
                    "detail": "Min length 8",
                    "remediation": "Set PASS_MIN_LEN 14",
                    "timestamp": "2026-01-01T00:00:00Z",
                },
            ],
        },
        {
            "script": "L07_ssh_posture",
            "host": "testhost",
            "timestamp": "2026-01-01T00:00:00Z",
            "findings": [
                {
                    "id": "L07-C1",
                    "name": "SSH Root Login",
                    "severity": "Critical",
                    "status": "PASS",
                    "detail": "PermitRootLogin no",
                    "remediation": "",
                    "timestamp": "2026-01-01T00:00:00Z",
                },
            ],
        },
    ],
}


# ── db.py tests ───────────────────────────────────────────────────────────────

class TestScanDatabase:
    def test_db_importable(self):
        from db import ScanDatabase  # noqa: F401

    def test_db_creates_file(self, tmp_path):
        from db import ScanDatabase
        db_path = tmp_path / "test.db"
        db = ScanDatabase(db_path=db_path)
        assert db_path.exists()

    def test_save_and_list_scans(self, tmp_path):
        from db import ScanDatabase
        db = ScanDatabase(db_path=tmp_path / "test.db")
        scan_id = db.save_scan(SAMPLE_REPORT)
        assert isinstance(scan_id, int)
        assert scan_id > 0
        scans = db.list_scans()
        assert len(scans) >= 1
        assert scans[0]["host"] == "testhost"

    def test_get_scan(self, tmp_path):
        from db import ScanDatabase
        db = ScanDatabase(db_path=tmp_path / "test.db")
        scan_id = db.save_scan(SAMPLE_REPORT)
        scan = db.get_scan(scan_id)
        assert scan is not None
        assert scan["host"] == "testhost"
        assert scan["scripts_run"] == 2

    def test_get_last_scan(self, tmp_path):
        from db import ScanDatabase
        db = ScanDatabase(db_path=tmp_path / "test.db")
        db.save_scan(SAMPLE_REPORT)
        last = db.get_last_scan(host="testhost")
        assert last is not None
        assert last["host"] == "testhost"

    def test_no_drift_without_baseline(self, tmp_path):
        from db import ScanDatabase
        db = ScanDatabase(db_path=tmp_path / "test.db")
        drift = db.detect_drift(SAMPLE_REPORT)
        assert drift["has_drift"] is False

    def test_drift_detects_new_finding(self, tmp_path):
        from db import ScanDatabase
        db = ScanDatabase(db_path=tmp_path / "test.db")
        db.save_scan(SAMPLE_REPORT)

        # Create a modified report with an extra finding
        new_report = json.loads(json.dumps(SAMPLE_REPORT))  # deep copy
        new_report["results"][0]["findings"].append({
            "id": "L01-C99",
            "name": "New Finding",
            "severity": "Critical",
            "status": "FAIL",
            "detail": "New issue detected",
            "remediation": "Fix it",
            "timestamp": "2026-01-02T00:00:00Z",
        })
        new_report["total_findings"] = 4
        new_report["fail_count"] = 2

        drift = db.detect_drift(new_report)
        assert drift["has_drift"] is True
        new_ids = {f["id"] for f in drift["new_findings"]}
        assert "L01-C99" in new_ids

    def test_drift_detects_resolved_finding(self, tmp_path):
        from db import ScanDatabase
        db = ScanDatabase(db_path=tmp_path / "test.db")
        db.save_scan(SAMPLE_REPORT)

        # New report is missing L01-C2
        new_report = json.loads(json.dumps(SAMPLE_REPORT))
        new_report["results"][0]["findings"] = [
            f for f in new_report["results"][0]["findings"] if f["id"] != "L01-C2"
        ]
        drift = db.detect_drift(new_report)
        assert drift["has_drift"] is True
        # resolved_findings come from DB rows which use "finding_id" column
        resolved_ids = {f.get("finding_id", f.get("id")) for f in drift["resolved_findings"]}
        assert "L01-C2" in resolved_ids

    def test_delete_old_scans(self, tmp_path):
        from db import ScanDatabase
        db = ScanDatabase(db_path=tmp_path / "test.db")
        for _ in range(5):
            db.save_scan(SAMPLE_REPORT)
        deleted = db.delete_old_scans(keep_last=2, host="testhost")
        assert deleted == 3
        assert len(db.list_scans(host="testhost")) == 2

    def test_format_drift_report_no_colour(self, tmp_path):
        from db import ScanDatabase, format_drift_report
        db = ScanDatabase(db_path=tmp_path / "test.db")
        db.save_scan(SAMPLE_REPORT)
        new_report = json.loads(json.dumps(SAMPLE_REPORT))
        new_report["results"][0]["findings"].append({
            "id": "L01-NEW",
            "name": "New Critical",
            "severity": "Critical",
            "status": "FAIL",
            "detail": "X",
            "remediation": "Y",
            "timestamp": "2026-01-02T00:00:00Z",
        })
        drift = db.detect_drift(new_report)
        report_text = format_drift_report(drift, no_colour=True)
        assert isinstance(report_text, str)
        assert "L01-NEW" in report_text or "New Critical" in report_text

    def test_detect_drift_uses_previous_scan_when_current_scan_id_is_supplied(self, tmp_path):
        from db import ScanDatabase

        db = ScanDatabase(db_path=tmp_path / "test.db")
        first_scan_id = db.save_scan(SAMPLE_REPORT)

        second_report = json.loads(json.dumps(SAMPLE_REPORT))
        second_report["results"][0]["findings"] = [
            {
                "id": "L01-C1",
                "name": "Password Max Age",
                "severity": "High",
                "status": "PASS",
                "detail": "Fixed",
                "remediation": "",
                "timestamp": "2026-01-02T00:00:00Z",
            }
        ]
        second_report["total_findings"] = 2
        second_report["fail_count"] = 0
        second_report["warn_count"] = 0

        second_scan_id = db.save_scan(second_report)
        current_scan = db.get_scan(second_scan_id)
        assert current_scan is not None

        drift = db.detect_drift(
            json.loads(current_scan["json_data"]),
            current_scan_id=second_scan_id,
        )
        assert drift["baseline_scan_id"] == first_scan_id
        assert drift["has_drift"] is True

    def test_delete_scan_removes_saved_scan(self, tmp_path):
        from db import ScanDatabase

        db = ScanDatabase(db_path=tmp_path / "test.db")
        scan_id = db.save_scan(SAMPLE_REPORT)
        assert db.delete_scan(scan_id) is True
        assert db.get_scan(scan_id) is None


# ── report_generator.py – CSV/text output tests ───────────────────────────────

class TestReportGeneratorCSV:
    def test_generate_csv_importable(self):
        from report_generator import generate_csv  # noqa: F401

    def test_csv_has_header(self):
        from report_generator import generate_csv
        csv_content = generate_csv(SAMPLE_REPORT)
        lines = csv_content.strip().split("\n")
        assert lines[0].startswith("Script,")
        assert "FindingID" in lines[0]
        assert "Status" in lines[0]
        assert "Severity" in lines[0]

    def test_csv_row_count(self):
        from report_generator import generate_csv
        csv_content = generate_csv(SAMPLE_REPORT)
        reader = csv.reader(io.StringIO(csv_content))
        rows = list(reader)
        # 1 header + 3 findings
        assert len(rows) == 4

    def test_csv_contains_fail_finding(self):
        from report_generator import generate_csv
        csv_content = generate_csv(SAMPLE_REPORT)
        assert "FAIL" in csv_content
        assert "L01-C1" in csv_content

    def test_csv_to_file(self, tmp_path):
        from report_generator import generate_csv
        out = tmp_path / "report.csv"
        out.write_text(generate_csv(SAMPLE_REPORT), encoding="utf-8")
        assert out.exists()
        assert out.stat().st_size > 0


class TestReportGeneratorText:
    def test_generate_text_importable(self):
        from report_generator import generate_text  # noqa: F401

    def test_text_contains_host(self):
        from report_generator import generate_text
        text = generate_text(SAMPLE_REPORT)
        assert "testhost" in text

    def test_text_contains_fail(self):
        from report_generator import generate_text
        text = generate_text(SAMPLE_REPORT)
        assert "FAIL" in text

    def test_text_contains_remediation(self):
        from report_generator import generate_text
        text = generate_text(SAMPLE_REPORT)
        assert "Remedy" in text

    def test_text_ends_with_separator(self):
        from report_generator import generate_text
        text = generate_text(SAMPLE_REPORT)
        assert "===" in text


# ── runner.py – new flags ─────────────────────────────────────────────────────

class TestRunnerNewFlags:
    def test_runner_accepts_html_flag(self):
        import runner
        import sys
        from unittest.mock import patch
        with patch.object(sys, 'argv', ['runner.py', '--html', '/tmp/test.html', '--dry-run']):
            args = runner.parse_args()
        assert args.html == '/tmp/test.html'

    def test_runner_accepts_csv_flag(self):
        import runner
        import sys
        from unittest.mock import patch
        with patch.object(sys, 'argv', ['runner.py', '--csv', '/tmp/test.csv', '--dry-run']):
            args = runner.parse_args()
        assert args.csv == '/tmp/test.csv'

    def test_runner_accepts_delay_flag(self):
        import runner
        import sys
        from unittest.mock import patch
        with patch.object(sys, 'argv', ['runner.py', '--delay', '1.5', '--dry-run']):
            args = runner.parse_args()
        assert args.delay == 1.5

    def test_runner_accepts_save_db_flag(self):
        import runner
        import sys
        from unittest.mock import patch
        with patch.object(sys, 'argv', ['runner.py', '--save-db', '--dry-run']):
            args = runner.parse_args()
        assert args.save_db is True

    def test_runner_accepts_diff_flag(self):
        import runner
        import sys
        from unittest.mock import patch
        with patch.object(sys, 'argv', ['runner.py', '--diff', '--dry-run']):
            args = runner.parse_args()
        assert args.diff is True

    def test_runner_default_delay_is_zero(self):
        import runner
        import sys
        from unittest.mock import patch
        with patch.object(sys, 'argv', ['runner.py', '--dry-run']):
            args = runner.parse_args()
        assert args.delay == 0.0


# ── api.py smoke tests ────────────────────────────────────────────────────────

class TestApiModule:
    def test_api_importable(self):
        import api  # noqa: F401

    def test_api_has_handler_class(self):
        import api
        assert hasattr(api, 'CyberSWISSHandler')

    def test_api_has_main_function(self):
        import api
        assert hasattr(api, 'main')

    def test_api_has_parse_args(self):
        import api
        assert hasattr(api, 'parse_args')

    def test_validate_scan_request_rejects_unknown_script(self):
        import api

        payload, error = api.validate_scan_request({"os": "linux", "scripts": ["L01", "NOPE"]})
        assert payload is None
        assert "Unknown script IDs" in error

    def test_validate_scan_request_normalises_valid_payload(self):
        import api

        payload, error = api.validate_scan_request({"os": "both", "scripts": ["l01"], "fix": False, "timeout": 60})
        assert error is None
        assert payload is not None
        assert payload["os_filter"] is None
        assert payload["script_ids"] == ["L01"]
        assert payload["timeout"] == 60
