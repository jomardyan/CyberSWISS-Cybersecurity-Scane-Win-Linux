"""
CyberSWISS – Tests for orchestration behaviour and the history tooling:
  - common/runner.py            (reporting filters, dry-run drift/trend, main())
  - common/db.py                (scan tags, tag filtering, the db.py CLI)
  - common/report_generator.py  (HTML output)
"""
from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "common"))

RUNNER = REPO_ROOT / "common" / "runner.py"
DB_CLI = REPO_ROOT / "common" / "db.py"


SAMPLE_REPORT = {
    "cyberswiss_report": True,
    "generated_at": "2026-01-01T00:00:00+00:00",
    "host": "orchhost",
    "scripts_run": 2,
    "total_findings": 4,
    "fail_count": 2,
    "warn_count": 1,
    "results": [
        {
            "script": "L01_password_policy",
            "script_meta": {"id": "L01", "os": "linux"},
            "findings": [
                {"id": "L01-C1", "name": "Max Age", "severity": "Critical",
                 "status": "FAIL", "detail": "99 days", "remediation": "Set 90"},
                {"id": "L01-C2", "name": "Min Length", "severity": "Low",
                 "status": "WARN", "detail": "8", "remediation": "Set 14"},
            ],
        },
        {
            "script": "W06_firewall_state",
            "script_meta": {"id": "W06", "os": "windows"},
            "findings": [
                {"id": "W06-C1", "name": "Firewall Off", "severity": "High",
                 "status": "FAIL", "detail": "Domain off", "remediation": "Enable"},
                {"id": "W06-C2", "name": "Logging", "severity": "Low",
                 "status": "PASS", "detail": "on", "remediation": ""},
            ],
        },
    ],
}


@pytest.fixture
def report():
    return copy.deepcopy(SAMPLE_REPORT)


def _run_runner(*args, cwd=None):
    """Invoke runner.py as a subprocess and return the CompletedProcess."""
    return subprocess.run(
        [sys.executable, str(RUNNER), *args],
        capture_output=True, text=True, timeout=180, cwd=cwd, check=False,
    )


def _run_db(*args):
    return subprocess.run(
        [sys.executable, str(DB_CLI), *args],
        capture_output=True, text=True, timeout=60, check=False,
    )


# ── Reporting filters shape every output, not just the terminal ──────────────

class TestReportingFilters:
    def test_min_severity_filters_the_saved_json(self, tmp_path):
        out = tmp_path / "audit.json"
        _run_runner("--scripts", "L01", "--no-colour", "--min-severity", "Critical",
                    "--output", str(out))
        data = json.loads(out.read_text())
        severities = {f["severity"] for r in data["results"] for f in r["findings"]}
        assert severities <= {"Critical"}

    def test_unfiltered_run_keeps_lower_severities(self, tmp_path):
        out = tmp_path / "audit.json"
        _run_runner("--scripts", "L01", "--no-colour", "--output", str(out))
        data = json.loads(out.read_text())
        severities = {f["severity"] for r in data["results"] for f in r["findings"]}
        assert severities - {"Critical"}

    def test_status_filter_shapes_counts_and_exit_code(self, tmp_path):
        out = tmp_path / "audit.json"
        result = _run_runner("--scripts", "L01", "--no-colour", "--status", "PASS",
                             "--output", str(out))
        data = json.loads(out.read_text())
        statuses = {f["status"] for r in data["results"] for f in r["findings"]}
        assert statuses <= {"PASS"}
        assert data["fail_count"] == 0
        assert result.returncode == 0

    def test_min_severity_reaches_sarif_output(self, tmp_path):
        sarif = tmp_path / "audit.sarif"
        _run_runner("--scripts", "L01", "--no-colour", "--min-severity", "Critical",
                    "--sarif", str(sarif))
        doc = json.loads(sarif.read_text())
        for rule in doc["runs"][0]["tool"]["driver"]["rules"]:
            assert rule["properties"]["severity"] == "Critical"


# ── --diff / --trend without re-scanning (what `make report-diff` runs) ──────

class TestDryRunHistory:
    def _seed(self, tmp_path, monkeypatch):
        """Two stored scans in an isolated repo-relative reports/ directory."""
        import db as db_module

        db_path = tmp_path / "hist.db"
        database = db_module.ScanDatabase(db_path=db_path)
        first = copy.deepcopy(SAMPLE_REPORT)
        first["results"] = [first["results"][0]]
        database.save_scan(first)
        database.save_scan(SAMPLE_REPORT)

        real_db = db_module.ScanDatabase
        monkeypatch.setattr(db_module, "ScanDatabase",
                            lambda *a, **kw: real_db(db_path=db_path))
        return database

    def test_dry_run_diff_reports_stored_drift(self, tmp_path, monkeypatch, capsys):
        import runner

        self._seed(tmp_path, monkeypatch)
        drift = runner.emit_stored_drift(no_colour=True, json_mode=False)
        assert drift is not None
        assert drift["baseline_scan_id"] == 1
        assert "DRIFT DETECTION REPORT" in capsys.readouterr().out

    def test_dry_run_diff_on_empty_history_is_graceful(self, tmp_path, monkeypatch, capsys):
        import db as db_module
        import runner

        real_db = db_module.ScanDatabase
        empty = tmp_path / "empty.db"
        monkeypatch.setattr(db_module, "ScanDatabase",
                            lambda *a, **kw: real_db(db_path=empty))
        assert runner.emit_stored_drift(no_colour=True, json_mode=False) is None
        assert "no scan history" in capsys.readouterr().out

    def test_dry_run_diff_warns_instead_of_raising(self, monkeypatch, capsys):
        import db as db_module
        import runner

        def _boom(*_a, **_kw):
            raise RuntimeError("db gone")

        monkeypatch.setattr(db_module, "ScanDatabase", _boom)
        assert runner.emit_stored_drift(no_colour=True, json_mode=True) is None
        assert "Drift analysis failed" in capsys.readouterr().err

    def test_dry_run_json_emits_a_single_document(self, tmp_path):
        result = _run_runner("--scripts", "L01", "--dry-run", "--json", "--trend", "3")
        # One parseable document, not a concatenation of several.
        payload = json.loads(result.stdout)
        assert payload["dry_run"] is True
        assert "scripts" in payload

    def test_dry_run_lists_scripts_without_running_them(self, tmp_path):
        out = tmp_path / "never.json"
        result = _run_runner("--scripts", "L01", "--dry-run", "--output", str(out))
        assert result.returncode == 0
        assert not out.exists()


# ── Scan tags ─────────────────────────────────────────────────────────────────

class TestScanTags:
    def _db(self, tmp_path, report):
        from db import ScanDatabase

        database = ScanDatabase(db_path=tmp_path / "tags.db")
        database.save_scan(report)
        return database

    def test_tags_are_written_for_each_scan(self, tmp_path, report):
        database = self._db(tmp_path, report)
        tags = database.get_scan(1)["tags"]
        assert {"L01", "W06", "linux", "windows", "host:orchhost"} <= set(tags)

    def test_tags_fall_back_to_the_script_name(self, tmp_path):
        from db import ScanDatabase

        database = ScanDatabase(db_path=tmp_path / "t.db")
        database.save_scan({"host": "h", "results": [
            {"script": "L07_ssh_posture", "findings": []}]})
        assert "L07" in database.get_scan(1)["tags"]

    def test_list_scans_filters_by_script_tag(self, tmp_path, report):
        database = self._db(tmp_path, report)
        assert len(database.list_scans(tag="L01")) == 1
        assert database.list_scans(tag="L99") == []

    def test_tag_filter_is_case_insensitive(self, tmp_path, report):
        database = self._db(tmp_path, report)
        assert len(database.list_scans(tag="l01")) == 1

    def test_tag_and_host_filters_combine(self, tmp_path, report):
        database = self._db(tmp_path, report)
        assert len(database.list_scans(tag="L01", host="orchhost")) == 1
        assert database.list_scans(tag="L01", host="elsewhere") == []

    def test_deleting_a_scan_removes_its_tags(self, tmp_path, report):
        database = self._db(tmp_path, report)
        database.delete_scan(1)
        assert database.list_scans(tag="L01") == []


# ── db.py command line ────────────────────────────────────────────────────────

class TestDatabaseCli:
    @pytest.fixture
    def seeded_db(self, tmp_path, report):
        from db import ScanDatabase

        path = tmp_path / "cli.db"
        database = ScanDatabase(db_path=path)
        first = copy.deepcopy(report)
        first["results"] = [first["results"][0]]
        database.save_scan(first)
        database.save_scan(report)
        return path

    def test_list_outputs_rows(self, seeded_db):
        result = _run_db("--db-path", str(seeded_db), "list")
        assert result.returncode == 0
        assert "orchhost" in result.stdout

    def test_list_json(self, seeded_db):
        result = _run_db("--db-path", str(seeded_db), "list", "--json")
        assert json.loads(result.stdout)["count"] == 2

    def test_list_tag_filter(self, seeded_db):
        result = _run_db("--db-path", str(seeded_db), "list", "--tag", "W06", "--json")
        assert json.loads(result.stdout)["count"] == 1

    def test_list_on_empty_db_is_friendly(self, tmp_path):
        result = _run_db("--db-path", str(tmp_path / "blank.db"), "list")
        assert result.returncode == 0
        assert "No scans stored yet" in result.stdout

    def test_show_includes_tags_and_findings(self, seeded_db):
        result = _run_db("--db-path", str(seeded_db), "show", "2")
        assert result.returncode == 0
        assert "Tags:" in result.stdout
        assert "L01-C1" in result.stdout

    def test_show_missing_scan_exits_nonzero(self, seeded_db):
        result = _run_db("--db-path", str(seeded_db), "show", "999")
        assert result.returncode == 1
        assert "not found" in result.stderr

    def test_trend_renders(self, seeded_db):
        result = _run_db("--db-path", str(seeded_db), "trend", "--no-colour")
        assert "POSTURE TREND REPORT" in result.stdout

    def test_drift_reports_new_findings_with_exit_code_2(self, seeded_db):
        result = _run_db("--db-path", str(seeded_db), "drift", "2", "--no-colour")
        assert "DRIFT DETECTION REPORT" in result.stdout
        assert result.returncode == 2

    def test_prune_keeps_only_the_newest(self, seeded_db):
        result = _run_db("--db-path", str(seeded_db), "prune", "--keep", "1")
        assert result.returncode == 0
        listing = _run_db("--db-path", str(seeded_db), "list", "--json")
        assert json.loads(listing.stdout)["count"] == 1

    def test_no_subcommand_is_an_error(self, seeded_db):
        result = _run_db("--db-path", str(seeded_db))
        assert result.returncode != 0


# ── HTML report ───────────────────────────────────────────────────────────────

class TestHtmlReport:
    def test_contains_host_and_counts(self, report):
        from report_generator import generate_html

        html = generate_html(report)
        assert "orchhost" in html
        assert "CyberSWISS Security Audit Report" in html

    def test_lists_every_finding(self, report):
        from report_generator import generate_html

        html = generate_html(report)
        for finding_id in ("L01-C1", "L01-C2", "W06-C1", "W06-C2"):
            assert finding_id in html

    def test_escapes_html_in_finding_text(self):
        from report_generator import generate_html

        html = generate_html({"host": "h", "results": [{"script": "L01", "findings": [
            {"id": "X", "name": "<script>alert(1)</script>", "severity": "High",
             "status": "FAIL", "detail": "", "remediation": ""}]}]})
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_handles_an_empty_report(self):
        from report_generator import generate_html

        html = generate_html({"host": "h", "results": []})
        assert "</html>" in html
