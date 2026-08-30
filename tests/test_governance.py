"""
CyberSWISS – Tests for the governance / CI-integration features:
  - common/baseline.py            (accepted-risk waivers, expiry, wildcards)
  - common/report_generator.py    (SARIF 2.1.0 and Markdown output)
  - common/db.py                  (posture trend analytics)
  - common/runner.py              (--baseline, --write-baseline, --sarif,
                                   --markdown, --trend)
  - common/api.py                 (trend endpoint, multi-format reports)
"""
from __future__ import annotations

import copy
import json
import sys
from datetime import date
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
    "total_findings": 4,
    "fail_count": 2,
    "warn_count": 1,
    "results": [
        {
            "script": "L01_password_policy",
            "host": "testhost",
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
        },
        {
            "script": "W06_firewall_state",
            "host": "testhost",
            "findings": [
                {
                    "id": "W06-C1",
                    "name": "Firewall Disabled",
                    "severity": "Critical",
                    "status": "FAIL",
                    "detail": "Domain profile off",
                    "remediation": "Enable Windows Defender Firewall",
                },
                {
                    "id": "W06-C2",
                    "name": "Firewall Logging",
                    "severity": "Low",
                    "status": "PASS",
                    "detail": "Logging enabled",
                    "remediation": "",
                },
            ],
        },
    ],
}


@pytest.fixture
def report():
    """A fresh deep copy so tests never share mutated finding dicts."""
    return copy.deepcopy(SAMPLE_REPORT)


def _baseline_with(*entries):
    return {"cyberswiss_baseline": True, "version": 1, "host": "testhost", "entries": list(entries)}


# ── Baseline module ───────────────────────────────────────────────────────────

class TestBaselineModule:
    def test_importable(self):
        import baseline  # noqa: F401

    def test_build_baseline_records_fail_and_warn_only(self, report):
        from baseline import build_baseline

        built = build_baseline(report)
        ids = {e["id"] for e in built["entries"]}
        assert ids == {"L01-C1", "L01-C2", "W06-C1"}
        assert "W06-C2" not in ids  # PASS findings are not waivable

    def test_build_baseline_applies_expiry(self, report):
        from baseline import build_baseline

        built = build_baseline(report, expires="2027-01-01")
        assert all(e["expires"] == "2027-01-01" for e in built["entries"])

    def test_round_trip_save_and_load(self, report, tmp_path):
        from baseline import build_baseline, load_baseline, save_baseline

        path = tmp_path / "baseline.json"
        save_baseline(build_baseline(report), path)
        loaded = load_baseline(path)
        assert loaded["cyberswiss_baseline"] is True
        assert len(loaded["entries"]) == 3

    def test_load_rejects_malformed_json(self, tmp_path):
        from baseline import BaselineError, load_baseline

        path = tmp_path / "bad.json"
        path.write_text("{not json", encoding="utf-8")
        with pytest.raises(BaselineError):
            load_baseline(path)

    def test_load_rejects_non_list_entries(self, tmp_path):
        from baseline import BaselineError, load_baseline

        path = tmp_path / "bad.json"
        path.write_text(json.dumps({"entries": {"id": "L01-C1"}}), encoding="utf-8")
        with pytest.raises(BaselineError):
            load_baseline(path)

    def test_load_rejects_missing_file(self, tmp_path):
        from baseline import BaselineError, load_baseline

        with pytest.raises(BaselineError):
            load_baseline(tmp_path / "does-not-exist.json")

    def test_apply_baseline_suppresses_matched_finding(self, report):
        from baseline import apply_baseline

        summary = apply_baseline(report, _baseline_with({"id": "L01-C1", "reason": "Legacy app"}))
        finding = report["results"][0]["findings"][0]
        assert finding["suppressed"] is True
        assert finding["suppression_reason"] == "Legacy app"
        assert summary["suppressed_count"] == 1

    def test_apply_baseline_recomputes_counts(self, report):
        from baseline import apply_baseline

        apply_baseline(report, _baseline_with({"id": "L01-C1"}, {"id": "L01-C2"}))
        assert report["fail_count"] == 1  # W06-C1 still failing
        assert report["warn_count"] == 0
        assert report["suppressed_count"] == 2

    def test_apply_baseline_leaves_total_findings_intact(self, report):
        from baseline import apply_baseline

        apply_baseline(report, _baseline_with({"id": "*"}))
        # Suppression is not deletion – the evidence stays in the report.
        assert sum(len(r["findings"]) for r in report["results"]) == 4

    def test_wildcard_id_matches_family(self, report):
        from baseline import apply_baseline

        summary = apply_baseline(report, _baseline_with({"id": "L01-*"}))
        assert summary["suppressed_count"] == 2

    def test_script_scope_limits_a_wildcard(self, report):
        from baseline import apply_baseline

        summary = apply_baseline(report, _baseline_with({"id": "*", "script": "W06_*"}))
        assert summary["suppressed_count"] == 1
        assert summary["suppressed"][0]["id"] == "W06-C1"

    def test_status_mismatch_does_not_suppress(self, report):
        from baseline import apply_baseline

        summary = apply_baseline(report, _baseline_with({"id": "L01-C1", "status": "WARN"}))
        assert summary["suppressed_count"] == 0

    def test_pass_findings_are_never_suppressed(self, report):
        from baseline import apply_baseline

        apply_baseline(report, _baseline_with({"id": "*"}))
        assert "suppressed" not in report["results"][1]["findings"][1]

    def test_expired_entry_stops_suppressing(self, report):
        from baseline import apply_baseline

        summary = apply_baseline(
            report,
            _baseline_with({"id": "L01-C1", "expires": "2020-01-01"}),
            today=date(2026, 1, 1),
        )
        assert summary["suppressed_count"] == 0
        assert len(summary["expired_entries"]) == 1
        assert report["fail_count"] == 2

    def test_future_expiry_still_suppresses(self, report):
        from baseline import apply_baseline

        summary = apply_baseline(
            report,
            _baseline_with({"id": "L01-C1", "expires": "2030-01-01"}),
            today=date(2026, 1, 1),
        )
        assert summary["suppressed_count"] == 1
        assert summary["expired_entries"] == []

    def test_unparseable_expiry_is_treated_as_no_expiry(self, report):
        from baseline import apply_baseline

        summary = apply_baseline(report, _baseline_with({"id": "L01-C1", "expires": "whenever"}))
        assert summary["suppressed_count"] == 1

    def test_unused_entries_are_reported(self, report):
        from baseline import apply_baseline

        summary = apply_baseline(report, _baseline_with({"id": "L01-C1"}, {"id": "L99-C9"}))
        assert [e["id"] for e in summary["unused_entries"]] == ["L99-C9"]

    def test_suppressed_findings_do_not_affect_exit_code(self, report):
        from baseline import apply_baseline
        from utils import expected_exit_code

        findings = [f for r in report["results"] for f in r["findings"]]
        assert expected_exit_code(findings) == 2
        apply_baseline(report, _baseline_with({"id": "L01-*"}, {"id": "W06-*"}))
        assert expected_exit_code(findings) == 0

    def test_format_summary_flags_expired_waivers(self, report):
        from baseline import apply_baseline, format_baseline_summary

        summary = apply_baseline(
            report,
            _baseline_with({"id": "L01-C1", "expires": "2020-01-01"}),
            today=date(2026, 1, 1),
        )
        text = format_baseline_summary(summary, no_colour=True)
        assert "expired" in text
        assert "L01-C1" in text

    def test_cli_create_and_show(self, report, tmp_path, capsys):
        import baseline

        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        out_path = tmp_path / "baseline.json"

        assert baseline.main(["create", str(report_path), "-o", str(out_path)]) == 0
        assert out_path.exists()

        assert baseline.main(["show", str(out_path)]) == 0
        assert "L01-C1" in capsys.readouterr().out

    def test_cli_apply_returns_clean_exit_when_everything_waived(self, report, tmp_path):
        import baseline

        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(json.dumps(_baseline_with({"id": "*"})), encoding="utf-8")

        annotated = tmp_path / "annotated.json"
        assert baseline.main(["apply", str(baseline_path), "--report", str(report_path),
                              "-o", str(annotated)]) == 0


# ── SARIF output ──────────────────────────────────────────────────────────────

class TestSarifGenerator:
    def _sarif(self, report, **kwargs):
        from report_generator import generate_sarif

        return json.loads(generate_sarif(report, **kwargs))

    def test_is_valid_sarif_envelope(self, report):
        doc = self._sarif(report)
        assert doc["version"] == "2.1.0"
        assert doc["$schema"].endswith("sarif-2.1.0.json")
        assert doc["runs"][0]["tool"]["driver"]["name"] == "CyberSWISS"

    def test_excludes_pass_findings_by_default(self, report):
        doc = self._sarif(report)
        rule_ids = {r["ruleId"] for r in doc["runs"][0]["results"]}
        assert rule_ids == {"L01-C1", "L01-C2", "W06-C1"}

    def test_include_passed_adds_pass_kind_results(self, report):
        doc = self._sarif(report, include_passed=True)
        results = {r["ruleId"]: r for r in doc["runs"][0]["results"]}
        assert results["W06-C2"]["kind"] == "pass"
        assert results["W06-C2"]["level"] == "none"

    def test_status_maps_to_sarif_level(self, report):
        results = {r["ruleId"]: r for r in self._sarif(report)["runs"][0]["results"]}
        assert results["L01-C1"]["level"] == "error"
        assert results["L01-C2"]["level"] == "warning"

    def test_security_severity_is_set_on_rules(self, report):
        rules = {r["id"]: r for r in self._sarif(report)["runs"][0]["tool"]["driver"]["rules"]}
        assert rules["W06-C1"]["properties"]["security-severity"] == "9.5"
        assert rules["L01-C1"]["properties"]["security-severity"] == "8.0"

    def test_results_are_anchored_to_the_check_script(self, report):
        results = {r["ruleId"]: r for r in self._sarif(report)["runs"][0]["results"]}
        linux_uri = results["L01-C1"]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        win_uri = results["W06-C1"]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert linux_uri == "linux/L01_password_policy.sh"
        assert win_uri == "windows/W06_firewall_state.ps1"

    def test_every_result_has_a_fingerprint(self, report):
        for result in self._sarif(report)["runs"][0]["results"]:
            assert result["partialFingerprints"]["cyberswissFindingId"]

    def test_remediation_becomes_rule_help(self, report):
        rules = {r["id"]: r for r in self._sarif(report)["runs"][0]["tool"]["driver"]["rules"]}
        assert "PASS_MAX_DAYS" in rules["L01-C1"]["help"]["text"]

    def test_baselined_findings_carry_sarif_suppressions(self, report):
        from baseline import apply_baseline

        apply_baseline(report, _baseline_with({"id": "L01-C1", "reason": "Signed off"}))
        results = {r["ruleId"]: r for r in self._sarif(report)["runs"][0]["results"]}
        assert results["L01-C1"]["suppressions"][0]["justification"] == "Signed off"
        assert "suppressions" not in results["W06-C1"]

    def test_timestamp_is_normalised_to_utc_z_form(self, report):
        doc = self._sarif(report)
        assert doc["runs"][0]["invocations"][0]["endTimeUtc"] == "2026-01-01T00:00:00Z"

    def test_handles_report_without_results(self):
        doc = self._sarif({"host": "h", "results": []})
        assert doc["runs"][0]["results"] == []


# ── Markdown output ───────────────────────────────────────────────────────────

class TestMarkdownGenerator:
    def test_reports_failure_verdict(self, report):
        from report_generator import generate_markdown

        md = generate_markdown(report)
        assert "Audit failed" in md
        assert "CyberSWISS Security Audit" in md

    def test_reports_pass_verdict_when_clean(self):
        from report_generator import generate_markdown

        clean = {"host": "h", "results": [{"script": "L01", "findings": [
            {"id": "L01-C1", "name": "ok", "severity": "Info", "status": "PASS"}]}]}
        assert "Audit passed" in generate_markdown(clean)

    def test_lists_actionable_findings_worst_first(self, report):
        from report_generator import generate_markdown

        md = generate_markdown(report)
        assert md.index("W06-C1") < md.index("L01-C1") < md.index("L01-C2")

    def test_pipes_in_text_are_escaped(self):
        from report_generator import generate_markdown

        piped = {"host": "h", "results": [{"script": "L01", "findings": [
            {"id": "L01-C1", "name": "a | b", "severity": "High", "status": "FAIL",
             "detail": "", "remediation": ""}]}]}
        assert "a \\| b" in generate_markdown(piped)

    def test_suppressed_findings_move_to_accepted_risk_section(self, report):
        from baseline import apply_baseline
        from report_generator import generate_markdown

        apply_baseline(report, _baseline_with({"id": "W06-C1", "reason": "Host is air-gapped"}))
        md = generate_markdown(report)
        assert "Accepted risk" in md
        assert "Host is air-gapped" in md
        assert "Audit failed" in md  # L01-C1 still fails

    def test_truncates_long_finding_lists(self):
        from report_generator import generate_markdown

        many = {"host": "h", "results": [{"script": "L01", "findings": [
            {"id": f"L01-C{i}", "name": f"f{i}", "severity": "High", "status": "FAIL",
             "detail": "", "remediation": ""} for i in range(30)]}]}
        md = generate_markdown(many, max_findings=10)
        assert "and 20 further finding(s)" in md


# ── Trend analytics ───────────────────────────────────────────────────────────

class TestTrendAnalytics:
    def _db_with_scans(self, tmp_path, fail_counts):
        from db import ScanDatabase

        db = ScanDatabase(db_path=tmp_path / "trend.db")
        for index, fails in enumerate(fail_counts):
            db.save_scan({
                "host": "testhost",
                "generated_at": f"2026-01-{index + 1:02d}T00:00:00+00:00",
                "scripts_run": 1,
                "fail_count": fails,
                "warn_count": 0,
                "total_findings": fails,
                "results": [{"script": "L01_password_policy", "findings": [
                    {"id": f"L01-C{n}", "name": f"f{n}", "severity": "High", "status": "FAIL"}
                    for n in range(fails)
                ]}],
            })
        return db

    def test_empty_history_returns_unknown_direction(self, tmp_path):
        from db import ScanDatabase

        trend = ScanDatabase(db_path=tmp_path / "empty.db").get_trend()
        assert trend["points"] == []
        assert trend["direction"] == "unknown"

    def test_points_are_oldest_first(self, tmp_path):
        trend = self._db_with_scans(tmp_path, [5, 3, 1]).get_trend()
        assert [p["fail_count"] for p in trend["points"]] == [5, 3, 1]

    def test_declining_failures_are_improving(self, tmp_path):
        trend = self._db_with_scans(tmp_path, [5, 3, 1]).get_trend()
        assert trend["direction"] == "improving"
        assert trend["delta"]["fail_count"] == -4

    def test_rising_failures_are_degrading(self, tmp_path):
        trend = self._db_with_scans(tmp_path, [1, 4]).get_trend()
        assert trend["direction"] == "degrading"
        assert trend["delta"]["fail_count"] == 3

    def test_unchanged_failures_are_stable(self, tmp_path):
        trend = self._db_with_scans(tmp_path, [2, 2]).get_trend()
        assert trend["direction"] == "stable"

    def test_single_scan_direction_is_unknown(self, tmp_path):
        trend = self._db_with_scans(tmp_path, [2]).get_trend()
        assert trend["direction"] == "unknown"

    def test_limit_bounds_the_window(self, tmp_path):
        trend = self._db_with_scans(tmp_path, [5, 4, 3, 2, 1]).get_trend(limit=2)
        assert [p["fail_count"] for p in trend["points"]] == [2, 1]

    def test_host_filter_excludes_other_hosts(self, tmp_path):
        db = self._db_with_scans(tmp_path, [3, 2])
        assert db.get_trend(host="testhost")["scan_count"] == 2
        assert db.get_trend(host="otherhost")["points"] == []

    def test_severity_breakdown_is_included(self, tmp_path):
        trend = self._db_with_scans(tmp_path, [2, 2]).get_trend()
        assert trend["points"][-1]["severity"] == {"High": 2}

    def test_worst_scripts_reflect_the_latest_scan(self, tmp_path):
        trend = self._db_with_scans(tmp_path, [1, 3]).get_trend()
        assert trend["worst_scripts"][0]["script"] == "L01_password_policy"
        assert trend["worst_scripts"][0]["fail_count"] == 3

    def test_format_trend_report_is_readable(self, tmp_path):
        from db import format_trend_report

        text = format_trend_report(self._db_with_scans(tmp_path, [5, 1]).get_trend(), no_colour=True)
        assert "POSTURE TREND REPORT" in text
        assert "IMPROVING" in text
        assert "\033[" not in text

    def test_format_trend_report_handles_empty_history(self):
        from db import format_trend_report

        text = format_trend_report({"points": []}, no_colour=True)
        assert "No scan history" in text

    def test_sparkline_scales_to_the_peak(self):
        from db import _sparkline

        assert _sparkline([0, 0]) == "▁▁"
        assert _sparkline([]) == ""
        assert _sparkline([0, 10])[-1] == "█"


# ── Runner wiring ─────────────────────────────────────────────────────────────

class TestRunnerGovernanceFlags:
    def _parse(self, argv):
        import runner

        old = sys.argv
        sys.argv = ["runner.py", *argv]
        try:
            return runner.parse_args()
        finally:
            sys.argv = old

    def test_accepts_sarif_and_markdown_flags(self):
        args = self._parse(["--sarif", "a.sarif", "--markdown", "a.md"])
        assert args.sarif == "a.sarif"
        assert args.markdown == "a.md"

    def test_accepts_baseline_flags(self):
        args = self._parse(["--baseline", "b.json", "--write-baseline", "n.json",
                            "--baseline-expires", "2027-01-01"])
        assert args.baseline == "b.json"
        assert args.write_baseline == "n.json"
        assert args.baseline_expires == "2027-01-01"

    def test_trend_defaults_to_ten_when_given_without_a_value(self):
        assert self._parse(["--trend"]).trend == 10

    def test_trend_accepts_an_explicit_window(self):
        assert self._parse(["--trend", "25"]).trend == 25

    def test_governance_flags_default_to_off(self):
        args = self._parse([])
        assert args.sarif is None and args.markdown is None
        assert args.baseline is None and args.write_baseline is None
        assert args.trend is None

    def test_emit_trend_reports_history(self, tmp_path, monkeypatch, capsys):
        import db as db_module
        import runner

        db_path = tmp_path / "trend.db"
        real_db = db_module.ScanDatabase
        monkeypatch.setattr(db_module, "ScanDatabase", lambda *a, **kw: real_db(db_path=db_path))
        trend = runner.emit_trend(5, no_colour=True, json_mode=False)
        assert trend is not None and trend["points"] == []
        assert "POSTURE TREND REPORT" in capsys.readouterr().out

    def test_emit_trend_warns_instead_of_raising_on_db_failure(self, monkeypatch, capsys):
        import db as db_module
        import runner

        def _boom(*_args, **_kwargs):
            raise RuntimeError("database unavailable")

        monkeypatch.setattr(db_module, "ScanDatabase", _boom)
        assert runner.emit_trend(5, no_colour=True, json_mode=True) is None
        assert "Trend analysis failed" in capsys.readouterr().err

    def test_invalid_baseline_file_aborts_before_scanning(self, tmp_path, monkeypatch, capsys):
        import runner

        bad = tmp_path / "bad.json"
        bad.write_text("{", encoding="utf-8")
        monkeypatch.setattr(sys, "argv", ["runner.py", "--baseline", str(bad), "--dry-run"])
        assert runner.main() == 1
        assert "ERROR" in capsys.readouterr().err


# ── API surface ───────────────────────────────────────────────────────────────

class TestApiGovernanceEndpoints:
    def test_trend_handler_exists(self):
        import api

        assert hasattr(api.CyberSWISSHandler, "handle_trend")

    def test_report_formats_are_declared(self):
        import api

        assert set(api.CyberSWISSHandler.REPORT_FORMATS) == {
            "html", "json", "sarif", "markdown", "csv", "text"
        }

    def test_version_reflects_the_extended_surface(self):
        import api

        assert api.VERSION >= "1.1.0"
