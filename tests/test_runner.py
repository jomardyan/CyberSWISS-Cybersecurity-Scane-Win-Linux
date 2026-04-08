"""
CyberSWISS – Tests for runner.py and utils.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure common/ is on path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "common"))

import utils  # noqa: E402
from utils import (  # noqa: E402
    current_host,
    current_os,
    discover_scripts,
    expected_exit_code,
    filter_findings,
    now_iso,
    parse_json_output,
    run_script,
    save_json_report,
    severity_int,
)


# ── utils tests ────────────────────────────────────────────────────────────────

class TestCurrentOs:
    def test_returns_valid_os(self):
        result = current_os()
        assert result in ("windows", "linux", "unknown")

    @patch("platform.system", return_value="Windows")
    def test_windows_detection(self, _mock):
        assert current_os() == "windows"

    @patch("platform.system", return_value="Linux")
    def test_linux_detection(self, _mock):
        assert current_os() == "linux"


class TestCurrentHost:
    def test_returns_non_empty_host(self):
        assert current_host()


class TestDiscoverScripts:
    def test_returns_list(self):
        scripts = discover_scripts()
        assert isinstance(scripts, list)

    def test_linux_filter(self):
        scripts = discover_scripts(os_filter="linux")
        for s in scripts:
            assert s["os"] == "linux"

    def test_windows_filter(self):
        scripts = discover_scripts(os_filter="windows")
        for s in scripts:
            assert s["os"] == "windows"

    def test_script_has_required_keys(self):
        scripts = discover_scripts()
        for s in scripts:
            for key in ("id", "name", "path", "os", "lang"):
                assert key in s, f"Missing key '{key}' in script {s}"

    def test_scripts_exist_on_disk(self):
        scripts = discover_scripts()
        for s in scripts:
            assert Path(s["path"]).exists(), f"Script not found: {s['path']}"

    def test_linux_scripts_are_executable(self):
        scripts = discover_scripts(os_filter="linux")
        for s in scripts:
            p = Path(s["path"])
            assert os.access(str(p), os.X_OK), f"Script not executable: {p}"

    def test_30_or_more_scripts_total(self):
        scripts = discover_scripts()
        assert len(scripts) >= 30, f"Expected >= 30 scripts, got {len(scripts)}"

    def test_at_least_15_linux_scripts(self):
        linux_scripts = discover_scripts(os_filter="linux")
        assert len(linux_scripts) >= 15, f"Expected >= 15 linux scripts, got {len(linux_scripts)}"

    def test_at_least_15_windows_scripts(self):
        win_scripts = discover_scripts(os_filter="windows")
        assert len(win_scripts) >= 15, f"Expected >= 15 windows scripts, got {len(win_scripts)}"

    def test_script_ids_are_unique(self):
        scripts = discover_scripts()
        ids = [s["id"] for s in scripts]
        assert len(ids) == len(set(ids)), f"Duplicate script IDs found: {ids}"


class TestSeverityInt:
    def test_known_severities(self):
        assert severity_int("Info") == 0
        assert severity_int("Low") == 1
        assert severity_int("Med") == 2
        assert severity_int("High") == 3
        assert severity_int("Critical") == 4

    def test_unknown_severity_returns_negative(self):
        assert severity_int("Unknown") == -1


class TestFilterFindings:
    SAMPLE = [
        {"id": "T1", "status": "FAIL", "severity": "High"},
        {"id": "T2", "status": "WARN", "severity": "Med"},
        {"id": "T3", "status": "PASS", "severity": "Low"},
        {"id": "T4", "status": "FAIL", "severity": "Critical"},
        {"id": "T5", "status": "INFO", "severity": "Info"},
    ]

    def test_no_filter(self):
        result = filter_findings(self.SAMPLE)
        assert len(result) == 5

    def test_min_severity_high(self):
        result = filter_findings(self.SAMPLE, min_severity="High")
        assert all(f["severity"] in ("High", "Critical") for f in result)
        assert len(result) == 2

    def test_status_filter_fail(self):
        result = filter_findings(self.SAMPLE, status_filter=["FAIL"])
        assert all(f["status"] == "FAIL" for f in result)
        assert len(result) == 2

    def test_combined_filter(self):
        result = filter_findings(self.SAMPLE, min_severity="High", status_filter=["FAIL"])
        assert len(result) == 2

    def test_empty_list(self):
        assert filter_findings([]) == []


class TestNowIso:
    def test_returns_string(self):
        ts = now_iso()
        assert isinstance(ts, str)
        assert "T" in ts
        assert ts.endswith("+00:00") or ts.endswith("Z") or "+" in ts


class TestSaveAndLoadJsonReport:
    def test_round_trip(self, tmp_path):
        data = {"key": "value", "findings": [{"id": "X1", "status": "PASS"}]}
        out = tmp_path / "test_report.json"
        save_json_report(data, out)
        loaded = utils.load_json_report(out)
        assert loaded == data

    def test_creates_parent_dirs(self, tmp_path):
        nested = tmp_path / "deep" / "nested" / "report.json"
        save_json_report({"x": 1}, nested)
        assert nested.exists()


class TestRunScript:
    def test_missing_script_returns_error(self):
        result = run_script("/nonexistent/script.sh")
        assert "error" in result
        assert result["exit_code"] == -1

    def test_unsupported_extension(self, tmp_path):
        p = tmp_path / "test.py"
        p.write_text("print('hello')")
        result = run_script(str(p))
        assert "error" in result
        assert result["exit_code"] == -1

    def test_simple_bash_script(self, tmp_path):
        """Test that a simple bash script returning JSON is handled correctly."""
        if current_os() != "linux":
            pytest.skip("Bash test only runs on Linux")
        script = tmp_path / "test_script.sh"
        script.write_text(
            '#!/usr/bin/env bash\n'
            'echo \'{"script":"test","host":"localhost","findings":[]}\'\n'
        )
        script.chmod(0o755)
        result = run_script(str(script), json_mode=True)
        assert result.get("script") == "test"
        assert result.get("findings") == []

    def test_timeout_handling(self, tmp_path):
        """Test that script timeout is handled gracefully."""
        if current_os() != "linux":
            pytest.skip("Bash test only runs on Linux")
        script = tmp_path / "slow_script.sh"
        script.write_text("#!/usr/bin/env bash\nsleep 60\n")
        script.chmod(0o755)
        result = run_script(str(script), timeout=1, json_mode=True)
        assert "error" in result
        assert result["exit_code"] == -2

    def test_normalises_exit_code_from_findings(self, tmp_path):
        if current_os() != "linux":
            pytest.skip("Bash test only runs on Linux")
        script = tmp_path / "pass_but_bad_exit.sh"
        script.write_text(
            '#!/usr/bin/env bash\n'
            'echo \'{"script":"pass_but_bad_exit","host":"localhost","findings":[{"id":"X1","status":"PASS","severity":"Low"}]}\'\n'
            'exit 1\n'
        )
        script.chmod(0o755)
        result = run_script(str(script), json_mode=True)
        assert result["exit_code"] == 0
        assert result["raw_exit_code"] == 1

    def test_extracts_json_from_noisy_stdout(self, tmp_path):
        if current_os() != "linux":
            pytest.skip("Bash test only runs on Linux")
        script = tmp_path / "noisy_json.sh"
        script.write_text(
            '#!/usr/bin/env bash\n'
            'echo "warning: preamble"\n'
            'echo \'{"script":"noisy_json","host":"localhost","findings":[]}\'\n'
        )
        script.chmod(0o755)
        result = run_script(str(script), json_mode=True)
        assert result["script"] == "noisy_json"
        assert result["findings"] == []

    def test_nonzero_without_json_reports_error(self, tmp_path):
        if current_os() != "linux":
            pytest.skip("Bash test only runs on Linux")
        script = tmp_path / "no_json_failure.sh"
        script.write_text("#!/usr/bin/env bash\nexit 1\n")
        script.chmod(0o755)
        result = run_script(str(script), json_mode=True)
        assert "error" in result
        assert result["exit_code"] == 1


class TestJsonParsingHelpers:
    def test_parse_json_output_accepts_trailing_json_object(self):
        parsed = parse_json_output('noise before\n{"script":"x","findings":[]}')
        assert parsed is not None
        assert parsed["script"] == "x"

    def test_expected_exit_code_prefers_fail_over_warn(self):
        findings = [
            {"status": "WARN"},
            {"status": "FAIL"},
        ]
        assert expected_exit_code(findings) == 2


# ── Integration: verify all scripts have correct shebang/metadata ──────────────
class TestScriptMetadata:
    def test_bash_scripts_have_shebang(self):
        for script_path in (REPO_ROOT / "linux").glob("*.sh"):
            first_line = script_path.read_text(encoding="utf-8").splitlines()[0]
            assert first_line.startswith("#!/"), \
                f"{script_path.name} missing shebang"
            assert "bash" in first_line or "env" in first_line, \
                f"{script_path.name} shebang should use bash"

    def test_ps1_scripts_have_requires(self):
        for script_path in (REPO_ROOT / "windows").glob("*.ps1"):
            content = script_path.read_text(encoding="utf-8")
            assert "#Requires" in content or ".SYNOPSIS" in content, \
                f"{script_path.name} missing #Requires or .SYNOPSIS"

    def test_linux_scripts_support_json_flag(self):
        """Verify all Linux scripts contain --json flag handling."""
        for script_path in (REPO_ROOT / "linux").glob("*.sh"):
            content = script_path.read_text(encoding="utf-8")
            assert "--json" in content, \
                f"{script_path.name} missing --json flag support"

    def test_linux_scripts_have_exit_codes(self):
        """Verify all Linux scripts have exit code logic."""
        for script_path in (REPO_ROOT / "linux").glob("*.sh"):
            content = script_path.read_text(encoding="utf-8")
            assert "exit" in content, \
                f"{script_path.name} missing exit code"

    def test_scripts_contain_add_finding_function(self):
        """Verify all Linux scripts define add_finding."""
        for script_path in (REPO_ROOT / "linux").glob("*.sh"):
            content = script_path.read_text(encoding="utf-8")
            assert "add_finding()" in content, \
                f"{script_path.name} missing add_finding() function"

    def test_windows_scripts_support_json_flag(self):
        """Verify all PowerShell scripts have -Json parameter."""
        for script_path in (REPO_ROOT / "windows").glob("*.ps1"):
            content = script_path.read_text(encoding="utf-8")
            assert "[switch]$Json" in content or "switch]$Json" in content, \
                f"{script_path.name} missing -Json parameter"

    def test_linux_scripts_support_fix_flag(self):
        """Verify all Linux scripts accept --fix flag."""
        for script_path in (REPO_ROOT / "linux").glob("*.sh"):
            content = script_path.read_text(encoding="utf-8")
            assert "--fix" in content, \
                f"{script_path.name} missing --fix flag support"

    def test_linux_scripts_have_fix_mode_variable(self):
        """Verify all Linux scripts declare FIX_MODE variable."""
        for script_path in (REPO_ROOT / "linux").glob("*.sh"):
            content = script_path.read_text(encoding="utf-8")
            assert "FIX_MODE=false" in content, \
                f"{script_path.name} missing FIX_MODE=false declaration"

    def test_windows_scripts_support_fix_flag(self):
        """Verify all PowerShell scripts have -Fix switch parameter."""
        for script_path in (REPO_ROOT / "windows").glob("*.ps1"):
            content = script_path.read_text(encoding="utf-8")
            assert "[switch]$Fix" in content, \
                f"{script_path.name} missing -Fix parameter"

    def test_linux_scripts_readonly_by_default(self):
        """Verify Linux scripts default to read-only (FIX_MODE starts as false)."""
        for script_path in (REPO_ROOT / "linux").glob("*.sh"):
            content = script_path.read_text(encoding="utf-8")
            # FIX_MODE must be initialised to false
            assert "FIX_MODE=false" in content, \
                f"{script_path.name}: FIX_MODE not initialised to false (not read-only by default)"

    def test_new_linux_scripts_exist(self):
        """Verify new extended security Linux scripts (L16-L28) are present."""
        for script_id in ("L16", "L17", "L18", "L19", "L20", "L21", "L22", "L23",
                          "L24", "L25", "L26", "L27", "L28"):
            matches = list((REPO_ROOT / "linux").glob(f"{script_id}_*.sh"))
            assert len(matches) == 1, f"Expected exactly one script for {script_id}, found: {matches}"

    def test_new_windows_scripts_exist(self):
        """Verify new extended security Windows scripts (W16-W28) are present."""
        for script_id in ("W16", "W17", "W18", "W19", "W20", "W21", "W22", "W23",
                          "W24", "W25", "W26", "W27", "W28"):
            matches = list((REPO_ROOT / "windows").glob(f"{script_id}_*.ps1"))
            assert len(matches) == 1, f"Expected exactly one script for {script_id}, found: {matches}"

    def test_windows_scripts_have_synopsis(self):
        """Verify all PowerShell scripts have .SYNOPSIS documentation block."""
        for script_path in (REPO_ROOT / "windows").glob("*.ps1"):
            content = script_path.read_text(encoding="utf-8")
            assert ".SYNOPSIS" in content, \
                f"{script_path.name} missing .SYNOPSIS documentation"

    def test_windows_scripts_have_author(self):
        """Verify all PowerShell scripts attribute to CyberSWISS Security Team."""
        for script_path in (REPO_ROOT / "windows").glob("*.ps1"):
            content = script_path.read_text(encoding="utf-8")
            assert "CyberSWISS" in content, \
                f"{script_path.name} missing CyberSWISS attribution"


# ── runner module smoke tests ──────────────────────────────────────────────────
class TestRunnerModule:
    def test_runner_importable(self):
        import runner  # noqa: F401

    def test_runner_select_scripts_linux(self):
        """runner.select_scripts should return Linux scripts when os_filter=linux."""
        import runner
        import argparse
        args = argparse.Namespace(
            os_filter="linux",
            scripts=None,
        )
        scripts = runner.select_scripts(args)
        assert all(s["os"] == "linux" for s in scripts)
        assert len(scripts) >= 15

    def test_runner_dry_run(self, capsys):
        """Dry-run mode should list scripts without executing any of them."""
        import runner
        from unittest.mock import patch
        with patch.object(sys, 'argv', ['runner.py', '--dry-run', '--os', 'linux', '--no-colour']):
            with patch('runner.run_script') as mock_run:
                rc = runner.main()
        # Should succeed without running any scripts
        assert rc == 0
        mock_run.assert_not_called()
        captured = capsys.readouterr()
        assert "would run" in captured.out
        assert "L01" in captured.out

    def test_runner_dry_run_json_output(self, capsys):
        """Dry-run --json mode should produce a valid JSON report with dry_run=true."""
        import runner
        import json
        from unittest.mock import patch
        with patch.object(sys, 'argv', ['runner.py', '--dry-run', '--os', 'linux', '--json']):
            with patch('runner.run_script') as mock_run:
                rc = runner.main()
        assert rc == 0
        mock_run.assert_not_called()
        captured = capsys.readouterr()
        report = json.loads(captured.out)
        assert report["dry_run"] is True
        assert report["cyberswiss_report"] is True
        assert isinstance(report["scripts"], list)
        assert len(report["scripts"]) >= 15
        for entry in report["scripts"]:
            for key in ("id", "os", "lang", "path", "name"):
                assert key in entry, f"Missing key '{key}' in dry-run entry"

    def test_runner_dry_run_with_id_filter(self, capsys):
        """Dry-run with --scripts filter should only list the requested script IDs."""
        import runner
        from unittest.mock import patch
        with patch.object(sys, 'argv', ['runner.py', '--dry-run', '--os', 'linux', '--scripts', 'L01', 'L07', '--no-colour']):
            with patch('runner.run_script') as mock_run:
                rc = runner.main()
        assert rc == 0
        mock_run.assert_not_called()
        captured = capsys.readouterr()
        assert "L01" in captured.out
        assert "L07" in captured.out
        # Other scripts should not appear
        assert "L03" not in captured.out

    def test_runner_dry_run_exit_code_zero(self):
        """Dry-run should return exit code 0 without executing any scripts."""
        import runner
        from unittest.mock import patch
        with patch.object(sys, 'argv', ['runner.py', '--dry-run', '--os', 'linux', '--no-colour']):
            with patch('runner.run_script') as mock_run:
                rc = runner.main()
        assert rc == 0
        mock_run.assert_not_called()

    def test_runner_has_fix_argument(self):
        """runner.py parse_args should accept --fix without error."""
        import runner
        import sys
        from unittest.mock import patch
        # Patch sys.argv to simulate --fix being passed
        with patch.object(sys, 'argv', ['runner.py', '--fix', '--dry-run']):
            args = runner.parse_args()
        assert args.fix is True

    def test_run_script_fix_mode_passes_flag(self, tmp_path):
        """run_script with fix_mode=True should pass --fix to bash scripts."""
        if current_os() != "linux":
            pytest.skip("Bash test only runs on Linux")
        # Script that echoes its arguments so we can verify --fix is passed
        script = tmp_path / "check_fix.sh"
        script.write_text(
            '#!/usr/bin/env bash\n'
            'FIX=false\n'
            'for arg in "$@"; do [[ "$arg" == "--fix" ]] && FIX=true; done\n'
            'echo \'{"script":"check_fix","host":"localhost","fix_received":"\'"$FIX"\'","findings":[]}\'\n'
        )
        script.chmod(0o755)
        result = run_script(str(script), json_mode=True, fix_mode=True)
        assert result.get("fix_received") == "true"

    def test_runner_json_mode_uses_findings_for_exit_code(self, capsys):
        import runner
        from unittest.mock import patch

        fake_script = {
            "id": "L01",
            "name": "L01_password_policy",
            "path": "/tmp/L01_password_policy.sh",
            "os": "linux",
        }
        fake_result = {
            "script": "L01_password_policy",
            "host": "localhost",
            "findings": [{"id": "L01-C1", "status": "FAIL", "severity": "High"}],
            "exit_code": 0,
        }

        with patch.object(sys, 'argv', ['runner.py', '--json']):
            with patch('runner.select_scripts', return_value=[fake_script]):
                with patch('runner.run_script', return_value=fake_result):
                    rc = runner.main()

        captured = capsys.readouterr()
        report = json.loads(captured.out)
        assert report["fail_count"] == 1
        assert rc == 2

    def test_runner_returns_130_on_keyboard_interrupt(self, capsys):
        import runner
        from unittest.mock import patch

        fake_script = {
            "id": "L01",
            "name": "L01_password_policy",
            "path": "/tmp/L01_password_policy.sh",
            "os": "linux",
        }

        with patch.object(sys, "argv", ["runner.py", "--os", "linux", "--no-colour"]):
            with patch("runner.select_scripts", return_value=[fake_script]):
                with patch("runner.run_script", side_effect=KeyboardInterrupt):
                    rc = runner.main()

        captured = capsys.readouterr()
        assert rc == 130
        assert "Audit interrupted by user" in captured.err

    def test_runner_fix_mode_reaudits_and_uses_verification_findings(self, capsys):
        import runner
        from unittest.mock import patch

        fake_script = {
            "id": "L01",
            "name": "L01_password_policy",
            "path": "/tmp/L01_password_policy.sh",
            "os": "linux",
        }
        audit_result = {
            "script": "L01_password_policy",
            "host": "localhost",
            "findings": [
                {"id": "L01-C1", "name": "Password length", "status": "FAIL", "severity": "High"},
            ],
            "exit_code": 2,
        }
        verify_result = {
            "script": "L01_password_policy",
            "host": "localhost",
            "findings": [
                {"id": "L01-C1", "name": "Password length", "status": "PASS", "severity": "High"},
            ],
            "exit_code": 0,
        }

        with patch.object(sys, "argv", ["runner.py", "--json", "--fix"]):
            with patch("runner.select_scripts", return_value=[fake_script]):
                with patch("runner.run_script", side_effect=[audit_result, verify_result]) as mock_run:
                    rc = runner.main()

        captured = capsys.readouterr()
        report = json.loads(captured.out)
        assert rc == 0
        assert mock_run.call_count == 2
        assert report["results"][0]["findings"][0]["status"] == "PASS"
        assert report["results"][0]["fix_report"]["fixed_count"] == 1
        assert report["results"][0]["fix_report"]["remaining_count"] == 0
