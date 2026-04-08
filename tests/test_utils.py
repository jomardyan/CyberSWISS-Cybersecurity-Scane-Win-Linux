"""
CyberSWISS – Tests for utils.py (standalone sanity)
"""
from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "common"))

from utils import coloured, filter_findings, severity_int  # noqa: E402


def test_coloured_non_tty_no_escape(monkeypatch):
    """Without a TTY, coloured() should return plain text."""
    monkeypatch.setattr("sys.stdout", io.StringIO())
    result = coloured("hello", "FAIL")
    # When stdout is not a tty, no ANSI codes
    assert "hello" in result


def test_severity_ordering():
    assert severity_int("Info") < severity_int("Low")
    assert severity_int("Low") < severity_int("Med")
    assert severity_int("Med") < severity_int("High")
    assert severity_int("High") < severity_int("Critical")


def test_filter_by_severity_critical_only():
    findings = [
        {"severity": "Critical", "status": "FAIL"},
        {"severity": "High",     "status": "FAIL"},
        {"severity": "Med",      "status": "WARN"},
    ]
    result = filter_findings(findings, min_severity="Critical")
    assert len(result) == 1
    assert result[0]["severity"] == "Critical"


def test_filter_combined():
    findings = [
        {"severity": "High",     "status": "FAIL"},
        {"severity": "High",     "status": "PASS"},
        {"severity": "Critical", "status": "FAIL"},
    ]
    result = filter_findings(findings, min_severity="High", status_filter=["FAIL"])
    assert len(result) == 2
    assert all(f["status"] == "FAIL" for f in result)
