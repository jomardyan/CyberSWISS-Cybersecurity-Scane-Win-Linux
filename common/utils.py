"""
CyberSWISS – Common Utilities
Shared helpers for the orchestrator, report generator, and GUI.
"""
from __future__ import annotations

import json
import os
import platform
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ── Constants ──────────────────────────────────────────────────────────────────
SEVERITY_ORDER = {"Info": 0, "Low": 1, "Med": 2, "High": 3, "Critical": 4}
STATUS_COLOURS = {
    "PASS": "\033[0;32m",
    "FAIL": "\033[0;31m",
    "WARN": "\033[0;33m",
    "INFO": "\033[0;36m",
}
RESET = "\033[0m"

REPO_ROOT = Path(__file__).resolve().parent.parent


# ── OS Detection ───────────────────────────────────────────────────────────────
def current_os() -> str:
    """Return 'windows', 'linux', or 'unknown'."""
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    if system == "linux":
        return "linux"
    return "unknown"


def current_host() -> str:
    """Return the best available local hostname for reports and logs."""
    candidates = [
        os.environ.get("COMPUTERNAME"),
        os.environ.get("HOSTNAME"),
        platform.node(),
        socket.gethostname(),
    ]
    if hasattr(os, "uname"):
        try:
            candidates.append(os.uname().nodename)
        except OSError:
            pass

    for value in candidates:
        if value and value.strip():
            return value.strip()
    return "localhost"


# ── Script Discovery ───────────────────────────────────────────────────────────
def discover_scripts(os_filter: str | None = None) -> list[dict[str, Any]]:
    """
    Walk windows/ and linux/ directories and return script metadata.

    Returns a list of dicts with keys:
        id, name, path, os, lang, admin_required
    """
    scripts: list[dict[str, Any]] = []

    os_dirs: dict[str, str] = {
        "windows": str(REPO_ROOT / "windows"),
        "linux": str(REPO_ROOT / "linux"),
    }

    for os_name, dir_path in os_dirs.items():
        if os_filter and os_filter.lower() != os_name:
            continue
        dir_ = Path(dir_path)
        if not dir_.exists():
            continue

        # Windows scripts: *.ps1, Linux scripts: *.sh
        extensions = ["*.ps1"] if os_name == "windows" else ["*.sh"]
        for ext in extensions:
            for script_path in sorted(dir_.glob(ext)):
                script_id = script_path.stem.split("_")[0]  # e.g. W01, L07
                name = script_path.stem  # e.g. W01_password_policy
                lang = "PowerShell" if script_path.suffix == ".ps1" else "Bash"
                category = _extract_script_category(script_path)
                scripts.append(
                    {
                        "id": script_id,
                        "name": name,
                        "path": str(script_path),
                        "os": os_name,
                        "lang": lang,
                        "admin_required": True,  # conservative default
                        "category": category,
                    }
                )

    return scripts


def _extract_script_category(script_path: Path) -> str:
    """
    Extract the ``Category`` value from the header comment block of a script.

    Looks for a line matching::

        # Category : <value>          (Bash)
        # Category : <value>          (PowerShell)

    Returns an empty string when no such line is found within the first
    50 lines (to avoid reading large files unnecessarily).
    """
    try:
        with open(script_path, encoding="utf-8", errors="ignore") as fh:
            for i, line in enumerate(fh):
                if i >= 50:
                    break
                stripped = line.strip().lstrip("#").strip()
                if stripped.lower().startswith("category"):
                    parts = stripped.split(":", 1)
                    if len(parts) == 2:
                        return parts[1].strip()
    except OSError:
        pass
    return ""


# ── Finding Helpers ────────────────────────────────────────────────────────────
def severity_int(severity: str) -> int:
    """Convert severity string to int for sorting."""
    return SEVERITY_ORDER.get(severity, -1)


def filter_findings(
    findings: list[dict],
    min_severity: str | None = None,
    status_filter: list[str] | None = None,
) -> list[dict]:
    """Filter a list of finding dicts."""
    result = findings
    if min_severity:
        min_int = SEVERITY_ORDER.get(min_severity, 0)
        result = [f for f in result if SEVERITY_ORDER.get(f.get("severity", ""), 0) >= min_int]
    if status_filter:
        upper_filter = [s.upper() for s in status_filter]
        result = [f for f in result if f.get("status", "").upper() in upper_filter]
    return result


# ── Output Helpers ─────────────────────────────────────────────────────────────
def coloured(text: str, status: str) -> str:
    """Wrap text with ANSI colour based on status."""
    if not sys.stdout.isatty():
        return text
    colour = STATUS_COLOURS.get(status.upper(), "")
    return f"{colour}{text}{RESET}"


def now_iso() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(tz=timezone.utc).isoformat()


# ── JSON I/O ───────────────────────────────────────────────────────────────────
def load_json_report(path: str | Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def save_json_report(data: dict, path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)


def expected_exit_code(findings: list[dict[str, Any]] | None) -> int:
    """Derive the canonical exit code from finding statuses."""
    findings = findings or []
    if any(f.get("status") == "FAIL" for f in findings):
        return 2
    if any(f.get("status") == "WARN" for f in findings):
        return 1
    return 0


def parse_json_output(stdout: str) -> dict[str, Any] | None:
    """
    Parse JSON emitted by a script.

    Some scripts print warnings or banners before the final JSON object. This
    helper accepts clean JSON and also scans for a trailing JSON object.
    """
    stripped = stdout.strip()
    if not stripped:
        return None

    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, dict):
        return data

    decoder = json.JSONDecoder()
    for start, char in enumerate(stripped):
        if char != "{":
            continue
        try:
            decoded, end = decoder.raw_decode(stripped[start:])
        except json.JSONDecodeError:
            continue
        if stripped[start + end :].strip():
            continue
        if isinstance(decoded, dict):
            return decoded

    return None


# ── Script Runner ──────────────────────────────────────────────────────────────
def run_script(
    script_path: str,
    json_mode: bool = True,
    timeout: int = 300,
    extra_args: list[str] | None = None,
    fix_mode: bool = False,
) -> dict[str, Any]:
    """
    Execute a single audit script and return its JSON output as a dict.

    Returns a dict with at minimum:
        script, host, timestamp, findings, exit_code, error (if any)
    """
    path = Path(script_path)
    if not path.exists():
        return {
            "script": path.stem,
            "error": f"Script not found: {script_path}",
            "findings": [],
            "exit_code": -1,
        }

    args: list[str] = []
    if path.suffix == ".ps1":
        args = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(path)]
    elif path.suffix == ".sh":
        args = ["bash", str(path)]
    else:
        return {"script": path.stem, "error": "Unsupported script type", "findings": [], "exit_code": -1}

    if json_mode:
        # PowerShell uses switch parameter style; Bash scripts use GNU-style flag
        args.append("-Json" if path.suffix == ".ps1" else "--json")
    if fix_mode:
        # PowerShell uses switch parameter style; Bash scripts use GNU-style flag
        args.append("-Fix" if path.suffix == ".ps1" else "--fix")
    if extra_args:
        args.extend(extra_args)

    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        exit_code = result.returncode
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if json_mode and stdout:
            data = parse_json_output(stdout)
            if data is not None:
                findings = data.get("findings", [])
                normalised_exit_code = expected_exit_code(findings)
                data.setdefault("script", path.stem)
                data.setdefault("findings", findings if isinstance(findings, list) else [])
                if exit_code != normalised_exit_code:
                    data["raw_exit_code"] = exit_code
                data["exit_code"] = normalised_exit_code
                if stderr:
                    data["stderr"] = stderr
                return data

        if json_mode and exit_code != 0 and not stdout:
            error = f"Script exited with code {exit_code} without emitting JSON output"
            if stderr:
                error = f"{error}: {stderr}"
            return {
                "script": path.stem,
                "error": error,
                "stderr": stderr,
                "exit_code": exit_code,
                "findings": [],
            }

        return {
            "script": path.stem,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "findings": [],
        }

    except subprocess.TimeoutExpired:
        return {
            "script": path.stem,
            "error": f"Script timed out after {timeout}s",
            "findings": [],
            "exit_code": -2,
        }
    except Exception as exc:  # pylint: disable=broad-except
        return {
            "script": path.stem,
            "error": str(exc),
            "findings": [],
            "exit_code": -3,
        }
