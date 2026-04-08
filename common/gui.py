#!/usr/bin/env python3
"""
CyberSWISS - Tkinter GUI
========================
Interactive operator console for selecting, running, reviewing, and exporting
CyberSWISS audit results.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import signal
import subprocess
import sys
import threading
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = REPO_ROOT / "reports"
STATUS_SORT_ORDER = {"FAIL": 0, "WARN": 1, "PASS": 2, "INFO": 3}


def _set_dpi_awareness() -> None:
    """Enable per-monitor DPI awareness on Windows."""
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except AttributeError:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except AttributeError:
            pass
    except OSError:
        pass


_set_dpi_awareness()

# Ensure common/ is importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext, ttk
except ImportError:
    print("ERROR: tkinter is not available. Install python3-tk.", file=sys.stderr)
    sys.exit(1)

from utils import (  # noqa: E402
    SEVERITY_ORDER,
    current_host,
    current_os,
    discover_scripts,
    expected_exit_code,
    now_iso,
    parse_json_output,
)


_BG = "#0b1320"
_BG_PANEL = "#111c2d"
_BG_PANEL_ALT = "#16253d"
_BG_CTRL = "#17304f"
_BG_OUTPUT = "#08111d"
_FG = "#ecf2f8"
_FG_DIM = "#93a4b7"
_ACCENT = "#4de2c5"
_ACCENT_SOFT = "#2a766f"
_GREEN = "#63d471"
_RED = "#ff6b6b"
_ORANGE = "#ffb347"
_BLUE = "#69a8ff"
_CARD_BG = "#12233a"

STATUS_COLOURS_TK: dict[str, str] = {
    "PASS": _GREEN,
    "FAIL": _RED,
    "WARN": _ORANGE,
    "INFO": _BLUE,
}


class ToolTip:
    """Small hover tooltip for Tk widgets."""

    def __init__(self, widget: tk.Widget, text: str, delay_ms: int = 450) -> None:
        self.widget = widget
        self.text = text
        self.delay_ms = delay_ms
        self._after_id: str | None = None
        self._tip_window: tk.Toplevel | None = None

        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule(self, _event: tk.Event[tk.Widget] | None = None) -> None:
        self._cancel()
        self._after_id = self.widget.after(self.delay_ms, self._show)

    def _cancel(self) -> None:
        if self._after_id is not None:
            self.widget.after_cancel(self._after_id)
            self._after_id = None

    def _show(self) -> None:
        if self._tip_window is not None or not self.text.strip():
            return

        x = self.widget.winfo_rootx() + 14
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 10
        self._tip_window = tk.Toplevel(self.widget)
        self._tip_window.wm_overrideredirect(True)
        self._tip_window.wm_geometry(f"+{x}+{y}")
        self._tip_window.configure(bg=_ACCENT_SOFT)

        label = tk.Label(
            self._tip_window,
            text=self.text,
            justify=tk.LEFT,
            bg=_CARD_BG,
            fg=_FG,
            relief=tk.FLAT,
            bd=0,
            padx=8,
            pady=6,
            font=("Segoe UI", 8),
            wraplength=320,
        )
        label.pack()

    def _hide(self, _event: tk.Event[tk.Widget] | None = None) -> None:
        self._cancel()
        if self._tip_window is not None:
            self._tip_window.destroy()
            self._tip_window = None


def _default_os_filter(os_filter: str | None) -> str:
    if os_filter in {"linux", "windows", "both"}:
        return os_filter
    detected = current_os()
    return detected if detected in {"linux", "windows"} else "both"


def _humanize_script_name(name: str) -> str:
    if "_" in name:
        name = name.split("_", 1)[1]
    return name.replace("_", " ").strip().title()


def _script_matches(script: dict[str, Any], term: str) -> bool:
    if not term:
        return True
    haystack = " ".join(
        [
            script.get("id", ""),
            script.get("name", ""),
            _humanize_script_name(script.get("name", "")),
            script.get("os", ""),
            script.get("lang", ""),
            script.get("path", ""),
        ]
    ).lower()
    return term in haystack


def _build_script_command(
    script_path: str,
    json_mode: bool = True,
    fix_mode: bool = False,
) -> list[str]:
    path = Path(script_path)
    if path.suffix == ".ps1":
        args = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(path)]
    elif path.suffix == ".sh":
        args = ["bash", str(path)]
    else:
        return [str(path)]

    if json_mode:
        args.append("-Json" if path.suffix == ".ps1" else "--json")
    if fix_mode:
        args.append("-Fix" if path.suffix == ".ps1" else "--fix")
    return args


def _index_findings_by_id(findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        str(finding.get("id", f"row-{idx}")): finding
        for idx, finding in enumerate(findings)
    }


def _summarize_fix_outcome(
    audit_findings: list[dict[str, Any]],
    verification_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compare pre-fix and post-fix findings for one script."""
    before = _index_findings_by_id(audit_findings)
    after = _index_findings_by_id(verification_findings)

    actionable_before = {
        fid: finding
        for fid, finding in before.items()
        if finding.get("status") in {"FAIL", "WARN"}
    }
    actionable_after = {
        fid: finding
        for fid, finding in after.items()
        if finding.get("status") in {"FAIL", "WARN"}
    }

    fixed_items: list[dict[str, Any]] = []
    remaining_items: list[dict[str, Any]] = []
    new_issues: list[dict[str, Any]] = []

    for finding_id, finding in actionable_before.items():
        verified = after.get(finding_id)
        verified_status = verified.get("status") if verified else "MISSING"
        if verified and verified_status in {"PASS", "INFO"}:
            fixed_items.append(
                {
                    "id": finding_id,
                    "name": finding.get("name", ""),
                    "before_status": finding.get("status", ""),
                    "after_status": verified_status,
                }
            )
        else:
            remaining_items.append(
                {
                    "id": finding_id,
                    "name": finding.get("name", ""),
                    "before_status": finding.get("status", ""),
                    "after_status": verified_status,
                    "detail": (verified or finding).get("detail", ""),
                }
            )

    for finding_id, finding in actionable_after.items():
        if finding_id not in actionable_before:
            new_issues.append(
                {
                    "id": finding_id,
                    "name": finding.get("name", ""),
                    "status": finding.get("status", ""),
                    "detail": finding.get("detail", ""),
                }
            )

    return {
        "verified": True,
        "fixed_count": len(fixed_items),
        "remaining_count": len(remaining_items),
        "new_issue_count": len(new_issues),
        "fixed_items": fixed_items,
        "remaining_items": remaining_items,
        "new_issues": new_issues,
        "audit_actionable_count": len(actionable_before),
        "verification_actionable_count": len(actionable_after),
    }


def _open_path(path: Path) -> None:
    if os.name == "nt":
        os.startfile(str(path))  # type: ignore[attr-defined]
        return
    if sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
        return
    subprocess.Popen(["xdg-open", str(path)])


def _terminate_process_tree(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            return

        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def _run_script_cancellable(
    script_path: str,
    stop_event: threading.Event,
    json_mode: bool = True,
    fix_mode: bool = False,
    timeout: int = 300,
) -> dict[str, Any]:
    """
    Run a single audit script and allow mid-flight cancellation.
    """
    path = Path(script_path)
    if not path.exists():
        return {
            "script": path.stem,
            "error": f"Script not found: {script_path}",
            "findings": [],
            "exit_code": -1,
        }

    args = _build_script_command(str(path), json_mode=json_mode, fix_mode=fix_mode)
    if len(args) == 1:
        return {
            "script": path.stem,
            "error": "Unsupported script type",
            "findings": [],
            "exit_code": -1,
        }

    popen_kwargs: dict[str, Any] = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
    }
    if os.name == "nt":
        popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        popen_kwargs["start_new_session"] = True

    try:
        proc = subprocess.Popen(args, **popen_kwargs)
        comm_result = {"stdout": "", "stderr": ""}

        def _drain() -> None:
            stdout, stderr = proc.communicate()
            comm_result["stdout"] = stdout or ""
            comm_result["stderr"] = stderr or ""

        comm_thread = threading.Thread(target=_drain, daemon=True)
        comm_thread.start()

        deadline = time.monotonic() + timeout
        cancelled = False
        timed_out = False

        while comm_thread.is_alive():
            if stop_event.is_set():
                _terminate_process_tree(proc)
                cancelled = True
                break
            if time.monotonic() > deadline:
                _terminate_process_tree(proc)
                timed_out = True
                break
            time.sleep(0.1)

        comm_thread.join(timeout=10)
        if comm_thread.is_alive():
            _terminate_process_tree(proc)
            comm_thread.join(timeout=2)

        if cancelled:
            return {
                "script": path.stem,
                "error": "Cancelled by user",
                "findings": [],
                "exit_code": -4,
            }
        if timed_out:
            return {
                "script": path.stem,
                "error": f"Script timed out after {timeout}s",
                "findings": [],
                "exit_code": -2,
            }

        stdout = comm_result["stdout"].strip()
        stderr = comm_result["stderr"].strip()
        exit_code = proc.returncode

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
                "findings": [],
                "exit_code": exit_code,
            }

        return {
            "script": path.stem,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "findings": [],
        }
    except Exception as exc:  # pylint: disable=broad-except
        return {
            "script": path.stem,
            "error": str(exc),
            "findings": [],
            "exit_code": -3,
        }


class CyberSWISSApp(tk.Tk):
    def __init__(self, os_filter: str | None = None) -> None:
        super().__init__()
        self.title("CyberSWISS Security Audit Console")
        self.configure(bg=_BG)
        self.resizable(True, True)
        self.minsize(1180, 760)

        self._apply_dpi_scaling()

        self._os_filter = _default_os_filter(os_filter)
        self._scripts: list[dict[str, Any]] = []
        self._visible_scripts: list[dict[str, Any]] = []
        self._results: list[dict[str, Any]] = []
        self._running = False
        self._worker_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._close_after_stop = False
        self._current_script_started_at = 0.0
        self._current_script_label = ""
        self._last_run_script_ids: list[str] = []
        self._last_snapshot_base: Path | None = None

        self._fix_var = tk.BooleanVar(value=False)
        self._autoscroll_var = tk.BooleanVar(value=True)
        self._stop_on_error_var = tk.BooleanVar(value=False)
        self._delay_var = tk.DoubleVar(value=0.0)
        self._timeout_var = tk.IntVar(value=300)
        self._sev_var = tk.StringVar(value="Info")
        self._filter_var = tk.StringVar()
        self._table_filter_var = tk.StringVar()
        self._table_status_var = tk.StringVar(value="All")
        self._os_var = tk.StringVar(value=self._os_filter)

        self._selected_count_var = tk.StringVar(value="0 selected / 0 visible")
        self._header_state_var = tk.StringVar(value="IDLE")
        self._list_header_var = tk.StringVar(value="Scripts")
        self._detail_var = tk.StringVar(value="Select a script to inspect it.")
        self._summary_var = tk.StringVar(value="Select scripts and start a run.")
        self._progress_var = tk.StringVar(value="Ready")
        self._status_left_var = tk.StringVar(value="Ready")
        self._clock_var = tk.StringVar()
        self._active_script_var = tk.StringVar(value="Current: idle")
        self._active_elapsed_var = tk.StringVar(value="Elapsed: 0.0s")
        self._queue_var = tk.StringVar(value="Queue: 0 pending")
        self._stat_vars = {
            "queued": tk.StringVar(value="0"),
            "completed": tk.StringVar(value="0"),
            "FAIL": tk.StringVar(value="0"),
            "WARN": tk.StringVar(value="0"),
            "PASS": tk.StringVar(value="0"),
            "INFO": tk.StringVar(value="0"),
        }

        self._table_sort_col = ""
        self._table_sort_rev = False
        self._tooltips: list[ToolTip] = []

        self._build_styles()
        self._build_ui()
        self._bind_events()
        self._refresh_scripts()
        self._refresh_run_metrics(total=0, completed=0, status_counts={})
        self._tick_clock()
        self._tick_active_runtime()

    def _apply_dpi_scaling(self) -> None:
        try:
            hwnd = self.winfo_id()
            dpi = ctypes.windll.user32.GetDpiForWindow(hwnd)
            if dpi > 0 and dpi != 96:
                scale = dpi / 96.0
                self.tk.call("tk", "scaling", scale)
                self.geometry(f"{int(1240 * scale)}x{int(820 * scale)}")
                return
        except (AttributeError, OSError):
            pass
        self.geometry("1240x820")

    def _build_styles(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "TNotebook",
            background=_BG,
            borderwidth=0,
        )
        style.configure(
            "TNotebook.Tab",
            background=_BG_CTRL,
            foreground=_FG_DIM,
            padding=(12, 8),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", _BG_PANEL_ALT)],
            foreground=[("selected", _ACCENT)],
        )
        style.configure(
            "Cyber.Treeview",
            background=_BG_PANEL_ALT,
            fieldbackground=_BG_PANEL_ALT,
            foreground=_FG,
            borderwidth=0,
            rowheight=26,
        )
        style.configure(
            "Cyber.Treeview.Heading",
            background=_BG_CTRL,
            foreground=_FG,
            relief="flat",
            padding=(8, 6),
        )
        style.map(
            "Cyber.Treeview",
            background=[("selected", _ACCENT_SOFT)],
            foreground=[("selected", _FG)],
        )
        style.configure(
            "Cyber.Horizontal.TProgressbar",
            troughcolor=_BG_PANEL_ALT,
            background=_ACCENT,
            borderwidth=0,
            lightcolor=_ACCENT,
            darkcolor=_ACCENT,
        )

    def _build_ui(self) -> None:
        self._build_menu()
        self._build_header()

        paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=(6, 0))

        left_frame = tk.Frame(paned, bg=_BG_PANEL, width=360)
        right_frame = tk.Frame(paned, bg=_BG)
        paned.add(left_frame, weight=1)
        paned.add(right_frame, weight=4)

        self._build_left_panel(left_frame)
        self._build_right_panel(right_frame)
        self._build_status_bar()
        self._attach_tooltips()

    def _build_menu(self) -> None:
        menu_opts: dict[str, Any] = {"tearoff": False}
        if sys.platform != "darwin":
            menu_opts.update(
                {
                    "bg": _BG_CTRL,
                    "fg": _FG,
                    "activebackground": _ACCENT_SOFT,
                    "activeforeground": _FG,
                    "relief": tk.FLAT,
                }
            )

        menubar = tk.Menu(self, **menu_opts)
        self.configure(menu=menubar)

        file_menu = tk.Menu(menubar, **menu_opts)
        file_menu.add_command(label="Save JSON", command=self._save_json)
        file_menu.add_command(label="Save HTML", command=self._save_html)
        file_menu.add_command(label="Save CSV", command=self._save_csv)
        file_menu.add_command(label="Save Text", command=self._save_text)
        file_menu.add_separator()
        file_menu.add_command(label="Quick Snapshot", command=self._quick_save_snapshot, accelerator="Ctrl+S")
        file_menu.add_command(label="Open Last Snapshot", command=self._open_last_snapshot)
        file_menu.add_command(label="Open Reports Directory", command=self._open_reports_dir)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close, accelerator="Ctrl+Q")
        menubar.add_cascade(label="File", menu=file_menu)

        selection_menu = tk.Menu(menubar, **menu_opts)
        selection_menu.add_command(label="Select All Visible", command=self._select_all)
        selection_menu.add_command(label="Clear Selection", command=self._deselect_all)
        selection_menu.add_command(label="Select Failed / Warning", command=self._select_failed_scripts)
        selection_menu.add_separator()
        selection_menu.add_command(label="Copy Command", command=self._copy_command)
        selection_menu.add_command(label="Open Selected Script", command=self._open_selected_script)
        menubar.add_cascade(label="Selection", menu=selection_menu)

        run_menu = tk.Menu(menubar, **menu_opts)
        run_menu.add_command(label="Run Selected", command=self._run_scripts, accelerator="Ctrl+R")
        run_menu.add_command(label="Dry Run", command=self._dry_run, accelerator="Ctrl+D")
        run_menu.add_command(label="Rerun Failed", command=self._rerun_failed)
        run_menu.add_command(label="Stop", command=self._stop_scripts, accelerator="Esc")
        run_menu.add_separator()
        run_menu.add_checkbutton(label="Fix Mode", variable=self._fix_var)
        run_menu.add_checkbutton(label="Auto-scroll", variable=self._autoscroll_var)
        run_menu.add_checkbutton(label="Stop on Script Error", variable=self._stop_on_error_var)
        menubar.add_cascade(label="Run", menu=run_menu)

        view_menu = tk.Menu(menubar, **menu_opts)
        scope_menu = tk.Menu(view_menu, **menu_opts)
        for value in ("linux", "windows", "both"):
            scope_menu.add_radiobutton(
                label=value.title(),
                variable=self._os_var,
                value=value,
                command=self._switch_os,
            )
        view_menu.add_cascade(label="Scope", menu=scope_menu)

        severity_menu = tk.Menu(view_menu, **menu_opts)
        for severity in SEVERITY_ORDER.keys():
            severity_menu.add_radiobutton(
                label=severity,
                variable=self._sev_var,
                value=severity,
                command=self._on_profile_change,
            )
        view_menu.add_cascade(label="Minimum Severity", menu=severity_menu)
        view_menu.add_separator()
        view_menu.add_command(label="Focus Script Filter", command=self._focus_script_filter, accelerator="Ctrl+F")
        view_menu.add_command(
            label="Focus Findings Filter",
            command=self._focus_findings_filter,
            accelerator="Ctrl+Shift+F",
        )
        view_menu.add_separator()
        view_menu.add_command(label="Show Output Log", command=self._show_output_log, accelerator="Ctrl+1")
        view_menu.add_command(label="Show Findings Table", command=self._show_findings_table, accelerator="Ctrl+2")
        view_menu.add_command(label="Clear Output Log", command=self._clear_output_view, accelerator="Ctrl+L")
        menubar.add_cascade(label="View", menu=view_menu)

        help_menu = tk.Menu(menubar, **menu_opts)
        help_menu.add_command(label="Keyboard Shortcuts", command=self._show_shortcuts, accelerator="F1")
        help_menu.add_separator()
        help_menu.add_command(label="Open Catalog", command=self._open_catalog)
        help_menu.add_command(label="Open Remediation Guide", command=self._open_remediation_guide)
        help_menu.add_command(label="Open Runtime Requirements", command=self._open_runtime_requirements)
        help_menu.add_separator()
        help_menu.add_command(label="About CyberSWISS", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

    def _build_header(self) -> None:
        header = tk.Frame(self, bg=_BG_CTRL, padx=16, pady=12)
        header.pack(fill=tk.X)

        left = tk.Frame(header, bg=_BG_CTRL)
        left.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Label(
            left,
            text="CyberSWISS Security Audit Console",
            font=("Segoe UI", 17, "bold"),
            fg=_FG,
            bg=_BG_CTRL,
        ).pack(anchor=tk.W)
        tk.Label(
            left,
            text="Interactive scanning, review, export, and controlled stop handling for Linux and Windows checks.",
            font=("Segoe UI", 9),
            fg=_FG_DIM,
            bg=_BG_CTRL,
        ).pack(anchor=tk.W, pady=(2, 0))

        self._header_state_label = tk.Label(
            header,
            textvariable=self._header_state_var,
            font=("Segoe UI", 10, "bold"),
            fg=_FG,
            bg=_ACCENT_SOFT,
            padx=12,
            pady=6,
        )
        self._header_state_label.pack(side=tk.RIGHT)

    def _build_left_panel(self, parent: tk.Frame) -> None:
        parent.pack_propagate(False)

        tk.Label(
            parent,
            textvariable=self._list_header_var,
            font=("Segoe UI", 11, "bold"),
            fg=_ACCENT,
            bg=_BG_PANEL,
        ).pack(anchor=tk.W, padx=10, pady=(10, 4))

        os_frame = tk.Frame(parent, bg=_BG_PANEL)
        os_frame.pack(fill=tk.X, padx=8, pady=(0, 4))
        tk.Label(os_frame, text="Scope:", fg=_FG_DIM, bg=_BG_PANEL).pack(side=tk.LEFT)
        for value in ("linux", "windows", "both"):
            tk.Radiobutton(
                os_frame,
                text=value.title(),
                variable=self._os_var,
                value=value,
                bg=_BG_PANEL,
                fg=_FG_DIM,
                selectcolor=_BG_CTRL,
                activebackground=_BG_PANEL,
                activeforeground=_ACCENT,
                command=self._switch_os,
                relief=tk.FLAT,
            ).pack(side=tk.LEFT, padx=4)

        filter_frame = tk.Frame(parent, bg=_BG_PANEL)
        filter_frame.pack(fill=tk.X, padx=8, pady=(0, 6))
        tk.Label(filter_frame, text="Filter", fg=_FG_DIM, bg=_BG_PANEL).pack(anchor=tk.W)
        self._script_filter_entry = tk.Entry(
            filter_frame,
            textvariable=self._filter_var,
            bg=_BG_CTRL,
            fg=_FG,
            insertbackground=_ACCENT,
            relief=tk.FLAT,
        )
        self._script_filter_entry.pack(fill=tk.X, pady=(3, 0))

        list_frame = tk.Frame(parent, bg=_BG_PANEL)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 6))
        scrollbar = tk.Scrollbar(list_frame, bg=_BG_CTRL, relief=tk.FLAT)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self._script_list = tk.Listbox(
            list_frame,
            selectmode=tk.MULTIPLE,
            bg=_BG_CTRL,
            fg=_FG,
            selectbackground=_ACCENT_SOFT,
            selectforeground=_FG,
            activestyle="none",
            font=("Consolas", 9),
            yscrollcommand=scrollbar.set,
            relief=tk.FLAT,
            borderwidth=0,
        )
        self._script_list.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self._script_list.yview)
        self._script_list.bind("<<ListboxSelect>>", self._on_script_select)
        self._script_list.bind("<Double-Button-1>", lambda _event: self._run_scripts())

        select_row = tk.Frame(parent, bg=_BG_PANEL)
        select_row.pack(fill=tk.X, padx=8, pady=(0, 4))
        for label, cmd in [
            ("Select All", self._select_all),
            ("Select Visible", self._select_visible),
            ("Clear", self._deselect_all),
            ("Failed", self._select_failed_scripts),
        ]:
            tk.Button(
                select_row,
                text=label,
                command=cmd,
                bg=_BG_CTRL,
                fg=_FG,
                relief=tk.FLAT,
                padx=8,
                pady=4,
            ).pack(side=tk.LEFT, padx=(0, 4))

        quick_row = tk.Frame(parent, bg=_BG_PANEL)
        quick_row.pack(fill=tk.X, padx=8, pady=(0, 6))
        for label, cmd in [
            ("Copy Command", self._copy_command),
            ("Open Script", self._open_selected_script),
        ]:
            tk.Button(
                quick_row,
                text=label,
                command=cmd,
                bg=_BG_CTRL,
                fg=_FG_DIM,
                relief=tk.FLAT,
                padx=8,
                pady=4,
            ).pack(side=tk.LEFT, padx=(0, 4))

        detail_frame = tk.LabelFrame(
            parent,
            text=" Script Detail ",
            fg=_ACCENT,
            bg=_BG_PANEL,
            font=("Segoe UI", 9),
            relief=tk.FLAT,
        )
        detail_frame.pack(fill=tk.X, padx=8, pady=(0, 10))
        tk.Label(
            detail_frame,
            textvariable=self._detail_var,
            fg=_FG_DIM,
            bg=_BG_PANEL,
            font=("Consolas", 8),
            justify=tk.LEFT,
            anchor=tk.W,
            wraplength=320,
        ).pack(fill=tk.X, padx=6, pady=6)

    def _build_right_panel(self, parent: tk.Frame) -> None:
        self._build_controls(parent)
        self._build_run_overview(parent)
        self._build_progress_bar(parent)

        tk.Label(
            parent,
            textvariable=self._summary_var,
            font=("Consolas", 10),
            fg=_ACCENT,
            bg=_BG,
            anchor=tk.W,
        ).pack(fill=tk.X, padx=10, pady=(4, 2))

        self._notebook = ttk.Notebook(parent)
        self._notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(2, 8))
        self._build_log_tab()
        self._build_table_tab()

    def _build_controls(self, parent: tk.Frame) -> None:
        ctrl = tk.Frame(parent, bg=_BG)
        ctrl.pack(fill=tk.X, padx=10, pady=(10, 4))

        row1 = tk.Frame(ctrl, bg=_BG)
        row1.pack(fill=tk.X)
        self._run_btn = tk.Button(
            row1,
            text="Run Selected",
            command=self._run_scripts,
            bg=_GREEN,
            fg="#04110a",
            font=("Segoe UI", 10, "bold"),
            relief=tk.FLAT,
            padx=14,
            pady=5,
            cursor="hand2",
        )
        self._run_btn.pack(side=tk.LEFT, padx=(0, 6))

        self._stop_btn = tk.Button(
            row1,
            text="Stop",
            command=self._stop_scripts,
            bg=_RED,
            fg=_FG,
            font=("Segoe UI", 10, "bold"),
            relief=tk.FLAT,
            padx=12,
            pady=5,
            cursor="hand2",
            state=tk.DISABLED,
        )
        self._stop_btn.pack(side=tk.LEFT, padx=(0, 6))

        self._dry_run_btn = tk.Button(
            row1,
            text="Dry Run",
            command=self._dry_run,
            bg=_BG_CTRL,
            fg=_FG,
            relief=tk.FLAT,
            padx=10,
            pady=5,
            cursor="hand2",
        )
        self._dry_run_btn.pack(side=tk.LEFT, padx=(0, 6))

        self._rerun_btn = tk.Button(
            row1,
            text="Rerun Failed",
            command=self._rerun_failed,
            bg=_BG_CTRL,
            fg=_FG,
            relief=tk.FLAT,
            padx=10,
            pady=5,
            cursor="hand2",
        )
        self._rerun_btn.pack(side=tk.LEFT, padx=(0, 6))

        self._snapshot_btn = tk.Button(
            row1,
            text="Snapshot",
            command=self._quick_save_snapshot,
            bg=_BG_CTRL,
            fg=_ACCENT,
            relief=tk.FLAT,
            padx=10,
            pady=5,
        )
        self._snapshot_btn.pack(side=tk.LEFT, padx=(0, 6))

        self._clear_log_btn = tk.Button(
            row1,
            text="Clear Log",
            command=self._clear_output_view,
            bg=_BG_CTRL,
            fg=_FG_DIM,
            relief=tk.FLAT,
            padx=10,
            pady=5,
        )
        self._clear_log_btn.pack(side=tk.LEFT)

        row2 = tk.Frame(ctrl, bg=_BG)
        row2.pack(fill=tk.X, pady=(6, 0))
        for label, cmd in [
            ("Save JSON", self._save_json),
            ("Save HTML", self._save_html),
            ("Save CSV", self._save_csv),
            ("Save Text", self._save_text),
            ("Open Reports", self._open_reports_dir),
        ]:
            tk.Button(
                row2,
                text=label,
                command=cmd,
                bg=_BG_CTRL,
                fg=_FG_DIM,
                relief=tk.FLAT,
                padx=8,
                pady=4,
            ).pack(side=tk.LEFT, padx=(0, 4))

        row3 = tk.Frame(ctrl, bg=_BG)
        row3.pack(fill=tk.X, pady=(6, 0))
        self._fix_check = tk.Checkbutton(
            row3,
            text="Fix Mode",
            variable=self._fix_var,
            bg=_BG,
            fg=_ORANGE,
            selectcolor=_BG_CTRL,
            activebackground=_BG,
            activeforeground=_ORANGE,
            relief=tk.FLAT,
            font=("Segoe UI", 9),
        )
        self._fix_check.pack(side=tk.LEFT, padx=(0, 10))

        self._autoscroll_check = tk.Checkbutton(
            row3,
            text="Auto-scroll",
            variable=self._autoscroll_var,
            bg=_BG,
            fg=_FG_DIM,
            selectcolor=_BG_CTRL,
            activebackground=_BG,
            activeforeground=_FG,
            relief=tk.FLAT,
            font=("Segoe UI", 9),
        )
        self._autoscroll_check.pack(side=tk.LEFT, padx=(0, 10))

        self._stop_on_error_check = tk.Checkbutton(
            row3,
            text="Stop on Script Error",
            variable=self._stop_on_error_var,
            bg=_BG,
            fg=_FG_DIM,
            selectcolor=_BG_CTRL,
            activebackground=_BG,
            activeforeground=_FG,
            relief=tk.FLAT,
            font=("Segoe UI", 9),
        )
        self._stop_on_error_check.pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(row3, text="Min Severity", fg=_FG_DIM, bg=_BG).pack(side=tk.LEFT, padx=(8, 4))
        self._severity_combo = ttk.Combobox(
            row3,
            textvariable=self._sev_var,
            values=list(SEVERITY_ORDER.keys()),
            width=9,
            state="readonly",
        )
        self._severity_combo.pack(side=tk.LEFT)

        tk.Label(row3, text="Timeout (s)", fg=_FG_DIM, bg=_BG).pack(side=tk.LEFT, padx=(12, 4))
        self._timeout_spin = tk.Spinbox(
            row3,
            from_=10,
            to=7200,
            increment=10,
            textvariable=self._timeout_var,
            width=7,
            bg=_BG_CTRL,
            fg=_FG,
            buttonbackground=_BG_CTRL,
            relief=tk.FLAT,
            insertbackground=_ACCENT,
        )
        self._timeout_spin.pack(side=tk.LEFT)

        tk.Label(row3, text="Delay (s)", fg=_FG_DIM, bg=_BG).pack(side=tk.LEFT, padx=(12, 4))
        self._delay_spin = tk.Spinbox(
            row3,
            from_=0,
            to=60,
            increment=0.5,
            textvariable=self._delay_var,
            width=6,
            bg=_BG_CTRL,
            fg=_FG,
            buttonbackground=_BG_CTRL,
            relief=tk.FLAT,
            insertbackground=_ACCENT,
        )
        self._delay_spin.pack(side=tk.LEFT)

        tk.Label(
            row3,
            textvariable=self._progress_var,
            fg=_FG_DIM,
            bg=_BG,
        ).pack(side=tk.RIGHT, padx=(8, 0))

    def _build_run_overview(self, parent: tk.Frame) -> None:
        frame = tk.Frame(parent, bg=_BG)
        frame.pack(fill=tk.X, padx=10, pady=(2, 6))

        top = tk.Frame(frame, bg=_BG)
        top.pack(fill=tk.X)
        tk.Label(
            top,
            textvariable=self._active_script_var,
            fg=_FG,
            bg=_BG,
            font=("Segoe UI", 10, "bold"),
        ).pack(side=tk.LEFT)
        tk.Label(
            top,
            textvariable=self._active_elapsed_var,
            fg=_FG_DIM,
            bg=_BG,
            font=("Consolas", 9),
        ).pack(side=tk.RIGHT)

        tk.Label(
            frame,
            textvariable=self._queue_var,
            fg=_FG_DIM,
            bg=_BG,
            font=("Consolas", 9),
            anchor=tk.W,
        ).pack(fill=tk.X, pady=(4, 8))

        cards = tk.Frame(frame, bg=_BG)
        cards.pack(fill=tk.X)
        card_specs = [
            ("Queued", "queued", _FG_DIM),
            ("Completed", "completed", _ACCENT),
            ("FAIL", "FAIL", _RED),
            ("WARN", "WARN", _ORANGE),
            ("PASS", "PASS", _GREEN),
            ("INFO", "INFO", _BLUE),
        ]
        for title, key, color in card_specs:
            card = tk.Frame(cards, bg=_CARD_BG, padx=10, pady=8)
            card.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
            tk.Label(
                card,
                text=title,
                fg=_FG_DIM,
                bg=_CARD_BG,
                font=("Segoe UI", 8),
            ).pack(anchor=tk.W)
            tk.Label(
                card,
                textvariable=self._stat_vars[key],
                fg=color,
                bg=_CARD_BG,
                font=("Segoe UI", 16, "bold"),
            ).pack(anchor=tk.W, pady=(3, 0))

    def _build_progress_bar(self, parent: tk.Frame) -> None:
        self._progress_bar = ttk.Progressbar(
            parent,
            style="Cyber.Horizontal.TProgressbar",
            mode="determinate",
            maximum=1,
            value=0,
        )
        self._progress_bar.pack(fill=tk.X, padx=10, pady=(0, 2))

    def _build_log_tab(self) -> None:
        frame = tk.Frame(self._notebook, bg=_BG_OUTPUT)
        self._notebook.add(frame, text="  Output Log  ")

        self._output = scrolledtext.ScrolledText(
            frame,
            bg=_BG_OUTPUT,
            fg=_FG,
            font=("Consolas", 9),
            relief=tk.FLAT,
            borderwidth=0,
            state=tk.DISABLED,
            wrap=tk.WORD,
        )
        self._output.pack(fill=tk.BOTH, expand=True)
        for status, color in STATUS_COLOURS_TK.items():
            self._output.tag_configure(status, foreground=color)
        self._output.tag_configure("header", foreground=_ACCENT, font=("Consolas", 10, "bold"))
        self._output.tag_configure("remedy", foreground="#8de4ff")
        self._output.tag_configure("timing", foreground=_FG_DIM)
        self._output.tag_configure("muted", foreground=_FG_DIM)

    def _build_table_tab(self) -> None:
        frame = tk.Frame(self._notebook, bg=_BG)
        self._notebook.add(frame, text="  Findings Table  ")

        toolbar = tk.Frame(frame, bg=_BG)
        toolbar.pack(fill=tk.X, padx=6, pady=6)
        tk.Label(toolbar, text="Filter", fg=_FG_DIM, bg=_BG).pack(side=tk.LEFT)
        self._table_filter_entry = tk.Entry(
            toolbar,
            textvariable=self._table_filter_var,
            bg=_BG_CTRL,
            fg=_FG,
            insertbackground=_ACCENT,
            relief=tk.FLAT,
            width=28,
        )
        self._table_filter_entry.pack(side=tk.LEFT, padx=(4, 8))

        tk.Label(toolbar, text="Status", fg=_FG_DIM, bg=_BG).pack(side=tk.LEFT)
        ttk.Combobox(
            toolbar,
            textvariable=self._table_status_var,
            values=["All", "FAIL", "WARN", "PASS", "INFO"],
            width=8,
            state="readonly",
        ).pack(side=tk.LEFT, padx=(4, 8))

        tk.Button(
            toolbar,
            text="Copy Row",
            command=self._copy_table_row,
            bg=_BG_CTRL,
            fg=_FG_DIM,
            relief=tk.FLAT,
            padx=8,
            pady=4,
        ).pack(side=tk.LEFT)

        columns = ("script", "id", "name", "status", "severity", "detail", "remediation")
        tree_frame = tk.Frame(frame, bg=_BG)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=(0, 6))
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        self._findings_tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
            style="Cyber.Treeview",
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set,
        )
        vsb.config(command=self._findings_tree.yview)
        hsb.config(command=self._findings_tree.xview)

        widths = {
            "script": 130,
            "id": 90,
            "name": 220,
            "status": 70,
            "severity": 80,
            "detail": 320,
            "remediation": 320,
        }
        for column in columns:
            self._findings_tree.heading(
                column,
                text=column.title(),
                command=lambda c=column: self._sort_table(c),
            )
            self._findings_tree.column(column, width=widths.get(column, 120), minwidth=80)

        self._findings_tree.tag_configure("FAIL", foreground=_RED)
        self._findings_tree.tag_configure("WARN", foreground=_ORANGE)
        self._findings_tree.tag_configure("PASS", foreground=_GREEN)
        self._findings_tree.tag_configure("INFO", foreground=_BLUE)

        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self._findings_tree.pack(fill=tk.BOTH, expand=True)

    def _add_tooltip(self, widget: tk.Widget, text: str) -> None:
        self._tooltips.append(ToolTip(widget, text))

    def _attach_tooltips(self) -> None:
        self._add_tooltip(
            self._header_state_label,
            "Shows the current global GUI state: idle, running, or stopping.",
        )
        self._add_tooltip(
            self._script_list,
            "Select one or more audit scripts. Double-click a script to run the current selection immediately.",
        )
        self._add_tooltip(
            self._run_btn,
            "Start execution for the currently selected scripts using the active timeout, delay, severity, and fix settings.",
        )
        self._add_tooltip(
            self._stop_btn,
            "Request a controlled stop. The GUI will terminate the active script process tree, then stop the queue.",
        )
        self._add_tooltip(
            self._dry_run_btn,
            "Preview the exact scripts and commands that would run without executing anything.",
        )
        self._add_tooltip(
            self._rerun_btn,
            "Automatically rerun scripts from the last session that produced FAIL, WARN, or execution errors.",
        )
        self._add_tooltip(
            self._snapshot_btn,
            "Save JSON, HTML, CSV, and text reports together into the reports directory with a timestamped filename.",
        )
        self._add_tooltip(
            self._clear_log_btn,
            "Clear only the visible output log. Existing results remain available for filtering and export.",
        )
        self._add_tooltip(
            self._fix_check,
            "Run scripts in remediation mode, then immediately re-audit them so the GUI can show what was actually fixed and what still remains.",
        )
        self._add_tooltip(
            self._autoscroll_check,
            "Keep the output view pinned to the newest log lines while a run is active.",
        )
        self._add_tooltip(
            self._stop_on_error_check,
            "Stop the remaining queue when any script returns an execution error.",
        )
        self._add_tooltip(
            self._severity_combo,
            "Hide findings below this severity in the live log and findings table. Raw results are still preserved for export.",
        )
        self._add_tooltip(
            self._timeout_spin,
            "Maximum runtime per script before the GUI marks it as timed out and terminates it.",
        )
        self._add_tooltip(
            self._delay_spin,
            "Optional pause inserted between scripts. Useful for pacing scans or reducing noise.",
        )
        self._add_tooltip(
            self._progress_bar,
            "Tracks how many scripts from the current queue have completed.",
        )
        self._add_tooltip(
            self._findings_tree,
            "Structured findings table. Filter, sort by clicking headers, and copy the selected row.",
        )
        self._add_tooltip(
            self._output,
            "Live execution log with timing, findings, remediation guidance, and run-level status messages.",
        )

    def _build_status_bar(self) -> None:
        bar = tk.Frame(self, bg=_BG_CTRL, pady=4)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        tk.Label(
            bar,
            textvariable=self._status_left_var,
            fg=_FG_DIM,
            bg=_BG_CTRL,
            font=("Segoe UI", 8),
            anchor=tk.W,
        ).pack(side=tk.LEFT, padx=12)
        tk.Label(
            bar,
            textvariable=self._selected_count_var,
            fg=_FG_DIM,
            bg=_BG_CTRL,
            font=("Segoe UI", 8),
        ).pack(side=tk.RIGHT, padx=12)
        tk.Label(
            bar,
            textvariable=self._clock_var,
            fg=_FG_DIM,
            bg=_BG_CTRL,
            font=("Segoe UI", 8),
        ).pack(side=tk.RIGHT, padx=(0, 12))

    def _focus_script_filter(self) -> None:
        self._script_filter_entry.focus_set()
        self._script_filter_entry.selection_range(0, tk.END)
        self._status_left_var.set("Script filter focused.")

    def _focus_findings_filter(self) -> None:
        self._show_findings_table()
        self._table_filter_entry.focus_set()
        self._table_filter_entry.selection_range(0, tk.END)
        self._status_left_var.set("Findings filter focused.")

    def _show_output_log(self) -> None:
        self._notebook.select(0)
        self._status_left_var.set("Output log tab selected.")

    def _show_findings_table(self) -> None:
        self._notebook.select(1)
        self._status_left_var.set("Findings table tab selected.")

    def _open_doc_path(self, path: Path, label: str) -> None:
        try:
            _open_path(path)
            self._status_left_var.set(f"Opened {label}: {path}")
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("CyberSWISS", f"Unable to open {label}:\n{exc}")

    def _open_catalog(self) -> None:
        self._open_doc_path(REPO_ROOT / "docs" / "CATALOG.md", "catalog")

    def _open_remediation_guide(self) -> None:
        self._open_doc_path(REPO_ROOT / "docs" / "REMEDIATION_GUIDE.md", "remediation guide")

    def _open_runtime_requirements(self) -> None:
        self._open_doc_path(REPO_ROOT / "docs" / "RUNTIME_REQUIREMENTS.md", "runtime requirements")

    def _open_last_snapshot(self) -> None:
        if self._last_snapshot_base is None:
            messagebox.showinfo("CyberSWISS", "No snapshot has been created in this session yet.")
            return

        for suffix in (".html", ".json", ".csv", ".txt"):
            candidate = self._last_snapshot_base.with_suffix(suffix)
            if candidate.exists():
                self._open_doc_path(candidate, f"snapshot{suffix}")
                return

        messagebox.showinfo("CyberSWISS", "The last snapshot files could not be found on disk.")

    def _show_shortcuts(self) -> None:
        messagebox.showinfo(
            "CyberSWISS Shortcuts",
            "Ctrl+R  Run selected scripts\n"
            "Ctrl+D  Dry run selected scripts\n"
            "Ctrl+S  Quick snapshot export\n"
            "Ctrl+L  Clear output log\n"
            "Ctrl+F  Focus script filter\n"
            "Ctrl+Shift+F  Focus findings filter\n"
            "Ctrl+1  Show output log tab\n"
            "Ctrl+2  Show findings table tab\n"
            "Ctrl+Q  Close the window\n"
            "F1      Show this shortcuts dialog\n"
            "Esc     Stop the active run",
        )

    def _show_about(self) -> None:
        messagebox.showinfo(
            "About CyberSWISS",
            "CyberSWISS Security Audit Console\n\n"
            f"Repository: {REPO_ROOT}\n"
            f"Visible scripts: {len(self._visible_scripts)}\n"
            f"Current scope: {self._os_filter}\n"
            "Use the menu bar for exports, selection controls, scope changes, and documentation shortcuts.",
        )

    def _bind_events(self) -> None:
        self._filter_var.trace_add("write", self._apply_filter)
        self._table_filter_var.trace_add("write", self._apply_table_filter)
        self._table_status_var.trace_add("write", self._apply_table_filter)
        self._sev_var.trace_add("write", self._on_profile_change)
        self._fix_var.trace_add("write", self._on_profile_change)

        self.bind("<Control-r>", lambda _event: self._run_scripts())
        self.bind("<Control-d>", lambda _event: self._dry_run())
        self.bind("<Control-s>", lambda _event: self._quick_save_snapshot())
        self.bind("<Control-l>", lambda _event: self._clear_output_view())
        self.bind("<Control-f>", lambda _event: self._focus_script_filter())
        self.bind("<Control-F>", lambda _event: self._focus_findings_filter())
        self.bind("<Control-1>", lambda _event: self._show_output_log())
        self.bind("<Control-2>", lambda _event: self._show_findings_table())
        self.bind("<Control-q>", lambda _event: self._on_close())
        self.bind("<F1>", lambda _event: self._show_shortcuts())
        self.bind("<Escape>", lambda _event: self._stop_scripts())
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _tick_clock(self) -> None:
        self._clock_var.set(datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.after(1000, self._tick_clock)

    def _tick_active_runtime(self) -> None:
        if self._running and self._current_script_started_at:
            elapsed = time.monotonic() - self._current_script_started_at
            self._active_elapsed_var.set(f"Elapsed: {elapsed:0.1f}s")
        elif not self._running:
            self._active_elapsed_var.set("Elapsed: 0.0s")

        if self._close_after_stop and not self._running:
            self.destroy()
            return
        self.after(250, self._tick_active_runtime)

    def _refresh_scripts(self, preserve_selection: bool = False) -> None:
        selected_ids = self._selected_script_ids() if preserve_selection else set()
        os_filter = None if self._os_filter == "both" else self._os_filter
        self._scripts = discover_scripts(os_filter=os_filter)
        self._rebuild_visible_scripts(selected_ids=selected_ids)

    def _rebuild_visible_scripts(self, selected_ids: set[str] | None = None) -> None:
        selected_ids = selected_ids or set()
        term = self._filter_var.get().strip().lower()
        self._visible_scripts = [script for script in self._scripts if _script_matches(script, term)]

        self._script_list.delete(0, tk.END)
        for index, script in enumerate(self._visible_scripts):
            label = f"{script['id']:4s}  {script['os'][0].upper()}  {_humanize_script_name(script['name'])}"
            self._script_list.insert(tk.END, label)
            if script["id"] in selected_ids:
                self._script_list.select_set(index)

        header = f"Scripts ({self._os_filter.title()}) - {len(self._visible_scripts)}"
        if term:
            header += f" filtered from {len(self._scripts)}"
        self._list_header_var.set(header)
        self._update_selected_count()
        self._refresh_detail_panel()

    def _selected_script_ids(self) -> set[str]:
        return {
            self._visible_scripts[index]["id"]
            for index in self._script_list.curselection()
            if index < len(self._visible_scripts)
        }

    def _get_selected_scripts(self) -> list[dict[str, Any]]:
        return [
            self._visible_scripts[index]
            for index in self._script_list.curselection()
            if index < len(self._visible_scripts)
        ]

    def _switch_os(self) -> None:
        self._os_filter = self._os_var.get()
        self._refresh_scripts()
        self._status_left_var.set(f"Scope switched to {self._os_filter}.")

    def _apply_filter(self, *_: Any) -> None:
        self._rebuild_visible_scripts(selected_ids=self._selected_script_ids())

    def _select_all(self) -> None:
        self._script_list.select_set(0, tk.END)
        self._update_selected_count()
        self._refresh_detail_panel()

    def _select_visible(self) -> None:
        self._select_all()

    def _deselect_all(self) -> None:
        self._script_list.select_clear(0, tk.END)
        self._update_selected_count()
        self._refresh_detail_panel()

    def _select_failed_scripts(self) -> None:
        retry_ids = self._collect_retry_ids()
        if not retry_ids:
            messagebox.showinfo("CyberSWISS", "No failed or warning scripts found in the current session.")
            return

        self._script_list.select_clear(0, tk.END)
        selected = 0
        for index, script in enumerate(self._visible_scripts):
            if script["id"] in retry_ids:
                self._script_list.select_set(index)
                selected += 1

        self._update_selected_count()
        self._refresh_detail_panel()
        if selected:
            self._status_left_var.set(f"Selected {selected} failed/warning script(s).")
        else:
            self._status_left_var.set("Failed scripts exist but are hidden by the current filter.")
            messagebox.showinfo(
                "CyberSWISS",
                "Failed scripts exist in the last session, but none are visible with the current scope/filter.",
            )

    def _collect_retry_ids(self) -> set[str]:
        retry_ids: set[str] = set()
        for result in self._results:
            meta = result.get("script_meta", {})
            script_id = meta.get("id")
            if not script_id:
                script_name = result.get("script", "")
                script_id = script_name.split("_", 1)[0].upper() if "_" in script_name else script_name[:3]
            if result.get("error"):
                retry_ids.add(script_id)
                continue
            if any(f.get("status") in {"FAIL", "WARN"} for f in result.get("findings", [])):
                retry_ids.add(script_id)
        return retry_ids

    def _on_script_select(self, _event: Any = None) -> None:
        self._update_selected_count()
        self._refresh_detail_panel()

    def _update_selected_count(self) -> None:
        self._selected_count_var.set(
            f"{len(self._script_list.curselection())} selected / {len(self._visible_scripts)} visible"
        )

    def _find_result_for_script(self, script_id: str) -> dict[str, Any] | None:
        for result in reversed(self._results):
            meta = result.get("script_meta", {})
            if meta.get("id") == script_id:
                return result
        return None

    def _refresh_detail_panel(self) -> None:
        selected = self._get_selected_scripts()
        if not selected:
            self._detail_var.set(
                "Select a script to inspect it.\n\n"
                "Shortcuts: Ctrl+R run, Ctrl+D dry-run, Ctrl+S snapshot, "
                "Ctrl+F script filter, Ctrl+Shift+F findings filter, Esc stop."
            )
            return

        if len(selected) > 1:
            ids = ", ".join(script["id"] for script in selected[:8])
            suffix = " ..." if len(selected) > 8 else ""
            runner_preview = "python3 common/runner.py --scripts " + " ".join(
                script["id"] for script in selected[:8]
            )
            if len(selected) > 8:
                runner_preview += " ..."
            self._detail_var.set(
                f"{len(selected)} scripts selected\n"
                f"IDs: {ids}{suffix}\n"
                f"Fix Mode: {'on' if self._fix_var.get() else 'off'}\n"
                f"Runner preview:\n{runner_preview}"
            )
            return

        script = selected[0]
        command_preview = " ".join(_build_script_command(script["path"], json_mode=True, fix_mode=self._fix_var.get()))
        last_result = self._find_result_for_script(script["id"])
        last_line = "Last run: not yet executed"
        if last_result:
            counts = Counter(f.get("status", "INFO") for f in last_result.get("findings", []))
            if last_result.get("error"):
                last_line = f"Last run: ERROR - {last_result['error']}"
            else:
                last_line = (
                    "Last run: "
                    f"FAIL {counts.get('FAIL', 0)} | "
                    f"WARN {counts.get('WARN', 0)} | "
                    f"PASS {counts.get('PASS', 0)} | "
                    f"INFO {counts.get('INFO', 0)}"
                )

        self._detail_var.set(
            f"ID: {script['id']}\n"
            f"Name: {_humanize_script_name(script['name'])}\n"
            f"OS: {script['os'].title()}\n"
            f"Language: {script['lang']}\n"
            f"Path: {script['path']}\n"
            f"{last_line}\n"
            f"Command:\n{command_preview}"
        )

    def _on_profile_change(self, *_: Any) -> None:
        self._refresh_detail_panel()
        self._refresh_table()

    def _append_output(self, text: str, tag: str = "") -> None:
        self._output.configure(state=tk.NORMAL)
        self._output.insert(tk.END, text, tag)
        if self._autoscroll_var.get():
            self._output.see(tk.END)
        self._output.configure(state=tk.DISABLED)

    def _clear_output_view(self) -> None:
        self._output.configure(state=tk.NORMAL)
        self._output.delete("1.0", tk.END)
        self._output.configure(state=tk.DISABLED)
        self._status_left_var.set("Output log cleared.")

    def _reset_session_state(self) -> None:
        self._results.clear()
        self._last_snapshot_base = None
        self._clear_output_view()
        self._summary_var.set("Session reset.")
        self._progress_bar.configure(maximum=1, value=0)
        self._progress_var.set("Ready")
        self._active_script_var.set("Current: idle")
        self._active_elapsed_var.set("Elapsed: 0.0s")
        self._queue_var.set("Queue: 0 pending")
        self._refresh_run_metrics(total=0, completed=0, status_counts={})
        self._refresh_table()
        self._refresh_detail_panel()

    def _refresh_run_metrics(
        self,
        total: int,
        completed: int,
        status_counts: dict[str, int],
    ) -> None:
        queued = max(total - completed, 0)
        self._stat_vars["queued"].set(str(queued))
        self._stat_vars["completed"].set(str(completed))
        for status in ("FAIL", "WARN", "PASS", "INFO"):
            self._stat_vars[status].set(str(status_counts.get(status, 0)))
        if total:
            self._queue_var.set(f"Queue: {queued} pending | {completed}/{total} complete")
        else:
            self._queue_var.set("Queue: 0 pending")

    def _aggregate_fix_report(self) -> dict[str, Any]:
        fix_results = [result.get("fix_report") for result in self._results if result.get("fix_report")]
        verified = [report for report in fix_results if report.get("verified")]
        return {
            "scripts_with_fix_report": len(fix_results),
            "scripts_verified": len(verified),
            "fixed_count": sum(report.get("fixed_count", 0) for report in verified),
            "remaining_count": sum(report.get("remaining_count", 0) for report in verified),
            "new_issue_count": sum(report.get("new_issue_count", 0) for report in verified),
            "verification_failed_count": sum(
                1 for report in fix_results if report.get("verification_error")
            ),
        }

    def _refresh_table(self) -> None:
        for row in self._findings_tree.get_children():
            self._findings_tree.delete(row)

        term = self._table_filter_var.get().strip().lower()
        status_filter = self._table_status_var.get()
        min_sev = SEVERITY_ORDER.get(self._sev_var.get(), 0)

        for result in self._results:
            script_name = result.get("script", "unknown")
            for finding in result.get("findings", []):
                status = finding.get("status", "")
                severity = finding.get("severity", "")
                if status_filter != "All" and status != status_filter:
                    continue
                if SEVERITY_ORDER.get(severity, 0) < min_sev:
                    continue

                values = (
                    script_name,
                    finding.get("id", ""),
                    finding.get("name", ""),
                    status,
                    severity,
                    finding.get("detail", ""),
                    finding.get("remediation", ""),
                )
                search_blob = " ".join(str(v).lower() for v in values)
                if term and term not in search_blob:
                    continue

                self._findings_tree.insert("", tk.END, values=values, tags=(status,))

    def _apply_table_filter(self, *_: Any) -> None:
        self._refresh_table()

    def _sort_table(self, column: str) -> None:
        if self._table_sort_col == column:
            self._table_sort_rev = not self._table_sort_rev
        else:
            self._table_sort_col = column
            self._table_sort_rev = False

        def _key(item_id: str) -> Any:
            value = self._findings_tree.set(item_id, column)
            if column == "severity":
                return SEVERITY_ORDER.get(value, -1)
            if column == "status":
                return STATUS_SORT_ORDER.get(value, 99)
            return value.lower() if isinstance(value, str) else value

        items = list(self._findings_tree.get_children(""))
        items.sort(key=_key, reverse=self._table_sort_rev)
        for position, item_id in enumerate(items):
            self._findings_tree.move(item_id, "", position)

    def _copy_table_row(self) -> None:
        selected = self._findings_tree.selection()
        if not selected:
            return
        values = self._findings_tree.item(selected[0], "values")
        self.clipboard_clear()
        self.clipboard_append("\t".join(str(value) for value in values))
        self._status_left_var.set("Selected finding copied to clipboard.")

    def _copy_command(self) -> None:
        selected = self._get_selected_scripts()
        if not selected:
            messagebox.showinfo("CyberSWISS", "Select at least one script first.")
            return

        commands = [
            " ".join(_build_script_command(script["path"], json_mode=True, fix_mode=self._fix_var.get()))
            for script in selected
        ]
        self.clipboard_clear()
        self.clipboard_append("\n".join(commands))
        self._status_left_var.set(f"Copied {len(commands)} command(s) to clipboard.")

    def _open_selected_script(self) -> None:
        selected = self._get_selected_scripts()
        if len(selected) != 1:
            messagebox.showinfo("CyberSWISS", "Select exactly one script to open it.")
            return
        try:
            _open_path(Path(selected[0]["path"]))
            self._status_left_var.set(f"Opened {selected[0]['id']}.")
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("CyberSWISS", f"Unable to open script:\n{exc}")

    def _dry_run(self) -> None:
        selected = self._get_selected_scripts()
        if not selected:
            messagebox.showwarning("CyberSWISS", "No scripts selected.")
            return

        self._clear_output_view()
        self._append_output(
            f"Dry-run prepared at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
            "header",
        )
        self._append_output(
            f"Scripts: {len(selected)} | Fix Mode: {'on' if self._fix_var.get() else 'off'} | "
            f"Timeout: {self._timeout_var.get()}s | Delay: {self._delay_var.get():.1f}s\n\n",
            "timing",
        )
        for script in selected:
            self._append_output(
                f"{script['id']:4s}  {_humanize_script_name(script['name'])}\n",
                "header",
            )
            self._append_output(
                "  " + " ".join(_build_script_command(script["path"], json_mode=True, fix_mode=self._fix_var.get())) + "\n",
                "muted",
            )
        self._summary_var.set(f"Dry-run complete for {len(selected)} script(s).")
        self._status_left_var.set(f"Dry-run listed {len(selected)} script(s).")
        self._notebook.select(0)

    def _run_scripts(self) -> None:
        self._start_run(self._get_selected_scripts(), source="selection")

    def _rerun_failed(self) -> None:
        retry_ids = self._collect_retry_ids()
        if not retry_ids:
            messagebox.showinfo("CyberSWISS", "No failed or warning scripts are available to rerun.")
            return

        scripts = [script for script in self._scripts if script["id"] in retry_ids]
        if not scripts:
            messagebox.showinfo("CyberSWISS", "Retry targets are not available in the current scope.")
            return

        self._start_run(scripts, source="failed")

    def _start_run(self, scripts: list[dict[str, Any]], source: str) -> None:
        if not scripts:
            messagebox.showwarning("CyberSWISS", "No scripts selected.")
            return
        if self._running:
            messagebox.showinfo("CyberSWISS", "A run is already active.")
            return

        timeout = max(10, int(self._timeout_var.get()))
        delay = max(0.0, float(self._delay_var.get()))
        fix_mode = self._fix_var.get()
        stop_on_error = self._stop_on_error_var.get()

        self._reset_session_state()
        self._running = True
        self._stop_event.clear()
        self._current_script_started_at = 0.0
        self._current_script_label = ""
        self._last_run_script_ids = [script["id"] for script in scripts]
        self._set_header_state("RUNNING", _ACCENT_SOFT)
        self._run_btn.config(state=tk.DISABLED)
        self._dry_run_btn.config(state=tk.DISABLED)
        self._rerun_btn.config(state=tk.DISABLED)
        self._stop_btn.config(state=tk.NORMAL, text="Stop")
        self._progress_bar.configure(maximum=max(len(scripts), 1), value=0)
        self._progress_var.set(f"Queued {len(scripts)} script(s)")
        self._summary_var.set(
            f"Prepared {len(scripts)} script(s) from {source} | "
            f"Fix Mode {'on' if fix_mode else 'off'} | Timeout {timeout}s | Delay {delay:.1f}s"
        )
        self._status_left_var.set(f"Running {len(scripts)} script(s)...")
        self._refresh_run_metrics(total=len(scripts), completed=0, status_counts={})
        self._append_output(
            f"CyberSWISS session started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
            "header",
        )
        self._append_output(
            f"Scripts: {len(scripts)} | Source: {source} | Fix Mode: {'on' if fix_mode else 'off'} | "
            f"Timeout: {timeout}s | Delay: {delay:.1f}s | Min Severity: {self._sev_var.get()}\n\n",
            "timing",
        )
        self._notebook.select(0)

        self._worker_thread = threading.Thread(
            target=self._worker,
            args=(list(scripts), fix_mode, timeout, delay, stop_on_error),
            daemon=True,
        )
        self._worker_thread.start()

    def _stop_scripts(self) -> None:
        if not self._running:
            return
        if self._stop_event.is_set():
            return
        self._stop_event.set()
        self._stop_btn.config(state=tk.DISABLED, text="Stopping...")
        self._set_header_state("STOPPING", _RED)
        self._progress_var.set("Stopping current script...")
        self._status_left_var.set("Stop requested. Waiting for the current process tree to terminate...")
        self._append_output("\nStop requested by user.\n", "FAIL")

    def _log_script_result(
        self,
        script: dict[str, Any],
        result: dict[str, Any],
        elapsed: float,
        displayed_findings: list[dict[str, Any]],
        hidden_count: int,
    ) -> None:
        header = f"{script['id']}  {_humanize_script_name(script['name'])}"
        self._append_output(f"\n{header}\n", "header")
        self._append_output(f"Elapsed: {elapsed:.1f}s\n", "timing")

        for finding in displayed_findings:
            status = finding.get("status", "?")
            line = (
                f"[{status}] [{finding.get('severity', '?')}] "
                f"{finding.get('id', '?')}: {finding.get('name', '?')}\n"
            )
            self._append_output(line, status)
            detail = finding.get("detail", "")
            if detail:
                self._append_output(f"  Detail : {detail}\n")
            remedy = finding.get("remediation", "")
            if remedy and status not in {"PASS", "INFO"}:
                self._append_output(f"  Remedy : {remedy}\n", "remedy")

        if hidden_count:
            self._append_output(
                f"{hidden_count} finding(s) hidden by the current severity filter.\n",
                "muted",
            )

        if result.get("error"):
            self._append_output(f"Error: {result['error']}\n", "FAIL")

        fix_report = result.get("fix_report")
        if fix_report:
            if fix_report.get("verification_error"):
                self._append_output(
                    f"Fix verification failed: {fix_report['verification_error']}\n",
                    "FAIL",
                )
            else:
                self._append_output(
                    "Fix verification: "
                    f"fixed {fix_report.get('fixed_count', 0)}, "
                    f"remaining {fix_report.get('remaining_count', 0)}, "
                    f"new issues {fix_report.get('new_issue_count', 0)}\n",
                    "timing",
                )
                for item in fix_report.get("fixed_items", [])[:8]:
                    self._append_output(
                        f"  Fixed: {item.get('id', '')} {item.get('name', '')} "
                        f"({item.get('before_status', '')} -> {item.get('after_status', '')})\n",
                        "PASS",
                    )
                if len(fix_report.get("fixed_items", [])) > 8:
                    self._append_output(
                        f"  ... and {len(fix_report['fixed_items']) - 8} more fixed item(s)\n",
                        "muted",
                    )
                for item in fix_report.get("remaining_items", [])[:8]:
                    self._append_output(
                        f"  Remaining: {item.get('id', '')} {item.get('name', '')} "
                        f"({item.get('after_status', '')})\n",
                        "WARN",
                    )
                if len(fix_report.get("remaining_items", [])) > 8:
                    self._append_output(
                        f"  ... and {len(fix_report['remaining_items']) - 8} more remaining item(s)\n",
                        "muted",
                    )

        stderr = result.get("stderr", "").strip()
        stdout = result.get("stdout", "").strip()
        if stderr and not result.get("findings"):
            self._append_output(f"stderr: {stderr}\n", "muted")
        elif stdout and not result.get("findings"):
            self._append_output(f"stdout: {stdout}\n", "muted")

        if not displayed_findings and not result.get("error"):
            self._append_output("No findings matched the current severity filter.\n", "muted")

    def _worker(
        self,
        scripts: list[dict[str, Any]],
        fix_mode: bool,
        timeout: int,
        delay: float,
        stop_on_error: bool,
    ) -> None:
        min_sev_int = SEVERITY_ORDER.get(self._sev_var.get(), 0)
        status_counts = Counter()
        error_count = 0
        total = len(scripts)

        for index, script in enumerate(scripts, start=1):
            if self._stop_event.is_set():
                break

            self._current_script_started_at = time.monotonic()
            self._current_script_label = script["id"]
            self.after(
                0,
                self._active_script_var.set,
                f"Current: {script['id']} - {_humanize_script_name(script['name'])}",
            )
            self.after(0, self._progress_var.set, f"Running {index}/{total}")

            start = time.monotonic()
            result = _run_script_cancellable(
                script["path"],
                self._stop_event,
                json_mode=True,
                fix_mode=fix_mode,
                timeout=timeout,
            )
            elapsed = time.monotonic() - start
            self._current_script_started_at = 0.0
            result.setdefault("script", Path(script["path"]).stem)
            result.setdefault(
                "script_meta",
                {
                    "id": script["id"],
                    "name": script["name"],
                    "os": script["os"],
                    "path": script["path"],
                },
            )

            if fix_mode and not result.get("error") and not self._stop_event.is_set():
                audit_findings = list(result.get("findings", []))
                self.after(0, self._progress_var.set, f"Verifying fixes for {script['id']}")
                verify_started = time.monotonic()
                verification = _run_script_cancellable(
                    script["path"],
                    self._stop_event,
                    json_mode=True,
                    fix_mode=False,
                    timeout=timeout,
                )
                result["fix_execution_seconds"] = round(elapsed, 3)
                result["verification_seconds"] = round(time.monotonic() - verify_started, 3)
                result["audit_findings"] = audit_findings
                result["verification_result"] = verification
                if verification.get("error"):
                    result["fix_report"] = {
                        "verified": False,
                        "verification_error": verification["error"],
                    }
                else:
                    verification_findings = list(verification.get("findings", []))
                    result["findings"] = verification_findings
                    result["exit_code"] = verification.get("exit_code", result.get("exit_code"))
                    if verification.get("stderr"):
                        result["stderr"] = verification.get("stderr")
                    result["fix_report"] = _summarize_fix_outcome(audit_findings, verification_findings)

            self._results.append(result)

            findings = result.get("findings", [])
            displayed_findings = [
                finding
                for finding in findings
                if SEVERITY_ORDER.get(finding.get("severity", ""), 0) >= min_sev_int
            ]
            for finding in findings:
                status_counts[finding.get("status", "INFO")] += 1
            if result.get("error"):
                error_count += 1

            completed = len(self._results)
            self.after(
                0,
                self._log_script_result,
                script,
                result,
                elapsed,
                displayed_findings,
                max(len(findings) - len(displayed_findings), 0),
            )
            self.after(0, self._progress_bar.configure, {"value": completed})
            self.after(0, self._refresh_run_metrics, total, completed, dict(status_counts))
            self.after(0, self._refresh_table)
            self.after(0, self._refresh_detail_panel)

            if result.get("error") and stop_on_error and not self._stop_event.is_set():
                self._stop_event.set()
                self.after(0, self._append_output, "Stop-on-script-error engaged.\n", "FAIL")

            if delay > 0 and index < total and not self._stop_event.is_set():
                remaining = delay
                while remaining > 0 and not self._stop_event.is_set():
                    self.after(0, self._progress_var.set, f"Delay before next script: {remaining:.1f}s")
                    sleep_for = min(0.2, remaining)
                    time.sleep(sleep_for)
                    remaining -= sleep_for

        self.after(0, self._finalize_run, total, dict(status_counts), error_count)

    def _finalize_run(
        self,
        total: int,
        status_counts: dict[str, int],
        error_count: int,
    ) -> None:
        completed = len(self._results)
        stopped = self._stop_event.is_set()
        summary = (
            f"{'Stopped after' if stopped else 'Completed'} {completed}/{total} scripts | "
            f"FAIL {status_counts.get('FAIL', 0)} | "
            f"WARN {status_counts.get('WARN', 0)} | "
            f"PASS {status_counts.get('PASS', 0)} | "
            f"INFO {status_counts.get('INFO', 0)}"
        )
        if error_count:
            summary += f" | ERRORS {error_count}"
        if self._fix_var.get():
            fix_summary = self._aggregate_fix_report()
            if fix_summary["scripts_with_fix_report"]:
                summary += (
                    f" | FIXED {fix_summary['fixed_count']} | "
                    f"REMAINING {fix_summary['remaining_count']}"
                )
                if fix_summary["verification_failed_count"]:
                    summary += f" | VERIFY-FAILED {fix_summary['verification_failed_count']}"

        self._running = False
        self._worker_thread = None
        self._stop_event.clear()
        self._current_script_started_at = 0.0
        self._current_script_label = ""
        self._active_script_var.set("Current: idle")
        self._progress_var.set("Stopped" if stopped else "Complete")
        self._summary_var.set(summary)
        self._status_left_var.set(summary)
        self._refresh_run_metrics(total=total, completed=completed, status_counts=status_counts)
        self._refresh_table()
        self._refresh_detail_panel()
        self._run_btn.config(state=tk.NORMAL)
        self._dry_run_btn.config(state=tk.NORMAL)
        self._rerun_btn.config(state=tk.NORMAL)
        self._stop_btn.config(state=tk.DISABLED, text="Stop")
        self._set_header_state("IDLE", _ACCENT_SOFT)
        self._append_output(f"\n{summary}\n", "header")

    def _set_header_state(self, label: str, bg_color: str) -> None:
        self._header_state_var.set(label)
        self._header_state_label.configure(bg=bg_color)

    def _require_results(self) -> bool:
        if not self._results:
            messagebox.showinfo("CyberSWISS", "No results available. Run scripts first.")
            return False
        return True

    def _build_report_dict(self) -> dict[str, Any]:
        all_findings = [finding for result in self._results for finding in result.get("findings", [])]
        fix_summary = self._aggregate_fix_report()
        return {
            "cyberswiss_report": True,
            "generated_at": now_iso(),
            "host": self._results[0].get("host", current_host()) if self._results else current_host(),
            "scripts_run": len(self._results),
            "total_findings": len(all_findings),
            "fail_count": sum(1 for finding in all_findings if finding.get("status") == "FAIL"),
            "warn_count": sum(1 for finding in all_findings if finding.get("status") == "WARN"),
            "results": self._results,
            "fix_summary": fix_summary,
            "run_profile": {
                "os_filter": self._os_filter,
                "min_severity": self._sev_var.get(),
                "timeout_seconds": self._timeout_var.get(),
                "delay_seconds": self._delay_var.get(),
                "fix_mode": self._fix_var.get(),
                "last_run_script_ids": self._last_run_script_ids,
            },
        }

    def _save_json(self) -> None:
        if not self._require_results():
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
            initialfile="cyberswiss_audit.json",
        )
        if not path:
            return
        Path(path).write_text(json.dumps(self._build_report_dict(), indent=2, default=str), encoding="utf-8")
        self._status_left_var.set(f"Saved JSON report to {path}")

    def _save_html(self) -> None:
        if not self._require_results():
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML Files", "*.html"), ("All Files", "*.*")],
            initialfile="cyberswiss_audit.html",
        )
        if not path:
            return
        try:
            from report_generator import generate_html  # noqa: PLC0415

            Path(path).write_text(generate_html(self._build_report_dict()), encoding="utf-8")
            self._status_left_var.set(f"Saved HTML report to {path}")
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("CyberSWISS", f"HTML export failed:\n{exc}")

    def _save_csv(self) -> None:
        if not self._require_results():
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            initialfile="cyberswiss_audit.csv",
        )
        if not path:
            return
        try:
            from report_generator import generate_csv  # noqa: PLC0415

            Path(path).write_text(generate_csv(self._build_report_dict()), encoding="utf-8")
            self._status_left_var.set(f"Saved CSV report to {path}")
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("CyberSWISS", f"CSV export failed:\n{exc}")

    def _save_text(self) -> None:
        if not self._require_results():
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            initialfile="cyberswiss_audit.txt",
        )
        if not path:
            return
        try:
            from report_generator import generate_text  # noqa: PLC0415

            Path(path).write_text(generate_text(self._build_report_dict()), encoding="utf-8")
            self._status_left_var.set(f"Saved text report to {path}")
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("CyberSWISS", f"Text export failed:\n{exc}")

    def _quick_save_snapshot(self) -> None:
        if not self._require_results():
            return

        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = REPORTS_DIR / f"cyberswiss_{stamp}"
        report = self._build_report_dict()

        try:
            from report_generator import generate_csv, generate_html, generate_text  # noqa: PLC0415

            base.with_suffix(".json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
            base.with_suffix(".html").write_text(generate_html(report), encoding="utf-8")
            base.with_suffix(".csv").write_text(generate_csv(report), encoding="utf-8")
            base.with_suffix(".txt").write_text(generate_text(report), encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("CyberSWISS", f"Snapshot export failed:\n{exc}")
            return

        self._last_snapshot_base = base
        self._status_left_var.set(f"Snapshot saved to {base.name}.*")
        self._append_output(f"\nSnapshot saved to {base}.*\n", "timing")

    def _open_reports_dir(self) -> None:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        try:
            _open_path(REPORTS_DIR)
            self._status_left_var.set(f"Opened reports directory: {REPORTS_DIR}")
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("CyberSWISS", f"Unable to open reports directory:\n{exc}")

    def _on_close(self) -> None:
        if not self._running:
            self.destroy()
            return

        self._close_after_stop = True
        self._stop_scripts()
        self._status_left_var.set("Window close deferred until the active run stops.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CyberSWISS GUI")
    parser.add_argument("--os", dest="os_filter", choices=["windows", "linux", "both"], default=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        app = CyberSWISSApp(os_filter=args.os_filter)
        app.mainloop()
    except tk.TclError as exc:
        print(f"ERROR: GUI could not start: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
