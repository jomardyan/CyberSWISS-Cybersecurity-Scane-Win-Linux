"""
CyberSWISS – Structural tests for the Tkinter GUI (common/gui.py).

The GUI cannot be instantiated on a headless runner without tkinter, so these
tests parse the module instead. That still catches the failure that actually
bites in practice: a menu entry or key binding wired to a method that does not
exist, which raises only when a user clicks it.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "common"))

GUI_PATH = REPO_ROOT / "common" / "gui.py"


@pytest.fixture(scope="module")
def tree():
    return ast.parse(GUI_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def method_names(tree):
    """Every method defined anywhere in the module."""
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _self_attributes_passed_as(tree, keyword: str) -> set[str]:
    """Collect `self.<name>` values passed as the given keyword argument."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if kw.arg != keyword:
                continue
            value = kw.value
            if (
                isinstance(value, ast.Attribute)
                and isinstance(value.value, ast.Name)
                and value.value.id == "self"
            ):
                found.add(value.attr)
    return found


class TestGuiModule:
    def test_module_parses(self, tree):
        assert isinstance(tree, ast.Module)

    def test_compiles_to_bytecode(self):
        compile(GUI_PATH.read_text(encoding="utf-8"), str(GUI_PATH), "exec")

    def test_tkinter_import_is_guarded(self):
        """A missing tkinter must produce a clear message, not a raw ImportError."""
        source = GUI_PATH.read_text(encoding="utf-8")
        head = source[: source.index("class ") if "class " in source else len(source)]
        assert "try:" in head and "tkinter" in head


class TestMenuWiring:
    def test_every_menu_command_resolves_to_a_method(self, tree, method_names):
        commands = _self_attributes_passed_as(tree, "command")
        missing = sorted(c for c in commands if c not in method_names)
        assert not missing, f"Menu entries wired to non-existent methods: {missing}"

    def test_every_bound_callback_resolves_to_a_method(self, tree, method_names):
        # self.bind("<Key>", self._handler) – positional, so check Call args too
        missing = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr in ("bind", "bind_all")):
                continue
            for arg in node.args:
                if (
                    isinstance(arg, ast.Attribute)
                    and isinstance(arg.value, ast.Name)
                    and arg.value.id == "self"
                    and arg.attr not in method_names
                    and not arg.attr.endswith("_var")
                ):
                    missing.append(arg.attr)
        assert not missing, f"Key bindings referencing non-existent methods: {missing}"


class TestExportSurface:
    EXPECTED_EXPORTS = [
        "_save_json",
        "_save_html",
        "_save_csv",
        "_save_text",
        "_save_sarif",
        "_save_markdown",
        "_quick_save_snapshot",
    ]

    @pytest.mark.parametrize("name", EXPECTED_EXPORTS)
    def test_export_method_exists(self, method_names, name):
        assert name in method_names

    def test_every_export_format_is_reachable_from_the_menu(self, tree):
        commands = _self_attributes_passed_as(tree, "command")
        for name in self.EXPECTED_EXPORTS:
            assert name in commands, f"{name} is defined but not reachable from the menu"

    def test_snapshot_writes_every_format(self):
        source = GUI_PATH.read_text(encoding="utf-8")
        snapshot = source[source.index("def _quick_save_snapshot"):]
        snapshot = snapshot[: snapshot.index("def _open_reports_dir")]
        for suffix in (".json", ".html", ".csv", ".txt", ".sarif", ".md"):
            assert f'with_suffix("{suffix}")' in snapshot, f"snapshot omits {suffix}"

    def test_generators_are_imported_from_the_shared_module(self):
        """The GUI must not re-implement report rendering."""
        source = GUI_PATH.read_text(encoding="utf-8")
        for generator in ("generate_html", "generate_csv", "generate_text",
                          "generate_sarif", "generate_markdown"):
            assert "from report_generator import" in source
            assert generator in source
