# =============================================================================
# CyberSWISS – Makefile
# =============================================================================
#
#  ┌─────────────────────────────────────────────────────────────────────────┐
#  │  END-USER targets  (running / reporting / setup)   →  make help         │
#  │  DEVELOPER targets (testing / linting / CI)        →  make help-dev     │
#  └─────────────────────────────────────────────────────────────────────────┘
#
# Quick start (end users):
#   make help          Show user-facing targets
#   make check-env     Validate all required tools are present
#   make install       Install Python dependencies
#   make scan          Run all audit scripts for the current OS
#   make report        Full scan → JSON + CSV + HTML
#
# Quick start (developers):
#   make help-dev      Show developer targets
#   make test          Run the test suite
#   make lint          Run all linters
#   make ci            Full CI gate
#
# Overridable variables (pass on command line):
#   PYTHON=python3.11       Override Python binary
#   SCRIPTS="W01 L07 L15"  Scan specific script IDs  (used by scan-id)
#   MIN_SEV=High            Minimum severity filter   (used by scan-sev)
#   DELAY=2                 Seconds between scripts   (used by scan-delay)
#   TAG=network             Filter by tag             (used by scan-tag)
#   VERBOSE=1               Enable verbose runner output
# =============================================================================

# ── Tuneable variables ────────────────────────────────────────────────────────
PYTHON      ?= python3
PIP         ?= $(PYTHON) -m pip
PYTEST      ?= $(PYTHON) -m pytest
RUNNER      := common/runner.py
REPORT_DIR  := reports
ARCHIVE_DIR := reports/archive
TIMESTAMP   := $(shell date +%Y%m%d_%H%M%S)
REPORT_BASE := $(REPORT_DIR)/cyberswiss_$(TIMESTAMP)

# Scan tuneables (override on CLI: make scan-sev MIN_SEV=Critical)
SCRIPTS     ?=
MIN_SEV     ?= Info
DELAY       ?= 0
TAG         ?=

# Verbose flag: VERBOSE=1 passes --verbose to the runner
_VERBOSE    := $(if $(filter 1,$(VERBOSE)),--verbose,)

# ── Colour helpers (degrade gracefully if tput unavailable) ──────────────────
BOLD  := $(shell tput bold   2>/dev/null || printf '')
RED   := $(shell tput setaf 1 2>/dev/null || printf '')
GRN   := $(shell tput setaf 2 2>/dev/null || printf '')
YLW   := $(shell tput setaf 3 2>/dev/null || printf '')
CYN   := $(shell tput setaf 6 2>/dev/null || printf '')
RST   := $(shell tput sgr0   2>/dev/null || printf '')

# ── Internal helpers ──────────────────────────────────────────────────────────
define _info
	@printf '$(CYN)[*]$(RST) %s\n' $(1)
endef

define _ok
	@printf '$(GRN)[✔]$(RST) %s\n' $(1)
endef

define _warn
	@printf '$(YLW)[!]$(RST) %s\n' $(1)
endef

define _err
	@printf '$(RED)[✘] ERROR: %s$(RST)\n' $(1) >&2
endef

# Guard: abort with a clear message if a required binary is missing.
# Usage: $(call _require_cmd,nmap,"Install nmap: sudo apt install nmap")
define _require_cmd
	@command -v $(1) >/dev/null 2>&1 || { \
	    printf '$(RED)[✘] Required command not found: $(BOLD)%s$(RST)\n' "$(1)" >&2; \
	    printf '    Hint: %s\n' "$(2)" >&2; \
	    exit 1; \
	}
endef

# Guard: abort if the runner script is missing.
define _require_runner
	@test -f "$(RUNNER)" || { \
	    printf '$(RED)[✘] Runner not found: %s$(RST)\n' "$(RUNNER)" >&2; \
	    printf '    Has the repo been cloned correctly?\n' >&2; \
	    exit 1; \
	}
endef

# Guard: abort if requirements.txt is missing.
define _require_requirements
	@test -f requirements.txt || { \
	    printf '$(RED)[✘] requirements.txt not found in $(CURDIR)$(RST)\n' >&2; \
	    exit 1; \
	}
endef

# Guard: check Python version is >= 3.8
define _require_python
	$(call _require_cmd,$(PYTHON),"Install Python 3.8+: https://www.python.org/downloads/")
	@$(PYTHON) -c "import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)" || { \
	    printf '$(RED)[✘] Python 3.8+ is required. Found: $(RST)'; \
	    $(PYTHON) --version 2>&1 >&2; \
	    exit 1; \
	}
endef

# ── .PHONY declaration ────────────────────────────────────────────────────────
# [USER]  – targets meant for end users (scanning, reporting, setup)
# [DEV]   – targets meant for developers (testing, linting, CI, formatting)

.PHONY: \
    help help-dev \
    check-env install install-all \
    scan scan-linux scan-windows \
    scan-high scan-critical scan-sev \
    scan-dry scan-fix scan-id scan-tag scan-delay \
    report report-db report-diff \
    archive archive-clean \
    db-clean clean clean-reports clean-all \
    check-python check-runner check-lint-tools upgrade \
    format format-check \
    test test-cov test-fast test-verbose \
    lint lint-python lint-shell lint-pylint \
    ci ci-lint ci-test ci-scan

# =============================================================================
# [USER] HELP  –  shown by default: make / make help
# =============================================================================
.DEFAULT_GOAL := help

help:
	@echo ''
	@printf '$(BOLD)$(CYN)CyberSWISS Security Scanner$(RST)\n'
	@printf '$(CYN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RST)\n'
	@printf '  Run $(BOLD)make help-dev$(RST) to see developer / CI targets.\n'
	@echo ''
	@printf '$(BOLD)Setup$(RST)\n'
	@printf '  $(CYN)%-26s$(RST) %s\n' check-env       "Validate required tools are installed"
	@printf '  $(CYN)%-26s$(RST) %s\n' install         "Install Python dependencies (requirements.txt)"
	@printf '  $(CYN)%-26s$(RST) %s\n' install-all     "Install Python deps + OS-level tooling (Linux)"
	@echo ''
	@printf '$(BOLD)Scanning$(RST)\n'
	@printf '  $(CYN)%-26s$(RST) %s\n' scan            "Run all scripts for the current OS"
	@printf '  $(CYN)%-26s$(RST) %s\n' scan-linux      "Linux scripts only"
	@printf '  $(CYN)%-26s$(RST) %s\n' scan-windows    "Windows scripts only"
	@printf '  $(CYN)%-26s$(RST) %s\n' scan-high       "Scripts with severity >= High"
	@printf '  $(CYN)%-26s$(RST) %s\n' scan-critical   "Scripts with severity = Critical"
	@printf '  $(CYN)%-26s$(RST) %s\n' "scan-sev MIN_SEV=X"   "Severity >= X  (Info/Low/Med/High/Critical)"
	@printf '  $(CYN)%-26s$(RST) %s\n' scan-dry        "Dry-run – list scripts without executing"
	@printf '  $(CYN)%-26s$(RST) %s\n' scan-fix        "Run with automatic remediations (⚠ modifies system)"
	@printf '  $(CYN)%-26s$(RST) %s\n' 'scan-id SCRIPTS="L07 W01"' "Run specific script IDs"
	@printf '  $(CYN)%-26s$(RST) %s\n' "scan-tag TAG=network"  "Run scripts matching a tag"
	@printf '  $(CYN)%-26s$(RST) %s\n' "scan-delay DELAY=2"    "Rate-limited scan (N seconds between scripts)"
	@echo ''
	@printf '$(BOLD)Reporting$(RST)\n'
	@printf '  $(CYN)%-26s$(RST) %s\n' report          "Full scan → timestamped JSON + CSV + HTML"
	@printf '  $(CYN)%-26s$(RST) %s\n' report-db       "report + save to DB and show drift"
	@printf '  $(CYN)%-26s$(RST) %s\n' report-diff     "Show drift vs previous DB entry (no re-scan)"
	@printf '  $(CYN)%-26s$(RST) %s\n' archive         "Zip all reports into reports/archive/"
	@printf '  $(CYN)%-26s$(RST) %s\n' archive-clean   "Remove archived zips older than 30 days"
	@echo ''
	@printf '$(BOLD)Cleanup$(RST)\n'
	@printf '  $(CYN)%-26s$(RST) %s\n' clean           "Remove Python cache files"
	@printf '  $(CYN)%-26s$(RST) %s\n' clean-reports   "Remove generated reports (keeps archive/)"
	@printf '  $(CYN)%-26s$(RST) %s\n' clean-all       "clean + clean-reports"
	@printf '  $(CYN)%-26s$(RST) %s\n' db-clean        "Remove the local scan history database"
	@echo ''
	@printf '$(BOLD)Variables$(RST) (pass on command line)\n'
	@printf '  $(YLW)%-26s$(RST) %s\n' "PYTHON=python3.11"    "Override Python binary (default: python3)"
	@printf '  $(YLW)%-26s$(RST) %s\n' 'SCRIPTS="L07 W01"'    "Script IDs for scan-id"
	@printf '  $(YLW)%-26s$(RST) %s\n' "MIN_SEV=High"         "Minimum severity for scan-sev"
	@printf '  $(YLW)%-26s$(RST) %s\n' "DELAY=2"              "Inter-script delay for scan-delay"
	@printf '  $(YLW)%-26s$(RST) %s\n' "TAG=network"          "Tag filter for scan-tag"
	@printf '  $(YLW)%-26s$(RST) %s\n' "VERBOSE=1"            "Enable verbose runner output"
	@echo ''

# =============================================================================
# [DEV] HELP  –  make help-dev
# =============================================================================
help-dev:
	@echo ''
	@printf '$(BOLD)$(CYN)CyberSWISS – Developer / CI Targets$(RST)\n'
	@printf '$(CYN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RST)\n'
	@printf '  Run $(BOLD)make help$(RST) to see end-user targets.\n'
	@echo ''
	@printf '$(BOLD)Dependency Management$(RST)\n'
	@printf '  $(CYN)%-22s$(RST) %s\n' check-python    "Assert Python >= 3.8 is available"
	@printf '  $(CYN)%-22s$(RST) %s\n' upgrade         "Upgrade all installed Python packages"
	@echo ''
	@printf '$(BOLD)Code Formatting$(RST)\n'
	@printf '  $(CYN)%-22s$(RST) %s\n' format          "Auto-format with black + isort (if available)"
	@printf '  $(CYN)%-22s$(RST) %s\n' format-check    "Dry-run format check (CI-safe, non-destructive)"
	@echo ''
	@printf '$(BOLD)Testing$(RST)\n'
	@printf '  $(CYN)%-22s$(RST) %s\n' test            "Run full pytest suite"
	@printf '  $(CYN)%-22s$(RST) %s\n' test-cov        "Run tests with HTML coverage report"
	@printf '  $(CYN)%-22s$(RST) %s\n' test-fast       "Run tests, stop on first failure"
	@printf '  $(CYN)%-22s$(RST) %s\n' test-verbose    "Run tests with full stdout"
	@echo ''
	@printf '$(BOLD)Linting$(RST)\n'
	@printf '  $(CYN)%-22s$(RST) %s\n' lint            "Run all linters (flake8 + shellcheck + pylint)"
	@printf '  $(CYN)%-22s$(RST) %s\n' lint-python     "flake8 on common/ and tests/"
	@printf '  $(CYN)%-22s$(RST) %s\n' lint-shell      "shellcheck on linux/ shell scripts"
	@printf '  $(CYN)%-22s$(RST) %s\n' lint-pylint     "pylint on core modules (score ≥ 7.0, non-blocking)"
	@echo ''
	@printf '$(BOLD)CI / Pipeline$(RST)\n'
	@printf '  $(CYN)%-22s$(RST) %s\n' ci              "Full gate: check-env → lint → test → scan-dry"
	@printf '  $(CYN)%-22s$(RST) %s\n' ci-lint         "CI lint only"
	@printf '  $(CYN)%-22s$(RST) %s\n' ci-test         "CI test only"
	@printf '  $(CYN)%-22s$(RST) %s\n' ci-scan         "CI scan (dry-run only)"
	@echo ''

# #############################################################################
#  ╔══════════════════════════════════════════════════════════════════════════╗
#  ║                        END-USER TARGETS                                 ║
#  ╚══════════════════════════════════════════════════════════════════════════╝
# #############################################################################

# =============================================================================
# [USER] ENVIRONMENT / SETUP
# =============================================================================
check-env: check-python check-runner
	@echo ''
	$(call _info,"Checking required tools…")
	$(call _require_cmd,git,"Install git via your package manager")
	$(call _ok,"git")
	$(call _require_cmd,bash,"bash is required to execute linux/ audit scripts")
	$(call _ok,"bash")
	@echo ''
	$(call _info,"Checking optional tools (warnings only)…")
	@for tool in nmap nikto shellcheck flake8 black; do \
	    if command -v $$tool >/dev/null 2>&1; then \
	        printf '$(GRN)[✔]$(RST) %-14s %s\n' "$$tool" "$$($$tool --version 2>&1 | head -1)"; \
	    else \
	        printf '$(YLW)[!]$(RST) %-14s not found (optional)\n' "$$tool"; \
	    fi; \
	done
	@echo ''
	$(call _ok,"Environment check complete.")

install: check-python
	$(call _require_requirements)
	$(call _info,"Upgrading pip…")
	$(PIP) install --upgrade pip
	$(call _info,"Installing Python dependencies…")
	$(PIP) install -r requirements.txt
	$(call _ok,"Python dependencies installed.")

install-all: install
	$(call _require_cmd,bash,"bash is required to run the install script")
	@test -f setup/install_runtime_linux.sh || { \
	    printf '$(RED)[✘] setup/install_runtime_linux.sh not found$(RST)\n' >&2; exit 1; \
	}
	$(call _info,"Running OS-level runtime installer…")
	bash setup/install_runtime_linux.sh --optional --yes
	$(call _ok,"Full installation complete.")

# =============================================================================
# [USER] SCANNING
# =============================================================================
scan: check-python check-runner
	$(call _info,"Running all scripts for current OS…")
	-$(PYTHON) $(RUNNER) $(_VERBOSE)
	@printf '$(CYN)[*]$(RST) Exit code reflects audit findings (0=clean, 1=warnings, 2=failures).\n'

scan-linux: check-python check-runner
	$(call _info,"Running Linux audit scripts…")
	-$(PYTHON) $(RUNNER) --os linux $(_VERBOSE)
	@printf '$(CYN)[*]$(RST) Exit code reflects audit findings (0=clean, 1=warnings, 2=failures).\n'

scan-windows: check-python check-runner
	$(call _info,"Running Windows audit scripts…")
	-$(PYTHON) $(RUNNER) --os windows $(_VERBOSE)
	@printf '$(CYN)[*]$(RST) Exit code reflects audit findings (0=clean, 1=warnings, 2=failures).\n'

scan-high: check-python check-runner
	$(call _info,"Running scripts with severity >= High…")
	-$(PYTHON) $(RUNNER) --min-severity High $(_VERBOSE)
	@printf '$(CYN)[*]$(RST) Exit code reflects audit findings (0=clean, 1=warnings, 2=failures).\n'

scan-critical: check-python check-runner
	$(call _info,"Running scripts with severity = Critical…")
	-$(PYTHON) $(RUNNER) --min-severity Critical $(_VERBOSE)
	@printf '$(CYN)[*]$(RST) Exit code reflects audit findings (0=clean, 1=warnings, 2=failures).\n'

scan-sev: check-python check-runner
	@test -n "$(MIN_SEV)" || { \
	    printf '$(RED)[✘] MIN_SEV is not set. Example: make scan-sev MIN_SEV=High$(RST)\n' >&2; exit 1; \
	}
	$(call _info,"Running scripts with severity >= $(MIN_SEV)…")
	-$(PYTHON) $(RUNNER) --min-severity $(MIN_SEV) $(_VERBOSE)
	@printf '$(CYN)[*]$(RST) Exit code reflects audit findings (0=clean, 1=warnings, 2=failures).\n'

scan-dry: check-python check-runner
	$(call _info,"Dry-run – listing scripts that would execute…")
	$(PYTHON) $(RUNNER) --dry-run

scan-fix: check-python check-runner
	$(call _warn,"Running with auto-remediation (--fix). This may modify system configuration.")
	@printf 'Press Ctrl-C within 5 seconds to abort… '; sleep 5 || exit 0; echo ''
	$(PYTHON) $(RUNNER) --fix $(_VERBOSE); true
	@printf '$(CYN)[*]$(RST) Exit code reflects audit findings (0=clean, 1=warnings, 2=failures).\n'

scan-id: check-python check-runner
	@test -n "$(SCRIPTS)" || { \
	    printf '$(RED)[✘] SCRIPTS is not set.\n    Example: make scan-id SCRIPTS="L07 W01 L15"$(RST)\n' >&2; \
	    exit 1; \
	}
	$(call _info,"Running scripts: $(SCRIPTS)")
	-$(PYTHON) $(RUNNER) --scripts $(SCRIPTS) $(_VERBOSE)
	@printf '$(CYN)[*]$(RST) Exit code reflects audit findings (0=clean, 1=warnings, 2=failures).\n'

scan-tag: check-python check-runner
	@test -n "$(TAG)" || { \
	    printf '$(RED)[✘] TAG is not set.\n    Example: make scan-tag TAG=network$(RST)\n' >&2; \
	    exit 1; \
	}
	$(call _info,"Running scripts with tag: $(TAG)")
	-$(PYTHON) $(RUNNER) --tags $(TAG) $(_VERBOSE)
	@printf '$(CYN)[*]$(RST) Exit code reflects audit findings (0=clean, 1=warnings, 2=failures).\n'

scan-delay: check-python check-runner
	$(call _info,"Rate-limited scan (delay=$(DELAY)s between scripts)…")
	-$(PYTHON) $(RUNNER) --delay $(DELAY) $(_VERBOSE)
	@printf '$(CYN)[*]$(RST) Exit code reflects audit findings (0=clean, 1=warnings, 2=failures).\n'

# =============================================================================
# [USER] REPORTING
# =============================================================================
report: check-python check-runner
	@mkdir -p $(REPORT_DIR)
	$(call _info,"Generating full report…")
	-$(PYTHON) $(RUNNER) $(_VERBOSE) \
	    --output  $(REPORT_BASE).json \
	    --csv     $(REPORT_BASE).csv \
	    --html    $(REPORT_BASE).html
	@test -f "$(REPORT_BASE).json" || { printf '$(RED)[✘] Report generation failed – no output file written.$(RST)\n' >&2; exit 1; }
	$(call _ok,"Reports written:")
	@printf '  $(CYN)→$(RST) $(REPORT_BASE).json\n'
	@printf '  $(CYN)→$(RST) $(REPORT_BASE).csv\n'
	@printf '  $(CYN)→$(RST) $(REPORT_BASE).html\n'

report-db: check-python check-runner
	@mkdir -p $(REPORT_DIR)
	$(call _info,"Generating report + saving to DB (with drift)…")
	-$(PYTHON) $(RUNNER) $(_VERBOSE) \
	    --output  $(REPORT_BASE).json \
	    --csv     $(REPORT_BASE).csv \
	    --html    $(REPORT_BASE).html \
	    --save-db --diff
	@test -f "$(REPORT_BASE).json" || { printf '$(RED)[✘] Report + DB save failed – no output file written.$(RST)\n' >&2; exit 1; }
	$(call _ok,"DB report complete: $(REPORT_BASE).json")

report-diff: check-python check-runner
	$(call _info,"Showing drift vs last DB entry (no re-scan)…")
	$(PYTHON) $(RUNNER) --diff --dry-run $(_VERBOSE)

archive:
	@mkdir -p $(ARCHIVE_DIR)
	@FILES=$$(ls $(REPORT_DIR)/*.json $(REPORT_DIR)/*.csv $(REPORT_DIR)/*.html 2>/dev/null); \
	if [ -z "$$FILES" ]; then \
	    printf '$(YLW)[!]$(RST) No report files found in $(REPORT_DIR)/ to archive.\n'; \
	else \
	    ZIP="$(ARCHIVE_DIR)/cyberswiss_archive_$(TIMESTAMP).zip"; \
	    zip -j "$$ZIP" $$FILES && \
	    printf '$(GRN)[✔]$(RST) Archived to %s\n' "$$ZIP"; \
	fi

archive-clean:
	$(call _warn,"Removing archived zips older than 30 days from $(ARCHIVE_DIR)/…")
	@find $(ARCHIVE_DIR) -name "*.zip" -mtime +30 -delete 2>/dev/null && \
	    $(call _ok,"Old archives removed.") || true

# =============================================================================
# [USER] CLEANUP
# =============================================================================
clean:
	$(call _info,"Removing Python cache files…")
	@find . -type d -name __pycache__      -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc"          -delete         2>/dev/null || true
	@find . -type d -name ".pytest_cache"  -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name "*.egg-info"     -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".mypy_cache"    -exec rm -rf {} + 2>/dev/null || true
	$(call _ok,"Cache files removed.")

clean-reports:
	$(call _warn,"This will delete all files in $(REPORT_DIR)/ except the archive/ subdirectory.")
	@find $(REPORT_DIR) -maxdepth 1 -type f \( -name "*.json" -o -name "*.csv" -o -name "*.html" \) \
	    -delete 2>/dev/null && printf '$(GRN)[✔]$(RST) Report files removed.\n' || true

clean-all: clean clean-reports
	$(call _ok,"Full cleanup complete.")

db-clean:
	$(call _warn,"This will delete the local scan history database.")
	@read -p "Are you sure? [y/N] " _ans; \
	case "$$_ans" in \
	    [yY]*) find . -name "cyberswiss*.db" -delete 2>/dev/null && \
	           printf '$(GRN)[✔]$(RST) Database files removed.\n' ;; \
	    *)     printf '$(YLW)[!]$(RST) Aborted.\n' ;; \
	esac

# #############################################################################
#  ╔══════════════════════════════════════════════════════════════════════════╗
#  ║                        DEVELOPER TARGETS                                ║
#  ╚══════════════════════════════════════════════════════════════════════════╝
# #############################################################################

# =============================================================================
# [DEV] INTERNAL CHECKS  (used as prerequisites, not listed in user help)
# =============================================================================
check-python:
	$(call _require_python)
	$(call _ok,"Python OK: $$($(PYTHON) --version)")

check-runner:
	$(call _require_runner)
	$(call _ok,"Runner found: $(RUNNER)")

check-lint-tools:
	$(call _require_python)
	@$(PYTHON) -c "import flake8" 2>/dev/null || { \
	    printf '$(RED)[✘] flake8 not installed. Run: make install$(RST)\n' >&2; \
	    exit 1; \
	}
	$(call _ok,"flake8 available")

# =============================================================================
# [DEV] DEPENDENCY MANAGEMENT
# =============================================================================
upgrade: check-python
	$(call _info,"Upgrading all installed packages…")
	$(PIP) install --upgrade pip
	$(PIP) list --outdated --format=freeze 2>/dev/null \
	    | grep -v '^\-e' \
	    | cut -d = -f 1 \
	    | xargs -r $(PIP) install --upgrade \
	    && $(call _ok,"All packages upgraded.") \
	    || $(call _warn,"Some packages may not have upgraded cleanly. Check output above.")

# =============================================================================
# [DEV] FORMATTING
# =============================================================================
format: check-python
	@if $(PYTHON) -m black --version >/dev/null 2>&1; then \
	    printf '$(CYN)[*]$(RST) Running black…\n'; \
	    $(PYTHON) -m black common/ tests/; \
	else \
	    printf '$(YLW)[!]$(RST) black not installed – skipping (pip install black)\n'; \
	fi
	@if $(PYTHON) -m isort --version >/dev/null 2>&1; then \
	    printf '$(CYN)[*]$(RST) Running isort…\n'; \
	    $(PYTHON) -m isort common/ tests/; \
	else \
	    printf '$(YLW)[!]$(RST) isort not installed – skipping (pip install isort)\n'; \
	fi

format-check: check-python
	@FAIL=0; \
	if $(PYTHON) -m black --version >/dev/null 2>&1; then \
	    $(PYTHON) -m black --check common/ tests/ || FAIL=1; \
	else \
	    printf '$(YLW)[!]$(RST) black not installed – skipping\n'; \
	fi; \
	if $(PYTHON) -m isort --version >/dev/null 2>&1; then \
	    $(PYTHON) -m isort --check-only common/ tests/ || FAIL=1; \
	else \
	    printf '$(YLW)[!]$(RST) isort not installed – skipping\n'; \
	fi; \
	if [ $$FAIL -ne 0 ]; then \
	    printf '$(RED)[✘] Format check failed. Run: make format$(RST)\n' >&2; \
	    exit 1; \
	fi
	$(call _ok,"Format check passed.")

# =============================================================================
# [DEV] TESTING
# =============================================================================
test: check-python
	$(call _require_cmd,$(PYTEST),"Run: make install")
	$(call _info,"Running test suite…")
	$(PYTEST) tests/ -v
	$(call _ok,"Tests passed.")

test-cov: check-python
	$(call _info,"Running tests with coverage…")
	$(PYTEST) tests/ -v \
	    --cov=common \
	    --cov-report=term-missing \
	    --cov-report=html:reports/coverage \
	    || { printf '$(RED)[✘] Tests failed or coverage threshold not met$(RST)\n' >&2; exit 1; }
	$(call _ok,"Coverage report: reports/coverage/index.html")

test-fast: check-python
	$(call _info,"Running tests (stop on first failure)…")
	$(PYTEST) tests/ -x -q

test-verbose: check-python
	$(call _info,"Running tests (verbose output)…")
	$(PYTEST) tests/ -v -s

# =============================================================================
# [DEV] LINTING
# =============================================================================
lint: check-lint-tools lint-python lint-shell lint-pylint
	$(call _ok,"All lint checks complete.")

lint-python: check-lint-tools
	$(call _info,"Running flake8…")
	$(PYTHON) -m flake8 common/ tests/ \
	    --max-line-length=120 \
	    --extend-ignore=E203,W503 \
	    && $(call _ok,"flake8 passed.") \
	    || { printf '$(RED)[✘] flake8 found issues. Fix before committing.$(RST)\n' >&2; exit 1; }

lint-shell:
	$(call _info,"Running shellcheck…")
	@if command -v shellcheck >/dev/null 2>&1; then \
	    shellcheck linux/*.sh setup/install_runtime_linux.sh \
	        && printf '$(GRN)[✔]$(RST) shellcheck passed.\n' \
	        || { printf '$(RED)[✘] shellcheck found issues in shell scripts.$(RST)\n' >&2; exit 1; }; \
	else \
	    printf '$(YLW)[!]$(RST) shellcheck not installed – skipping shell lint\n'; \
	    printf '    Install: sudo apt install shellcheck\n'; \
	fi

lint-pylint: check-python
	$(call _info,"Running pylint (informational)…")
	@if $(PYTHON) -m pylint --version >/dev/null 2>&1; then \
	    $(PYTHON) -m pylint common/utils.py common/runner.py common/report_generator.py \
	        --disable=C0114,C0115,C0116,R0903,W0611 \
	        --fail-under=7.0 \
	        && printf '$(GRN)[✔]$(RST) pylint passed.\n' \
	        || printf '$(YLW)[!]$(RST) pylint score below threshold (non-blocking).\n'; \
	else \
	    printf '$(YLW)[!]$(RST) pylint not installed – skipping (pip install pylint)\n'; \
	fi

# =============================================================================
# [DEV] CI / PIPELINE
# =============================================================================
ci: ci-lint ci-test ci-scan
	$(call _ok,"CI gate passed: lint + test + scan-dry all succeeded.")

ci-lint: lint-python lint-shell
	$(call _ok,"CI lint passed.")

ci-test: test
	$(call _ok,"CI tests passed.")

ci-scan: scan-dry
	$(call _ok,"CI scan (dry-run) passed.")
