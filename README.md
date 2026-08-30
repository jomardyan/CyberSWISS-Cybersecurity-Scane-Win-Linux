# CyberSWISS – Enterprise Security Audit & Remediation Platform

[![CI](https://github.com/jomardyan/CyberSWISS-Cybersecurity-Scan-Win-Linux/actions/workflows/ci.yml/badge.svg)](https://github.com/jomardyan/CyberSWISS-Cybersecurity-Scan-Win-Linux/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue)](https://www.python.org/downloads/)
[![Bash 4.0+](https://img.shields.io/badge/Bash-4.0%2B-brightgreen)](https://www.gnu.org/software/bash/)
[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-blue)](https://docs.microsoft.com/en-us/powershell/)

> **AUTHORIZED INTERNAL USE ONLY** — All scripts are **read-only by default**.  
> Remediation requires an explicit `--fix` / `-Fix` flag and administrative privileges.

---

## Table of Contents

- [Overview](#overview)
- [Business Value](#business-value)
- [Key Features](#key-features)
- [Repository Structure](#repository-structure)
- [Quick Start](#quick-start)
  - [Prerequisites](#prerequisites)
  - [Install Dependencies](#install-dependencies)
  - [Run Audits](#run-audits)
  - [Reporting](#reporting)
  - [Drift Detection](#drift-detection)
  - [Trend Analysis](#trend-analysis)
  - [Baselines & Accepted Risk](#baselines--accepted-risk)
  - [Remediation](#remediation)
  - [GUI](#gui)
  - [REST API Server](#rest-api-server)
- [Make / Developer Workflow](#make--developer-workflow)
- [REST API Reference](#rest-api-reference)
- [Script Catalog](#script-catalog)
  - [Windows PowerShell Scripts (33)](#windows-powershell-scripts-33)
  - [Linux Bash Scripts (33)](#linux-bash-scripts-33)
- [Active Directory & GPO Integration](#active-directory--gpo-integration)
- [Drift Detection Detail](#drift-detection-detail)
- [GitHub Actions CI/CD](#github-actions-cicd)
- [CLI Reference](#cli-reference)
- [Exit Codes](#exit-codes)
- [Make Reference](#make-reference)
- [Documentation](#documentation)
- [Security Notice](#security-notice)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

**CyberSWISS** is a production-grade, cross-platform security audit and remediation platform built for endpoints, servers, and Active Directory environments. It provides **66 runnable audit scripts** (33 Windows PowerShell + 33 Linux Bash), a Python orchestrator, REST API server, SQLite scan history with drift detection and trend analytics, baseline waivers for accepted risk, multi-format reporting (HTML, JSON, CSV, plain-text, SARIF, Markdown), and a Tkinter GUI — all following a unified interface.

### Design Principles

| Principle | Description |
|---|---|
| **Defensive only** | Detection, validation, inventory, and configuration review — no offensive capabilities |
| **Read-only by default** | No system changes without an explicit `--fix` / `-Fix` flag |
| **No secrets in logs** | All output is safe to store and forward to a SIEM |
| **SIEM-ready** | Every script supports `--json` / `-Json` for structured, machine-readable output |
| **AD/GPO compatible** | W16 enforces domain policy via GPO-safe registry writes; no RSAT required |
| **Drift detection** | Built-in SQLite history surfaces new, resolved, and changed findings across successive scans |
| **CI/CD ready** | `--diff` flag returns exit code `2` on regressions; SARIF output feeds GitHub code scanning; GitHub Actions workflow included |
| **Accepted risk is explicit** | Signed-off findings live in a versioned baseline file with an expiry date — never in a silent code change |

---

## Business Value

CyberSWISS directly addresses the business risk that undetected security gaps create: regulatory fines, breach costs, downtime, and reputational damage. The table below maps each capability to a concrete business outcome.

### ROI at a Glance

| Business Outcome | How CyberSWISS Delivers It |
|---|---|
| **Reduce breach risk** | 66 automated checks cover the attack surface continuously — not just once a year during a pen test |
| **Cut audit preparation time** | One command produces SOC 2, HIPAA, and GDPR evidence reports in minutes instead of weeks of manual evidence collection |
| **Avoid regulatory fines** | Built-in compliance mapping (L22/W22) identifies control gaps before auditors do — giving teams time to remediate |
| **Contain remediation costs** | `--fix` mode auto-remediates low-risk findings (misconfigurations, insecure defaults) in the same run, reducing ticket backlogs |
| **Protect revenue-critical systems** | Credential theft hardening (L31/W31), PrivEsc posture (L29/W29), and IR readiness (L33/W33) protect the systems that generate revenue |
| **Accelerate secure software delivery** | SAST, SCA, IaC, and API security checks (L18–L20, L24–L26 / W19–W21, W24–W26) integrate directly into CI/CD pipelines |
| **Demonstrate security posture to clients** | HTML and JSON reports provide board-ready summaries and client-facing evidence of diligence |
| **Reduce dependency on external consultants** | Self-service GUI and CLI mean internal teams can run enterprise-grade audits without specialist contractors |
| **Enable continuous security improvement** | Drift detection (`--diff`) surfaces new risks between scans, turning security from a point-in-time snapshot into an ongoing programme |

---

### Cost of Inaction vs CyberSWISS

| Risk Area | Typical Cost of a Gap | CyberSWISS Check |
|---|---|---|
| Unpatched CVEs | Average breach cost $4.45M (IBM 2023) | L21 / W21 – Vulnerability Scanning |
| Exposed secrets / credentials | Majority of cloud breaches start with leaked keys | L16 / W17 – Secrets Scanning |
| Misconfigured firewall / open ports | Direct perimeter breach vector | L06, L05 / W06, W05 – Firewall & Listeners |
| Weak password policy | Credential stuffing and brute-force entry | L01 / W01 – Password Policy |
| Unencrypted disks | GDPR fines up to €20M or 4% global revenue | L11 / W11 – LUKS / BitLocker |
| Missing audit logs | Forensic blindness during incident response | L08, L09 / W08, W09 – Logging & Auditing |
| SOC 2 / HIPAA / GDPR gap | Audit failure, contract loss, regulatory action | L22 / W22 – Compliance Automation |
| Insecure third-party code | Supply-chain attack (e.g. Log4Shell) | L20 / W21 – SCA & License Compliance |
| No incident response plan | Extended MTTR, uncontrolled breach spread | L33 / W33 – IR Readiness |

---

### Who Benefits

| Stakeholder | Value Delivered |
|---|---|
| **CISO / Security Team** | Continuous, evidence-backed posture visibility across all endpoints and servers |
| **Compliance & Risk Officers** | Automated SOC 2 / HIPAA / GDPR control evidence with one command — no manual spreadsheets |
| **DevSecOps / Platform Engineering** | CI/CD-gate integration blocks regressions before they reach production |
| **IT Operations** | Self-service remediation of common misconfigurations reduces escalation to security specialists |
| **Finance / Board** | Quantified risk reduction in plain language; defensible due-diligence record for insurers and partners |
| **External Auditors & Pen Testers** | Structured JSON output and timestamped scan history accelerates evidence review |

---

## Key Features

| Feature | Details |
|---|---|
| **66 modular scripts** | Each security domain is its own script — run any subset with `--scripts L07 L21 W16` |
| **Opt-in remediation** | `--fix` / `-Fix` applies fixes only when explicitly requested; destructive operations include a 10-second abort window |
| **Multi-format output** | JSON, HTML, CSV, plain-text, SARIF, or Markdown — all generated in one pass |
| **SARIF 2.1.0 output** | `--sarif` publishes findings straight to GitHub code scanning, Azure DevOps, or any SAST dashboard |
| **Markdown output** | `--markdown` produces a PR comment or GitHub Actions job summary — verdict, counts, and the findings that need action |
| **Baseline waivers** | `--baseline` suppresses formally accepted findings (with wildcards and expiry dates) so CI breaks only on *new* risk |
| **Trend analytics** | `--trend N` shows whether the posture is improving or degrading across the last N stored scans |
| **Scan history & drift detection** | SQLite backend with `--save-db` + `--diff` for regression tracking |
| **History tooling** | `common/db.py` lists, inspects, compares, and prunes stored scans — searchable by script ID, OS, or host tag |
| **REST API server** | 9 endpoints with async scan support, history management, six report formats, drift, and trend analysis |
| **Interactive GUI** | Tkinter-based point-and-click scanning; no CLI knowledge required |
| **Parallel execution** | `--parallel N` runs N scripts concurrently for faster audit cycles |
| **Rate-limiting / IDS evasion** | `--delay SEC` inserts configurable sleep between scripts |
| **Vulnerability scanning** | L21/W21 provide CVE counts, version checks, nmap/nikto-style probes, and CPU mitigation audits |
| **Secrets detection** | L16/W17 detect `.env` leaks, cloud credentials (AWS/Azure/GCP), Docker auth, and IIS passwords |
| **DAST & API security** | L18/W19 check HTTP headers, CORS, Swagger/GraphQL exposure, TRACE method, and TLS cert expiry |
| **IaC scanning** | L19/W20 cover Dockerfile, docker-compose, Terraform, Kubernetes, Helm, ARM, Bicep, and Ansible |
| **SCA & license compliance** | L20/W21 detect vulnerable packages, copyleft licenses, Log4Shell (CVE-2021-44228), and EOL runtimes |
| **OpenVAS integration** | L23/W23 orchestrate OpenVAS scans via the GVM API for deep CVE identification |
| **Web & SQLi scanning** | L24–L25/W24–W25 perform web vulnerability and SQL injection checks against target URLs |
| **SAST/SCA** | L26/W26 run static analysis and dependency auditing via Bandit, Semgrep, npm audit, and more |
| **DNS security** | L27/W27 audit DNSSEC, DANE, SPF, DKIM, DMARC, and DNS-over-HTTPS configuration |
| **Backup/recovery resilience** | L28/W28 validate backup schedules, retention, restore testing, and offsite replication |
| **Compliance mapping** | L22/W22 map findings to SOC 2, HIPAA, and GDPR controls |
| **AD/GPO compatibility** | W16 audits domain policy, privileged groups, LAPS, Kerberos, UAC, and AD Recycle Bin |

---

## Repository Structure

```
CyberSWISS/
├── windows/                        # 33 PowerShell audit scripts (W01–W33)
│   ├── W01_password_policy.ps1
│   ├── W02_local_admin_review.ps1
│   ├── ...
│   ├── W22_compliance_checks.ps1
│   ├── W23_openvas_vuln_scan.ps1
│   ├── W24_web_vuln_scan.ps1
│   ├── W25_sqli_scanner.ps1
│   ├── W26_sast_sca_scanner.ps1
│   ├── W27_dns_resolution_security.ps1
│   ├── W28_backup_recovery_resilience.ps1
│   ├── W29_privesc_posture.ps1
│   ├── W30_deep_persistence.ps1
│   ├── W31_credential_theft_hardening.ps1
│   ├── W32_usb_media_control.ps1
│   └── W33_ir_readiness.ps1
│
├── linux/                          # 33 Bash audit scripts (L01–L33)
│   ├── L01_password_policy.sh
│   ├── L02_sudo_users_review.sh
│   ├── ...
│   ├── L22_compliance_checks.sh
│   ├── L23_openvas_vuln_scan.sh
│   ├── L24_web_vuln_scan.sh
│   ├── L25_sqli_scanner.sh
│   ├── L26_sast_sca_scanner.sh
│   ├── L27_dns_resolution_security.sh
│   ├── L28_backup_recovery_resilience.sh
│   ├── L29_privesc_posture.sh
│   ├── L30_deep_persistence.sh
│   ├── L31_credential_theft_hardening.sh
│   ├── L32_usb_media_control.sh
│   └── L33_ir_readiness.sh
│
├── common/                         # Python orchestrator & utilities
│   ├── runner.py                   # CLI orchestrator — main entry point
│   ├── report_generator.py         # Multi-format reports (HTML, JSON, CSV, TXT, SARIF, MD)
│   ├── db.py                       # SQLite scan history, drift detection, trend analytics
│   ├── baseline.py                 # Accepted-risk waivers (suppression, expiry, wildcards)
│   ├── api.py                      # REST API v1 server (8 endpoints, async scan support)
│   ├── gui.py                      # Tkinter GUI for interactive scanning
│   └── utils.py                    # Shared utilities: script discovery, execution, filtering
│
├── .github/workflows/
│   └── ci.yml                      # GitHub Actions pipeline (lint, test, audit, SARIF, gate)
│
├── ci/
│   └── README.md                   # Pipeline inputs (ci/baseline.json – accepted risk)
│
├── docs/
│   ├── CATALOG.md                  # Complete script catalog with descriptions & severity
│   ├── USAGE.md                    # CLI usage guide, scheduling, SIEM integration
│   ├── REMEDIATION_GUIDE.md        # Per-script remediation steps
│   └── RUNTIME_REQUIREMENTS.md    # Full OS-level dependency list
│
├── tests/
│   ├── test_runner.py              # Orchestration & CLI argument tests
│   ├── test_extended.py            # DB, API, report generation & new-script tests
│   ├── test_governance.py          # Baselines, SARIF/Markdown output, trend analytics
│   ├── test_api_endpoints.py       # HTTP-level tests against a live API server
│   ├── test_orchestration.py       # Reporting filters, scan tags, db.py CLI, HTML report
│   ├── test_gui_structure.py       # GUI menu/binding wiring (no tkinter required)
│   └── test_utils.py              # Utility function tests
│
├── setup/
│   ├── install_runtime_linux.sh    # Bootstrap installer for Linux dependencies
│   └── install_runtime_windows.ps1 # Bootstrap installer for Windows dependencies
│
├── reports/                        # Output directory for generated scan reports
├── LICENSE
├── README.md
└── requirements.txt
```

---

## Quick Start

### Prerequisites

| Requirement | Linux | Windows |
|---|---|---|
| Python | 3.9+ | 3.9+ |
| Shell | Bash 4.0+ | PowerShell 5.1+ |
| Privileges | `sudo` / root for full results | Elevated PowerShell prompt |

### Install Dependencies

```bash
# Clone the repository
git clone https://github.com/jomardyan/CyberSWISS-Cybersecurity-Scan-Win-Linux.git
cd CyberSWISS-Cybersecurity-Scan-Win-Linux

# Install the development toolchain (pytest, flake8, pylint, black, isort)
pip install -r requirements.txt
```

> **CyberSWISS has no third-party Python runtime dependencies.** The
> orchestrator, reporting, history database, REST API, and GUI are built
> entirely on the standard library, so a bare Python install is enough to run
> a scan. `requirements.txt` covers the development and test toolchain only.

> **Tip:** A `Makefile` is included that wraps all common tasks — see [Make / Developer Workflow](#make--developer-workflow) for the short form of every command below.

For full script coverage, OS-level tools (nmap, nikto, auditd, etc.) must also be installed. Use the included bootstrap scripts:

```bash
# Linux
sudo ./setup/install_runtime_linux.sh --optional --yes
```

```powershell
# Windows (elevated PowerShell)
PowerShell -ExecutionPolicy Bypass -File .\setup\install_runtime_windows.ps1 -Optional
```

See [docs/RUNTIME_REQUIREMENTS.md](docs/RUNTIME_REQUIREMENTS.md) for the complete dependency list.

---

### Run Audits

```bash
# Run all Linux checks
sudo python3 common/runner.py --os linux

# Run all Windows checks (elevated PowerShell)
python .\common\runner.py --os windows

# Run specific scripts by ID
sudo python3 common/runner.py --scripts L07 L16 L21 W16

# Preview which scripts would run without executing them
python3 common/runner.py --os linux --dry-run --json | python3 -m json.tool
```

---

### Reporting

Generate all output formats in a single pass:

```bash
sudo python3 common/runner.py --os linux \
  --output   reports/audit.json \
  --html     reports/audit.html \
  --csv      reports/audit.csv  \
  --text     reports/audit.txt  \
  --sarif    reports/audit.sarif \
  --markdown reports/audit.md   \
  --save-db
```

**SARIF** (`--sarif`) is the format GitHub code scanning, Azure DevOps, and most SAST
dashboards ingest — uploading it puts CyberSWISS findings in the repository's
Security tab next to every other security alert. Severities map to
`security-severity` scores (Critical 9.5 → Info 1.0), each result is anchored to the
check script that produced it, and baselined findings are emitted as SARIF
`suppressions` rather than as fresh alerts.

**Markdown** (`--markdown`) is sized for a pull-request comment or a job summary.
Write it straight into the GitHub Actions summary panel:

```bash
python3 common/runner.py --os linux --markdown - >> "$GITHUB_STEP_SUMMARY"
```

---

### Drift Detection

```bash
# First run — establish a baseline
sudo python3 common/runner.py --os linux --save-db

# Subsequent runs — surface new, resolved, and changed findings
# exits with code 2 if new regressions are detected (useful for CI gates)
sudo python3 common/runner.py --os linux --save-db --diff
```

---

### Trend Analysis

Drift answers *"what changed since last time?"*. A trend answers *"are we getting
better or worse?"* — the question a security programme is actually judged on.

```bash
# Posture across the last 10 stored scans (add --dry-run to skip re-scanning)
python3 common/runner.py --trend 10 --dry-run
```

```
  Scan    Timestamp                        FAIL  WARN  Total
  --------------------------------------------------------
  #1      2026-03-01T09:00:00+00:00           9     4     41
  #2      2026-03-08T09:00:00+00:00           6     4     41
  #3      2026-03-15T09:00:00+00:00           2     1     41

  FAIL trend : █▆▂  (oldest → newest)
  WARN trend : █████

  ▼  Posture is IMPROVING: FAIL -7, WARN -3 across the window.

  Top failing scripts (latest scan):
       2 FAIL  L06_firewall_state
```

`GET /api/v1/trend?limit=10&host=web-prod-01` returns the same data as JSON.

#### Managing the history database

`common/db.py` is the command-line front end to the SQLite history — listing,
inspecting, comparing, and pruning stored scans without writing SQL:

```bash
python3 common/db.py list                  # recent scans, newest first
python3 common/db.py list --tag L07        # only scans that included the SSH checks
python3 common/db.py list --host web-prod-01
python3 common/db.py show 12               # one scan with its findings and tags
python3 common/db.py trend --limit 10      # posture trend
python3 common/db.py drift 12              # drift for a scan vs its predecessor
python3 common/db.py prune --keep 50       # retention: drop all but the newest 50
```

Every subcommand accepts `--json` for scripting and `--db-path` to operate on an
alternative database file. Each saved scan is tagged with the script IDs it ran,
the OS families it covered, and `host:<name>`, which is what `--tag` filters on.
The same targets are available as `make db-list`, `make db-show SCAN_ID=12`, and
`make db-prune KEEP=50`.

---

### Baselines & Accepted Risk

Some findings are known, reviewed, and formally accepted — a compensating control
is in place, or the business has signed off the risk. Re-reporting them on every
run buries genuinely new problems and makes a CI gate unusable.

A **baseline** is a JSON file of those accepted findings. Matched findings stay in
the report, marked as accepted risk, but no longer count towards FAIL/WARN or the
exit code:

```bash
# 1. Record today's FAIL/WARN findings as accepted risk
sudo python3 common/runner.py --os linux --write-baseline ci/baseline.json

# 2. Edit ci/baseline.json to record the real justification and an expiry date

# 3. Gate CI on new findings only – exits 0 while nothing new appears
sudo python3 common/runner.py --os linux --baseline ci/baseline.json
```

```json
{
  "cyberswiss_baseline": true,
  "version": 1,
  "host": "web-prod-01",
  "entries": [
    {
      "id": "L01-C1",
      "script": "L01_password_policy",
      "severity": "High",
      "status": "FAIL",
      "reason": "Accepted – legacy payroll app cannot rotate credentials",
      "owner": "security@example.com",
      "expires": "2026-12-31"
    }
  ]
}
```

| Behaviour | Detail |
|---|---|
| **Wildcards** | `id` and `script` accept shell-style patterns (`L01-*`, `W2?_*`) to waive a whole family of checks |
| **Expiry** | Once `expires` passes, the waiver stops suppressing and the finding is reported again — waivers cannot silently become permanent |
| **Never hidden** | Suppressed findings stay in every report, flagged as accepted risk with their justification |
| **PASS is not waivable** | Only FAIL and WARN findings can be baselined |
| **Hygiene** | Waivers that matched nothing are listed as candidates for removal |

Manage baseline files directly with `python3 common/baseline.py {create,show,apply}`,
or through `make baseline`, `make baseline-show`, and `make scan-baselined`.

---

### Remediation

```bash
# Apply all safe auto-fixes
# Destructive operations include a 10-second abort window
sudo python3 common/runner.py --os linux --fix
```

---

### GUI

```bash
python3 common/gui.py
```

---

### REST API Server

```bash
python3 common/api.py --host 127.0.0.1 --port 8080
```

---

## Make / Developer Workflow

A `Makefile` at the repository root wraps every common task into a short, discoverable command.

```bash
make          # show end-user targets (scanning, reporting, setup)
make help-dev # show developer targets (testing, linting, CI, formatting)
```

### End-User targets

| Command | Equivalent manual command | Description |
|---|---|---|
| `make check-env` | *(runs checks internally)* | Validate Python, git, bash, and optional tools |
| `make install` | `pip install -r requirements.txt` | Install Python dependencies |
| `make install-all` | `bash setup/install_runtime_linux.sh --optional --yes` | Python deps + OS-level tooling |
| `make scan` | `python3 common/runner.py` | Run all scripts for the current OS |
| `make scan-linux` | `python3 common/runner.py --os linux` | Linux scripts only |
| `make scan-windows` | `python3 common/runner.py --os windows` | Windows scripts only |
| `make scan-high` | `python3 common/runner.py --min-severity High` | High + Critical severity only |
| `make scan-critical` | `python3 common/runner.py --min-severity Critical` | Critical severity only |
| `make scan-dry` | `python3 common/runner.py --dry-run` | List scripts without running them |
| `make scan-fix` | `python3 common/runner.py --fix` | Run with auto-remediations (⚠ 5 s abort window) |
| `make report` | `python3 common/runner.py --output … --csv … --html …` | Full scan → timestamped JSON + CSV + HTML |
| `make report-db` | `… --save-db --diff` | report + persist to DB + show drift |
| `make report-diff` | `… --diff --dry-run` | Show drift vs last DB entry (no re-scan) |
| `make report-sarif` | `… --sarif … --markdown …` | Full scan → SARIF + Markdown for CI / code scanning |
| `make report-trend` | `… --trend N --dry-run` | Posture trend across the last `TREND` stored scans |
| `make baseline` | `… --write-baseline $(BASELINE)` | Record current findings as accepted risk |
| `make baseline-show` | `common/baseline.py show …` | List the waivers in the baseline file |
| `make scan-baselined` | `… --baseline $(BASELINE)` | Scan, failing only on non-waived findings |
| `make archive` | `zip reports/archive/…` | Zip all current reports |
| `make db-list` | `common/db.py list` | List stored scans in the history database |
| `make db-show` | `common/db.py show $(SCAN_ID)` | Show one stored scan and its findings |
| `make db-prune` | `common/db.py prune --keep $(KEEP)` | Retention: keep only the newest `KEEP` scans |
| `make clean` | `find . -name __pycache__ …` | Remove Python cache files |
| `make clean-all` | *(clean + clean-reports)* | Remove cache + generated reports |

#### Scan variables

Pass overrides on the command line:

```bash
make scan-sev   MIN_SEV=Critical          # severity filter
make scan-id    SCRIPTS="L07 L15 W16"     # specific script IDs
make scan-tag   TAG=network               # tag filter
make scan-delay DELAY=2                   # 2 s between scripts
make report-trend TREND=20                # trend window
make db-prune    KEEP=100                 # history retention
make db-show     SCAN_ID=12               # inspect one stored scan
make scan-baselined BASELINE=ci/prod.json # alternative baseline file
make scan       VERBOSE=1                 # verbose runner output
make scan       PYTHON=python3.11         # override Python binary
```

### Developer targets (`make help-dev`)

| Command | Description |
|---|---|
| `make test` | Run full pytest suite |
| `make test-cov` | Tests with HTML coverage report (`reports/coverage/`) |
| `make test-fast` | Stop on first failure (`pytest -x`) |
| `make lint` | flake8 + shellcheck + pylint (all in one) |
| `make lint-python` | flake8 on `common/` and `tests/` |
| `make lint-shell` | shellcheck on `linux/` scripts |
| `make lint-pylint` | pylint on `common/` |
| `make test-verbose` | Full suite with verbose output |
| `make format` | Auto-format with black + isort |
| `make format-check` | Dry-run format check (CI-safe) |
| `make upgrade` | Upgrade all installed pip packages |
| `make ci` | Full CI gate: check-env → lint → test → scan-dry |
| `make ci-lint` | Lint step only |
| `make ci-test` | Test step only |
| `make ci-scan` | Dry-run scan step only |

### Typical workflows

```bash
# First-time setup
git clone https://github.com/jomardyan/CyberSWISS-Cybersecurity-Scan-Win-Linux.git
cd CyberSWISS-Cybersecurity-Scan-Win-Linux
make install
make check-env

# Daily operator scan (Linux)
make scan

# Generate timestamped reports
make report

# Scan only high-severity scripts and show drift vs last run
make report-db MIN_SEV=High

# Developer: lint + test before committing
make lint test

# Full CI gate locally
make ci
```

---

## REST API Reference

CyberSWISS exposes a built-in REST API (`common/api.py`) using Python's standard `http.server` — no extra dependencies required.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/v1/health` | Health check and script count |
| `GET`  | `/api/v1/scripts` | List all available audit scripts |
| `POST` | `/api/v1/scan` | Start an async background scan — body accepts `os`, `scripts`, `tags`, `min_severity`, `fix`, `timeout` |
| `GET`  | `/api/v1/scan/{id}` | Poll scan status and retrieve results |
| `GET`  | `/api/v1/history` | List past scans — `?limit=N&host=NAME&tag=L07` |
| `GET`  | `/api/v1/report/{id}` | Report for a saved scan — `?format=` one of `html`, `json`, `sarif`, `markdown`, `csv`, `text` (default `html`) |
| `GET`  | `/api/v1/drift/{id}` | Drift analysis vs the previous scan |
| `GET`  | `/api/v1/trend` | Posture trend across recent scans — `?limit=N&host=NAME` |
| `DELETE` | `/api/v1/scan/{id}` | Delete a scan from history |

```bash
# Start the API server
python3 common/api.py --host 127.0.0.1 --port 8080

# Trigger a scan (all selection knobs are optional)
curl -s -X POST http://127.0.0.1:8080/api/v1/scan \
  -H 'Content-Type: application/json' \
  -d '{"os":"linux","tags":["network"],"min_severity":"High","fix":false}' \
  | python3 -m json.tool

# List scan history
curl -s http://127.0.0.1:8080/api/v1/history | python3 -m json.tool

# Fetch a stored scan as SARIF and upload it to code scanning
curl -s "http://127.0.0.1:8080/api/v1/report/1?format=sarif" -o audit.sarif

# Ask whether the posture is improving
curl -s "http://127.0.0.1:8080/api/v1/trend?limit=10" | python3 -m json.tool
```

---

## Script Catalog

### Windows PowerShell Scripts (33)

| ID  | Script | Category | Severity | Fix Support |
|-----|--------|----------|----------|-------------|
| W01 | Password Policy Audit | Accounts & Auth | High | Read-only |
| W02 | Local Admin Review | Accounts & Auth | High | Read-only |
| W03 | Patch Level & Software Inventory | Patch Management | Critical | Read-only |
| W04 | Services Audit | Services/Daemons | High | Disables insecure services |
| W05 | Network Listeners | Network Exposure | High | Read-only |
| W06 | Firewall State | Network Exposure | High | Enables firewall profiles |
| W07 | SMB/WinRM Posture | Network Exposure | High | Disables SMBv1, enables signing |
| W08 | Event Log Configuration | Logging & Auditing | High | Increases log sizes |
| W09 | Audit Policy | Logging & Auditing | High | Enables audit subcategories |
| W10 | Registry Hardening | Registry Security | High | AutoRun off, NTLMv2, LSASS PPL |
| W11 | BitLocker Status | Encryption | High | Read-only |
| W12 | Secure Boot & TPM | Boot Security | High | Read-only |
| W13 | Defender & EDR | Endpoint Protection | Critical | Enables real-time protection |
| W14 | Scheduled Tasks Audit | Persistence Mechanisms | High | Read-only |
| W15 | CIS Baseline Hardening | Baseline Hardening | High | PowerShell logging, SMB hardening |
| W16 | Active Directory & GPO Security | Identity & Access | High | GPO-compatible registry writes |
| W17 | Secrets Scanning | Secrets & Credentials | High | Read-only |
| W18 | Attack Surface Management | Network Exposure | High | Read-only |
| W19 | API Endpoint Discovery & DAST | Application Security | High | Read-only |
| W20 | IaC Security Scanning | DevSecOps | Medium | Read-only |
| W21 | SCA & License Compliance | Open-Source Risk | Medium | Read-only |
| W22 | Compliance Automation | Regulatory Mapping | High | Read-only |
| W23 | OpenVAS Vulnerability Scan | Vulnerability Management | Critical | Read-only |
| W24 | Web Vulnerability Scan | Application Security | High | Read-only |
| W25 | SQL Injection Scanner | Application Security | High | Read-only |
| W26 | SAST / SCA Scanner | DevSecOps | High | Read-only |
| W27 | DNS Resolution Security | Network Exposure | Medium | Read-only |
| W28 | Backup & Recovery Resilience | Resilience & Recovery | High | Read-only |
| W29 | Privilege Escalation Posture | PrivEsc Prevention | Critical | Disables AlwaysInstallElevated, enforces UAC |
| W30 | Deep Persistence Detection | Persistence Mechanisms | Critical | Disables LoadAppInit_DLLs |
| W31 | Credential Theft Hardening | Credential Protection | Critical | Disables WDigest, enforces NTLMv2, reduces cached logons |
| W32 | USB & Removable Media Control | Endpoint Controls | High | Disables AutoRun |
| W33 | Incident Response Readiness | Detection & Response | High | Enables PS ScriptBlock Logging, starts W32Time |

---

### Linux Bash Scripts (33)

| ID  | Script | Category | Severity | Fix Support |
|-----|--------|----------|----------|-------------|
| L01 | Password Policy | Accounts & Auth | High | Sets PASS_MAX_DAYS, min length |
| L02 | Sudo & Privileged Users | Accounts & Auth | High | Read-only |
| L03 | Patch Level | Patch Management | Critical | Runs apt/dnf/zypper upgrade |
| L04 | Services Audit | Services/Daemons | High | Disables insecure services |
| L05 | Network Listeners | Network Exposure | High | Read-only |
| L06 | Firewall State | Network Exposure | High | Enables ufw/firewalld |
| L07 | SSH Posture | Network Exposure | High | Read-only |
| L08 | Auditd & Logging | Logging & Auditing | High | Installs & enables auditd |
| L09 | Syslog Configuration | Logging & Auditing | Medium | Installs & enables rsyslog |
| L10 | File Permissions (SUID/SGID) | File Permissions | High | Read-only |
| L11 | LUKS Encryption | Encryption | High | Read-only |
| L12 | Secure Boot | Boot Security | High | Read-only |
| L13 | AV & EDR Presence | Endpoint Protection | Critical | Installs ClamAV |
| L14 | Cron & Persistence | Persistence Mechanisms | High | Read-only |
| L15 | CIS Baseline Hardening | Baseline Hardening | High | Writes sysctl.d hardening config |
| L16 | Secrets Scanning | Secrets & Credentials | High | Read-only |
| L17 | Attack Surface Management | Network Exposure | High | Persists iptables DROP rules |
| L18 | API Endpoint Discovery & DAST | Application Security | High | Read-only |
| L19 | IaC Security Scanning | DevSecOps | Medium | Read-only |
| L20 | SCA & License Compliance | Open-Source Risk | Medium | Read-only |
| L21 | Vulnerability Scanning | Vulnerability Management | High | Read-only |
| L22 | Compliance Automation | Regulatory Mapping | High | Read-only |
| L23 | OpenVAS Vulnerability Scan | Vulnerability Management | Critical | Read-only |
| L24 | Web Vulnerability Scan | Application Security | High | Read-only |
| L25 | SQL Injection Scanner | Application Security | High | Read-only |
| L26 | SAST / SCA Scanner | DevSecOps | High | Read-only |
| L27 | DNS Resolution Security | Network Exposure | Medium | Read-only |
| L28 | Backup & Recovery Resilience | Resilience & Recovery | High | Read-only |
| L29 | Privilege Escalation Posture | PrivEsc Prevention | Critical | Removes other-write from writable systemd units |
| L30 | Deep Persistence Detection | Persistence Mechanisms | Critical | Read-only |
| L31 | Credential Theft Hardening | Credential Protection | Critical | Sets ptrace_scope=1, disables core dumps |
| L32 | USB & Removable Media Control | Endpoint Controls | High | Blacklists usb_storage module |
| L33 | Incident Response Readiness | Detection & Response | High | Enables systemd-timesyncd |

---

## Active Directory & GPO Integration

`W16_ad_gpo_security.ps1` is fully compatible with AD-joined Windows endpoints and can be deployed as a **GPO Startup Script** or **Scheduled Task via GPO**.

**What it audits:**
- Domain password policy via `HKLM:\SYSTEM\...\Netlogon\Parameters` (locale-neutral, no RSAT required)
- Membership of Domain Admins, Enterprise Admins, and Schema Admins
- LAPS deployment status
- Kerberos RC4 ticket encryption
- UAC settings, NTLMv2 enforcement, and AD Recycle Bin

**Fix mode:** `-Fix` writes GPO-compatible registry values. It does **not** modify AD objects; AD policy changes must be made via GPMC.

```powershell
# Deploy as GPO Computer Startup Script
# Path: \\domain\SYSVOL\...\scripts\W16_ad_gpo_security.ps1
# Arguments: -Json   (for SIEM ingestion)
#            -Fix    (optional: apply local hardening baselines)
```

---

## Drift Detection Detail

```
  ▲  NEW FINDINGS (1)
     [FAIL] [High] L07-C3: SSH MFA – No MFA configured

  ✔  RESOLVED FINDINGS (1)
     [WARN] [High] L07-C2: SSH Protocol – previously flagged, now fixed

  ↔  CHANGED FINDINGS (1)
     [WARN→FAIL] [High] L21-C1: OS CVE count increased from 12 to 47
```

`--diff` prints this summary inline and exits with code `2` when new `FAIL` findings are detected — ideal for blocking CI/CD pipelines on regressions. To review the stored history without re-scanning, combine it with `--dry-run` (`make report-diff`).

---

## GitHub Actions CI/CD

The included `.github/workflows/ci.yml` runs automatically on every push and pull request.

| Job | What it validates | Tools |
|-----|-------------------|-------|
| `python-tests` | Lint and unit tests for `common/` — flake8 is enforced, pylint runs at an 8.0 threshold, pytest reports coverage | `flake8`, `pylint`, `pytest` (Python 3.11) |
| `bash-lint` | Syntax and best-practice checks for all `linux/*.sh` scripts | `shellcheck` |
| `linux-smoke` | Smoke tests: L01, L07, L15 with `--json` to verify output structure | Bash, JSON validation |
| `orchestrator` | End-to-end audit with `--min-severity Med`, report generation, SARIF upload to code scanning, and a Markdown job summary | Python runner, `report_generator.py`, `upload-sarif` |
| `baseline-gate` | Re-runs the audit against `ci/baseline.json` so the build breaks only on findings that are not accepted risk | Python runner (`--baseline`) |

All jobs must pass before merging to `main`. Locally, `make ci` runs the same
lint → test → dry-run gate.

### Wiring CyberSWISS into your own pipeline

```yaml
permissions:
  contents: read
  security-events: write        # required for the SARIF upload

steps:
  - name: Run CyberSWISS audit
    run: |
      python3 common/runner.py --os linux \
        --baseline ci/baseline.json \
        --sarif /tmp/audit.sarif \
        --markdown - >> "$GITHUB_STEP_SUMMARY"

  - name: Upload SARIF to code scanning
    if: always()
    uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: /tmp/audit.sarif
      category: cyberswiss
```

The run exits `2` on any finding that is not waived in `ci/baseline.json`, so
the gate stays quiet until genuinely new risk appears. See
[`ci/README.md`](ci/README.md) for how to create and maintain that file.

---

## CLI Reference

```
python3 common/runner.py [OPTIONS]

Target selection:
  --os {linux,windows,both}     Run all scripts for the specified OS (default: auto-detect)
  --scripts ID [ID ...]         Run specific scripts by ID (e.g. L07 W16 L21)

Filtering:
  --min-severity SEV            Only report findings at or above severity
                                  Values: Info / Low / Med / High / Critical
  --status STAT [STAT ...]      Filter output by finding status (PASS FAIL WARN INFO)

Output formats:
  --output   FILE               Write JSON results to FILE
  --html     FILE               Write HTML report to FILE
  --csv      FILE               Write CSV report to FILE
  --text     FILE               Write plain-text report to FILE
  --sarif    FILE               Write SARIF 2.1.0 report to FILE (GitHub code scanning)
  --markdown FILE               Write Markdown report to FILE (PR comment / job summary)
                                  Any of the above accept - for stdout
  --json                        Print JSON to stdout

History, drift & trend:
  --save-db                     Persist results to SQLite scan history database
  --diff                        Show drift vs last scan; exit code 2 on new regressions
  --trend [N]                   Show posture trend across the last N scans (default: 10)

Baselines (accepted risk):
  --baseline FILE               Suppress findings waived in FILE; they no longer
                                  affect FAIL/WARN counts or the exit code
  --write-baseline FILE         Record this scan's FAIL/WARN findings as a baseline
  --baseline-expires DATE       Expiry (YYYY-MM-DD) written onto every new entry

Scan behaviour:
  --delay  SEC                  Sleep SEC seconds between scripts (IDS/rate-limit evasion)
  --timeout SEC                 Per-script timeout in seconds (default: 300)
  --parallel N                  Run N scripts concurrently (default: 1)
  --dry-run                     List scripts that would run without executing them

Remediation:
  --fix                         Apply opt-in fixes (disabled by default)

History & retention:
  python3 common/db.py {list,show,trend,drift,prune} [--json]
                                Inspect and prune the scan history database

Baselines:
  python3 common/baseline.py {create,show,apply}
                                Manage accepted-risk waiver files

REST API:
  python3 common/api.py [--host HOST] [--port PORT] [--db-path FILE]
                                Start REST API server (default: 0.0.0.0:8080;
                                use --host 127.0.0.1 for local-only access)
```

---

## Exit Codes

| Code | Meaning |
|------|--------|
| `0` | All checks passed |
| `1` | At least one WARNING |
| `2` | At least one FAILURE, or new regressions detected with `--diff` |

Findings waived by a `--baseline` file are excluded from this calculation — an
audit whose every failure is formally accepted exits `0`.

---

## Make Reference

A quick-reference card — run `make help` or `make help-dev` in the repo root for the live, colour-coded version.

```
make                     # end-user help (default)
make help-dev            # developer help

# Setup
make install             # pip install -r requirements.txt
make install-all         # + OS-level tools
make check-env           # validate environment

# Scanning
make scan                # all scripts, current OS
make scan-linux          # Linux only
make scan-high           # severity >= High
make scan-dry            # dry-run (list scripts)
make scan-fix            # with auto-remediation
make scan-id SCRIPTS="L07 W16"
make scan-sev MIN_SEV=Critical

# Reporting
make report              # JSON + CSV + HTML (timestamped)
make report-db           # + save to DB + drift
make report-diff         # drift vs last DB entry (no re-scan)
make report-sarif        # SARIF (code scanning) + Markdown
make report-trend        # posture trend across stored scans
make archive             # zip current reports

# Accepted risk
make baseline            # record current findings as accepted risk
make baseline-show       # list the waivers
make scan-baselined      # fail only on non-waived findings

# Scan history
make db-list             # list stored scans
make db-show SCAN_ID=12  # one scan and its findings
make db-prune KEEP=50    # retention

# Developer
make test                # pytest
make lint                # flake8 + shellcheck + pylint
make format              # black + isort
make ci                  # lint + test + scan-dry
```

---

## Documentation

| Document | Description |
|---|---|
| [docs/CATALOG.md](docs/CATALOG.md) | Complete script catalog with descriptions and severity ratings |
| [docs/USAGE.md](docs/USAGE.md) | CLI usage guide, scheduling, and SIEM integration examples |
| [docs/REMEDIATION_GUIDE.md](docs/REMEDIATION_GUIDE.md) | Detailed per-finding remediation steps |
| [docs/RUNTIME_REQUIREMENTS.md](docs/RUNTIME_REQUIREMENTS.md) | Full OS-level dependency list for all scripts |
| [ci/README.md](ci/README.md) | Pipeline inputs — creating and maintaining `ci/baseline.json` |

---

## Security Notice

This platform is designed for **authorized, internal security auditing only**.

- All scripts perform **non-destructive, read-only checks** by default
- Remediation (`--fix` / `-Fix`) is **disabled by default** and requires an explicit flag
- No credentials, secrets, or PII are collected or logged
- Audit reports should be treated as sensitive documents and access-controlled accordingly
- Only run on systems and networks for which you have **explicit written authorization**

---

## Contributing

Contributions are welcome. Please follow these guidelines:

1. **Fork** the repository and create a feature branch from `main`
2. **Add tests** — new scripts require corresponding entries in `tests/`
3. **Follow conventions** — Bash scripts must pass `shellcheck`; Python must pass `flake8` (rules in `.flake8`) and `pylint` at threshold 8.0+. `make lint test` runs both plus the suite; `make ci` runs the full gate
4. **Script naming** — use the next available ID prefix (`L##` / `W##`) followed by a descriptive snake_case name
5. **Output contract** — scripts must emit at minimum: `CHECK_ID`, `STATUS` (`PASS` / `FAIL` / `WARN` / `INFO`), `SEVERITY`, and `MESSAGE` fields in JSON mode
6. **No secrets** — never log credentials, tokens, or PII; all output must be safe for SIEM ingestion
7. **Open a Pull Request** — include a description, the checks added or modified, and evidence that tests pass

For significant changes, open an issue first to discuss the proposed approach.

---

## License

This project is licensed under the [MIT License](LICENSE).
