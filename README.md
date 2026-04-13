# CyberSWISS – Enterprise Security Audit & Remediation Platform

[![CI/CD Pipeline](https://img.shields.io/badge/CI%2FCD-passing-brightgreen)](https://github.com/jomardyan/CyberSWISS-Cybersecurity-Scane-Win-Linux/actions)
[![Python Tests](https://img.shields.io/badge/Python%20Tests-passing-brightgreen)](https://github.com/jomardyan/CyberSWISS-Cybersecurity-Scane-Win-Linux/actions)
[![Bash Lint](https://img.shields.io/badge/Bash%20Lint-passing-brightgreen)](https://github.com/jomardyan/CyberSWISS-Cybersecurity-Scane-Win-Linux/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue)](https://www.python.org/downloads/)
[![Bash 4.0+](https://img.shields.io/badge/Bash-4.0%2B-brightgreen)](https://www.gnu.org/software/bash/)
[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-blue)](https://docs.microsoft.com/en-us/powershell/)

> **AUTHORIZED INTERNAL USE ONLY** — All scripts are **read-only by default**.  
> Remediation requires an explicit `--fix` / `-Fix` flag and administrative privileges.

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Repository Structure](#repository-structure)
- [Quick Start](#quick-start)
  - [Prerequisites](#prerequisites)
  - [Install Dependencies](#install-dependencies)
  - [Run Audits](#run-audits)
  - [Reporting](#reporting)
  - [Drift Detection](#drift-detection)
  - [Remediation](#remediation)
  - [GUI](#gui)
  - [REST API Server](#rest-api-server)
- [Make / Developer Workflow](#make--developer-workflow)
- [REST API Reference](#rest-api-reference)
- [Script Catalog](#script-catalog)
  - [Windows PowerShell Scripts (28)](#windows-powershell-scripts-28)
  - [Linux Bash Scripts (28)](#linux-bash-scripts-28)
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

**CyberSWISS** is a production-grade, cross-platform security audit and remediation platform built for endpoints, servers, and Active Directory environments. It provides **56 runnable audit scripts** (28 Windows PowerShell + 28 Linux Bash), a Python orchestrator, REST API server, SQLite scan history with drift detection, multi-format reporting (HTML, JSON, CSV, plain-text), and a Tkinter GUI — all following a unified interface.

### Design Principles

| Principle | Description |
|---|---|
| **Defensive only** | Detection, validation, inventory, and configuration review — no offensive capabilities |
| **Read-only by default** | No system changes without an explicit `--fix` / `-Fix` flag |
| **No secrets in logs** | All output is safe to store and forward to a SIEM |
| **SIEM-ready** | Every script supports `--json` / `-Json` for structured, machine-readable output |
| **AD/GPO compatible** | W16 enforces domain policy via GPO-safe registry writes; no RSAT required |
| **Drift detection** | Built-in SQLite history surfaces new, resolved, and changed findings across successive scans |
| **CI/CD ready** | `--diff` flag returns exit code `2` on regressions; GitHub Actions workflow included |

---

## Key Features

| Feature | Details |
|---|---|
| **56 modular scripts** | Each security domain is its own script — run any subset with `--scripts L07 L21 W16` |
| **Opt-in remediation** | `--fix` / `-Fix` applies fixes only when explicitly requested; destructive operations include a 10-second abort window |
| **Multi-format output** | JSON, HTML, CSV, or plain-text — all generated in one pass |
| **Scan history & drift detection** | SQLite backend with `--save-db` + `--diff` for regression tracking |
| **REST API server** | 8 endpoints with async scan support, history management, HTML reports, and drift analysis |
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
├── windows/                        # 28 PowerShell audit scripts (W01–W28)
│   ├── W01_password_policy.ps1
│   ├── W02_local_admin_review.ps1
│   ├── ...
│   ├── W22_compliance_checks.ps1
│   ├── W23_openvas_vuln_scan.ps1
│   ├── W24_web_vuln_scan.ps1
│   ├── W25_sqli_scanner.ps1
│   ├── W26_sast_sca_scanner.ps1
│   ├── W27_dns_resolution_security.ps1
│   └── W28_backup_recovery_resilience.ps1
│
├── linux/                          # 28 Bash audit scripts (L01–L28)
│   ├── L01_password_policy.sh
│   ├── L02_sudo_users_review.sh
│   ├── ...
│   ├── L22_compliance_checks.sh
│   ├── L23_openvas_vuln_scan.sh
│   ├── L24_web_vuln_scan.sh
│   ├── L25_sqli_scanner.sh
│   ├── L26_sast_sca_scanner.sh
│   ├── L27_dns_resolution_security.sh
│   └── L28_backup_recovery_resilience.sh
│
├── common/                         # Python orchestrator & utilities
│   ├── runner.py                   # CLI orchestrator — main entry point
│   ├── report_generator.py         # Multi-format report generation (HTML, JSON, CSV, TXT)
│   ├── db.py                       # SQLite scan history, drift detection, query interface
│   ├── api.py                      # REST API v1 server (8 endpoints, async scan support)
│   ├── gui.py                      # Tkinter GUI for interactive scanning
│   └── utils.py                    # Shared utilities: script discovery, execution, filtering
│
├── ci/
│   └── audit_pipeline.yml          # Legacy CI config
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
git clone https://github.com/jomardyan/CyberSWISS-Cybersecurity-Scane-Win-Linux.git
cd CyberSWISS-Cybersecurity-Scane-Win-Linux

# Install Python packages
pip install -r requirements.txt
```

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
  --output reports/audit.json \
  --html   reports/audit.html \
  --csv    reports/audit.csv  \
  --text   reports/audit.txt  \
  --save-db
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
| `make archive` | `zip reports/archive/…` | Zip all current reports |
| `make clean` | `find . -name __pycache__ …` | Remove Python cache files |
| `make clean-all` | *(clean + clean-reports)* | Remove cache + generated reports |

#### Scan variables

Pass overrides on the command line:

```bash
make scan-sev   MIN_SEV=Critical          # severity filter
make scan-id    SCRIPTS="L07 L15 W16"     # specific script IDs
make scan-tag   TAG=network               # tag filter
make scan-delay DELAY=2                   # 2 s between scripts
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
| `make format` | Auto-format with black + isort |
| `make format-check` | Dry-run format check (CI-safe) |
| `make upgrade` | Upgrade all installed pip packages |
| `make ci` | Full CI gate: check-env → lint → test → scan-dry |
| `make ci-lint` | Lint step only |
| `make ci-test` | Test step only |

### Typical workflows

```bash
# First-time setup
git clone https://github.com/jomardyan/CyberSWISS-Cybersecurity-Scane-Win-Linux.git
cd CyberSWISS-Cybersecurity-Scane-Win-Linux
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

---

## REST API Reference

CyberSWISS exposes a built-in REST API (`common/api.py`) using Python's standard `http.server` — no extra dependencies required.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/v1/health` | Health check and script count |
| `GET`  | `/api/v1/scripts` | List all available audit scripts |
| `POST` | `/api/v1/scan` | Start an async background scan |
| `GET`  | `/api/v1/scan/{id}` | Poll scan status and retrieve results |
| `GET`  | `/api/v1/history` | List past scans from the database |
| `GET`  | `/api/v1/report/{id}` | HTML report for a saved scan |
| `GET`  | `/api/v1/drift/{id}` | Drift analysis vs the previous scan |
| `DELETE` | `/api/v1/scan/{id}` | Delete a scan from history |

```bash
# Start the API server
python3 common/api.py --host 127.0.0.1 --port 8080

# Trigger a scan
curl -s -X POST http://127.0.0.1:8080/api/v1/scan \
  -H 'Content-Type: application/json' \
  -d '{"os":"linux","fix":false}' | python3 -m json.tool

# List scan history
curl -s http://127.0.0.1:8080/api/v1/history | python3 -m json.tool
```

---

## Script Catalog

### Windows PowerShell Scripts (28)

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

---

### Linux Bash Scripts (28)

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

---

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

Use `--diff` prints this summary inline and exits with code `2` if any new `FAIL` findings are detected — ideal for blocking CI/CD pipelines on regressions.

---

---

## GitHub Actions CI/CD

The included `.github/workflows/ci.yml` runs automatically on every push and pull request.

| Job | What it validates | Tools |
|-----|-------------------|-------|
| `python-tests` | Linting and unit tests for `common/*.py` | `pylint` (7.0+ threshold), `pytest` with coverage (Python 3.11) |
| `bash-lint` | Syntax and best-practices checks for all `linux/*.sh` scripts | `shellcheck` |
| `linux-smoke` | Smoke tests: L01, L07, L15 with `--json` to verify output structure | Bash, JSON validation |
| `orchestrator` | End-to-end integration: full audit with `--min-severity Med` + report generation | Python runner, `report_generator.py` |

All jobs must pass before merging to `main`.

---

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
  --output FILE                 Write JSON results to FILE
  --html   FILE                 Write HTML report to FILE
  --csv    FILE                 Write CSV report to FILE
  --text   FILE                 Write plain-text report to FILE
  --json                        Print JSON to stdout

History & drift:
  --save-db                     Persist results to SQLite scan history database
  --diff                        Show drift vs last scan; exit code 2 on new regressions

Scan behaviour:
  --delay  SEC                  Sleep SEC seconds between scripts (IDS/rate-limit evasion)
  --timeout SEC                 Per-script timeout in seconds (default: 300)
  --parallel N                  Run N scripts concurrently (default: 1)
  --dry-run                     List scripts that would run without executing them

Remediation:
  --fix                         Apply opt-in fixes (disabled by default)

REST API:
  python3 common/api.py [--host HOST] [--port PORT]
                                Start REST API server (default: 127.0.0.1:5000)
```

---

---

## Exit Codes

| Code | Meaning |
|------|--------|
| `0` | All checks passed |
| `1` | At least one WARNING |
| `2` | At least one FAILURE, or new regressions detected with `--diff` |

---

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
make archive             # zip current reports

# Developer
make test                # pytest
make lint                # flake8 + shellcheck + pylint
make format              # black + isort
make ci                  # lint + test + scan-dry
```

---

---

## Documentation

| Document | Description |
|---|---|
| [docs/CATALOG.md](docs/CATALOG.md) | Complete script catalog with descriptions and severity ratings |
| [docs/USAGE.md](docs/USAGE.md) | CLI usage guide, scheduling, and SIEM integration examples |
| [docs/REMEDIATION_GUIDE.md](docs/REMEDIATION_GUIDE.md) | Detailed per-finding remediation steps |
| [docs/RUNTIME_REQUIREMENTS.md](docs/RUNTIME_REQUIREMENTS.md) | Full OS-level dependency list for all scripts |

---

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
3. **Follow conventions** — Bash scripts must pass `shellcheck`; Python must pass `pylint` at threshold 7.0+
4. **Script naming** — use the next available ID prefix (`L##` / `W##`) followed by a descriptive snake_case name
5. **Output contract** — scripts must emit at minimum: `CHECK_ID`, `STATUS` (`PASS` / `FAIL` / `WARN` / `INFO`), `SEVERITY`, and `MESSAGE` fields in JSON mode
6. **No secrets** — never log credentials, tokens, or PII; all output must be safe for SIEM ingestion
7. **Open a Pull Request** — include a description, the checks added or modified, and evidence that tests pass

For significant changes, open an issue first to discuss the proposed approach.

---

## License

This project is licensed under the [MIT License](LICENSE).
