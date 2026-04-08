# 🔒 CyberSWISS – Enterprise Security Audit & Remediation Platform

[![CI/CD Pipeline](https://img.shields.io/badge/CI%2FCD-passing-brightgreen)](https://github.com/jomardyan/CyberSWISS/actions/workflows/ci.yml)
[![Python Tests](https://img.shields.io/badge/Python%20Tests-passing-brightgreen)](https://github.com/jomardyan/CyberSWISS/actions/workflows/ci.yml)
[![Bash Lint](https://img.shields.io/badge/Bash%20Lint-passing-brightgreen)](https://github.com/jomardyan/CyberSWISS/actions/workflows/ci.yml)
[![Integration Tests](https://img.shields.io/badge/Integration%20Tests-passing-brightgreen)](https://github.com/jomardyan/CyberSWISS/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9+-blue)](https://www.python.org/downloads/)
[![Bash 4.0+](https://img.shields.io/badge/Bash-4.0+-brightgreen)](https://www.gnu.org/software/bash/)
[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1+-blue)](https://docs.microsoft.com/en-us/powershell/)

> **AUTHORIZED INTERNAL USE ONLY** – This repository contains security audit scripts for Windows and Linux endpoints/servers.  
> All scripts are **read-only by default**. Remediation requires an explicit `--fix` flag plus administrative approval.

---

## Overview

CyberSWISS is a professional, enterprise-grade security audit and remediation platform for financial-institution endpoints, servers, and Active Directory environments. It provides **44 runnable audit scripts** (22 Windows PowerShell + 22 Linux Bash), a Python orchestrator, REST API server, SQLite scan history with drift detection, multi-format reporting (HTML, JSON, CSV, plain-text), and a Tkinter GUI — all following a unified interface.

### Key Principles

- 🛡️ **Defensive only** – detection, validation, inventory, configuration review
- 📖 **Read-only by default** – no system changes without explicit `--fix` / `-Fix` flag
- 🔐 **No secrets in logs** – all output is safe to store and forward to SIEM
- ✅ **SIEM-ready** – all scripts support `--json` / `-Json` for structured output
- 🏢 **AD/GPO compatible** – W16 enforces domain password policy, LAPS, Kerberos hardening via GPO-safe registry writes
- 🔄 **Drift detection** – built-in SQLite history compares successive scans to surface new/resolved/changed findings
- 🌐 **REST API** – programmatic access to scan execution, history, HTML reports, and drift analysis
- 🏗️ **CI/CD ready** – `--diff` flag returns non-zero exit on new findings; 7-job GitHub Actions workflow included

---

## Key Features

| Feature | Details |
|---|---|
| **Modular architecture** | Each security domain is its own script — run any subset with `--scripts L07 L21 W16` |
| **Opt-in remediation** | `--fix` / `-Fix` applies fixes only when explicitly requested; destructive operations include a 10-second abort window |
| **Multi-format output** | JSON, HTML, CSV, plain-text — generated in one pass with `--output`, `--html`, `--csv`, `--text` |
| **Scan history & drift detection** | SQLite database (`--save-db`) + `--diff` for CI/CD change tracking and regression detection |
| **REST API server** | 8 REST endpoints with full async scan support, history management, HTML reports, and drift analysis |
| **Interactive GUI** | Tkinter-based GUI for point-and-click scanning without command-line knowledge |
| **Evasion / rate-limiting** | `--delay SEC` inserts configurable sleep between scripts to evade IDS/rate limiting |
| **Filtering & reporting** | `--min-severity`, `--status`, `--output`, `--html`, `--csv`, `--text` for precise output control |
| **Parallel execution** | `--parallel N` runs N scripts concurrently for faster audit cycles |
| **CI/CD integration** | `--diff` flag returns exit code 2 on regressions; perfect for pipeline gates |
| **AD/GPO compatibility** | W16 audits domain policy, privileged groups, LAPS, Kerberos, UAC, and AD Recycle Bin; `-Fix` writes GPO-compatible registry values |
| **Vulnerability scanning** | L21 provides CVE counts, OpenSSL/SSH/web-server version checks, nmap/nikto-style probes, and CPU mitigation audits |
| **Secrets detection** | L16/W17 detect `.env` leaks, cloud credentials (AWS/Azure/GCP), Docker auth, registry AutoLogon, IIS passwords |
| **DAST & API security** | L18/W19 check HTTP headers, CORS, Swagger/GraphQL exposure, TRACE method, admin endpoints, TLS cert expiry |
| **IaC scanning** | L19/W20 scan Dockerfile, docker-compose, Terraform, Kubernetes, Helm, ARM, Bicep, and Ansible playbooks |
| **SCA & license checks** | L20/W21 detect vulnerable packages, copyleft licenses (GPL/AGPL/LGPL), Log4j CVE-2021-44228, EOL runtimes |
| **Compliance mapping** | L22/W22 map findings to SOC 2, HIPAA, and GDPR controls (audit logging, encryption, access, retention, IDS/IPS) |
| **No secrets in logs** | All output is safe for SIEM ingestion — passwords, tokens, keys are never logged |
| **SIEM-ready** | All scripts support `--json` / `-Json` for direct Splunk, Elastic, or other SIEM integration |

---

## Repository Structure

```
CyberSWISS/
├── windows/                   # 22 PowerShell audit scripts (W01–W22)
│   ├── W01_password_policy.ps1
│   ├── W02_local_admin_review.ps1
│   ├── W03_patch_level.ps1
│   ├── ... (through W22_compliance_checks.ps1)
│   └── W22_compliance_checks.ps1
│
├── linux/                     # 22 Bash audit scripts (L01–L22)
│   ├── L01_password_policy.sh
│   ├── L02_sudo_users_review.sh
│   ├── L03_patch_level.sh
│   ├── ... (through L22_compliance_checks.sh)
│   └── L22_compliance_checks.sh
│
├── common/                    # Python orchestrator & utilities
│   ├── runner.py              # CLI orchestrator & executor
│   ├── report_generator.py    # Multi-format report generation (HTML, JSON, CSV, TXT)
│   ├── db.py                  # SQLite scan history, drift detection, query interface
│   ├── api.py                 # REST API v1 server (8 endpoints, async scan support)
│   ├── gui.py                 # Tkinter GUI for interactive scanning
│   └── utils.py               # Shared utilities (script discovery, execution, filtering)
│
├── ci/                        # CI/CD pipeline configuration
│   └── audit_pipeline.yml     # Legacy CI config (active workflow: .github/workflows/ci.yml)
│
├── docs/                      # Documentation
│   ├── CATALOG.md             # Complete script catalog with descriptions & severity
│   ├── USAGE.md               # CLI usage guide, scheduling, SIEM integration
│   └── REMEDIATION_GUIDE.md   # Detailed remediation steps for each script
│
├── tests/                     # Automated test suite
│   ├── test_runner.py         # Runner orchestration & CLI argument tests
│   ├── test_extended.py       # DB, API, report generation, new-script tests
│   └── test_utils.py          # Utility function tests
│
├── reports/                   # Output directory (gitignored)
│   └── (scan reports in JSON, HTML, CSV, plain-text)
│
├── .github/
│   └── workflows/
│       └── ci.yml             # GitHub Actions CI pipeline (7 jobs: lint, test, metadata, smoke)
│
├── LICENSE                    # MIT License
├── README.md                  # This file
└── requirements.txt           # Python dependencies (colorama, pytest)
```

---

## Quick Start

### Prerequisites

```bash
# Python 3.9+
pip install -r requirements.txt

# Full runtime dependency list for Linux/Windows script coverage
# See docs/RUNTIME_REQUIREMENTS.md

# Linux: run as root/sudo for full results
# Windows: run from an elevated PowerShell prompt
```

For full script coverage, install the OS-level tools listed in [docs/RUNTIME_REQUIREMENTS.md](/home/jomar/infrascan/CyberSWISS---Cybersecurity-Scaner-/docs/RUNTIME_REQUIREMENTS.md). `requirements.txt` only installs Python packages.

Bootstrap installers are included:

```bash
sudo ./setup/install_runtime_linux.sh --optional --yes
```

```powershell
PowerShell -ExecutionPolicy Bypass -File .\setup\install_runtime_windows.ps1 -Optional
```

### Run All Linux Checks

```bash
sudo python3 common/runner.py --os linux
```

### Run All Windows Checks (elevated PowerShell)

```powershell
python .\common\runner.py --os windows
```

### Run Specific Scripts

```bash
sudo python3 common/runner.py --scripts L07 L16 L21 W16
```

### Full Reporting — All Formats in One Pass

```bash
sudo python3 common/runner.py --os linux \
  --output reports/audit.json \
  --html   reports/audit.html \
  --csv    reports/audit.csv  \
  --text   reports/audit.txt  \
  --save-db
```

### Drift Detection (CI/CD)

```bash
# First run — save baseline
sudo python3 common/runner.py --os linux --save-db

# Subsequent run — show new/resolved/changed findings; exit non-zero on regressions
sudo python3 common/runner.py --os linux --save-db --diff
```

### Apply Opt-In Remediation

```bash
# Apply all safe auto-fixes (10-second abort window before destructive operations)
sudo python3 common/runner.py --os linux --fix
```

### Rate-Limit Between Scripts (Evasion / IDS Avoidance)

```bash
sudo python3 common/runner.py --os linux --delay 2
```

### Dry Run (Preview Which Scripts Would Run)

```bash
python3 common/runner.py --os linux --dry-run --json | python3 -m json.tool
```

### Launch GUI

```bash
python3 common/gui.py
```

### Start the REST API Server

```bash
python3 common/api.py --host 127.0.0.1 --port 8080
```

---

## REST API

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
# Start server
python3 common/api.py --host 127.0.0.1 --port 8080

# Trigger a scan
curl -s -X POST http://127.0.0.1:8080/api/v1/scan \
  -H 'Content-Type: application/json' \
  -d '{"os":"linux","fix":false}' | python3 -m json.tool

# List scan history
curl -s http://127.0.0.1:8080/api/v1/history | python3 -m json.tool
```

---

## Complete Script Catalog (44 Scripts)

### Windows PowerShell Scripts (22 scripts)

| ID  | Script | Category | Severity | Fix Support |
|-----|--------|----------|----------|-------------|
| W01 | Password Policy Audit | Accounts & Auth | High | ❌ Read-only |
| W02 | Local Admin Review | Accounts & Auth | High | ❌ Read-only |
| W03 | Patch Level & Software Inventory | Patch Management | Critical | ❌ Read-only |
| W04 | Services Audit | Services/Daemons | High | ✅ Disables insecure services |
| W05 | Network Listeners | Network Exposure | High | ❌ Read-only |
| W06 | Firewall State | Network Exposure | High | ✅ Enables firewall profiles |
| W07 | SMB/WinRM Posture | Network Exposure | High | ✅ Disables SMBv1, enables signing |
| W08 | Event Log Configuration | Logging & Auditing | High | ✅ Increases log sizes |
| W09 | Audit Policy | Logging & Auditing | High | ✅ Enables audit subcategories |
| W10 | Registry Hardening | Registry Security | High | ✅ AutoRun off, NTLMv2, LSASS PPL |
| W11 | BitLocker Status | Encryption | High | ❌ Read-only |
| W12 | Secure Boot & TPM | Boot Security | High | ❌ Read-only |
| W13 | Defender & EDR | Endpoint Protection | Critical | ✅ Enables real-time protection |
| W14 | Scheduled Tasks Audit | Persistence Mechanisms | High | ❌ Read-only |
| W15 | CIS Baseline Hardening | Baseline Hardening | High | ✅ PowerShell logging, SMB hardening |
| W16 | **Active Directory & GPO** | Identity & Access | High | ✅ GPO-compatible registry writes |
| W17 | Secrets Scanning | Secrets & Credentials | High | ❌ Read-only |
| W18 | Attack Surface Management | Network Exposure | High | ❌ Read-only |
| W19 | API Endpoint Discovery & DAST | Application Security | High | ❌ Read-only |
| W20 | IaC Security Scanning | DevSecOps | Medium | ❌ Read-only |
| W21 | SCA & License Compliance | Open-Source Risk | Medium | ❌ Read-only |
| W22 | Compliance Automation | Regulatory Mapping | High | ❌ Read-only |

### Linux Bash Scripts (22 scripts)

| ID  | Script | Category | Severity | Fix Support |
|-----|--------|----------|----------|-------------|
| L01 | Password Policy | Accounts & Auth | High | ✅ Sets PASS_MAX_DAYS, min length |
| L02 | Sudo & Privileged Users | Accounts & Auth | High | ❌ Read-only |
| L03 | Patch Level | Patch Management | Critical | ✅ Runs apt/dnf/zypper upgrade |
| L04 | Services Audit | Services/Daemons | High | ✅ Disables insecure services |
| L05 | Network Listeners | Network Exposure | High | ❌ Read-only |
| L06 | Firewall State | Network Exposure | High | ✅ Enables ufw/firewalld |
| L07 | SSH Posture | Network Exposure | High | ❌ Read-only (audit only) |
| L08 | Auditd & Logging | Logging & Auditing | High | ✅ Installs & enables auditd |
| L09 | Syslog Configuration | Logging & Auditing | Medium | ✅ Installs & enables rsyslog |
| L10 | File Permissions (SUID/SGID) | File Permissions | High | ❌ Read-only |
| L11 | LUKS Encryption | Encryption | High | ❌ Read-only |
| L12 | Secure Boot | Boot Security | High | ❌ Read-only |
| L13 | AV & EDR Presence | Endpoint Protection | Critical | ✅ Installs ClamAV |
| L14 | Cron & Persistence | Persistence Mechanisms | High | ❌ Read-only |
| L15 | CIS Baseline Hardening | Baseline Hardening | High | ✅ Writes sysctl.d hardening conf |
| L16 | Secrets Scanning | Secrets & Credentials | High | ❌ Read-only |
| L17 | Attack Surface Management | Network Exposure | High | ✅ Persists iptables DROP rules |
| L18 | API Endpoint Discovery & DAST | Application Security | High | ❌ Read-only |
| L19 | IaC Security Scanning | DevSecOps | Medium | ❌ Read-only |
| L20 | SCA & License Compliance | Open-Source Risk | Medium | ❌ Read-only |
| L21 | Vulnerability Scanning | Vulnerability Mgmt | High | ❌ Read-only |
| L22 | Compliance Automation | Regulatory Mapping | High | ❌ Read-only |

---

## Active Directory / GPO Integration (W16)

`W16_ad_gpo_security.ps1` is fully compatible with AD-joined Windows endpoints and can be deployed as a **GPO Startup Script** or **Scheduled Task via GPO**:

- Reads domain password policy via `HKLM:\SYSTEM\...\Netlogon\Parameters` (locale-neutral, no RSAT required)
- Audits Domain Admins, Enterprise Admins, and Schema Admins membership
- Checks LAPS deployment, Kerberos RC4 ticket encryption, UAC settings, NTLMv2 enforcement, and AD Recycle Bin
- `-Fix` writes GPO-compatible registry values (does **not** modify AD objects; AD policy changes should be made via GPMC)

```powershell
# Deploy as GPO Computer Startup Script
# Path: \\domain\SYSVOL\...\scripts\W16_ad_gpo_security.ps1
# Arguments: -Json   (for SIEM ingestion)
#            -Fix    (optional: apply local hardening baselines)
```

---

## Drift Detection

```
  ▲  NEW FINDINGS (1)
     [FAIL] [High] L07-C3: SSH MFA – No MFA configured

  ✔  RESOLVED FINDINGS (1)
     [WARN] [High] L07-C2: SSH Protocol – previously flagged, now fixed

  ↔  CHANGED FINDINGS (1)
     [WARN→FAIL] [High] L21-C1: OS CVE count increased from 12 to 47
```

Use `--diff` to show this output inline; the runner exits `2` if new FAILs are detected — perfect for blocking CI/CD pipelines on regressions.

---

## GitHub Actions CI/CD Pipeline

The included `.github/workflows/ci.yml` runs automatically on every push and pull request:

| Job | What it validates | Tools |
|-----|-------------------|-------|
| `python-tests` | Python linting and unit tests for `common/*.py` | `pylint` (7.0+ threshold), `pytest` with coverage (Python 3.11) |
| `bash-lint` | Bash syntax and best-practices checks for all `linux/*.sh` scripts | `shellcheck` (warning severity) |
| `linux-smoke` | Smoke tests running L01, L07, L15 with `--json` to verify output structure | Bash shell, JSON validation |
| `orchestrator` | End-to-end integration: full audit with `--min-severity Med`, report generation | Python runner, report_generator.py, HTML output |

**Status:** All tests must pass before merging to `main`.

---

## CLI Reference

```
python3 common/runner.py [OPTIONS]

Target selection:
  --os {linux,windows,both}   Run all scripts for the specified OS (default: auto-detect)
  --scripts ID [ID ...]        Run specific scripts by ID (e.g. L07 W16 L21)

Filtering & output:
  --min-severity SEV           Only report findings at or above severity (Info/Low/Med/High/Critical)
  --status STAT [STAT ...]     Filter output by finding status (PASS FAIL WARN INFO)

Output formats:
  --output FILE                Write JSON results to FILE
  --html   FILE                Write HTML report to FILE
  --csv    FILE                Write CSV report to FILE
  --text   FILE                Write plain-text report to FILE
  --json                       Print JSON to stdout

History & drift detection:
  --save-db                    Persist results to SQLite scan history database
  --diff                       Show drift vs last scan; exit code 2 on new regressions

Scanning behaviour:
  --delay  SEC                 Sleep SEC seconds between scripts (IDS/rate-limit evasion)
  --timeout SEC                Per-script timeout in seconds (default: 300)
  --parallel N                 Run N scripts concurrently (default: 1)
  --dry-run                    List scripts that would run without executing them

Remediation:
  --fix                        Apply opt-in fixes (read-only by default)

REST API:
  python3 common/api.py --host HOST --port PORT   Start REST API server (default: 127.0.0.1:5000)
```

---

## CLI Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed |
| `1` | At least one WARNING |
| `2` | At least one FAILURE (or new regressions detected with `--diff`) |

---

## Documentation

- 📋 [Script Catalog](docs/CATALOG.md)
- 📖 [Usage Guide](docs/USAGE.md)
- 🔧 [Remediation Guide](docs/REMEDIATION_GUIDE.md)

---

## Security Notice

This platform is designed for **authorized, internal security auditing only**.  
- Scripts perform **non-destructive, read-only checks** by default  
- Remediation (`--fix`) is **disabled by default** and requires an explicit flag  
- No credentials, secrets, or PII are collected or logged  
- Audit reports should be treated as sensitive and access-controlled
