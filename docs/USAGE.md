# CyberSWISS Usage Guide

## Prerequisites

### Common
- Python 3.9+
- `pip install -r requirements.txt`
- Full OS/runtime dependency list: [RUNTIME_REQUIREMENTS.md](/home/jomar/infrascan/CyberSWISS---Cybersecurity-Scaner-/docs/RUNTIME_REQUIREMENTS.md)
- Bootstrap installers:
  - Linux: `sudo ./setup/install_runtime_linux.sh --optional --yes`
  - Windows: `PowerShell -ExecutionPolicy Bypass -File .\setup\install_runtime_windows.ps1 -Optional`

### Linux Scripts
- Bash 4.0+
- `sudo` access for most scripts
- Optional: `ss` or `netstat`, `auditd`, `cryptsetup`, `mokutil`

### Windows Scripts
- PowerShell 5.1+
- Administrator privileges
- Run from an elevated PowerShell prompt

---

## Quick Start

### Bootstrap Runtime
```bash
sudo ./setup/install_runtime_linux.sh --optional --yes
```

```powershell
PowerShell -ExecutionPolicy Bypass -File .\setup\install_runtime_windows.ps1 -Optional
```

### Basic Audit
```bash
sudo python3 common/runner.py --os linux
```

```powershell
python .\common\runner.py --os windows
```

## Advanced Usage Examples

### Full Audit with Multi-Format Reporting
```bash
# Run complete audit on Linux, generate all report formats in one pass
sudo python3 common/runner.py --os linux \
  --output reports/audit.json \
  --html reports/audit.html \
  --csv reports/audit.csv \
  --text reports/audit.txt \
  --save-db
```

### Filtered Audit (High severity only)
```bash
sudo python3 common/runner.py --os linux \
  --min-severity High \
  --output reports/high-severity.json
```

### CVE Scanning + Secrets Detection Only
```bash
# Vulnerability scanning (L21) and Secrets scanning (L16)
sudo python3 common/runner.py --scripts L16 L21 \
  --output reports/security-risks.json \
  --html reports/security-risks.html
```

### Drift Detection for CI/CD
```bash
# First run – establish baseline
sudo python3 common/runner.py --os linux --save-db

# Subsequent run – detect changes; exit non-zero on regressions
sudo python3 common/runner.py --os linux --save-db --diff
# Exit code 2 if new FAIL findings detected
```

### Rate-Limited Scanning (Evasion)
```bash
# Insert 5-second delay between scripts to avoid IDS/rate-limiting
sudo python3 common/runner.py --os linux --delay 5 --output reports/audit.json
```

### Parallel Scanning (Faster)
```bash
# Run 4 scripts concurrently (speeds up overall audit)
sudo python3 common/runner.py --os linux --parallel 4 --output reports/audit.json
```

### Apply Remediation
```bash
# Apply all opt-in fixes (read-only by default)
sudo python3 common/runner.py --os linux --fix

# Combine with dry-run to see what would happen
sudo python3 common/runner.py --os linux --dry-run --fix
```

### Verified Fix Mode in GUI
```bash
python3 common/gui.py
```

Fix Mode in the GUI now performs:

1. A remediation run with `--fix`
2. An immediate verification run without `--fix`
3. A fix summary showing what was actually fixed, what remains, and whether verification failed

### Interactive GUI
```bash
# Launch point-and-click scanning interface
python3 common/gui.py

# Or run with pre-selected OS
python3 common/gui.py --os linux
```

GUI capabilities include:

- run / stop control for active scripts
- rerun-failed workflow
- per-script tooltip help
- multi-format report snapshot export
- verified fix-mode reporting

### REST API Server
```bash
# Start API server on custom host/port
python3 common/api.py --host 0.0.0.0 --port 8080

# In another terminal, trigger a scan
curl -s -X POST http://localhost:8080/api/v1/scan \
  -H 'Content-Type: application/json' \
  -d '{"os":"linux","fix":false}' | python3 -m json.tool

# Check scan history
curl -s http://localhost:8080/api/v1/history | python3 -m json.tool
```

### Windows + Linux Combined Audit
```powershell
# Run all 52 scripts (both Windows and Linux) with drift tracking
python .\common\runner.py --os both \
  --save-db \
  --output reports/full_audit.json \
  --html reports/full_audit.html
```

### Export for SIEM (JSON streaming)
```bash
# Direct JSON output to Splunk HEC
sudo python3 common/runner.py --os linux --json | \
  curl -s -H "Authorization: Splunk $HEC_TOKEN" \
    -d @- "https://splunk.company.com:8088/services/collector/event"
```

---

## CLI Reference

### runner.py – Main Orchestrator

```
usage: runner.py [-h] [--os {windows,linux,both}] [--scripts ID [ID ...]]
                 [--min-severity SEV] [--status {PASS,FAIL,WARN,INFO} ...]
                 [--output FILE] [--timeout SEC] [--parallel N]
                 [--dry-run] [--no-colour] [--json] [--fix]
                 [--delay SEC] [--save-db] [--diff]

Options:
  --os {linux,windows,both}    Filter by OS (default: auto-detect current platform)
  
  --scripts ID [ID ...]        Run specific script IDs (e.g. L07 W16 L21)
                               If not provided, runs all scripts for chosen OS
  
  --min-severity SEV           Only show findings >= severity level
                               Options: Info, Low, Med, High, Critical
  
  --status STAT [STAT ...]     Only show findings with specific status
                               Options: PASS, FAIL, WARN, INFO
  
  --output FILE                Write JSON report to FILE
  
  --html   FILE                Write formatted HTML report to FILE
  
  --csv    FILE                Write CSV report to FILE
  
  --text   FILE                Write plain-text report to FILE
  
  --json                       Output JSON to stdout (incompatible with --output)
  
  --fix                        Apply opt-in fixes. Default is read-only.
                               Destructive operations have 10-second abort window.
  
  --timeout SEC                Per-script timeout in seconds (default: 300)
  
  --parallel N                 Run N scripts concurrently (default: 1)
                               Higher values speed up scans but increase resource usage
  
  --delay SEC                  Sleep SEC seconds between scripts
                               Useful for evading rate-limiting and IDS detections
  
  --dry-run                    List scripts that would run without executing them
  
  --no-colour                  Disable ANSI colour output
  
  --save-db                    Persist scan results to SQLite database
                               Enables --diff for drift analysis on future runs
  
  --diff                       Show drift vs last scan (requires --save-db)
                               Exits with code 2 if regressions detected (new FAILs)
  
  -h, --help                   Show help message
```

### Individual Linux Scripts

All Linux scripts support:
```
--json    Output in JSON format
--fix     Apply remediation (select scripts only, off by default)
-h/--help Show usage
```

**Exit codes:**
- `0` = All checks passed
- `1` = At least one WARNING
- `2` = At least one FAILURE

### Individual Windows Scripts (PowerShell)

Windows scripts commonly support the following parameters:
```powershell
-Json     # Output in JSON format (all scripts)
-Fix      # Apply remediation where supported (select scripts only, off by default)
```

**Exit codes:**
- `0` = All checks passed
- `1` = At least one WARNING
- `2` = At least one FAILURE

---

## SIEM Integration

All scripts support `--json` / `-Json` output. Pipe to your SIEM:

```bash
# Splunk (HEC)
sudo bash linux/L07_ssh_posture.sh --json | curl -s -H "Authorization: Splunk $HEC_TOKEN" \
  -d @- "https://splunk:8088/services/collector/event"

# Elastic
sudo bash linux/L15_cis_baseline.sh --json | curl -s -XPOST \
  "https://elastic:9200/cyberswiss/_doc" -H 'Content-Type: application/json' -d @-
```

---

## Scheduling / Automation

### Linux (cron)
```cron
# Run full audit every Sunday at 02:00, save report
0 2 * * 0 root /usr/bin/python3 /opt/cyberswiss/common/runner.py --os linux \
  --output /var/log/cyberswiss/audit_$(date +\%Y\%m\%d).json >> /var/log/cyberswiss/runner.log 2>&1
```

### Windows (Task Scheduler)
```powershell
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2am
$action  = New-ScheduledTaskAction -Execute "python.exe" `
           -Argument "C:\cyberswiss\common\runner.py --os windows --output C:\audit\report.json"
Register-ScheduledTask -TaskName "CyberSWISS Weekly Audit" `
  -Trigger $trigger -Action $action -RunLevel Highest
```

---

## Security Notes

- All scripts are **read-only by default**. The `--fix` flag is disabled by default.
- Scripts do **not** modify any system configuration unless `--fix` is explicitly passed.
- GUI `Fix Mode` verifies post-remediation state by re-running the script without fix mode and recording the verified outcome in the report.
- No credentials, secrets, or sensitive data are written to output files.
- Audit results should be treated as sensitive – restrict access to report files.
- Review the [CATALOG.md](CATALOG.md) for admin requirements per script.
