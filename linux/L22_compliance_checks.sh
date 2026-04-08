#!/usr/bin/env bash
# =============================================================================
# L22 – Compliance Automation (Linux)
# =============================================================================
# ID       : L22
# Category : Compliance Automation
# Severity : High
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : Yes
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L22_compliance_checks.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L22"
SCRIPT_NAME="Compliance Automation"
HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
JSON_MODE=false
FIX_MODE=false
FINDINGS='[]'

for arg in "$@"; do
    case "$arg" in
        --json) JSON_MODE=true ;;
        --fix)  FIX_MODE=true  ;;
        -h|--help) echo "Usage: $0 [--json] [--fix]"; exit 0 ;;
        *) echo "Unknown argument: $arg" >&2; exit 1 ;;
    esac
done

add_finding() {
    local id="$1" name="$2" sev="$3" status="$4" detail="$5" remediation="$6"
    local entry
    entry=$(printf '{"id":"%s","name":"%s","severity":"%s","status":"%s","detail":"%s","remediation":"%s","timestamp":"%s"}' \
        "$id" "$name" "$sev" "$status" "$(echo "$detail" | sed 's/"/\\"/g')" "$(echo "$remediation" | sed 's/"/\\"/g')" "$TIMESTAMP")
    if [[ "$FINDINGS" == '[]' ]]; then FINDINGS="[$entry]"; else FINDINGS="${FINDINGS%]},${entry}]"; fi
    if [[ "$JSON_MODE" == false ]]; then
        case "$status" in
            PASS) colour='\033[0;32m' ;; WARN) colour='\033[0;33m' ;; FAIL) colour='\033[0;31m' ;; *) colour='\033[0;36m' ;;
        esac
        printf "${colour}[%s] [%s] %s: %s\033[0m\n" "$status" "$sev" "$id" "$name"
        [[ -n "$detail" ]]      && printf "       Detail : %s\n" "$detail"
        [[ "$status" != "PASS" && -n "$remediation" ]] && printf "\033[0;36m       Remedy : %s\033[0m\n" "$remediation"
    fi
}

# C1 – Audit logging: auditd running + key rules (SOC2 CC7.2 / HIPAA §164.312(b))
audit_issues=""
if ! command -v auditctl &>/dev/null && ! systemctl is-active --quiet auditd 2>/dev/null; then
    audit_issues="auditd not installed or not running"
else
    if ! systemctl is-active --quiet auditd 2>/dev/null; then
        audit_issues="auditd installed but not running"
    else
        # Check for key audit rules
        audit_rules=$(auditctl -l 2>/dev/null || cat /etc/audit/audit.rules 2>/dev/null || true)
        for pattern in "login" "execve\|exec\|4755\|suid" "sudo\|wheel\|su\b"; do
            echo "$audit_rules" | grep -qiE "$pattern" 2>/dev/null || \
                audit_issues="${audit_issues} missing-rule:${pattern};"
        done
    fi
fi

if [[ -z "$audit_issues" ]]; then
    add_finding "${SCRIPT_ID}-C1" "Audit Logging (SOC2 CC7.2 / HIPAA §164.312(b))" "High" "PASS" \
        "auditd is running with login, exec, and privilege escalation rules" ""
else
    add_finding "${SCRIPT_ID}-C1" "Audit Logging (SOC2 CC7.2 / HIPAA §164.312(b))" "High" "FAIL" \
        "Audit logging issues: ${audit_issues}" \
        "Install and start auditd; add rules for login, file access, and privilege escalation. See auditd.conf(5)."
fi

# C2 – Data encryption at rest (HIPAA §164.312(a)(2)(iv) / GDPR Art. 32)
enc_issues=""
# LUKS check
if command -v lsblk &>/dev/null; then
    encrypted_devs=$(lsblk -o NAME,TYPE,FSTYPE 2>/dev/null | grep -i 'crypt\|luks' || true)
    if [[ -z "$encrypted_devs" ]]; then
        enc_issues="No LUKS/dm-crypt encrypted partitions detected"
    fi
fi
# MySQL unencrypted data directory
if command -v mysql &>/dev/null || systemctl is-active --quiet mysql 2>/dev/null || systemctl is-active --quiet mysqld 2>/dev/null; then
    mysql_datadir=$(mysql -Nse "SHOW VARIABLES LIKE 'datadir';" 2>/dev/null | awk '{print $2}' || true)
    if [[ -n "$mysql_datadir" ]]; then
        enc_at_rest=$(mysql -Nse "SHOW VARIABLES LIKE 'innodb_encrypt%';" 2>/dev/null | grep -i 'ON\|1' || true)
        [[ -z "$enc_at_rest" ]] && enc_issues="${enc_issues} MySQL:InnoDB-encryption-not-confirmed"
    fi
fi

if [[ -z "$enc_issues" ]]; then
    add_finding "${SCRIPT_ID}-C2" "Data Encryption at Rest (HIPAA §164.312 / GDPR Art.32)" "High" "PASS" \
        "LUKS encrypted partitions detected" ""
else
    add_finding "${SCRIPT_ID}-C2" "Data Encryption at Rest (HIPAA §164.312 / GDPR Art.32)" "High" "WARN" \
        "${enc_issues}" \
        "Enable LUKS full-disk encryption for data partitions; enable InnoDB encryption for MySQL"
fi

# C3 – Access control: least privilege (SOC2 CC6.3 / HIPAA §164.312(a)(1))
priv_issues=""
# Extra UID 0 accounts
extra_root=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd 2>/dev/null || true)
[[ -n "$extra_root" ]] && priv_issues="Extra UID-0 account(s): ${extra_root};"

# World-writable directories in /etc
ww_etc=$(find /etc -maxdepth 2 -type d -perm -002 2>/dev/null | head -5 || true)
[[ -n "$ww_etc" ]] && priv_issues="${priv_issues} World-writable /etc dirs: ${ww_etc};"

# Unexpected SUID/SGID binaries
expected_suid_count=20
actual_suid_count=$(find /usr/bin /usr/sbin /bin /sbin -perm /4000 2>/dev/null | wc -l || true)
if [[ "$actual_suid_count" -gt "$expected_suid_count" ]]; then
    priv_issues="${priv_issues} Unexpected SUID count:${actual_suid_count}(expected<=${expected_suid_count});"
fi

if [[ -z "$priv_issues" ]]; then
    add_finding "${SCRIPT_ID}-C3" "Least Privilege / Access Control (SOC2 CC6.3)" "High" "PASS" \
        "No extra UID-0 accounts, no world-writable /etc dirs, SUID count within threshold" ""
else
    add_finding "${SCRIPT_ID}-C3" "Least Privilege / Access Control (SOC2 CC6.3)" "High" "FAIL" \
        "${priv_issues}" \
        "Remove extra UID-0 accounts; fix world-writable /etc dirs (chmod o-w); audit SUID binaries"
fi

# C4 – Log retention >= 90 days (SOC2 CC2.2 / HIPAA §164.312(b))
retention_issues=""
# Calculate effective retention: parse rotation frequency and count
logrotate_rotate=0
logrotate_freq="weekly"
if [[ -f /etc/logrotate.conf ]] || ls /etc/logrotate.d/ &>/dev/null; then
    logrotate_rotate=$(grep -rh 'rotate\s' /etc/logrotate.conf /etc/logrotate.d/ 2>/dev/null | \
        grep -oE 'rotate\s+[0-9]+' | awk '{print $2}' | sort -n | head -1 || echo 0)
    # Detect frequency: prefer most conservative (daily/weekly/monthly)
    if grep -rqh 'daily' /etc/logrotate.conf /etc/logrotate.d/ 2>/dev/null; then
        logrotate_freq="daily"
    elif grep -rqh 'monthly' /etc/logrotate.conf /etc/logrotate.d/ 2>/dev/null; then
        logrotate_freq="monthly"
    fi
fi

# Compute effective days of retention
effective_days=0
case "$logrotate_freq" in
    daily)   effective_days=$(( logrotate_rotate * 1 )) ;;
    weekly)  effective_days=$(( logrotate_rotate * 7 )) ;;
    monthly) effective_days=$(( logrotate_rotate * 30 )) ;;
esac

if [[ "$logrotate_rotate" -gt 0 && "$effective_days" -lt 90 ]]; then
    retention_issues="logrotate: ${logrotate_rotate} ${logrotate_freq} rotations = ~${effective_days} days (below 90-day requirement)"
fi

# Check oldest log file age
oldest_log_days=0
oldest_log=$(ls -t /var/log/*.log /var/log/syslog* /var/log/messages* 2>/dev/null | tail -1 || true)
if [[ -n "$oldest_log" ]]; then
    mod_time=$(stat -c '%Y' "$oldest_log" 2>/dev/null || true)
    now_time=$(date +%s)
    oldest_log_days=$(( (now_time - mod_time) / 86400 ))
fi

if [[ "$oldest_log_days" -lt 90 && -z "$retention_issues" ]]; then
    retention_issues="Oldest log is only ${oldest_log_days} days old – retention may be <90 days"
fi

if [[ -z "$retention_issues" ]]; then
    add_finding "${SCRIPT_ID}-C4" "Log Retention >= 90 Days (SOC2 CC2.2 / HIPAA §164.312(b))" "Med" "PASS" \
        "Log rotation and retention appear configured for >= 90 days" ""
else
    add_finding "${SCRIPT_ID}-C4" "Log Retention >= 90 Days (SOC2 CC2.2 / HIPAA §164.312(b))" "Med" "WARN" \
        "${retention_issues}" \
        "Configure logrotate to retain logs >= 90 days (rotate 13 weekly or 3 monthly with compress)"
fi

# C5 – Incident response readiness (SOC2 CC7.3)
ids_found=""
for ids_tool in aide tripwire ossec wazuh samhain; do
    command -v "$ids_tool" &>/dev/null && ids_found="${ids_found} ${ids_tool}"
    systemctl is-active --quiet "$ids_tool" 2>/dev/null && ids_found="${ids_found} ${ids_tool}(active)"
done
# Check for ossec/wazuh directories
[[ -d /var/ossec ]] && ids_found="${ids_found} ossec(dir:/var/ossec)"
[[ -d /var/wazuh ]] && ids_found="${ids_found} wazuh(dir:/var/wazuh)"

# Dedup
ids_found=$(echo "$ids_found" | tr ' ' '\n' | sort -u | tr '\n' ' ' | xargs || true)

if [[ -z "$ids_found" ]]; then
    add_finding "${SCRIPT_ID}-C5" "IDS/IPS Presence (SOC2 CC7.3)" "High" "FAIL" \
        "No IDS/IPS tools detected (aide, tripwire, ossec, wazuh, samhain)" \
        "Install and configure an IDS: apt-get install aide or deploy Wazuh agent for SIEM integration"
else
    add_finding "${SCRIPT_ID}-C5" "IDS/IPS Presence (SOC2 CC7.3)" "High" "PASS" \
        "IDS/IPS tool(s) present: ${ids_found}" ""
fi

# C6 – GDPR data minimisation: large files in unexpected locations (GDPR Art. 5)
large_files=""
while IFS= read -r -d '' f; do
    size_mb=$(du -m "$f" 2>/dev/null | cut -f1 || true)
    [[ -n "$size_mb" ]] && large_files="${large_files} ${f}(${size_mb}MB)"
done < <(find /tmp /home /var/tmp -maxdepth 4 -type f -size +100M -print0 2>/dev/null)

if [[ -z "$large_files" ]]; then
    add_finding "${SCRIPT_ID}-C6" "GDPR Data Minimisation – Large Files (GDPR Art.5)" "Med" "PASS" \
        "No files >100MB found in /tmp, /home, /var/tmp" ""
else
    add_finding "${SCRIPT_ID}-C6" "GDPR Data Minimisation – Large Files (GDPR Art.5)" "Med" "WARN" \
        "Large file(s) in potentially unexpected locations:${large_files}" \
        "Review large files for data dumps/exports. Ensure data minimisation policies are enforced."
fi

# C7 – Change management (SOC2 CC8.1)
change_issues=""
# dpkg/dnf install logs
if [[ ! -f /var/log/dpkg.log ]] && [[ ! -f /var/log/dnf.log ]] && [[ ! -f /var/log/yum.log ]]; then
    change_issues="No package installation log found (dpkg.log / dnf.log / yum.log);"
fi

# /etc in git repo for config tracking
if ! git -C /etc rev-parse --is-inside-work-tree &>/dev/null; then
    change_issues="${change_issues} /etc is not tracked in a git repository;"
fi

# AIDE/tripwire file integrity monitoring
fim_present=false
command -v aide     &>/dev/null && fim_present=true
command -v tripwire &>/dev/null && fim_present=true
[[ -f /var/lib/aide/aide.db ]] && fim_present=true
[[ "$fim_present" == false ]] && change_issues="${change_issues} No file integrity monitoring (aide/tripwire) configured;"

if [[ -z "$change_issues" ]]; then
    add_finding "${SCRIPT_ID}-C7" "Change Management Controls (SOC2 CC8.1)" "Med" "PASS" \
        "Package logs present, /etc tracked in git, and FIM tool available" ""
else
    add_finding "${SCRIPT_ID}-C7" "Change Management Controls (SOC2 CC8.1)" "Med" "WARN" \
        "${change_issues}" \
        "Enable dpkg/dnf logging; track /etc with etckeeper (git); install aide for FIM"
fi

# ── Optional Fix ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "WARNING: --fix will attempt to enable logrotate and initialise aide if available" >&2
    echo "Press Ctrl+C within 10 seconds to abort..." >&2
    sleep 10
    # Enable logrotate timer if systemd available
    if systemctl list-unit-files logrotate.timer &>/dev/null; then
        systemctl enable --now logrotate.timer 2>/dev/null && \
            echo "logrotate.timer enabled." >&2 || echo "Failed to enable logrotate.timer." >&2
    fi
    # Initialise aide if available and database not yet created
    if command -v aide &>/dev/null && [[ ! -f /var/lib/aide/aide.db ]]; then
        echo "Initialising AIDE database (non-destructive)..." >&2
        aide --init 2>/dev/null && \
            mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true
        echo "AIDE database initialised at /var/lib/aide/aide.db" >&2
    fi
fi

# ── Output ───────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_compliance_checks" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
else
    echo ""
    echo "=== ${SCRIPT_ID} ${SCRIPT_NAME} – ${HOSTNAME_VAL} ==="
    FAIL_COUNT=$(printf '%s\n' "$FINDINGS" | grep -c '"status":"FAIL"' || true)
    WARN_COUNT=$(printf '%s\n' "$FINDINGS" | grep -c '"status":"WARN"' || true)
    TOTAL=$(printf '%s\n' "$FINDINGS" | grep -c '"id":' || true)
    echo "Summary: ${TOTAL} finding(s), ${FAIL_COUNT} FAIL, ${WARN_COUNT} WARN"
fi

FAIL_COUNT=$(printf '%s\n' "$FINDINGS" | grep -c '"status":"FAIL"' || true)
WARN_COUNT=$(printf '%s\n' "$FINDINGS" | grep -c '"status":"WARN"' || true)
if [[ "$FAIL_COUNT" -gt 0 ]]; then exit 2; fi
if [[ "$WARN_COUNT" -gt 0 ]]; then exit 1; fi
exit 0
