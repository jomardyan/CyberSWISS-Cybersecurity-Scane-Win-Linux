#!/usr/bin/env bash
# =============================================================================
# L08 – Auditd / Logging Configuration (Linux)
# =============================================================================
# ID       : L08
# Category : Logging & Auditing
# Severity : High
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : Yes
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L08_auditd_logging.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L08"
SCRIPT_NAME="Auditd & Logging Configuration"
HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
JSON_MODE=false
FIX_MODE=false
FINDINGS='[]'

for arg in "$@"; do
    case "$arg" in
        --json) JSON_MODE=true ;;
        --fix)  FIX_MODE=true  ;;
        -h|--help) echo "Usage: sudo $0 [--json] [--fix]"; exit 0 ;;
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

# C1 – auditd installed and running
if command -v auditctl &>/dev/null; then
    if systemctl is-active --quiet auditd 2>/dev/null || service auditd status &>/dev/null 2>&1; then
        add_finding "${SCRIPT_ID}-C1" "auditd Service Running" "High" "PASS" \
            "auditd service is running" ""
    else
        add_finding "${SCRIPT_ID}-C1" "auditd Service Running" "High" "FAIL" \
            "auditd is installed but NOT running" \
            "Start: systemctl start auditd && systemctl enable auditd"
    fi
else
    add_finding "${SCRIPT_ID}-C1" "auditd Installed" "High" "FAIL" \
        "auditd not found" \
        "Install: apt-get install auditd (Debian) or yum install audit (RHEL)"
fi

# C2 – auditd rules: key areas covered
AUDIT_RULES_DIRS=("/etc/audit/rules.d" "/etc/audit/audit.rules")
all_rules=""
for dir in "${AUDIT_RULES_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        all_rules+=$(cat "${dir}"/*.rules 2>/dev/null || true)
    elif [[ -f "$dir" ]]; then
        all_rules+=$(cat "$dir" 2>/dev/null || true)
    fi
done
# Also check loaded rules
if command -v auditctl &>/dev/null; then
    all_rules+=$(auditctl -l 2>/dev/null || true)
fi

declare -A required_audit_checks=(
    ["privileged"]="Privileged command execution monitoring"
    ["sudoers\|sudo"]="sudo/sudoers changes monitoring"
    ["passwd\|shadow"]="Password file modification monitoring"
    ["cron"]="Cron modification monitoring"
    ["ssh"]="SSH key/config monitoring"
    ["modules\|insmod\|rmmod"]="Kernel module loading monitoring"
    ["-e 2\|immutable"]="Audit config immutability"
    ["time-change\|adjtimex"]="System time change monitoring"
    ["identity\|-w /etc/passwd"]="User/group identity monitoring"
)

for pattern in "${!required_audit_checks[@]}"; do
    desc="${required_audit_checks[$pattern]}"
    # Sanitize the pattern key: remove backslashes and replace non-alphanumeric chars with dashes
    safe_id="${pattern//\\/}"
    safe_id="${safe_id//[^a-zA-Z0-9_-]/-}"
    if echo "$all_rules" | grep -qiE "$pattern" 2>/dev/null; then
        add_finding "${SCRIPT_ID}-C2-${safe_id:0:15}" "Audit Rule: ${desc:0:40}" "High" "PASS" \
            "${desc} rule found" ""
    else
        add_finding "${SCRIPT_ID}-C2-${safe_id:0:15}" "Audit Rule: ${desc:0:40}" "High" "WARN" \
            "${desc} – no matching rule detected" \
            "Add audit rule for: ${desc}. See /etc/audit/rules.d/ documentation."
    fi
done

# C3 – auditd log file size / space remaining
AUDIT_LOG=/var/log/audit/audit.log
if [[ -f "$AUDIT_LOG" ]]; then
    log_size_mb=$(du -m "$AUDIT_LOG" 2>/dev/null | awk '{print $1}')
    add_finding "${SCRIPT_ID}-C3" "Audit Log Size" "Info" "INFO" \
        "Current audit.log size: ${log_size_mb}MB" ""
    # Check disk usage of /var/log/audit
    disk_usage=$(df -h /var/log/audit 2>/dev/null | tail -1 | awk '{print $5}' | tr -d '%' || echo 0)
    if [[ "$disk_usage" -gt 85 ]] 2>/dev/null; then
        add_finding "${SCRIPT_ID}-C3b" "Audit Log Partition Space" "High" "WARN" \
            "/var/log/audit partition is ${disk_usage}% full" \
            "Increase partition size or configure log rotation in /etc/audit/auditd.conf"
    fi
fi

# C4 – auditd.conf: space_left_action
AUDITD_CONF=/etc/audit/auditd.conf
if [[ -f "$AUDITD_CONF" ]]; then
    space_action=$(grep -iE '^\s*space_left_action\s*=' "$AUDITD_CONF" | awk -F= '{print $2}' | tr -d ' ' | head -1 || echo "")
    if [[ "$space_action" =~ ^(email|syslog|rotate)$ ]]; then
        add_finding "${SCRIPT_ID}-C4" "auditd space_left_action" "Med" "PASS" \
            "space_left_action=${space_action}" ""
    else
        add_finding "${SCRIPT_ID}-C4" "auditd space_left_action" "Med" "WARN" \
            "space_left_action=${space_action:-not_set} (should be email/syslog)" \
            "Set space_left_action = email in /etc/audit/auditd.conf"
    fi

    # disk_full_action
    disk_full=$(grep -iE '^\s*disk_full_action\s*=' "$AUDITD_CONF" | awk -F= '{print $2}' | tr -d ' ' | head -1 || echo "")
    if [[ "$disk_full" =~ ^(halt|single|syslog)$ ]]; then
        add_finding "${SCRIPT_ID}-C4b" "auditd disk_full_action" "Med" "PASS" \
            "disk_full_action=${disk_full}" ""
    else
        add_finding "${SCRIPT_ID}-C4b" "auditd disk_full_action" "Med" "WARN" \
            "disk_full_action=${disk_full:-not_set}" \
            "Set disk_full_action = halt or syslog in auditd.conf to handle full disk"
    fi
fi

# C5 – journald persistent storage
if [[ -d /etc/systemd/journald.conf.d || -f /etc/systemd/journald.conf ]]; then
    storage=$(grep -rh 'Storage=' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/ 2>/dev/null | tail -1 | awk -F= '{print $2}' 2>/dev/null || true)
    storage="${storage:-auto}"
    if [[ "$storage" == "persistent" ]]; then
        add_finding "${SCRIPT_ID}-C5" "journald Persistent Storage" "Med" "PASS" \
            "journald Storage=persistent" ""
    else
        add_finding "${SCRIPT_ID}-C5" "journald Persistent Storage" "Med" "WARN" \
            "journald Storage=${storage} (logs may not survive reboot)" \
            "Set Storage=persistent in /etc/systemd/journald.conf"
    fi
fi

# ── Optional Fix ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "INFO: --fix: Installing and enabling auditd." >&2
    if command -v apt-get &>/dev/null; then
        apt-get install -y auditd audispd-plugins 2>/dev/null | tail -3 || true
    elif command -v dnf &>/dev/null; then
        dnf install -y audit 2>/dev/null | tail -3 || true
    elif command -v yum &>/dev/null; then
        yum install -y audit 2>/dev/null | tail -3 || true
    fi
    if command -v systemctl &>/dev/null; then
        systemctl enable --now auditd 2>/dev/null && echo "auditd enabled and started" >&2 || true
    fi
fi

# ── Output ───────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_auditd_logging" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
