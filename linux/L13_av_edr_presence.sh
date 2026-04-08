#!/usr/bin/env bash
# =============================================================================
# L13 – AV / EDR Presence Signals (Linux)
# =============================================================================
# ID       : L13
# Category : Malware Protections / EDR
# Severity : Critical
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : No (best results with sudo)
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : ./L13_av_edr_presence.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L13"
SCRIPT_NAME="AV & EDR Presence Signals"
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

DETECTED_AV=()

# ── ClamAV ──────────────────────────────────────────────────────────────────
if command -v clamscan &>/dev/null || command -v clamd &>/dev/null; then
    DETECTED_AV+=("ClamAV")
    # Check signature age
    if command -v freshclam &>/dev/null; then
        sig_path=$(find /var/lib/clamav /usr/share/clamav -name '*.cvd' -o -name '*.cld' 2>/dev/null | head -1 || echo "")
        if [[ -n "$sig_path" ]]; then
            sig_age_days=$(( ( $(date +%s) - $(stat -c %Y "$sig_path") ) / 86400 ))
            if [[ "$sig_age_days" -le 1 ]]; then
                add_finding "${SCRIPT_ID}-C1" "ClamAV Signatures" "High" "PASS" \
                    "ClamAV signatures updated ${sig_age_days} day(s) ago" ""
            elif [[ "$sig_age_days" -le 3 ]]; then
                add_finding "${SCRIPT_ID}-C1" "ClamAV Signatures" "High" "WARN" \
                    "ClamAV signatures are ${sig_age_days} days old" \
                    "Update: freshclam"
            else
                add_finding "${SCRIPT_ID}-C1" "ClamAV Signatures" "High" "FAIL" \
                    "ClamAV signatures are ${sig_age_days} days old (stale)" \
                    "Update immediately: freshclam"
            fi
        fi
    fi
    # Check clamd service
    if systemctl is-active --quiet clamav-daemon 2>/dev/null || \
       systemctl is-active --quiet clamd 2>/dev/null || \
       systemctl is-active --quiet clamd@scan 2>/dev/null; then
        add_finding "${SCRIPT_ID}-C1b" "ClamAV Daemon" "High" "PASS" "clamd service is running" ""
    else
        add_finding "${SCRIPT_ID}-C1b" "ClamAV Daemon" "High" "WARN" \
            "ClamAV installed but daemon not running" \
            "Start: systemctl start clamav-daemon"
    fi
fi

# ── Known EDR/AV agents – process and service signal detection ───────────────
declare -A EDR_SIGNALS=(
    ["SentinelAgent"]="SentinelOne EDR"
    ["sentineld"]="SentinelOne EDR"
    ["ds_agent"]="Trend Micro Deep Security"
    ["dsa"]="Trend Micro Deep Security"
    ["cbdaemon"]="Carbon Black"
    ["cbsensor"]="Carbon Black"
    ["falcon-sensor"]="CrowdStrike Falcon"
    ["falconctl"]="CrowdStrike Falcon"
    ["elastic-endpoint"]="Elastic Security"
    ["sav"]="Sophos"
    ["savd"]="Sophos AV"
    ["bdagentd"]="Bitdefender"
    ["xagt"]="FireEye/Trellix HX"
    ["cis"]="Cisco AMP"
    ["klnagent"]="Kaspersky"
    ["drweb"]="Dr.Web"
    ["mcafeetp"]="McAfee/Trellix"
    ["isecespd"]="McAfee Endpoint"
    ["eset_daemon"]="ESET"
)

for proc in "${!EDR_SIGNALS[@]}"; do
    product="${EDR_SIGNALS[$proc]}"
    if pgrep -x "$proc" &>/dev/null 2>&1 || systemctl is-active --quiet "$proc" 2>/dev/null; then
        DETECTED_AV+=("$product")
    fi
done

# ── Summary ──────────────────────────────────────────────────────────────────
# Deduplicate
unique_av=($(echo "${DETECTED_AV[@]:-}" | tr ' ' '\n' | sort -u | tr '\n' ' '))

if [[ "${#unique_av[@]}" -gt 0 ]]; then
    add_finding "${SCRIPT_ID}-C2" "EDR/AV Agent Detected" "Critical" "PASS" \
        "Detected: ${unique_av[*]}" ""
else
    add_finding "${SCRIPT_ID}-C2" "EDR/AV Agent Detected" "Critical" "FAIL" \
        "No known AV/EDR agent detected" \
        "Install and configure an AV/EDR solution (ClamAV minimum, enterprise EDR preferred)"
fi

# C3 – AppArmor / SELinux (MAC enforcement)
SELINUX_MODE=""
APPARMOR_STATUS=""

if command -v getenforce &>/dev/null; then
    SELINUX_MODE=$(getenforce 2>/dev/null || echo "unknown")
fi
if command -v aa-status &>/dev/null; then
    APPARMOR_STATUS=$(aa-status --enabled 2>/dev/null && echo "enabled" || echo "disabled")
fi

if [[ "$SELINUX_MODE" == "Enforcing" ]]; then
    add_finding "${SCRIPT_ID}-C3" "SELinux Status" "High" "PASS" \
        "SELinux is Enforcing" ""
elif [[ "$SELINUX_MODE" == "Permissive" ]]; then
    add_finding "${SCRIPT_ID}-C3" "SELinux Status" "High" "WARN" \
        "SELinux is Permissive (not enforcing)" \
        "Set enforcing: setenforce 1 and update /etc/selinux/config SELINUX=enforcing"
elif [[ "$APPARMOR_STATUS" == "enabled" ]]; then
    add_finding "${SCRIPT_ID}-C3" "AppArmor Status" "High" "PASS" \
        "AppArmor is enabled and active" ""
else
    add_finding "${SCRIPT_ID}-C3" "MAC (SELinux/AppArmor)" "High" "WARN" \
        "Neither SELinux nor AppArmor detected as enforcing" \
        "Enable AppArmor (Debian/Ubuntu: apt-get install apparmor) or SELinux (RHEL)"
fi

# C4 – File integrity monitoring (AIDE/Tripwire/Samhain)
FIM_DETECTED=false
for tool in aide tripwire samhain fcheck; do
    if command -v "$tool" &>/dev/null; then
        FIM_DETECTED=true
        add_finding "${SCRIPT_ID}-C4" "File Integrity Monitor: ${tool}" "Med" "PASS" \
            "${tool} is installed" ""
        break
    fi
done
if [[ "$FIM_DETECTED" == false ]]; then
    add_finding "${SCRIPT_ID}-C4" "File Integrity Monitor" "Med" "WARN" \
        "No file integrity monitor (AIDE/Tripwire/Samhain) detected" \
        "Install AIDE: apt-get install aide (Debian) or yum install aide (RHEL); aideinit"
fi

# ── Optional Fix ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "INFO: --fix: Installing ClamAV as a basic AV solution." >&2
    if command -v apt-get &>/dev/null; then
        apt-get install -y clamav clamav-daemon 2>/dev/null | tail -3 || true
        systemctl enable --now clamav-daemon 2>/dev/null || true
    elif command -v dnf &>/dev/null; then
        dnf install -y clamav clamd 2>/dev/null | tail -3 || true
        systemctl enable --now clamd@scan 2>/dev/null || true
    elif command -v yum &>/dev/null; then
        yum install -y clamav clamd 2>/dev/null | tail -3 || true
    fi
    echo "ClamAV install attempted. Consider deploying a commercial EDR for production." >&2
fi

# ── Output ───────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_av_edr_presence" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
