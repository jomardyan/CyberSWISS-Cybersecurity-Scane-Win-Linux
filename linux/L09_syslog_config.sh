#!/usr/bin/env bash
# =============================================================================
# L09 – Syslog / rsyslog / syslog-ng Configuration (Linux)
# =============================================================================
# ID       : L09
# Category : Logging & Auditing
# Severity : Med
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : Yes
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L09_syslog_config.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L09"
SCRIPT_NAME="Syslog Configuration"
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

# C1 – Detect which syslog daemon is installed/running
SYSLOG_DAEMON=""
if systemctl is-active --quiet rsyslog 2>/dev/null; then
    SYSLOG_DAEMON="rsyslog"
elif systemctl is-active --quiet syslog-ng 2>/dev/null; then
    SYSLOG_DAEMON="syslog-ng"
elif systemctl is-active --quiet syslogd 2>/dev/null; then
    SYSLOG_DAEMON="syslogd"
elif systemctl is-active --quiet systemd-journald 2>/dev/null; then
    SYSLOG_DAEMON="systemd-journald"
fi

if [[ -n "$SYSLOG_DAEMON" ]]; then
    add_finding "${SCRIPT_ID}-C1" "Syslog Daemon Running" "High" "PASS" \
        "Syslog daemon detected: ${SYSLOG_DAEMON}" ""
else
    add_finding "${SCRIPT_ID}-C1" "Syslog Daemon Running" "High" "FAIL" \
        "No syslog daemon detected as running" \
        "Install rsyslog: apt-get install rsyslog (Debian) or yum install rsyslog (RHEL)"
fi

# C2 – Remote log forwarding configured
REMOTE_FWD=false
for conf in /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog-ng/syslog-ng.conf; do
    [[ -f "$conf" ]] || continue
    if grep -qE '^\s*[*@]?\*[.@]?[*!]?\s+@{1,2}[0-9a-zA-Z]|\bdestination\b.*tcp\|udp' "$conf" 2>/dev/null; then
        REMOTE_FWD=true
        fwd_target=$(grep -E '@@|@[^@]' "$conf" 2>/dev/null | grep -v '#' | head -1 || echo "configured")
        add_finding "${SCRIPT_ID}-C2" "Remote Log Forwarding" "Med" "PASS" \
            "Remote syslog forwarding configured (${fwd_target:-see config})" ""
        break
    fi
done
if [[ "$REMOTE_FWD" == false ]]; then
    add_finding "${SCRIPT_ID}-C2" "Remote Log Forwarding" "Med" "WARN" \
        "No remote syslog forwarding detected" \
        "Configure remote log forwarding to a SIEM or central log server"
fi

# C3 – Auth log exists and is non-empty
AUTH_LOG=""
for f in /var/log/auth.log /var/log/secure; do
    [[ -f "$f" ]] && AUTH_LOG="$f" && break
done
if [[ -n "$AUTH_LOG" ]]; then
    log_lines=$(wc -l < "$AUTH_LOG" 2>/dev/null || echo 0)
    if [[ "$log_lines" -gt 0 ]]; then
        add_finding "${SCRIPT_ID}-C3" "Auth Log Present" "High" "PASS" \
            "${AUTH_LOG} has ${log_lines} lines" ""
    else
        add_finding "${SCRIPT_ID}-C3" "Auth Log Present" "High" "WARN" \
            "${AUTH_LOG} is empty" \
            "Investigate why auth logging is empty"
    fi
else
    add_finding "${SCRIPT_ID}-C3" "Auth Log Present" "High" "FAIL" \
        "Neither /var/log/auth.log nor /var/log/secure found" \
        "Ensure auth logging is configured in syslog daemon"
fi

# C4 – /var/log permissions (should not be world-readable or writable)
if [[ -d /var/log ]]; then
    world_writable_logs=$(find /var/log -maxdepth 1 -perm -o+w -type f 2>/dev/null | tr '\n' ',' | sed 's/,$//' || true)
    if [[ -n "$world_writable_logs" ]]; then
        add_finding "${SCRIPT_ID}-C4" "World-Writable Log Files" "High" "FAIL" \
            "World-writable log files: ${world_writable_logs}" \
            "Fix permissions: chmod o-w <logfile>"
    else
        add_finding "${SCRIPT_ID}-C4" "World-Writable Log Files" "High" "PASS" \
            "No world-writable log files in /var/log" ""
    fi
fi

# C5 – logrotate configured
if command -v logrotate &>/dev/null && [[ -d /etc/logrotate.d || -f /etc/logrotate.conf ]]; then
    log_count=$(ls /etc/logrotate.d/ 2>/dev/null | wc -l || true)
    add_finding "${SCRIPT_ID}-C5" "Log Rotation Configured" "Med" "PASS" \
        "logrotate installed with ${log_count} rotation config(s)" ""
else
    add_finding "${SCRIPT_ID}-C5" "Log Rotation Configured" "Med" "WARN" \
        "logrotate not found or not configured" \
        "Install: apt-get install logrotate  and configure /etc/logrotate.d/"
fi

# C6 – systemd journal rate limiting
if [[ -f /etc/systemd/journald.conf ]]; then
    rate_limit=$(grep -iE '^\s*RateLimitIntervalSec\|RateLimitBurst' /etc/systemd/journald.conf 2>/dev/null || echo "")
    if [[ -n "$rate_limit" ]]; then
        add_finding "${SCRIPT_ID}-C6" "Journal Rate Limiting" "Low" "PASS" \
            "Rate limiting configured: ${rate_limit}" ""
    else
        add_finding "${SCRIPT_ID}-C6" "Journal Rate Limiting" "Low" "INFO" \
            "Journal rate limiting not explicitly configured (defaults apply)" ""
    fi
fi

# ── Optional Fix ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "INFO: --fix: Ensuring a syslog daemon is installed and enabled." >&2
    if command -v apt-get &>/dev/null && ! command -v rsyslogd &>/dev/null; then
        apt-get install -y rsyslog 2>/dev/null | tail -3 || true
    elif command -v dnf &>/dev/null && ! command -v rsyslogd &>/dev/null; then
        dnf install -y rsyslog 2>/dev/null | tail -3 || true
    fi
    for svc in rsyslog syslog-ng syslogd; do
        if command -v systemctl &>/dev/null && systemctl list-unit-files "${svc}.service" &>/dev/null; then
            systemctl enable --now "${svc}" 2>/dev/null && { echo "${svc} enabled" >&2; break; } || true
        fi
    done
fi

# ── Output ───────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_syslog_config" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
