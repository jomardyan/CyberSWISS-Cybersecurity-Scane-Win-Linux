#!/usr/bin/env bash
# =============================================================================
# L04 – Running Services Audit (Linux)
# =============================================================================
# ID       : L04
# Category : Services/Daemons & Insecure Defaults
# Severity : High
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES (systemd)
# Admin    : Yes
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L04_services_audit.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L04"
SCRIPT_NAME="Running Services Audit"
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

# Known insecure or legacy services to flag
declare -A INSECURE_SERVICES=(
    ["telnet"]="Telnet – plaintext remote access"
    ["rsh"]="rsh – insecure remote shell"
    ["rlogin"]="rlogin – insecure remote login"
    ["rexec"]="rexec – insecure remote exec"
    ["tftp"]="TFTP – no authentication"
    ["ftp"]="FTP – plaintext file transfer"
    ["vsftpd"]="vsftpd FTP server – verify if required"
    ["snmpd"]="SNMP daemon – check version (v1/v2 weak auth)"
    ["nis"]="NIS – legacy insecure directory service"
    ["rpcbind"]="RPCbind – legacy RPC port mapper"
    ["finger"]="Finger – exposes user information"
    ["talk"]="Talk – insecure chat service"
    ["ntalk"]="NTalk – insecure chat service"
    ["xinetd"]="xinetd – legacy super-server"
    ["cups"]="CUPS – printing service (should not run on servers)"
    ["avahi-daemon"]="Avahi/mDNS – multicast discovery (not for servers)"
)

# C1 – Count running systemd services
if command -v systemctl &>/dev/null; then
    running_count=$(systemctl list-units --type=service --state=running --no-legend 2>/dev/null | wc -l || true)
    add_finding "${SCRIPT_ID}-C1" "Running Services Count" "Info" "INFO" \
        "${running_count} systemd services currently running" ""

    # C2 – Check for insecure services
    insecure_found=false
    for svc in "${!INSECURE_SERVICES[@]}"; do
        desc="${INSECURE_SERVICES[$svc]}"
        # Check multiple possible service name patterns
        for pattern in "${svc}" "${svc}.service" "${svc}d" "${svc}d.service"; do
            if systemctl is-active --quiet "$pattern" 2>/dev/null; then
                add_finding "${SCRIPT_ID}-C2-${svc}" "Insecure Service Active: ${svc}" "High" "WARN" \
                    "Service '${pattern}' is running: ${desc}" \
                    "Stop and disable: systemctl stop ${pattern} && systemctl disable ${pattern}"
                insecure_found=true
                break
            fi
        done
    done
    if [[ "$insecure_found" == false ]]; then
        add_finding "${SCRIPT_ID}-C2" "Insecure Services" "High" "PASS" \
            "No known insecure legacy services detected as running" ""
    fi

    # C3 – Services running as root that should not (check common ones)
    # Only check systemd service files for User= directive
    non_root_services=("nginx" "apache2" "httpd" "mysql" "postgresql" "redis")
    for svc in "${non_root_services[@]}"; do
        if systemctl is-active --quiet "${svc}" 2>/dev/null || systemctl is-active --quiet "${svc}.service" 2>/dev/null; then
            # Check the running process UID
            svc_pid=$(systemctl show "${svc}" -p MainPID 2>/dev/null | awk -F= '{print $2}')
            if [[ -n "$svc_pid" && "$svc_pid" -gt 0 ]]; then
                svc_uid=$(stat -c %u /proc/"$svc_pid" 2>/dev/null || echo "unknown")
                if [[ "$svc_uid" == "0" ]]; then
                    add_finding "${SCRIPT_ID}-C3-${svc}" "Service Running as Root: ${svc}" "High" "WARN" \
                        "Service '${svc}' runs as UID 0 (root)" \
                        "Configure a dedicated non-root service account for '${svc}'"
                fi
            fi
        fi
    done

    # C4 – Failed services (may indicate tampering or misconfiguration)
    failed_services=$(systemctl list-units --type=service --state=failed --no-legend 2>/dev/null | awk '{print $1}' | tr '\n' ',' | sed 's/,$//' || true)
    if [[ -n "$failed_services" ]]; then
        add_finding "${SCRIPT_ID}-C4" "Failed Services" "Med" "WARN" \
            "Failed services: ${failed_services}" \
            "Investigate: systemctl status <service>; check logs: journalctl -u <service>"
    else
        add_finding "${SCRIPT_ID}-C4" "Failed Services" "Med" "PASS" \
            "No failed systemd services" ""
    fi
else
    # SysV fallback
    if command -v service &>/dev/null; then
        add_finding "${SCRIPT_ID}-C1" "Service Manager" "Info" "WARN" \
            "systemctl not found – using SysV service check" ""
        for svc in "${!INSECURE_SERVICES[@]}"; do
            if service "$svc" status &>/dev/null 2>&1; then
                add_finding "${SCRIPT_ID}-C2-${svc}" "Insecure Service Active: ${svc}" "High" "WARN" \
                    "SysV service '${svc}' appears running" \
                    "Disable: chkconfig ${svc} off (RHEL) or update-rc.d ${svc} disable (Debian)"
            fi
        done
    fi
fi

# ── Optional Fix ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "INFO: --fix: Stopping and disabling insecure legacy services." >&2
    for svc in telnet rsh rlogin rexec tftp ftp vsftpd nis rpcbind finger talk ntalk xinetd; do
        for pattern in "${svc}" "${svc}.service" "${svc}d" "${svc}d.service"; do
            if systemctl is-active --quiet "$pattern" 2>/dev/null; then
                systemctl stop "$pattern" 2>/dev/null && systemctl disable "$pattern" 2>/dev/null && \
                    echo "Stopped and disabled: ${pattern}" >&2 || true
                break
            fi
        done
    done
fi

# ── Output ───────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_services_audit" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
