#!/usr/bin/env bash
# =============================================================================
# L15 – CIS Baseline Hardening Checks (Linux)
# =============================================================================
# ID       : L15
# Category : Baseline Hardening
# Severity : High
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : Yes
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L15_cis_baseline.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L15"
SCRIPT_NAME="CIS Baseline Hardening Checks"
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

check_sysctl() {
    local id="$1" name="$2" sev="$3" param="$4" expected="$5" remediation="$6"
    local val
    val=$(sysctl -n "$param" 2>/dev/null || echo "")
    if [[ "$val" == "$expected" ]]; then
        add_finding "$id" "$name" "$sev" "PASS" "${param}=${val}" ""
    elif [[ -z "$val" ]]; then
        add_finding "$id" "$name" "$sev" "WARN" "${param}: not found (may not apply to this kernel)" "$remediation"
    else
        add_finding "$id" "$name" "$sev" "FAIL" "${param}=${val} (expected ${expected})" "$remediation"
    fi
}

# ── Sysctl Hardening ─────────────────────────────────────────────────────────
# Network
check_sysctl "${SCRIPT_ID}-C1"  "IP Forwarding Disabled"    "High"     "net.ipv4.ip_forward"                    "0" "sysctl -w net.ipv4.ip_forward=0 && echo 'net.ipv4.ip_forward=0' >> /etc/sysctl.d/99-cis.conf"
check_sysctl "${SCRIPT_ID}-C2"  "Source Routing Disabled"   "High"     "net.ipv4.conf.all.accept_source_route"  "0" "sysctl -w net.ipv4.conf.all.accept_source_route=0"
check_sysctl "${SCRIPT_ID}-C3"  "ICMP Redirects Ignored"    "Med"      "net.ipv4.conf.all.accept_redirects"     "0" "sysctl -w net.ipv4.conf.all.accept_redirects=0"
check_sysctl "${SCRIPT_ID}-C4"  "Secure ICMP Redirects"     "Med"      "net.ipv4.conf.all.secure_redirects"     "0" "sysctl -w net.ipv4.conf.all.secure_redirects=0"
check_sysctl "${SCRIPT_ID}-C5"  "Log Suspicious Packets"    "Low"      "net.ipv4.conf.all.log_martians"         "1" "sysctl -w net.ipv4.conf.all.log_martians=1"
check_sysctl "${SCRIPT_ID}-C6"  "TCP SYN Cookies"           "Med"      "net.ipv4.tcp_syncookies"                "1" "sysctl -w net.ipv4.tcp_syncookies=1"
check_sysctl "${SCRIPT_ID}-C7"  "Reverse Path Filtering"    "High"     "net.ipv4.conf.all.rp_filter"            "1" "sysctl -w net.ipv4.conf.all.rp_filter=1"
check_sysctl "${SCRIPT_ID}-C8"  "IPv6 Router Advertisements" "Med"     "net.ipv6.conf.all.accept_ra"            "0" "sysctl -w net.ipv6.conf.all.accept_ra=0 (if IPv6 not needed)"
# Kernel
check_sysctl "${SCRIPT_ID}-C9"  "ASLR Enabled"              "High"     "kernel.randomize_va_space"              "2" "sysctl -w kernel.randomize_va_space=2"
check_sysctl "${SCRIPT_ID}-C10" "Ptrace Scope"              "Med"      "kernel.yama.ptrace_scope"               "1" "sysctl -w kernel.yama.ptrace_scope=1"
check_sysctl "${SCRIPT_ID}-C11" "Dmesg Restriction"         "Low"      "kernel.dmesg_restrict"                  "1" "sysctl -w kernel.dmesg_restrict=1"
check_sysctl "${SCRIPT_ID}-C12" "Kernel Pointer Restriction" "Med"     "kernel.kptr_restrict"                   "2" "sysctl -w kernel.kptr_restrict=2"
check_sysctl "${SCRIPT_ID}-C13" "Core Dump Restriction"     "Low"      "fs.suid_dumpable"                       "0" "sysctl -w fs.suid_dumpable=0"

# ── File System Hardening ────────────────────────────────────────────────────
# C14 – /tmp noexec mount
tmp_noexec=$(mount | grep ' /tmp ' | grep -o 'noexec' || echo "")
if [[ -n "$tmp_noexec" ]]; then
    add_finding "${SCRIPT_ID}-C14" "/tmp noexec" "High" "PASS" "/tmp is mounted with noexec" ""
else
    add_finding "${SCRIPT_ID}-C14" "/tmp noexec" "High" "WARN" "/tmp is NOT mounted with noexec" \
        "Add noexec to /tmp mount options in /etc/fstab"
fi

# C15 – /tmp nosuid mount
tmp_nosuid=$(mount | grep ' /tmp ' | grep -o 'nosuid' || echo "")
if [[ -n "$tmp_nosuid" ]]; then
    add_finding "${SCRIPT_ID}-C15" "/tmp nosuid" "Med" "PASS" "/tmp is mounted with nosuid" ""
else
    add_finding "${SCRIPT_ID}-C15" "/tmp nosuid" "Med" "WARN" "/tmp is NOT mounted with nosuid" \
        "Add nosuid to /tmp mount options in /etc/fstab"
fi

# C16 – umask for system accounts
sys_umask=$(grep -E '^\s*umask\s+' /etc/profile /etc/bash.bashrc /etc/bashrc 2>/dev/null | head -1 | awk '{print $2}' || echo "")
if [[ "$sys_umask" =~ ^0?27$|^077$|^027$ ]]; then
    add_finding "${SCRIPT_ID}-C16" "Default umask" "Med" "PASS" "System umask=${sys_umask}" ""
else
    add_finding "${SCRIPT_ID}-C16" "Default umask" "Med" "WARN" \
        "System umask=${sys_umask:-not_explicitly_set} (022 is too permissive)" \
        "Set umask 027 in /etc/profile or /etc/bash.bashrc"
fi

# C17 – /etc/motd / /etc/issue warning banners
if [[ -s /etc/motd ]] || [[ -s /etc/issue ]]; then
    add_finding "${SCRIPT_ID}-C17" "Login Warning Banner" "Low" "PASS" \
        "/etc/motd or /etc/issue is configured" ""
else
    add_finding "${SCRIPT_ID}-C17" "Login Warning Banner" "Low" "WARN" \
        "/etc/motd and /etc/issue are empty (no legal warning banner)" \
        "Add authorized-use warning to /etc/motd and /etc/issue"
fi

# ── Optional Fix ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "WARNING: --fix will apply sysctl hardening settings." >&2
    echo "Press Ctrl+C within 10 seconds to abort..." >&2
    sleep 10
    SYSCTL_CONF="/etc/sysctl.d/99-cyberswiss.conf"
    {
        echo "# CyberSWISS CIS baseline – applied $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        echo "net.ipv4.ip_forward=0"
        echo "net.ipv4.conf.all.accept_source_route=0"
        echo "net.ipv4.conf.all.accept_redirects=0"
        echo "net.ipv4.conf.all.secure_redirects=0"
        echo "net.ipv4.conf.all.log_martians=1"
        echo "net.ipv4.tcp_syncookies=1"
        echo "net.ipv4.conf.all.rp_filter=1"
        echo "kernel.randomize_va_space=2"
        echo "kernel.yama.ptrace_scope=1"
        echo "kernel.dmesg_restrict=1"
        echo "kernel.kptr_restrict=2"
        echo "fs.suid_dumpable=0"
    } > "$SYSCTL_CONF"
    sysctl -p "$SYSCTL_CONF" 2>/dev/null && echo "Sysctl hardening applied: ${SYSCTL_CONF}" >&2 || true
fi

# ── Output ───────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_cis_baseline" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
