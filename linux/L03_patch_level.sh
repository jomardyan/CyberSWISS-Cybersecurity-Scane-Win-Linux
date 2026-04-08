#!/usr/bin/env bash
# =============================================================================
# L03 – Patch Level & Vulnerable Packages (Linux)
# =============================================================================
# ID       : L03
# Category : Patch Level & Vulnerable Software
# Severity : Critical
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : Yes (sudo for package manager queries)
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L03_patch_level.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L03"
SCRIPT_NAME="Patch Level & Vulnerable Packages"
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

detect_pkg_manager() {
    if command -v apt-get &>/dev/null; then echo "apt"
    elif command -v dnf &>/dev/null;   then echo "dnf"
    elif command -v yum &>/dev/null;   then echo "yum"
    elif command -v zypper &>/dev/null; then echo "zypper"
    elif command -v pacman &>/dev/null; then echo "pacman"
    else echo "unknown"
    fi
}

PKG_MGR=$(detect_pkg_manager)
add_finding "${SCRIPT_ID}-C0" "Package Manager Detected" "Info" "INFO" "PKG_MGR=${PKG_MGR}" ""

# C1 – Pending security updates
case "$PKG_MGR" in
    apt)
        # Refresh cache silently
        apt-get update -qq 2>/dev/null || true
        pending=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst' || true); pending=${pending:-0}
        security_pending=$(apt-get -s upgrade 2>/dev/null | grep -c 'security' || true); security_pending=${security_pending:-0}
        if [[ "$security_pending" -gt 0 ]]; then
            add_finding "${SCRIPT_ID}-C1" "Pending Security Updates" "Critical" "FAIL" \
                "${security_pending} security update(s) pending (${pending} total)" \
                "Apply: apt-get upgrade -y  or  unattended-upgrades"
        elif [[ "$pending" -gt 0 ]]; then
            add_finding "${SCRIPT_ID}-C1" "Pending Updates" "High" "WARN" \
                "${pending} non-security update(s) pending" \
                "Apply: apt-get upgrade -y"
        else
            add_finding "${SCRIPT_ID}-C1" "Pending Updates" "Critical" "PASS" \
                "No pending updates detected" ""
        fi
        ;;
    dnf|yum)
        pending=$($PKG_MGR check-update --security 2>/dev/null | grep -c '^\S' || true); pending=${pending:-0}
        all_pending=$($PKG_MGR check-update 2>/dev/null | grep -c '^\S' || true); all_pending=${all_pending:-0}
        if [[ "$pending" -gt 0 ]]; then
            add_finding "${SCRIPT_ID}-C1" "Pending Security Updates" "Critical" "FAIL" \
                "${pending} security update(s) pending" \
                "Apply: ${PKG_MGR} update --security -y"
        elif [[ "$all_pending" -gt 0 ]]; then
            add_finding "${SCRIPT_ID}-C1" "Pending Updates" "High" "WARN" \
                "${all_pending} non-security update(s) pending" \
                "Apply: ${PKG_MGR} update -y"
        else
            add_finding "${SCRIPT_ID}-C1" "Pending Updates" "Critical" "PASS" \
                "No pending updates detected" ""
        fi
        ;;
    zypper)
        pending=$(zypper list-updates --type security 2>/dev/null | grep -c '^|' || true)
        if [[ "$pending" -gt 0 ]]; then
            add_finding "${SCRIPT_ID}-C1" "Pending Security Patches" "Critical" "FAIL" \
                "${pending} security patch(es) pending" \
                "Apply: zypper patch --category security"
        else
            add_finding "${SCRIPT_ID}-C1" "Pending Security Patches" "Critical" "PASS" \
                "No pending security patches detected" ""
        fi
        ;;
    *)
        add_finding "${SCRIPT_ID}-C1" "Pending Updates" "Critical" "WARN" \
            "Cannot check pending updates for package manager: ${PKG_MGR}" \
            "Manually check for updates"
        ;;
esac

# C2 – Kernel version and age
KERNEL_VER=$(uname -r)
add_finding "${SCRIPT_ID}-C2" "Kernel Version" "Info" "INFO" "Running kernel: ${KERNEL_VER}" ""

# C3 – Last package update timestamp
case "$PKG_MGR" in
    apt)
        if [[ -f /var/lib/apt/lists/lock ]]; then
            last_update=$(stat -c %Y /var/lib/apt/lists/partial 2>/dev/null || stat -c %Y /var/lib/apt/lists 2>/dev/null || echo 0)
            days_since=$(( ( $(date +%s) - last_update ) / 86400 ))
            if [[ "$days_since" -le 7 ]]; then
                add_finding "${SCRIPT_ID}-C3" "Last APT Update" "Med" "PASS" \
                    "Last apt update: ${days_since} day(s) ago" ""
            else
                add_finding "${SCRIPT_ID}-C3" "Last APT Update" "Med" "WARN" \
                    "apt cache last updated ${days_since} day(s) ago" \
                    "Run: apt-get update"
            fi
        fi
        ;;
    dnf|yum)
        last_log=$(ls -t /var/log/dnf*.log /var/log/yum.log 2>/dev/null | head -1)
        if [[ -n "$last_log" ]]; then
            last_update=$(stat -c %Y "$last_log" 2>/dev/null || echo 0)
            days_since=$(( ( $(date +%s) - last_update ) / 86400 ))
            if [[ "$days_since" -le 7 ]]; then
                add_finding "${SCRIPT_ID}-C3" "Last Package Manager Activity" "Med" "PASS" \
                    "${PKG_MGR} last active: ${days_since} day(s) ago" ""
            else
                add_finding "${SCRIPT_ID}-C3" "Last Package Manager Activity" "Med" "WARN" \
                    "${PKG_MGR} last active: ${days_since} day(s) ago" \
                    "Run: ${PKG_MGR} check-update"
            fi
        fi
        ;;
esac

# C4 – Automatic security updates configured
case "$PKG_MGR" in
    apt)
        if dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii'; then
            ua_enabled=$(grep -r 'origin.*security' /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null | grep -v '^\s*//' | head -1 || true)
            if [[ -n "$ua_enabled" ]]; then
                add_finding "${SCRIPT_ID}-C4" "Automatic Security Updates" "High" "PASS" \
                    "unattended-upgrades installed and configured for security" ""
            else
                add_finding "${SCRIPT_ID}-C4" "Automatic Security Updates" "High" "WARN" \
                    "unattended-upgrades installed but security origin not confirmed" \
                    "Review /etc/apt/apt.conf.d/50unattended-upgrades"
            fi
        else
            add_finding "${SCRIPT_ID}-C4" "Automatic Security Updates" "High" "WARN" \
                "unattended-upgrades not installed" \
                "Install: apt-get install unattended-upgrades && dpkg-reconfigure unattended-upgrades"
        fi
        ;;
    dnf)
        if rpm -q dnf-automatic &>/dev/null; then
            add_finding "${SCRIPT_ID}-C4" "Automatic Security Updates" "High" "PASS" \
                "dnf-automatic is installed" ""
        else
            add_finding "${SCRIPT_ID}-C4" "Automatic Security Updates" "High" "WARN" \
                "dnf-automatic not installed" \
                "Install: dnf install dnf-automatic && systemctl enable --now dnf-automatic-install.timer"
        fi
        ;;
esac

# C5 – Reboot required
if [[ -f /var/run/reboot-required ]]; then
    add_finding "${SCRIPT_ID}-C5" "Reboot Required" "Med" "WARN" \
        "/var/run/reboot-required exists – kernel or core library update pending" \
        "Schedule a reboot to apply updates"
else
    add_finding "${SCRIPT_ID}-C5" "Reboot Required" "Med" "PASS" \
        "No reboot-required flag detected" ""
fi

# ── Optional Fix ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "WARNING: --fix will run package upgrades. Press Ctrl+C within 10 seconds to abort..." >&2
    sleep 10
    case "$PKG_MGR" in
        apt)     apt-get upgrade -y 2>&1 | tail -5 ;;
        dnf|yum) $PKG_MGR update -y 2>&1 | tail -5 ;;
        zypper)  zypper patch -y 2>&1 | tail -5 ;;
        *)       echo "INFO: --fix: Automatic upgrade not supported for package manager: ${PKG_MGR}" >&2 ;;
    esac
fi

# ── Output ───────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_patch_level" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
