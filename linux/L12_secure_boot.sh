#!/usr/bin/env bash
# =============================================================================
# L12 – Secure Boot & Kernel Integrity (Linux)
# =============================================================================
# ID       : L12
# Category : Encryption
# Severity : High
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES (UEFI systems)
# Admin    : Yes
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L12_secure_boot.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L12"
SCRIPT_NAME="Secure Boot & Kernel Integrity"
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

# C1 – Secure Boot state (via mokutil or efivar)
SECURE_BOOT="unknown"
if command -v mokutil &>/dev/null; then
    sb_state=$(mokutil --sb-state 2>/dev/null || echo "")
    if echo "$sb_state" | grep -qi "SecureBoot enabled"; then
        SECURE_BOOT="enabled"
        add_finding "${SCRIPT_ID}-C1" "Secure Boot" "High" "PASS" \
            "Secure Boot is enabled (mokutil)" ""
    elif echo "$sb_state" | grep -qi "SecureBoot disabled"; then
        SECURE_BOOT="disabled"
        add_finding "${SCRIPT_ID}-C1" "Secure Boot" "High" "FAIL" \
            "Secure Boot is DISABLED" \
            "Enable Secure Boot in UEFI/BIOS firmware settings"
    else
        add_finding "${SCRIPT_ID}-C1" "Secure Boot" "High" "WARN" \
            "Secure Boot state undetermined: ${sb_state:-no output}" \
            "Check UEFI firmware settings"
    fi
elif [[ -f /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c ]]; then
    # Read byte 4 (index 4) = 1 means enabled
    sb_val=$(od -An -N5 -tx1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c 2>/dev/null | awk 'NR==1{print $NF}' || echo "00")
    if [[ "$sb_val" == "01" ]]; then
        add_finding "${SCRIPT_ID}-C1" "Secure Boot" "High" "PASS" "Secure Boot is enabled (EFI var)" ""
    else
        add_finding "${SCRIPT_ID}-C1" "Secure Boot" "High" "FAIL" "Secure Boot is DISABLED (EFI var=${sb_val})" \
            "Enable Secure Boot in UEFI firmware"
    fi
elif [[ -d /sys/firmware/efi ]]; then
    add_finding "${SCRIPT_ID}-C1" "Secure Boot" "High" "WARN" \
        "UEFI detected but cannot determine Secure Boot state (install mokutil)" \
        "Install: apt-get install mokutil  or  yum install mokutil"
else
    add_finding "${SCRIPT_ID}-C1" "Secure Boot" "High" "WARN" \
        "UEFI not detected – may be legacy BIOS or container" \
        "Migrate to UEFI and enable Secure Boot"
fi

# C2 – Kernel lockdown mode
if [[ -f /sys/kernel/security/lockdown ]]; then
    lockdown=$(cat /sys/kernel/security/lockdown 2>/dev/null || echo "unknown")
    if echo "$lockdown" | grep -qi '\[integrity\]\|\[confidentiality\]'; then
        add_finding "${SCRIPT_ID}-C2" "Kernel Lockdown" "High" "PASS" \
            "Kernel lockdown: ${lockdown}" ""
    else
        add_finding "${SCRIPT_ID}-C2" "Kernel Lockdown" "High" "WARN" \
            "Kernel lockdown not active: ${lockdown}" \
            "Enable lockdown: kernel boot parameter lockdown=integrity or lockdown=confidentiality"
    fi
else
    add_finding "${SCRIPT_ID}-C2" "Kernel Lockdown" "High" "WARN" \
        "Kernel lockdown not available (/sys/kernel/security/lockdown absent)" \
        "Enable CONFIG_SECURITY_LOCKDOWN_LSM in kernel or use AppArmor/SELinux"
fi

# C3 – Kernel module signing
if [[ -f /proc/sys/kernel/modules_disabled ]]; then
    mod_disabled=$(cat /proc/sys/kernel/modules_disabled 2>/dev/null || echo 0)
    if [[ "$mod_disabled" -eq 1 ]]; then
        add_finding "${SCRIPT_ID}-C3" "Kernel Module Loading" "High" "PASS" \
            "kernel.modules_disabled=1 (no new modules can be loaded)" ""
    else
        add_finding "${SCRIPT_ID}-C3" "Kernel Module Loading" "High" "INFO" \
            "kernel.modules_disabled=0 (modules can be loaded dynamically)" \
            "For high-security systems, set sysctl kernel.modules_disabled=1 after all modules loaded"
    fi
fi

# C4 – GRUB password protected
GRUB_CFG=""
for f in /boot/grub/grub.cfg /boot/grub2/grub.cfg /etc/grub.d/40_custom; do
    [[ -f "$f" ]] && GRUB_CFG="$f" && break
done
if [[ -n "$GRUB_CFG" ]]; then
    if grep -qi 'password_pbkdf2\|set superusers\|password --md5' "$GRUB_CFG" 2>/dev/null; then
        add_finding "${SCRIPT_ID}-C4" "GRUB Password Protected" "High" "PASS" \
            "GRUB bootloader password appears to be set" ""
    else
        add_finding "${SCRIPT_ID}-C4" "GRUB Password Protected" "High" "WARN" \
            "No GRUB password detected in ${GRUB_CFG}" \
            "Set GRUB password: grub-mkpasswd-pbkdf2 and configure in /etc/grub.d/40_custom"
    fi
fi

# C5 – IMA (Integrity Measurement Architecture)
if [[ -d /sys/kernel/security/ima ]]; then
    add_finding "${SCRIPT_ID}-C5" "IMA Enabled" "Med" "PASS" \
        "IMA is active (/sys/kernel/security/ima present)" ""
else
    add_finding "${SCRIPT_ID}-C5" "IMA Enabled" "Med" "WARN" \
        "IMA not detected" \
        "Enable IMA by adding ima=on to kernel boot parameters (advanced configuration)"
fi

# C6 – dmesg restriction
dmesg_restrict=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null || echo "0")
if [[ "$dmesg_restrict" -eq 1 ]]; then
    add_finding "${SCRIPT_ID}-C6" "dmesg Restriction" "Low" "PASS" \
        "kernel.dmesg_restrict=1" ""
else
    add_finding "${SCRIPT_ID}-C6" "dmesg Restriction" "Low" "WARN" \
        "kernel.dmesg_restrict=0 (non-root users can read kernel messages)" \
        "Set: sysctl -w kernel.dmesg_restrict=1  and persist in /etc/sysctl.d/"
fi

# ── Optional Fix ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "INFO: --fix: Secure Boot and kernel integrity settings require UEFI/firmware configuration." >&2
    echo "       These cannot be changed from within the running OS." >&2
fi

# ── Output ───────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_secure_boot" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
