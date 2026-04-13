#!/usr/bin/env bash
# =============================================================================
# L32 – USB & Removable Media Control (Linux)
# =============================================================================
# ID       : L32
# Category : Endpoint Controls
# Severity : High
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : Yes
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L32_usb_media_control.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L32"
SCRIPT_NAME="USB & Removable Media Control"
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

# ── C1: USB storage kernel module state ──────────────────────────────────────
usb_storage_loaded=0
if lsmod 2>/dev/null | grep -q '^usb_storage'; then usb_storage_loaded=1; fi
usb_storage_blacklisted=false

for bl_file in /etc/modprobe.d/*.conf /etc/modprobe.conf; do
    [[ -f "$bl_file" ]] || continue
    if grep -qE 'blacklist\s+usb.storage|install\s+usb.storage\s+/bin/(true|false)' "$bl_file" 2>/dev/null; then
        usb_storage_blacklisted=true
        break
    fi
done

if [[ "$usb_storage_loaded" -gt 0 ]]; then
    if [[ "$usb_storage_blacklisted" == false ]]; then
        add_finding "${SCRIPT_ID}-C1" "USB Storage Module Loaded and Not Blacklisted" "High" "WARN" \
            "usb_storage module is loaded and not blacklisted – USB drives can be mounted by any user" \
            "Blacklist: echo 'blacklist usb_storage' >> /etc/modprobe.d/disable-usb-storage.conf; modprobe -r usb_storage"
    else
        add_finding "${SCRIPT_ID}-C1" "USB Storage Module" "High" "WARN" \
            "usb_storage is currently loaded despite being blacklisted (may require reboot to take effect)" \
            "Reboot to apply blacklist, or: modprobe -r usb_storage"
    fi
else
    if [[ "$usb_storage_blacklisted" == true ]]; then
        add_finding "${SCRIPT_ID}-C1" "USB Storage Module" "High" "PASS" \
            "usb_storage is blacklisted and not currently loaded" ""
    else
        add_finding "${SCRIPT_ID}-C1" "USB Storage Module" "High" "INFO" \
            "usb_storage is not currently loaded (not explicitly blacklisted – may load on device insertion)" \
            "Consider blacklisting: echo 'blacklist usb_storage' >> /etc/modprobe.d/disable-usb-storage.conf"
    fi
fi

# ── C2: Recently connected USB devices ───────────────────────────────────────
usb_history=()
# dmesg USB events from the past 24h
if command -v journalctl &>/dev/null; then
    usb_history+=($(journalctl --since "24 hours ago" -k 2>/dev/null | grep -i 'usb\|mass storage\|scsi' | grep -iv 'hub\|root hub\|keyboard\|mouse\|bluetooth\|audio\|hid' | head -20 || true))
fi
# Also check udev db
if command -v udevadm &>/dev/null; then
    recent_usb=$(udevadm info --export-db 2>/dev/null | grep -A2 'ID_BUS=usb' | grep 'ID_MODEL=' | sort -u | head -10 || true)
    [[ -n "$recent_usb" ]] && usb_history+=("${recent_usb}")
fi

if [[ "${#usb_history[@]}" -gt 0 ]]; then
    sample="${usb_history[0]}"
    add_finding "${SCRIPT_ID}-C2" "USB Mass Storage Devices Detected" "Med" "WARN" \
        "${#usb_history[@]} USB storage event(s) in recent logs. Sample: ${sample:0:200}" \
        "Review USB connection history. Consider usbguard for device allowlisting."
else
    add_finding "${SCRIPT_ID}-C2" "Recent USB Device Activity" "Med" "PASS" \
        "No recent USB mass storage events found in system logs" ""
fi

# ── C3: usbguard presence and policy ─────────────────────────────────────────
if command -v usbguard &>/dev/null; then
    ugd_running=$(systemctl is-active usbguard 2>/dev/null || echo "inactive")
    if [[ "$ugd_running" == "active" ]]; then
        add_finding "${SCRIPT_ID}-C3" "USBGuard Active" "High" "PASS" \
            "usbguard daemon is running and enforcing device policy" ""
    else
        add_finding "${SCRIPT_ID}-C3" "USBGuard Installed but Not Active" "High" "WARN" \
            "usbguard is installed but daemon is ${ugd_running}" \
            "Enable: systemctl enable --now usbguard. Configure policy in /etc/usbguard/rules.conf"
    fi
else
    add_finding "${SCRIPT_ID}-C3" "USBGuard Not Installed" "High" "WARN" \
        "usbguard is not installed. No device-level USB allowlisting is enforced." \
        "Install: apt-get install usbguard OR dnf install usbguard; systemctl enable --now usbguard"
fi

# ── C4: Automount policy ──────────────────────────────────────────────────────
automount_enabled=false

# Check udisks2/gvfs automount inhibited via udev rules
if [[ -f /etc/udev/rules.d/85-no-automount.rules ]] || grep -rq 'ENV{UDISKS_AUTO}="0"' /etc/udev/rules.d/ 2>/dev/null; then
    automount_enabled=false
else
    # Check if udisksd or gvfsd is running (desktop automount services)
    if pgrep -xE 'udisksd|gvfsd-disc' &>/dev/null; then
        automount_enabled=true
    fi
fi

if [[ "$automount_enabled" == true ]]; then
    add_finding "${SCRIPT_ID}-C4" "Removable Media Automount Enabled" "Med" "WARN" \
        "udisks2/gvfsd automount services are active without explicit disable rules" \
        "Disable automounting: create /etc/udev/rules.d/85-no-automount.rules with: ENV{UDISKS_AUTO}=\\\"0\\\""
else
    add_finding "${SCRIPT_ID}-C4" "Removable Media Automount" "Med" "PASS" \
        "No active or unrestricted automount service detected" ""
fi

# ── C5: /etc/fstab removable media entries with exec/suid ────────────────────
if [[ -f /etc/fstab ]]; then
    risky_mounts=$(grep -v '^\s*#' /etc/fstab | awk '
        $3 ~ /^(vfat|ntfs|exfat|fuseblk)$/ {
            if ($4 !~ /noexec/ || $4 !~ /nosuid/) print $0
        }' | head -10 || true)
    if [[ -n "$risky_mounts" ]]; then
        add_finding "${SCRIPT_ID}-C5" "Removable Filesystem Mounts Without noexec/nosuid" "Med" "WARN" \
            "fstab entries for removable/FAT filesystems missing noexec or nosuid: $(echo "$risky_mounts" | head -3 | tr '\n' ' | ')" \
            "Add noexec,nosuid,nodev to all removable media mount options in /etc/fstab"
    else
        add_finding "${SCRIPT_ID}-C5" "fstab Removable Media Options" "Med" "PASS" \
            "All removable media fstab entries have appropriate security mount options" ""
    fi
fi

# ── C6: World-writable removable mount points ────────────────────────────────
ww_mounts=$(find /media /mnt -maxdepth 2 -type d -perm -0002 2>/dev/null | head -10 || true)
if [[ -n "$ww_mounts" ]]; then
    add_finding "${SCRIPT_ID}-C6" "World-Writable Removable Mount Points" "Med" "WARN" \
        "World-writable dirs under /media or /mnt: $(echo "$ww_mounts" | tr '\n' ' | ')" \
        "Fix: chmod o-w <directory>"
else
    add_finding "${SCRIPT_ID}-C6" "Removable Mount Point Permissions" "Med" "PASS" \
        "No world-writable removable media mount points found" ""
fi

# ── Optional Fix ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "INFO: --fix: applying USB storage blacklist..." >&2
    if [[ "$usb_storage_blacklisted" == false ]]; then
        echo 'blacklist usb_storage' >> /etc/modprobe.d/cyberswiss-usb.conf
        echo 'install usb_storage /bin/true' >> /etc/modprobe.d/cyberswiss-usb.conf
        modprobe -r usb_storage 2>/dev/null && echo "Fixed: usb_storage unloaded and blacklisted" >&2 || \
            echo "Fixed: usb_storage blacklisted (will take effect at next modprobe)" >&2
    fi
fi

# ── Output ────────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_usb_media_control" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
