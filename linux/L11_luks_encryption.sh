#!/usr/bin/env bash
# =============================================================================
# L11 – LUKS Encryption Check (Linux)
# =============================================================================
# ID       : L11
# Category : Encryption
# Severity : High
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : Yes
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L11_luks_encryption.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L11"
SCRIPT_NAME="LUKS Encryption Check"
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

# C1 – cryptsetup available
if ! command -v cryptsetup &>/dev/null; then
    add_finding "${SCRIPT_ID}-C0" "cryptsetup Available" "High" "WARN" \
        "cryptsetup not found – cannot verify LUKS encryption" \
        "Install: apt-get install cryptsetup (Debian) or yum install cryptsetup (RHEL)"
else
    add_finding "${SCRIPT_ID}-C0" "cryptsetup Available" "High" "PASS" \
        "cryptsetup is installed" ""
fi

# C2 – Enumerate block devices and check for LUKS
LUKS_DEVS=()
NON_LUKS_DEVS=()

if command -v lsblk &>/dev/null; then
    # Get all non-ROM, non-loop block devices
    while IFS= read -r dev; do
        [[ -z "$dev" ]] && continue
        dev_path="/dev/${dev}"
        [[ ! -b "$dev_path" ]] && continue
        # Skip small devices (< 1GB) – likely boot partitions etc.
        size_bytes=$(lsblk -b -dn -o SIZE "$dev_path" 2>/dev/null || echo 0)
        [[ "$size_bytes" -lt 1073741824 ]] && continue

        if command -v cryptsetup &>/dev/null; then
            luks_check=$(cryptsetup isLuks "$dev_path" 2>/dev/null && echo "yes" || echo "no")
        else
            luks_check="unknown"
        fi

        if [[ "$luks_check" == "yes" ]]; then
            LUKS_DEVS+=("$dev_path")
            # Get LUKS metadata
            luks_info=$(cryptsetup luksDump "$dev_path" 2>/dev/null | \
                grep -E 'Version|Cipher|Hash spec|Key Slot 0' | \
                head -5 | tr '\n' ';' || echo "info unavailable")
            add_finding "${SCRIPT_ID}-C2-${dev}" "LUKS Encrypted: ${dev_path}" "High" "PASS" \
                "${dev_path}: LUKS encrypted | ${luks_info}" ""
        else
            fstype=$(lsblk -dn -o FSTYPE "$dev_path" 2>/dev/null | tr -d ' ')
            mountpoint=$(lsblk -dn -o MOUNTPOINT "$dev_path" 2>/dev/null | tr -d ' ')
            # Only flag if it's a data partition (has filesystem and mount)
            if [[ -n "$fstype" && -n "$mountpoint" && "$mountpoint" != "[SWAP]" ]]; then
                NON_LUKS_DEVS+=("$dev_path")
                add_finding "${SCRIPT_ID}-C2-${dev}-noenc" "Not Encrypted: ${dev_path}" "High" "FAIL" \
                    "${dev_path}: ${fstype} mounted at ${mountpoint} – NOT LUKS encrypted" \
                    "Enable LUKS encryption on this volume (requires data migration)"
            fi
        fi
    done < <(lsblk -dn -o NAME 2>/dev/null | grep -v '^loop\|^sr')
fi

if [[ "${#LUKS_DEVS[@]}" -eq 0 && "${#NON_LUKS_DEVS[@]}" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C2" "LUKS Encryption" "High" "WARN" \
        "No evaluatable block devices found (may be a VM or container)" ""
fi

# C3 – Check dm-crypt/LUKS mapped devices (active)
if command -v dmsetup &>/dev/null; then
    luks_maps=$(dmsetup ls --target crypt 2>/dev/null | awk '{print $1}' | tr '\n' ',' | sed 's/,$//' || echo "")
    if [[ -n "$luks_maps" ]]; then
        add_finding "${SCRIPT_ID}-C3" "Active Encrypted Volumes" "High" "PASS" \
            "dm-crypt mapped devices: ${luks_maps}" ""
    else
        add_finding "${SCRIPT_ID}-C3" "Active Encrypted Volumes" "High" "INFO" \
            "No dm-crypt mapped devices found" ""
    fi
fi

# C4 – /etc/crypttab present
if [[ -f /etc/crypttab ]]; then
    ct_entries=$(awk '!/^\s*#/ && /\S/' /etc/crypttab 2>/dev/null | wc -l | tr -d ' ')
    add_finding "${SCRIPT_ID}-C4" "/etc/crypttab Present" "Med" "PASS" \
        "/etc/crypttab has ${ct_entries} entry/entries" ""
else
    add_finding "${SCRIPT_ID}-C4" "/etc/crypttab Present" "Med" "INFO" \
        "/etc/crypttab not found (may be pre-configured or not required)" ""
fi

# C5 – Swap encryption
swap_devs=$(swapon --show=NAME 2>/dev/null | tail -n +2 || cat /proc/swaps 2>/dev/null | tail -n +2 | awk '{print $1}' || echo "")
for swap in $swap_devs; do
    [[ -z "$swap" ]] && continue
    # Check if swap device is encrypted
    if command -v cryptsetup &>/dev/null; then
        # The mapper name typically contains 'swap' for encrypted swap
        is_crypt=$(dmsetup info "$swap" 2>/dev/null | grep -i 'crypt\|luks' || echo "")
        if [[ -n "$is_crypt" ]] || echo "$swap" | grep -q 'dm-\|crypt'; then
            add_finding "${SCRIPT_ID}-C5" "Swap Encryption" "Med" "PASS" \
                "Swap device ${swap} appears to be encrypted" ""
        else
            add_finding "${SCRIPT_ID}-C5-unenc" "Swap Not Encrypted: ${swap}" "Med" "WARN" \
                "Swap device ${swap} may not be encrypted" \
                "Configure encrypted swap in /etc/crypttab"
        fi
    fi
done

# ── Optional Fix ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "INFO: --fix: Disk encryption cannot be applied automatically to existing systems." >&2
    echo "       Enabling LUKS requires backup, data migration, and manual steps." >&2
fi

# ── Output ───────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_luks_encryption" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
