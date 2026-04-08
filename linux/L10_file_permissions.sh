#!/usr/bin/env bash
# =============================================================================
# L10 – File Permissions: SUID/SGID/World-Writable (Linux)
# =============================================================================
# ID       : L10
# Category : File/Registry Permissions & Hardening
# Severity : High
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : Yes
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L10_file_permissions.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L10"
SCRIPT_NAME="File Permissions: SUID/SGID/World-Writable"
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

# C1 – SUID binaries (exclude expected ones)
EXPECTED_SUID=(
    "/usr/bin/sudo" "/usr/bin/passwd" "/usr/bin/su" "/usr/bin/newgrp"
    "/usr/bin/gpasswd" "/usr/bin/chsh" "/usr/bin/chfn" "/bin/ping"
    "/usr/bin/ping" "/usr/sbin/pam_timestamp_check" "/usr/bin/pkexec"
    "/usr/libexec/polkit-agent-helper-1" "/sbin/mount.nfs"
    "/usr/bin/mount" "/usr/bin/umount"
)

suid_files=$(find / -xdev -perm -4000 -type f 2>/dev/null | sort || true)
unexpected_suid=()
while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    found=false
    for expected in "${EXPECTED_SUID[@]}"; do
        [[ "$file" == "$expected" ]] && found=true && break
    done
    if [[ "$found" == false ]]; then
        unexpected_suid+=("$file")
    fi
done <<< "$suid_files"

suid_total=$(echo "$suid_files" | grep -c '/' || true)

if [[ "${#unexpected_suid[@]}" -gt 0 ]]; then
    add_finding "${SCRIPT_ID}-C1" "Unexpected SUID Binaries" "High" "WARN" \
        "${#unexpected_suid[@]} unexpected SUID files: ${unexpected_suid[*]:0:10}" \
        "Review each: for f in <files>; do ls -la \$f; done – remove SUID if not needed: chmod u-s <file>"
else
    add_finding "${SCRIPT_ID}-C1" "SUID Binaries" "High" "PASS" \
        "${suid_total} SUID files found – all match expected list" ""
fi

# C2 – SGID binaries (flag unusual ones)
sgid_files=$(find / -xdev -perm -2000 -type f 2>/dev/null | sort || true)
sgid_count=$(echo "$sgid_files" | grep -c '/' || true)
if [[ "$sgid_count" -gt 20 ]]; then
    add_finding "${SCRIPT_ID}-C2" "SGID Binaries Count" "Med" "WARN" \
        "${sgid_count} SGID files found (> 20 may warrant review)" \
        "Review: find / -xdev -perm -2000 -type f – remove SGID if not needed: chmod g-s <file>"
else
    add_finding "${SCRIPT_ID}-C2" "SGID Binaries Count" "Med" "PASS" \
        "${sgid_count} SGID files found (within expected range)" ""
fi

# C3 – World-writable files outside /tmp and /var/tmp
ww_files=$(find / -xdev -perm -0002 -type f \
    ! -path '/tmp/*' ! -path '/var/tmp/*' ! -path '/proc/*' ! -path '/sys/*' \
    2>/dev/null | head -20 || true)
ww_count=$(echo "$ww_files" | grep -c '/' || true)
if [[ "$ww_count" -gt 0 ]]; then
    add_finding "${SCRIPT_ID}-C3" "World-Writable Files" "High" "FAIL" \
        "${ww_count} world-writable files (sample): $(echo "$ww_files" | tr '\n' ',')" \
        "Remove world-write: chmod o-w <file>"
else
    add_finding "${SCRIPT_ID}-C3" "World-Writable Files" "High" "PASS" \
        "No unexpected world-writable files detected" ""
fi

# C4 – World-writable directories without sticky bit (outside /tmp)
ww_dirs=$(find / -xdev -perm -0002 -type d ! -perm -1000 \
    ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' \
    2>/dev/null | head -20 || true)
ww_dir_count=$(echo "$ww_dirs" | grep -c '/' || true)
if [[ "$ww_dir_count" -gt 0 ]]; then
    add_finding "${SCRIPT_ID}-C4" "World-Writable Dirs (no sticky)" "High" "FAIL" \
        "${ww_dir_count} world-writable dirs without sticky bit: $(echo "$ww_dirs" | tr '\n' ',')" \
        "Add sticky bit: chmod +t <directory>"
else
    add_finding "${SCRIPT_ID}-C4" "World-Writable Dirs (no sticky)" "High" "PASS" \
        "No world-writable directories without sticky bit" ""
fi

# C5 – Unowned files
unowned=$(find / -xdev \( -nouser -o -nogroup \) -type f 2>/dev/null | head -10 || true)
unowned_count=$(echo "$unowned" | grep -c '/' || true)
if [[ "$unowned_count" -gt 0 ]]; then
    add_finding "${SCRIPT_ID}-C5" "Unowned Files" "Med" "WARN" \
        "${unowned_count} files with no owner/group: $(echo "$unowned" | tr '\n' ',')" \
        "Assign ownership: chown root:root <file> or delete if unnecessary"
else
    add_finding "${SCRIPT_ID}-C5" "Unowned Files" "Med" "PASS" \
        "No unowned files detected" ""
fi

# C6 – /etc/passwd and /etc/shadow permissions
for f_path in /etc/passwd /etc/group; do
    perm=$(stat -c "%a" "$f_path" 2>/dev/null || echo "unknown")
    if [[ "$perm" =~ ^(644|640|600)$ ]]; then
        add_finding "${SCRIPT_ID}-C6-${f_path##*/}" "Permission: ${f_path}" "High" "PASS" \
            "${f_path} permissions: ${perm}" ""
    else
        add_finding "${SCRIPT_ID}-C6-${f_path##*/}" "Permission: ${f_path}" "High" "WARN" \
            "${f_path} permissions: ${perm} (expected 644 or less)" \
            "Fix: chmod 644 ${f_path}"
    fi
done

if [[ -f /etc/shadow ]]; then
    shadow_perm=$(stat -c "%a" /etc/shadow 2>/dev/null || echo "unknown")
    if [[ "$shadow_perm" =~ ^(640|600|000)$ ]]; then
        add_finding "${SCRIPT_ID}-C6-shadow" "Permission: /etc/shadow" "Critical" "PASS" \
            "/etc/shadow permissions: ${shadow_perm}" ""
    else
        add_finding "${SCRIPT_ID}-C6-shadow" "Permission: /etc/shadow" "Critical" "FAIL" \
            "/etc/shadow permissions: ${shadow_perm} (expected 640 or 600)" \
            "Fix: chmod 640 /etc/shadow && chown root:shadow /etc/shadow"
    fi
fi

# ── Optional Fix ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    if [[ "${EUID}" -ne 0 ]]; then
        echo "INFO: --fix requires root to correct file permissions." >&2
    else
        echo "INFO: --fix will apply safe permission corrections for critical files and world-writable directories." >&2

        chmod 644 /etc/passwd /etc/group 2>/dev/null || true
        if [[ -f /etc/shadow ]]; then
            if getent group shadow >/dev/null 2>&1; then
                chown root:shadow /etc/shadow 2>/dev/null || true
            else
                chown root:root /etc/shadow 2>/dev/null || true
            fi
            chmod 640 /etc/shadow 2>/dev/null || true
        fi

        while IFS= read -r dir_path; do
            [[ -z "$dir_path" ]] && continue
            chmod +t "$dir_path" 2>/dev/null || true
        done <<< "$ww_dirs"

        echo "INFO: Applied chmod 644 to /etc/passwd and /etc/group, chmod 640 to /etc/shadow, and added sticky bits to flagged world-writable directories." >&2
        echo "INFO: SUID/SGID binaries and world-writable regular files still require manual review." >&2
    fi
fi

# ── Output ───────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_file_permissions" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
