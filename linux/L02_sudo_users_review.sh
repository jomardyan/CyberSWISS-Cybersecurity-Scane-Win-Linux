#!/usr/bin/env bash
# =============================================================================
# L02 – Sudo & Privileged Users Review (Linux)
# =============================================================================
# ID       : L02
# Category : Accounts & Auth
# Severity : High
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : Yes (root/sudo)
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L02_sudo_users_review.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L02"
SCRIPT_NAME="Sudo & Privileged Users Review"
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

# C1 – Root account locked or has no direct login
root_status=$(passwd -S root 2>/dev/null | awk '{print $2}' || echo "unknown")
if [[ "$root_status" == "L" || "$root_status" == "LK" ]]; then
    add_finding "${SCRIPT_ID}-C1" "Root Direct Login" "High" "PASS" \
        "Root account is locked (status=${root_status})" ""
elif [[ "$root_status" == "NP" ]]; then
    add_finding "${SCRIPT_ID}-C1" "Root Direct Login" "High" "PASS" \
        "Root has no password (NP) – console login disabled" ""
else
    add_finding "${SCRIPT_ID}-C1" "Root Direct Login" "High" "WARN" \
        "Root account status: ${root_status} – verify direct root login is disabled" \
        "Lock root: passwd -l root and ensure PermitRootLogin no in sshd_config"
fi

# C2 – UID 0 accounts (should only be root)
uid0_accounts=$(awk -F: '$3 == 0 {print $1}' /etc/passwd | tr '\n' ',' | sed 's/,$//')
uid0_count=$(awk -F: '$3 == 0 {count++} END {print count+0}' /etc/passwd)
if [[ "$uid0_count" -eq 1 ]]; then
    add_finding "${SCRIPT_ID}-C2" "UID 0 Accounts" "Critical" "PASS" \
        "Only root has UID 0" ""
else
    add_finding "${SCRIPT_ID}-C2" "UID 0 Accounts" "Critical" "FAIL" \
        "${uid0_count} accounts with UID 0: ${uid0_accounts}" \
        "Remove UID 0 from non-root accounts or delete them"
fi

# C3 – Members of sudo/wheel/admin group
for grp in sudo wheel admin; do
    if getent group "$grp" &>/dev/null; then
        members=$(getent group "$grp" | awk -F: '{print $4}')
        count=$(echo "$members" | tr ',' '\n' | grep -c '\S' || true)
        count=${count:-0}
        if [[ "$count" -le 3 ]]; then
            add_finding "${SCRIPT_ID}-C3-${grp}" "Group ${grp} Members" "Med" "PASS" \
                "Members (${count}): ${members:-none}" ""
        else
            add_finding "${SCRIPT_ID}-C3-${grp}" "Group ${grp} Members" "Med" "WARN" \
                "${count} members in ${grp}: ${members}" \
                "Review and remove unnecessary members from the ${grp} group"
        fi
    fi
done

# C4 – Sudoers: NOPASSWD entries
nopasswd_entries=$(grep -rh 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^\s*#' || true)
if [[ -n "$nopasswd_entries" ]]; then
    add_finding "${SCRIPT_ID}-C4" "NOPASSWD Sudo Entries" "High" "WARN" \
        "$(echo "$nopasswd_entries" | head -5 | tr '\n' ';')" \
        "Review and remove NOPASSWD entries unless operationally required and risk-accepted"
else
    add_finding "${SCRIPT_ID}-C4" "NOPASSWD Sudo Entries" "High" "PASS" \
        "No NOPASSWD entries in sudoers" ""
fi

# C5 – Sudoers: ALL=(ALL) ALL without restriction
all_all_entries=$(grep -rh 'ALL=(ALL)' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^\s*#' || true)
if [[ -n "$all_all_entries" ]]; then
    count_unrestricted=$(echo "$all_all_entries" | wc -l)
    add_finding "${SCRIPT_ID}-C5" "Unrestricted Sudo (ALL:ALL)" "High" "WARN" \
        "${count_unrestricted} unrestricted sudo rule(s) found" \
        "Limit sudo rules to specific commands rather than ALL=(ALL) ALL"
else
    add_finding "${SCRIPT_ID}-C5" "Unrestricted Sudo (ALL:ALL)" "High" "PASS" \
        "No unrestricted ALL=(ALL) ALL entries" ""
fi

# C6 – Accounts with shell that are system accounts (UID < 1000 with real shell)
system_shell_accounts=$(awk -F: '$3 < 1000 && $3 > 0 && $7 !~ /nologin|false|sync|shutdown|halt/ {print $1":"$3":"$7}' /etc/passwd | tr '\n' '|')
if [[ -n "$system_shell_accounts" ]]; then
    add_finding "${SCRIPT_ID}-C6" "System Accounts With Login Shell" "Med" "WARN" \
        "${system_shell_accounts%|}" \
        "Set shell to /sbin/nologin for system accounts: usermod -s /sbin/nologin <username>"
else
    add_finding "${SCRIPT_ID}-C6" "System Accounts With Login Shell" "Med" "PASS" \
        "No system accounts with login shell detected" ""
fi

# C7 – Inactive user accounts (> 90 days since last login, excluding system accounts)
LAST_CMD=$(command -v lastlog 2>/dev/null || true)
if [[ -n "$LAST_CMD" ]]; then
    inactive=$(lastlog -b 90 2>/dev/null | tail -n +2 | awk '$2 != "**Never" && NF > 0 {print $1}' | tr '\n' ',' | sed 's/,$//' || true)
    if [[ -n "$inactive" ]]; then
        add_finding "${SCRIPT_ID}-C7" "Inactive Accounts (> 90 days)" "Med" "WARN" \
            "Inactive: ${inactive}" \
            "Disable unused accounts: usermod -L <username> or userdel"
    else
        add_finding "${SCRIPT_ID}-C7" "Inactive Accounts (> 90 days)" "Med" "PASS" \
            "No accounts with login > 90 days ago" ""
    fi
fi

# ── Optional Fix ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "WARNING: --fix will lock login shells for system accounts (UID < 1000) with interactive shells." >&2
    echo "Press Ctrl+C within 10 seconds to abort..." >&2
    sleep 10
    awk -F: '$3 < 1000 && $3 > 0 && $7 !~ /nologin|false|sync|shutdown|halt/ {print $1}' /etc/passwd | while read -r acct; do
        usermod -s /sbin/nologin "$acct" 2>/dev/null && echo "Locked shell for: $acct" >&2 || true
    done
fi

# ── Output ───────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_sudo_users_review" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
