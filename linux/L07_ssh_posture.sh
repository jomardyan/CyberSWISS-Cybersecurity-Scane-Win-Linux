#!/usr/bin/env bash
# =============================================================================
# L07 – SSH Posture Check (Linux)
# =============================================================================
# ID       : L07
# Category : Network Exposure
# Severity : High
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : No (reads sshd_config; some checks need root)
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : ./L07_ssh_posture.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L07"
SCRIPT_NAME="SSH Posture Check"
HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
JSON_MODE=false
FIX_MODE=false
FINDINGS='[]'
SSHD_CONFIG="/etc/ssh/sshd_config"

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

get_sshd_value() {
    # Returns the effective value of an sshd_config directive (first non-comment match)
    local directive="$1"
    local default_val="${2:-}"
    local val
    # Check include dirs too (ssh may include /etc/ssh/sshd_config.d/*.conf)
    val=$(grep -rh -iE "^\s*${directive}\s+" "$SSHD_CONFIG" /etc/ssh/sshd_config.d/*.conf 2>/dev/null | \
          grep -v '^\s*#' | head -1 | awk '{print $2}' || echo "")
    if [[ -z "$val" ]]; then
        echo "$default_val"
    else
        echo "$val"
    fi
}

if [[ ! -f "$SSHD_CONFIG" ]]; then
    add_finding "${SCRIPT_ID}-C0" "sshd_config Found" "High" "WARN" \
        "${SSHD_CONFIG} not found – SSH may not be installed" \
        "Install OpenSSH server if required"
    # Exit cleanly
    if [[ "$JSON_MODE" == true ]]; then
        printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
            "${SCRIPT_ID}_ssh_posture" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
    fi
    exit 1
fi

# C1 – PermitRootLogin
root_login=$(get_sshd_value "PermitRootLogin" "yes")
if [[ "$root_login" =~ ^(no|prohibit-password|without-password)$ ]]; then
    add_finding "${SCRIPT_ID}-C1" "PermitRootLogin" "Critical" "PASS" \
        "PermitRootLogin=${root_login}" ""
else
    add_finding "${SCRIPT_ID}-C1" "PermitRootLogin" "Critical" "FAIL" \
        "PermitRootLogin=${root_login} (allows direct root login)" \
        "Set: PermitRootLogin no  (or prohibit-password) in ${SSHD_CONFIG}"
fi

# C2 – PasswordAuthentication
pwd_auth=$(get_sshd_value "PasswordAuthentication" "yes")
if [[ "$pwd_auth" =~ ^[Nn]o$ ]]; then
    add_finding "${SCRIPT_ID}-C2" "PasswordAuthentication" "High" "PASS" \
        "PasswordAuthentication=no (key-only)" ""
else
    add_finding "${SCRIPT_ID}-C2" "PasswordAuthentication" "High" "WARN" \
        "PasswordAuthentication=${pwd_auth} (passwords accepted)" \
        "Disable password auth (use keys): PasswordAuthentication no  in ${SSHD_CONFIG}"
fi

# C3 – PermitEmptyPasswords
empty_pwd=$(get_sshd_value "PermitEmptyPasswords" "no")
if [[ "$empty_pwd" =~ ^[Nn]o$ ]]; then
    add_finding "${SCRIPT_ID}-C3" "PermitEmptyPasswords" "Critical" "PASS" \
        "PermitEmptyPasswords=no" ""
else
    add_finding "${SCRIPT_ID}-C3" "PermitEmptyPasswords" "Critical" "FAIL" \
        "PermitEmptyPasswords=${empty_pwd}" \
        "Set: PermitEmptyPasswords no  in ${SSHD_CONFIG}"
fi

# C4 – Protocol version (should be 2 only)
protocol=$(get_sshd_value "Protocol" "2")
if [[ "$protocol" == "2" ]]; then
    add_finding "${SCRIPT_ID}-C4" "SSH Protocol Version" "High" "PASS" \
        "Protocol=2 (SSHv1 not in use)" ""
else
    add_finding "${SCRIPT_ID}-C4" "SSH Protocol Version" "High" "FAIL" \
        "Protocol=${protocol} (SSHv1 may be enabled)" \
        "Set: Protocol 2  in ${SSHD_CONFIG}"
fi

# C5 – MaxAuthTries
max_auth=$(get_sshd_value "MaxAuthTries" "6")
if [[ "$max_auth" -le 4 ]] 2>/dev/null; then
    add_finding "${SCRIPT_ID}-C5" "MaxAuthTries" "Med" "PASS" \
        "MaxAuthTries=${max_auth} (<= 4)" ""
else
    add_finding "${SCRIPT_ID}-C5" "MaxAuthTries" "Med" "WARN" \
        "MaxAuthTries=${max_auth} (> 4)" \
        "Set: MaxAuthTries 3  in ${SSHD_CONFIG}"
fi

# C6 – LoginGraceTime
grace=$(get_sshd_value "LoginGraceTime" "120")
grace_num=$(echo "$grace" | sed 's/[^0-9].*//g')
if [[ -n "$grace_num" && "$grace_num" -le 60 ]] 2>/dev/null; then
    add_finding "${SCRIPT_ID}-C6" "LoginGraceTime" "Low" "PASS" \
        "LoginGraceTime=${grace} (<= 60s)" ""
else
    add_finding "${SCRIPT_ID}-C6" "LoginGraceTime" "Low" "WARN" \
        "LoginGraceTime=${grace} (> 60s)" \
        "Set: LoginGraceTime 30  in ${SSHD_CONFIG}"
fi

# C7 – X11 Forwarding disabled
x11=$(get_sshd_value "X11Forwarding" "yes")
if [[ "$x11" =~ ^[Nn]o$ ]]; then
    add_finding "${SCRIPT_ID}-C7" "X11Forwarding" "Med" "PASS" \
        "X11Forwarding=no" ""
else
    add_finding "${SCRIPT_ID}-C7" "X11Forwarding" "Med" "WARN" \
        "X11Forwarding=${x11}" \
        "Disable: X11Forwarding no  in ${SSHD_CONFIG} (unless GUI required)"
fi

# C8 – Allowed ciphers (flag weak ones)
ciphers=$(get_sshd_value "Ciphers" "")
if [[ -n "$ciphers" ]]; then
    weak_ciphers=$(echo "$ciphers" | grep -iE 'arcfour|3des|blowfish|cast|rc4' || true)
    if [[ -n "$weak_ciphers" ]]; then
        add_finding "${SCRIPT_ID}-C8" "Weak SSH Ciphers" "High" "FAIL" \
            "Weak cipher(s) configured: ${weak_ciphers}" \
            "Remove weak ciphers from Ciphers directive in ${SSHD_CONFIG}"
    else
        add_finding "${SCRIPT_ID}-C8" "SSH Ciphers" "High" "PASS" \
            "No obviously weak ciphers in Ciphers setting" ""
    fi
else
    add_finding "${SCRIPT_ID}-C8" "SSH Ciphers" "Low" "INFO" \
        "Ciphers not explicitly set (using OpenSSH defaults)" ""
fi

# C9 – AllowUsers / AllowGroups defined (restrict access)
allow_users=$(get_sshd_value "AllowUsers" "")
allow_groups=$(get_sshd_value "AllowGroups" "")
if [[ -n "$allow_users" || -n "$allow_groups" ]]; then
    add_finding "${SCRIPT_ID}-C9" "SSH Access Restriction" "Med" "PASS" \
        "AllowUsers='${allow_users}' AllowGroups='${allow_groups}'" ""
else
    add_finding "${SCRIPT_ID}-C9" "SSH Access Restriction" "Med" "WARN" \
        "No AllowUsers or AllowGroups restriction defined" \
        "Add: AllowUsers <user1> <user2>  or AllowGroups sshusers  in ${SSHD_CONFIG}"
fi

# ── Optional Fix ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "WARNING: --fix will backup and modify ${SSHD_CONFIG}" >&2
    echo "Press Ctrl+C within 10 seconds to abort..." >&2
    sleep 10
    BACKUP="${SSHD_CONFIG}.cyberswiss.bak.$(date +%Y%m%d%H%M%S)"
    cp "$SSHD_CONFIG" "$BACKUP"
    echo "Backup created: ${BACKUP}" >&2
    # Apply minimal fixes
    sed -i 's/^#*\s*PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"
    sed -i 's/^#*\s*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSHD_CONFIG"
    sed -i 's/^#*\s*X11Forwarding.*/X11Forwarding no/' "$SSHD_CONFIG"
    echo "Basic SSH hardening applied. Reload sshd: systemctl reload sshd" >&2
fi

# ── Output ───────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_ssh_posture" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
