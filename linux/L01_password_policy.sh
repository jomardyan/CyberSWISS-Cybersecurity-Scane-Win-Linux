#!/usr/bin/env bash
# =============================================================================
# L01 – Password Policy Audit (Linux)
# =============================================================================
# ID       : L01
# Category : Accounts & Auth
# Severity : High
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES, Arch
# Admin    : Yes (root/sudo for /etc/shadow and PAM)
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L01_password_policy.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L01"
SCRIPT_NAME="Password Policy Audit"
HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
JSON_MODE=false
FIX_MODE=false
FINDINGS='[]'

# ── Argument Parsing ─────────────────────────────────────────────────────────
for arg in "$@"; do
    case "$arg" in
        --json) JSON_MODE=true ;;
        --fix)  FIX_MODE=true  ;;
        -h|--help)
            echo "Usage: sudo $0 [--json] [--fix]"
            echo "  --json  Output in JSON format"
            echo "  --fix   Apply basic remediation (requires explicit flag)"
            exit 0 ;;
        *) echo "Unknown argument: $arg" >&2; exit 1 ;;
    esac
done

# ── Helpers ──────────────────────────────────────────────────────────────────
add_finding() {
    local id="$1" name="$2" sev="$3" status="$4" detail="$5" remediation="$6"
    local entry
    entry=$(printf '{"id":"%s","name":"%s","severity":"%s","status":"%s","detail":"%s","remediation":"%s","timestamp":"%s"}' \
        "$id" "$name" "$sev" "$status" "$(echo "$detail" | sed 's/"/\\"/g')" "$(echo "$remediation" | sed 's/"/\\"/g')" "$TIMESTAMP")
    if [[ "$FINDINGS" == '[]' ]]; then
        FINDINGS="[$entry]"
    else
        FINDINGS="${FINDINGS%]},${entry}]"
    fi
    if [[ "$JSON_MODE" == false ]]; then
        case "$status" in
            PASS) colour='\033[0;32m' ;;
            WARN) colour='\033[0;33m' ;;
            FAIL) colour='\033[0;31m' ;;
            *)    colour='\033[0;36m' ;;
        esac
        printf "${colour}[%s] [%s] %s: %s\033[0m\n" "$status" "$sev" "$id" "$name"
        [[ -n "$detail" ]]      && printf "       Detail : %s\n" "$detail"
        [[ "$status" != "PASS" && -n "$remediation" ]] && printf "\033[0;36m       Remedy : %s\033[0m\n" "$remediation"
    fi
}

# ── Checks ───────────────────────────────────────────────────────────────────

# C1 – /etc/login.defs: PASS_MAX_DAYS
if [[ -f /etc/login.defs ]]; then
    max_days=$(grep -E '^\s*PASS_MAX_DAYS' /etc/login.defs | awk '{print $2}' | head -1 || true)
    if [[ -z "$max_days" ]]; then
        add_finding "${SCRIPT_ID}-C1" "PASS_MAX_DAYS" "High" "WARN" \
            "PASS_MAX_DAYS not set in /etc/login.defs" \
            "Set PASS_MAX_DAYS 90 in /etc/login.defs"
    elif [[ "$max_days" -le 90 && "$max_days" -gt 0 ]]; then
        add_finding "${SCRIPT_ID}-C1" "PASS_MAX_DAYS" "High" "PASS" \
            "PASS_MAX_DAYS=${max_days} (<= 90)" ""
    else
        add_finding "${SCRIPT_ID}-C1" "PASS_MAX_DAYS" "High" "FAIL" \
            "PASS_MAX_DAYS=${max_days} (> 90 or 0=never)" \
            "Set PASS_MAX_DAYS 90 in /etc/login.defs"
    fi
else
    add_finding "${SCRIPT_ID}-C1" "PASS_MAX_DAYS" "High" "WARN" \
        "/etc/login.defs not found" "Install shadow-utils or equivalent"
fi

# C2 – PASS_MIN_LEN
if [[ -f /etc/login.defs ]]; then
    min_len=$(grep -E '^\s*PASS_MIN_LEN' /etc/login.defs | awk '{print $2}' | head -1 || true)
    if [[ -z "$min_len" ]]; then
        add_finding "${SCRIPT_ID}-C2" "PASS_MIN_LEN" "High" "WARN" \
            "PASS_MIN_LEN not set (may rely on PAM)" \
            "Set PASS_MIN_LEN 14 in /etc/login.defs or configure pam_pwquality"
    elif [[ "$min_len" -ge 14 ]]; then
        add_finding "${SCRIPT_ID}-C2" "PASS_MIN_LEN" "High" "PASS" \
            "PASS_MIN_LEN=${min_len} (>= 14)" ""
    else
        add_finding "${SCRIPT_ID}-C2" "PASS_MIN_LEN" "High" "FAIL" \
            "PASS_MIN_LEN=${min_len} (< 14)" \
            "Set PASS_MIN_LEN 14 in /etc/login.defs"
    fi
fi

# C3 – PAM pwquality minlen
PAM_PWQUALITY_CONF=""
for f in /etc/security/pwquality.conf /etc/pam.d/common-password /etc/pam.d/system-auth; do
    [[ -f "$f" ]] && PAM_PWQUALITY_CONF="$f" && break
done

if [[ -n "$PAM_PWQUALITY_CONF" ]]; then
    pam_minlen=$(grep -E 'minlen' "$PAM_PWQUALITY_CONF" 2>/dev/null | grep -v '^\s*#' | grep -oP 'minlen\s*=?\s*\K\d+' | head -1 || true)
    if [[ -n "$pam_minlen" && "$pam_minlen" -ge 14 ]]; then
        add_finding "${SCRIPT_ID}-C3" "PAM pwquality minlen" "High" "PASS" \
            "minlen=${pam_minlen} in ${PAM_PWQUALITY_CONF}" ""
    elif [[ -n "$pam_minlen" ]]; then
        add_finding "${SCRIPT_ID}-C3" "PAM pwquality minlen" "High" "FAIL" \
            "minlen=${pam_minlen} (< 14) in ${PAM_PWQUALITY_CONF}" \
            "Set minlen=14 in /etc/security/pwquality.conf"
    else
        add_finding "${SCRIPT_ID}-C3" "PAM pwquality minlen" "High" "WARN" \
            "minlen not explicitly set in pwquality config" \
            "Set minlen=14 in /etc/security/pwquality.conf"
    fi
else
    add_finding "${SCRIPT_ID}-C3" "PAM pwquality" "Med" "WARN" \
        "pwquality config not found" \
        "Install libpam-pwquality (Debian) or pam_pwquality (RHEL)"
fi

# C4 – Account lockout (faillock or pam_tally2)
FAILLOCK_CONF=/etc/security/faillock.conf
if [[ -f "$FAILLOCK_CONF" ]]; then
    deny_val=$(grep -E '^\s*deny\s*=' "$FAILLOCK_CONF" | awk -F= '{print $2}' | tr -d ' ' | head -1 || true)
    if [[ -n "$deny_val" && "$deny_val" -gt 0 && "$deny_val" -le 10 ]]; then
        add_finding "${SCRIPT_ID}-C4" "Account Lockout (faillock)" "High" "PASS" \
            "deny=${deny_val} (<= 10)" ""
    else
        add_finding "${SCRIPT_ID}-C4" "Account Lockout (faillock)" "High" "FAIL" \
            "deny=${deny_val:-not_set} (should be 1-10)" \
            "Set deny=5 in /etc/security/faillock.conf"
    fi
elif grep -rq 'pam_tally2\|pam_faillock' /etc/pam.d/ 2>/dev/null; then
    add_finding "${SCRIPT_ID}-C4" "Account Lockout" "High" "PASS" \
        "pam_tally2 or pam_faillock configured in PAM" ""
else
    add_finding "${SCRIPT_ID}-C4" "Account Lockout" "High" "FAIL" \
        "No account lockout mechanism detected" \
        "Install and configure pam_faillock or pam_tally2"
fi

# C5 – Password history (pam_pwhistory)
if grep -rq 'pam_pwhistory\|remember=' /etc/pam.d/ 2>/dev/null; then
    remember=$(grep -r 'remember=' /etc/pam.d/ 2>/dev/null | grep -oP 'remember=\K\d+' | sort -n | tail -1 || true)
    if [[ -n "$remember" && "$remember" -ge 24 ]]; then
        add_finding "${SCRIPT_ID}-C5" "Password History" "Med" "PASS" \
            "remember=${remember} (>= 24)" ""
    else
        add_finding "${SCRIPT_ID}-C5" "Password History" "Med" "WARN" \
            "remember=${remember:-set_but_low} (< 24 recommended)" \
            "Set remember=24 in pam_pwhistory configuration"
    fi
else
    add_finding "${SCRIPT_ID}-C5" "Password History" "Med" "WARN" \
        "pam_pwhistory not configured" \
        "Add: password required pam_pwhistory.so remember=24 in /etc/pam.d/common-password"
fi

# C6 – Accounts with empty passwords (from /etc/shadow)
if [[ -r /etc/shadow ]]; then
    empty_pw=$(awk -F: '($2 == "" || $2 == "!!" ) && $2 == "" {print $1}' /etc/shadow 2>/dev/null || true)
    if [[ -n "$empty_pw" ]]; then
        add_finding "${SCRIPT_ID}-C6" "Accounts With Empty Passwords" "Critical" "FAIL" \
            "Accounts: ${empty_pw//$'\n'/, }" \
            "Set passwords: passwd <username>"
    else
        add_finding "${SCRIPT_ID}-C6" "Accounts With Empty Passwords" "Critical" "PASS" \
            "No accounts with empty passwords detected" ""
    fi
else
    add_finding "${SCRIPT_ID}-C6" "Accounts With Empty Passwords" "Critical" "WARN" \
        "/etc/shadow not readable (run as root)" \
        "Run with sudo"
fi

# ── Optional Fix ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "WARNING: --fix will modify /etc/login.defs and PAM configuration" >&2
    echo "Press Ctrl+C within 10 seconds to abort..." >&2
    sleep 10
    # Set PASS_MAX_DAYS 90
    if [[ -f /etc/login.defs ]]; then
        sed -i 's/^\s*PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
        grep -q 'PASS_MAX_DAYS' /etc/login.defs || echo 'PASS_MAX_DAYS   90' >> /etc/login.defs
    fi
    # Set PASS_MIN_LEN 14
    if [[ -f /etc/login.defs ]]; then
        sed -i 's/^\s*PASS_MIN_LEN.*/PASS_MIN_LEN    14/' /etc/login.defs
        grep -q 'PASS_MIN_LEN' /etc/login.defs || echo 'PASS_MIN_LEN    14' >> /etc/login.defs
    fi
    echo "Basic password policy applied to /etc/login.defs" >&2
fi

# ── Output ───────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_password_policy" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
else
    echo ""
    echo "=== ${SCRIPT_ID} ${SCRIPT_NAME} – ${HOSTNAME_VAL} ==="
    FAIL_COUNT=$(printf '%s\n' "$FINDINGS" | grep -c '"status":"FAIL"' || true)
    WARN_COUNT=$(printf '%s\n' "$FINDINGS" | grep -c '"status":"WARN"' || true)
    TOTAL=$(printf '%s\n' "$FINDINGS" | grep -c '"id":' || true)
    echo ""
    echo "Summary: ${TOTAL} finding(s), ${FAIL_COUNT} FAIL, ${WARN_COUNT} WARN"
fi

# Exit code: 0=all pass, 1=warnings, 2=failures
FAIL_COUNT=$(printf '%s\n' "$FINDINGS" | grep -c '"status":"FAIL"' || true)
WARN_COUNT=$(printf '%s\n' "$FINDINGS" | grep -c '"status":"WARN"' || true)
if [[ "$FAIL_COUNT" -gt 0 ]]; then exit 2; fi
if [[ "$WARN_COUNT" -gt 0 ]]; then exit 1; fi
exit 0
