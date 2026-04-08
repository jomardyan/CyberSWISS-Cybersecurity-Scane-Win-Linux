#!/usr/bin/env bash
# =============================================================================
# L06 – Firewall State (Linux)
# =============================================================================
# ID       : L06
# Category : Network Exposure
# Severity : High
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : Yes
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L06_firewall_state.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L06"
SCRIPT_NAME="Firewall State"
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

FW_DETECTED=false

# C1 – ufw (Ubuntu/Debian)
if command -v ufw &>/dev/null; then
    ufw_status=$(ufw status 2>/dev/null | head -1 || echo "unknown")
    if echo "$ufw_status" | grep -qi "Status: active"; then
        add_finding "${SCRIPT_ID}-C1" "UFW Firewall Active" "High" "PASS" \
            "ufw status: active" ""
        FW_DETECTED=true
        # Check default INPUT policy
        default_deny=$(ufw status verbose 2>/dev/null | grep "Default:" | grep -i "deny\|reject" | head -1 || true)
        if [[ -n "$default_deny" ]]; then
            add_finding "${SCRIPT_ID}-C2" "UFW Default Deny Inbound" "High" "PASS" \
                "Default inbound policy is deny/reject" ""
        else
            add_finding "${SCRIPT_ID}-C2" "UFW Default Deny Inbound" "High" "WARN" \
                "Default inbound policy may not be deny" \
                "Set: ufw default deny incoming"
        fi
    else
        add_finding "${SCRIPT_ID}-C1" "UFW Firewall Active" "High" "FAIL" \
            "ufw status: ${ufw_status}" \
            "Enable: ufw enable"
        FW_DETECTED=true
    fi
fi

# C2 – firewalld (RHEL/CentOS/Fedora)
if command -v firewall-cmd &>/dev/null; then
    fw_state=$(firewall-cmd --state 2>/dev/null || echo "not running")
    if [[ "$fw_state" == "running" ]]; then
        add_finding "${SCRIPT_ID}-C1-firewalld" "firewalld Active" "High" "PASS" \
            "firewalld state: running" ""
        FW_DETECTED=true
        # Default zone
        default_zone=$(firewall-cmd --get-default-zone 2>/dev/null || echo "unknown")
        add_finding "${SCRIPT_ID}-C3-firewalld" "firewalld Default Zone" "Med" "INFO" \
            "Default zone: ${default_zone}" ""
    else
        add_finding "${SCRIPT_ID}-C1-firewalld" "firewalld Active" "High" "FAIL" \
            "firewalld state: ${fw_state}" \
            "Start: systemctl start firewalld && systemctl enable firewalld"
        FW_DETECTED=true
    fi
fi

# C3 – iptables/nftables (fallback / additional check)
if command -v iptables &>/dev/null; then
    # Check if any INPUT rules are defined beyond ACCEPT
    input_rules=$(iptables -L INPUT -n 2>/dev/null | grep -c -E 'DROP|REJECT|ACCEPT' || true)
    input_policy=$(iptables -L INPUT -n 2>/dev/null | head -1 | awk '{print $4}' | tr -d '()' || echo "unknown")
    if [[ "$input_policy" == "DROP" || "$input_policy" == "REJECT" ]]; then
        add_finding "${SCRIPT_ID}-C4" "iptables Default INPUT Policy" "High" "PASS" \
            "iptables INPUT default policy: ${input_policy}" ""
        FW_DETECTED=true
    elif [[ "$input_rules" -gt 2 ]]; then
        add_finding "${SCRIPT_ID}-C4" "iptables Rules Present" "High" "INFO" \
            "iptables has ${input_rules} INPUT rules (default: ${input_policy})" ""
        FW_DETECTED=true
    fi
fi

if command -v nft &>/dev/null; then
    nft_rules=$(nft list ruleset 2>/dev/null | wc -l || true)
    if [[ "$nft_rules" -gt 5 ]]; then
        add_finding "${SCRIPT_ID}-C5" "nftables Rules Present" "High" "PASS" \
            "${nft_rules} nftables rules configured" ""
        FW_DETECTED=true
    fi
fi

# C6 – No firewall detected
if [[ "$FW_DETECTED" == false ]]; then
    add_finding "${SCRIPT_ID}-C6" "No Firewall Detected" "Critical" "FAIL" \
        "No ufw, firewalld, iptables, or nftables rules detected" \
        "Install and configure a firewall: ufw (Debian/Ubuntu) or firewalld (RHEL)"
fi

# C7 – IPv6 firewall
if command -v ip6tables &>/dev/null; then
    ip6_policy=$(ip6tables -L INPUT -n 2>/dev/null | head -1 | awk '{print $4}' | tr -d '()' || echo "unknown")
    if [[ "$ip6_policy" == "DROP" || "$ip6_policy" == "REJECT" ]]; then
        add_finding "${SCRIPT_ID}-C7" "IPv6 Firewall" "Med" "PASS" \
            "ip6tables INPUT default policy: ${ip6_policy}" ""
    else
        add_finding "${SCRIPT_ID}-C7" "IPv6 Firewall" "Med" "WARN" \
            "ip6tables INPUT default policy: ${ip6_policy} (not DROP/REJECT)" \
            "Set IPv6 firewall rules or disable IPv6 if not required"
    fi
fi

# ── Optional Fix ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "WARNING: --fix will enable the firewall with default settings." >&2
    echo "Press Ctrl+C within 10 seconds to abort..." >&2
    sleep 10
    if command -v ufw &>/dev/null; then
        ufw --force enable 2>&1 && echo "ufw enabled" >&2 || true
    elif command -v firewall-cmd &>/dev/null; then
        systemctl enable --now firewalld 2>&1 && echo "firewalld enabled" >&2 || true
    else
        echo "INFO: --fix: No supported firewall (ufw/firewalld) found to enable." >&2
    fi
fi

# ── Output ───────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_firewall_state" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
