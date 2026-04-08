#!/usr/bin/env bash
# =============================================================================
# L05 – Network Listeners & Open Ports (Linux)
# =============================================================================
# ID       : L05
# Category : Network Exposure
# Severity : High
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : Yes (root for full process mapping with ss/netstat)
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L05_network_listeners.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L05"
SCRIPT_NAME="Network Listeners & Open Ports"
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

# Risky ports: port -> description|severity
declare -A RISKY_PORTS=(
    ["21"]="FTP plaintext|High"
    ["23"]="Telnet plaintext remote access|Critical"
    ["25"]="SMTP relay (unexpected on endpoints)|Med"
    ["69"]="TFTP no authentication|High"
    ["111"]="RPCbind/portmapper|Med"
    ["135"]="MS-RPC endpoint mapper|Med"
    ["137"]="NetBIOS Name Service|Med"
    ["138"]="NetBIOS Datagram|Med"
    ["139"]="NetBIOS Session/SMBv1|High"
    ["161"]="SNMP weak auth v1/v2|High"
    ["512"]="rexec insecure|Critical"
    ["513"]="rlogin insecure|Critical"
    ["514"]="rsh/syslog plaintext|High"
    ["873"]="rsync (unauthenticated if misconfigured)|Med"
    ["1433"]="MS SQL Server|Med"
    ["3306"]="MySQL (check if internet-exposed)|Med"
    ["5432"]="PostgreSQL (check if internet-exposed)|Med"
    ["6379"]="Redis often unauthenticated|High"
    ["27017"]="MongoDB often unauthenticated|High"
)

# Detect ss or netstat
if command -v ss &>/dev/null; then
    NET_CMD="ss"
else
    NET_CMD="netstat"
fi

# Get all listening ports
if [[ "$NET_CMD" == "ss" ]]; then
    LISTENER_RAW=$(ss -tlnup 2>/dev/null || ss -tlnp 2>/dev/null)
else
    LISTENER_RAW=$(netstat -tlnup 2>/dev/null || netstat -tlnp 2>/dev/null)
fi

LISTEN_COUNT=$(echo "$LISTENER_RAW" | grep -c 'LISTEN\|tcp\|udp' || true)
LISTEN_COUNT=${LISTEN_COUNT:-0}
add_finding "${SCRIPT_ID}-C1" "Listening Ports Count" "Info" "INFO" \
    "~${LISTEN_COUNT} listening ports/sockets detected (via ${NET_CMD})" ""

# C2 – Check for risky ports
risky_idx=0
flagged_risky_ports=()
all_ports=$(echo "$LISTENER_RAW" | grep -oP '(?<=:)\d+(?=\s)' | sort -un || true)

for port in $all_ports; do
    if [[ -v "RISKY_PORTS[$port]" ]]; then
        desc=$(echo "${RISKY_PORTS[$port]}" | cut -d'|' -f1)
        sev=$(echo "${RISKY_PORTS[$port]}" | cut -d'|' -f2)
        # Get process info
        proc_info=$(echo "$LISTENER_RAW" | grep ":${port} " | awk '{print $NF}' | head -1 || echo "unknown")
        flagged_risky_ports+=("$port")
        add_finding "${SCRIPT_ID}-C2-${port}" "Risky Port Open: ${port}/tcp" "$sev" "WARN" \
            "Port ${port} (${desc}) is listening – process: ${proc_info}" \
            "Disable or firewall this service if not required"
        risky_idx=$((risky_idx + 1))
    fi
done

if [[ "$risky_idx" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C2" "Risky Ports" "High" "PASS" \
        "No well-known risky ports detected as listeners" ""
fi

# C3 – Ports bound to all interfaces (0.0.0.0 or ::)
wildcard_ports=$(echo "$LISTENER_RAW" | grep -E '0\.0\.0\.0:\d+|:::\d+|\*:\d+' | grep -oP '(?<=:)\d+' | sort -un | tr '\n' ',' | sed 's/,$//' || true)
if [[ -n "$wildcard_ports" ]]; then
    add_finding "${SCRIPT_ID}-C3" "Ports Bound to All Interfaces" "Med" "WARN" \
        "Ports: ${wildcard_ports}" \
        "Bind services to specific IPs where possible (e.g., listen 127.0.0.1)"
else
    add_finding "${SCRIPT_ID}-C3" "Ports Bound to All Interfaces" "Med" "PASS" \
        "No ports bound to 0.0.0.0 or ::" ""
fi

# C4 – SSH port check (non-standard may reduce noise; standard means exposure)
ssh_port=$(ss -tlnp 2>/dev/null | grep -i 'sshd\|ssh' | grep -oP '(?<=:)\d+' | head -1 || \
           grep -E '^\s*Port\s+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1 || echo "22")
if [[ "$ssh_port" == "22" ]]; then
    add_finding "${SCRIPT_ID}-C4" "SSH on Default Port 22" "Low" "WARN" \
        "SSH is listening on the default port 22" \
        "Consider changing to a non-standard port and restricting with firewall rules"
else
    add_finding "${SCRIPT_ID}-C4" "SSH Port" "Low" "INFO" \
        "SSH is on non-default port ${ssh_port}" ""
fi

# ── Optional Fix ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    if [[ "${EUID}" -ne 0 ]]; then
        echo "INFO: --fix requires root to apply firewall rules." >&2
    elif [[ "${#flagged_risky_ports[@]}" -eq 0 ]]; then
        echo "INFO: --fix found no risky listener ports to firewall." >&2
    elif command -v iptables &>/dev/null; then
        echo "WARNING: --fix will add iptables DROP rules for risky ports on non-loopback interfaces." >&2
        rules_added=0
        for port in "${flagged_risky_ports[@]}"; do
            if iptables -C INPUT -p tcp --dport "$port" ! -i lo -j DROP 2>/dev/null; then
                :
            else
                iptables -I INPUT -p tcp --dport "$port" ! -i lo -j DROP 2>/dev/null && rules_added=1 || true
            fi
            if iptables -C INPUT -p udp --dport "$port" ! -i lo -j DROP 2>/dev/null; then
                :
            else
                iptables -I INPUT -p udp --dport "$port" ! -i lo -j DROP 2>/dev/null && rules_added=1 || true
            fi
        done
        if [[ "$rules_added" -eq 1 ]]; then
            echo "INFO: Added firewall blocks for risky ports: $(printf '%s ' "${flagged_risky_ports[@]}" | xargs)." >&2
            if command -v iptables-save &>/dev/null; then
                if [[ -d /etc/iptables ]]; then
                    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
                else
                    iptables-save > /tmp/cyberswiss_iptables.rules 2>/dev/null || true
                fi
            fi
        else
            echo "INFO: No new iptables rules were needed for the detected risky ports." >&2
        fi
    else
        echo "INFO: --fix could not apply firewall rules because iptables is not available." >&2
    fi
fi

# ── Output ───────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    # Escape listener raw for JSON
    listeners_json=$(echo "$LISTENER_RAW" | head -40 | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))" 2>/dev/null || echo '""')
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s,"listeners":%s}\n' \
        "${SCRIPT_ID}_network_listeners" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS" "$listeners_json"
else
    echo ""
    echo "=== ${SCRIPT_ID} ${SCRIPT_NAME} – ${HOSTNAME_VAL} ==="
    echo "--- Listening Ports (first 20) ---"
    echo "$LISTENER_RAW" | head -21
    FAIL_COUNT=$(printf '%s\n' "$FINDINGS" | grep -c '"status":"FAIL"' || true)
    WARN_COUNT=$(printf '%s\n' "$FINDINGS" | grep -c '"status":"WARN"' || true)
    TOTAL=$(printf '%s\n' "$FINDINGS" | grep -c '"id":' || true)
    echo ""
    echo "Summary: ${TOTAL} finding(s), ${FAIL_COUNT} FAIL, ${WARN_COUNT} WARN"
fi

FAIL_COUNT=$(printf '%s\n' "$FINDINGS" | grep -c '"status":"FAIL"' || true)
WARN_COUNT=$(printf '%s\n' "$FINDINGS" | grep -c '"status":"WARN"' || true)
if [[ "$FAIL_COUNT" -gt 0 ]]; then exit 2; fi
if [[ "$WARN_COUNT" -gt 0 ]]; then exit 1; fi
exit 0
