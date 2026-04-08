#!/usr/bin/env bash
# =============================================================================
# L17 – Attack Surface Management (Linux)
# =============================================================================
# ID       : L17
# Category : Attack Surface Management
# Severity : High
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : Yes
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L17_attack_surface.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L17"
SCRIPT_NAME="Attack Surface Management"
HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
JSON_MODE=false
FIX_MODE=false
FINDINGS='[]'

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

is_public_ip() {
    local ip="$1"
    # Returns 0 (true) if the IP is a routable public address
    [[ "$ip" =~ ^10\. ]]                          && return 1
    [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] && return 1
    [[ "$ip" =~ ^192\.168\. ]]                     && return 1
    [[ "$ip" =~ ^127\. ]]                          && return 1
    [[ "$ip" =~ ^::1$ ]]                           && return 1
    [[ "$ip" =~ ^fe80: ]]                          && return 1
    [[ "$ip" =~ ^169\.254\. ]]                     && return 1
    return 0
}

# C1 – Internet-facing network interfaces
public_ifaces=""
while IFS= read -r line; do
    ip=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
    iface=$(echo "$line" | awk '{print $NF}' || true)
    [[ -z "$ip" ]] && continue
    if is_public_ip "$ip"; then
        public_ifaces="${public_ifaces} ${iface}:${ip}"
    fi
done < <(ip addr show 2>/dev/null | awk '/inet / {print $2, $NF}' || true)

if [[ -z "$public_ifaces" ]]; then
    add_finding "${SCRIPT_ID}-C1" "Internet-Facing Interfaces" "High" "INFO" \
        "No public routable IPs detected on any interface" ""
else
    add_finding "${SCRIPT_ID}-C1" "Internet-Facing Interfaces" "High" "WARN" \
        "Public IP(s) detected on interfaces:${public_ifaces}" \
        "Ensure firewall rules restrict inbound traffic to required ports only"
fi

# C2 – Sensitive services bound to 0.0.0.0
declare -A SENSITIVE_PORTS=([3306]="MySQL" [5432]="PostgreSQL" [6379]="Redis" [27017]="MongoDB" [9200]="Elasticsearch" [5984]="CouchDB")
exposed_services=""
ss_out=$(ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || true)
for port in "${!SENSITIVE_PORTS[@]}"; do
    svc="${SENSITIVE_PORTS[$port]}"
    if echo "$ss_out" | grep -qE "0\.0\.0\.0:${port}\b"; then
        exposed_services="${exposed_services} ${svc}(${port})"
    fi
done

if [[ -z "$exposed_services" ]]; then
    add_finding "${SCRIPT_ID}-C2" "Sensitive Services Bound to 0.0.0.0" "High" "PASS" \
        "No sensitive database/cache services bound to 0.0.0.0" ""
else
    add_finding "${SCRIPT_ID}-C2" "Sensitive Services Bound to 0.0.0.0" "High" "FAIL" \
        "Service(s) exposed on all interfaces:${exposed_services}" \
        "Bind to 127.0.0.1 in each service config (e.g., bind 127.0.0.1 in redis.conf)"
fi

# C3 – Unnecessary risky open ports
declare -A RISKY_PORTS=([23]="Telnet" [21]="FTP" [512]="rexec" [513]="rlogin" [514]="rsh" [111]="rpcbind" [2049]="NFS" [6000]="X11")
risky_open=""
for port in "${!RISKY_PORTS[@]}"; do
    svc="${RISKY_PORTS[$port]}"
    if echo "$ss_out" | grep -qE ":${port}\b.*LISTEN"; then
        risky_open="${risky_open} ${svc}(${port})"
    fi
done

if [[ -z "$risky_open" ]]; then
    add_finding "${SCRIPT_ID}-C3" "Risky Open Ports" "High" "PASS" \
        "No high-risk legacy service ports detected (telnet, ftp, rsh, rpcbind, NFS, X11)" ""
else
    add_finding "${SCRIPT_ID}-C3" "Risky Open Ports" "High" "FAIL" \
        "Risky port(s) open:${risky_open}" \
        "Disable legacy services. Replace Telnet/FTP/RSH with SSH/SFTP."
fi

# C4 – Running web servers and their versions
web_issues=""
for svc in nginx apache2 httpd; do
    if command -v "$svc" &>/dev/null; then
        ver=$("$svc" -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
        [[ -z "$ver" ]] && continue
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [[ "$svc" == "nginx" ]]; then
            if [[ "$major" -eq 1 && "$minor" -lt 24 ]]; then
                web_issues="${web_issues} nginx/${ver}(outdated<1.24)"
            fi
        elif [[ "$svc" == "apache2" || "$svc" == "httpd" ]]; then
            if [[ "$major" -eq 2 && "$minor" -eq 4 ]]; then
                patch=$(echo "$ver" | cut -d. -f3)
                [[ "$patch" -lt 57 ]] && web_issues="${web_issues} apache/${ver}(outdated<2.4.57)"
            fi
        fi
    fi
done

if [[ -z "$web_issues" ]]; then
    add_finding "${SCRIPT_ID}-C4" "Web Server Versions" "Med" "PASS" \
        "No outdated web server versions detected" ""
else
    add_finding "${SCRIPT_ID}-C4" "Web Server Versions" "Med" "WARN" \
        "Potentially outdated web server(s):${web_issues}" \
        "Update web servers to current stable releases"
fi

# C5 – SSL/TLS certificate expiry on localhost HTTPS
if command -v openssl &>/dev/null; then
    cert_issues=""
    for port in 443 8443; do
        if echo "$ss_out" | grep -qE ":${port}\b.*LISTEN"; then
            expiry=$(echo | timeout 5 openssl s_client -connect "localhost:${port}" -servername localhost 2>/dev/null \
                | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || true)
            if [[ -n "$expiry" ]]; then
                exp_epoch=$(date -d "$expiry" +%s 2>/dev/null || true)
                now_epoch=$(date +%s)
                days_left=$(( (exp_epoch - now_epoch) / 86400 ))
                if [[ "$days_left" -lt 30 ]]; then
                    cert_issues="${cert_issues} port${port}:expires_in_${days_left}_days"
                fi
            fi
        fi
    done
    if [[ -z "$cert_issues" ]]; then
        add_finding "${SCRIPT_ID}-C5" "SSL/TLS Certificate Expiry" "High" "PASS" \
            "No certificates expiring within 30 days on localhost HTTPS ports" ""
    else
        add_finding "${SCRIPT_ID}-C5" "SSL/TLS Certificate Expiry" "High" "FAIL" \
            "Certificate(s) expiring soon:${cert_issues}" \
            "Renew certificates immediately. Consider automated renewal with certbot/ACME."
    fi
else
    add_finding "${SCRIPT_ID}-C5" "SSL/TLS Certificate Expiry" "High" "WARN" \
        "openssl not available – certificate expiry check skipped" \
        "Install openssl to enable TLS certificate checks"
fi

# C6 – DNS zone transfer check
if command -v dig &>/dev/null && systemctl is-active --quiet named 2>/dev/null; then
    domain=$(hostname -d 2>/dev/null || true)
    if [[ -n "$domain" ]]; then
        axfr=$(dig @localhost AXFR "$domain" 2>/dev/null | grep -v '^;' | head -5 || true)
        if [[ -n "$axfr" ]]; then
            add_finding "${SCRIPT_ID}-C6" "DNS Zone Transfer (AXFR)" "High" "FAIL" \
                "Zone transfer allowed for domain ${domain} from localhost" \
                "Restrict AXFR to authorised secondary nameservers only in named.conf (allow-transfer)"
        else
            add_finding "${SCRIPT_ID}-C6" "DNS Zone Transfer (AXFR)" "High" "PASS" \
                "Zone transfer (AXFR) refused for ${domain}" ""
        fi
    else
        add_finding "${SCRIPT_ID}-C6" "DNS Zone Transfer (AXFR)" "Low" "INFO" \
            "BIND running but no domain name configured – AXFR check skipped" ""
    fi
else
    add_finding "${SCRIPT_ID}-C6" "DNS Zone Transfer (AXFR)" "Low" "INFO" \
        "BIND/named not running or dig not available – DNS zone transfer check skipped" ""
fi

# C7 – IPv6 attack surface
ipv6_issues=""
if [[ -f /proc/net/if_inet6 ]]; then
    if command -v ip6tables &>/dev/null; then
        rule_count=$(ip6tables -L INPUT 2>/dev/null | grep -c -v '^#' || true)
        if [[ "$rule_count" -le 3 ]]; then
            ipv6_issues="ip6tables INPUT chain has no meaningful rules (${rule_count} lines)"
        fi
    else
        ipv6_issues="IPv6 enabled but ip6tables not available"
    fi
fi

if [[ -z "$ipv6_issues" ]]; then
    add_finding "${SCRIPT_ID}-C7" "IPv6 Attack Surface" "Med" "PASS" \
        "IPv6 not active or ip6tables rules are in place" ""
else
    add_finding "${SCRIPT_ID}-C7" "IPv6 Attack Surface" "Med" "WARN" \
        "$ipv6_issues" \
        "Add ip6tables rules equivalent to IPv4 firewall rules, or disable IPv6 if not required"
fi

# ── Optional Fix ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "WARNING: --fix will add iptables rules to block sensitive services on non-loopback interfaces" >&2
    echo "         Rules will be persisted via iptables-save / firewalld where available." >&2
    echo "Press Ctrl+C within 10 seconds to abort..." >&2
    sleep 10
    rules_added=0
    for port in 3306 5432 6379 27017; do
        if echo "$ss_out" | grep -qE "0\.0\.0\.0:${port}\b"; then
            if iptables -I INPUT -p tcp --dport "$port" ! -i lo -j DROP 2>/dev/null; then
                echo "Blocked port ${port} on non-loopback interfaces via iptables INPUT DROP" >&2
                rules_added=1
            else
                echo "Failed to add iptables rule for port ${port} (requires root)" >&2
            fi
        fi
    done
    # Persist rules if any were added
    if [[ "$rules_added" -eq 1 ]]; then
        if command -v iptables-save &>/dev/null; then
            if [[ -d /etc/iptables ]]; then
                iptables-save > /etc/iptables/rules.v4 2>/dev/null && \
                    echo "Rules saved to /etc/iptables/rules.v4 (requires iptables-persistent to restore on reboot – install with: apt-get install iptables-persistent)" >&2 || \
                    echo "Could not write /etc/iptables/rules.v4 – install iptables-persistent (Debian/Ubuntu) or iptables-services (RHEL)" >&2
            else
                iptables-save > /tmp/cyberswiss_iptables.rules 2>/dev/null
                echo "Rules saved to /tmp/cyberswiss_iptables.rules. To persist across reboots: install iptables-persistent (apt-get install iptables-persistent) and move the file to /etc/iptables/rules.v4" >&2
            fi
        elif command -v firewall-cmd &>/dev/null; then
            echo "firewalld detected – use 'firewall-cmd --permanent' to persist rules" >&2
        else
            echo "WARNING: Could not persist rules automatically. Install iptables-persistent (Debian/Ubuntu) or iptables-services (RHEL) and run iptables-save manually." >&2
        fi
    fi
fi

# ── Output ───────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_attack_surface" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
