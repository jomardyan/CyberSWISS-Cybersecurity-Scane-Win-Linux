#!/usr/bin/env bash
# =============================================================================
# L27 - DNS Resolution Security (Linux)
# =============================================================================
# ID       : L27
# Category : Network Exposure
# Severity : High
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : Yes
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L27_dns_resolution_security.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L27"
SCRIPT_NAME="DNS Resolution Security"
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
            PASS) colour='\033[0;32m' ;;
            WARN) colour='\033[0;33m' ;;
            FAIL) colour='\033[0;31m' ;;
            *)    colour='\033[0;36m' ;;
        esac
        printf "${colour}[%s] [%s] %s: %s\033[0m\n" "$status" "$sev" "$id" "$name"
        [[ -n "$detail" ]] && printf "       Detail : %s\n" "$detail"
        [[ "$status" != "PASS" && -n "$remediation" ]] && printf "\033[0;36m       Remedy : %s\033[0m\n" "$remediation"
    fi
}

read_resolved_setting() {
    local key="$1"
    local file value=""
    local files=(/etc/systemd/resolved.conf)

    if compgen -G '/etc/systemd/resolved.conf.d/*.conf' > /dev/null; then
        while IFS= read -r file; do
            files+=("$file")
        done < <(find /etc/systemd/resolved.conf.d -maxdepth 1 -type f -name '*.conf' | sort)
    fi

    for file in "${files[@]}"; do
        [[ -f "$file" ]] || continue
        value=$(grep -E "^\s*${key}\s*=" "$file" 2>/dev/null | tail -1 | awk -F= '{print $2}' | tr -d "[:space:]" || true)
        if [[ -n "$value" ]]; then
            printf '%s\n' "$value"
            return 0
        fi
    done
    return 1
}

collect_resolvers() {
    local resolvers=""
    if command -v resolvectl &>/dev/null; then
        resolvers=$(resolvectl dns 2>/dev/null | awk '{for (i = 3; i <= NF; i++) print $i}' | grep -E '^[0-9A-Fa-f:.]+$' | sort -u || true)
    fi
    if [[ -z "$resolvers" && -f /etc/resolv.conf ]]; then
        resolvers=$(grep -E '^\s*nameserver\s+' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | sort -u || true)
    fi
    printf '%s\n' "$resolvers" | sed '/^$/d'
}

is_known_public_resolver() {
    case "$1" in
        1.1.1.1|1.0.0.1|8.8.8.8|8.8.4.4|9.9.9.9|149.112.112.112|208.67.222.222|208.67.220.220|94.140.14.14|94.140.15.15|76.76.2.0|76.76.10.0)
            return 0
            ;;
        2606:4700:4700::1111|2606:4700:4700::1001|2001:4860:4860::8888|2001:4860:4860::8844|2620:fe::fe|2620:fe::9|2620:119:35::35|2620:119:53::53)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

is_loopback_resolver() {
    case "$1" in
        127.*|::1|127.0.0.53|127.0.0.54)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

is_loopback_listener() {
    local listener="$1"
    local address="$listener"

    if [[ "$address" == \[*\]:* ]]; then
        address="${address#\[}"
        address="${address%%\]:*}"
    else
        address="${address%:*}"
    fi
    address="${address%%\%*}"

    case "$address" in
        127.*|::1)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

has_systemd_resolved=false
if command -v systemctl &>/dev/null && systemctl list-unit-files systemd-resolved.service >/dev/null 2>&1; then
    has_systemd_resolved=true
fi

# C1 - Resolver file permissions
if [[ -e /etc/resolv.conf ]]; then
    resolv_perm=$(stat -c '%a' /etc/resolv.conf 2>/dev/null || echo "unknown")
    if [[ "$resolv_perm" =~ ^[0-9]{3,4}$ ]]; then
        owner_perms=$(( (10#$resolv_perm / 100) % 10 ))
        group_perms=$(( (10#$resolv_perm / 10) % 10 ))
        other_perms=$(( 10#$resolv_perm % 10 ))
        if (( group_perms & 2 )) || (( other_perms & 2 )); then
            add_finding "${SCRIPT_ID}-C1" "Resolver File Permissions" "High" "FAIL" \
                "/etc/resolv.conf permissions=${resolv_perm} (group/other writable)" \
                "Set secure permissions: chown root:root /etc/resolv.conf && chmod 644 /etc/resolv.conf"
        elif (( owner_perms >= 4 )); then
            add_finding "${SCRIPT_ID}-C1" "Resolver File Permissions" "High" "PASS" \
                "/etc/resolv.conf permissions=${resolv_perm}" ""
        else
            add_finding "${SCRIPT_ID}-C1" "Resolver File Permissions" "High" "WARN" \
                "/etc/resolv.conf permissions=${resolv_perm} are unusual" \
                "Verify resolver file ownership and set chmod 644 unless your distro requires a different mode"
        fi
    else
        add_finding "${SCRIPT_ID}-C1" "Resolver File Permissions" "High" "WARN" \
            "Could not determine /etc/resolv.conf permissions" \
            "Verify /etc/resolv.conf ownership is root:root and not writable by non-root users"
    fi
else
    add_finding "${SCRIPT_ID}-C1" "Resolver File Permissions" "High" "WARN" \
        "/etc/resolv.conf is missing" \
        "Restore resolver configuration or ensure systemd-resolved manages the stub resolver"
fi

# C2 - Resolver trust profile
mapfile -t RESOLVERS < <(collect_resolvers)
if [[ "${#RESOLVERS[@]}" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C2" "Upstream Resolver Trust Profile" "High" "WARN" \
        "No upstream DNS resolvers could be discovered" \
        "Verify resolvectl or /etc/resolv.conf is configured with approved internal DNS resolvers"
else
    public_resolvers=()
    loopback_only=true
    for resolver in "${RESOLVERS[@]}"; do
        is_loopback_resolver "$resolver" || loopback_only=false
        if is_known_public_resolver "$resolver"; then
            public_resolvers+=("$resolver")
        fi
    done

    resolver_list=$(printf '%s ' "${RESOLVERS[@]}" | xargs || true)
    if [[ "${#public_resolvers[@]}" -gt 0 ]]; then
        add_finding "${SCRIPT_ID}-C2" "Upstream Resolver Trust Profile" "High" "WARN" \
            "Approved resolver review needed. Detected public resolver(s): $(printf '%s ' "${public_resolvers[@]}" | xargs). Full set: ${resolver_list}" \
            "Prefer enterprise-managed internal resolvers, DNS filtering, or a validated encrypted resolver policy instead of ad hoc public DNS"
    elif [[ "$loopback_only" == true ]]; then
        add_finding "${SCRIPT_ID}-C2" "Upstream Resolver Trust Profile" "Info" "INFO" \
            "Only loopback/stub resolvers are visible locally: ${resolver_list}" \
            "Verify the local DNS stub forwards to approved internal resolvers"
    else
        add_finding "${SCRIPT_ID}-C2" "Upstream Resolver Trust Profile" "High" "PASS" \
            "Discovered resolvers: ${resolver_list}" ""
    fi
fi

# C3 - DNSSEC validation
dnssec_state=""
if command -v resolvectl &>/dev/null; then
    dnssec_state=$(resolvectl status 2>/dev/null | awk -F': ' '/DNSSEC setting:/ {print tolower($2); exit}' || true)
fi
if [[ -z "$dnssec_state" ]]; then
    dnssec_state=$(read_resolved_setting DNSSEC 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
fi
if [[ -z "$dnssec_state" ]] && [[ -d /etc/unbound ]]; then
    dnssec_state=$(grep -RhiE '^\s*dnssec-validation:\s*(auto|yes)' /etc/unbound 2>/dev/null | head -1 | awk '{print tolower($2)}' || true)
fi

case "$dnssec_state" in
    yes|true|allow-downgrade|auto)
        add_finding "${SCRIPT_ID}-C3" "DNSSEC Validation" "High" "PASS" \
            "DNSSEC validation appears enabled (${dnssec_state})" ""
        ;;
    no|false)
        add_finding "${SCRIPT_ID}-C3" "DNSSEC Validation" "High" "WARN" \
            "DNSSEC validation appears disabled (${dnssec_state})" \
            "Enable DNSSEC validation in systemd-resolved, unbound, or your local DNS forwarder where supported"
        ;;
    *)
        if [[ "$has_systemd_resolved" == true || -d /etc/unbound ]]; then
            add_finding "${SCRIPT_ID}-C3" "DNSSEC Validation" "High" "WARN" \
                "DNSSEC validation is not explicitly configured" \
                "Set DNSSEC=yes or allow-downgrade in systemd-resolved, or dnssec-validation: auto in unbound"
        else
            add_finding "${SCRIPT_ID}-C3" "DNSSEC Validation" "Info" "INFO" \
                "No DNSSEC-capable local resolver configuration was detected" \
                "If this host relies on a local forwarder, explicitly enable DNSSEC validation there"
        fi
        ;;
esac

# C4 - DNS over TLS
dot_state=$(read_resolved_setting DNSOverTLS 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
if [[ -z "$dot_state" ]] && [[ -d /etc/unbound ]]; then
    dot_state=$(grep -RhiE '^\s*forward-tls-upstream:\s*yes' /etc/unbound 2>/dev/null | head -1 | awk '{print tolower($2)}' || true)
fi

case "$dot_state" in
    yes|true|opportunistic)
        add_finding "${SCRIPT_ID}-C4" "Encrypted DNS Transport" "Med" "PASS" \
            "Encrypted DNS transport appears enabled (${dot_state})" ""
        ;;
    no|false)
        add_finding "${SCRIPT_ID}-C4" "Encrypted DNS Transport" "Med" "WARN" \
            "Encrypted DNS transport appears disabled (${dot_state})" \
            "Prefer DNS over TLS or another authenticated enterprise resolver path where operationally supported"
        ;;
    *)
        add_finding "${SCRIPT_ID}-C4" "Encrypted DNS Transport" "Info" "INFO" \
            "No explicit DNS over TLS configuration was detected" \
            "Review whether encrypted DNS transport should be enforced for this host or resolver tier"
        ;;
esac

# C5 - LLMNR and mDNS posture
llmnr_state=$(read_resolved_setting LLMNR 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
mdns_state=$(read_resolved_setting MulticastDNS 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
avahi_active=false
if command -v systemctl &>/dev/null && systemctl is-active --quiet avahi-daemon 2>/dev/null; then
    avahi_active=true
fi

name_resolution_issues=""
[[ "$llmnr_state" != "no" ]] && name_resolution_issues="${name_resolution_issues} LLMNR=${llmnr_state:-default};"
[[ "$mdns_state" != "no" ]] && name_resolution_issues="${name_resolution_issues} MulticastDNS=${mdns_state:-default};"
[[ "$avahi_active" == true ]] && name_resolution_issues="${name_resolution_issues} avahi-daemon=active;"

if [[ -z "$name_resolution_issues" ]]; then
    add_finding "${SCRIPT_ID}-C5" "Multicast Name Resolution" "High" "PASS" \
        "LLMNR and MulticastDNS are disabled and avahi-daemon is not active" ""
else
    add_finding "${SCRIPT_ID}-C5" "Multicast Name Resolution" "High" "WARN" \
        "Name-resolution exposure indicators:${name_resolution_issues}" \
        "Disable LLMNR and MulticastDNS where possible; stop Avahi on hosts that do not require mDNS service discovery"
fi

# C6 - Local DNS listener exposure
dns_listeners=""
if command -v ss &>/dev/null; then
    dns_listeners=$(ss -tulnH 2>/dev/null | awk '$5 ~ /:53$/ {print $5}' | sort -u || true)
elif command -v netstat &>/dev/null; then
    dns_listeners=$(netstat -tuln 2>/dev/null | awk '$4 ~ /:53$/ {print $4}' | sort -u || true)
fi

if [[ -z "$dns_listeners" ]]; then
    add_finding "${SCRIPT_ID}-C6" "DNS Service Exposure" "Med" "INFO" \
        "No local DNS listener on port 53 was detected" ""
else
    exposed_listeners=""
    while IFS= read -r listener; do
        [[ -z "$listener" ]] && continue
        if ! is_loopback_listener "$listener"; then
            exposed_listeners="${exposed_listeners} ${listener}"
        fi
    done <<< "$dns_listeners"

    if [[ -z "$exposed_listeners" ]]; then
        add_finding "${SCRIPT_ID}-C6" "DNS Service Exposure" "Med" "PASS" \
            "DNS listeners are restricted to loopback/stub addresses: $(echo "$dns_listeners" | xargs)" ""
    else
        add_finding "${SCRIPT_ID}-C6" "DNS Service Exposure" "High" "FAIL" \
            "DNS listener exposed beyond loopback: $(echo "$exposed_listeners" | xargs)" \
            "Restrict local DNS services to loopback or approved interfaces only, and firewall port 53 from untrusted networks"
    fi
fi

if [[ "$FIX_MODE" == true ]]; then
    if [[ "${EUID}" -ne 0 ]]; then
        echo "INFO: --fix requires root to write resolver policy drop-ins." >&2
    elif [[ "$has_systemd_resolved" == true ]]; then
        mkdir -p /etc/systemd/resolved.conf.d
        cat > /etc/systemd/resolved.conf.d/99-cyberswiss-security.conf <<'EOF'
[Resolve]
LLMNR=no
MulticastDNS=no
EOF
        if command -v systemctl &>/dev/null; then
            systemctl restart systemd-resolved 2>/dev/null || true
        fi
        echo "INFO: --fix wrote /etc/systemd/resolved.conf.d/99-cyberswiss-security.conf and attempted to restart systemd-resolved." >&2
        echo "      DNSSEC and DNS-over-TLS were not changed automatically because they are resolver-environment specific." >&2
    else
        echo "INFO: --fix: No supported automatic remediation path for this host's DNS stack." >&2
    fi
fi

if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_dns_resolution_security" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
else
    echo ""
    echo "=== ${SCRIPT_ID} ${SCRIPT_NAME} - ${HOSTNAME_VAL} ==="
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
