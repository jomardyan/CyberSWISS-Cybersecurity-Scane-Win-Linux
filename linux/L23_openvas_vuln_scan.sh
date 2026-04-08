#!/usr/bin/env bash
# =============================================================================
# L23 – OpenVAS / Nessus-Style Comprehensive Vulnerability Scanner (Linux)
# =============================================================================
# ID       : L23
# Category : Vulnerability Assessment
# Severity : Critical
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : Yes
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L23_openvas_vuln_scan.sh [--json] [--fix]
#
# Description
# -----------
# Performs an OpenVAS / Nessus-style infrastructure vulnerability assessment:
#   C1  – OpenVAS/Nessus scanner availability and last-scan status
#   C2  – SSL/TLS certificate validity on common HTTPS services
#   C3  – Weak TLS protocol exposure (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
#   C4  – Insecure / legacy protocols in use (Telnet, FTP, rsh/rlogin, rexec)
#   C5  – Samba/SMB version and SMBv1 exposure
#   C6  – Anonymous FTP access
#   C7  – SNMP default community strings (public/private)
#   C8  – Kernel version CVE cross-reference
#   C9  – Unpatched high-severity packages (CVE metadata from OSV / distro feeds)
#   C10 – Web server security-header hardening
# =============================================================================
set -euo pipefail

SCRIPT_ID="L23"
SCRIPT_NAME="OpenVAS / Nessus-Style Vulnerability Scanner"
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

# ── C1 – OpenVAS / Nessus scanner presence ────────────────────────────────────
openvas_info=""
scanner_found=false
if command -v openvas &>/dev/null || command -v openvasmd &>/dev/null || command -v gvm-cli &>/dev/null; then
    scanner_found=true
    openvas_info="OpenVAS/GVM CLI found"
fi
if command -v nessuscli &>/dev/null || [[ -x /opt/nessus/sbin/nessuscli ]]; then
    scanner_found=true
    openvas_info="${openvas_info} Nessus CLI found"
fi

if [[ "$scanner_found" == true ]]; then
    # Check for recent scan results
    recent_report=""
    for report_dir in /var/lib/openvas /var/lib/gvm/openvas /opt/nessus/var; do
        if [[ -d "$report_dir" ]]; then
            recent=$(find "$report_dir" -name "*.xml" -o -name "*.nessus" 2>/dev/null \
                | xargs ls -t 2>/dev/null | head -1 || true)
            [[ -n "$recent" ]] && recent_report="$recent"
        fi
    done
    if [[ -n "$recent_report" ]]; then
        age_days=$(( ($(date +%s) - $(stat -c %Y "$recent_report" 2>/dev/null || echo 0)) / 86400 ))
        if [[ "$age_days" -le 7 ]]; then
            add_finding "${SCRIPT_ID}-C1" "Vulnerability Scanner Last Scan" "Info" "PASS" \
                "${openvas_info}. Most recent report: ${recent_report} (${age_days}d ago)" ""
        else
            add_finding "${SCRIPT_ID}-C1" "Vulnerability Scanner Last Scan" "High" "WARN" \
                "${openvas_info}. Last scan report is ${age_days} days old: ${recent_report}" \
                "Schedule weekly vulnerability scans. Configure automated scanning in OpenVAS/GVM."
        fi
    else
        add_finding "${SCRIPT_ID}-C1" "Vulnerability Scanner Last Scan" "High" "WARN" \
            "${openvas_info}. No recent scan reports found." \
            "Run a full authenticated scan against this host: openvas-start && gvm-cli scan"
    fi
else
    add_finding "${SCRIPT_ID}-C1" "Vulnerability Scanner Presence" "High" "WARN" \
        "No OpenVAS/GVM or Nessus scanner detected on this host." \
        "Install OpenVAS/GVM (apt-get install gvm) or deploy a Nessus agent for continuous vulnerability assessment."
fi

# ── C2 – SSL/TLS certificate validity ────────────────────────────────────────
cert_issues=""
if command -v openssl &>/dev/null; then
    for port in 443 8443 8080; do
        # Check if port is listening
        if command -v ss &>/dev/null; then
            listening=$(ss -tlnp 2>/dev/null | awk '{print $4}' | grep -E ":${port}$" || true)
        else
            listening=$(netstat -tlnp 2>/dev/null | awk '{print $4}' | grep -E ":${port}$" || true)
        fi
        [[ -z "$listening" ]] && continue

        cert_info=$(echo | openssl s_client -connect "localhost:${port}" -servername localhost \
            -verify_return_error 2>/dev/null </dev/null 2>/dev/null | \
            openssl x509 -noout -dates -subject 2>/dev/null || true)
        [[ -z "$cert_info" ]] && continue

        not_after=$(echo "$cert_info" | grep 'notAfter' | cut -d= -f2 || true)
        if [[ -n "$not_after" ]]; then
            expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null || true)
            now_epoch=$(date +%s)
            if [[ -n "$expiry_epoch" ]]; then
                days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
                if [[ "$days_left" -lt 0 ]]; then
                    cert_issues="${cert_issues} port${port}:EXPIRED(${not_after});"
                elif [[ "$days_left" -lt 30 ]]; then
                    cert_issues="${cert_issues} port${port}:EXPIRES_SOON(${days_left}d);"
                fi
            fi
        fi

        # Check for self-signed cert
        subject=$(echo "$cert_info" | grep 'subject=' | sed 's/subject=//' || true)
        issuer=$(echo | openssl s_client -connect "localhost:${port}" -servername localhost 2>/dev/null </dev/null 2>/dev/null | \
            openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer=//' || true)
        if [[ -n "$subject" && -n "$issuer" && "$subject" == "$issuer" ]]; then
            cert_issues="${cert_issues} port${port}:SELF-SIGNED;"
        fi
    done
fi

if [[ -z "$cert_issues" ]]; then
    add_finding "${SCRIPT_ID}-C2" "SSL/TLS Certificate Validity" "High" "PASS" \
        "All checked HTTPS listeners have valid, non-expired certificates" ""
else
    add_finding "${SCRIPT_ID}-C2" "SSL/TLS Certificate Validity" "High" "FAIL" \
        "Certificate issue(s) detected:${cert_issues}" \
        "Replace expired/self-signed certificates with CA-signed certs. Use Let's Encrypt (certbot) for automation."
fi

# ── C3 – Weak TLS protocol exposure ──────────────────────────────────────────
tls_issues=""
if command -v openssl &>/dev/null; then
    for port in 443 8443; do
        if command -v ss &>/dev/null; then
            listening=$(ss -tlnp 2>/dev/null | awk '{print $4}' | grep -E ":${port}$" || true)
        else
            listening=$(netstat -tlnp 2>/dev/null | awk '{print $4}' | grep -E ":${port}$" || true)
        fi
        [[ -z "$listening" ]] && continue

        for proto in ssl2 ssl3 tls1 tls1_1; do
            result=$(echo | timeout 5 openssl s_client -connect "localhost:${port}" \
                -"${proto}" 2>&1 </dev/null || true)
            if echo "$result" | grep -q "CONNECTED"; then
                tls_issues="${tls_issues} port${port}:${proto}-accepted;"
            fi
        done
    done
fi

if [[ -z "$tls_issues" ]]; then
    add_finding "${SCRIPT_ID}-C3" "Weak TLS Protocol Exposure" "Critical" "PASS" \
        "No SSLv2/SSLv3/TLS1.0/TLS1.1 acceptance detected on checked HTTPS listeners" ""
else
    add_finding "${SCRIPT_ID}-C3" "Weak TLS Protocol Exposure" "Critical" "FAIL" \
        "Weak protocol(s) accepted:${tls_issues}" \
        "Disable SSLv2/3, TLS1.0, TLS1.1. Configure only TLS 1.2 and TLS 1.3. See: ssl_protocols TLSv1.2 TLSv1.3 (nginx)"
fi

# ── C4 – Insecure / legacy protocols ─────────────────────────────────────────
insecure_services=""
declare -A LEGACY_PORTS=(
    [23]="Telnet"
    [21]="FTP"
    [514]="rsh"
    [513]="rlogin"
    [512]="rexec"
    [69]="TFTP"
    [79]="Finger"
)

for port in "${!LEGACY_PORTS[@]}"; do
    svc="${LEGACY_PORTS[$port]}"
    if command -v ss &>/dev/null; then
        listening=$(ss -tlnp 2>/dev/null | awk '{print $4}' | grep -E ":${port}$" || true)
        udp_listening=$(ss -ulnp 2>/dev/null | awk '{print $4}' | grep -E ":${port}$" || true)
    else
        listening=$(netstat -tlnp 2>/dev/null | awk '{print $4}' | grep -E ":${port}$" || true)
        udp_listening=$(netstat -ulnp 2>/dev/null | awk '{print $4}' | grep -E ":${port}$" || true)
    fi
    if [[ -n "$listening" || -n "$udp_listening" ]]; then
        insecure_services="${insecure_services} ${svc}(${port});"
    fi
done

if [[ -z "$insecure_services" ]]; then
    add_finding "${SCRIPT_ID}-C4" "Insecure Legacy Protocol Exposure" "Critical" "PASS" \
        "No insecure legacy protocols (Telnet/FTP/rsh/rlogin/rexec/TFTP/Finger) detected" ""
else
    add_finding "${SCRIPT_ID}-C4" "Insecure Legacy Protocol Exposure" "Critical" "FAIL" \
        "Legacy/insecure service(s) listening:${insecure_services}" \
        "Disable legacy protocols. Replace Telnet with SSH, FTP with SFTP, rsh with SSH. Disable unused services."
fi

# ── C5 – Samba/SMB version and SMBv1 exposure ────────────────────────────────
smb_issues=""
if command -v smbstatus &>/dev/null || command -v smbd &>/dev/null; then
    smb_ver=$(smbd --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
    if [[ -n "$smb_ver" ]]; then
        major=$(echo "$smb_ver" | cut -d. -f1)
        minor=$(echo "$smb_ver" | cut -d. -f2)
        patch=$(echo "$smb_ver" | cut -d. -f3)
        # Samba < 4.17.12 / < 4.18.8 / < 4.19.1 has CVE-2023-3961, CVE-2023-4091 etc.
        if [[ "$major" -lt 4 ]] || { [[ "$major" -eq 4 && "$minor" -lt 17 ]]; }; then
            smb_issues="${smb_issues} samba/${smb_ver}(outdated-CVE-risk);"
        fi
    fi

    # Check SMBv1 enabled in smb.conf
    smb_conf=""
    for conf in /etc/samba/smb.conf /etc/smb.conf; do
        [[ -f "$conf" ]] && smb_conf="$conf" && break
    done
    if [[ -n "$smb_conf" ]]; then
        if grep -qiE 'min[[:space:]]+protocol[[:space:]]*=[[:space:]]*(NT1|LANMAN|CORE)' "$smb_conf" 2>/dev/null; then
            smb_issues="${smb_issues} SMBv1-enabled-in-conf;"
        fi
        if ! grep -qiE 'min[[:space:]]+protocol' "$smb_conf" 2>/dev/null; then
            smb_issues="${smb_issues} no-min-protocol-set(SMBv1-may-be-default);"
        fi
    fi
fi

# Check SMB port directly
for port in 139 445; do
    if command -v ss &>/dev/null; then
        listening=$(ss -tlnp 2>/dev/null | awk '{print $4}' | grep -E ":${port}$" || true)
    else
        listening=$(netstat -tlnp 2>/dev/null | awk '{print $4}' | grep -E ":${port}$" || true)
    fi
    [[ -n "$listening" ]] && smb_issues="${smb_issues} SMB-port-${port}-open;"
done

if [[ -z "$smb_issues" ]]; then
    add_finding "${SCRIPT_ID}-C5" "Samba/SMB Version and SMBv1 Exposure" "Critical" "PASS" \
        "No Samba installation or SMB port exposure detected" ""
else
    add_finding "${SCRIPT_ID}-C5" "Samba/SMB Version and SMBv1 Exposure" "Critical" "WARN" \
        "SMB/Samba issue(s):${smb_issues}" \
        "Set 'min protocol = SMB2' in smb.conf. Upgrade Samba to latest stable. Restrict SMB ports at firewall."
fi

# ── C6 – Anonymous FTP access ─────────────────────────────────────────────────
anon_ftp=false
if command -v ftp &>/dev/null; then
    if command -v ss &>/dev/null; then
        ftp_open=$(ss -tlnp 2>/dev/null | awk '{print $4}' | grep -E ":21$" || true)
    else
        ftp_open=$(netstat -tlnp 2>/dev/null | awk '{print $4}' | grep -E ":21$" || true)
    fi
    if [[ -n "$ftp_open" ]]; then
        ftp_result=$(echo -e "user anonymous anon@test.com\nquit\n" | \
            timeout 8 ftp -n -v localhost 2>&1 || true)
        if echo "$ftp_result" | grep -qiE '230|Login successful|logged in'; then
            anon_ftp=true
        fi
    fi
fi

# Also check vsftpd / proftpd config
for conf in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf /etc/proftpd/proftpd.conf; do
    [[ -f "$conf" ]] || continue
    if grep -qiE 'anonymous_enable\s*=\s*YES' "$conf" 2>/dev/null; then
        anon_ftp=true
    fi
    if grep -qiE '^\s*<Anonymous\s' "$conf" 2>/dev/null; then
        anon_ftp=true
    fi
done

if [[ "$anon_ftp" == true ]]; then
    add_finding "${SCRIPT_ID}-C6" "Anonymous FTP Access" "Critical" "FAIL" \
        "Anonymous FTP login is enabled on this host." \
        "Disable anonymous FTP: set 'anonymous_enable=NO' in vsftpd.conf. Use SFTP (SSH) instead of FTP."
else
    add_finding "${SCRIPT_ID}-C6" "Anonymous FTP Access" "Critical" "PASS" \
        "Anonymous FTP login not detected" ""
fi

# ── C7 – SNMP default community strings ───────────────────────────────────────
snmp_issues=""
if command -v ss &>/dev/null; then
    snmp_open=$(ss -ulnp 2>/dev/null | awk '{print $4}' | grep -E ":161$" || true)
else
    snmp_open=$(netstat -ulnp 2>/dev/null | awk '{print $4}' | grep -E ":161$" || true)
fi

if [[ -n "$snmp_open" ]]; then
    # Check snmpd.conf for default community strings
    for conf in /etc/snmp/snmpd.conf /etc/snmpd.conf; do
        [[ -f "$conf" ]] || continue
        if grep -qiE '^[[:space:]]*(rocommunity|rwcommunity)[[:space:]]+(public|private)' "$conf" 2>/dev/null; then
            community=$(grep -iE '^[[:space:]]*(rocommunity|rwcommunity)[[:space:]]+(public|private)' "$conf" | \
                awk '{print $1":"$2}' | tr '\n' ' ' || true)
            snmp_issues="${snmp_issues} default-community:${community};"
        fi
    done

    if command -v snmpwalk &>/dev/null; then
        for community in public private; do
            result=$(timeout 5 snmpwalk -v2c -c "$community" -r 1 -t 3 localhost system 2>&1 || true)
            if echo "$result" | grep -qiE 'sysDescr|sysName'; then
                snmp_issues="${snmp_issues} community-${community}-accepted;"
            fi
        done
    fi

    if [[ -z "$snmp_issues" ]]; then
        add_finding "${SCRIPT_ID}-C7" "SNMP Default Community Strings" "Critical" "PASS" \
            "SNMP port 161 open but no default community strings accepted" ""
    else
        add_finding "${SCRIPT_ID}-C7" "SNMP Default Community Strings" "Critical" "FAIL" \
            "SNMP issue(s):${snmp_issues}" \
            "Change SNMP community strings from 'public'/'private'. Use SNMPv3 with authentication and privacy. Restrict SNMP to management network."
    fi
else
    add_finding "${SCRIPT_ID}-C7" "SNMP Default Community Strings" "Info" "PASS" \
        "SNMP UDP port 161 is not listening" ""
fi

# ── C8 – Kernel version CVE cross-reference ───────────────────────────────────
kernel_ver=$(uname -r 2>/dev/null || true)
kernel_issues=""

if [[ -n "$kernel_ver" ]]; then
    # Extract base version (remove arch/distro suffix)
    kernel_base=$(echo "$kernel_ver" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' || true)
    if [[ -n "$kernel_base" ]]; then
        major=$(echo "$kernel_base" | cut -d. -f1)
        minor=$(echo "$kernel_base" | cut -d. -f2)
        patch=$(echo "$kernel_base" | cut -d. -f3)

        # Known CVE thresholds for LTS kernels
        # 5.4 LTS: CVE-2022-0847 (DirtyPipe) affected < 5.8; CVE-2021-4034 (Polkit PwnKit)
        # 5.15 LTS: CVE-2023-3269 affected < 6.1.37
        if [[ "$major" -eq 4 && "$minor" -lt 19 ]]; then
            kernel_issues="kernel ${kernel_ver}: < 4.19 – multiple unpatched CVEs, EOL LTS"
        elif [[ "$major" -eq 5 && "$minor" -lt 4 ]]; then
            kernel_issues="kernel ${kernel_ver}: < 5.4 LTS – not on supported LTS branch"
        elif [[ "$major" -eq 5 && "$minor" -eq 4 && "$patch" -lt 200 ]]; then
            kernel_issues="kernel ${kernel_ver}: 5.4.x older patch – may lack recent CVE fixes"
        elif [[ "$major" -lt 4 ]]; then
            kernel_issues="kernel ${kernel_ver}: version ${major}.x is EOL and critically outdated"
        fi

        # DirtyPipe: CVE-2022-0847 affects 5.8–5.16 (patched in 5.16.11, 5.15.25, 5.10.102)
        if [[ "$major" -eq 5 ]]; then
            if [[ "$minor" -eq 8 || "$minor" -eq 9 || "$minor" -eq 10 && "$patch" -lt 102 ]]; then
                kernel_issues="${kernel_issues} CVE-2022-0847(DirtyPipe-risk);"
            elif [[ "$minor" -eq 15 && "$patch" -lt 25 ]]; then
                kernel_issues="${kernel_issues} CVE-2022-0847(DirtyPipe-risk);"
            elif [[ "$minor" -eq 16 && "$patch" -lt 11 ]]; then
                kernel_issues="${kernel_issues} CVE-2022-0847(DirtyPipe-risk);"
            fi
        fi
    fi

    # Check if kernel has known vulnerabilities via sysfs
    if [[ -d /sys/devices/system/cpu/vulnerabilities ]]; then
        vuln_count=$(grep -rl 'Vulnerable' /sys/devices/system/cpu/vulnerabilities/ 2>/dev/null | wc -l || true)
        if [[ "$vuln_count" -gt 0 ]]; then
            kernel_issues="${kernel_issues} ${vuln_count}-CPU-vulnerability(ies)-unmitigated;"
        fi
    fi
fi

if [[ -z "$kernel_issues" ]]; then
    add_finding "${SCRIPT_ID}-C8" "Kernel CVE Cross-Reference" "Critical" "PASS" \
        "Kernel ${kernel_ver} – no critical version-level CVE flags detected" ""
else
    add_finding "${SCRIPT_ID}-C8" "Kernel CVE Cross-Reference" "Critical" "FAIL" \
        "Kernel issue(s): ${kernel_issues}" \
        "Update kernel to latest LTS release for your distribution. Run: apt-get install linux-image-generic OR dnf update kernel"
fi

# ── C9 – Unpatched packages with known CVEs ───────────────────────────────────
cve_pkg_issues=""
if command -v apt-get &>/dev/null && command -v apt-cache &>/dev/null; then
    # Use debian-security to count packages with security fixes pending
    unattended_upgrades_avail=$(apt-get -s upgrade 2>/dev/null \
        | grep -c '^Inst' || true)
    security_upgrades=$(apt-get -s upgrade 2>/dev/null \
        | grep '^Inst' | grep -ci 'security' || true)
    if [[ "$security_upgrades" -gt 0 ]]; then
        cve_pkg_issues="${security_upgrades} security packages pending (total upgrades: ${unattended_upgrades_avail})"
    elif [[ "$unattended_upgrades_avail" -gt 10 ]]; then
        cve_pkg_issues="${unattended_upgrades_avail} package upgrades pending – security CVEs may be included"
    fi
elif command -v dnf &>/dev/null; then
    sec_count=$(dnf check-update --security 2>/dev/null | grep -cE '\.' || true)
    if [[ "$sec_count" -gt 0 ]]; then
        cve_pkg_issues="${sec_count} packages have pending security updates via dnf"
    fi
elif command -v yum &>/dev/null; then
    sec_count=$(yum check-update --security 2>/dev/null | grep -cE '\.' || true)
    if [[ "$sec_count" -gt 0 ]]; then
        cve_pkg_issues="${sec_count} packages have pending security updates via yum"
    fi
fi

# Additional: check if unattended-upgrades is configured (Debian/Ubuntu)
if command -v apt-get &>/dev/null; then
    ua_conf="/etc/apt/apt.conf.d/50unattended-upgrades"
    ua_enabled="/etc/apt/apt.conf.d/20auto-upgrades"
    ua_active=false
    if [[ -f "$ua_enabled" ]] && grep -qE 'APT::Periodic::Unattended-Upgrade[[:space:]]+"1"' "$ua_enabled" 2>/dev/null; then
        ua_active=true
    fi
    if [[ "$ua_active" == false ]]; then
        cve_pkg_issues="${cve_pkg_issues} Automatic security updates (unattended-upgrades) not enabled;"
    fi
fi

if [[ -z "$cve_pkg_issues" ]]; then
    add_finding "${SCRIPT_ID}-C9" "Unpatched Packages / CVE Exposure" "Critical" "PASS" \
        "No pending security package updates detected" ""
else
    add_finding "${SCRIPT_ID}-C9" "Unpatched Packages / CVE Exposure" "Critical" "FAIL" \
        "${cve_pkg_issues}" \
        "Apply security patches: apt-get upgrade -y OR dnf update --security -y. Enable unattended-upgrades for automatic security updates."
fi

# ── C10 – Web server security-header hardening ────────────────────────────────
header_issues=""
if command -v curl &>/dev/null; then
    for port in 80 443 8080 8443; do
        scheme="http"
        [[ "$port" == "443" || "$port" == "8443" ]] && scheme="https"

        # Check if port is listening
        if command -v ss &>/dev/null; then
            listening=$(ss -tlnp 2>/dev/null | awk '{print $4}' | grep -E ":${port}$" || true)
        else
            listening=$(netstat -tlnp 2>/dev/null | awk '{print $4}' | grep -E ":${port}$" || true)
        fi
        [[ -z "$listening" ]] && continue

        headers=$(curl -k --connect-timeout 4 --max-time 8 -sI "${scheme}://localhost:${port}/" 2>/dev/null || true)
        [[ -z "$headers" ]] && continue

        # Check for missing security headers
        missing=""
        echo "$headers" | grep -qi 'Strict-Transport-Security'  || missing="${missing} HSTS;"
        echo "$headers" | grep -qi 'X-Content-Type-Options'     || missing="${missing} X-Content-Type-Options;"
        echo "$headers" | grep -qi 'X-Frame-Options'            || missing="${missing} X-Frame-Options;"
        echo "$headers" | grep -qi 'Content-Security-Policy'    || missing="${missing} CSP;"
        echo "$headers" | grep -qi 'Referrer-Policy'            || missing="${missing} Referrer-Policy;"

        # Check for server version disclosure
        server_header=$(echo "$headers" | grep -i '^Server:' | head -1 || true)
        if echo "$server_header" | grep -qiE '[0-9]+\.[0-9]+'; then
            missing="${missing} Server-version-disclosed(${server_header});"
        fi

        [[ -n "$missing" ]] && header_issues="${header_issues} port${port}:[${missing}]"
    done
fi

if [[ -z "$header_issues" ]]; then
    add_finding "${SCRIPT_ID}-C10" "Web Server Security Headers" "Med" "PASS" \
        "All detected web listeners have required security headers" ""
else
    add_finding "${SCRIPT_ID}-C10" "Web Server Security Headers" "Med" "WARN" \
        "Missing security header(s):${header_issues}" \
        "Add security headers: HSTS, X-Content-Type-Options: nosniff, X-Frame-Options: DENY, CSP, Referrer-Policy. Suppress server version in headers."
fi

# ── Optional Fix ──────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "INFO: Applying available automated fixes for L23 findings..." >&2
    # Disable Telnet service if running
    if systemctl is-active telnet.socket &>/dev/null 2>&1; then
        systemctl stop telnet.socket && systemctl disable telnet.socket && \
            echo "Telnet socket disabled." >&2
    fi
    # Enable unattended-upgrades on Debian/Ubuntu
    if command -v apt-get &>/dev/null && ! dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii'; then
        apt-get install -y unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades && \
            echo "Unattended-upgrades installed and configured." >&2
    fi
    echo "NOTE: SMB, TLS, SNMP, and certificate fixes require manual configuration." >&2
fi

# ── Output ────────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_openvas_vuln_scan" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
