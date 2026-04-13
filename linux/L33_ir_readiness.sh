#!/usr/bin/env bash
# =============================================================================
# L33 – Incident Response Readiness (Linux)
# =============================================================================
# ID       : L33
# Category : Detection & Response
# Severity : High
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : Yes
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L33_ir_readiness.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L33"
SCRIPT_NAME="Incident Response Readiness"
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

# ── C1: auditd presence and status ───────────────────────────────────────────
if command -v auditd &>/dev/null || command -v auditctl &>/dev/null; then
    auditd_active=$(systemctl is-active auditd 2>/dev/null || echo "unknown")
    if [[ "$auditd_active" == "active" ]]; then
        rule_count=$(auditctl -l 2>/dev/null | grep -c '^-' || echo 0)
        add_finding "${SCRIPT_ID}-C1" "auditd Active" "High" "PASS" \
            "auditd is running with ${rule_count} rule(s) loaded" ""
    else
        add_finding "${SCRIPT_ID}-C1" "auditd Not Active" "High" "FAIL" \
            "auditd is installed but status is: ${auditd_active}" \
            "Enable: systemctl enable --now auditd; load rules from /etc/audit/rules.d/"
    fi
else
    add_finding "${SCRIPT_ID}-C1" "auditd Not Installed" "High" "FAIL" \
        "auditd is not installed. No kernel-level activity logging available." \
        "Install: apt-get install auditd audispd-plugins OR dnf install audit; systemctl enable --now auditd"
fi

# ── C2: rsyslog / syslog-ng / systemd-journald log forwarding ────────────────
log_forwarding=false
fwd_detail=""

# Check rsyslog remote forwarding
if [[ -d /etc/rsyslog.d ]] || [[ -f /etc/rsyslog.conf ]]; then
    if grep -rqE '^\*\.\*\s+(@@?|action\(type="omfwd")' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null; then
        log_forwarding=true
        fwd_detail="rsyslog remote forwarding configured"
    fi
fi
# Check syslog-ng
if [[ -d /etc/syslog-ng ]]; then
    if grep -rq 'tcp\|udp\|syslog-ng-tcp\|network(' /etc/syslog-ng/ 2>/dev/null; then
        log_forwarding=true
        fwd_detail="syslog-ng remote destination configured"
    fi
fi

if [[ "$log_forwarding" == true ]]; then
    add_finding "${SCRIPT_ID}-C2" "Remote Log Forwarding Configured" "High" "PASS" \
        "${fwd_detail}" ""
else
    add_finding "${SCRIPT_ID}-C2" "No Remote Log Forwarding Detected" "High" "WARN" \
        "Logs appear to be stored locally only. No SIEM/remote syslog forwarding detected." \
        "Configure rsyslog forwarding: *.* @@siem.example.com:514 in /etc/rsyslog.d/forwarding.conf"
fi

# ── C3: Log retention (journald + syslog) ────────────────────────────────────
journal_retention=""
if [[ -f /etc/systemd/journald.conf ]]; then
    journal_retention=$(grep -i 'MaxRetentionSec\|MaxFileSec' /etc/systemd/journald.conf 2>/dev/null | tr '\n' ' ' || true)
fi
journal_disk=$(journalctl --disk-usage 2>/dev/null | grep -oE '[0-9.]+ [KMGT]?' | head -1 || echo "unknown")

if [[ -z "$journal_retention" ]]; then
    add_finding "${SCRIPT_ID}-C3" "Journal Retention Not Explicitly Configured" "Med" "WARN" \
        "MaxRetentionSec/MaxFileSec not set in journald.conf. Default retention applies (limited by disk). Current usage: ${journal_disk}" \
        "Set explicit retention: MaxRetentionSec=7776000 (90 days) in /etc/systemd/journald.conf"
else
    add_finding "${SCRIPT_ID}-C3" "Journal Retention Configured" "Med" "PASS" \
        "journald retention settings: ${journal_retention}; current disk usage: ${journal_disk}" ""
fi

# ── C4: Time synchronisation ─────────────────────────────────────────────────
time_sync=false
time_detail=""

for svc in systemd-timesyncd chronyd ntpd; do
    if systemctl is-active "$svc" &>/dev/null; then
        time_sync=true
        time_detail="$svc is active"
        break
    fi
done
# Also check if timedatectl shows synchronised
if timedatectl status 2>/dev/null | grep -q "synchronized: yes"; then
    time_sync=true
    time_detail="${time_detail} (clock synchronized)"
fi

if [[ "$time_sync" == true ]]; then
    add_finding "${SCRIPT_ID}-C4" "Time Synchronisation Active" "High" "PASS" \
        "${time_detail}" ""
else
    add_finding "${SCRIPT_ID}-C4" "No Time Synchronisation Service Active" "High" "FAIL" \
        "NTP/chrony/systemd-timesyncd not running. Logs lack reliable timestamps for forensic correlation." \
        "Enable: systemctl enable --now systemd-timesyncd OR install chrony: apt-get install chrony && systemctl enable --now chronyd"
fi

# ── C5: Core dump / crash collection ─────────────────────────────────────────
coredump_dest=""
if [[ -f /etc/systemd/coredump.conf ]] || [[ -d /etc/systemd/coredump.conf.d ]]; then
    coredump_dest=$(grep -rh 'Storage=' /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/ 2>/dev/null | head -1 || echo "")
fi
coredumpctl_ok=false
command -v coredumpctl &>/dev/null && coredumpctl_ok=true

if [[ "$coredumpctl_ok" == true ]] && [[ "${coredump_dest}" != "Storage=none" ]]; then
    add_finding "${SCRIPT_ID}-C5" "System Crash Dump Collection Available" "Med" "PASS" \
        "coredumpctl available; core storage: ${coredump_dest:-default}" ""
else
    add_finding "${SCRIPT_ID}-C5" "Core Dump Collection Not Configured" "Med" "WARN" \
        "systemd-coredump/coredumpctl not available or storage disabled. Crash evidence may be lost." \
        "Ensure systemd-coredump is installed and Storage is not set to none in /etc/systemd/coredump.conf"
fi

# ── C6: Forensic / triage tools availability ─────────────────────────────────
required_tools=(ss netstat lsof ps strace strings file hexdump md5sum sha256sum)
missing_tools=()
for t in "${required_tools[@]}"; do
    command -v "$t" &>/dev/null || missing_tools+=("$t")
done

if [[ "${#missing_tools[@]}" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C6" "Forensic Triage Tools Available" "Med" "PASS" \
        "All required triage tools present: ${required_tools[*]}" ""
else
    add_finding "${SCRIPT_ID}-C6" "Missing Forensic Triage Tools" "Med" "WARN" \
        "Missing tools: ${missing_tools[*]}" \
        "Install: apt-get install iproute2 procps lsof strace binutils coreutils"
fi

# ── C7: Memory acquisition capability ────────────────────────────────────────
avml_present=false
lime_present=false
command -v avml &>/dev/null     && avml_present=true
find /lib/modules -name 'lime*.ko' 2>/dev/null | grep -q '.' && lime_present=true

if [[ "$avml_present" == true ]] || [[ "$lime_present" == true ]]; then
    add_finding "${SCRIPT_ID}-C7" "Memory Acquisition Tool Available" "Med" "PASS" \
        "avml=${avml_present}, LiME=${lime_present}" ""
else
    add_finding "${SCRIPT_ID}-C7" "No Memory Acquisition Tool Detected" "Med" "INFO" \
        "Neither AVML nor LiME found. Live memory forensics capability may be absent." \
        "Download AVML from https://github.com/microsoft/avml or build LiME from https://github.com/504ensicsLabs/LiME"
fi

# ── C8: Incident response playbook / contact file ─────────────────────────────
ir_docs_found=false
for path in /etc/ir /etc/incident \
            /opt/security /usr/local/share/ir \
            /var/log/ir_plan.txt /etc/ir_contacts.txt; do
    if [[ -e "$path" ]]; then
        ir_docs_found=true
        break
    fi
done

if [[ "$ir_docs_found" == true ]]; then
    add_finding "${SCRIPT_ID}-C8" "IR Documentation Found" "Med" "PASS" \
        "IR playbook/contact file found on endpoint" ""
else
    add_finding "${SCRIPT_ID}-C8" "No IR Documentation Detected on Endpoint" "Med" "INFO" \
        "No IR playbook or contact file found in standard locations (/etc/ir, /opt/security, etc.)" \
        "Place IR contacts and basic playbook at /etc/ir/contacts.txt for first-responder awareness"
fi

# ── C9: Sysmon for Linux (Sysinternals sysmon) ───────────────────────────────
if command -v sysmon &>/dev/null; then
    sysmon_state=$(sysmon -s 2>/dev/null | head -3 || echo "unknown")
    add_finding "${SCRIPT_ID}-C9" "Sysmon for Linux Present" "High" "PASS" \
        "sysmon binary found. ${sysmon_state}" ""
else
    add_finding "${SCRIPT_ID}-C9" "Sysmon for Linux Not Installed" "High" "INFO" \
        "Microsoft Sysmon not found. auditd is the primary alternative for process/network telemetry." \
        "Install Sysmon for Linux from Microsoft's sysinternalsuite for high-fidelity event logging"
fi

# ── Optional Fix ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "INFO: --fix mode: attempting to enable/start time sync..." >&2
    if ! systemctl is-active systemd-timesyncd &>/dev/null && ! systemctl is-active chronyd &>/dev/null; then
        systemctl enable --now systemd-timesyncd 2>/dev/null && \
            echo "Fixed: systemd-timesyncd enabled" >&2 || echo "Could not enable systemd-timesyncd" >&2
    fi
fi

# ── Output ────────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_ir_readiness" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
