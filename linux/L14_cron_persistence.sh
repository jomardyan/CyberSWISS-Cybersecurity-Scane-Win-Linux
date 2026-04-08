#!/usr/bin/env bash
# =============================================================================
# L14 – Cron Jobs & Persistence Review (Linux)
# =============================================================================
# ID       : L14
# Category : Persistence & Scheduled Tasks
# Severity : High
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : Yes (root to read all crontabs)
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L14_cron_persistence.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L14"
SCRIPT_NAME="Cron Jobs & Persistence Review"
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

# Suspicious patterns in cron commands
SUSPICIOUS_PATTERNS=(
    "curl.*http\|wget.*http"
    "base64\s*-d\|base64\s*--decode"
    "bash\s*-i\|sh\s*-i"
    "/tmp/\|/var/tmp/"
    "mkfifo\|nc\s\|ncat\|socat"
    "chmod\s*[0-9]*7[57]"
    "python.*-c\|perl.*-e\|ruby.*-e"
    "eval\s*(.*)"
    "/dev/tcp\|/dev/udp"
)

flag_cron_entry() {
    local source="$1"
    local entry="$2"
    local idx="$3"

    # Skip comments and empty lines
    [[ "$entry" =~ ^\s*# ]] && return
    [[ -z "${entry// /}" ]] && return

    for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
        if echo "$entry" | grep -qiE "$pattern" 2>/dev/null; then
            add_finding "${SCRIPT_ID}-C2-${idx}" "Suspicious Cron Entry in ${source}" "High" "WARN" \
                "Entry: ${entry:0:200}" \
                "Investigate this cron entry. Remove if not authorised."
            return
        fi
    done
}

# C1 – System crontab files
CRON_DIRS=(
    "/etc/crontab"
    "/etc/cron.d"
    "/etc/cron.hourly"
    "/etc/cron.daily"
    "/etc/cron.weekly"
    "/etc/cron.monthly"
)

all_cron_entries=0
susp_idx=0

for cron_src in "${CRON_DIRS[@]}"; do
    if [[ -f "$cron_src" ]]; then
        while IFS= read -r line; do
            all_cron_entries=$((all_cron_entries + 1))
            flag_cron_entry "$cron_src" "$line" "$susp_idx"
            susp_idx=$((susp_idx + 1))
        done < "$cron_src"
    elif [[ -d "$cron_src" ]]; then
        for f in "$cron_src"/*; do
            [[ -f "$f" ]] || continue
            while IFS= read -r line; do
                all_cron_entries=$((all_cron_entries + 1))
                flag_cron_entry "$f" "$line" "$susp_idx"
                susp_idx=$((susp_idx + 1))
            done < "$f"
        done
    fi
done

add_finding "${SCRIPT_ID}-C1" "System Cron Entries" "Info" "INFO" \
    "${all_cron_entries} system cron lines reviewed" ""

# C2 – User crontabs
if [[ -d /var/spool/cron/crontabs ]]; then
    for ctab in /var/spool/cron/crontabs/*; do
        [[ -f "$ctab" ]] || continue
        owner=$(basename "$ctab")
        while IFS= read -r line; do
            flag_cron_entry "user:${owner}" "$line" "$susp_idx"
            susp_idx=$((susp_idx + 1))
        done < "$ctab"
        add_finding "${SCRIPT_ID}-C3-${owner}" "User Crontab: ${owner}" "Info" "INFO" \
            "Crontab found for user ${owner}" ""
    done
elif [[ -d /var/spool/cron ]]; then
    for ctab in /var/spool/cron/*; do
        [[ -f "$ctab" ]] || continue
        owner=$(basename "$ctab")
        while IFS= read -r line; do
            flag_cron_entry "user:${owner}" "$line" "$susp_idx"
            susp_idx=$((susp_idx + 1))
        done < "$ctab"
        add_finding "${SCRIPT_ID}-C3-${owner}" "User Crontab: ${owner}" "Info" "INFO" \
            "Crontab found for user ${owner}" ""
    done
fi

# C4 – Systemd timers (alternative persistence mechanism)
if command -v systemctl &>/dev/null; then
    timer_count=$(systemctl list-timers --all --no-legend 2>/dev/null | wc -l || true)
    add_finding "${SCRIPT_ID}-C4" "Systemd Timers" "Info" "INFO" \
        "${timer_count} systemd timer(s) configured" ""

    # Check for user timers in unusual locations
    susp_timers=$(find /home /tmp /var/tmp -name '*.timer' -o -name '*.service' 2>/dev/null | head -10 || true)
    if [[ -n "$susp_timers" ]]; then
        add_finding "${SCRIPT_ID}-C4b" "Systemd Units in User Directories" "High" "WARN" \
            "Suspicious timer/service files: ${susp_timers//$'\n'/ | }" \
            "Investigate and remove if not authorised"
    fi
fi

# C5 – rc.local / init.d persistence
for init_file in /etc/rc.local /etc/rc.d/rc.local; do
    if [[ -f "$init_file" && -x "$init_file" ]]; then
        rc_lines=$(grep -v '^\s*#\|^\s*$\|^exit' "$init_file" 2>/dev/null | wc -l || true)
        if [[ "$rc_lines" -gt 0 ]]; then
            add_finding "${SCRIPT_ID}-C5" "rc.local Active" "Med" "WARN" \
                "${init_file} has ${rc_lines} active line(s)" \
                "Review ${init_file} for unauthorised startup commands"
        else
            add_finding "${SCRIPT_ID}-C5" "rc.local Active" "Low" "PASS" \
                "${init_file} has no active commands" ""
        fi
    fi
done

# C6 – /etc/profile.d / bashrc unusual entries
profile_suspicious=$(grep -rh 'curl\|wget\|base64\|/tmp\|eval' /etc/profile.d/ ~/.bashrc /etc/bashrc 2>/dev/null | grep -v '^\s*#' | head -5 || true)
if [[ -n "$profile_suspicious" ]]; then
    # Replace newlines with ' | ' so the multi-line output is safe in a JSON string
    profile_suspicious_safe="${profile_suspicious//$'\n'/ | }"
    add_finding "${SCRIPT_ID}-C6" "Suspicious Shell Init Commands" "High" "WARN" \
        "Suspicious entries in shell init files: ${profile_suspicious_safe:0:200}" \
        "Investigate these entries in /etc/profile.d/, ~/.bashrc, /etc/bashrc"
else
    add_finding "${SCRIPT_ID}-C6" "Shell Init Files" "Med" "PASS" \
        "No obviously suspicious entries in shell init files" ""
fi

# ── Optional Fix ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "INFO: --fix: No automatic remediation for cron persistence findings." >&2
    echo "       Removing cron jobs automatically could disrupt legitimate scheduled tasks." >&2
fi

# ── Output ───────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_cron_persistence" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
