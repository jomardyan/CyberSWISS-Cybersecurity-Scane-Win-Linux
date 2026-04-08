#!/usr/bin/env bash
# =============================================================================
# L28 - Backup and Recovery Resilience (Linux)
# =============================================================================
# ID       : L28
# Category : Resilience & Recovery
# Severity : High
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : Yes
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L28_backup_recovery_resilience.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L28"
SCRIPT_NAME="Backup and Recovery Resilience"
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

collect_remote_indicator_files() {
    local home_dir file
    local -a files=()

    shopt -s nullglob
    for file in \
        /etc/restic* \
        /etc/borg* \
        /etc/rclone* \
        /etc/backup* \
        /etc/default/* \
        /etc/cron*/* \
        /var/spool/cron/* \
        /usr/local/bin/*backup* \
        /usr/local/bin/*restic* \
        /usr/local/bin/*borg* \
        /usr/local/bin/*rclone* \
        /opt/*backup* \
        /opt/*/*backup* \
        /opt/*restic* \
        /opt/*/*restic* \
        /opt/*rclone* \
        /opt/*/*rclone*
    do
        [[ -f "$file" ]] && files+=("$file")
    done

    for home_dir in /root /home/*; do
        [[ -d "$home_dir" ]] || continue
        for file in \
            "$home_dir/.env" \
            "$home_dir"/backup*.sh \
            "$home_dir"/.config/restic/* \
            "$home_dir"/.config/rclone/* \
            "$home_dir"/.config/borg/*
        do
            [[ -f "$file" ]] && files+=("$file")
        done
    done
    shopt -u nullglob

    printf '%s\n' "${files[@]}" | sort -u | head -120
}

BACKUP_DIRS=(
    /var/backups
    /backup
    /backups
    /srv/backup
    /srv/backups
    /mnt/backup
    /mnt/backups
    /root/backups
)

existing_backup_dirs=()
for dir_path in "${BACKUP_DIRS[@]}"; do
    [[ -d "$dir_path" ]] && existing_backup_dirs+=("$dir_path")
done

# C1 - Backup tooling or schedules
tools_found=()
for tool in restic borg borgmatic rsnapshot duplicity rclone snapper timeshift rdiff-backup rsync; do
    command -v "$tool" &>/dev/null && tools_found+=("$tool")
done

backup_timers=""
if command -v systemctl &>/dev/null; then
    backup_timers=$(systemctl list-unit-files 2>/dev/null | grep -Ei 'restic|borg|backup|rsnapshot|duplicity|rclone|snapper|timeshift' | awk '{print $1}' | head -5 || true)
fi
backup_cron_hits=$(grep -RhiE 'restic|borg|rsnapshot|duplicity|rclone|timeshift|backup' /etc/cron* /var/spool/cron 2>/dev/null | head -3 || true)

if [[ "${#tools_found[@]}" -gt 0 || -n "$backup_timers" || -n "$backup_cron_hits" ]]; then
    detail_parts=()
    [[ "${#tools_found[@]}" -gt 0 ]] && detail_parts+=("tools=$(printf '%s ' "${tools_found[@]}" | xargs)")
    [[ -n "$backup_timers" ]] && detail_parts+=("timers=$(echo "$backup_timers" | tr '\n' ',' | sed 's/,$//')")
    [[ -n "$backup_cron_hits" ]] && detail_parts+=("cron-patterns-detected")
    add_finding "${SCRIPT_ID}-C1" "Backup Tooling and Scheduling" "High" "PASS" \
        "$(printf '%s; ' "${detail_parts[@]}" | sed 's/; $//')" ""
else
    add_finding "${SCRIPT_ID}-C1" "Backup Tooling and Scheduling" "High" "WARN" \
        "No backup tooling, timers, or cron jobs were detected" \
        "Deploy a managed backup solution such as restic, borg, rsnapshot, enterprise backup agents, or snapshot orchestration"
fi

# C2 - Recent backup evidence
recent_artifacts=""
if [[ "${#existing_backup_dirs[@]}" -gt 0 ]]; then
    recent_artifacts=$(find "${existing_backup_dirs[@]}" -maxdepth 3 \
        \( -type f \( -name '*.bak' -o -name '*.tar' -o -name '*.tar.gz' -o -name '*.tgz' -o -name '*.zst' -o -name '*.xz' -o -name '*.sql.gz' -o -name '*.restic' -o -name '*.borg' \) -o \
           -type d \( -name 'snapshot*' -o -name 'snapshots' \) \) \
        -mtime -7 2>/dev/null | head -10 || true)
fi

if [[ -n "$recent_artifacts" ]]; then
    add_finding "${SCRIPT_ID}-C2" "Recent Backup Evidence" "High" "PASS" \
        "Backup artifacts modified within 7 days: $(echo "$recent_artifacts" | tr '\n' ',' | sed 's/,$//')" ""
else
    add_finding "${SCRIPT_ID}-C2" "Recent Backup Evidence" "High" "WARN" \
        "No recent backup artifact was found in common backup locations within the last 7 days" \
        "Verify scheduled backups are completing successfully and writing to approved backup targets"
fi

# C3 - Backup directory permissions
if [[ "${#existing_backup_dirs[@]}" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C3" "Backup Storage Permissions" "Med" "INFO" \
        "No common local backup directories were found to assess permissions" \
        "Review the actual backup repository path and ensure it is not writable by non-administrative users"
else
    permission_issues=""
    permission_warnings=""
    for dir_path in "${existing_backup_dirs[@]}"; do
        perm=$(stat -c '%a' "$dir_path" 2>/dev/null || echo "")
        [[ -z "$perm" ]] && continue
        group_perms=$(( (10#$perm / 10) % 10 ))
        other_perms=$(( 10#$perm % 10 ))
        if (( group_perms & 2 )) || (( other_perms & 2 )); then
            permission_issues="${permission_issues} ${dir_path}(${perm});"
        elif (( other_perms > 0 )); then
            permission_warnings="${permission_warnings} ${dir_path}(${perm});"
        fi
    done

    if [[ -n "$permission_issues" ]]; then
        add_finding "${SCRIPT_ID}-C3" "Backup Storage Permissions" "High" "FAIL" \
            "Backup directories are writable by group/other:${permission_issues}" \
            "Restrict backup paths to root or the dedicated backup service account, for example chmod 750 and chown root:backup"
    elif [[ -n "$permission_warnings" ]]; then
        add_finding "${SCRIPT_ID}-C3" "Backup Storage Permissions" "Med" "WARN" \
            "Backup directories are readable by other users:${permission_warnings}" \
            "Reduce backup directory exposure and ensure sensitive archives are encrypted and not broadly readable"
    else
        add_finding "${SCRIPT_ID}-C3" "Backup Storage Permissions" "Med" "PASS" \
            "Backup directory permissions look restricted: $(printf '%s ' "${existing_backup_dirs[@]}" | xargs)" ""
    fi
fi

# C4 - Point-in-time snapshot capability
snapshot_detail=""
if command -v snapper &>/dev/null && snapper list 2>/dev/null | grep -q '|' ; then
    snapshot_detail="snapper snapshots detected"
elif command -v timeshift &>/dev/null && timeshift --list-snapshots 2>/dev/null | grep -qi 'snapshot'; then
    snapshot_detail="timeshift snapshots detected"
elif command -v zfs &>/dev/null && zfs list -H -t snapshot 2>/dev/null | head -1 | grep -q '.'; then
    snapshot_detail="ZFS snapshots detected"
elif command -v btrfs &>/dev/null && btrfs subvolume list -s / 2>/dev/null | head -1 | grep -q '.'; then
    snapshot_detail="Btrfs snapshots detected"
elif command -v lvs &>/dev/null && lvs --noheadings -o lv_attr 2>/dev/null | grep -q 's'; then
    snapshot_detail="LVM snapshots detected"
fi

if [[ -n "$snapshot_detail" ]]; then
    add_finding "${SCRIPT_ID}-C4" "Point-in-Time Snapshot Coverage" "Med" "PASS" \
        "${snapshot_detail}" ""
else
    add_finding "${SCRIPT_ID}-C4" "Point-in-Time Snapshot Coverage" "Med" "WARN" \
        "No snapshot tooling or point-in-time snapshots were detected" \
        "Consider snapshots (Btrfs, ZFS, LVM, snapper, timeshift) to improve rollback and ransomware recovery options"
fi

# C5 - Off-host backup indicators
remote_backup_indicators=""
mapfile -t remote_indicator_files < <(collect_remote_indicator_files)
if [[ "${#remote_indicator_files[@]}" -gt 0 ]]; then
    remote_backup_indicators+=$(grep -HiE 'RESTIC_REPOSITORY=.*(s3:|b2:|azure:|gs:|sftp:|swift:|rest:|rclone:)' "${remote_indicator_files[@]}" 2>/dev/null | head -2 || true)
    remote_backup_indicators+=$'\n'
    remote_backup_indicators+=$(grep -HiE 'rclone (copy|sync)|rsync .+(@|::)|sftp://|scp ' "${remote_indicator_files[@]}" 2>/dev/null | head -3 || true)
fi
remote_backup_indicators=$(printf '%s\n' "$remote_backup_indicators" | sed '/^$/d' | head -5 || true)

if [[ -n "$remote_backup_indicators" ]]; then
    add_finding "${SCRIPT_ID}-C5" "Off-Host Backup Indicators" "High" "PASS" \
        "Detected remote backup indicators in configuration or automation: $(echo "$remote_backup_indicators" | tr '\n' ',' | sed 's/,$//')" ""
else
    add_finding "${SCRIPT_ID}-C5" "Off-Host Backup Indicators" "High" "WARN" \
        "No remote or off-host backup indicators were detected" \
        "Maintain at least one offline, immutable, or off-host backup copy so host compromise does not remove every recovery path"
fi

# C6 - Failed backup services
failed_backup_units=""
if command -v systemctl &>/dev/null; then
    failed_backup_units=$(systemctl --failed --no-legend 2>/dev/null | grep -Ei 'restic|borg|backup|rsnapshot|duplicity|rclone|timeshift' | awk '{print $1}' | head -5 || true)
fi

if [[ -n "$failed_backup_units" ]]; then
    add_finding "${SCRIPT_ID}-C6" "Backup Job Health" "High" "FAIL" \
        "Failed backup-related systemd units detected: $(echo "$failed_backup_units" | tr '\n' ',' | sed 's/,$//')" \
        "Review journalctl output for the failed units, restore job execution, and verify backups complete without errors"
elif [[ "${#tools_found[@]}" -gt 0 || -n "$backup_timers" ]]; then
    add_finding "${SCRIPT_ID}-C6" "Backup Job Health" "Med" "PASS" \
        "No failed backup-related systemd units were detected" ""
else
    add_finding "${SCRIPT_ID}-C6" "Backup Job Health" "Info" "INFO" \
        "No backup-related systemd units were detected to evaluate job health" ""
fi

if [[ "$FIX_MODE" == true ]]; then
    if [[ "${EUID}" -ne 0 ]]; then
        echo "INFO: --fix requires root to harden backup directory permissions." >&2
    elif [[ "${#existing_backup_dirs[@]}" -eq 0 ]]; then
        echo "INFO: --fix found no common backup directories to harden." >&2
    else
        hardened_dirs=()
        for dir_path in "${existing_backup_dirs[@]}"; do
            chmod g-w,o-rwx "$dir_path" 2>/dev/null || true
            hardened_dirs+=("$dir_path")
        done
        echo "INFO: Hardened backup directory permissions on: $(printf '%s ' "${hardened_dirs[@]}" | xargs)." >&2
        echo "INFO: Backup architecture, off-host copies, and restore workflow validation still require manual review." >&2
    fi
fi

if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_backup_recovery_resilience" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
