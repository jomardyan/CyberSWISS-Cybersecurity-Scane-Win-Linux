#!/usr/bin/env bash
# =============================================================================
# L30 – Deep Persistence & Autoruns Audit (Linux)
# =============================================================================
# ID       : L30
# Category : Persistence & Autoruns
# Severity : Critical
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : Yes
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L30_deep_persistence.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L30"
SCRIPT_NAME="Deep Persistence & Autoruns Audit"
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

# Suspicious content patterns
SUSP_PAT='curl[[:space:]]|wget[[:space:]]|base64[[:space:]]-d|bash[[:space:]]-i|/tmp/|/dev/tcp|nc[[:space:]]|mkfifo|python[[:space:]]-c|perl[[:space:]]-e|eval[[:space:]]*['\''"(]|nohup|setsid'

# ── C1: User-level systemd units (persistence without root) ──────────────────
susp_user_units=()
while IFS= read -r unit; do
    content=$(cat "$unit" 2>/dev/null || true)
    if echo "$content" | grep -qiE "$SUSP_PAT" 2>/dev/null; then
        susp_user_units+=("$unit")
    fi
done < <(find /home /root /var /tmp -name '*.service' -o -name '*.timer' 2>/dev/null | head -50)

if [[ "${#susp_user_units[@]}" -gt 0 ]]; then
    add_finding "${SCRIPT_ID}-C1" "Suspicious User Systemd Units" "Critical" "FAIL" \
        "${#susp_user_units[@]} suspicious unit file(s): ${susp_user_units[*]:0:5}" \
        "Review and remove: systemctl disable --user <unit>; rm <file>"
else
    user_units=$(find /home -name '*.service' -o -name '*.timer' 2>/dev/null | wc -l || echo 0)
    add_finding "${SCRIPT_ID}-C1" "User Systemd Units" "High" "PASS" \
        "${user_units} user systemd unit file(s) found – none flagged as suspicious" ""
fi

# ── C2: Shell profile backdoors across all users ─────────────────────────────
profile_files=(
    "/etc/profile"
    "/etc/bash.bashrc"
    "/etc/environment"
)
# Add per-user profile files
while IFS=: read -r uname _ uid _ _ uhome _; do
    (( uid >= 1000 || uid == 0 )) || continue
    for f in "$uhome/.bashrc" "$uhome/.bash_profile" "$uhome/.profile" "$uhome/.zshrc" "$uhome/.zprofile"; do
        [[ -f "$f" ]] && profile_files+=("$f")
    done
done < /etc/passwd

susp_profiles=()
for pf in "${profile_files[@]}"; do
    [[ -f "$pf" ]] || continue
    if grep -qiE "$SUSP_PAT" "$pf" 2>/dev/null; then
        susp_profiles+=("$pf")
    fi
done

if [[ "${#susp_profiles[@]}" -gt 0 ]]; then
    add_finding "${SCRIPT_ID}-C2" "Suspicious Shell Profile Entries" "Critical" "FAIL" \
        "Backdoor patterns found in: ${susp_profiles[*]}" \
        "Review each file manually and remove suspicious lines. Use 'diff' against known-good baselines."
else
    add_finding "${SCRIPT_ID}-C2" "Shell Profile Files" "High" "PASS" \
        "${#profile_files[@]} profile file(s) reviewed – no backdoor patterns found" ""
fi

# ── C3: LD_PRELOAD / LD_LIBRARY_PATH abuse ───────────────────────────────────
ld_preload_issues=()

# Check /etc/ld.so.preload
if [[ -f /etc/ld.so.preload ]]; then
    content=$(cat /etc/ld.so.preload 2>/dev/null | grep -v '^\s*#\|^\s*$' || true)
    if [[ -n "$content" ]]; then
        ld_preload_issues+=("/etc/ld.so.preload: $(echo "$content" | head -3 | tr '\n' ' ')")
    fi
fi

# Check environment for LD_PRELOAD set globally
if grep -qrh 'LD_PRELOAD' /etc/profile.d/ /etc/environment /etc/bash.bashrc 2>/dev/null; then
    ld_preload_issues+=("LD_PRELOAD found in global shell init files")
fi

if [[ "${#ld_preload_issues[@]}" -gt 0 ]]; then
    add_finding "${SCRIPT_ID}-C3" "LD_PRELOAD Abuse Risk" "Critical" "FAIL" \
        "${ld_preload_issues[*]}" \
        "Remove entries from /etc/ld.so.preload unless explicitly required. Any .so file here runs in every process."
else
    add_finding "${SCRIPT_ID}-C3" "LD_PRELOAD Configuration" "Critical" "PASS" \
        "No suspicious LD_PRELOAD configuration found" ""
fi

# ── C4: PAM module tampering ──────────────────────────────────────────────────
susp_pam=()
for pam_cfg in /etc/pam.d/*; do
    [[ -f "$pam_cfg" ]] || continue
    # Look for .so files not under /lib/security or /lib64/security
    while IFS= read -r line; do
        [[ "$line" =~ ^\s*# ]] && continue
        if echo "$line" | grep -qE '\.so\b' && ! echo "$line" | grep -qE '/lib(64)?/security/'; then
            susp_pam+=("$(basename $pam_cfg): $line")
        fi
    done < "$pam_cfg"
done

if [[ "${#susp_pam[@]}" -gt 0 ]]; then
    add_finding "${SCRIPT_ID}-C4" "Suspicious PAM Module Entries" "Critical" "FAIL" \
        "${#susp_pam[@]} PAM entries with non-standard .so paths: ${susp_pam[0]}" \
        "Review /etc/pam.d/* for injected modules. Any .so outside /lib/security can intercept credentials."
else
    add_finding "${SCRIPT_ID}-C4" "PAM Module Configuration" "Critical" "PASS" \
        "All PAM modules reference standard /lib/security paths" ""
fi

# ── C5: /etc/profile.d unusual scripts ───────────────────────────────────────
susp_profiled=()
for f in /etc/profile.d/*.sh; do
    [[ -f "$f" ]] || continue
    if grep -qiE "$SUSP_PAT" "$f" 2>/dev/null; then
        susp_profiled+=("$f")
    fi
done

if [[ "${#susp_profiled[@]}" -gt 0 ]]; then
    add_finding "${SCRIPT_ID}-C5" "Suspicious /etc/profile.d Scripts" "High" "WARN" \
        "Suspicious content in: ${susp_profiled[*]}" \
        "Review these scripts. Non-authorised scripts in /etc/profile.d run for all login shells."
else
    count=$(ls /etc/profile.d/*.sh 2>/dev/null | wc -l || echo 0)
    add_finding "${SCRIPT_ID}-C5" "/etc/profile.d Scripts" "High" "PASS" \
        "${count} script(s) in /etc/profile.d – none flagged as suspicious" ""
fi

# ── C6: Unauthorised SSHD AuthorizedKeysFile locations ───────────────────────
if [[ -f /etc/ssh/sshd_config ]]; then
    auth_keys_file=$(grep -i 'AuthorizedKeysFile' /etc/ssh/sshd_config 2>/dev/null | grep -v '^\s*#' | awk '{print $2}' | head -1 || true)
    if [[ -n "$auth_keys_file" && "$auth_keys_file" != ".ssh/authorized_keys" && "$auth_keys_file" != "%h/.ssh/authorized_keys" ]]; then
        add_finding "${SCRIPT_ID}-C6" "Non-Standard AuthorizedKeysFile" "High" "WARN" \
            "AuthorizedKeysFile = ${auth_keys_file}" \
            "Set AuthorizedKeysFile to .ssh/authorized_keys in /etc/ssh/sshd_config"
    else
        add_finding "${SCRIPT_ID}-C6" "SSH AuthorizedKeysFile Location" "High" "PASS" \
            "AuthorizedKeysFile uses standard path" ""
    fi

    # Count authorized_keys files and flag any outside home dirs
    susp_auth_keys=$(find / -name 'authorized_keys' ! -path '/home/*/.ssh/authorized_keys' ! -path '/root/.ssh/authorized_keys' 2>/dev/null | head -10 || true)
    if [[ -n "$susp_auth_keys" ]]; then
        add_finding "${SCRIPT_ID}-C6b" "Authorized Keys in Unusual Locations" "High" "WARN" \
            "authorized_keys files outside home dirs: $(echo "$susp_auth_keys" | tr '\n' ' | ')" \
            "Investigate these files – they may represent persistent backdoor access."
    fi
fi

# ── C7: Suspicious files recently modified in key directories ────────────────
recently_modified=$(find /bin /sbin /usr/bin /usr/sbin /lib /lib64 /etc -newer /etc/passwd \
    -type f ! -name '*.log' ! -name '*.tmp' 2>/dev/null | head -20 || true)
mod_count=$(echo "$recently_modified" | grep -c '/' || echo 0)

if [[ "$mod_count" -gt 10 ]]; then
    add_finding "${SCRIPT_ID}-C7" "Numerous System Files Recently Modified" "High" "WARN" \
        "${mod_count} system-path files modified more recently than /etc/passwd (sample): $(echo "$recently_modified" | head -5 | tr '\n' ' | ')" \
        "Review recently modified system files for unexpected changes. Consider deploying AIDE/Tripwire."
else
    add_finding "${SCRIPT_ID}-C7" "System File Modification Timestamps" "High" "PASS" \
        "${mod_count} system-path files modified since last passwd change (within expected range)" ""
fi

# ── C8: Git hooks with suspicious content ────────────────────────────────────
susp_hooks=()
while IFS= read -r hook; do
    [[ -x "$hook" ]] || continue
    if grep -qiE "$SUSP_PAT" "$hook" 2>/dev/null; then
        susp_hooks+=("$hook")
    fi
done < <(find / -path '*/.git/hooks/*' -type f 2>/dev/null | head -30)

if [[ "${#susp_hooks[@]}" -gt 0 ]]; then
    add_finding "${SCRIPT_ID}-C8" "Suspicious Git Hooks" "High" "WARN" \
        "${#susp_hooks[@]} suspicious git hook(s): ${susp_hooks[*]:0:3}" \
        "Review git hooks: cat <hook_file>. Git hooks run code automatically on git operations."
else
    add_finding "${SCRIPT_ID}-C8" "Git Hooks" "Med" "PASS" \
        "No suspicious patterns found in git hooks on this system" ""
fi

# ── Output ────────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_deep_persistence" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
