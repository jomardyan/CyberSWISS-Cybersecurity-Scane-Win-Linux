#!/usr/bin/env bash
# =============================================================================
# L31 – Credential Theft Hardening (Linux)
# =============================================================================
# ID       : L31
# Category : Credential Protection
# Severity : Critical
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : Yes
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L31_credential_theft_hardening.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L31"
SCRIPT_NAME="Credential Theft Hardening"
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

# ── C1: Password hash algorithm in /etc/shadow ───────────────────────────────
if [[ -r /etc/shadow ]]; then
    weak_hashes=$(grep -v '^\s*#\|!!\|:\*:' /etc/shadow 2>/dev/null | awk -F: '$2 != "" && $2 !~ /^\$[56y]/' | awk -F: '{print $1}' | head -10 || true)
    if [[ -n "$weak_hashes" ]]; then
        add_finding "${SCRIPT_ID}-C1" "Weak Password Hash Algorithm" "Critical" "FAIL" \
            "Users with MD5/DES/SHA1 password hashes (not SHA-512/yescrypt): ${weak_hashes//$'\n'/, }" \
            "Set ENCRYPT_METHOD SHA512 in /etc/login.defs and run: passwd <user> to force re-hash."
    else
        add_finding "${SCRIPT_ID}-C1" "Password Hash Algorithm" "Critical" "PASS" \
            "All password hashes use SHA-512 or yescrypt" ""
    fi
else
    add_finding "${SCRIPT_ID}-C1" "Password Hash Algorithm" "Critical" "WARN" \
        "Cannot read /etc/shadow – run as root for credential checks" \
        "Run this script with sudo."
fi

# ── C2: /etc/shadow world-readable ───────────────────────────────────────────
shadow_perm=$(stat -c '%a' /etc/shadow 2>/dev/null || echo "?")
shadow_owner=$(stat -c '%U:%G' /etc/shadow 2>/dev/null || echo "?")
if [[ "$shadow_perm" =~ [0-9][0-9][1-7] ]]; then
    add_finding "${SCRIPT_ID}-C2" "/etc/shadow World-Readable" "Critical" "FAIL" \
        "/etc/shadow permissions: ${shadow_perm} (owner: ${shadow_owner}) – readable by all users" \
        "chmod 640 /etc/shadow; chown root:shadow /etc/shadow"
else
    add_finding "${SCRIPT_ID}-C2" "/etc/shadow Permissions" "Critical" "PASS" \
        "/etc/shadow: ${shadow_perm} (${shadow_owner}) – correctly restricted" ""
fi

# ── C3: SSH private keys with weak or no permissions ─────────────────────────
bad_key_perms=()
while IFS= read -r keyfile; do
    perm=$(stat -c '%a' "$keyfile" 2>/dev/null || continue)
    # Private keys should be 600 or 400 at most
    if [[ "$perm" =~ ^[0-9][1-7][0-9]$ ]] || [[ "$perm" =~ ^[0-9][0-9][1-7]$ ]]; then
        bad_key_perms+=("$keyfile:$perm")
    fi
done < <(find /home /root /etc/ssh -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' -o -name '*_key' 2>/dev/null | grep -v '\.pub$')

if [[ "${#bad_key_perms[@]}" -gt 0 ]]; then
    add_finding "${SCRIPT_ID}-C3" "SSH Private Keys With Excess Permissions" "Critical" "FAIL" \
        "${#bad_key_perms[@]} key file(s) with group/world read access: ${bad_key_perms[*]:0:5}" \
        "Fix: chmod 600 <keyfile>. SSH private keys must not be readable by other users."
else
    add_finding "${SCRIPT_ID}-C3" "SSH Private Key Permissions" "Critical" "PASS" \
        "All SSH private keys have restricted permissions (600/400)" ""
fi

# ── C4: Unencrypted SSH private keys (no passphrase) ─────────────────────────
unprotected_keys=()
while IFS= read -r keyfile; do
    if head -3 "$keyfile" 2>/dev/null | grep -q 'BEGIN.*PRIVATE KEY'; then
        if ! grep -q 'ENCRYPTED' "$keyfile" 2>/dev/null; then
            unprotected_keys+=("$keyfile")
        fi
    fi
done < <(find /home /root /etc -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' 2>/dev/null | grep -v '\.pub$')

if [[ "${#unprotected_keys[@]}" -gt 0 ]]; then
    add_finding "${SCRIPT_ID}-C4" "Unencrypted SSH Private Keys" "High" "WARN" \
        "${#unprotected_keys[@]} SSH key(s) without passphrase: ${unprotected_keys[*]:0:5}" \
        "Add passphrase: ssh-keygen -p -f <keyfile>. Unencrypted keys allow immediate lateral movement if stolen."
else
    add_finding "${SCRIPT_ID}-C4" "SSH Private Key Encryption" "High" "PASS" \
        "All SSH private keys appear to be passphrase-protected or keys not present" ""
fi

# ── C5: Cached sudo credentials timeout ──────────────────────────────────────
sudo_timeout=$(grep -rh 'timestamp_timeout' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^\s*#' | head -1 || true)
if [[ -z "$sudo_timeout" ]]; then
    add_finding "${SCRIPT_ID}-C5" "sudo Credential Cache Timeout" "Med" "WARN" \
        "timestamp_timeout not set – defaults to 15 minutes. An attacker with brief access inherits sudo session." \
        "Add 'Defaults timestamp_timeout=5' to /etc/sudoers (visudo) to limit credential caching window."
else
    timeout_val=$(echo "$sudo_timeout" | grep -oE '\-?[0-9]+' | head -1 || echo "?")
    if [[ "$timeout_val" -gt 15 ]] 2>/dev/null; then
        add_finding "${SCRIPT_ID}-C5" "sudo Credential Cache Timeout" "Med" "WARN" \
            "timestamp_timeout=${timeout_val} minutes – longer than recommended 5 minutes" \
            "Set: Defaults timestamp_timeout=5 in /etc/sudoers (visudo)"
    else
        add_finding "${SCRIPT_ID}-C5" "sudo Credential Cache Timeout" "Med" "PASS" \
            "sudo timestamp_timeout=${timeout_val} minutes (within acceptable range)" ""
    fi
fi

# ── C6: Core dumps enabled (may contain credentials in memory) ───────────────
core_pattern=$(cat /proc/sys/kernel/core_pattern 2>/dev/null || echo "?")
core_limit=$(ulimit -c 2>/dev/null || echo "?")

if [[ "$core_limit" != "0" ]] || echo "$core_pattern" | grep -qv '^|'; then
    # Also check /etc/security/limits.conf
    hard_core=$(grep -h 'hard.*core' /etc/security/limits.conf /etc/security/limits.d/*.conf 2>/dev/null | grep -v '^\s*#' | awk '$4 != "0"' | head -1 || true)
    if [[ "$core_limit" != "0" || -n "$hard_core" ]]; then
        add_finding "${SCRIPT_ID}-C6" "Core Dumps Enabled" "High" "WARN" \
            "Core dumps may be enabled (core_pattern=${core_pattern}, ulimit -c=${core_limit}). Core files can expose passwords from memory." \
            "Disable: echo 'kernel.core_pattern=|/bin/false' >> /etc/sysctl.d/99-coredump.conf; sysctl -p; echo '* hard core 0' >> /etc/security/limits.conf"
    else
        add_finding "${SCRIPT_ID}-C6" "Core Dumps" "High" "PASS" \
            "Core dumps disabled via limits (hard core=0)" ""
    fi
fi

# ── C7: Cleartext credentials in common config files ─────────────────────────
cred_patterns='password\s*=\s*[^$\s{][^\s]{3,}|passwd\s*=\s*[^$\s{][^\s]{3,}|secret\s*=\s*[^$\s{][^\s]{3,}|token\s*=\s*[A-Za-z0-9+/]{20,}'
cred_files=(
    "/etc/fstab"
    "/etc/mysql/my.cnf"
    "/etc/postgresql/*/main/pg_hba.conf"
    "/etc/php*/*/php.ini"
    "/var/www/html/wp-config.php"
    "/opt/*/config*.conf"
    "/opt/*/config*.ini"
    "/opt/*/config*.yaml"
    "/opt/*/config*.yml"
    "/etc/nginx/conf.d/*.conf"
    "/etc/apache2/sites-enabled/*.conf"
)

cred_hits=()
for pattern in "${cred_files[@]}"; do
    for f in $pattern; do
        [[ -f "$f" ]] || continue
        if grep -qiE "$cred_patterns" "$f" 2>/dev/null; then
            cred_hits+=("$f")
        fi
    done
done

if [[ "${#cred_hits[@]}" -gt 0 ]]; then
    add_finding "${SCRIPT_ID}-C7" "Cleartext Credentials in Config Files" "Critical" "FAIL" \
        "${#cred_hits[@]} file(s) contain potential cleartext credentials: ${cred_hits[*]:0:5}" \
        "Replace plain-text passwords with environment variable references or a secrets manager (Vault, AWS Secrets Manager)."
else
    add_finding "${SCRIPT_ID}-C7" "Cleartext Credentials in Config Files" "Critical" "PASS" \
        "No obvious cleartext credentials found in common config paths" ""
fi

# ── C8: SSH agent forwarding exposure ────────────────────────────────────────
if [[ -f /etc/ssh/sshd_config ]]; then
    allow_agent_fwd=$(grep -i 'AllowAgentForwarding' /etc/ssh/sshd_config 2>/dev/null | grep -v '^\s*#' | awk '{print $2}' | tail -1 || echo "yes")
    if [[ "${allow_agent_fwd,,}" != "no" ]]; then
        add_finding "${SCRIPT_ID}-C8" "SSH Agent Forwarding Enabled" "High" "WARN" \
            "AllowAgentForwarding=${allow_agent_fwd}. An attacker who compromises an intermediate host can use the agent to authenticate further." \
            "Set 'AllowAgentForwarding no' in /etc/ssh/sshd_config; then: systemctl reload sshd"
    else
        add_finding "${SCRIPT_ID}-C8" "SSH Agent Forwarding" "High" "PASS" \
            "AllowAgentForwarding is disabled" ""
    fi
fi

# ── C9: Bash/shell history containing credentials ────────────────────────────
hist_hits=()
while IFS=: read -r uname _ uid _ _ uhome _; do
    (( uid >= 1000 || uid == 0 )) || continue
    for hist_file in "$uhome/.bash_history" "$uhome/.zsh_history"; do
        [[ -f "$hist_file" ]] || continue
        if grep -qiE 'password|passwd|secret|token|apikey|api_key|--password|:\/\/[^:@]+:[^:@]+@' "$hist_file" 2>/dev/null; then
            hist_hits+=("${hist_file} (user: ${uname})")
        fi
    done
done < /etc/passwd

if [[ "${#hist_hits[@]}" -gt 0 ]]; then
    add_finding "${SCRIPT_ID}-C9" "Credentials in Shell History" "High" "WARN" \
        "${#hist_hits[@]} history file(s) contain potential credential material: ${hist_hits[*]:0:3}" \
        "Clear: history -c; cat /dev/null > ~/.bash_history. Set HISTCONTROL=ignorespace:erasedups in ~/.bashrc."
else
    add_finding "${SCRIPT_ID}-C9" "Shell History Credential Exposure" "High" "PASS" \
        "No obvious credential patterns found in shell history files" ""
fi

# ── C10: ptrace scope (credential dumping via /proc) ─────────────────────────
ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo "?")
if [[ "$ptrace_scope" == "0" ]]; then
    add_finding "${SCRIPT_ID}-C10" "ptrace_scope Allows Process Memory Reads" "High" "FAIL" \
        "kernel.yama.ptrace_scope=0. Any process can attach to and read memory of another process owned by the same user (mimikatz-style attacks)." \
        "Set: echo 'kernel.yama.ptrace_scope=1' >> /etc/sysctl.d/99-ptrace.conf; sysctl -p"
elif [[ "$ptrace_scope" == "?" ]]; then
    add_finding "${SCRIPT_ID}-C10" "ptrace_scope" "High" "INFO" \
        "kernel.yama.ptrace_scope not available (Yama LSM not loaded)" ""
else
    add_finding "${SCRIPT_ID}-C10" "ptrace_scope" "High" "PASS" \
        "kernel.yama.ptrace_scope=${ptrace_scope} (restricted)" ""
fi

# ── Optional Fix ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "INFO: --fix: applying safe remediations..." >&2
    # Harden ptrace_scope
    if [[ "${ptrace_scope:-0}" == "0" ]]; then
        echo 'kernel.yama.ptrace_scope=1' >> /etc/sysctl.d/99-cyberswiss-creds.conf
        sysctl -w kernel.yama.ptrace_scope=1 2>/dev/null && echo "Fixed: ptrace_scope set to 1" >&2 || true
    fi
    # Disable core dumps
    if ! grep -q 'hard.*core.*0' /etc/security/limits.conf 2>/dev/null; then
        echo '* hard core 0' >> /etc/security/limits.conf
        echo "Fixed: hard core limit set to 0" >&2
    fi
fi

# ── Output ────────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_credential_theft_hardening" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
