#!/usr/bin/env bash
# =============================================================================
# L16 – Secrets & Credential Exposure Scan (Linux)
# =============================================================================
# ID       : L16
# Category : Secrets & Credential Exposure
# Severity : Critical
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : Yes (root for full filesystem access)
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L16_secrets_scan.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L16"
SCRIPT_NAME="Secrets & Credential Exposure Scan"
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

# C1 – .env files with sensitive-looking content (non-empty, non-placeholder values)
env_hits=0
env_files=""
# Placeholder RE: values that are clearly not real secrets (template expressions excluded separately)
# Deliberately excludes the words "secret" and "password" from this list to avoid false negatives
# where a field like API_SECRET=my_actual_secret_value would be wrongly ignored.
_PLACEHOLDER_RE='(changeme|change_me|your[_[:alnum:]]*|replace[_[:alnum:]]*|placeholder|sample|example|dummy|todo|fixme|none|null|undefined|xxx+|<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\})'
while IFS= read -r -d '' f; do
    # Check each matching line individually: flag the file if at least one line has a real secret
    # (non-empty value that is not a placeholder pattern or empty template expression)
    real_secret=false
    while IFS= read -r line; do
        # Extract the value part after the first '='
        val="${line#*=}"
        val="${val%%#*}"      # strip inline comment
        val="${val//[[:space:]]/}"  # strip whitespace
        # Skip empty values
        [[ -z "$val" ]] && continue
        # Skip template expressions like ${VAR} or {{value}}
        [[ "$val" =~ ^\$\{[^}]+\}$ ]] && continue
        [[ "$val" =~ ^\{\{[^}]+\}\}$ ]] && continue
        # Skip obvious placeholder values
        if echo "$val" | grep -qiE "^${_PLACEHOLDER_RE}$" 2>/dev/null; then continue; fi
        # Non-empty, non-placeholder value found – this is a potential real secret
        real_secret=true
        break
    done < <(grep -iE '^\s*(DB_PASS(WORD)?|API[_-]?KEY|APP?[_-]?SECRET|ACCESS[_-]?TOKEN|AUTH[_-]?TOKEN|PRIVATE[_-]?KEY|SECRET[_-]?KEY|PASSWORD|SECRET|TOKEN|apiKey|secretKey|accessToken|authToken|dbPassword|dbPass)\s*=' "$f" 2>/dev/null)
    if [[ "$real_secret" == true ]]; then
        env_hits=$((env_hits + 1))
        env_files="${env_files} ${f}"
    fi
done < <(find /home /var/www /opt -name ".env" -type f -print0 2>/dev/null)

if [[ "$env_hits" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C1" ".env Files with Secrets" "Critical" "PASS" \
        "No .env files containing sensitive keys found in /home, /var/www, /opt" ""
else
    add_finding "${SCRIPT_ID}-C1" ".env Files with Secrets" "Critical" "FAIL" \
        "${env_hits} .env file(s) contain sensitive key patterns:${env_files}" \
        "Move secrets to a secrets manager (Vault, AWS Secrets Manager). Add .env to .gitignore."
fi

# C2 – Exposed private SSH keys (world-readable)
key_hits=0
key_files=""
while IFS= read -r -d '' f; do
    perms=$(stat -c '%a' "$f" 2>/dev/null || true)
    # World-readable: last octet has read bit (4,5,6,7)
    last_digit="${perms: -1}"
    if [[ "$last_digit" =~ [4-7] ]]; then
        key_hits=$((key_hits + 1))
        key_files="${key_files} ${f}(${perms})"
    fi
done < <(find /home /root /etc/ssh -type f \( -name "*.pem" -o -name "id_rsa" -o -name "id_ecdsa" -o -name "id_ed25519" \) -print0 2>/dev/null)

if [[ "$key_hits" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C2" "World-Readable Private SSH Keys" "Critical" "PASS" \
        "No world-readable private key files found" ""
else
    add_finding "${SCRIPT_ID}-C2" "World-Readable Private SSH Keys" "Critical" "FAIL" \
        "${key_hits} world-readable private key(s):${key_files}" \
        "Run: chmod 600 <keyfile> for each affected file"
fi

# C3 – Hardcoded credentials in common config directories
cred_hits=0
cred_files=""
while IFS= read -r -d '' f; do
    if grep -iqE '^\s*(password|secret|api_key)\s*=' "$f" 2>/dev/null; then
        cred_hits=$((cred_hits + 1))
        cred_files="${cred_files} ${f}"
    fi
done < <(find /etc /var/www -maxdepth 3 -type f \( -name "*.conf" -o -name "*.cfg" \) -print0 2>/dev/null)

if [[ "$cred_hits" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C3" "Hardcoded Credentials in Configs" "High" "PASS" \
        "No plaintext credential patterns found in /etc or /var/www config files" ""
else
    add_finding "${SCRIPT_ID}-C3" "Hardcoded Credentials in Configs" "High" "FAIL" \
        "${cred_hits} config file(s) with credential patterns:${cred_files}" \
        "Replace hardcoded credentials with environment variables or a secrets manager"
fi

# C4 – AWS/cloud credential files exposed
cloud_issues=""
for creds_path in /root/.aws/credentials /root/.azure /root/.gcp; do
    [[ -e "$creds_path" ]] || continue
    perms=$(stat -c '%a' "$creds_path" 2>/dev/null || true)
    last_digit="${perms: -1}"
    if [[ "$last_digit" =~ [4-7] ]]; then
        cloud_issues="${cloud_issues} ${creds_path}(world-readable:${perms})"
    else
        cloud_issues="${cloud_issues} ${creds_path}(exists,perms:${perms})"
    fi
done
while IFS= read -r -d '' f; do
    perms=$(stat -c '%a' "$f" 2>/dev/null || true)
    last_digit="${perms: -1}"
    [[ "$last_digit" =~ [4-7] ]] && cloud_issues="${cloud_issues} ${f}(world-readable:${perms})"
done < <(find /home -maxdepth 3 -path "*/.aws/credentials" -print0 2>/dev/null)

if [[ -z "$cloud_issues" ]]; then
    add_finding "${SCRIPT_ID}-C4" "Cloud Credential Files" "High" "PASS" \
        "No world-readable cloud credential files found" ""
else
    add_finding "${SCRIPT_ID}-C4" "Cloud Credential Files" "High" "WARN" \
        "Cloud credential file(s) found:${cloud_issues}" \
        "Restrict permissions (chmod 600) and prefer IAM roles or short-lived tokens over static credentials"
fi

# C5 – Git repositories with secrets (.gitignore doesn't exclude .env)
git_hits=0
git_issues=""
while IFS= read -r -d '' gitdir; do
    repo=$(dirname "$gitdir")
    gitignore="${repo}/.gitignore"
    if [[ ! -f "$gitignore" ]] || ! grep -q '\.env' "$gitignore" 2>/dev/null; then
        git_hits=$((git_hits + 1))
        git_issues="${git_issues} ${repo}"
    fi
done < <(find /home /opt /var/www -maxdepth 5 -name ".git" -type d -print0 2>/dev/null)

if [[ "$git_hits" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C5" "Git Repos Missing .env in .gitignore" "High" "PASS" \
        "All found git repos have .env excluded in .gitignore" ""
else
    add_finding "${SCRIPT_ID}-C5" "Git Repos Missing .env in .gitignore" "High" "WARN" \
        "${git_hits} git repo(s) missing .env exclusion:${git_issues}" \
        "Add .env to .gitignore in each repo. Audit git log for committed secrets with git-secrets or truffleHog."
fi

# C6 – Docker credential files with plaintext auth
docker_hits=0
docker_files=""
while IFS= read -r -d '' f; do
    if grep -q '"auth"' "$f" 2>/dev/null; then
        # auth field present – may be base64 plaintext
        docker_hits=$((docker_hits + 1))
        docker_files="${docker_files} ${f}"
    fi
done < <(find /root /home -maxdepth 4 -path "*/.docker/config.json" -print0 2>/dev/null)

if [[ "$docker_hits" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C6" "Docker Plaintext Credentials" "High" "PASS" \
        "No Docker config.json files with plaintext auth fields found" ""
else
    add_finding "${SCRIPT_ID}-C6" "Docker Plaintext Credentials" "High" "FAIL" \
        "${docker_hits} Docker config file(s) with auth entries:${docker_files}" \
        "Use a credential store (pass, secretservice) instead of plaintext auth in docker config.json"
fi

# C7 – World-readable shadow backup files
shadow_hits=0
shadow_files=""
while IFS= read -r -d '' f; do
    perms=$(stat -c '%a' "$f" 2>/dev/null || true)
    last_digit="${perms: -1}"
    if [[ "$last_digit" =~ [4-7] ]]; then
        shadow_hits=$((shadow_hits + 1))
        shadow_files="${shadow_files} ${f}(${perms})"
    fi
done < <(find /etc -maxdepth 2 -type f \( -name "shadow*" -o -name "shadow.bak" -o -name "shadow.orig" -o -name "passwd.bak" -o -name "passwd.orig" \) -print0 2>/dev/null)

if [[ "$shadow_hits" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C7" "World-Readable Shadow/Passwd Backups" "Critical" "PASS" \
        "No world-readable shadow or passwd backup files found in /etc" ""
else
    add_finding "${SCRIPT_ID}-C7" "World-Readable Shadow/Passwd Backups" "Critical" "FAIL" \
        "${shadow_hits} sensitive backup file(s) with open permissions:${shadow_files}" \
        "Run: chmod 000 <file> or remove unnecessary backup files. Shadow file must not be world-readable."
fi

# ── Optional Fix ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "INFO: Secrets require manual review – automated removal risks data loss." >&2
    echo "Recommendations:" >&2
    echo "  1. Use HashiCorp Vault or cloud-native secrets managers for all credentials." >&2
    echo "  2. Run: git-secrets --scan or truffleHog to audit git history." >&2
    echo "  3. Rotate any secrets found by this scan immediately." >&2
    echo "  4. Restrict file permissions: chmod 600 on all private keys." >&2
fi

# ── Output ───────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_secrets_scan" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
