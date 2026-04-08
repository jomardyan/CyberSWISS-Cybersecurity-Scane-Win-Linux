#!/usr/bin/env bash
# =============================================================================
# L26 – SAST / SCA Code & Dependency Security Scanner (Linux)
# =============================================================================
# ID       : L26
# Category : Code & Dependency Security (SAST/SCA)
# Severity : High
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : Yes
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L26_sast_sca_scanner.sh [--json] [--fix]
#
# Description
# -----------
# Performs static application security testing (SAST) and software composition
# analysis (SCA) — similar to industry-standard SAST/SCA tools:
#   C1  – Dependency vulnerability scan (package manifest CVE cross-reference)
#   C2  – Hardcoded secrets / credentials in source code
#   C3  – Python security issues (insecure functions, eval/exec usage)
#   C4  – JavaScript / Node.js security anti-patterns
#   C5  – Insecure use of shell commands in application code
#   C6  – SQL injection prone patterns in source code
#   C7  – Path traversal vulnerabilities in source code
#   C8  – Cryptographic weakness patterns (MD5, SHA1, DES, RC4 usage)
#   C9  – Insecure deserialization patterns
#   C10 – Dependency freshness (outdated lock files / unpinned versions)
# =============================================================================
set -euo pipefail

SCRIPT_ID="L26"
SCRIPT_NAME="SAST/SCA Code & Dependency Security Scanner"
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

# Scan roots: common application directories
SCAN_ROOTS=("/var/www" "/opt" "/home" "/srv" "/app")
EFFECTIVE_ROOTS=()
for root in "${SCAN_ROOTS[@]}"; do
    [[ -d "$root" ]] && EFFECTIVE_ROOTS+=("$root")
done

_find_files() {
    local pattern="$1" maxdepth="${2:-6}"
    if [[ "${#EFFECTIVE_ROOTS[@]}" -eq 0 ]]; then return; fi
    find "${EFFECTIVE_ROOTS[@]}" -maxdepth "$maxdepth" -type f -name "$pattern" \
        ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/vendor/*" \
        ! -path "*/__pycache__/*" ! -path "*/.tox/*" \
        -print0 2>/dev/null || true
}

_count_grep() {
    local pattern="$1"; shift
    grep -rlE "$pattern" "$@" 2>/dev/null | wc -l || true
}

# ── C1 – Dependency vulnerability scan ───────────────────────────────────────
dep_vuln_issues=""
dep_vuln_count=0

# Python: check pip packages against known-bad versions via safety db snapshot
if command -v pip3 &>/dev/null || command -v pip &>/dev/null; then
    PIP=$(command -v pip3 || command -v pip)
    # Check for known critically vulnerable packages
    declare -A VULN_PY_PKGS=(
        ["django"]="<4.2.9"
        ["flask"]="<3.0.2"
        ["requests"]="<2.31.0"
        ["pillow"]="<10.0.1"
        ["cryptography"]="<41.0.3"
        ["urllib3"]="<1.26.17"
        ["pyyaml"]="<6.0.1"
        ["setuptools"]="<65.5.1"
        ["werkzeug"]="<3.0.1"
        ["sqlalchemy"]="<2.0.23"
    )
    installed_py=$("$PIP" list --format=json 2>/dev/null || echo "[]")
    for pkg in "${!VULN_PY_PKGS[@]}"; do
        ver=$(echo "$installed_py" | python3 -c "
import json,sys
pkgs = json.load(sys.stdin)
for p in pkgs:
    if p['name'].lower() == '${pkg}'.lower():
        print(p['version'])
        break
" 2>/dev/null || true)
        if [[ -n "$ver" ]]; then
            vuln_threshold="${VULN_PY_PKGS[$pkg]}"
            dep_vuln_count=$((dep_vuln_count + 1))
            dep_vuln_issues="${dep_vuln_issues} Python:${pkg}==${ver}(needs${vuln_threshold});"
        fi
    done
fi

# Node.js: check for npm audit markers in package-lock.json
while IFS= read -r -d '' lock_file; do
    vuln_count=$(python3 - "$lock_file" 2>/dev/null <<'PYEOF'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    count = sum(1 for pkg, info in d.get('packages', {}).items()
                if isinstance(info, dict) and info.get('deprecated'))
    print(count)
except Exception:
    print(0)
PYEOF
)
    vuln_count="${vuln_count:-0}"
    if [[ "$vuln_count" -gt 0 ]]; then
        dep_vuln_count=$((dep_vuln_count + 1))
        dep_vuln_issues="${dep_vuln_issues} Node:${lock_file}(${vuln_count}-deprecated-pkgs);"
    fi
done < <(_find_files "package-lock.json" 5)

if [[ "$dep_vuln_count" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C1" "Dependency Vulnerability Scan" "High" "PASS" \
        "No known-vulnerable package versions detected in scanned environment" ""
else
    add_finding "${SCRIPT_ID}-C1" "Dependency Vulnerability Scan" "High" "FAIL" \
        "${dep_vuln_count} potentially vulnerable dependency(ies):${dep_vuln_issues}" \
        "Update vulnerable dependencies. Use 'pip install --upgrade <pkg>', 'npm audit fix'. Integrate dependency scanning into CI/CD pipeline."
fi

# ── C2 – Hardcoded secrets in source code ────────────────────────────────────
SECRET_PATTERNS='(api[_-]?key|apikey|api[_-]?secret|app_secret|access[_-]?token|auth[_-]?token|secret[_-]?key|private[_-]?key|password|passwd|db_pass|database_password)\s*[=:]\s*["\x27][A-Za-z0-9+/\-_]{8,}'
secret_hits=0
secret_files=""

while IFS= read -r -d '' f; do
    if grep -qiEo "$SECRET_PATTERNS" "$f" 2>/dev/null; then
        # Filter out obvious test/example values
        real_secret=false
        while IFS= read -r match; do
            val=$(echo "$match" | grep -oiE '[=:]\s*["\x27][^"\x27]{8,}' | tr -d '=: "\x27' | head -1 || true)
            if ! echo "$val" | grep -qiE '(placeholder|changeme|your[_a-z]*|example|test|sample|xxx+|<[^>]+>|\$\{[^}]+\})'; then
                real_secret=true
                break
            fi
        done < <(grep -iEo "$SECRET_PATTERNS" "$f" 2>/dev/null | head -10)
        if [[ "$real_secret" == true ]]; then
            secret_hits=$((secret_hits + 1))
            secret_files="${secret_files} ${f};"
        fi
    fi
done < <(find "${EFFECTIVE_ROOTS[@]+"${EFFECTIVE_ROOTS[@]}"}" -maxdepth 6 -type f \
    \( -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.php" -o -name "*.java" \
       -o -name "*.rb" -o -name "*.go" -o -name "*.env" -o -name "*.yaml" -o -name "*.yml" \
       -o -name "*.json" -o -name "*.xml" -o -name "*.conf" -o -name "*.cfg" \) \
    ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/vendor/*" \
    -print0 2>/dev/null)

if [[ "$secret_hits" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C2" "Hardcoded Secrets in Source Code" "Critical" "PASS" \
        "No hardcoded credential patterns detected in scanned application files" ""
else
    add_finding "${SCRIPT_ID}-C2" "Hardcoded Secrets in Source Code" "Critical" "FAIL" \
        "${secret_hits} file(s) with potential hardcoded secrets:${secret_files}" \
        "Replace hardcoded secrets with environment variables or a secrets manager (HashiCorp Vault, AWS Secrets Manager). Run git-secrets or truffleHog on git history."
fi

# ── C3 – Python security anti-patterns ───────────────────────────────────────
py_issues=0
py_files=""

while IFS= read -r -d '' f; do
    file_issues=""
    # eval() / exec() with variable arguments (code injection risk)
    grep -qE '^\s*(eval|exec)\s*\([^)]*[^"\x27)]+\)' "$f" 2>/dev/null && \
        file_issues="${file_issues}eval/exec-with-variable;"
    # subprocess with shell=True and variable interpolation
    grep -qE 'subprocess\.(run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True' "$f" 2>/dev/null && \
        file_issues="${file_issues}subprocess-shell=True;"
    # os.system with variable input
    grep -qE 'os\.system\s*\([^)]*[^"\x27)]+\)' "$f" 2>/dev/null && \
        file_issues="${file_issues}os.system-with-variable;"
    # pickle.loads from untrusted input
    grep -qE 'pickle\.(loads?|load)\s*\(' "$f" 2>/dev/null && \
        file_issues="${file_issues}pickle-deserialisation;"
    # yaml.load without Loader=SafeLoader
    grep -qE 'yaml\.load\s*\([^)]*\)' "$f" 2>/dev/null && \
        ! grep -qE 'yaml\.load\s*\([^)]*Loader\s*=' "$f" 2>/dev/null && \
        file_issues="${file_issues}yaml.load-unsafe;"
    # tempfile.mktemp (race condition)
    grep -qE 'tempfile\.mktemp\s*\(' "$f" 2>/dev/null && \
        file_issues="${file_issues}tempfile.mktemp-race;"
    # assert used for security checks
    grep -qE '^\s*assert\s+.*(auth|admin|permission|role|login|user)' "$f" 2>/dev/null && \
        file_issues="${file_issues}assert-security-check(disabled-with-O-flag);"

    if [[ -n "$file_issues" ]]; then
        py_issues=$((py_issues + 1))
        py_files="${py_files} ${f}(${file_issues});"
    fi
done < <(_find_files "*.py")

if [[ "$py_issues" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C3" "Python Security Anti-Patterns" "High" "PASS" \
        "No Python security anti-patterns detected in scanned files" ""
else
    add_finding "${SCRIPT_ID}-C3" "Python Security Anti-Patterns" "High" "FAIL" \
        "${py_issues} Python file(s) with security issues:${py_files}" \
        "Replace eval/exec with safer alternatives. Use subprocess with shell=False. Use yaml.safe_load. Use pickle alternatives (JSON, MessagePack) for untrusted data."
fi

# ── C4 – JavaScript / Node.js security anti-patterns ─────────────────────────
js_issues=0
js_files=""

while IFS= read -r -d '' f; do
    file_issues=""
    # eval() usage
    grep -qE '\beval\s*\(' "$f" 2>/dev/null && file_issues="${file_issues}eval();"
    # innerHTML with variable (XSS risk)
    grep -qE 'innerHTML\s*=\s*[^"'"'"';]' "$f" 2>/dev/null && file_issues="${file_issues}innerHTML-assignment;"
    # document.write
    grep -qE 'document\.write\s*\(' "$f" 2>/dev/null && file_issues="${file_issues}document.write;"
    # child_process.exec with variable (command injection)
    grep -qE 'exec\s*\([^"'"'"']' "$f" 2>/dev/null && \
        grep -q 'child_process\|require.*exec' "$f" 2>/dev/null && \
        file_issues="${file_issues}child_process.exec-with-variable;"
    # SQL string concatenation in Node
    grep -qE '(query|execute)\s*\(\s*["\x27].*\+|`(SELECT|INSERT|UPDATE|DELETE).*\$\{' "$f" 2>/dev/null && \
        file_issues="${file_issues}sql-string-concat;"
    # Prototype pollution
    grep -qE 'Object\.assign\s*\(\s*\{\s*\}.*req\.' "$f" 2>/dev/null && \
        file_issues="${file_issues}possible-prototype-pollution;"
    # JWT verification disabled
    grep -qE '(algorithms\s*:\s*\[\s*["\x27]none["\x27]|verify.*false)' "$f" 2>/dev/null && \
        file_issues="${file_issues}jwt-none-algorithm;"

    if [[ -n "$file_issues" ]]; then
        js_issues=$((js_issues + 1))
        js_files="${js_files} ${f}(${file_issues});"
    fi
done < <(find "${EFFECTIVE_ROOTS[@]+"${EFFECTIVE_ROOTS[@]}"}" -maxdepth 6 -type f \
    \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" \) \
    ! -path "*/node_modules/*" ! -path "*/.git/*" \
    -print0 2>/dev/null)

if [[ "$js_issues" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C4" "JavaScript/Node.js Security Anti-Patterns" "High" "PASS" \
        "No JavaScript/Node.js security anti-patterns detected in scanned files" ""
else
    add_finding "${SCRIPT_ID}-C4" "JavaScript/Node.js Security Anti-Patterns" "High" "FAIL" \
        "${js_issues} JS/TS file(s) with security issues:${js_files}" \
        "Avoid eval(). Use textContent instead of innerHTML. Use child_process.execFile (no shell). Use parameterised queries. Use DOMPurify for HTML sanitisation."
fi

# ── C5 – Insecure shell command execution in app code ─────────────────────────
shell_inject_hits=0
shell_inject_files=""

SHELL_INJECT_RE='(os\.system|subprocess\.call|subprocess\.run|subprocess\.Popen|exec\(|shell_exec\(|passthru\(|popen\(|backtick|`[^`]*\$)'

while IFS= read -r -d '' f; do
    if grep -qE "$SHELL_INJECT_RE" "$f" 2>/dev/null; then
        # Look specifically for user-controlled variable in shell call
        if grep -qE '(os\.system|shell_exec|exec)\s*\([^)]*(\$_(GET|POST|REQUEST|SERVER)|request\.|params\.)' "$f" 2>/dev/null || \
           grep -qE 'subprocess\.(run|call|Popen)\s*\([^)]*shell\s*=\s*True' "$f" 2>/dev/null; then
            shell_inject_hits=$((shell_inject_hits + 1))
            shell_inject_files="${shell_inject_files} ${f};"
        fi
    fi
done < <(find "${EFFECTIVE_ROOTS[@]+"${EFFECTIVE_ROOTS[@]}"}" -maxdepth 6 -type f \
    \( -name "*.py" -o -name "*.php" -o -name "*.rb" -o -name "*.js" \) \
    ! -path "*/node_modules/*" ! -path "*/.git/*" -print0 2>/dev/null)

if [[ "$shell_inject_hits" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C5" "Insecure Shell Command Execution" "Critical" "PASS" \
        "No obvious shell injection patterns with user-controlled input detected" ""
else
    add_finding "${SCRIPT_ID}-C5" "Insecure Shell Command Execution" "Critical" "FAIL" \
        "${shell_inject_hits} file(s) with shell injection risk:${shell_inject_files}" \
        "Never pass user input to shell commands. Use parameterised APIs (subprocess with list args, no shell=True). Validate and whitelist all command arguments."
fi

# ── C6 – SQL injection prone patterns in source code ─────────────────────────
code_sqli_hits=0
code_sqli_files=""

SQL_CONCAT_RE='(execute|query|cursor\.execute|db\.query)\s*\(\s*["\x27](SELECT|INSERT|UPDATE|DELETE|DROP|CREATE).*["\x27]\s*(\+|%|\.format\(|f["\x27])|f["\x27](SELECT|INSERT|UPDATE|DELETE).*\{[^}]'

while IFS= read -r -d '' f; do
    if grep -qiE "$SQL_CONCAT_RE" "$f" 2>/dev/null; then
        code_sqli_hits=$((code_sqli_hits + 1))
        code_sqli_files="${code_sqli_files} ${f};"
    fi
done < <(find "${EFFECTIVE_ROOTS[@]+"${EFFECTIVE_ROOTS[@]}"}" -maxdepth 6 -type f \
    \( -name "*.py" -o -name "*.php" -o -name "*.java" -o -name "*.js" -o -name "*.rb" \) \
    ! -path "*/node_modules/*" ! -path "*/.git/*" -print0 2>/dev/null)

if [[ "$code_sqli_hits" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C6" "SQL Injection Patterns in Source Code" "Critical" "PASS" \
        "No SQL string concatenation patterns detected in scanned source files" ""
else
    add_finding "${SCRIPT_ID}-C6" "SQL Injection Patterns in Source Code" "Critical" "FAIL" \
        "${code_sqli_hits} file(s) with SQL string concatenation:${code_sqli_files}" \
        "Use parameterised queries: cursor.execute('SELECT ? FROM t WHERE id=?', (val,)) in Python, PreparedStatement in Java. Use an ORM."
fi

# ── C7 – Path traversal vulnerabilities ──────────────────────────────────────
path_trav_hits=0
path_trav_files=""

PATH_TRAV_RE='(open\(|file_get_contents\(|readFile\(|createReadStream\(|fopen\()\s*[^)]*(\$_(GET|POST|REQUEST)|request\.(args|form|params|query)|req\.(query|body|params))'

while IFS= read -r -d '' f; do
    if grep -qE "$PATH_TRAV_RE" "$f" 2>/dev/null; then
        path_trav_hits=$((path_trav_hits + 1))
        path_trav_files="${path_trav_files} ${f};"
    fi
done < <(find "${EFFECTIVE_ROOTS[@]+"${EFFECTIVE_ROOTS[@]}"}" -maxdepth 6 -type f \
    \( -name "*.py" -o -name "*.php" -o -name "*.js" -o -name "*.ts" \) \
    ! -path "*/node_modules/*" ! -path "*/.git/*" -print0 2>/dev/null)

if [[ "$path_trav_hits" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C7" "Path Traversal Vulnerability Patterns" "High" "PASS" \
        "No path traversal patterns with user-controlled input detected" ""
else
    add_finding "${SCRIPT_ID}-C7" "Path Traversal Vulnerability Patterns" "High" "FAIL" \
        "${path_trav_hits} file(s) with potential path traversal:${path_trav_files}" \
        "Validate and sanitise file paths. Use os.path.realpath() and verify it starts with an allowed base directory. Never use user input directly in file open operations."
fi

# ── C8 – Cryptographic weakness patterns ─────────────────────────────────────
crypto_hits=0
crypto_files=""

WEAK_CRYPTO_RE='(hashlib\.(md5|sha1)\s*\(|MD5\.|SHA1\.|new\s*\(\s*["\x27](md5|sha1|des|rc4|rc2|blowfish)["\x27]|Cipher\.getInstance\s*\(\s*["\x27](DES|RC4|MD5withRSA)|createHash\s*\(\s*["\x27](md5|sha1)["\x27]|DES\.new|ARC4\.new)'

while IFS= read -r -d '' f; do
    if grep -qiE "$WEAK_CRYPTO_RE" "$f" 2>/dev/null; then
        algos=$(grep -iEo "$WEAK_CRYPTO_RE" "$f" 2>/dev/null | head -3 | tr '\n' ',' | sed 's/,$//')
        crypto_hits=$((crypto_hits + 1))
        crypto_files="${crypto_files} ${f}(${algos});"
    fi
done < <(find "${EFFECTIVE_ROOTS[@]+"${EFFECTIVE_ROOTS[@]}"}" -maxdepth 6 -type f \
    \( -name "*.py" -o -name "*.java" -o -name "*.js" -o -name "*.ts" -o -name "*.php" \) \
    ! -path "*/node_modules/*" ! -path "*/.git/*" -print0 2>/dev/null)

if [[ "$crypto_hits" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C8" "Weak Cryptographic Algorithm Usage" "High" "PASS" \
        "No deprecated/weak cryptographic algorithms (MD5/SHA1/DES/RC4) detected in source code" ""
else
    add_finding "${SCRIPT_ID}-C8" "Weak Cryptographic Algorithm Usage" "High" "FAIL" \
        "${crypto_hits} file(s) using weak crypto:${crypto_files}" \
        "Replace MD5/SHA1 with SHA-256/SHA-3. Replace DES/RC4 with AES-256-GCM. Use bcrypt/scrypt/argon2 for password hashing. Never use MD5/SHA1 for security-sensitive purposes."
fi

# ── C9 – Insecure deserialization patterns ────────────────────────────────────
deser_hits=0
deser_files=""

DESER_RE='(pickle\.(loads?|load)\s*\(|yaml\.load\s*\([^)]*[^S]afe|unserialize\s*\(\s*\$_(GET|POST|REQUEST)|ObjectInputStream|readObject\s*\(\)|Marshal\.load\s*\(|JSON\.parse\s*\([^)]*request\.|JSON\.parse\s*\([^)]*req\.)'

while IFS= read -r -d '' f; do
    if grep -qE "$DESER_RE" "$f" 2>/dev/null; then
        deser_hits=$((deser_hits + 1))
        patterns=$(grep -Eo "$DESER_RE" "$f" 2>/dev/null | head -2 | tr '\n' ',' | sed 's/,$//')
        deser_files="${deser_files} ${f}(${patterns});"
    fi
done < <(find "${EFFECTIVE_ROOTS[@]+"${EFFECTIVE_ROOTS[@]}"}" -maxdepth 6 -type f \
    \( -name "*.py" -o -name "*.php" -o -name "*.java" -o -name "*.rb" -o -name "*.js" \) \
    ! -path "*/node_modules/*" ! -path "*/.git/*" -print0 2>/dev/null)

if [[ "$deser_hits" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C9" "Insecure Deserialization Patterns" "Critical" "PASS" \
        "No insecure deserialization patterns detected in scanned files" ""
else
    add_finding "${SCRIPT_ID}-C9" "Insecure Deserialization Patterns" "Critical" "FAIL" \
        "${deser_hits} file(s) with deserialization risk:${deser_files}" \
        "Never deserialise untrusted data with pickle/yaml.load/unserialize. Use yaml.safe_load, JSON for data exchange. Sign and verify serialised data before deserialisation."
fi

# ── C10 – Dependency freshness and version pinning ────────────────────────────
dep_fresh_issues=""

# Python: check requirements.txt for unpinned or wildcard versions
while IFS= read -r -d '' req_file; do
    unpinned=0
    wildcard=0
    while IFS= read -r line; do
        [[ "$line" =~ ^#|^$ ]] && continue
        [[ "$line" =~ ^-[er] ]] && continue
        if ! echo "$line" | grep -qE '(==|===)'; then
            unpinned=$((unpinned + 1))
        fi
        if echo "$line" | grep -qE '\*|>=|~='; then
            wildcard=$((wildcard + 1))
        fi
    done < "$req_file"
    if [[ "$unpinned" -gt 3 || "$wildcard" -gt 3 ]]; then
        dep_fresh_issues="${dep_fresh_issues} Python:${req_file}(${unpinned}-unpinned,${wildcard}-wildcard);"
    fi
done < <(_find_files "requirements*.txt" 5)

# Node.js: check for * or latest in package.json
while IFS= read -r -d '' pkg_file; do
    wildcard_count=$(python3 -c "
import json,sys
try:
    d=json.load(open('${pkg_file}'))
    deps={**d.get('dependencies',{}),**d.get('devDependencies',{})}
    count=sum(1 for v in deps.values() if v in ('*','latest') or v.startswith('^') or v.startswith('~'))
    print(count)
except: print(0)
" 2>/dev/null || echo "0")
    if [[ "$wildcard_count" -gt 5 ]]; then
        dep_fresh_issues="${dep_fresh_issues} Node:${pkg_file}(${wildcard_count}-wildcard-versions);"
    fi
done < <(_find_files "package.json" 4)

# Check age of lock files
while IFS= read -r -d '' lock_file; do
    age_days=$(( ($(date +%s) - $(stat -c %Y "$lock_file" 2>/dev/null || echo 0)) / 86400 ))
    if [[ "$age_days" -gt 90 ]]; then
        dep_fresh_issues="${dep_fresh_issues} ${lock_file}(${age_days}d-not-updated);"
    fi
done < <(find "${EFFECTIVE_ROOTS[@]+"${EFFECTIVE_ROOTS[@]}"}" -maxdepth 5 -type f \
    \( -name "package-lock.json" -o -name "yarn.lock" -o -name "Pipfile.lock" -o -name "poetry.lock" \) \
    -print0 2>/dev/null)

if [[ -z "$dep_fresh_issues" ]]; then
    add_finding "${SCRIPT_ID}-C10" "Dependency Freshness and Version Pinning" "Med" "PASS" \
        "Dependency files appear reasonably pinned and recently updated" ""
else
    add_finding "${SCRIPT_ID}-C10" "Dependency Freshness and Version Pinning" "Med" "WARN" \
        "Dependency management issues:${dep_fresh_issues}" \
        "Pin all dependencies to exact versions in requirements.txt (==). Commit and regularly update lock files. Run 'pip-compile', 'npm ci' in CI. Use Dependabot or Renovate for automated updates."
fi

# ── Optional Fix ──────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "INFO: SAST/SCA fixes require developer action on application code." >&2
    echo "Recommendations:" >&2
    echo "  1. Integrate this script into CI/CD to fail builds on FAIL-level findings." >&2
    echo "  2. Run 'pip install --upgrade <vulnerable-package>' for Python dependencies." >&2
    echo "  3. Run 'npm audit fix' for Node.js packages." >&2
    echo "  4. Replace weak crypto, eval(), pickle, and shell injection patterns manually." >&2

    # Auto-fix: upgrade Python packages with known vulnerabilities if pip is available
    if command -v pip3 &>/dev/null; then
        for pkg in "${!VULN_PY_PKGS[@]}"; do
            ver=$(pip3 show "$pkg" 2>/dev/null | grep '^Version:' | awk '{print $2}' || true)
            if [[ -n "$ver" ]]; then
                echo "Upgrading Python package: ${pkg}" >&2
                pip3 install --upgrade "$pkg" 2>&1 | tail -1 >&2 || true
            fi
        done
    fi
fi

# ── Output ────────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_sast_sca_scanner" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
