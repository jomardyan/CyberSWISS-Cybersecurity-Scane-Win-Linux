#!/usr/bin/env bash
# =============================================================================
# L20 – SCA & License Compliance (Linux)
# =============================================================================
# ID       : L20
# Category : SCA & License Compliance
# Severity : Med
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : No (best results with sudo)
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : ./L20_sca_licenses.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L20"
SCRIPT_NAME="SCA & License Compliance"
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

ver_lt() {
    # Returns 0 (true) if version $1 < $2.
    # Strips build metadata (+...) before comparison.
    # Strips pre-release labels (-alpha, -rc1, etc.) for the base numeric comparison;
    # a version with a pre-release label is treated as less than the same base without one.
    local v1="${1%%+*}"   # strip build metadata
    local v2="${2%%+*}"

    # Separate base and pre-release (e.g. "3.0.9-rc1" → base="3.0.9", pre="rc1")
    local base1="${v1%%-*}" pre1="" base2="${v2%%-*}" pre2=""
    [[ "$v1" == *-* ]] && pre1="${v1#*-}"
    [[ "$v2" == *-* ]] && pre2="${v2#*-}"

    # Compare base version components numerically (strip non-numeric suffixes per component)
    local IFS=. i
    local a=($base1) b=($base2)
    local maxlen=$(( ${#a[@]} > ${#b[@]} ? ${#a[@]} : ${#b[@]} ))
    for (( i=0; i<maxlen; i++ )); do
        local ai="${a[i]:-0}" bi="${b[i]:-0}"
        # Keep only leading digits (e.g. "10a" → 10)
        ai=$( echo "$ai" | grep -oE '^[0-9]+' || echo 0 )
        bi=$( echo "$bi" | grep -oE '^[0-9]+' || echo 0 )
        (( 10#${ai:-0} < 10#${bi:-0} )) && return 0
        (( 10#${ai:-0} > 10#${bi:-0} )) && return 1
    done

    # Base versions are equal; a pre-release version is less than the final release
    [[ -n "$pre1" && -z "$pre2" ]] && return 0  # v1 is pre-release, v2 is final → v1 < v2
    return 1
}

# C1 – Python packages with known CVEs
pip_cmd=""
command -v pip3 &>/dev/null && pip_cmd="pip3"
command -v pip &>/dev/null  && [[ -z "$pip_cmd" ]] && pip_cmd="pip"

if [[ -z "$pip_cmd" ]]; then
    add_finding "${SCRIPT_ID}-C1" "Python Package CVE Check" "High" "WARN" \
        "pip/pip3 not found – Python package CVE check skipped" \
        "Install pip and re-run to check Python package vulnerabilities"
else
    vuln_pkgs=""
    declare -A MIN_VERSIONS=(
        [requests]="2.32.0"
        [urllib3]="1.26.18"
        [cryptography]="42.0.0"
        [Pillow]="10.0.0"
        [PyYAML]="6.0.1"
        [Django]="4.2.0"
    )
    pkg_list=$($pip_cmd list --format=columns 2>/dev/null || true)
    for pkg in requests urllib3 cryptography Pillow PyYAML Django; do
        min_ver="${MIN_VERSIONS[$pkg]:-}"
        [[ -z "$min_ver" ]] && continue
        installed=$(echo "$pkg_list" | grep -i "^${pkg}\s" | awk '{print $2}' | head -1 || true)
        [[ -z "$installed" ]] && continue
        if ver_lt "$installed" "$min_ver"; then
            vuln_pkgs="${vuln_pkgs} ${pkg}==${installed}(min:${min_ver})"
        fi
    done
    if [[ -z "$vuln_pkgs" ]]; then
        add_finding "${SCRIPT_ID}-C1" "Python Package CVE Check" "High" "PASS" \
            "Checked Python packages appear to meet minimum safe versions" ""
    else
        add_finding "${SCRIPT_ID}-C1" "Python Package CVE Check" "High" "FAIL" \
            "Vulnerable Python package(s):${vuln_pkgs}" \
            "Run: ${pip_cmd} install --upgrade requests urllib3 cryptography Pillow PyYAML Django"
    fi
fi

# C2 – Node.js package audit
if command -v npm &>/dev/null; then
    npm_audit_out=""
    crit_count=0
    high_count=0
    # Try npm audit in directories with package.json
    audit_dir=""
    for d in /home /opt /var/www; do
        first_pkg=$(find "$d" -maxdepth 4 -name "package.json" -not -path "*/node_modules/*" 2>/dev/null | head -1 || true)
        if [[ -n "$first_pkg" ]]; then
            audit_dir=$(dirname "$first_pkg")
            break
        fi
    done
    if [[ -n "$audit_dir" ]]; then
        npm_audit_out=$(cd "$audit_dir" && npm audit --json 2>/dev/null || true)
        crit_count=$(echo "$npm_audit_out" | grep -o '"critical":[0-9]*' | grep -o '[0-9]*' | head -1 || echo 0)
        high_count=$(echo "$npm_audit_out" | grep -o '"high":[0-9]*' | grep -o '[0-9]*' | head -1 || echo 0)
    fi
    if [[ "$crit_count" -gt 0 || "$high_count" -gt 0 ]]; then
        add_finding "${SCRIPT_ID}-C2" "Node.js Package Audit" "Critical" "FAIL" \
            "npm audit: ${crit_count} critical, ${high_count} high vulnerabilities in ${audit_dir}" \
            "Run: cd ${audit_dir} && npm audit fix  to resolve known vulnerabilities"
    else
        add_finding "${SCRIPT_ID}-C2" "Node.js Package Audit" "High" "PASS" \
            "No critical or high npm vulnerabilities detected${audit_dir:+ in ${audit_dir}}" ""
    fi
else
    # No npm – check for package.json files
    pkg_json_count=$(find /home /opt /var/www -maxdepth 5 -name "package.json" -not -path "*/node_modules/*" 2>/dev/null | wc -l || true)
    if [[ "$pkg_json_count" -gt 0 ]]; then
        add_finding "${SCRIPT_ID}-C2" "Node.js Package Audit" "High" "WARN" \
            "${pkg_json_count} package.json file(s) found but npm not available for audit" \
            "Install Node.js/npm and run: npm audit in each project directory"
    else
        add_finding "${SCRIPT_ID}-C2" "Node.js Package Audit" "High" "INFO" \
            "npm not installed and no package.json files found" ""
    fi
fi

# C3 – Copyleft license detection
copyleft_hits=""
while IFS= read -r -d '' f; do
    if grep -qiE '"license"\s*:\s*"(GPL|AGPL|LGPL)' "$f" 2>/dev/null; then
        gpl_pkgs=$(grep -iE '"license"\s*:\s*"(GPL|AGPL|LGPL)' "$f" 2>/dev/null | head -3 || true)
        copyleft_hits="${copyleft_hits} ${f}:${gpl_pkgs};"
    fi
done < <(find /home /opt /var/www -maxdepth 6 -name "package.json" -not -path "*/node_modules/*/node_modules/*" -type f -print0 2>/dev/null)

while IFS= read -r -d '' f; do
    if grep -qiE '^(GPL|AGPL|LGPL)' "$f" 2>/dev/null; then
        copyleft_hits="${copyleft_hits} ${f}:GPL-licensed-dependency;"
    fi
done < <(find /home /opt /var/www -maxdepth 5 -name "requirements.txt" -type f -print0 2>/dev/null)

if [[ -z "$copyleft_hits" ]]; then
    add_finding "${SCRIPT_ID}-C3" "Copyleft License Detection" "High" "PASS" \
        "No GPL/AGPL/LGPL licensed packages detected in scanned manifests" ""
else
    add_finding "${SCRIPT_ID}-C3" "Copyleft License Detection" "High" "WARN" \
        "Copyleft license(s) found: ${copyleft_hits}" \
        "Review GPL/AGPL license obligations. Consult legal team before distributing software using copyleft dependencies."
fi

# C4 – Outdated package managers
pm_issues=""
if command -v pip3 &>/dev/null; then
    pip_ver=$(pip3 --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1 || true)
    major=$(echo "$pip_ver" | cut -d. -f1)
    [[ -n "$major" && "$major" -lt 21 ]] && pm_issues="${pm_issues} pip3/${pip_ver}(outdated<21)"
fi
if command -v npm &>/dev/null; then
    npm_ver=$(npm --version 2>/dev/null || true)
    npm_major=$(echo "$npm_ver" | cut -d. -f1)
    [[ -n "$npm_major" && "$npm_major" -lt 8 ]] && pm_issues="${pm_issues} npm/${npm_ver}(outdated<8)"
fi
if command -v gem &>/dev/null; then
    gem_ver=$(gem --version 2>/dev/null || true)
    gem_major=$(echo "$gem_ver" | cut -d. -f1)
    [[ -n "$gem_major" && "$gem_major" -lt 3 ]] && pm_issues="${pm_issues} gem/${gem_ver}(outdated<3)"
fi

if [[ -z "$pm_issues" ]]; then
    add_finding "${SCRIPT_ID}-C4" "Package Manager Versions" "Low" "PASS" \
        "Installed package managers meet minimum version requirements" ""
else
    add_finding "${SCRIPT_ID}-C4" "Package Manager Versions" "Low" "WARN" \
        "Outdated package manager(s):${pm_issues}" \
        "Update package managers: pip install --upgrade pip; npm install -g npm"
fi

# C5 – Ruby gems security
if command -v bundle &>/dev/null && command -v bundler-audit &>/dev/null; then
    gemfile_dir=""
    for d in /home /opt /var/www; do
        first_gemlock=$(find "$d" -maxdepth 4 -name "Gemfile.lock" 2>/dev/null | head -1 || true)
        [[ -n "$first_gemlock" ]] && gemfile_dir=$(dirname "$first_gemlock") && break
    done
    if [[ -n "$gemfile_dir" ]]; then
        audit_out=$(cd "$gemfile_dir" && bundler-audit check 2>&1 || true)
        vuln_count=$(echo "$audit_out" | grep -c "Vulnerability found" || true)
        if [[ "$vuln_count" -gt 0 ]]; then
            add_finding "${SCRIPT_ID}-C5" "Ruby Gems Security" "High" "FAIL" \
                "${vuln_count} vulnerable gem(s) found by bundler-audit in ${gemfile_dir}" \
                "Run: bundle update in ${gemfile_dir} to update vulnerable gems"
        else
            add_finding "${SCRIPT_ID}-C5" "Ruby Gems Security" "High" "PASS" \
                "bundler-audit found no vulnerable gems in ${gemfile_dir}" ""
        fi
    else
        add_finding "${SCRIPT_ID}-C5" "Ruby Gems Security" "High" "INFO" \
            "No Gemfile.lock found in search paths" ""
    fi
else
    gemlock_count=$(find /home /opt /var/www -maxdepth 5 -name "Gemfile.lock" 2>/dev/null | wc -l || true)
    if [[ "$gemlock_count" -gt 0 ]]; then
        add_finding "${SCRIPT_ID}-C5" "Ruby Gems Security" "High" "WARN" \
            "${gemlock_count} Gemfile.lock found but bundler-audit not available" \
            "Install bundler-audit: gem install bundler-audit and run: bundler-audit check"
    else
        add_finding "${SCRIPT_ID}-C5" "Ruby Gems Security" "High" "INFO" \
            "No Ruby Gemfile.lock files found and bundler-audit not installed" ""
    fi
fi

# C6 – Java artifacts – log4j vulnerable versions
log4j_hits=""
while IFS= read -r -d '' f; do
    fname=$(basename "$f")
    # Vulnerable: log4j-core 2.0 through 2.14.x (CVE-2021-44228) or log4j 1.x (EOL)
    # Pattern matches minor versions 0-14 using word boundary (\b) to avoid partial matches
    # on safe versions like 2.15.x, 2.17.x. Covers: log4j-1.x.y, log4j-core-2.0 … 2.14.x.
    if echo "$fname" | grep -qiE 'log4j-(core-)?(1\.[0-9.]+|2\.(0|[1-9]|1[0-4])\b)'; then
        log4j_hits="${log4j_hits} ${f}"
    fi
done < <(find /opt /var/www /srv -maxdepth 8 -name "*.jar" -type f -print0 2>/dev/null)

if [[ -z "$log4j_hits" ]]; then
    add_finding "${SCRIPT_ID}-C6" "Log4j Vulnerable JARs" "Critical" "PASS" \
        "No log4j vulnerable version JARs detected in /opt, /var/www, /srv" ""
else
    add_finding "${SCRIPT_ID}-C6" "Log4j Vulnerable JARs" "Critical" "FAIL" \
        "Vulnerable log4j JAR(s) found:${log4j_hits}" \
        "Upgrade to log4j-core >= 2.17.1 immediately (CVE-2021-44228 Log4Shell). Remove all 1.x JARs."
fi

# C7 – Container image / OS EOL check
os_release=""
os_eol=false
if [[ -f /etc/os-release ]]; then
    os_name=$(grep -oP '(?<=^NAME=").*(?=")' /etc/os-release 2>/dev/null || \
              grep '^NAME=' /etc/os-release | cut -d= -f2 | tr -d '"' || true)
    os_ver=$(grep -oP '(?<=^VERSION_ID=").*(?=")' /etc/os-release 2>/dev/null || \
             grep '^VERSION_ID=' /etc/os-release | cut -d= -f2 | tr -d '"' || true)
    os_release="${os_name} ${os_ver}"

    if echo "$os_release" | grep -qiE 'ubuntu.*(16\.04|18\.04)'; then
        os_eol=true
    elif echo "$os_release" | grep -qiE 'centos.*(6|7)'; then
        os_eol=true
    elif echo "$os_release" | grep -qiE 'debian.*(8|9)\b'; then
        os_eol=true
    fi
fi

if [[ "$os_eol" == true ]]; then
    add_finding "${SCRIPT_ID}-C7" "End-of-Life OS / Container Base Image" "Critical" "FAIL" \
        "OS is at End-of-Life: ${os_release}" \
        "Upgrade to a supported OS release. EOL systems no longer receive security patches."
elif [[ -n "$os_release" ]]; then
    add_finding "${SCRIPT_ID}-C7" "End-of-Life OS / Container Base Image" "Critical" "PASS" \
        "OS release appears current: ${os_release}" ""
else
    add_finding "${SCRIPT_ID}-C7" "End-of-Life OS / Container Base Image" "Med" "WARN" \
        "Could not determine OS release from /etc/os-release" \
        "Manually verify the OS is not end-of-life"
fi

# ── Optional Fix ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "INFO: SCA fixes require reviewing package audit reports." >&2
    echo "Recommendations:" >&2
    echo "  1. Run: pip3 install --upgrade <package> for vulnerable Python packages." >&2
    echo "  2. Run: npm audit fix in Node.js project directories." >&2
    echo "  3. Integrate Dependabot or Renovate for automated dependency updates." >&2
    echo "  4. Remove any log4j 1.x or log4j-core < 2.17.1 JARs immediately." >&2
fi

# ── Output ───────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_sca_licenses" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
