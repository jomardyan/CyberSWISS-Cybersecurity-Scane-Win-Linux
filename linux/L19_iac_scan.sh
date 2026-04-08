#!/usr/bin/env bash
# =============================================================================
# L19 – IaC Security Scan (Linux)
# =============================================================================
# ID       : L19
# Category : IaC Security
# Severity : High
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : No
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : ./L19_iac_scan.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L19"
SCRIPT_NAME="IaC Security Scan"
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

IaC_SEARCH_DIRS=(/home /opt /var/www /srv)

# C1 – Dockerfile security issues
docker_issues=""
docker_count=0
while IFS= read -r -d '' f; do
    docker_count=$((docker_count + 1))
    # USER root as last USER instruction
    last_user=$(grep -iE '^USER\s+' "$f" 2>/dev/null | tail -1 || true)
    if [[ -z "$last_user" ]] || echo "$last_user" | grep -qi 'root\|0'; then
        docker_issues="${docker_issues} ${f}:runs-as-root;"
    fi
    # Privileged flag
    grep -qiE '\-\-privileged' "$f" 2>/dev/null && docker_issues="${docker_issues} ${f}:--privileged-flag;"
    # ADD vs COPY
    grep -qiE '^ADD\s+' "$f" 2>/dev/null && docker_issues="${docker_issues} ${f}:ADD-instead-of-COPY;"
    # Sensitive env vars
    grep -qiE '^(ENV|ARG)\s+.*(PASSWORD|SECRET|KEY|TOKEN)' "$f" 2>/dev/null && \
        docker_issues="${docker_issues} ${f}:sensitive-ENV/ARG;"
    # No HEALTHCHECK
    grep -qiE '^HEALTHCHECK\s+' "$f" 2>/dev/null || docker_issues="${docker_issues} ${f}:no-HEALTHCHECK;"
done < <(find "${IaC_SEARCH_DIRS[@]}" -maxdepth 6 -name "Dockerfile" -type f -print0 2>/dev/null)

if [[ "$docker_count" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C1" "Dockerfile Security" "High" "INFO" \
        "No Dockerfiles found in search paths" ""
elif [[ -z "$docker_issues" ]]; then
    add_finding "${SCRIPT_ID}-C1" "Dockerfile Security" "High" "PASS" \
        "${docker_count} Dockerfile(s) checked – no critical issues found" ""
else
    add_finding "${SCRIPT_ID}-C1" "Dockerfile Security" "High" "FAIL" \
        "${docker_count} Dockerfile(s) with issues: ${docker_issues}" \
        "Use non-root USER, prefer COPY over ADD, avoid secrets in ENV/ARG, add HEALTHCHECK"
fi

# C2 – docker-compose security
compose_issues=""
compose_count=0
while IFS= read -r -d '' f; do
    compose_count=$((compose_count + 1))
    grep -qiE 'privileged:\s*true' "$f" 2>/dev/null && compose_issues="${compose_issues} ${f}:privileged=true;"
    grep -qiE 'network_mode:\s*host' "$f" 2>/dev/null && compose_issues="${compose_issues} ${f}:network_mode=host;"
    grep -qiE '(/etc:|/var/run/docker\.sock:)' "$f" 2>/dev/null && \
        compose_issues="${compose_issues} ${f}:sensitive-volume-mount;"
done < <(find "${IaC_SEARCH_DIRS[@]}" -maxdepth 6 \( -name "docker-compose.yml" -o -name "docker-compose.yaml" \) -type f -print0 2>/dev/null)

if [[ "$compose_count" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C2" "Docker Compose Security" "High" "INFO" \
        "No docker-compose files found in search paths" ""
elif [[ -z "$compose_issues" ]]; then
    add_finding "${SCRIPT_ID}-C2" "Docker Compose Security" "High" "PASS" \
        "${compose_count} docker-compose file(s) checked – no critical issues found" ""
else
    add_finding "${SCRIPT_ID}-C2" "Docker Compose Security" "High" "FAIL" \
        "${compose_count} docker-compose file(s) with issues: ${compose_issues}" \
        "Remove privileged:true and host networking; avoid mounting /etc or docker.sock"
fi

# C3 – Terraform security
tf_issues=""
tf_count=0
while IFS= read -r -d '' f; do
    tf_count=$((tf_count + 1))
    # Public S3 ACLs
    grep -qiE 'acl\s*=\s*"public' "$f" 2>/dev/null && tf_issues="${tf_issues} ${f}:public-s3-acl;"
    # Hardcoded secrets
    grep -qiE '(password|secret|api_key)\s*=\s*"[^"]{3,}"' "$f" 2>/dev/null && \
        tf_issues="${tf_issues} ${f}:hardcoded-secret;"
    # Unencrypted storage (encrypted = false or absent)
    if grep -qiE 'aws_ebs_volume|aws_db_instance|aws_s3_bucket' "$f" 2>/dev/null; then
        grep -qiE 'encrypted\s*=\s*false' "$f" 2>/dev/null && tf_issues="${tf_issues} ${f}:encryption=false;"
    fi
done < <(find "${IaC_SEARCH_DIRS[@]}" -maxdepth 8 -name "*.tf" -type f -print0 2>/dev/null)

if [[ "$tf_count" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C3" "Terraform Security" "High" "INFO" \
        "No Terraform (.tf) files found in search paths" ""
elif [[ -z "$tf_issues" ]]; then
    add_finding "${SCRIPT_ID}-C3" "Terraform Security" "High" "PASS" \
        "${tf_count} Terraform file(s) checked – no critical issues found" ""
else
    add_finding "${SCRIPT_ID}-C3" "Terraform Security" "High" "FAIL" \
        "${tf_count} Terraform file(s) with issues: ${tf_issues}" \
        "Use Terraform variables/secrets backends; enforce encryption; review S3 bucket ACLs"
fi

# C4 – Kubernetes manifests
k8s_issues=""
k8s_count=0
K8S_PATHS=(/home /opt /var/www /srv /etc/kubernetes)
while IFS= read -r -d '' f; do
    grep -qiE '(apiVersion|kind:)' "$f" 2>/dev/null || continue
    k8s_count=$((k8s_count + 1))
    grep -qiE 'privileged:\s*true' "$f" 2>/dev/null && k8s_issues="${k8s_issues} ${f}:privileged=true;"
    grep -qiE 'hostPID:\s*true' "$f" 2>/dev/null && k8s_issues="${k8s_issues} ${f}:hostPID=true;"
    grep -qiE 'hostNetwork:\s*true' "$f" 2>/dev/null && k8s_issues="${k8s_issues} ${f}:hostNetwork=true;"
    grep -qiE 'runAsUser:\s*0' "$f" 2>/dev/null && k8s_issues="${k8s_issues} ${f}:runAsRoot;"
    grep -qiE 'namespace:\s*default' "$f" 2>/dev/null && k8s_issues="${k8s_issues} ${f}:default-namespace;"
    grep -qiE 'containers:' "$f" 2>/dev/null && \
        ! grep -qiE 'securityContext:' "$f" 2>/dev/null && \
        k8s_issues="${k8s_issues} ${f}:no-securityContext;"
done < <(find "${K8S_PATHS[@]}" -maxdepth 8 -name "*.yaml" -type f -print0 2>/dev/null)

if [[ "$k8s_count" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C4" "Kubernetes Manifest Security" "High" "INFO" \
        "No Kubernetes YAML manifests found in search paths" ""
elif [[ -z "$k8s_issues" ]]; then
    add_finding "${SCRIPT_ID}-C4" "Kubernetes Manifest Security" "High" "PASS" \
        "${k8s_count} K8s manifest(s) checked – no critical issues found" ""
else
    add_finding "${SCRIPT_ID}-C4" "Kubernetes Manifest Security" "High" "FAIL" \
        "${k8s_count} K8s manifest(s) with issues: ${k8s_issues}" \
        "Enforce securityContext, avoid privileged/hostPID/hostNetwork, use dedicated namespaces"
fi

# C5 – Helm charts
helm_issues=""
helm_count=0
while IFS= read -r -d '' chart; do
    helm_count=$((helm_count + 1))
    chart_dir=$(dirname "$chart")
    # Check appVersion present
    grep -qiE 'appVersion' "$chart" 2>/dev/null || helm_issues="${helm_issues} ${chart}:no-appVersion;"
    # Check values.yaml for insecure defaults:
    # Flag the chart if any individual password field has a non-empty, non-templated value.
    # This per-line check avoids false negatives when some fields are templated but others are not.
    values_file="${chart_dir}/values.yaml"
    if [[ -f "$values_file" ]]; then
        while IFS= read -r line; do
            val="${line#*:}"
            val="${val%%#*}"
            val="${val//[[:space:]]/}"
            # Skip empty or template-only values ({{ ... }})
            [[ -z "$val" ]] && continue
            [[ "$val" =~ ^\{\{[^}]+\}\}$ ]] && continue
            # Non-empty, non-templated password field found
            helm_issues="${helm_issues} ${chart}:hardcoded-password-in-values.yaml;"
            break
        done < <(grep -iE 'password:\s*\S' "$values_file" 2>/dev/null)
    fi
done < <(find "${IaC_SEARCH_DIRS[@]}" -maxdepth 8 -name "Chart.yaml" -type f -print0 2>/dev/null)

if [[ "$helm_count" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C5" "Helm Chart Security" "Med" "INFO" \
        "No Helm Chart.yaml files found in search paths" ""
elif [[ -z "$helm_issues" ]]; then
    add_finding "${SCRIPT_ID}-C5" "Helm Chart Security" "Med" "PASS" \
        "${helm_count} Helm chart(s) checked – no critical issues found" ""
else
    add_finding "${SCRIPT_ID}-C5" "Helm Chart Security" "Med" "WARN" \
        "${helm_count} Helm chart(s) with issues: ${helm_issues}" \
        "Set appVersion; replace default passwords in values.yaml with secrets references"
fi

# C6 – Ansible playbooks
ansible_issues=""
ansible_count=0
while IFS= read -r -d '' f; do
    grep -qiE '^.*hosts:' "$f" 2>/dev/null || continue
    ansible_count=$((ansible_count + 1))
    # no_log: false on password tasks
    if grep -qiE '(password|secret|key)' "$f" 2>/dev/null; then
        grep -qiE 'no_log:\s*(yes|true)' "$f" 2>/dev/null || \
            ansible_issues="${ansible_issues} ${f}:no-no_log-on-sensitive-task;"
    fi
    # World-readable inventory
    perms=$(stat -c '%a' "$f" 2>/dev/null || true)
    last_digit="${perms: -1}"
    [[ "$last_digit" =~ [4-7] ]] && ansible_issues="${ansible_issues} ${f}:world-readable(${perms});"
done < <(find "${IaC_SEARCH_DIRS[@]}" -maxdepth 8 -name "*.yml" -type f -print0 2>/dev/null)

if [[ "$ansible_count" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C6" "Ansible Playbook Security" "Med" "INFO" \
        "No Ansible playbooks (yml with hosts:) found in search paths" ""
elif [[ -z "$ansible_issues" ]]; then
    add_finding "${SCRIPT_ID}-C6" "Ansible Playbook Security" "Med" "PASS" \
        "${ansible_count} Ansible playbook(s) checked – no critical issues found" ""
else
    add_finding "${SCRIPT_ID}-C6" "Ansible Playbook Security" "Med" "WARN" \
        "${ansible_count} Ansible playbook(s) with issues: ${ansible_issues}" \
        "Use no_log: true on tasks handling credentials; restrict inventory file permissions to 640"
fi

# C7 – IaC tools present
tools_found=""
for tool in terraform ansible kubectl helm docker; do
    command -v "$tool" &>/dev/null && tools_found="${tools_found} ${tool}($(command -v "$tool"))"
done

if [[ -z "$tools_found" ]]; then
    add_finding "${SCRIPT_ID}-C7" "IaC Tools Installed" "Info" "INFO" \
        "No IaC tools (terraform, ansible, kubectl, helm, docker) found in PATH" ""
else
    add_finding "${SCRIPT_ID}-C7" "IaC Tools Installed" "Info" "INFO" \
        "Installed IaC tools:${tools_found}" \
        "Ensure IaC tools are up-to-date and restricted to authorised users only"
fi

# ── Optional Fix ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "INFO: IaC security fixes require development team involvement." >&2
    echo "Recommendations:" >&2
    echo "  1. Integrate tfsec/checkov/trivy into CI/CD pipelines for automated IaC scanning." >&2
    echo "  2. Use Ansible Vault for sensitive variables." >&2
    echo "  3. Apply Kubernetes Pod Security Admission policies." >&2
    echo "  4. Enforce Dockerfile linting with hadolint in your build pipeline." >&2
fi

# ── Output ───────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_iac_scan" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
