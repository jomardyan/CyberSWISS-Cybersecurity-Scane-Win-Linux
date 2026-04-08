#!/usr/bin/env bash
# =============================================================================
# L18 – API Security & DAST (Linux)
# =============================================================================
# ID       : L18
# Category : API Security & DAST
# Severity : High
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : No (network checks only)
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : ./L18_api_endpoints.sh [--json] [--fix]
# =============================================================================
set -euo pipefail

SCRIPT_ID="L18"
SCRIPT_NAME="API Security & DAST"
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

CURL_OPTS="--connect-timeout 3 --max-time 5 -sk"
HAS_CURL=true
command -v curl &>/dev/null || HAS_CURL=false

# C1 – Discover local HTTP/HTTPS services
HTTP_PORTS=(80 443 8080 8443 3000 4000 5000 8000 9000)
OPEN_PORTS=()
ss_out=$(ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || true)
open_list=""
for port in "${HTTP_PORTS[@]}"; do
    if echo "$ss_out" | grep -qE ":${port}\b.*LISTEN"; then
        OPEN_PORTS+=("$port")
        open_list="${open_list} ${port}"
    fi
done

if [[ ${#OPEN_PORTS[@]} -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C1" "Local HTTP/HTTPS Services" "Info" "INFO" \
        "No HTTP/HTTPS service ports detected (80,443,8080,8443,3000,4000,5000,8000,9000)" ""
else
    add_finding "${SCRIPT_ID}-C1" "Local HTTP/HTTPS Services" "Info" "INFO" \
        "HTTP/HTTPS service(s) listening on port(s):${open_list}" \
        "Review each service and ensure only required endpoints are exposed"
fi

# C2 – HTTP security headers
if [[ "$HAS_CURL" == false ]]; then
    add_finding "${SCRIPT_ID}-C2" "HTTP Security Headers" "High" "WARN" \
        "curl not available – HTTP security header checks skipped" \
        "Install curl to enable HTTP security header checks"
else
    headers_issues=""
    checked_ports=0
    for port in "${OPEN_PORTS[@]}"; do
        scheme="http"
        [[ "$port" == "443" || "$port" == "8443" ]] && scheme="https"
        response=$(curl $CURL_OPTS -I "${scheme}://localhost:${port}/" 2>/dev/null || true)
        [[ -z "$response" ]] && continue
        checked_ports=$((checked_ports + 1))
        for hdr in "X-Frame-Options" "X-Content-Type-Options" "Content-Security-Policy" "Strict-Transport-Security" "Permissions-Policy"; do
            if ! echo "$response" | grep -qi "^${hdr}:"; then
                headers_issues="${headers_issues} port${port}:missing-${hdr};"
            fi
        done
    done
    if [[ "$checked_ports" -eq 0 ]]; then
        add_finding "${SCRIPT_ID}-C2" "HTTP Security Headers" "High" "INFO" \
            "No HTTP services responded to curl checks" ""
    elif [[ -z "$headers_issues" ]]; then
        add_finding "${SCRIPT_ID}-C2" "HTTP Security Headers" "High" "PASS" \
            "All required security headers present on checked services" ""
    else
        add_finding "${SCRIPT_ID}-C2" "HTTP Security Headers" "High" "FAIL" \
            "Missing security headers: ${headers_issues}" \
            "Add missing headers in web server/app config (e.g., nginx add_header, Apache Header always set)"
    fi
fi

# C3 – API documentation endpoints exposed
if [[ "$HAS_CURL" == false ]]; then
    add_finding "${SCRIPT_ID}-C3" "API Documentation Endpoints Exposed" "Med" "WARN" \
        "curl not available – API docs endpoint check skipped" \
        "Install curl and re-run to check for exposed API documentation"
else
    api_docs_found=""
    for port in "${OPEN_PORTS[@]}"; do
        scheme="http"
        [[ "$port" == "443" || "$port" == "8443" ]] && scheme="https"
        for path in /swagger /swagger-ui /swagger-ui.html /api-docs /openapi.json /graphql; do
            status_code=$(curl $CURL_OPTS -o /dev/null -w '%{http_code}' "${scheme}://localhost:${port}${path}" 2>/dev/null || true)
            if [[ "$status_code" =~ ^(200|301|302)$ ]]; then
                api_docs_found="${api_docs_found} ${scheme}://localhost:${port}${path}(${status_code})"
            fi
        done
    done
    if [[ -z "$api_docs_found" ]]; then
        add_finding "${SCRIPT_ID}-C3" "API Documentation Endpoints Exposed" "Med" "PASS" \
            "No accessible API documentation endpoints found (swagger, openapi, graphql)" ""
    else
        add_finding "${SCRIPT_ID}-C3" "API Documentation Endpoints Exposed" "Med" "WARN" \
            "API documentation accessible:${api_docs_found}" \
            "Restrict API docs to internal/dev environments only; add authentication if required in production"
    fi
fi

# C4 – HTTP TRACE method enabled
if [[ "$HAS_CURL" == false ]]; then
    add_finding "${SCRIPT_ID}-C4" "HTTP TRACE Method" "Med" "WARN" \
        "curl not available – TRACE method check skipped" \
        "Install curl to enable HTTP method checks"
else
    trace_enabled=""
    for port in "${OPEN_PORTS[@]}"; do
        scheme="http"
        [[ "$port" == "443" || "$port" == "8443" ]] && scheme="https"
        status_code=$(curl $CURL_OPTS -o /dev/null -w '%{http_code}' -X TRACE "${scheme}://localhost:${port}/" 2>/dev/null || true)
        if [[ "$status_code" == "200" ]]; then
            trace_enabled="${trace_enabled} ${scheme}://localhost:${port}"
        fi
    done
    if [[ -z "$trace_enabled" ]]; then
        add_finding "${SCRIPT_ID}-C4" "HTTP TRACE Method" "Med" "PASS" \
            "HTTP TRACE method not enabled on any discovered service" ""
    else
        add_finding "${SCRIPT_ID}-C4" "HTTP TRACE Method" "Med" "FAIL" \
            "TRACE method enabled on:${trace_enabled}" \
            "Disable TRACE: nginx: add 'if (\$request_method = TRACE) { return 405; }'; Apache: TraceEnable Off"
    fi
fi

# C5 – CORS misconfiguration (Access-Control-Allow-Origin: *)
if [[ "$HAS_CURL" == false ]]; then
    add_finding "${SCRIPT_ID}-C5" "CORS Misconfiguration" "High" "WARN" \
        "curl not available – CORS check skipped" \
        "Install curl to enable CORS checks"
else
    cors_issues=""
    for port in "${OPEN_PORTS[@]}"; do
        scheme="http"
        [[ "$port" == "443" || "$port" == "8443" ]] && scheme="https"
        cors=$(curl $CURL_OPTS -I -H "Origin: https://evil.example.com" "${scheme}://localhost:${port}/" 2>/dev/null \
            | grep -i "Access-Control-Allow-Origin" || true)
        if echo "$cors" | grep -q '\*'; then
            cors_issues="${cors_issues} port${port}:ACAO=*"
        fi
    done
    if [[ -z "$cors_issues" ]]; then
        add_finding "${SCRIPT_ID}-C5" "CORS Misconfiguration" "High" "PASS" \
            "No wildcard Access-Control-Allow-Origin header detected" ""
    else
        add_finding "${SCRIPT_ID}-C5" "CORS Misconfiguration" "High" "FAIL" \
            "Wildcard CORS policy detected:${cors_issues}" \
            "Replace 'Access-Control-Allow-Origin: *' with explicit allowed origins"
    fi
fi

# C6 – Admin/debug endpoints accessible
if [[ "$HAS_CURL" == false ]]; then
    add_finding "${SCRIPT_ID}-C6" "Admin/Debug Endpoints" "High" "WARN" \
        "curl not available – admin endpoint check skipped" \
        "Install curl to enable admin endpoint checks"
else
    admin_found=""
    for port in "${OPEN_PORTS[@]}"; do
        scheme="http"
        [[ "$port" == "443" || "$port" == "8443" ]] && scheme="https"
        for path in /admin /console /actuator /actuator/env /metrics /health /debug /phpinfo.php; do
            status_code=$(curl $CURL_OPTS -o /dev/null -w '%{http_code}' "${scheme}://localhost:${port}${path}" 2>/dev/null || true)
            if [[ "$status_code" =~ ^(200|301|302)$ ]]; then
                admin_found="${admin_found} ${scheme}://localhost:${port}${path}(${status_code})"
            fi
        done
    done
    if [[ -z "$admin_found" ]]; then
        add_finding "${SCRIPT_ID}-C6" "Admin/Debug Endpoints" "High" "PASS" \
            "No accessible admin or debug endpoints found" ""
    else
        add_finding "${SCRIPT_ID}-C6" "Admin/Debug Endpoints" "High" "WARN" \
            "Admin/debug endpoint(s) accessible:${admin_found}" \
            "Restrict admin/actuator endpoints with authentication and network-level access controls"
    fi
fi

# C7 – HTTPS redirect (HTTP port 80 should redirect to HTTPS)
if [[ "$HAS_CURL" == false ]]; then
    add_finding "${SCRIPT_ID}-C7" "HTTPS Redirect" "Med" "WARN" \
        "curl not available – HTTPS redirect check skipped" \
        "Install curl to enable redirect checks"
else
    if echo "$ss_out" | grep -qE ":80\b.*LISTEN"; then
        redirect=$(curl $CURL_OPTS -o /dev/null -w '%{http_code}' "http://localhost:80/" 2>/dev/null || true)
        location=$(curl $CURL_OPTS -I "http://localhost:80/" 2>/dev/null | grep -i "^Location:" || true)
        if [[ "$redirect" =~ ^(301|302|307|308)$ ]] && echo "$location" | grep -qi "https://"; then
            add_finding "${SCRIPT_ID}-C7" "HTTPS Redirect" "Med" "PASS" \
                "HTTP port 80 correctly redirects to HTTPS (${redirect})" ""
        elif [[ "$redirect" == "200" ]]; then
            add_finding "${SCRIPT_ID}-C7" "HTTPS Redirect" "Med" "WARN" \
                "HTTP port 80 serves content directly without HTTPS redirect" \
                "Configure 301 redirect from HTTP to HTTPS on port 80"
        else
            add_finding "${SCRIPT_ID}-C7" "HTTPS Redirect" "Med" "INFO" \
                "Port 80 returned HTTP ${redirect} – manual review recommended" ""
        fi
    else
        add_finding "${SCRIPT_ID}-C7" "HTTPS Redirect" "Med" "INFO" \
            "Port 80 not listening – HTTPS redirect check not applicable" ""
    fi
fi

# ── Optional Fix ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "INFO: API security requires configuration changes in application code and API gateway." >&2
    echo "Recommendations:" >&2
    echo "  1. Configure an API gateway (Kong, nginx, Traefik) to enforce security headers." >&2
    echo "  2. Implement OAuth 2.0 / API key authentication on all endpoints." >&2
    echo "  3. Disable TRACE method and restrict CORS origins explicitly." >&2
    echo "  4. Protect admin/actuator endpoints with network ACLs or authentication middleware." >&2
fi

# ── Output ───────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_api_endpoints" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
