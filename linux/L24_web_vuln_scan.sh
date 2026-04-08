#!/usr/bin/env bash
# =============================================================================
# L24 – Web Vulnerability Scanner (Linux)
# =============================================================================
# ID       : L24
# Category : Web Application Security
# Severity : Critical
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : Yes
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L24_web_vuln_scan.sh [--json] [--fix]
#
# Description
# -----------
# Performs a comprehensive web vulnerability scan against locally running
# web servers — similar to industry-standard web vulnerability scanners:
#   C1  – Dangerous / exposed backup and configuration file discovery
#   C2  – Outdated web server software version detection
#   C3  – HTTP method permissiveness (TRACE, PUT, DELETE exposure)
#   C4  – Default or sensitive path exposure (/admin, /phpmyadmin, etc.)
#   C5  – Directory listing enabled
#   C6  – Clickjacking / framing controls (X-Frame-Options / CSP frame-ancestors)
#   C7  – Mixed content and HTTPS redirection
#   C8  – Insecure cookie attributes (missing Secure / HttpOnly / SameSite)
#   C9  – Cross-site scripting (XSS) reflection indicators in error responses
#   C10 – Web application firewall (WAF) absence detection
# =============================================================================
set -euo pipefail

SCRIPT_ID="L24"
SCRIPT_NAME="Web Vulnerability Scanner"
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

# ── Detect listening web ports ─────────────────────────────────────────────────
_listening_ports() {
    if command -v ss &>/dev/null; then
        ss -tlnp 2>/dev/null | awk '{print $4}' | grep -oE '[0-9]+$' | sort -un || true
    else
        netstat -tlnp 2>/dev/null | awk '{print $4}' | grep -oE '[0-9]+$' | sort -un || true
    fi
}

WEB_PORTS=()
for p in 80 443 8080 8443 8000 8888 3000; do
    if _listening_ports | grep -qx "$p"; then
        WEB_PORTS+=("$p")
    fi
done

_http_get() {
    local url="$1"; shift
    curl -k --connect-timeout 4 --max-time 10 -s "$@" "$url" 2>/dev/null || true
}
_http_head() {
    local url="$1"; shift
    curl -k --connect-timeout 4 --max-time 10 -sI "$@" "$url" 2>/dev/null || true
}

# ── C1 – Dangerous / backup / config file exposure ────────────────────────────
DANGER_PATHS=(
    "/.git/config" "/.git/HEAD" "/.env" "/.env.backup" "/.env.local"
    "/wp-config.php" "/wp-config.php.bak" "/config.php" "/config.php.bak"
    "/database.yml" "/settings.py" "/settings.py.bak"
    "/backup.zip" "/backup.tar.gz" "/db.sql" "/dump.sql" "/database.sql"
    "/phpinfo.php" "/info.php" "/test.php" "/phptest.php"
    "/server-status" "/server-info"
    "/.htpasswd" "/.htaccess"
    "/WEB-INF/web.xml" "/META-INF/MANIFEST.MF"
    "/crossdomain.xml" "/clientaccesspolicy.xml"
)

dangerous_found=""
if command -v curl &>/dev/null && [[ "${#WEB_PORTS[@]}" -gt 0 ]]; then
    for port in "${WEB_PORTS[@]}"; do
        scheme="http"; [[ "$port" =~ ^(443|8443)$ ]] && scheme="https"
        base="${scheme}://localhost:${port}"
        for path in "${DANGER_PATHS[@]}"; do
            status_code=$(_http_head "${base}${path}" -o /dev/null -w '%{http_code}' 2>/dev/null || echo "000")
            if [[ "$status_code" == "200" ]]; then
                dangerous_found="${dangerous_found} port${port}:${path}(${status_code});"
            fi
        done
    done
fi

if [[ -z "$dangerous_found" ]]; then
    add_finding "${SCRIPT_ID}-C1" "Dangerous File/Path Exposure" "Critical" "PASS" \
        "No exposed backup, config, or sensitive files detected on checked web ports" ""
else
    add_finding "${SCRIPT_ID}-C1" "Dangerous File/Path Exposure" "Critical" "FAIL" \
        "Exposed sensitive file(s):${dangerous_found}" \
        "Remove or restrict access to backup/config files. Add deny rules in nginx/Apache. Ensure .git directories are not web-accessible."
fi

# ── C2 – Outdated web server software detection ───────────────────────────────
outdated_servers=""
if command -v curl &>/dev/null && [[ "${#WEB_PORTS[@]}" -gt 0 ]]; then
    for port in "${WEB_PORTS[@]}"; do
        scheme="http"; [[ "$port" =~ ^(443|8443)$ ]] && scheme="https"
        headers=$(_http_head "${scheme}://localhost:${port}/")
        server_hdr=$(echo "$headers" | grep -i '^Server:' | head -1 | tr -d '\r' || true)
        [[ -z "$server_hdr" ]] && continue

        # Extract version
        if echo "$server_hdr" | grep -qiE 'Apache/[12]\.[0-4]\.'; then
            ver=$(echo "$server_hdr" | grep -oiE 'Apache/[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            minor=$(echo "$ver" | cut -d/ -f2 | cut -d. -f2)
            patch=$(echo "$ver" | cut -d/ -f2 | cut -d. -f3)
            if [[ "$minor" -eq 4 && "$patch" -lt 57 ]]; then
                outdated_servers="${outdated_servers} port${port}:${ver}(Apache<2.4.57);"
            fi
        fi
        if echo "$server_hdr" | grep -qiE 'nginx/1\.([01][0-9]|2[0-3])\.'; then
            outdated_servers="${outdated_servers} port${port}:$(echo "$server_hdr" | grep -oiE 'nginx/[0-9.]+' | head -1)(outdated);"
        fi
        # PHP version disclosure in X-Powered-By
        php_hdr=$(echo "$headers" | grep -i '^X-Powered-By:' | head -1 | tr -d '\r' || true)
        if echo "$php_hdr" | grep -qiE 'PHP/([5-7]\.[0-3]\.|8\.[01]\.)'; then
            outdated_servers="${outdated_servers} port${port}:$(echo "$php_hdr" | grep -oiE 'PHP/[0-9]+\.[0-9]+\.[0-9]+' | head -1)(outdated-PHP);"
        fi
    done
fi

if [[ -z "$outdated_servers" ]]; then
    add_finding "${SCRIPT_ID}-C2" "Outdated Web Server Software" "High" "PASS" \
        "No clearly outdated web server versions detected in response headers" ""
else
    add_finding "${SCRIPT_ID}-C2" "Outdated Web Server Software" "High" "FAIL" \
        "Outdated server software detected:${outdated_servers}" \
        "Update web server software to latest stable version. Suppress version info: ServerTokens Prod (Apache), server_tokens off (nginx)."
fi

# ── C3 – HTTP method permissiveness ───────────────────────────────────────────
dangerous_methods=""
if command -v curl &>/dev/null && [[ "${#WEB_PORTS[@]}" -gt 0 ]]; then
    for port in "${WEB_PORTS[@]}"; do
        scheme="http"; [[ "$port" =~ ^(443|8443)$ ]] && scheme="https"
        base="${scheme}://localhost:${port}"
        for method in TRACE PUT DELETE CONNECT PATCH; do
            code=$(curl -k --connect-timeout 4 --max-time 8 -s -o /dev/null -w '%{http_code}' \
                -X "$method" "${base}/" 2>/dev/null || echo "000")
            # TRACE returning 200 = XST vulnerability; PUT/DELETE 200/201/204 = dangerous
            if [[ "$method" == "TRACE" && "$code" == "200" ]]; then
                dangerous_methods="${dangerous_methods} port${port}:${method}(${code}-XST-risk);"
            elif [[ "$method" != "TRACE" && "$code" =~ ^(200|201|204)$ ]]; then
                dangerous_methods="${dangerous_methods} port${port}:${method}(${code});"
            fi
        done
    done
fi

if [[ -z "$dangerous_methods" ]]; then
    add_finding "${SCRIPT_ID}-C3" "Dangerous HTTP Methods Enabled" "High" "PASS" \
        "TRACE/PUT/DELETE not returning success responses on checked web listeners" ""
else
    add_finding "${SCRIPT_ID}-C3" "Dangerous HTTP Methods Enabled" "High" "FAIL" \
        "Dangerous HTTP method(s) accepted:${dangerous_methods}" \
        "Restrict HTTP methods. Apache: LimitExcept GET POST HEAD. nginx: if (\$request_method !~ ^(GET|POST|HEAD)$) { return 405; }"
fi

# ── C4 – Default / sensitive admin path exposure ──────────────────────────────
ADMIN_PATHS=(
    "/admin" "/admin/" "/administrator" "/wp-admin" "/wp-login.php"
    "/phpmyadmin" "/pma" "/mysql" "/dbadmin"
    "/jenkins" "/jira" "/confluence" "/sonar"
    "/actuator" "/actuator/health" "/actuator/env" "/actuator/mappings"
    "/api/v1/users" "/api/v1/admin" "/swagger-ui.html" "/swagger-ui/"
    "/console" "/manager/html" "/host-manager/html"
    "/_cat/indices" "/_cluster/health"
)

admin_exposed=""
if command -v curl &>/dev/null && [[ "${#WEB_PORTS[@]}" -gt 0 ]]; then
    for port in "${WEB_PORTS[@]}"; do
        scheme="http"; [[ "$port" =~ ^(443|8443)$ ]] && scheme="https"
        base="${scheme}://localhost:${port}"
        for path in "${ADMIN_PATHS[@]}"; do
            code=$(curl -k --connect-timeout 3 --max-time 6 -s -o /dev/null -w '%{http_code}' \
                "${base}${path}" 2>/dev/null || echo "000")
            if [[ "$code" == "200" || "$code" == "301" || "$code" == "302" ]]; then
                admin_exposed="${admin_exposed} port${port}:${path}(${code});"
            fi
        done
    done
fi

if [[ -z "$admin_exposed" ]]; then
    add_finding "${SCRIPT_ID}-C4" "Default/Sensitive Path Exposure" "High" "PASS" \
        "No default admin or sensitive paths accessible on checked web ports" ""
else
    add_finding "${SCRIPT_ID}-C4" "Default/Sensitive Path Exposure" "High" "WARN" \
        "Accessible sensitive path(s):${admin_exposed}" \
        "Restrict admin paths to internal networks/VPN only. Add authentication. Disable unused endpoints (Spring Boot Actuator, Swagger in production)."
fi

# ── C5 – Directory listing enabled ────────────────────────────────────────────
dir_listing_found=""
if command -v curl &>/dev/null && [[ "${#WEB_PORTS[@]}" -gt 0 ]]; then
    for port in "${WEB_PORTS[@]}"; do
        scheme="http"; [[ "$port" =~ ^(443|8443)$ ]] && scheme="https"
        for path in "/" "/images/" "/static/" "/assets/" "/uploads/" "/files/"; do
            body=$(_http_get "${scheme}://localhost:${port}${path}" 2>/dev/null | head -c 2000 || true)
            if echo "$body" | grep -qiE 'Index of|Directory listing|Parent Directory|<title>Index'; then
                dir_listing_found="${dir_listing_found} port${port}:${path};"
            fi
        done
    done
fi

if [[ -z "$dir_listing_found" ]]; then
    add_finding "${SCRIPT_ID}-C5" "Directory Listing Enabled" "Med" "PASS" \
        "No directory listing responses detected on checked web ports" ""
else
    add_finding "${SCRIPT_ID}-C5" "Directory Listing Enabled" "Med" "FAIL" \
        "Directory listing enabled:${dir_listing_found}" \
        "Disable directory listing. Apache: Options -Indexes. nginx: autoindex off."
fi

# ── C6 – Clickjacking / framing controls ──────────────────────────────────────
clickjack_issues=""
if command -v curl &>/dev/null && [[ "${#WEB_PORTS[@]}" -gt 0 ]]; then
    for port in "${WEB_PORTS[@]}"; do
        scheme="http"; [[ "$port" =~ ^(443|8443)$ ]] && scheme="https"
        headers=$(_http_head "${scheme}://localhost:${port}/")
        has_xfo=$(echo "$headers" | grep -qi 'X-Frame-Options' && echo "yes" || echo "no")
        has_csp_frame=$(echo "$headers" | grep -i 'Content-Security-Policy' | grep -qi 'frame-ancestors' && echo "yes" || echo "no")
        if [[ "$has_xfo" == "no" && "$has_csp_frame" == "no" ]]; then
            clickjack_issues="${clickjack_issues} port${port}:missing-X-Frame-Options-and-CSP-frame-ancestors;"
        fi
    done
fi

if [[ -z "$clickjack_issues" ]]; then
    add_finding "${SCRIPT_ID}-C6" "Clickjacking Protection" "Med" "PASS" \
        "X-Frame-Options or CSP frame-ancestors present on checked web listeners" ""
else
    add_finding "${SCRIPT_ID}-C6" "Clickjacking Protection" "Med" "FAIL" \
        "Missing clickjacking protection:${clickjack_issues}" \
        "Add header: X-Frame-Options: DENY or SAMEORIGIN. Or use CSP: Content-Security-Policy: frame-ancestors 'none'."
fi

# ── C7 – HTTPS redirection / mixed content ────────────────────────────────────
https_issues=""
# Check if HTTP port 80 is open but doesn't redirect to HTTPS
if command -v curl &>/dev/null; then
    if _listening_ports | grep -qx "80"; then
        code=$(curl --connect-timeout 4 --max-time 8 -s -o /dev/null -w '%{http_code}' \
            http://localhost/ 2>/dev/null || echo "000")
        location=$(curl --connect-timeout 4 --max-time 8 -sI http://localhost/ 2>/dev/null \
            | grep -i '^Location:' | head -1 | tr -d '\r' || true)
        if [[ "$code" != "301" && "$code" != "302" ]]; then
            https_issues="${https_issues} port80:no-HTTPS-redirect(code:${code});"
        elif echo "$location" | grep -qi 'http://'; then
            https_issues="${https_issues} port80:redirects-to-HTTP-not-HTTPS(${location});"
        fi
    fi

    # Check for HSTS on HTTPS ports
    for port in 443 8443; do
        _listening_ports | grep -qx "$port" || continue
        headers=$(_http_head "https://localhost:${port}/")
        if ! echo "$headers" | grep -qi 'Strict-Transport-Security'; then
            https_issues="${https_issues} port${port}:missing-HSTS-header;"
        fi
    done
fi

if [[ -z "$https_issues" ]]; then
    add_finding "${SCRIPT_ID}-C7" "HTTPS Enforcement and HSTS" "High" "PASS" \
        "HTTP to HTTPS redirection and HSTS headers configured correctly" ""
else
    add_finding "${SCRIPT_ID}-C7" "HTTPS Enforcement and HSTS" "High" "WARN" \
        "HTTPS enforcement issue(s):${https_issues}" \
        "Configure HTTP to HTTPS permanent redirect (301). Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
fi

# ── C8 – Insecure cookie attributes ───────────────────────────────────────────
cookie_issues=""
if command -v curl &>/dev/null && [[ "${#WEB_PORTS[@]}" -gt 0 ]]; then
    for port in "${WEB_PORTS[@]}"; do
        scheme="http"; [[ "$port" =~ ^(443|8443)$ ]] && scheme="https"
        headers=$(_http_head "${scheme}://localhost:${port}/")
        # Look for Set-Cookie headers
        while IFS= read -r cookie_line; do
            [[ -z "$cookie_line" ]] && continue
            cookie_name=$(echo "$cookie_line" | grep -oiE 'Set-Cookie:[[:space:]]*[^=]+' | sed 's/Set-Cookie:[[:space:]]*//' | cut -d= -f1 | tr -d '\r' || true)
            missing_attrs=""
            echo "$cookie_line" | grep -qi 'Secure'   || missing_attrs="${missing_attrs}Secure,"
            echo "$cookie_line" | grep -qi 'HttpOnly' || missing_attrs="${missing_attrs}HttpOnly,"
            echo "$cookie_line" | grep -qi 'SameSite' || missing_attrs="${missing_attrs}SameSite,"
            if [[ -n "$missing_attrs" ]]; then
                cookie_issues="${cookie_issues} port${port}:${cookie_name:-cookie}(missing:${missing_attrs%,});"
            fi
        done < <(echo "$headers" | grep -i '^Set-Cookie:' || true)
    done
fi

if [[ -z "$cookie_issues" ]]; then
    add_finding "${SCRIPT_ID}-C8" "Insecure Cookie Attributes" "High" "PASS" \
        "No insecure cookie attribute patterns detected in response headers" ""
else
    add_finding "${SCRIPT_ID}-C8" "Insecure Cookie Attributes" "High" "FAIL" \
        "Cookie(s) missing security attributes:${cookie_issues}" \
        "Set cookie flags: Secure (HTTPS-only), HttpOnly (no JS access), SameSite=Strict/Lax. Example: Set-Cookie: session=xyz; Secure; HttpOnly; SameSite=Strict"
fi

# ── C9 – Basic XSS reflection detection ───────────────────────────────────────
xss_issues=""
XSS_PAYLOAD='<script>alert(1)</script>'
XSS_ENCODED='%3Cscript%3Ealert%281%29%3C%2Fscript%3E'

if command -v curl &>/dev/null && [[ "${#WEB_PORTS[@]}" -gt 0 ]]; then
    for port in "${WEB_PORTS[@]}"; do
        scheme="http"; [[ "$port" =~ ^(443|8443)$ ]] && scheme="https"
        for path in "/" "/search" "/search.php" "/index.php" "/q"; do
            for param in "q" "search" "query" "s" "id"; do
                response=$(_http_get "${scheme}://localhost:${port}${path}?${param}=${XSS_ENCODED}" 2>/dev/null \
                    | head -c 8192 || true)
                if echo "$response" | grep -qF "$XSS_PAYLOAD"; then
                    xss_issues="${xss_issues} port${port}:${path}?${param}=XSS_REFLECTED;"
                    break
                fi
            done
            [[ -n "$xss_issues" ]] && break
        done
    done
fi

if [[ -z "$xss_issues" ]]; then
    add_finding "${SCRIPT_ID}-C9" "Reflected XSS Indicators" "Critical" "PASS" \
        "No reflected XSS payload detected in tested parameter responses" ""
else
    add_finding "${SCRIPT_ID}-C9" "Reflected XSS Indicators" "Critical" "FAIL" \
        "Potential reflected XSS:${xss_issues}" \
        "Encode all user input before rendering in HTML. Set Content-Security-Policy. Use a WAF. Validate and sanitise all GET/POST parameters."
fi

# ── C10 – WAF absence detection ───────────────────────────────────────────────
waf_indicators=""
no_waf_ports=""
if command -v curl &>/dev/null && [[ "${#WEB_PORTS[@]}" -gt 0 ]]; then
    for port in "${WEB_PORTS[@]}"; do
        scheme="http"; [[ "$port" =~ ^(443|8443)$ ]] && scheme="https"
        # Send a known-malicious-looking request
        headers=$(_http_head "${scheme}://localhost:${port}/?q=<script>alert(1)</script>&id=1 UNION SELECT 1--")
        # WAF typically returns 403/406/429 or adds vendor headers
        code=$(echo "$headers" | head -1 | grep -oE '[0-9]{3}' | head -1 || echo "000")
        waf_hdr=$(echo "$headers" | grep -iE 'X-Sucuri|X-Cache|X-Firewall|Server:.*cloudflare|X-CDN|X-WAF' | head -1 || true)

        if [[ -n "$waf_hdr" || "$code" == "403" || "$code" == "406" ]]; then
            waf_indicators="${waf_indicators} port${port}:WAF-detected(${code});"
        else
            no_waf_ports="${no_waf_ports} port${port};"
        fi
    done
fi

if [[ -n "$waf_indicators" || -z "$no_waf_ports" ]]; then
    add_finding "${SCRIPT_ID}-C10" "Web Application Firewall (WAF) Presence" "Med" "PASS" \
        "WAF or input-blocking detected:${waf_indicators:-none-needed-no-web-ports}" ""
else
    add_finding "${SCRIPT_ID}-C10" "Web Application Firewall (WAF) Presence" "Med" "WARN" \
        "No WAF detected on web listener(s):${no_waf_ports}" \
        "Deploy a WAF (ModSecurity with OWASP Core Rule Set for nginx/Apache, or a cloud WAF). WAFs block common web attacks before they reach application code."
fi

# ── Optional Fix ──────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "INFO: Applying available automated fixes for L24 findings..." >&2

    # Disable Apache directory listing in default conf if Apache is running
    for conf in /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf; do
        [[ -f "$conf" ]] || continue
        if grep -q 'Options Indexes' "$conf"; then
            sed -i 's/Options Indexes/Options -Indexes/g' "$conf" && \
                echo "Disabled Apache directory listing in ${conf}" >&2
        fi
    done

    # Add X-Frame-Options to nginx if not present
    for site_conf in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do
        [[ -f "$site_conf" ]] || continue
        if ! grep -q 'X-Frame-Options' "$site_conf" 2>/dev/null; then
            echo "NOTE: Add 'add_header X-Frame-Options SAMEORIGIN always;' to ${site_conf}" >&2
        fi
    done

    echo "NOTE: Manual review required for XSS, WAF, and cookie attribute fixes." >&2
fi

# ── Output ────────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_web_vuln_scan" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
