#!/usr/bin/env bash
# =============================================================================
# L25 – SQL Injection Detection Scanner (Linux)
# =============================================================================
# ID       : L25
# Category : SQL Injection & Database Security
# Severity : Critical
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : Yes
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L25_sqli_scanner.sh [--json] [--fix]
#
# Description
# -----------
# Performs SQL injection vulnerability detection and database security checks:
#   C1  – SQL injection probe on common web endpoints (error-based detection)
#   C2  – Boolean-based blind SQL injection indicators
#   C3  – Time-based SQL injection indicators
#   C4  – Database service exposure assessment (MySQL/MariaDB/PostgreSQL/MSSQL)
#   C5  – Database default / weak credentials check
#   C6  – Database remote access permissions
#   C7  – Stored procedures with dangerous permissions
#   C8  – Database error exposure in application responses
#   C9  – ORM / prepared statement framework detection
#   C10 – Database audit logging configuration
# =============================================================================
set -euo pipefail

SCRIPT_ID="L25"
SCRIPT_NAME="SQL Injection Detection Scanner"
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

_http_get() {
    curl -k --connect-timeout 4 --max-time 10 -s "$@" 2>/dev/null || true
}

_listening_ports() {
    if command -v ss &>/dev/null; then
        ss -tlnp 2>/dev/null | awk '{print $4}' | grep -oE '[0-9]+$' | sort -un || true
    else
        netstat -tlnp 2>/dev/null | awk '{print $4}' | grep -oE '[0-9]+$' | sort -un || true
    fi
}

WEB_PORTS=()
for p in 80 443 8080 8443 8000 3000 5000; do
    if _listening_ports | grep -qx "$p"; then
        WEB_PORTS+=("$p")
    fi
done

# Common SQL injection test endpoints
SQLI_PATHS=("/login" "/login.php" "/signin" "/auth" "/user" "/user.php"
    "/product" "/product.php" "/item" "/search" "/search.php"
    "/api/v1/user" "/api/v1/product" "/api/users" "/api/items")

# ── C1 – Error-based SQL injection detection ──────────────────────────────────
# Common SQL error signatures from MySQL, PostgreSQL, MSSQL, Oracle, SQLite
SQL_ERROR_PATTERNS="(SQL syntax|mysql_fetch|ORA-[0-9]+|PG::SyntaxError|sqlite3::exception|Microsoft OLE DB|Unclosed quotation|Incorrect syntax near|pg_query|ODBC SQL|DB2 SQL|syntax error.*near)"

sqli_error_found=""
SQLI_PAYLOADS=("'" "')" "'--" "1'" "1'--" "' OR '1'='1" "1 OR 1=1" "' OR 1=1--")

if command -v curl &>/dev/null && [[ "${#WEB_PORTS[@]}" -gt 0 ]]; then
    for port in "${WEB_PORTS[@]}"; do
        scheme="http"; [[ "$port" =~ ^(443|8443)$ ]] && scheme="https"
        for path in "${SQLI_PATHS[@]}"; do
            code=$(curl -k --connect-timeout 3 --max-time 5 -s -o /dev/null -w '%{http_code}' \
                "${scheme}://localhost:${port}${path}" 2>/dev/null || echo "000")
            [[ "$code" == "404" ]] && continue

            for param in "id" "user" "username" "q" "search" "product" "item"; do
                for payload in "'" "' OR '1'='1"; do
                    response=$(_http_get "${scheme}://localhost:${port}${path}?${param}=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${payload}'))" 2>/dev/null || echo "${payload}")")
                    if echo "$response" | grep -qiEo "$SQL_ERROR_PATTERNS" 2>/dev/null; then
                        err=$(echo "$response" | grep -iEo "$SQL_ERROR_PATTERNS" | head -1)
                        sqli_error_found="${sqli_error_found} port${port}:${path}?${param}=[SQL-error:${err}];"
                        break 2
                    fi
                done
            done
        done
    done
fi

if [[ -z "$sqli_error_found" ]]; then
    add_finding "${SCRIPT_ID}-C1" "Error-Based SQL Injection" "Critical" "PASS" \
        "No SQL error messages reflected in tested web endpoint responses" ""
else
    add_finding "${SCRIPT_ID}-C1" "Error-Based SQL Injection" "Critical" "FAIL" \
        "SQL error exposed in response:${sqli_error_found}" \
        "Use parameterised queries/prepared statements. Suppress database error messages in production. Enable application-level error handling."
fi

# ── C2 – Boolean-based blind SQLi indicators ─────────────────────────────────
boolean_sqli=""
if command -v curl &>/dev/null && [[ "${#WEB_PORTS[@]}" -gt 0 ]]; then
    for port in "${WEB_PORTS[@]}"; do
        scheme="http"; [[ "$port" =~ ^(443|8443)$ ]] && scheme="https"
        for path in "${SQLI_PATHS[@]}"; do
            code=$(curl -k --connect-timeout 3 --max-time 5 -s -o /dev/null -w '%{http_code}' \
                "${scheme}://localhost:${port}${path}" 2>/dev/null || echo "000")
            [[ "$code" == "404" ]] && continue

            for param in "id" "user" "username"; do
                # True condition vs false condition
                resp_true=$(_http_get  "${scheme}://localhost:${port}${path}?${param}=1%20AND%201%3D1" | wc -c 2>/dev/null || echo "0")
                resp_false=$(_http_get "${scheme}://localhost:${port}${path}?${param}=1%20AND%201%3D2" | wc -c 2>/dev/null || echo "0")
                # Significant content difference suggests boolean-based injection
                if [[ "$resp_true" -gt 100 && "$resp_false" -lt 50 ]] && \
                   [[ $(( resp_true - resp_false )) -gt 100 ]]; then
                    boolean_sqli="${boolean_sqli} port${port}:${path}?${param}(true:${resp_true}b,false:${resp_false}b);"
                fi
            done
        done
    done
fi

if [[ -z "$boolean_sqli" ]]; then
    add_finding "${SCRIPT_ID}-C2" "Boolean-Based Blind SQL Injection" "Critical" "PASS" \
        "No boolean-based blind SQLi response-size differences detected" ""
else
    add_finding "${SCRIPT_ID}-C2" "Boolean-Based Blind SQL Injection" "Critical" "FAIL" \
        "Potential boolean-based blind SQLi indicators:${boolean_sqli}" \
        "Use parameterised queries. Ensure all user-supplied input is passed via bind parameters, never concatenated into SQL strings."
fi

# ── C3 – Time-based SQLi indicators ───────────────────────────────────────────
time_sqli=""
# Time-based payloads for different DB engines
TIME_PAYLOADS=(
    "1%20AND%20SLEEP(3)--"       # MySQL
    "1%3BSELECT%20PG_SLEEP(3)--" # PostgreSQL
    "1%3BWAITFOR%20DELAY%20'0:0:3'--" # MSSQL
)

if command -v curl &>/dev/null && [[ "${#WEB_PORTS[@]}" -gt 0 ]]; then
    for port in "${WEB_PORTS[@]}"; do
        scheme="http"; [[ "$port" =~ ^(443|8443)$ ]] && scheme="https"
        for path in "/login" "/login.php" "/api/v1/user"; do
            code=$(curl -k --connect-timeout 3 --max-time 5 -s -o /dev/null -w '%{http_code}' \
                "${scheme}://localhost:${port}${path}" 2>/dev/null || echo "000")
            [[ "$code" == "404" ]] && continue

            for payload in "${TIME_PAYLOADS[@]}"; do
                start_time=$(date +%s%N 2>/dev/null || date +%s)
                _http_get "${scheme}://localhost:${port}${path}?id=${payload}" \
                    --max-time 5 >/dev/null 2>&1 || true
                end_time=$(date +%s%N 2>/dev/null || date +%s)
                elapsed_ms=$(( (end_time - start_time) / 1000000 )) 2>/dev/null || \
                    elapsed_ms=$(( (end_time - start_time) * 1000 ))
                if [[ "$elapsed_ms" -ge 2800 && "$elapsed_ms" -le 6000 ]]; then
                    time_sqli="${time_sqli} port${port}:${path}(${elapsed_ms}ms-possible-time-delay);"
                    break
                fi
            done
        done
    done
fi

if [[ -z "$time_sqli" ]]; then
    add_finding "${SCRIPT_ID}-C3" "Time-Based Blind SQL Injection" "Critical" "PASS" \
        "No time-delay responses consistent with time-based SQLi detected" ""
else
    add_finding "${SCRIPT_ID}-C3" "Time-Based Blind SQL Injection" "Critical" "WARN" \
        "Possible time-based SQLi (response delay):${time_sqli}" \
        "Use parameterised queries. Inspect application code for raw SQL string construction. Use a web application firewall to block SQLi payloads."
fi

# ── C4 – Database service exposure ────────────────────────────────────────────
db_exposure=""
declare -A DB_PORTS=(
    [3306]="MySQL/MariaDB"
    [5432]="PostgreSQL"
    [1433]="MSSQL"
    [1521]="Oracle"
    [27017]="MongoDB"
    [6379]="Redis"
    [5984]="CouchDB"
    [9200]="Elasticsearch"
    [9300]="Elasticsearch-transport"
)

for port in "${!DB_PORTS[@]}"; do
    svc="${DB_PORTS[$port]}"
    if _listening_ports | grep -qx "$port"; then
        # Check if listening on 0.0.0.0 (externally accessible) vs 127.0.0.1 (local only)
        if command -v ss &>/dev/null; then
            bind_addr=$(ss -tlnp 2>/dev/null | awk '{print $4}' | grep -E ":${port}$" | head -1 || true)
        else
            bind_addr=$(netstat -tlnp 2>/dev/null | awk '{print $4}' | grep -E ":${port}$" | head -1 || true)
        fi
        if echo "$bind_addr" | grep -qE '^0\.0\.0\.0:|^\*:|^:::'; then
            db_exposure="${db_exposure} ${svc}(port${port}:EXTERNAL-BIND-risk);"
        else
            db_exposure="${db_exposure} ${svc}(port${port}:localhost-only-OK);"
        fi
    fi
done

if [[ -z "$db_exposure" ]]; then
    add_finding "${SCRIPT_ID}-C4" "Database Service Network Exposure" "Critical" "PASS" \
        "No database service ports detected listening" ""
else
    if echo "$db_exposure" | grep -q "EXTERNAL-BIND"; then
        add_finding "${SCRIPT_ID}-C4" "Database Service Network Exposure" "Critical" "FAIL" \
            "Database(s) bound to external interface:${db_exposure}" \
            "Bind database services to 127.0.0.1 only. Use firewall rules to restrict DB port access. Never expose databases directly to untrusted networks."
    else
        add_finding "${SCRIPT_ID}-C4" "Database Service Network Exposure" "Critical" "PASS" \
            "Database services listening on localhost only:${db_exposure}" ""
    fi
fi

# ── C5 – Database default / weak credentials ──────────────────────────────────
weak_db_creds=""

# MySQL/MariaDB
if command -v mysql &>/dev/null && _listening_ports | grep -qx "3306"; then
    for creds in "root:" "root:root" "root:password" "root:mysql" "root:123456" "admin:admin"; do
        user="${creds%%:*}"; pass="${creds#*:}"
        if mysql -h 127.0.0.1 -u "$user" ${pass:+-p"$pass"} -e "SELECT 1;" 2>/dev/null | grep -q "1"; then
            weak_db_creds="${weak_db_creds} MySQL:${user}/${pass:-empty};"
            break
        fi
    done
fi

# PostgreSQL
if command -v psql &>/dev/null && _listening_ports | grep -qx "5432"; then
    for creds in "postgres:" "postgres:postgres" "postgres:password" "admin:admin"; do
        user="${creds%%:*}"; pass="${creds#*:}"
        if PGPASSWORD="$pass" psql -h 127.0.0.1 -U "$user" -c "SELECT 1;" 2>/dev/null | grep -q "1"; then
            weak_db_creds="${weak_db_creds} PostgreSQL:${user}/${pass:-empty};"
            break
        fi
    done
fi

# Redis (no auth)
if _listening_ports | grep -qx "6379" && command -v redis-cli &>/dev/null; then
    if redis-cli -h 127.0.0.1 ping 2>/dev/null | grep -q "PONG"; then
        weak_db_creds="${weak_db_creds} Redis:unauthenticated;"
    fi
fi

if [[ -z "$weak_db_creds" ]]; then
    add_finding "${SCRIPT_ID}-C5" "Database Default/Weak Credentials" "Critical" "PASS" \
        "No default or weak credentials accepted by detected database services" ""
else
    add_finding "${SCRIPT_ID}-C5" "Database Default/Weak Credentials" "Critical" "FAIL" \
        "Weak/default credentials accepted:${weak_db_creds}" \
        "Change default database passwords immediately. Disable anonymous access. Use strong, randomly generated passwords stored in a secrets manager."
fi

# ── C6 – Database remote access configuration ────────────────────────────────
db_remote_access=""

# MySQL: check bind-address
for conf in /etc/mysql/mysql.conf.d/mysqld.cnf /etc/mysql/my.cnf /etc/my.cnf; do
    [[ -f "$conf" ]] || continue
    bind=$(grep -iE '^bind-address' "$conf" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | head -1 || true)
    if [[ "$bind" == "0.0.0.0" || -z "$bind" ]]; then
        db_remote_access="${db_remote_access} MySQL:bind-address=${bind:-not-set}(remote-access-risk);"
    fi
done

# PostgreSQL: check listen_addresses
for conf in /etc/postgresql/*/main/postgresql.conf /var/lib/pgsql/data/postgresql.conf; do
    [[ -f "$conf" ]] || continue
    listen=$(grep -E '^listen_addresses' "$conf" 2>/dev/null | awk -F= '{print $2}' | tr -d " '" | head -1 || true)
    if echo "$listen" | grep -qE '\*|0\.0\.0\.0'; then
        # Check pg_hba.conf for remote auth methods
        hba_file=$(dirname "$conf")/pg_hba.conf
        if [[ -f "$hba_file" ]] && grep -qE '^host.*trust' "$hba_file" 2>/dev/null; then
            db_remote_access="${db_remote_access} PostgreSQL:trust-auth-in-pg_hba.conf(CRITICAL);"
        else
            db_remote_access="${db_remote_access} PostgreSQL:listen_addresses=${listen}(remote-access-with-auth);"
        fi
    fi
done

if [[ -z "$db_remote_access" ]]; then
    add_finding "${SCRIPT_ID}-C6" "Database Remote Access Configuration" "High" "PASS" \
        "Database services appear bound to localhost or not present" ""
else
    add_finding "${SCRIPT_ID}-C6" "Database Remote Access Configuration" "High" "WARN" \
        "Remote DB access configuration risk:${db_remote_access}" \
        "Set MySQL bind-address=127.0.0.1. Set PostgreSQL listen_addresses='localhost'. Use VPN/SSH tunnels for remote DB administration."
fi

# ── C7 – Dangerous stored procedures / functions ──────────────────────────────
dangerous_procs=""

# MySQL: check for xp_cmdshell equivalent (UDF file-based exploitation indicators)
if command -v mysql &>/dev/null && _listening_ports | grep -qx "3306"; then
    # Check for sys_exec or lib_mysqludf_sys UDF
    for udf_lib in /usr/lib/mysql/plugin/lib_mysqludf_sys.so /tmp/lib_mysqludf_sys.so; do
        if [[ -f "$udf_lib" ]]; then
            dangerous_procs="${dangerous_procs} MySQL:dangerous-UDF-lib:${udf_lib};"
        fi
    done
fi

# Check MySQL general query log enabled (data exfiltration risk if writable)
for conf in /etc/mysql/mysql.conf.d/mysqld.cnf /etc/mysql/my.cnf /etc/my.cnf; do
    [[ -f "$conf" ]] || continue
    if grep -qiE '^general_log\s*=\s*(1|ON)' "$conf" 2>/dev/null; then
        log_file=$(grep -iE '^general_log_file' "$conf" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | head -1 || true)
        if [[ -n "$log_file" ]]; then
            perms=$(stat -c '%a' "$log_file" 2>/dev/null || true)
            last_digit="${perms: -1}"
            [[ "$last_digit" =~ [4-7] ]] && dangerous_procs="${dangerous_procs} MySQL:general-query-log-world-readable(${log_file});"
        fi
    fi
done

if [[ -z "$dangerous_procs" ]]; then
    add_finding "${SCRIPT_ID}-C7" "Dangerous DB Procedures/UDFs" "High" "PASS" \
        "No dangerous stored procedures or UDF libraries detected" ""
else
    add_finding "${SCRIPT_ID}-C7" "Dangerous DB Procedures/UDFs" "High" "FAIL" \
        "Dangerous database artifact(s):${dangerous_procs}" \
        "Remove dangerous UDF libraries. Restrict FILE privilege. Disable general query log or restrict file permissions."
fi

# ── C8 – Database error exposure in app responses ────────────────────────────
db_error_exposure=""
DB_ERROR_RE="(mysql_error|pg_last_error|oci_error|sqlite_error|SQLSTATE|PDOException|java.sql.SQLException|ORA-[0-9]+|DB2 SQL|Microsoft OLE DB|ADODB|MySqlException|NpgsqlException)"

if command -v curl &>/dev/null && [[ "${#WEB_PORTS[@]}" -gt 0 ]]; then
    for port in "${WEB_PORTS[@]}"; do
        scheme="http"; [[ "$port" =~ ^(443|8443)$ ]] && scheme="https"
        for path in "/" "/404_nonexistent_$(date +%s)" "/error" "/api/v1/error"; do
            response=$(_http_get "${scheme}://localhost:${port}${path}" | head -c 4096 || true)
            if echo "$response" | grep -qiEo "$DB_ERROR_RE" 2>/dev/null; then
                err_type=$(echo "$response" | grep -iEo "$DB_ERROR_RE" | head -1)
                db_error_exposure="${db_error_exposure} port${port}:${path}(${err_type});"
            fi
        done
    done
fi

if [[ -z "$db_error_exposure" ]]; then
    add_finding "${SCRIPT_ID}-C8" "Database Error Message Exposure" "High" "PASS" \
        "No database error messages detected in web application responses" ""
else
    add_finding "${SCRIPT_ID}-C8" "Database Error Message Exposure" "High" "FAIL" \
        "DB error message(s) visible in HTTP responses:${db_error_exposure}" \
        "Suppress detailed error messages in production. Implement custom error pages. Log errors server-side only. Never expose DB stack traces to end users."
fi

# ── C9 – ORM / prepared statement usage detection ────────────────────────────
# Check application code for raw SQL string concatenation
raw_sql_found=""
raw_sql_count=0
# Pattern: execute/query/prepare call with quote+concat, or f-string with SQL keyword
_RAW_SQL_RE='(execute\(|query\(|prepare\().*["\x27]\s*\+.*\$|(f|F)["\x27].*(SELECT|INSERT|UPDATE|DELETE)'

while IFS= read -r -d '' f; do
    # Look for dangerous raw SQL patterns: string concatenation with variables
    if grep -qE "$_RAW_SQL_RE" "$f" 2>/dev/null || \
       grep -qE '(mysql_query|pg_query|sqlite_query)\s*\(\s*".*\.' "$f" 2>/dev/null; then
        raw_sql_count=$((raw_sql_count + 1))
        raw_sql_found="${raw_sql_found} ${f};"
    fi
done < <(find /var/www /opt /home -maxdepth 5 -type f \
    \( -name "*.php" -o -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.java" \) \
    -print0 2>/dev/null)

if [[ "$raw_sql_count" -eq 0 ]]; then
    add_finding "${SCRIPT_ID}-C9" "Raw SQL String Concatenation" "Critical" "PASS" \
        "No raw SQL string concatenation patterns detected in scanned application files" ""
else
    add_finding "${SCRIPT_ID}-C9" "Raw SQL String Concatenation" "Critical" "WARN" \
        "${raw_sql_count} file(s) with potential raw SQL patterns:${raw_sql_found}" \
        "Replace raw SQL string concatenation with parameterised queries / prepared statements. Use an ORM (SQLAlchemy, Hibernate, Eloquent)."
fi

# ── C10 – Database audit logging ──────────────────────────────────────────────
db_audit_issues=""

# MySQL: check if audit plugin or general_log configured
if _listening_ports | grep -qx "3306"; then
    audit_ok=false
    for conf in /etc/mysql/mysql.conf.d/mysqld.cnf /etc/mysql/my.cnf /etc/my.cnf; do
        [[ -f "$conf" ]] || continue
        if grep -qiE '(audit_log|audit-log|general_log)' "$conf" 2>/dev/null; then
            audit_ok=true
        fi
    done
    if [[ "$audit_ok" == false ]]; then
        db_audit_issues="${db_audit_issues} MySQL:no-audit-logging-configured;"
    fi
fi

# PostgreSQL: check log_connections / log_statement
for conf in /etc/postgresql/*/main/postgresql.conf /var/lib/pgsql/data/postgresql.conf; do
    [[ -f "$conf" ]] || continue
    log_conn=$(grep -E '^log_connections' "$conf" 2>/dev/null | awk -F= '{print $2}' | tr -d " '" | head -1 || true)
    log_stmt=$(grep -E '^log_statement' "$conf" 2>/dev/null | awk -F= '{print $2}' | tr -d " '" | head -1 || true)
    if [[ "$log_conn" != "on" ]]; then
        db_audit_issues="${db_audit_issues} PostgreSQL:log_connections=off;"
    fi
    if [[ "$log_stmt" != "all" && "$log_stmt" != "ddl" ]]; then
        db_audit_issues="${db_audit_issues} PostgreSQL:log_statement=${log_stmt:-not-set};"
    fi
done

if [[ -z "$db_audit_issues" ]]; then
    add_finding "${SCRIPT_ID}-C10" "Database Audit Logging" "High" "PASS" \
        "Database audit/query logging appears configured" ""
else
    add_finding "${SCRIPT_ID}-C10" "Database Audit Logging" "High" "WARN" \
        "Database audit logging issues:${db_audit_issues}" \
        "Enable MySQL audit log plugin or general_log. Set PostgreSQL log_connections=on, log_statement=ddl. Send DB logs to centralised SIEM."
fi

# ── Optional Fix ──────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo "INFO: SQL injection fixes require application code changes – automated fix not available." >&2
    echo "Recommendations:" >&2
    echo "  1. Replace all raw SQL with parameterised queries / prepared statements." >&2
    echo "  2. Enable database audit logging." >&2
    echo "  3. Bind database services to 127.0.0.1 only." >&2
    echo "  4. Change all default database passwords immediately." >&2

    # Attempt to restrict MySQL to localhost
    for conf in /etc/mysql/mysql.conf.d/mysqld.cnf /etc/mysql/my.cnf; do
        [[ -f "$conf" ]] || continue
        if ! grep -q 'bind-address' "$conf" 2>/dev/null; then
            echo "bind-address = 127.0.0.1" >> "$conf" && \
                echo "Set MySQL bind-address=127.0.0.1 in ${conf}" >&2
        fi
    done
fi

# ── Output ────────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_sqli_scanner" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
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
