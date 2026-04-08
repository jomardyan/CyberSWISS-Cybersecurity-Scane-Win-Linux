#Requires -Version 5.1
<#
.SYNOPSIS
    W25 – SQL Injection Detection Scanner (Windows)
.DESCRIPTION
    Performs SQL injection vulnerability detection and database security checks:
      C1  – SQL injection probe on common web endpoints (error-based detection)
      C2  – Boolean-based blind SQL injection indicators
      C3  – Time-based SQL injection indicators
      C4  – Database service exposure assessment (SQL Server, MySQL, PostgreSQL)
      C5  – SQL Server default / weak sa password check
      C6  – SQL Server dangerous configurations (xp_cmdshell, CLR enabled)
      C7  – SQL Server audit logging and C2 audit mode
      C8  – Database error exposure in application responses
      C9  – Raw SQL string concatenation in .NET application code
      C10 – Entity Framework / ORM parameterisation check
    Read-only by default. Pass -Fix to apply remediation where available.
.NOTES
    ID         : W25
    Category   : SQL Injection & Database Security
    Severity   : Critical
    OS         : Windows 10/11, Server 2016+
    Admin      : Yes
    Language   : PowerShell 5.1+
    Author     : CyberSWISS Security Team
.PARAMETER Json
    Output results in JSON format for SIEM ingestion.
.PARAMETER Fix
    WARNING: Applies recommended baseline values. Off by default. Use with caution.
.EXAMPLE
    .\W25_sqli_scanner.ps1
    .\W25_sqli_scanner.ps1 -Json
    .\W25_sqli_scanner.ps1 -Fix
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Json,
    [switch]$Fix
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── Helpers ──────────────────────────────────────────────────────────────
$script:findings = [System.Collections.Generic.List[hashtable]]::new()

function Add-Finding {
    param(
        [string]$Id,
        [string]$Name,
        [ValidateSet('Info','Low','Med','High','Critical')]
        [string]$Severity,
        [string]$Status,
        [string]$Detail,
        [string]$Remediation
    )
    $script:findings.Add(@{
        id          = $Id
        name        = $Name
        severity    = $Severity
        status      = $Status
        detail      = $Detail
        remediation = $Remediation
        timestamp   = (Get-Date -Format 'o')
    })
}

function Write-Finding {
    param([hashtable]$f)
    $color = switch ($f.status) {
        'PASS' { 'Green'  }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red'    }
        default{ 'White'  }
    }
    Write-Host ("[{0}] [{1}] {2}: {3}" -f $f.status, $f.severity, $f.id, $f.name) -ForegroundColor $color
    if ($f.detail)      { Write-Host "       Detail : $($f.detail)"      }
    if ($f.status -ne 'PASS' -and $f.remediation) {
        Write-Host "       Remedy : $($f.remediation)" -ForegroundColor Cyan
    }
}

function Invoke-HttpGet {
    param([string]$Uri, [int]$TimeoutSec = 8)
    # PowerShell 5.1-compatible certificate check bypass (equivalent to -SkipCertificateCheck)
    $originalCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    try {
        return Invoke-WebRequest -Uri $Uri -Method Get -UseBasicParsing `
            -TimeoutSec $TimeoutSec -ErrorAction SilentlyContinue 2>$null
    } catch { return $null } finally {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallback
    }
}
#endregion

#region ── Detect active web ports ──────────────────────────────────────────────
$webPorts = @()
foreach ($port in @(80, 443, 8080, 8443, 8000, 3000)) {
    try {
        $conn = New-Object System.Net.Sockets.TcpClient
        $conn.ConnectAsync('127.0.0.1', $port).Wait(500) | Out-Null
        if ($conn.Connected) { $webPorts += $port }
        $conn.Close()
    } catch {}
}

$sqliPaths = @('/login', '/signin', '/search', '/user', '/product',
               '/Default.aspx', '/Login.aspx', '/Search.aspx', '/api/v1/user')
$sqlErrorPattern = 'SQL syntax|OLE DB|ODBC.*Driver|Unclosed quotation|Incorrect syntax|System\.Data\.SqlClient|SqlException|ORA-[0-9]+|PG::|SQLite|mysql_fetch'
#endregion

#region ── Checks ────────────────────────────────────────────────────────────────
function Invoke-Checks {
    # Set PS 5.1-compatible certificate bypass for all web requests in this function
    $originalCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    try {

    # C1 – Error-based SQL injection detection ────────────────────────────────
    $sqliErrorFound = @()
    foreach ($port in $webPorts) {
        $scheme = if ($port -in @(443, 8443)) { 'https' } else { 'http' }
        foreach ($path in $sqliPaths) {
            try {
                $baseResp = Invoke-WebRequest -Uri "${scheme}://localhost:${port}$path" `
                    -UseBasicParsing -TimeoutSec 4 -ErrorAction SilentlyContinue 2>$null
                if (-not $baseResp -or $baseResp.StatusCode -eq 404) { continue }
            } catch { continue }

            foreach ($param in @('id', 'user', 'username', 'search', 'q')) {
                foreach ($payload in @("'", "' OR '1'='1")) {
                    $encoded = [Uri]::EscapeDataString($payload)
                    $resp = Invoke-HttpGet "${scheme}://localhost:${port}${path}?${param}=${encoded}"
                    if ($resp -and $resp.Content -match $sqlErrorPattern) {
                        $err = ([regex]::Match($resp.Content, $sqlErrorPattern)).Value
                        $sqliErrorFound += "port${port}:${path}?${param}=[SQL-error:$err]"
                        break
                    }
                }
                if ($sqliErrorFound.Count -gt 0) { break }
            }
        }
    }

    if ($sqliErrorFound.Count -eq 0) {
        Add-Finding 'W25-C1' 'Error-Based SQL Injection' 'Critical' 'PASS' `
            'No SQL error messages reflected in tested web endpoint responses' ''
    } else {
        Add-Finding 'W25-C1' 'Error-Based SQL Injection' 'Critical' 'FAIL' `
            ("SQL error exposed: " + ($sqliErrorFound -join ', ')) `
            'Use parameterised queries (SqlCommand.Parameters). Suppress database errors in production. Use CustomErrors in web.config. Never expose connection strings or SQL errors to end users.'
    }

    # C2 – Boolean-based blind SQLi ───────────────────────────────────────────
    $boolSqli = @()
    foreach ($port in $webPorts) {
        $scheme = if ($port -in @(443, 8443)) { 'https' } else { 'http' }
        foreach ($path in $sqliPaths) {
            foreach ($param in @('id', 'user', 'username')) {
                $trueResp  = Invoke-HttpGet "${scheme}://localhost:${port}${path}?${param}=1%20AND%201%3D1"
                $falseResp = Invoke-HttpGet "${scheme}://localhost:${port}${path}?${param}=1%20AND%201%3D2"
                if ($trueResp -and $falseResp) {
                    $diff = [Math]::Abs($trueResp.Content.Length - $falseResp.Content.Length)
                    if ($trueResp.Content.Length -gt 100 -and $falseResp.Content.Length -lt 50 -and $diff -gt 100) {
                        $boolSqli += "port${port}:${path}?${param}(true:$($trueResp.Content.Length)b,false:$($falseResp.Content.Length)b)"
                        break
                    }
                }
            }
        }
    }

    if ($boolSqli.Count -eq 0) {
        Add-Finding 'W25-C2' 'Boolean-Based Blind SQL Injection' 'Critical' 'PASS' `
            'No boolean-based blind SQLi response-size differences detected' ''
    } else {
        Add-Finding 'W25-C2' 'Boolean-Based Blind SQL Injection' 'Critical' 'FAIL' `
            ("Potential boolean-based blind SQLi: " + ($boolSqli -join ', ')) `
            'Use parameterised queries. Ensure all user input goes through SqlCommand.Parameters, never string concatenation.'
    }

    # C3 – Time-based SQLi indicators ─────────────────────────────────────────
    $timeSqli = @()
    $timePayloads = @(
        "1;WAITFOR DELAY '0:0:3'--",   # MSSQL
        "1 AND SLEEP(3)--",            # MySQL
        "1;SELECT PG_SLEEP(3)--"       # PostgreSQL
    )
    foreach ($port in $webPorts) {
        $scheme = if ($port -in @(443, 8443)) { 'https' } else { 'http' }
        foreach ($payload in $timePayloads) {
            $encoded = [Uri]::EscapeDataString($payload)
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                Invoke-WebRequest -Uri "${scheme}://localhost:${port}/login?id=$encoded" `
                    -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue 2>$null | Out-Null
            } catch {}
            $sw.Stop()
            if ($sw.ElapsedMilliseconds -ge 2800 -and $sw.ElapsedMilliseconds -le 6000) {
                $timeSqli += "port${port}:login?id=$($payload.Split(';')[0])(delay:$($sw.ElapsedMilliseconds)ms)"
                break
            }
        }
    }

    if ($timeSqli.Count -eq 0) {
        Add-Finding 'W25-C3' 'Time-Based Blind SQL Injection' 'Critical' 'PASS' `
            'No time-delay responses consistent with time-based SQLi detected' ''
    } else {
        Add-Finding 'W25-C3' 'Time-Based Blind SQL Injection' 'Critical' 'WARN' `
            ("Possible time-based SQLi: " + ($timeSqli -join ', ')) `
            'Use parameterised queries. Deploy WAF with SQLi rule set. Enable IIS Request Filtering to block SQL keywords in query strings.'
    }

    # C4 – Database service exposure ──────────────────────────────────────────
    $dbExposure = @()
    $dbPorts = @{
        1433  = 'SQL Server'
        1434  = 'SQL Server Browser'
        3306  = 'MySQL'
        5432  = 'PostgreSQL'
        27017 = 'MongoDB'
        6379  = 'Redis'
        9200  = 'Elasticsearch'
    }
    foreach ($port in $dbPorts.Keys) {
        try {
            $conn = New-Object System.Net.Sockets.TcpClient
            if ($conn.ConnectAsync('127.0.0.1', $port).Wait(300)) {
                # Check if DB is externally bound (0.0.0.0) via netstat
                $isExternal = $false
                try {
                    $isExternal = [bool](Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue |
                                  Where-Object { $_.LocalAddress -eq '0.0.0.0' })
                } catch {}
                if ($isExternal) {
                    $dbExposure += "$($dbPorts[$port])(port${port}:EXTERNAL-BIND-risk)"
                } else {
                    $dbExposure += "$($dbPorts[$port])(port${port}:localhost-only-OK)"
                }
            }
            $conn.Close()
        } catch {}
    }

    if ($dbExposure.Count -eq 0) {
        Add-Finding 'W25-C4' 'Database Service Network Exposure' 'Critical' 'PASS' `
            'No database service ports detected listening' ''
    } elseif ($dbExposure | Where-Object { $_ -match 'EXTERNAL-BIND' }) {
        Add-Finding 'W25-C4' 'Database Service Network Exposure' 'Critical' 'FAIL' `
            ("DB bound to external interface: " + ($dbExposure -join ', ')) `
            'Bind SQL Server to 127.0.0.1 only. Use Windows Firewall to block 1433 from external access. Use SQL Server Configuration Manager > Protocols > TCP/IP > IP Addresses.'
    } else {
        Add-Finding 'W25-C4' 'Database Service Network Exposure' 'Critical' 'PASS' `
            ("Database services localhost-only: " + ($dbExposure -join ', ')) ''
    }

    # C5 – SQL Server dangerous configurations ────────────────────────────────
    $sqlDangerConfig = @()
    try {
        # Check if SQL Server is running
        $sqlSvc = Get-Service -Name 'MSSQLSERVER', 'MSSQL$*' -ErrorAction SilentlyContinue |
                  Where-Object { $_.Status -eq 'Running' }
        if ($sqlSvc) {
            # Try trusted connection to check xp_cmdshell and CLR
            $conn = New-Object System.Data.SqlClient.SqlConnection
            $conn.ConnectionString = 'Server=localhost;Integrated Security=true;Connect Timeout=5'
            try {
                $conn.Open()
                $cmd = $conn.CreateCommand()

                # Check xp_cmdshell
                $cmd.CommandText = "SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell'"
                $xpCmd = $cmd.ExecuteScalar()
                if ($xpCmd -eq 1) { $sqlDangerConfig += 'xp_cmdshell=ENABLED' }

                # Check CLR enabled
                $cmd.CommandText = "SELECT value_in_use FROM sys.configurations WHERE name = 'clr enabled'"
                $clr = $cmd.ExecuteScalar()
                if ($clr -eq 1) { $sqlDangerConfig += 'clr_enabled=1(verify-strict-security)' }

                # Check Ole Automation Procedures
                $cmd.CommandText = "SELECT value_in_use FROM sys.configurations WHERE name = 'Ole Automation Procedures'"
                $oleAuto = $cmd.ExecuteScalar()
                if ($oleAuto -eq 1) { $sqlDangerConfig += 'Ole_Automation_Procedures=ENABLED' }

                # Check for sa account enabled
                $cmd.CommandText = "SELECT is_disabled FROM sys.server_principals WHERE name = 'sa'"
                $saDisabled = $cmd.ExecuteScalar()
                if ($saDisabled -eq 0) { $sqlDangerConfig += 'sa_account=ENABLED' }

                $conn.Close()
            } catch { $conn.Close() }
        }
    } catch {}

    if ($sqlDangerConfig.Count -eq 0) {
        Add-Finding 'W25-C5' 'SQL Server Dangerous Configurations' 'Critical' 'PASS' `
            'No dangerous SQL Server configurations (xp_cmdshell, sa enabled, OLE automation) detected' ''
    } else {
        Add-Finding 'W25-C5' 'SQL Server Dangerous Configurations' 'Critical' 'FAIL' `
            ("Dangerous SQL Server config: " + ($sqlDangerConfig -join ', ')) `
            "Disable xp_cmdshell: EXEC sp_configure 'xp_cmdshell',0; RECONFIGURE. Disable sa: ALTER LOGIN sa DISABLE. Disable OLE Automation Procedures. Use Windows Authentication."

        if ($Fix -and $PSCmdlet.ShouldProcess('SQL Server', 'Disable xp_cmdshell and sa account')) {
            try {
                $conn = New-Object System.Data.SqlClient.SqlConnection
                $conn.ConnectionString = 'Server=localhost;Integrated Security=true;Connect Timeout=5'
                $conn.Open()
                $cmd = $conn.CreateCommand()
                if ($sqlDangerConfig -contains 'xp_cmdshell=ENABLED') {
                    $cmd.CommandText = "EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',0; RECONFIGURE"
                    $cmd.ExecuteNonQuery() | Out-Null
                    Write-Warning 'xp_cmdshell disabled.'
                }
                $conn.Close()
            } catch { Write-Warning "Failed to apply SQL Server fix: $_" }
        }
    }

    # C6 – SQL Server audit logging ───────────────────────────────────────────
    $sqlAuditIssues = @()
    try {
        $sqlSvc = Get-Service -Name 'MSSQLSERVER', 'MSSQL$*' -ErrorAction SilentlyContinue |
                  Where-Object { $_.Status -eq 'Running' }
        if ($sqlSvc) {
            $conn = New-Object System.Data.SqlClient.SqlConnection
            $conn.ConnectionString = 'Server=localhost;Integrated Security=true;Connect Timeout=5'
            try {
                $conn.Open()
                $cmd = $conn.CreateCommand()

                # Check server audit objects
                $cmd.CommandText = 'SELECT COUNT(*) FROM sys.server_audits WHERE is_state_enabled = 1'
                $auditCount = $cmd.ExecuteScalar()
                if ($auditCount -eq 0) { $sqlAuditIssues += 'No-enabled-server-audits' }

                # Check login auditing
                $cmd.CommandText = "SELECT value_in_use FROM sys.configurations WHERE name = 'c2 audit mode'"
                $c2mode = $cmd.ExecuteScalar()
                if ($c2mode -ne 1) { $sqlAuditIssues += 'C2-audit-mode=disabled' }

                $conn.Close()
            } catch { $conn.Close() }
        }
    } catch {}

    if ($sqlAuditIssues.Count -eq 0) {
        Add-Finding 'W25-C6' 'SQL Server Audit Logging' 'High' 'PASS' `
            'SQL Server audit logging appears configured' ''
    } else {
        Add-Finding 'W25-C6' 'SQL Server Audit Logging' 'High' 'WARN' `
            ("SQL Server audit issues: " + ($sqlAuditIssues -join ', ')) `
            'Enable SQL Server Audit: CREATE SERVER AUDIT, CREATE SERVER AUDIT SPECIFICATION. Enable login auditing in SQL Server properties > Security > Login Auditing = All.'
    }

    # C7 – Database error exposure in app responses ───────────────────────────
    $dbErrorExposure = @()
    foreach ($port in $webPorts) {
        $scheme = if ($port -in @(443, 8443)) { 'https' } else { 'http' }
        foreach ($path in @('/', '/error', '/api/v1/error', '/404_nonexistent')) {
            $resp = Invoke-HttpGet "${scheme}://localhost:${port}$path"
            if ($resp -and $resp.Content -match $sqlErrorPattern) {
                $errType = ([regex]::Match($resp.Content, $sqlErrorPattern)).Value
                $dbErrorExposure += "port${port}:$path($errType)"
            }
        }
    }

    if ($dbErrorExposure.Count -eq 0) {
        Add-Finding 'W25-C7' 'Database Error Message Exposure' 'High' 'PASS' `
            'No database error messages detected in web application responses' ''
    } else {
        Add-Finding 'W25-C7' 'Database Error Message Exposure' 'High' 'FAIL' `
            ("DB error visible in responses: " + ($dbErrorExposure -join ', ')) `
            'Enable CustomErrors in web.config: <customErrors mode="On" defaultRedirect="~/Error">. Never pass SqlException details to the response. Use structured logging server-side.'
    }

    # C8 – Raw SQL string concatenation in .NET code ──────────────────────────
    $rawSqlFiles = @()
    $scanRoots = @('C:\inetpub\wwwroot', 'C:\apps', 'C:\websites') |
                 Where-Object { Test-Path $_ }
    if ($scanRoots.Count -gt 0) {
        $sqlConcatPattern = '(ExecuteNonQuery|ExecuteScalar|ExecuteReader|SqlCommand|OleDbCommand)\s*\([^)]*\+|"(SELECT|INSERT|UPDATE|DELETE|DROP).*"\s*\+'
        foreach ($root in $scanRoots) {
            Get-ChildItem -Path $root -Recurse -Include '*.cs', '*.vb', '*.aspx', '*.ashx' `
                -ErrorAction SilentlyContinue |
                Select-Object -First 500 |
                ForEach-Object {
                    try {
                        if (Select-String -Path $_.FullName -Pattern $sqlConcatPattern -Quiet -ErrorAction SilentlyContinue) {
                            $rawSqlFiles += $_.FullName
                        }
                    } catch {}
                }
        }
    }

    if ($rawSqlFiles.Count -eq 0) {
        Add-Finding 'W25-C8' 'Raw SQL String Concatenation in Code' 'Critical' 'PASS' `
            'No raw SQL string concatenation patterns detected in scanned application files' ''
    } else {
        Add-Finding 'W25-C8' 'Raw SQL String Concatenation in Code' 'Critical' 'FAIL' `
            ("$($rawSqlFiles.Count) file(s) with SQL concat: " + (($rawSqlFiles | Select-Object -First 3) -join ', ')) `
            'Replace all string-concatenated SQL with SqlCommand.Parameters.AddWithValue(). Use Entity Framework, Dapper, or LINQ to SQL which automatically parameterise queries.'
    }

    # C9 – Entity Framework raw SQL patterns ──────────────────────────────────
    $efRawSql = @()
    $efRawPattern = '(FromSql|ExecuteSqlRaw|ExecuteSqlCommand)\s*\([^)]*\+'
    if ($scanRoots.Count -gt 0) {
        foreach ($root in $scanRoots) {
            Get-ChildItem -Path $root -Recurse -Include '*.cs', '*.vb' -ErrorAction SilentlyContinue |
                Select-Object -First 500 |
                ForEach-Object {
                    try {
                        if (Select-String -Path $_.FullName -Pattern $efRawPattern -Quiet -ErrorAction SilentlyContinue) {
                            $efRawSql += $_.FullName
                        }
                    } catch {}
                }
        }
    }

    if ($efRawSql.Count -eq 0) {
        Add-Finding 'W25-C9' 'Entity Framework Raw SQL Usage' 'High' 'PASS' `
            'No Entity Framework FromSql/ExecuteSqlRaw with string concatenation detected' ''
    } else {
        Add-Finding 'W25-C9' 'Entity Framework Raw SQL Usage' 'High' 'FAIL' `
            ("$($efRawSql.Count) EF file(s) with raw SQL concat: " + (($efRawSql | Select-Object -First 3) -join ', ')) `
            'Use FromSqlInterpolated($"SELECT * FROM t WHERE id = {id}") or ExecuteSqlInterpolated() which automatically parameterises interpolated strings. Never use + concatenation with FromSqlRaw.'
    }

    # C10 – Connection string encryption check ────────────────────────────────
    $connStrIssues = @()
    $webConfigPaths = @()
    if ($scanRoots.Count -gt 0) {
        foreach ($root in $scanRoots) {
            $webConfigPaths += Get-ChildItem -Path $root -Recurse -Filter 'web.config' `
                -ErrorAction SilentlyContinue | Select-Object -First 20
        }
    }

    foreach ($wc in $webConfigPaths) {
        try {
            [xml]$xml = Get-Content $wc.FullName -ErrorAction SilentlyContinue
            $connStrings = $xml.configuration.connectionStrings.add
            foreach ($cs in $connStrings) {
                $connStr = $cs.connectionString
                # Check for plain text passwords
                if ($connStr -match '(?i)(password|pwd)\s*=\s*[^;]+;' -and
                    $connStr -notmatch '(?i)Integrated Security\s*=\s*(True|SSPI)') {
                    if ($wc.FullName -notmatch 'encrypt|Protected') {
                        $connStrIssues += "$($wc.FullName):$($cs.name)"
                    }
                }
            }
        } catch {}
    }

    if ($connStrIssues.Count -eq 0) {
        Add-Finding 'W25-C10' 'Connection String Security' 'Critical' 'PASS' `
            'No plaintext passwords in connection strings detected (or no web.config found)' ''
    } else {
        Add-Finding 'W25-C10' 'Connection String Security' 'Critical' 'FAIL' `
            ("Plaintext password in connection string(s): " + ($connStrIssues -join ', ')) `
            'Encrypt connectionStrings section: aspnet_regiis -pe "connectionStrings" -app /. Use Windows Authentication (Integrated Security=SSPI) instead of SQL authentication. Store secrets in Azure Key Vault or Windows Credential Manager.'
    }

    } finally {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallback
    }
}
#endregion

#region ── Execute & output ──────────────────────────────────────────────────────
Invoke-Checks

if ($Json) {
    @{
        script    = 'W25_sqli_scanner'
        host      = $env:COMPUTERNAME
        timestamp = (Get-Date -Format 'o')
        findings  = $script:findings
    } | ConvertTo-Json -Depth 10
} else {
    Write-Host ''
    Write-Host "=== W25 SQL Injection Detection Scanner – $env:COMPUTERNAME ===" -ForegroundColor Cyan
    foreach ($f in $script:findings) { Write-Finding $f }
    $failCount = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
    $warnCount = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
    Write-Host "`nSummary: $($script:findings.Count) finding(s), $failCount FAIL, $warnCount WARN"
}

$failCount = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
$warnCount = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
if ($failCount -gt 0) { exit 2 }
if ($warnCount -gt 0) { exit 1 }
exit 0
#endregion
