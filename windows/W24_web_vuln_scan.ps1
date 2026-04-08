#Requires -Version 5.1
<#
.SYNOPSIS
    W24 – Web Vulnerability Scanner (Windows)
.DESCRIPTION
    Performs a comprehensive web vulnerability scan against locally running
    web services — similar to industry-standard web vulnerability scanners:
      C1  – Dangerous / exposed backup and configuration file discovery
      C2  – Outdated web server software version detection
      C3  – HTTP method permissiveness (TRACE, PUT, DELETE exposure)
      C4  – Default or sensitive path exposure (/admin, /phpmyadmin, etc.)
      C5  – Directory listing enabled
      C6  – Clickjacking / framing controls (X-Frame-Options / CSP frame-ancestors)
      C7  – HTTPS enforcement and HSTS header presence
      C8  – Insecure cookie attributes (missing Secure / HttpOnly / SameSite)
      C9  – Cross-site scripting (XSS) reflection indicators
      C10 – Web application firewall (WAF) absence detection
    Read-only by default. Pass -Fix to apply remediation where available.
.NOTES
    ID         : W24
    Category   : Web Application Security
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
    .\W24_web_vuln_scan.ps1
    .\W24_web_vuln_scan.ps1 -Json
    .\W24_web_vuln_scan.ps1 -Fix
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

function Invoke-HttpHead {
    param([string]$Uri, [int]$TimeoutSec = 8)
    # PowerShell 5.1-compatible certificate check bypass (equivalent to -SkipCertificateCheck)
    $originalCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    try {
        $resp = Invoke-WebRequest -Uri $Uri -Method Head -UseBasicParsing `
            -TimeoutSec $TimeoutSec -ErrorAction SilentlyContinue 2>$null
        return $resp
    } catch { return $null } finally {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallback
    }
}

function Invoke-HttpGet {
    param([string]$Uri, [int]$TimeoutSec = 8)
    # PowerShell 5.1-compatible certificate check bypass (equivalent to -SkipCertificateCheck)
    $originalCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    try {
        $resp = Invoke-WebRequest -Uri $Uri -Method Get -UseBasicParsing `
            -TimeoutSec $TimeoutSec -ErrorAction SilentlyContinue 2>$null
        return $resp
    } catch { return $null } finally {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallback
    }
}
#endregion

#region ── Detect active web ports ──────────────────────────────────────────────
$webPorts = @()
$candidatePorts = @(80, 443, 8080, 8443, 8000, 8888, 3000)
foreach ($port in $candidatePorts) {
    try {
        $conn = New-Object System.Net.Sockets.TcpClient
        $conn.ConnectAsync('127.0.0.1', $port).Wait(500) | Out-Null
        if ($conn.Connected) { $webPorts += $port }
        $conn.Close()
    } catch {}
}
#endregion

#region ── Checks ────────────────────────────────────────────────────────────────
function Invoke-Checks {
    # Set PS 5.1-compatible certificate bypass for all web requests in this function
    $originalCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    try {

    # C1 – Dangerous / backup / config file exposure ──────────────────────────
    $dangerPaths = @(
        '/.git/config', '/.git/HEAD', '/.env', '/.env.backup', '/wp-config.php',
        '/wp-config.php.bak', '/config.php', '/database.yml', '/phpinfo.php',
        '/info.php', '/test.php', '/server-status', '/server-info', '/.htpasswd',
        '/backup.zip', '/db.sql', '/dump.sql', '/WEB-INF/web.xml',
        '/crossdomain.xml', '/clientaccesspolicy.xml', '/web.config.bak',
        '/web.config.old', '/global.asax.bak', '/appsettings.Development.json'
    )

    $dangerousFound = @()
    foreach ($port in $webPorts) {
        $scheme = if ($port -in @(443, 8443)) { 'https' } else { 'http' }
        foreach ($path in $dangerPaths) {
            $resp = Invoke-HttpHead "${scheme}://localhost:${port}$path"
            if ($resp -and $resp.StatusCode -eq 200) {
                $dangerousFound += "port${port}:$path(200)"
            }
        }
    }

    if ($dangerousFound.Count -eq 0) {
        Add-Finding 'W24-C1' 'Dangerous File/Path Exposure' 'Critical' 'PASS' `
            'No exposed backup, config, or sensitive files detected on checked web ports' ''
    } else {
        Add-Finding 'W24-C1' 'Dangerous File/Path Exposure' 'Critical' 'FAIL' `
            ("Exposed sensitive file(s): " + ($dangerousFound -join ', ')) `
            'Remove or restrict access to backup/config/source files. Block .git, .env, .bak paths in IIS/web.config. Use Request Filtering to deny dangerous extensions.'
    }

    # C2 – Outdated web server software detection ─────────────────────────────
    $outdatedServers = @()
    foreach ($port in $webPorts) {
        $scheme = if ($port -in @(443, 8443)) { 'https' } else { 'http' }
        $resp = Invoke-HttpHead "${scheme}://localhost:${port}/"
        if (-not $resp) { continue }
        $serverHdr = $resp.Headers['Server']
        if ($serverHdr) {
            # Check IIS version
            if ($serverHdr -match 'IIS/([0-9]+\.[0-9]+)') {
                $iisVer = [version]$Matches[1]
                if ($iisVer -lt [version]'10.0') {
                    $outdatedServers += "port${port}:IIS/$($Matches[1])(outdated)"
                }
            }
            # Check for version disclosure (any server showing version numbers is a risk)
            if ($serverHdr -match '[0-9]+\.[0-9]+\.[0-9]+') {
                $outdatedServers += "port${port}:ServerVersionDisclosed($serverHdr)"
            }
        }
        # Check X-Powered-By for ASP.NET version
        $poweredBy = $resp.Headers['X-Powered-By']
        if ($poweredBy -and $poweredBy -match 'ASP\.NET') {
            $aspVer = $resp.Headers['X-AspNet-Version']
            if ($aspVer -and [version]$aspVer -lt [version]'4.8') {
                $outdatedServers += "port${port}:ASP.NET/$aspVer(outdated)"
            }
        }
    }

    if ($outdatedServers.Count -eq 0) {
        Add-Finding 'W24-C2' 'Outdated Web Server Software' 'High' 'PASS' `
            'No outdated web server version disclosure detected in response headers' ''
    } else {
        Add-Finding 'W24-C2' 'Outdated Web Server Software' 'High' 'FAIL' `
            ("Server software issue(s): " + ($outdatedServers -join ', ')) `
            'Update IIS and .NET Framework. Remove Server/X-Powered-By/X-AspNet-Version headers in IIS (customHeaders removeAll + requestFiltering removeServerHeader).'
    }

    # C3 – HTTP method permissiveness ─────────────────────────────────────────
    $dangerousMethods = @()
    foreach ($port in $webPorts) {
        $scheme = if ($port -in @(443, 8443)) { 'https' } else { 'http' }
        foreach ($method in @('TRACE','PUT','DELETE')) {
            try {
                $resp = Invoke-WebRequest -Uri "${scheme}://localhost:${port}/" -Method $method `
                    -UseBasicParsing -TimeoutSec 6 -ErrorAction SilentlyContinue 2>$null
                if ($resp -and $resp.StatusCode -in @(200, 201, 204)) {
                    $dangerousMethods += "port${port}:$method($($resp.StatusCode))"
                }
            } catch {}
        }
    }

    if ($dangerousMethods.Count -eq 0) {
        Add-Finding 'W24-C3' 'Dangerous HTTP Methods Enabled' 'High' 'PASS' `
            'TRACE/PUT/DELETE not returning success responses on checked web listeners' ''
    } else {
        Add-Finding 'W24-C3' 'Dangerous HTTP Methods Enabled' 'High' 'FAIL' `
            ("Dangerous method(s) accepted: " + ($dangerousMethods -join ', ')) `
            'Restrict HTTP verbs in IIS: Request Filtering > HTTP Verbs > Allow only GET, POST, HEAD. Or use web.config <system.webServer><security><requestFiltering><verbs>.'
    }

    # C4 – Default / sensitive admin path exposure ────────────────────────────
    $adminPaths = @(
        '/admin', '/administrator', '/wp-admin', '/wp-login.php',
        '/_admin', '/manage', '/management', '/console',
        '/elmah.axd', '/trace.axd', '/ScriptResource.axd',
        '/api/v1/admin', '/api/v1/users', '/swagger/index.html',
        '/swagger-ui/', '/health', '/actuator', '/actuator/env',
        '/_cat/indices', '/_cluster/health'
    )

    $adminExposed = @()
    foreach ($port in $webPorts) {
        $scheme = if ($port -in @(443, 8443)) { 'https' } else { 'http' }
        foreach ($path in $adminPaths) {
            try {
                $resp = Invoke-WebRequest -Uri "${scheme}://localhost:${port}$path" `
                    -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue 2>$null
                if ($resp -and $resp.StatusCode -in @(200, 301, 302)) {
                    $adminExposed += "port${port}:$path($($resp.StatusCode))"
                }
            } catch {}
        }
    }

    if ($adminExposed.Count -eq 0) {
        Add-Finding 'W24-C4' 'Default/Sensitive Path Exposure' 'High' 'PASS' `
            'No default admin or sensitive paths accessible on checked web ports' ''
    } else {
        Add-Finding 'W24-C4' 'Default/Sensitive Path Exposure' 'High' 'WARN' `
            ("Accessible sensitive path(s): " + ($adminExposed -join ', ')) `
            'Restrict admin/diagnostic endpoints to localhost/VPN only. Add IP restrictions in IIS. Disable trace.axd, elmah.axd, swagger in production.'
    }

    # C5 – Directory listing enabled ──────────────────────────────────────────
    $dirListingFound = @()
    foreach ($port in $webPorts) {
        $scheme = if ($port -in @(443, 8443)) { 'https' } else { 'http' }
        foreach ($path in @('/', '/images/', '/static/', '/uploads/', '/files/')) {
            $resp = Invoke-HttpGet "${scheme}://localhost:${port}$path"
            if ($resp -and $resp.Content -match '(?i)(Index of|Directory listing|Parent Directory)') {
                $dirListingFound += "port${port}:$path"
            }
        }
    }

    if ($dirListingFound.Count -eq 0) {
        Add-Finding 'W24-C5' 'Directory Listing Enabled' 'Med' 'PASS' `
            'No directory listing responses detected on checked web ports' ''
    } else {
        Add-Finding 'W24-C5' 'Directory Listing Enabled' 'Med' 'FAIL' `
            ("Directory listing enabled: " + ($dirListingFound -join ', ')) `
            'Disable directory browsing in IIS Manager > Directory Browsing (disable). Or in web.config: <directoryBrowse enabled="false" />.'
    }

    # C6 – Clickjacking protection ────────────────────────────────────────────
    $clickjackIssues = @()
    foreach ($port in $webPorts) {
        $scheme = if ($port -in @(443, 8443)) { 'https' } else { 'http' }
        $resp = Invoke-HttpHead "${scheme}://localhost:${port}/"
        if (-not $resp) { continue }
        $hasXFO = $resp.Headers['X-Frame-Options']
        $cspHdr = $resp.Headers['Content-Security-Policy']
        $hasCSPFrame = $cspHdr -and $cspHdr -match 'frame-ancestors'
        if (-not $hasXFO -and -not $hasCSPFrame) {
            $clickjackIssues += "port${port}:missing-X-Frame-Options-and-CSP-frame-ancestors"
        }
    }

    if ($clickjackIssues.Count -eq 0) {
        Add-Finding 'W24-C6' 'Clickjacking Protection' 'Med' 'PASS' `
            'X-Frame-Options or CSP frame-ancestors present on checked web listeners' ''
    } else {
        Add-Finding 'W24-C6' 'Clickjacking Protection' 'Med' 'FAIL' `
            ("Missing clickjacking protection: " + ($clickjackIssues -join ', ')) `
            'Add X-Frame-Options: DENY in IIS custom headers or web.config customHeaders. Or use Content-Security-Policy: frame-ancestors ''none''.'
    }

    # C7 – HTTPS enforcement and HSTS ─────────────────────────────────────────
    $httpsIssues = @()
    # Check if HTTP (80) redirects to HTTPS
    if (80 -in $webPorts) {
        try {
            $resp = Invoke-WebRequest -Uri 'http://localhost/' -UseBasicParsing `
                -MaximumRedirection 0 -TimeoutSec 6 -ErrorAction SilentlyContinue 2>$null
            if ($resp -and $resp.StatusCode -notin @(301, 302, 307, 308)) {
                $httpsIssues += "port80:no-HTTPS-redirect(status:$($resp.StatusCode))"
            }
        } catch {}
    }

    # Check HSTS on HTTPS ports
    foreach ($port in $webPorts | Where-Object { $_ -in @(443, 8443) }) {
        $resp = Invoke-HttpHead "https://localhost:$port/"
        if ($resp -and -not $resp.Headers['Strict-Transport-Security']) {
            $httpsIssues += "port${port}:missing-HSTS-header"
        }
    }

    if ($httpsIssues.Count -eq 0) {
        Add-Finding 'W24-C7' 'HTTPS Enforcement and HSTS' 'High' 'PASS' `
            'HTTP to HTTPS redirect and HSTS configured correctly' ''
    } else {
        Add-Finding 'W24-C7' 'HTTPS Enforcement and HSTS' 'High' 'WARN' `
            ("HTTPS enforcement issue(s): " + ($httpsIssues -join ', ')) `
            'Configure IIS HTTP to HTTPS redirect (301). Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains. Use IIS HTTPS Redirect module.'
    }

    # C8 – Insecure cookie attributes ─────────────────────────────────────────
    $cookieIssues = @()
    foreach ($port in $webPorts) {
        $scheme = if ($port -in @(443, 8443)) { 'https' } else { 'http' }
        $resp = Invoke-HttpHead "${scheme}://localhost:${port}/"
        if (-not $resp) { continue }
        $setCookieHdrs = try { $resp.Headers.GetValues('Set-Cookie') } catch { $null }
        if (-not $setCookieHdrs) { continue }
        foreach ($cookie in $setCookieHdrs) {
            $cookieName = ($cookie -split '=')[0].Trim()
            $missing = @()
            if ($cookie -notmatch '(?i);\s*Secure')   { $missing += 'Secure'   }
            if ($cookie -notmatch '(?i);\s*HttpOnly') { $missing += 'HttpOnly' }
            if ($cookie -notmatch '(?i);\s*SameSite') { $missing += 'SameSite' }
            if ($missing.Count -gt 0) {
                $cookieIssues += "port${port}:$cookieName(missing:$($missing -join ','))"
            }
        }
    }

    if ($cookieIssues.Count -eq 0) {
        Add-Finding 'W24-C8' 'Insecure Cookie Attributes' 'High' 'PASS' `
            'No insecure cookie attribute patterns detected in response headers' ''
    } else {
        Add-Finding 'W24-C8' 'Insecure Cookie Attributes' 'High' 'FAIL' `
            ("Cookie(s) missing security attributes: " + ($cookieIssues -join ', ')) `
            'Set RequireSSL=true and HttpOnly=true on ASP.NET session cookies. Use SameSite=Strict in forms authentication. Configure in web.config <httpCookies requireSSL="true" httpOnlyCookies="true" sameSite="Strict">.'
    }

    # C9 – XSS reflection probe ───────────────────────────────────────────────
    $xssIssues = @()
    $xssPayload = '<script>alert(1)</script>'
    $xssEncoded = [Uri]::EscapeDataString($xssPayload)
    foreach ($port in $webPorts) {
        $scheme = if ($port -in @(443, 8443)) { 'https' } else { 'http' }
        foreach ($path in @('/', '/search', '/search.aspx', '/Default.aspx')) {
            foreach ($param in @('q', 'search', 'query', 'id')) {
                $resp = Invoke-HttpGet "${scheme}://localhost:${port}${path}?${param}=${xssEncoded}"
                if ($resp -and $resp.Content -match [regex]::Escape($xssPayload)) {
                    $xssIssues += "port${port}:${path}?${param}=XSS_REFLECTED"
                    break
                }
            }
            if ($xssIssues.Count -gt 0) { break }
        }
    }

    if ($xssIssues.Count -eq 0) {
        Add-Finding 'W24-C9' 'Reflected XSS Indicators' 'Critical' 'PASS' `
            'No reflected XSS payload detected in tested parameter responses' ''
    } else {
        Add-Finding 'W24-C9' 'Reflected XSS Indicators' 'Critical' 'FAIL' `
            ("Potential reflected XSS: " + ($xssIssues -join ', ')) `
            'Use AntiXSS library or HtmlEncode all user output. Enable IIS Request Filtering. Set Content-Security-Policy. Add WAF rules for XSS patterns.'
    }

    # C10 – WAF absence detection ─────────────────────────────────────────────
    $wafDetected = @()
    $noWafPorts  = @()
    foreach ($port in $webPorts) {
        $scheme = if ($port -in @(443, 8443)) { 'https' } else { 'http' }
        try {
            $resp = Invoke-WebRequest -Uri "${scheme}://localhost:${port}/?q=<script>alert(1)</script>&id=1 UNION SELECT 1--" `
                -UseBasicParsing -TimeoutSec 6 -ErrorAction SilentlyContinue 2>$null
            $hasWafHeaders = $resp -and ($resp.Headers['X-Sucuri-ID'] -or $resp.Headers['X-Cache'] -or
                $resp.Headers['X-Firewall-Protection'] -or ($resp.Headers['Server'] -imatch 'cloudflare'))
            if ($hasWafHeaders -or ($resp -and $resp.StatusCode -in @(403, 406))) {
                $wafDetected += "port${port}:WAF-detected($($resp.StatusCode))"
            } else {
                $noWafPorts += "port${port}"
            }
        } catch {}
    }

    if ($wafDetected.Count -gt 0 -or $webPorts.Count -eq 0) {
        Add-Finding 'W24-C10' 'Web Application Firewall (WAF) Presence' 'Med' 'PASS' `
            ("WAF detected or no web ports active: " + ($wafDetected -join ', ')) ''
    } else {
        Add-Finding 'W24-C10' 'Web Application Firewall (WAF) Presence' 'Med' 'WARN' `
            ("No WAF detected on: " + ($noWafPorts -join ', ')) `
            'Deploy ModSecurity for IIS or use Azure Front Door WAF / Azure Application Gateway with OWASP rules. Enable IIS Dynamic IP Restrictions and Request Filtering.'
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
        script    = 'W24_web_vuln_scan'
        host      = $env:COMPUTERNAME
        timestamp = (Get-Date -Format 'o')
        findings  = $script:findings
    } | ConvertTo-Json -Depth 10
} else {
    Write-Host ''
    Write-Host "=== W24 Web Vulnerability Scanner – $env:COMPUTERNAME ===" -ForegroundColor Cyan
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
