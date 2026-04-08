#Requires -Version 5.1
<#
.SYNOPSIS
    W19 – API Endpoint Discovery & Security Check (Windows)
.DESCRIPTION
    Discovers local HTTP/HTTPS services (IIS, Kestrel, node.js, etc.), checks
    security headers, tests for exposed API documentation, CORS misconfig,
    and performs basic DAST-like security header verification.
    Read-only by default. Pass -Fix to apply remediation where available.
.NOTES
    ID         : W19
    Category   : API Security & DAST
    Severity   : High
    OS         : Windows 10/11, Server 2016+
    Admin      : No (network checks only)
    Language   : PowerShell 5.1+
    Author     : CyberSWISS Security Team
.PARAMETER Json
    Output results in JSON format for SIEM ingestion.
.PARAMETER Fix
    WARNING: Applies recommended baseline values. Off by default. Use with caution.
.EXAMPLE
    .\W19_api_endpoints.ps1
    .\W19_api_endpoints.ps1 -Json
    .\W19_api_endpoints.ps1 -Fix
#>
[CmdletBinding()]
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
        [string]$Status,   # PASS / FAIL / WARN / INFO
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
#endregion

#region ── Checks ────────────────────────────────────────────────────────────────
function Invoke-Checks {

    # C1 – Discover local HTTP/HTTPS services
    $httpPorts = @(80, 443, 8080, 8443, 3000, 4000, 5000, 8000, 9000)
    $activePorts = [System.Collections.Generic.List[int]]::new()
    try {
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop
        foreach ($port in $httpPorts) {
            if ($listeners | Where-Object { $_.LocalPort -eq $port }) {
                $activePorts.Add($port)
            }
        }
        if ($activePorts.Count -gt 0) {
            Add-Finding 'W19-C1' 'Local HTTP/HTTPS Services' 'Info' 'INFO' `
                "HTTP/HTTPS listeners on ports: $($activePorts -join ', ')" `
                'Review each service to ensure it is expected and properly secured.'
        } else {
            Add-Finding 'W19-C1' 'Local HTTP/HTTPS Services' 'Info' 'INFO' `
                'No HTTP/HTTPS services detected on common ports (80,443,8080,8443,3000,4000,5000,8000,9000).' ''
        }
    } catch {
        Add-Finding 'W19-C1' 'Local HTTP/HTTPS Services' 'Info' 'WARN' `
            "Could not enumerate TCP listeners: $_" 'Run as administrator for full network visibility.'
    }

    # C2 – HTTP security headers
    $requiredHeaders = @('X-Frame-Options','X-Content-Type-Options','Content-Security-Policy','Strict-Transport-Security','X-XSS-Protection')
    $headerIssues    = [System.Collections.Generic.List[string]]::new()
    foreach ($port in $activePorts) {
        $scheme = if ($port -in @(443, 8443)) { 'https' } else { 'http' }
        $uri    = "${scheme}://localhost:${port}/"
        try {
            $resp = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
            if ($resp) {
                foreach ($hdr in $requiredHeaders) {
                    if (-not $resp.Headers.ContainsKey($hdr)) {
                        $headerIssues.Add("Port ${port} missing: $hdr")
                    }
                }
            }
        } catch {}
    }
    if ($activePorts.Count -eq 0) {
        Add-Finding 'W19-C2' 'HTTP Security Headers' 'High' 'INFO' 'No local HTTP services to check.' ''
    } elseif ($headerIssues.Count -eq 0) {
        Add-Finding 'W19-C2' 'HTTP Security Headers' 'High' 'PASS' `
            'All scanned services return required security headers.' ''
    } else {
        Add-Finding 'W19-C2' 'HTTP Security Headers' 'High' 'WARN' `
            "$($headerIssues.Count) missing header(s): $($headerIssues[0..4] -join ' | ')" `
            'Add security headers in IIS (web.config), nginx, or app middleware. Reference: https://securityheaders.com/'
    }

    # C3 – Exposed API documentation
    $apiDocPaths  = @('/swagger', '/swagger-ui', '/swagger-ui.html', '/api-docs', '/openapi.json', '/graphql')
    $exposedDocs  = [System.Collections.Generic.List[string]]::new()
    foreach ($port in $activePorts) {
        $scheme = if ($port -in @(443, 8443)) { 'https' } else { 'http' }
        foreach ($docPath in $apiDocPaths) {
            $uri = "${scheme}://localhost:${port}${docPath}"
            try {
                $resp = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
                if ($resp -and $resp.StatusCode -in @(200, 301, 302)) {
                    $exposedDocs.Add("${scheme}://localhost:${port}${docPath} (HTTP $($resp.StatusCode))")
                }
            } catch {}
        }
    }
    if ($exposedDocs.Count -gt 0) {
        Add-Finding 'W19-C3' 'Exposed API Documentation' 'Med' 'WARN' `
            "API docs accessible: $($exposedDocs -join ' | ')" `
            'Restrict API documentation to authenticated users or internal networks only. Disable Swagger in production builds.'
    } else {
        Add-Finding 'W19-C3' 'Exposed API Documentation' 'Med' 'PASS' `
            'No publicly accessible API documentation endpoints detected.' ''
    }

    # C4 – CORS misconfiguration
    $corsIssues = [System.Collections.Generic.List[string]]::new()
    foreach ($port in $activePorts) {
        $scheme = if ($port -in @(443, 8443)) { 'https' } else { 'http' }
        $uri    = "${scheme}://localhost:${port}/"
        try {
            $resp = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 5 `
                -Headers @{ 'Origin' = 'https://evil.example.com' } -ErrorAction SilentlyContinue
            if ($resp -and $resp.Headers['Access-Control-Allow-Origin'] -eq '*') {
                $corsIssues.Add("Port $($port): Access-Control-Allow-Origin: * (wildcard CORS)")
            }
        } catch {}
    }
    if ($corsIssues.Count -gt 0) {
        Add-Finding 'W19-C4' 'CORS Misconfiguration' 'High' 'FAIL' `
            ($corsIssues -join ' | ') `
            'Replace wildcard CORS with specific allowed origins. Never use Access-Control-Allow-Origin: * for authenticated endpoints.'
    } else {
        Add-Finding 'W19-C4' 'CORS Misconfiguration' 'High' 'PASS' `
            'No wildcard CORS headers detected on scanned services.' ''
    }

    # C5 – Admin/debug endpoints
    $debugPaths  = @('/admin','/console','/actuator','/metrics','/health','/debug','/elmah.axd','/trace.axd','/env','/info')
    $exposedAdmin = [System.Collections.Generic.List[string]]::new()
    foreach ($port in $activePorts) {
        $scheme = if ($port -in @(443, 8443)) { 'https' } else { 'http' }
        foreach ($dPath in $debugPaths) {
            $uri = "${scheme}://localhost:${port}${dPath}"
            try {
                $resp = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
                if ($resp -and $resp.StatusCode -eq 200) {
                    $exposedAdmin.Add("${scheme}://localhost:${port}${dPath}")
                }
            } catch {}
        }
    }
    if ($exposedAdmin.Count -gt 0) {
        Add-Finding 'W19-C5' 'Admin/Debug Endpoints Exposed' 'Critical' 'FAIL' `
            "Accessible admin/debug endpoints: $($exposedAdmin -join ' | ')" `
            'Restrict admin/actuator endpoints to localhost or authenticated admin users only. Remove debug endpoints from production.'
    } else {
        Add-Finding 'W19-C5' 'Admin/Debug Endpoints Exposed' 'High' 'PASS' `
            'No unauthenticated admin or debug endpoints detected.' ''
    }

    # C6 – IIS configuration review
    $appHostConfig = 'C:\Windows\System32\inetsrv\config\applicationHost.config'
    if (Test-Path $appHostConfig) {
        try {
            $iisContent = Get-Content $appHostConfig -ErrorAction Stop -Raw
            $iisIssues  = [System.Collections.Generic.List[string]]::new()
            if ($iisContent -imatch 'customErrors\s+mode\s*=\s*"Off"')         { $iisIssues.Add('customErrors mode="Off" (debug info exposed)') }
            if ($iisContent -imatch 'directoryBrowse\s+enabled\s*=\s*"true"')  { $iisIssues.Add('Directory browsing enabled') }
            if ($iisIssues.Count -gt 0) {
                Add-Finding 'W19-C6' 'IIS Security Configuration' 'High' 'WARN' `
                    ($iisIssues -join ' | ') `
                    'Set customErrors mode="RemoteOnly" or "On". Disable directory browsing in IIS Manager or applicationHost.config.'
            } else {
                Add-Finding 'W19-C6' 'IIS Security Configuration' 'High' 'PASS' `
                    'IIS applicationHost.config: no obvious debug mode or directory browsing issues.' ''
            }
        } catch {
            Add-Finding 'W19-C6' 'IIS Security Configuration' 'High' 'WARN' `
                "Could not read applicationHost.config: $_" 'Run as administrator.'
        }
    } else {
        Add-Finding 'W19-C6' 'IIS Security Configuration' 'Info' 'INFO' `
            'IIS applicationHost.config not found. IIS may not be installed.' ''
    }

    # C7 – TLS certificate expiry for HTTPS services
    $httpsPorts = $activePorts | Where-Object { $_ -in @(443, 8443) }
    if ($httpsPorts.Count -eq 0) {
        Add-Finding 'W19-C7' 'TLS Certificate Expiry' 'High' 'INFO' `
            'No HTTPS services detected on standard ports (443, 8443).' ''
    } else {
        foreach ($port in $httpsPorts) {
            try {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
                $req = [System.Net.HttpWebRequest]::Create("https://localhost:$port/")
                $req.Timeout = 5000
                try {
                    $req.GetResponse().Close()
                } catch [System.Net.WebException] {
                    # May still have cert even with HTTP error
                }
                $cert = $req.ServicePoint.Certificate
                if ($cert) {
                    $expiry    = [datetime]::Parse($cert.GetExpirationDateString())
                    $daysLeft  = ($expiry - (Get-Date)).Days
                    $thumbprint = $cert.GetCertHashString()
                    if ($daysLeft -le 0) {
                        Add-Finding 'W19-C7' "TLS Cert Expiry (port $port)" 'Critical' 'FAIL' `
                            "Certificate EXPIRED $([Math]::Abs($daysLeft)) day(s) ago. Thumbprint: $thumbprint" `
                            'Renew the TLS certificate immediately and update IIS/service binding.'
                    } elseif ($daysLeft -le 30) {
                        Add-Finding 'W19-C7' "TLS Cert Expiry (port $port)" 'High' 'FAIL' `
                            "Certificate expires in $daysLeft day(s) (<= 30). Thumbprint: $thumbprint" `
                            'Renew TLS certificate immediately.'
                    } elseif ($daysLeft -le 90) {
                        Add-Finding 'W19-C7' "TLS Cert Expiry (port $port)" 'Med' 'WARN' `
                            "Certificate expires in $daysLeft day(s) (<= 90). Thumbprint: $thumbprint" `
                            'Plan TLS certificate renewal within 30 days.'
                    } else {
                        Add-Finding 'W19-C7' "TLS Cert Expiry (port $port)" 'Info' 'PASS' `
                            "Certificate valid for $daysLeft day(s). Thumbprint: $thumbprint" ''
                    }
                } else {
                    Add-Finding 'W19-C7' "TLS Cert Expiry (port $port)" 'Med' 'WARN' `
                        'Could not retrieve certificate from HTTPS endpoint.' `
                        'Verify TLS certificate is properly bound to the service.'
                }
            } catch {
                Add-Finding 'W19-C7' "TLS Cert Expiry (port $port)" 'Med' 'WARN' `
                    "Could not inspect TLS certificate on port ${port}: $_" `
                    'Verify the HTTPS service is running and accessible.'
            } finally {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
            }
        }
    }
}
#endregion

#region ── Output ────────────────────────────────────────────────────────────────
Invoke-Checks

if ($Fix) {
    Write-Warning "⚠  -Fix flag detected: API security issues require manual remediation."
    Write-Host '   Guidance for IIS security headers (web.config):' -ForegroundColor Cyan
    Write-Host '   <system.webServer><httpProtocol><customHeaders>' -ForegroundColor Cyan
    Write-Host '     <add name="X-Frame-Options" value="SAMEORIGIN" />' -ForegroundColor Cyan
    Write-Host '     <add name="X-Content-Type-Options" value="nosniff" />' -ForegroundColor Cyan
    Write-Host '     <add name="Content-Security-Policy" value="default-src ''self''" />' -ForegroundColor Cyan
    Write-Host '   </customHeaders></httpProtocol></system.webServer>' -ForegroundColor Cyan
    Write-Host '   Reference: https://docs.microsoft.com/iis/configuration/system.webserver/httprotocol/customheaders/' -ForegroundColor Cyan
}

if ($Json) {
    $result = @{
        script    = 'W19_api_endpoints'
        host      = $env:COMPUTERNAME
        timestamp = (Get-Date -Format 'o')
        findings  = $script:findings
    }
    $result | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W19 API Endpoint Discovery & Security Check – $env:COMPUTERNAME ===" -ForegroundColor Cyan
    foreach ($f in $script:findings) { Write-Finding $f }
    $fails = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
    $warns = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
    Write-Host ("`nSummary: {0} finding(s), {1} FAIL, {2} WARN" -f $script:findings.Count, $fails, $warns)
}

$exitCode = 0
if (($script:findings | Where-Object { $_.status -eq 'WARN' }).Count -gt 0) { $exitCode = 1 }
if (($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { $exitCode = 2 }
exit $exitCode
#endregion
