#Requires -Version 5.1
<#
.SYNOPSIS
    W23 – OpenVAS / Nessus-Style Comprehensive Vulnerability Scanner (Windows)
.DESCRIPTION
    Performs an OpenVAS / Nessus-style infrastructure vulnerability assessment:
      C1  – OpenVAS/Nessus agent presence and last-scan status
      C2  – Weak TLS protocol enablement (SSLv2, SSLv3, TLS 1.0, TLS 1.1) via registry
      C3  – SMBv1 protocol enabled (EternalBlue / WannaCry / NotPetya risk)
      C4  – Insecure / legacy protocols in use (Telnet service, FTP service)
      C5  – Anonymous network shares
      C6  – RDP security level and NLA enforcement
      C7  – SNMP default community strings
      C8  – Unquoted service paths (privilege escalation risk)
      C9  – Pending Windows security updates (WSUS / Windows Update)
      C10 – IIS web server security-header hardening
    Read-only by default. Pass -Fix to apply remediation where available.
.NOTES
    ID         : W23
    Category   : Vulnerability Assessment
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
    .\W23_openvas_vuln_scan.ps1
    .\W23_openvas_vuln_scan.ps1 -Json
    .\W23_openvas_vuln_scan.ps1 -Fix
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

    # C1 – OpenVAS / Nessus agent presence ─────────────────────────────────────
    $scannerFound = $false
    $scannerInfo  = ''

    # Nessus agent
    $nessusPaths = @(
        'C:\Program Files\Tenable\Nessus Agent\nessuscli.exe',
        'C:\Program Files (x86)\Tenable\Nessus\nessuscli.exe',
        'C:\Program Files\Nessus\nessuscli.exe'
    )
    foreach ($p in $nessusPaths) {
        if (Test-Path $p) {
            $scannerFound = $true
            $scannerInfo  = "Nessus agent found at $p"
            break
        }
    }

    # Check Nessus/OpenVAS Windows services
    $scannerServices = @('Tenable Nessus','nessus','OpenVAS','gvm')
    foreach ($svcName in $scannerServices) {
        try {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($svc) {
                $scannerFound = $true
                $scannerInfo += " Service:$svcName($($svc.Status))"
            }
        } catch {}
    }

    if ($scannerFound) {
        Add-Finding 'W23-C1' 'Vulnerability Scanner Presence' 'Info' 'PASS' `
            $scannerInfo ''
    } else {
        Add-Finding 'W23-C1' 'Vulnerability Scanner Presence' 'High' 'WARN' `
            'No Nessus agent or OpenVAS scanner detected on this host.' `
            'Install Nessus Agent (https://www.tenable.com/products/nessus/nessus-agents) or configure a Tenable/OpenVAS scan policy targeting this host.'
    }

    # C2 – Weak TLS protocol enablement (registry) ────────────────────────────
    $weakProtos = @()
    $tlsRegBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    $protoChecks = @(
        @{ Name = 'SSL 2.0'; Key = 'SSL 2.0\Server'; DisabledValue = 1 },
        @{ Name = 'SSL 3.0'; Key = 'SSL 3.0\Server'; DisabledValue = 1 },
        @{ Name = 'TLS 1.0'; Key = 'TLS 1.0\Server'; DisabledValue = 1 },
        @{ Name = 'TLS 1.1'; Key = 'TLS 1.1\Server'; DisabledValue = 1 }
    )

    foreach ($proto in $protoChecks) {
        $regPath = Join-Path $tlsRegBase $proto.Key
        try {
            $disabled = (Get-ItemProperty -Path $regPath -Name 'Disabled' -ErrorAction SilentlyContinue).Disabled
            $enabled  = (Get-ItemProperty -Path $regPath -Name 'Enabled'  -ErrorAction SilentlyContinue).Enabled

            # Protocol is weak/enabled if: Disabled is 0, or Enabled is 1, or no key (OS default may allow)
            if ($disabled -eq 0 -or $enabled -eq 1) {
                $weakProtos += $proto.Name
            } elseif ($null -eq $disabled -and $proto.Name -in @('SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1')) {
                # No explicit disable key – OS default may still allow these
                $weakProtos += "$($proto.Name)(no-explicit-disable)"
            }
        } catch {
            $weakProtos += "$($proto.Name)(registry-error)"
        }
    }

    if ($weakProtos.Count -eq 0) {
        Add-Finding 'W23-C2' 'Weak TLS Protocol Enablement' 'Critical' 'PASS' `
            'SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1 are explicitly disabled in SCHANNEL registry.' ''
    } else {
        Add-Finding 'W23-C2' 'Weak TLS Protocol Enablement' 'Critical' 'FAIL' `
            ("Weak protocol(s) not explicitly disabled: " + ($weakProtos -join ', ')) `
            'Disable weak TLS in registry: HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols. Set Disabled=1 for SSL2, SSL3, TLS1.0, TLS1.1. Use IIS Crypto or Nartac Software tool to automate.'

        if ($Fix -and $PSCmdlet.ShouldProcess('SCHANNEL', 'Disable weak TLS protocols')) {
            foreach ($proto in $protoChecks) {
                $regPath = Join-Path $tlsRegBase $proto.Key
                try {
                    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                    Set-ItemProperty -Path $regPath -Name 'Enabled'  -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $regPath -Name 'Disabled' -Value 1 -Type DWord -Force
                    Write-Warning "Disabled $($proto.Name) in SCHANNEL registry."
                } catch { Write-Warning "Failed to disable $($proto.Name): $_" }
            }
        }
    }

    # C3 – SMBv1 enabled ──────────────────────────────────────────────────────
    $smb1Enabled = $false
    $smb1Detail  = ''
    try {
        $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction SilentlyContinue
        if ($smb1Feature -and $smb1Feature.State -eq 'Enabled') {
            $smb1Enabled = $true
            $smb1Detail  = 'SMB1Protocol Windows Feature is Enabled'
        }
    } catch {}

    try {
        $smb1Config = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
        if ($smb1Config -and $smb1Config.EnableSMB1Protocol) {
            $smb1Enabled = $true
            $smb1Detail += ' EnableSMB1Protocol=True in SmbServerConfiguration'
        }
    } catch {}

    if ($smb1Enabled) {
        Add-Finding 'W23-C3' 'SMBv1 Protocol Enabled' 'Critical' 'FAIL' `
            $smb1Detail.Trim() `
            'Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force OR Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol. Protects against EternalBlue/WannaCry.'

        if ($Fix -and $PSCmdlet.ShouldProcess('SMB', 'Disable SMBv1')) {
            try {
                Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
                Write-Warning 'SMBv1 disabled via Set-SmbServerConfiguration.'
            } catch { Write-Warning "Failed to disable SMBv1 via SmbServerConfiguration: $_" }
        }
    } else {
        Add-Finding 'W23-C3' 'SMBv1 Protocol Enabled' 'Critical' 'PASS' `
            'SMBv1 is disabled on this host' ''
    }

    # C4 – Insecure / legacy protocol services ────────────────────────────────
    $legacyIssues = @()
    $legacyServices = @(
        @{ Name = 'Telnet';       ServiceName = 'TlntSvr'   },
        @{ Name = 'TFTP client';  ServiceName = 'TFTPC'     },
        @{ Name = 'Simple TCP/IP (FTP)'; ServiceName = 'simptcp' },
        @{ Name = 'FTP Service (IIS)';   ServiceName = 'ftpsvc'  }
    )
    foreach ($svc in $legacyServices) {
        try {
            $s = Get-Service -Name $svc.ServiceName -ErrorAction SilentlyContinue
            if ($s -and $s.Status -eq 'Running') {
                $legacyIssues += "$($svc.Name)($($svc.ServiceName))-RUNNING"
            }
        } catch {}
    }

    # Check for Telnet Windows Feature
    try {
        $telnetFeature = Get-WindowsOptionalFeature -Online -FeatureName 'TelnetClient' -ErrorAction SilentlyContinue
        if ($telnetFeature -and $telnetFeature.State -eq 'Enabled') {
            $legacyIssues += 'TelnetClient-Feature-Enabled'
        }
    } catch {}

    if ($legacyIssues.Count -eq 0) {
        Add-Finding 'W23-C4' 'Insecure Legacy Protocol Services' 'Critical' 'PASS' `
            'No Telnet, TFTP, or legacy FTP services running' ''
    } else {
        Add-Finding 'W23-C4' 'Insecure Legacy Protocol Services' 'Critical' 'FAIL' `
            ("Legacy service(s) active: " + ($legacyIssues -join ', ')) `
            'Disable Telnet service (TlntSvr) and FTP service (ftpsvc) if not required. Use SSH/SFTP instead. Remove TelnetClient Windows Feature if not needed.'
    }

    # C5 – Anonymous network shares ───────────────────────────────────────────
    $anonShares = @()
    try {
        $shares = Get-SmbShare -ErrorAction SilentlyContinue
        foreach ($share in $shares) {
            try {
                $acl = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
                if ($acl | Where-Object { $_.AccountName -match 'Everyone|Anonymous|ANONYMOUS' -and $_.AccessRight -ne 'None' }) {
                    $anonShares += "$($share.Name)($($share.Path))"
                }
            } catch {}
        }
    } catch {}

    # Also check NullSessionShares registry key
    $nullSessionShares = ''
    try {
        $nullReg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
            -Name 'NullSessionShares' -ErrorAction SilentlyContinue
        if ($nullReg -and $nullReg.NullSessionShares) {
            $nullSessionShares = $nullReg.NullSessionShares -join ', '
        }
    } catch {}

    if ($anonShares.Count -eq 0 -and [string]::IsNullOrEmpty($nullSessionShares)) {
        Add-Finding 'W23-C5' 'Anonymous Network Shares' 'Critical' 'PASS' `
            'No shares accessible by Everyone/Anonymous detected' ''
    } else {
        $detail = ''
        if ($anonShares.Count -gt 0) { $detail += "Anonymous-accessible shares: $($anonShares -join ', '). " }
        if ($nullSessionShares)       { $detail += "NullSessionShares: $nullSessionShares." }
        Add-Finding 'W23-C5' 'Anonymous Network Shares' 'Critical' 'FAIL' `
            $detail.Trim() `
            'Remove Everyone/Anonymous from share ACLs. Clear NullSessionShares registry value. Set RestrictNullSessAccess=1 in LanmanServer parameters.'
    }

    # C6 – RDP security level and NLA enforcement ─────────────────────────────
    $rdpIssues = @()
    try {
        # Check if RDP is enabled at all
        $rdpEnabled = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
            -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections
        if ($rdpEnabled -eq 0) {
            # RDP is enabled – check NLA
            $nlaRequired = (Get-ItemProperty `
                -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
                -Name 'UserAuthenticationRequired' -ErrorAction SilentlyContinue).UserAuthenticationRequired
            if ($nlaRequired -ne 1) {
                $rdpIssues += 'NLA(Network Level Authentication) not required'
            }

            # Check RDP security layer (2 = SSL/TLS required; 0 = RDP native = weaker)
            $secLayer = (Get-ItemProperty `
                -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
                -Name 'SecurityLayer' -ErrorAction SilentlyContinue).SecurityLayer
            if ($secLayer -ne 2) {
                $rdpIssues += "SecurityLayer=$secLayer(should be 2 for TLS)"
            }

            # Check RDP encryption level (4 = FIPS Compliant; 3 = High; 2 = ClientCompatible; 1 = Low)
            $encLevel = (Get-ItemProperty `
                -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
                -Name 'MinEncryptionLevel' -ErrorAction SilentlyContinue).MinEncryptionLevel
            if ($encLevel -lt 3) {
                $rdpIssues += "MinEncryptionLevel=$encLevel(should be >=3)"
            }
        }
    } catch {}

    if ($rdpIssues.Count -eq 0) {
        Add-Finding 'W23-C6' 'RDP Security Level and NLA' 'High' 'PASS' `
            'RDP is disabled or properly configured with NLA and TLS security layer' ''
    } else {
        Add-Finding 'W23-C6' 'RDP Security Level and NLA' 'High' 'FAIL' `
            ("RDP misconfiguration(s): " + ($rdpIssues -join '; ')) `
            'Enable NLA: Set UserAuthenticationRequired=1. Set SecurityLayer=2 (TLS). Set MinEncryptionLevel=3. Use Group Policy: Computer Config > Admin Templates > Windows Components > Remote Desktop Services.'

        if ($Fix -and $PSCmdlet.ShouldProcess('RDP', 'Enforce NLA and TLS security layer')) {
            try {
                $rdpTcpPath = 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
                Set-ItemProperty -Path $rdpTcpPath -Name 'UserAuthenticationRequired' -Value 1 -Type DWord -Force
                Set-ItemProperty -Path $rdpTcpPath -Name 'SecurityLayer'              -Value 2 -Type DWord -Force
                Set-ItemProperty -Path $rdpTcpPath -Name 'MinEncryptionLevel'         -Value 3 -Type DWord -Force
                Write-Warning 'RDP NLA and TLS security layer enforced.'
            } catch { Write-Warning "Failed to enforce RDP security: $_" }
        }
    }

    # C7 – SNMP default community strings ─────────────────────────────────────
    $snmpIssues = @()
    try {
        $snmpSvc = Get-Service -Name 'SNMP' -ErrorAction SilentlyContinue
        if ($snmpSvc -and $snmpSvc.Status -eq 'Running') {
            # Check SNMP community strings in registry
            $snmpRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities'
            if (Test-Path $snmpRegPath) {
                $communities = Get-ItemProperty -Path $snmpRegPath -ErrorAction SilentlyContinue
                if ($communities) {
                    foreach ($prop in $communities.PSObject.Properties) {
                        if ($prop.Name -imatch 'public|private' -and $prop.Name -notmatch '^PS') {
                            $snmpIssues += "Community:$($prop.Name)(value:$($prop.Value))"
                        }
                    }
                }
            } else {
                $snmpIssues += 'SNMP running but ValidCommunities registry key missing (default community may be accepted)'
            }
        }
    } catch {}

    if ($snmpIssues.Count -eq 0) {
        Add-Finding 'W23-C7' 'SNMP Default Community Strings' 'Critical' 'PASS' `
            'SNMP service not running or no default community strings (public/private) detected' ''
    } else {
        Add-Finding 'W23-C7' 'SNMP Default Community Strings' 'Critical' 'FAIL' `
            ("SNMP issue(s): " + ($snmpIssues -join ', ')) `
            'Change SNMP community strings from public/private to strong random values. Prefer SNMPv3 with authentication and encryption. Restrict SNMP access by IP in SNMP service properties.'
    }

    # C8 – Unquoted service paths ──────────────────────────────────────────────
    $unquotedPaths = @()
    try {
        $services = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue
        foreach ($svc in $services) {
            $path = $svc.PathName
            if ([string]::IsNullOrWhiteSpace($path)) { continue }
            # Skip if already quoted, or if it's a driver/kernel path, or system32 built-ins
            if ($path.StartsWith('"')) { continue }
            if ($path -match '^[A-Z]:\\Windows\\') { continue }
            # Unquoted path with spaces is exploitable
            if ($path -match ' ' -and $path -match '^[A-Za-z]:\\') {
                $unquotedPaths += "$($svc.Name): $path"
            }
        }
    } catch {}

    if ($unquotedPaths.Count -eq 0) {
        Add-Finding 'W23-C8' 'Unquoted Service Paths' 'High' 'PASS' `
            'No unquoted service executable paths with spaces detected' ''
    } else {
        $sample = ($unquotedPaths | Select-Object -First 5) -join ' | '
        Add-Finding 'W23-C8' 'Unquoted Service Paths' 'High' 'FAIL' `
            ("$($unquotedPaths.Count) unquoted path(s) (first 5): $sample") `
            'Wrap service executable paths in double quotes in the registry: HKLM:\SYSTEM\CurrentControlSet\Services\<ServiceName>\ImagePath. Prevents local privilege escalation.'
    }

    # C9 – Pending Windows security updates ────────────────────────────────────
    $pendingUpdates = @()
    try {
        $updateSession  = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $searchResult   = $updateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
        foreach ($update in $searchResult.Updates) {
            if ($update.MsrcSeverity -in @('Critical','Important') -or
                $update.Title -match 'Security Update|Cumulative Update|KB') {
                $pendingUpdates += "$($update.Title.Substring(0, [Math]::Min(80, $update.Title.Length)))"
            }
        }
    } catch {
        # COM object not available (Server Core or restricted environment)
        try {
            $hotfixes = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending
            $lastPatch = $hotfixes | Select-Object -First 1
            if ($lastPatch) {
                $daysSince = ((Get-Date) - [datetime]$lastPatch.InstalledOn).Days
                if ($daysSince -gt 30) {
                    $pendingUpdates += "Last hotfix applied $daysSince days ago ($($lastPatch.HotFixID))"
                }
            } else {
                $pendingUpdates += 'No hotfixes found – patch history unavailable'
            }
        } catch {}
    }

    if ($pendingUpdates.Count -eq 0) {
        Add-Finding 'W23-C9' 'Pending Windows Security Updates' 'Critical' 'PASS' `
            'No pending Critical/Important security updates detected' ''
    } else {
        $sample = ($pendingUpdates | Select-Object -First 5) -join ' | '
        Add-Finding 'W23-C9' 'Pending Windows Security Updates' 'Critical' 'FAIL' `
            ("$($pendingUpdates.Count) pending security update(s) (first 5): $sample") `
            'Apply pending updates: Start > Windows Update > Check for updates. For servers: Install-WindowsUpdate -AcceptAll (PSWindowsUpdate module) or WSUS/SCCM deployment.'
    }

    # C10 – IIS web server security-header hardening ───────────────────────────
    $iisIssues = @()
    try {
        $iisModule = Get-Module -Name WebAdministration -ListAvailable -ErrorAction SilentlyContinue
        if ($iisModule) {
            Import-Module WebAdministration -ErrorAction SilentlyContinue

            $sites = Get-Website -ErrorAction SilentlyContinue
            foreach ($site in $sites) {
                if ($site.State -ne 'Started') { continue }

                # Check custom headers for this site
                $customHeaders = Get-WebConfigurationProperty -PSPath "IIS:\Sites\$($site.Name)" `
                    -Filter 'system.webServer/httpProtocol/customHeaders' `
                    -Name Collection -ErrorAction SilentlyContinue

                $hdrNames = if ($customHeaders) { $customHeaders.name } else { @() }
                $missing  = @()
                if ($hdrNames -notcontains 'Strict-Transport-Security')  { $missing += 'HSTS' }
                if ($hdrNames -notcontains 'X-Content-Type-Options')     { $missing += 'X-Content-Type-Options' }
                if ($hdrNames -notcontains 'X-Frame-Options')            { $missing += 'X-Frame-Options' }
                if ($hdrNames -notcontains 'Content-Security-Policy')    { $missing += 'CSP' }

                # Check if server version header is suppressed
                $removeHeaders = Get-WebConfigurationProperty -PSPath "IIS:\Sites\$($site.Name)" `
                    -Filter 'system.webServer/httpProtocol/customHeaders' `
                    -Name Collection -ErrorAction SilentlyContinue
                # Check global removeServerHeader setting
                try {
                    $requestFiltering = Get-WebConfigurationProperty -PSPath "IIS:\Sites\$($site.Name)" `
                        -Filter 'system.webServer/security/requestFiltering' `
                        -Name 'removeServerHeader' -ErrorAction SilentlyContinue
                    if ($requestFiltering.Value -ne $true) { $missing += 'Server-header-not-removed' }
                } catch { $missing += 'Server-header-check-failed' }

                if ($missing.Count -gt 0) {
                    $iisIssues += "Site '$($site.Name)': missing $($missing -join ', ')"
                }
            }
        }
    } catch {}

    if ($iisIssues.Count -eq 0) {
        Add-Finding 'W23-C10' 'IIS Web Server Security Headers' 'Med' 'PASS' `
            'IIS not installed, no running sites detected, or all sites have required security headers' ''
    } else {
        Add-Finding 'W23-C10' 'IIS Web Server Security Headers' 'Med' 'WARN' `
            ($iisIssues -join '; ') `
            'Add security headers in IIS Manager or web.config: HSTS, X-Content-Type-Options: nosniff, X-Frame-Options: DENY, CSP. Enable removeServerHeader in requestFiltering. Consider using OWASP IIS10 security hardening config.'
    }
}
#endregion

#region ── Execute & output ──────────────────────────────────────────────────────
Invoke-Checks

if ($Json) {
    $scriptName = 'W23_openvas_vuln_scan'
    $output = [ordered]@{
        script    = $scriptName
        host      = $env:COMPUTERNAME
        timestamp = (Get-Date -Format 'o')
        findings  = $script:findings
    }
    $output | ConvertTo-Json -Depth 10
} else {
    Write-Host ''
    Write-Host "=== W23 OpenVAS / Nessus-Style Vulnerability Scanner – $env:COMPUTERNAME ===" -ForegroundColor Cyan
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
