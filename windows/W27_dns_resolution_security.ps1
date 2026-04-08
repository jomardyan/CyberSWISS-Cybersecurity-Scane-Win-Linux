#Requires -Version 5.1
<#
.SYNOPSIS
    W27 - DNS Resolution Security (Windows)
.DESCRIPTION
    Reviews Windows DNS client posture, including resolver selection, LLMNR,
    Smart Multi-Homed Name Resolution, NetBIOS over TCP/IP, DoH readiness, and
    local DNS listener exposure.
    Read-only by default. Pass -Fix to apply limited hardening where safe.
.NOTES
    ID         : W27
    Category   : Network Exposure
    Severity   : High
    OS         : Windows 10/11, Windows Server 2016+
    Admin      : Yes
    Language   : PowerShell 5.1+
    Author     : CyberSWISS Security Team
.PARAMETER Json
    Output results in JSON format for SIEM ingestion.
.PARAMETER Fix
    WARNING: Applies limited DNS client hardening. Off by default. Use with caution.
.EXAMPLE
    .\W27_dns_resolution_security.ps1
    .\W27_dns_resolution_security.ps1 -Json
    .\W27_dns_resolution_security.ps1 -Fix
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Json,
    [switch]$Fix
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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
    param([hashtable]$Finding)
    $color = switch ($Finding.status) {
        'PASS' { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
        default { 'White' }
    }
    Write-Host ("[{0}] [{1}] {2}: {3}" -f $Finding.status, $Finding.severity, $Finding.id, $Finding.name) -ForegroundColor $color
    if ($Finding.detail) {
        Write-Host "       Detail : $($Finding.detail)"
    }
    if ($Finding.status -ne 'PASS' -and $Finding.remediation) {
        Write-Host "       Remedy : $($Finding.remediation)" -ForegroundColor Cyan
    }
}

function Test-KnownPublicDns {
    param([string]$Address)
    $knownPublic = @(
        '1.1.1.1','1.0.0.1','8.8.8.8','8.8.4.4','9.9.9.9','149.112.112.112',
        '208.67.222.222','208.67.220.220','94.140.14.14','94.140.15.15',
        '2606:4700:4700::1111','2606:4700:4700::1001','2001:4860:4860::8888',
        '2001:4860:4860::8844','2620:fe::fe','2620:fe::9'
    )
    return $knownPublic -contains $Address
}

function Get-PolicyValue {
    param([string]$Name)
    $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    return (Get-ItemProperty -Path $policyPath -Name $Name -ErrorAction SilentlyContinue).$Name
}

function Invoke-Checks {
    $dnsAdapters = @()
    try {
        $dnsAdapters = @(
            Get-DnsClientServerAddress -ErrorAction Stop |
                Where-Object { $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0 }
        )
    } catch {
        Add-Finding 'W27-C1' 'DNS Client Configuration' 'High' 'WARN' `
            "Could not query DNS client configuration: $_" `
            'Run as administrator and verify the DnsClient module is available.'
    }

    if ($dnsAdapters.Count -gt 0) {
        $adapterSummary = @(
            $dnsAdapters | ForEach-Object {
                "{0}=[{1}]" -f $_.InterfaceAlias, ($_.ServerAddresses -join ', ')
            }
        )
        Add-Finding 'W27-C1' 'DNS Client Configuration' 'Info' 'INFO' `
            ("Configured DNS servers: " + ($adapterSummary -join ' | ')) ''

        $publicResolvers = [System.Collections.Generic.List[string]]::new()
        foreach ($adapter in $dnsAdapters) {
            foreach ($server in $adapter.ServerAddresses) {
                if (Test-KnownPublicDns -Address $server) {
                    $publicResolvers.Add("{0}:{1}" -f $adapter.InterfaceAlias, $server)
                }
            }
        }

        if ($publicResolvers.Count -gt 0) {
            Add-Finding 'W27-C2' 'Resolver Trust Profile' 'High' 'WARN' `
                ("Known public DNS resolver(s) detected: " + ($publicResolvers -join ' | ')) `
                'Prefer enterprise-managed internal resolvers or an approved encrypted DNS policy instead of ad hoc public resolvers.'
        } else {
            Add-Finding 'W27-C2' 'Resolver Trust Profile' 'High' 'PASS' `
                'No well-known public DNS resolvers were detected on active adapters.' ''
        }
    } else {
        Add-Finding 'W27-C1' 'DNS Client Configuration' 'High' 'WARN' `
            'No active DNS client server configuration was discovered.' `
            'Verify adapter DNS settings and ensure the DNS Client service is functioning normally.'
        Add-Finding 'W27-C2' 'Resolver Trust Profile' 'Info' 'INFO' `
            'Resolver trust profile could not be evaluated because no active DNS servers were discovered.' ''
    }

    $llmnrValue = Get-PolicyValue -Name 'EnableMulticast'
    if ($llmnrValue -eq 0) {
        Add-Finding 'W27-C3' 'LLMNR Policy' 'High' 'PASS' 'LLMNR is disabled by policy (EnableMulticast=0).' ''
    } elseif ($null -eq $llmnrValue) {
        Add-Finding 'W27-C3' 'LLMNR Policy' 'High' 'WARN' `
            'LLMNR is not explicitly disabled by policy.' `
            'Disable LLMNR via Group Policy: Computer Configuration > Administrative Templates > Network > DNS Client > Turn Off Multicast Name Resolution.'
    } else {
        Add-Finding 'W27-C3' 'LLMNR Policy' 'High' 'FAIL' `
            "LLMNR policy is not hardened (EnableMulticast=$llmnrValue)." `
            'Set EnableMulticast=0 under HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient or enforce the Group Policy setting to turn off multicast name resolution.'
    }

    $smartNameValue = Get-PolicyValue -Name 'DisableSmartNameResolution'
    if ($smartNameValue -eq 1) {
        Add-Finding 'W27-C4' 'Smart Multi-Homed Name Resolution' 'Med' 'PASS' `
            'Smart Multi-Homed Name Resolution is disabled by policy.' ''
    } elseif ($null -eq $smartNameValue) {
        Add-Finding 'W27-C4' 'Smart Multi-Homed Name Resolution' 'Med' 'WARN' `
            'Smart Multi-Homed Name Resolution is not explicitly disabled by policy.' `
            'Disable the policy to reduce opportunistic name resolution leakage on multi-homed systems.'
    } else {
        Add-Finding 'W27-C4' 'Smart Multi-Homed Name Resolution' 'Med' 'WARN' `
            "DisableSmartNameResolution=$smartNameValue" `
            'Set DisableSmartNameResolution=1 under HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient.'
    }

    try {
        $netbios = @(
            Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE" -ErrorAction Stop
        )
        $enabledNetbios = @($netbios | Where-Object { $_.TcpipNetbiosOptions -eq 1 })
        $dhcpNetbios = @($netbios | Where-Object { $_.TcpipNetbiosOptions -eq 0 })
        if ($enabledNetbios.Count -gt 0) {
            Add-Finding 'W27-C5' 'NetBIOS over TCP/IP' 'High' 'FAIL' `
                ("NetBIOS over TCP/IP is enabled on: " + (($enabledNetbios | ForEach-Object { $_.Description }) -join ' | ')) `
                'Disable NetBIOS over TCP/IP on active adapters unless a validated legacy dependency still requires it.'
        } elseif ($dhcpNetbios.Count -gt 0) {
            Add-Finding 'W27-C5' 'NetBIOS over TCP/IP' 'Med' 'WARN' `
                ("NetBIOS behavior is DHCP-controlled on: " + (($dhcpNetbios | ForEach-Object { $_.Description }) -join ' | ')) `
                'Prefer explicitly disabling NetBIOS over TCP/IP on adapters that do not require legacy name resolution.'
        } else {
            Add-Finding 'W27-C5' 'NetBIOS over TCP/IP' 'Med' 'PASS' `
                'NetBIOS over TCP/IP is disabled on active adapters.' ''
        }
    } catch {
        Add-Finding 'W27-C5' 'NetBIOS over TCP/IP' 'Med' 'WARN' `
            "Could not query adapter NetBIOS settings: $_" `
            'Review Win32_NetworkAdapterConfiguration.TcpipNetbiosOptions on active adapters.'
    }

    $dohCmd = Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue
    if ($null -eq $dohCmd) {
        Add-Finding 'W27-C6' 'DNS over HTTPS Readiness' 'Info' 'INFO' `
            'Get-DnsClientDohServerAddress is not available on this host.' `
            'If you require encrypted DNS at the endpoint, review DoH support for this Windows build.'
    } else {
        try {
            $dohEntries = @(Get-DnsClientDohServerAddress -ErrorAction Stop)
            if ($dohEntries.Count -gt 0) {
                Add-Finding 'W27-C6' 'DNS over HTTPS Readiness' 'Med' 'PASS' `
                    ("DoH templates configured: " + (($dohEntries | ForEach-Object { $_.ServerAddress }) -join ', ')) ''
            } else {
                Add-Finding 'W27-C6' 'DNS over HTTPS Readiness' 'Med' 'WARN' `
                    'No DoH server templates are configured.' `
                    'If endpoint-encrypted DNS is part of your standard, register approved DoH resolvers and enforce policy accordingly.'
            }
        } catch {
            Add-Finding 'W27-C6' 'DNS over HTTPS Readiness' 'Med' 'WARN' `
                "Could not query DoH settings: $_" `
                'Review DoH configuration with Get-DnsClientDohServerAddress on supported Windows builds.'
        }
    }

    $listenerFindings = [System.Collections.Generic.List[string]]::new()
    try {
        $udp53 = @(Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue)
        foreach ($endpoint in $udp53) {
            if ($endpoint.LocalAddress -notin @('127.0.0.1', '::1')) {
                $listenerFindings.Add("UDP/$($endpoint.LocalAddress):53")
            }
        }
    } catch {}
    try {
        $tcp53 = @(Get-NetTCPConnection -State Listen -LocalPort 53 -ErrorAction SilentlyContinue)
        foreach ($endpoint in $tcp53) {
            if ($endpoint.LocalAddress -notin @('127.0.0.1', '::1')) {
                $listenerFindings.Add("TCP/$($endpoint.LocalAddress):53")
            }
        }
    } catch {}

    if ($listenerFindings.Count -gt 0) {
        Add-Finding 'W27-C7' 'DNS Service Exposure' 'High' 'FAIL' `
            ("Local DNS service exposed beyond loopback: " + ((@($listenerFindings | Sort-Object -Unique | Select-Object -First 10)) -join ' | ')) `
            'Restrict local DNS services to approved interfaces only and firewall port 53 from untrusted networks.'
    } else {
        Add-Finding 'W27-C7' 'DNS Service Exposure' 'Med' 'PASS' `
            'No port 53 listeners exposed beyond loopback were detected.' ''
    }

    if ($Fix) {
        $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
        Write-Warning '--Fix will disable LLMNR and Smart Multi-Homed Name Resolution by policy.'
        if ($PSCmdlet.ShouldProcess('Windows DNS client policy', 'Disable LLMNR and Smart Multi-Homed Name Resolution')) {
            New-Item -Path $policyPath -Force | Out-Null
            New-ItemProperty -Path $policyPath -Name 'EnableMulticast' -PropertyType DWord -Value 0 -Force | Out-Null
            New-ItemProperty -Path $policyPath -Name 'DisableSmartNameResolution' -PropertyType DWord -Value 1 -Force | Out-Null
            Write-Host 'Applied DNS client policy hardening. A reboot or gpupdate may be required for all consumers.' -ForegroundColor Green
        }
    }
}

Invoke-Checks

if ($Json) {
    @{
        script    = 'W27_dns_resolution_security'
        host      = $env:COMPUTERNAME
        timestamp = (Get-Date -Format 'o')
        findings  = $script:findings
    } | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W27 DNS Resolution Security - $env:COMPUTERNAME ===" -ForegroundColor Cyan
    foreach ($finding in $script:findings) {
        Write-Finding $finding
    }
    $fails = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
    $warns = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
    Write-Host ("`nSummary: {0} finding(s), {1} FAIL, {2} WARN" -f $script:findings.Count, $fails, $warns)
}

$exitCode = 0
if (($script:findings | Where-Object { $_.status -eq 'WARN' }).Count -gt 0) { $exitCode = 1 }
if (($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { $exitCode = 2 }
exit $exitCode
