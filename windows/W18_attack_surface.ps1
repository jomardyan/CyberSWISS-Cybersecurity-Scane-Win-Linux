#Requires -Version 5.1
<#
.SYNOPSIS
    W18 – Attack Surface Management (Windows)
.DESCRIPTION
    Identifies Windows attack surface: internet-facing services, unnecessary
    Windows features, exposed file shares, RDP/SMB/WinRM exposure, and
    Windows Defender Attack Surface Reduction (ASR) rule status.
    Read-only by default. Pass -Fix to apply remediation where available.
.NOTES
    ID         : W18
    Category   : Attack Surface Management
    Severity   : High
    OS         : Windows 10/11, Server 2016+
    Admin      : Yes
    Language   : PowerShell 5.1+
    Author     : CyberSWISS Security Team
.PARAMETER Json
    Output results in JSON format for SIEM ingestion.
.PARAMETER Fix
    WARNING: Applies recommended baseline values. Off by default. Use with caution.
.EXAMPLE
    .\W18_attack_surface.ps1
    .\W18_attack_surface.ps1 -Json
    .\W18_attack_surface.ps1 -Fix
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

    # C1 – Windows features attack surface
    $riskyFeatures = @('TelnetClient','TelnetServer','TFTP','SMB1Protocol','LegacyComponents','DirectPlay','WindowsMediaPlayer')
    $enabledRisky  = [System.Collections.Generic.List[string]]::new()
    try {
        # Try Get-WindowsOptionalFeature first (client OS), fall back to Get-WindowsFeature (server)
        $features = Get-WindowsOptionalFeature -Online -ErrorAction Stop
        foreach ($feat in $features) {
            if ($riskyFeatures -contains $feat.FeatureName -and $feat.State -eq 'Enabled') {
                $enabledRisky.Add($feat.FeatureName)
            }
        }
    } catch {
        try {
            $features = Get-WindowsFeature -ErrorAction Stop
            foreach ($feat in $features) {
                if ($riskyFeatures -contains $feat.Name -and $feat.Installed) {
                    $enabledRisky.Add($feat.Name)
                }
            }
        } catch {
            Add-Finding 'W18-C1' 'Windows Features Attack Surface' 'High' 'WARN' `
                'Could not enumerate Windows features. Run as administrator.' `
                'Run: Get-WindowsOptionalFeature -Online | Where-Object State -eq Enabled'
            return
        }
    }
    if ($enabledRisky.Count -gt 0) {
        Add-Finding 'W18-C1' 'Windows Features Attack Surface' 'High' 'FAIL' `
            "Risky features enabled: $($enabledRisky -join ', ')" `
            'Disable with: Disable-WindowsOptionalFeature -Online -FeatureName <name> -NoRestart'
    } else {
        Add-Finding 'W18-C1' 'Windows Features Attack Surface' 'High' 'PASS' `
            'No high-risk optional Windows features are enabled.' ''
    }

    # C2 – Exposed file shares
    try {
        $shares     = Get-SmbShare -ErrorAction Stop
        $shareIssues = [System.Collections.Generic.List[string]]::new()
        foreach ($share in $shares) {
            try {
                $acl = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
                $everyoneAccess = $acl | Where-Object { $_.AccountName -match 'Everyone|EVERYONE' }
                if ($everyoneAccess -and $share.Name -in @('ADMIN$','C$','D$')) {
                    $shareIssues.Add("$($share.Name): accessible by Everyone")
                } elseif ($everyoneAccess -and $share.Name -notin @('ADMIN$','C$','IPC$')) {
                    $shareIssues.Add("$($share.Name): non-default share accessible by Everyone")
                }
            } catch {}
        }
        if ($shareIssues.Count -gt 0) {
            Add-Finding 'W18-C2' 'File Share Exposure' 'High' 'FAIL' `
                ($shareIssues -join ' | ') `
                'Remove Everyone access from shares. Use specific AD groups. Disable default admin shares if not required.'
        } else {
            Add-Finding 'W18-C2' 'File Share Exposure' 'High' 'PASS' `
                "Reviewed $($shares.Count) share(s); no Everyone-accessible shares detected." ''
        }
    } catch {
        Add-Finding 'W18-C2' 'File Share Exposure' 'High' 'WARN' `
            "Could not enumerate SMB shares: $_" 'Run as administrator.'
    }

    # C3 – Remote Desktop status and NLA enforcement
    try {
        $rdpDeny = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' `
            -Name 'fDenyTSConnections' -ErrorAction Stop).fDenyTSConnections
        if ($rdpDeny -eq 1) {
            Add-Finding 'W18-C3' 'Remote Desktop (RDP)' 'High' 'PASS' 'RDP is disabled.' ''
        } else {
            $nla = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
                -Name 'UserAuthentication' -ErrorAction SilentlyContinue).UserAuthentication
            if ($nla -eq 1) {
                Add-Finding 'W18-C3' 'Remote Desktop (RDP)' 'Med' 'WARN' `
                    'RDP is enabled with NLA enforced. Ensure RDP is firewalled to trusted networks only.' `
                    'Restrict RDP access via firewall rules. Consider using VPN + RDP or Windows Admin Center.'
            } else {
                Add-Finding 'W18-C3' 'Remote Desktop (RDP)' 'High' 'FAIL' `
                    'RDP is enabled WITHOUT Network Level Authentication (NLA).' `
                    'Enable NLA: Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" UserAuthentication 1'
            }
        }
    } catch {
        Add-Finding 'W18-C3' 'Remote Desktop (RDP)' 'High' 'WARN' `
            "Could not read RDP registry settings: $_" 'Run as administrator.'
    }

    # C4 – ASR (Attack Surface Reduction) rules
    $asrPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
    $osVer   = [System.Environment]::OSVersion.Version
    if ($osVer.Major -ge 10) {
        if (Test-Path $asrPath) {
            $asrRules = Get-ItemProperty $asrPath -ErrorAction SilentlyContinue
            $ruleCount = ($asrRules.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }).Count
            if ($ruleCount -gt 0) {
                Add-Finding 'W18-C4' 'ASR Rules' 'High' 'PASS' `
                    "$ruleCount ASR rule(s) configured via policy." ''
            } else {
                Add-Finding 'W18-C4' 'ASR Rules' 'High' 'WARN' `
                    'ASR registry path exists but no rules are configured.' `
                    'Configure ASR rules via GPO or Intune. Recommended: enable at minimum Block Office macro rules and credential theft rules.'
            }
        } else {
            Add-Finding 'W18-C4' 'ASR Rules' 'High' 'WARN' `
                'No ASR rules configured on this Windows 10/11 system.' `
                'Enable ASR rules via GPO: Computer Config > Admin Templates > Windows Defender Exploit Guard > Attack Surface Reduction.'
        }
    } else {
        Add-Finding 'W18-C4' 'ASR Rules' 'Info' 'INFO' `
            'ASR rules require Windows 10/11 or Server 2019+. Current OS version may not support ASR.' ''
    }

    # C5 – Open inbound firewall rules for risky ports
    $riskyPorts = @(23, 21, 3389)
    $riskySmbPort = 445
    $fwIssues   = [System.Collections.Generic.List[string]]::new()
    try {
        $inboundRules = Get-NetFirewallRule -Direction Inbound -Action Allow -ErrorAction Stop |
            Where-Object { $_.Enabled -eq 'True' }
        foreach ($rule in $inboundRules) {
            $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
            if ($null -eq $portFilter) { continue }
            $ports = $portFilter.LocalPort
            foreach ($rPort in $riskyPorts) {
                if ($ports -contains $rPort -or $ports -contains [string]$rPort) {
                    $addrFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                    $remote = if ($addrFilter) { $addrFilter.RemoteAddress } else { 'Any' }
                    $fwIssues.Add("Port $rPort open (Rule: $($rule.DisplayName), Remote: $($remote -join ','))")
                }
            }
        }
        if ($fwIssues.Count -gt 0) {
            Add-Finding 'W18-C5' 'Risky Inbound Firewall Rules' 'High' 'WARN' `
                ($fwIssues[0..4] -join ' | ') `
                'Restrict or remove firewall rules for Telnet (23), FTP (21), RDP (3389) to trusted source IPs only.'
        } else {
            Add-Finding 'W18-C5' 'Risky Inbound Firewall Rules' 'High' 'PASS' `
                'No broadly-open inbound rules for Telnet, FTP, or RDP detected.' ''
        }
    } catch {
        Add-Finding 'W18-C5' 'Risky Inbound Firewall Rules' 'High' 'WARN' `
            "Could not enumerate firewall rules: $_" 'Run as administrator.'
    }

    # C6 – WinRM access
    try {
        $listeners = @(Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate -ErrorAction Stop)
        if ($listeners.Count -eq 0) {
            Add-Finding 'W18-C6' 'WinRM Listener Security' 'Med' 'PASS' 'WinRM has no configured listeners.' ''
        } else {
            $httpListeners  = $listeners | Where-Object { $_.Transport -eq 'HTTP' }
            $httpsListeners = $listeners | Where-Object { $_.Transport -eq 'HTTPS' }
            if ($httpListeners -and -not $httpsListeners) {
                Add-Finding 'W18-C6' 'WinRM Listener Security' 'High' 'FAIL' `
                    'WinRM listener configured with HTTP only (no HTTPS).' `
                    'Configure HTTPS listener: winrm create winrm/config/listener?Address=*+Transport=HTTPS @{CertificateThumbprint="<thumbprint>"}'
            } elseif ($httpListeners -and $httpsListeners) {
                Add-Finding 'W18-C6' 'WinRM Listener Security' 'Med' 'WARN' `
                    'WinRM has both HTTP and HTTPS listeners. Remove HTTP listener.' `
                    'Remove HTTP listener: winrm delete winrm/config/listener?Address=*+Transport=HTTP'
            } else {
                Add-Finding 'W18-C6' 'WinRM Listener Security' 'Med' 'PASS' 'WinRM configured with HTTPS only.' ''
            }
        }
    } catch {
        Add-Finding 'W18-C6' 'WinRM Listener Security' 'Med' 'INFO' `
            'WinRM service not running or not configured.' ''
    }

    # C7 – Unnecessary services running (attack surface)
    $unnecessaryServices = @(
        @{ Name = 'Fax';            Display = 'Fax Service' }
        @{ Name = 'TlntSvr';        Display = 'Telnet Server' }
        @{ Name = 'MSFTPSVC';       Display = 'IIS FTP Service' }
        @{ Name = 'RemoteRegistry'; Display = 'Remote Registry' }
        @{ Name = 'WMPNetworkSvc';  Display = 'Windows Media Player Network Sharing' }
    )
    $runningUnnecessary = [System.Collections.Generic.List[string]]::new()
    foreach ($svc in $unnecessaryServices) {
        $s = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if ($s -and $s.Status -eq 'Running') { $runningUnnecessary.Add($svc.Display) }
    }
    if ($runningUnnecessary.Count -gt 0) {
        Add-Finding 'W18-C7' 'Unnecessary Services Running' 'Med' 'WARN' `
            "Unnecessary/risky services running: $($runningUnnecessary -join ', ')" `
            'Stop and disable: Stop-Service <name> -Force; Set-Service <name> -StartupType Disabled'
    } else {
        Add-Finding 'W18-C7' 'Unnecessary Services Running' 'Med' 'PASS' `
            'No unnecessary high-risk services (Fax, Telnet, FTP, RemoteRegistry, WMP Network) running.' ''
    }
}
#endregion

#region ── Output ────────────────────────────────────────────────────────────────
Invoke-Checks

if ($Fix) {
    Write-Warning "⚠  -Fix flag detected: Disabling attack surface features."
    Write-Warning "   Press Ctrl+C within 10 seconds to abort."
    Start-Sleep 10
    if ($PSCmdlet.ShouldProcess('Windows features and services', 'Reduce attack surface')) {
        # Disable TelnetClient if enabled
        $telnet = Get-WindowsOptionalFeature -Online -FeatureName 'TelnetClient' -ErrorAction SilentlyContinue
        if ($telnet -and $telnet.State -eq 'Enabled') {
            Disable-WindowsOptionalFeature -Online -FeatureName 'TelnetClient' -NoRestart -ErrorAction SilentlyContinue
            Write-Host 'TelnetClient feature disabled.' -ForegroundColor Green
        }
        # Disable RemoteRegistry
        $rrSvc = Get-Service -Name RemoteRegistry -ErrorAction SilentlyContinue
        if ($rrSvc -and $rrSvc.Status -eq 'Running') {
            Stop-Service -Name RemoteRegistry -Force -ErrorAction SilentlyContinue
            Set-Service  -Name RemoteRegistry -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Host 'RemoteRegistry stopped and disabled.' -ForegroundColor Green
        }
    }
}

if ($Json) {
    $result = @{
        script    = 'W18_attack_surface'
        host      = $env:COMPUTERNAME
        timestamp = (Get-Date -Format 'o')
        findings  = $script:findings
    }
    $result | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W18 Attack Surface Management – $env:COMPUTERNAME ===" -ForegroundColor Cyan
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
