#Requires -Version 5.1
<#
.SYNOPSIS
    W06 – Windows Firewall State Check
.DESCRIPTION
    Verifies Windows Defender Firewall is enabled on all profiles (Domain,
    Private, Public), checks default inbound/outbound actions, and reviews
    any inbound allow rules that expose high-risk services.
    Read-only by default. Pass -Fix to apply remediation where available.
.NOTES
    ID       : W06
    Category : Network Exposure
    Severity : High
    OS       : Windows 10/11, Server 2016+
    Admin    : Yes
    Language : PowerShell 5.1+
    Author   : CyberSWISS Security Team
.PARAMETER Json
    Output results in JSON format.
.PARAMETER Fix
    WARNING: Applies remediation where available. Read-only by default. Use with caution.
.EXAMPLE
    .\W06_firewall_state.ps1
    .\W06_firewall_state.ps1 -Json
    .\W06_firewall_state.ps1 -Fix
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
    param([string]$Id,[string]$Name,[string]$Severity,[string]$Status,[string]$Detail,[string]$Remediation)
    $script:findings.Add(@{ id=$Id; name=$Name; severity=$Severity; status=$Status; detail=$Detail; remediation=$Remediation; timestamp=(Get-Date -Format 'o') })
}
function Write-Finding {
    param([hashtable]$f)
    $color = switch ($f.status) { 'PASS'{'Green'} 'WARN'{'Yellow'} 'FAIL'{'Red'} 'INFO'{'Cyan'} default{'White'} }
    Write-Host ("[{0}] [{1}] {2}: {3}" -f $f.status,$f.severity,$f.id,$f.name) -ForegroundColor $color
    if ($f.detail)      { Write-Host "       Detail : $($f.detail)" }
    if ($f.status -notin 'PASS','INFO' -and $f.remediation) { Write-Host "       Remedy : $($f.remediation)" -ForegroundColor Cyan }
}

function Invoke-Checks {
    # C1 – Firewall profile state
    $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    if (-not $profiles) {
        Add-Finding 'W06-C1' 'Firewall Profiles' 'Critical' 'WARN' `
            'Could not retrieve firewall profiles (requires admin or RSAT)' `
            'Run as administrator or check Windows Defender Firewall service'
        return
    }

    foreach ($profile in $profiles) {
        if ($profile.Enabled) {
            Add-Finding "W06-C1-$($profile.Name)" "Firewall Profile Enabled: $($profile.Name)" 'High' 'PASS' `
                "$($profile.Name) profile is enabled" ''
        } else {
            Add-Finding "W06-C1-$($profile.Name)" "Firewall Profile Disabled: $($profile.Name)" 'High' 'FAIL' `
                "$($profile.Name) profile is DISABLED" `
                "Enable firewall: Set-NetFirewallProfile -Profile $($profile.Name) -Enabled True"
        }

        # Default inbound action should be Block
        if ($profile.DefaultInboundAction -eq 'Block') {
            Add-Finding "W06-C2-$($profile.Name)" "Default Inbound Block: $($profile.Name)" 'High' 'PASS' `
                "DefaultInboundAction=Block on $($profile.Name)" ''
        } else {
            Add-Finding "W06-C2-$($profile.Name)" "Default Inbound Allow: $($profile.Name)" 'High' 'FAIL' `
                "DefaultInboundAction=$($profile.DefaultInboundAction) on $($profile.Name)" `
                "Set: Set-NetFirewallProfile -Profile $($profile.Name) -DefaultInboundAction Block"
        }
    }

    # C3 – Rules allowing inbound connections on risky ports
    $riskyPorts = @(21,23,135,137,138,139,445,3389,5985,5986)
    $inboundAllowRules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue
    $riskyRules = [System.Collections.Generic.List[string]]::new()

    foreach ($rule in $inboundAllowRules) {
        $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
        if ($portFilter) {
            $rawPort = $portFilter.LocalPort
            # 'Any' means all ports; otherwise parse discrete ports and ranges
            $matchedPorts = @()
            if ($rawPort -eq 'Any') {
                $matchedPorts = $riskyPorts
            } else {
                foreach ($segment in ($rawPort -split ',')) {
                    $segment = $segment.Trim()
                    if ($segment -match '^(\d+)-(\d+)$') {
                        $lo = [int]$Matches[1]; $hi = [int]$Matches[2]
                        if ($lo -le $hi) {
                            $matchedPorts += $riskyPorts | Where-Object { $_ -ge $lo -and $_ -le $hi }
                        }
                    } elseif ($segment -match '^\d+$') {
                        $p = [int]$segment
                        if ($riskyPorts -contains $p) { $matchedPorts += $p }
                    }
                }
            }
            foreach ($mp in ($matchedPorts | Select-Object -Unique)) {
                $riskyRules.Add("Rule='$($rule.DisplayName)' Port=$mp")
            }
        }
    }

    if ($riskyRules.Count -gt 0) {
        Add-Finding 'W06-C3' 'Inbound Rules Allowing Risky Ports' 'Med' 'WARN' `
            ($riskyRules | Select-Object -First 10 | Out-String).Trim() `
            'Review each rule and restrict to specific source IPs or disable if not required'
    } else {
        Add-Finding 'W06-C3' 'Inbound Rules Allowing Risky Ports' 'Med' 'PASS' `
            'No inbound allow rules for well-known risky ports' ''
    }

    # C4 – Total inbound allow rules count
    $totalAllow = ($inboundAllowRules | Measure-Object).Count
    Add-Finding 'W06-C4' 'Inbound Allow Rules Count' 'Info' 'INFO' "$totalAllow enabled inbound allow rules" ''
}

Invoke-Checks

if ($Fix) {
    Write-Warning "⚠  -Fix flag detected. About to enable Windows Defender Firewall on all profiles."
    Write-Warning "   Press Ctrl+C within 10 seconds to abort."
    Start-Sleep 10
    if ($PSCmdlet.ShouldProcess('Windows Firewall', 'Enable on all profiles')) {
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
        Write-Host "Windows Defender Firewall enabled on all profiles." -ForegroundColor Green
    }
}

if ($Json) {
    @{ script='W06_firewall_state'; host=$env:COMPUTERNAME; timestamp=(Get-Date -Format 'o'); findings=$script:findings } | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W06 Firewall State – $env:COMPUTERNAME ===" -ForegroundColor Cyan
    foreach ($f in $script:findings) { Write-Finding $f }
    $fails = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
    $warns = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
    Write-Host ("`nSummary: {0} finding(s), {1} FAIL, {2} WARN" -f $script:findings.Count, $fails, $warns)
}

$exitCode = 0
if (($script:findings | Where-Object { $_.status -eq 'WARN' }).Count -gt 0) { $exitCode = 1 }
if (($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { $exitCode = 2 }
exit $exitCode
