#Requires -Version 5.1
<#
.SYNOPSIS
    W13 – Windows Defender / EDR Presence Check
.DESCRIPTION
    Non-invasive audit of Windows Defender state (real-time protection,
    signature age, exclusions) and detection of common EDR agent processes.
    Read-only by default. Pass -Fix to apply remediation where available.
.NOTES
    ID       : W13
    Category : Malware Protections / EDR
    Severity : Critical
    OS       : Windows 10/11, Server 2016+
    Admin    : Yes (recommended for full Defender status)
    Language : PowerShell 5.1+
    Author   : CyberSWISS Security Team
.PARAMETER Json
    Output results in JSON format.
.PARAMETER Fix
    WARNING: Applies remediation where available. Read-only by default. Use with caution.
.EXAMPLE
    .\W13_defender_edr.ps1
    .\W13_defender_edr.ps1 -Json
    .\W13_defender_edr.ps1 -Fix
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

# Known EDR/AV agent process names (non-exhaustive signal list)
$knownEdrProcesses = @(
    @{ Process='MsMpEng';         Product='Windows Defender'       },
    @{ Process='SentinelAgent';   Product='SentinelOne'            },
    @{ Process='CSFalconService'; Product='CrowdStrike Falcon'     },
    @{ Process='cb';              Product='Carbon Black'           },
    @{ Process='CylanceSvc';      Product='Cylance PROTECT'        },
    @{ Process='mcshield';        Product='McAfee/Trellix'         },
    @{ Process='savservice';      Product='Sophos'                 },
    @{ Process='bdagent';         Product='Bitdefender GravityZone' },
    @{ Process='ds_agent';        Product='Trend Micro Deep Security'},
    @{ Process='xagt';            Product='FireEye/Trellix HX'    },
    @{ Process='elastic-endpoint';Product='Elastic Security'      }
)

function Invoke-Checks {
    # C1 – Defender real-time protection
    try {
        $defStatus = Get-MpComputerStatus -ErrorAction Stop
        if ($defStatus.RealTimeProtectionEnabled) {
            Add-Finding 'W13-C1' 'Defender Real-Time Protection' 'Critical' 'PASS' 'Real-time protection is enabled' ''
        } else {
            Add-Finding 'W13-C1' 'Defender Real-Time Protection' 'Critical' 'FAIL' 'Real-time protection is DISABLED' `
                'Enable: Set-MpPreference -DisableRealtimeMonitoring $false'
        }

        # C2 – Signature age
        $sigAge = ([DateTime]::Now - $defStatus.AntivirusSignatureLastUpdated).Days
        if ($sigAge -le 1) {
            Add-Finding 'W13-C2' 'Defender Signature Age' 'High' 'PASS' "Signatures updated $sigAge day(s) ago" ''
        } elseif ($sigAge -le 3) {
            Add-Finding 'W13-C2' 'Defender Signature Age' 'High' 'WARN' "Signatures $sigAge days old (last: $($defStatus.AntivirusSignatureLastUpdated))" `
                'Update: Update-MpSignature'
        } else {
            Add-Finding 'W13-C2' 'Defender Signature Age' 'High' 'FAIL' "Signatures $sigAge days old – critically stale" `
                'Update immediately: Update-MpSignature'
        }

        # C3 – Tamper protection
        if ($defStatus.IsTamperProtected) {
            Add-Finding 'W13-C3' 'Defender Tamper Protection' 'High' 'PASS' 'Tamper protection is enabled' ''
        } else {
            Add-Finding 'W13-C3' 'Defender Tamper Protection' 'High' 'WARN' 'Tamper protection is not enabled' `
                'Enable via Windows Security > Virus & threat protection > Manage settings'
        }

        # C4 – Exclusions (flag if any exist)
        $excl = Get-MpPreference -ErrorAction SilentlyContinue | Select-Object ExclusionPath,ExclusionExtension,ExclusionProcess
        $exclCount = ($excl.ExclusionPath.Count + $excl.ExclusionExtension.Count + $excl.ExclusionProcess.Count)
        if ($exclCount -gt 0) {
            Add-Finding 'W13-C4' 'Defender Exclusions' 'Med' 'WARN' `
                "$exclCount exclusion(s) defined – review for abuse" `
                'Audit: Get-MpPreference | Select ExclusionPath,ExclusionExtension,ExclusionProcess'
        } else {
            Add-Finding 'W13-C4' 'Defender Exclusions' 'Med' 'PASS' 'No Defender exclusions configured' ''
        }
    } catch {
        Add-Finding 'W13-C1' 'Windows Defender Status' 'Critical' 'WARN' `
            "Cannot query Defender: $_ (may indicate Defender is disabled or replaced)" `
            'Ensure Windows Defender or a third-party AV/EDR is active'
    }

    # C5 – EDR process detection
    $runningProcs = Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
    $detectedEDR = [System.Collections.Generic.List[string]]::new()
    foreach ($edr in $knownEdrProcesses) {
        if ($runningProcs -contains $edr.Process) {
            $detectedEDR.Add($edr.Product)
        }
    }

    if ($detectedEDR.Count -gt 0) {
        Add-Finding 'W13-C5' 'EDR Agent Detected' 'Info' 'PASS' "Detected: $($detectedEDR -join ', ')" ''
    } else {
        Add-Finding 'W13-C5' 'EDR Agent Detected' 'High' 'WARN' 'No known EDR agent process detected' `
            'Verify an EDR/AV solution is installed and running on this endpoint'
    }

    # C6 – Windows Defender service state
    $defSvc = Get-Service -Name 'WinDefend' -ErrorAction SilentlyContinue
    if ($defSvc) {
        if ($defSvc.Status -eq 'Running') {
            Add-Finding 'W13-C6' 'WinDefend Service' 'High' 'PASS' 'WinDefend service is running' ''
        } else {
            Add-Finding 'W13-C6' 'WinDefend Service' 'High' 'FAIL' "WinDefend service status: $($defSvc.Status)" `
                'Start service: Start-Service WinDefend'
        }
    }
}

Invoke-Checks

if ($Fix) {
    Write-Warning "⚠  -Fix flag detected. About to enable Windows Defender real-time protection."
    Write-Warning "   Press Ctrl+C within 10 seconds to abort."
    Start-Sleep 10
    if ($PSCmdlet.ShouldProcess('Windows Defender', 'Enable real-time protection')) {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Write-Host "Windows Defender real-time protection enabled." -ForegroundColor Green
    }
}

if ($Json) {
    @{ script='W13_defender_edr'; host=$env:COMPUTERNAME; timestamp=(Get-Date -Format 'o'); findings=$script:findings } | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W13 Defender & EDR – $env:COMPUTERNAME ===" -ForegroundColor Cyan
    foreach ($f in $script:findings) { Write-Finding $f }
    $fails = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
    $warns = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
    Write-Host ("`nSummary: {0} finding(s), {1} FAIL, {2} WARN" -f $script:findings.Count, $fails, $warns)
}

$exitCode = 0
if (($script:findings | Where-Object { $_.status -eq 'WARN' }).Count -gt 0) { $exitCode = 1 }
if (($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { $exitCode = 2 }
exit $exitCode
