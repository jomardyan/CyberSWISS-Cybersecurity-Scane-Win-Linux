#Requires -Version 5.1
<#
.SYNOPSIS
    W03 – Patch Level & Vulnerable Software Inventory (Windows)
.DESCRIPTION
    Reports installed Windows updates, last update date, and enumerates installed
    software with version numbers. Flags systems that appear unpatched (> 30 days
    since last update). Read-only by default. Pass -Fix to apply remediation where available.
.NOTES
    ID       : W03
    Category : Patch Level & Vulnerable Software
    Severity : Critical
    OS       : Windows 10/11, Server 2016+
    Admin    : Yes (recommended for full WMI access)
    Language : PowerShell 5.1+
    Author   : CyberSWISS Security Team
.PARAMETER Json
    Output results in JSON format.
.PARAMETER SoftwareOnly
    Only enumerate installed software; skip patch checks.
.PARAMETER Fix
    WARNING: Applies remediation where available. Read-only by default. Use with caution.
.EXAMPLE
    .\W03_patch_level.ps1
    .\W03_patch_level.ps1 -Json
    .\W03_patch_level.ps1 -SoftwareOnly
    .\W03_patch_level.ps1 -Fix
#>
[CmdletBinding()]
param(
    [switch]$Json,
    [switch]$SoftwareOnly,
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
    if ($f.status -ne 'PASS' -and $f.status -ne 'INFO' -and $f.remediation) { Write-Host "       Remedy : $($f.remediation)" -ForegroundColor Cyan }
}

function Invoke-Checks {
    # ── Patch checks ─────────────────────────────────────────────────────────
    if (-not $SoftwareOnly) {
        # Last installed update via WMI
        try {
            $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending
            $latest   = $hotfixes | Select-Object -First 1

            if ($null -eq $latest) {
                Add-Finding 'W03-C1' 'Windows Updates Installed' 'Critical' 'WARN' `
                    'No hotfixes found via Get-HotFix' `
                    'Verify Windows Update service is running and check WSUS/WU logs'
            } else {
                $daysSince = if ($latest.InstalledOn) { ([DateTime]::Now - [DateTime]$latest.InstalledOn).Days } else { 999 }
                if ($daysSince -le 30) {
                    Add-Finding 'W03-C1' 'Last Windows Update' 'Critical' 'PASS' `
                        "Last update: $($latest.HotFixID) installed $daysSince day(s) ago" ''
                } elseif ($daysSince -le 60) {
                    Add-Finding 'W03-C1' 'Last Windows Update' 'Critical' 'WARN' `
                        "Last update: $($latest.HotFixID) installed $daysSince day(s) ago (>30)" `
                        'Run Windows Update immediately'
                } else {
                    Add-Finding 'W03-C1' 'Last Windows Update' 'Critical' 'FAIL' `
                        "Last update: $($latest.HotFixID) installed $daysSince day(s) ago (>60)" `
                        'System is critically behind on patches. Apply all pending updates now.'
                }
                Add-Finding 'W03-C2' 'Hotfix Count' 'Info' 'INFO' `
                    "$($hotfixes.Count) hotfixes installed. Latest: $($latest.HotFixID)" ''
            }
        } catch {
            Add-Finding 'W03-C1' 'Windows Updates' 'High' 'WARN' "Error reading updates: $_" 'Ensure WMI/WUA service is running'
        }

        # Check Windows Update service state
        $wuService = Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue
        if ($wuService) {
            $status = if ($wuService.StartType -eq 'Disabled') { 'FAIL' } else { 'PASS' }
            $sev    = if ($status -eq 'FAIL') { 'High' } else { 'Info' }
            Add-Finding 'W03-C3' 'Windows Update Service' $sev $status `
                "StartType=$($wuService.StartType) Status=$($wuService.Status)" `
                'Enable Windows Update service: Set-Service wuauserv -StartupType Automatic'
        }

        # Pending reboot check (registry keys)
        $pendingReboot = $false
        $rebootKeys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        )
        foreach ($key in $rebootKeys) {
            if (Test-Path $key) { $pendingReboot = $true; break }
        }
        if ($pendingReboot) {
            Add-Finding 'W03-C4' 'Pending Reboot' 'Med' 'WARN' 'System has a pending reboot (updates waiting)' 'Reboot the system to complete pending updates'
        } else {
            Add-Finding 'W03-C4' 'Pending Reboot' 'Med' 'PASS' 'No pending reboot detected' ''
        }
    }

    # ── Software Inventory ────────────────────────────────────────────────────
    $regPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $software = foreach ($path in $regPaths) {
        Get-ItemProperty $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher,
                @{ N='InstallDate'; E={ $_.InstallDate } }
    }
    $software = $software | Sort-Object DisplayName -Unique

    Add-Finding 'W03-C5' 'Installed Software Count' 'Info' 'INFO' `
        "$($software.Count) packages found" ''

    # Flag potentially risky known software categories (heuristic only)
    $riskyPatterns = @('TeamViewer','AnyDesk','VNC','RealVNC','TightVNC','UltraVNC',
                       'WinSCP','Putty','FileZilla','Wireshark','Nmap','Metasploit')
    $flagged = $software | Where-Object { $name = $_.DisplayName; $riskyPatterns | Where-Object { $name -ilike "*$_*" } }
    if ($flagged) {
        Add-Finding 'W03-C6' 'Potentially Risky Software Detected' 'Med' 'WARN' `
            ($flagged.DisplayName -join ', ') `
            'Review whether these tools are authorised and required on this endpoint'
    } else {
        Add-Finding 'W03-C6' 'Risky Software Check' 'Med' 'PASS' 'No flagged software categories detected' ''
    }
}

Invoke-Checks

if ($Fix) {
    Write-Warning "⚠  -Fix flag: No automatic Windows Update trigger available without PSWindowsUpdate module."
    Write-Host "   Run: Install-Module PSWindowsUpdate -Force; Get-WUInstall -AcceptAll -AutoReboot" -ForegroundColor Cyan
}

# Build software list for JSON output
$regPaths2 = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$softwareList = foreach ($p in $regPaths2) {
    Get-ItemProperty $p -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName,DisplayVersion,Publisher
}
$softwareList = $softwareList | Sort-Object DisplayName -Unique

if ($Json) {
    @{
        script       = 'W03_patch_level'
        host         = $env:COMPUTERNAME
        timestamp    = (Get-Date -Format 'o')
        findings     = $script:findings
        software     = $softwareList
    } | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W03 Patch Level & Software Inventory – $env:COMPUTERNAME ===" -ForegroundColor Cyan
    foreach ($f in $script:findings) { Write-Finding $f }
    Write-Host "`n--- Installed Software (top 20) ---"
    $softwareList | Select-Object -First 20 | Format-Table -AutoSize
    $fails = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
    $warns = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
    Write-Host ("`nSummary: {0} finding(s), {1} FAIL, {2} WARN" -f $script:findings.Count, $fails, $warns)
}

$exitCode = 0
if (($script:findings | Where-Object { $_.status -eq 'WARN' }).Count -gt 0) { $exitCode = 1 }
if (($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { $exitCode = 2 }
exit $exitCode
