#Requires -Version 5.1
<#
.SYNOPSIS
    W32 – USB & Removable Media Control (Windows)
.DESCRIPTION
    Audits Windows endpoint for USB and removable media security controls:
    device installation policy, AutoRun/AutoPlay configuration, removable
    storage access policies, recent USB device history, and BitLocker
    enforcement for removable drives (BitLocker To Go).
.NOTES
    ID       : W32
    Category : Endpoint Controls
    Severity : High
    OS       : Windows 10/11, Server 2016+
    Admin    : Yes
    Language : PowerShell 5.1+
    Author   : CyberSWISS Security Team
.PARAMETER Json
    Output results in JSON format.
.PARAMETER Fix
    Apply automated remediation where safe.
.EXAMPLE
    .\W32_usb_media_control.ps1
    .\W32_usb_media_control.ps1 -Json
    .\W32_usb_media_control.ps1 -Fix
#>
[CmdletBinding()]
param(
    [switch]$Json,
    [switch]$Fix
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

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

function Get-RegProp {
    param([string]$Path, [string]$Name)
    try { (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

function Invoke-Checks {

    # C1 – AutoRun disabled for all drives
    $autoRunPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    $noAutoRun   = Get-RegProp $autoRunPath 'NoDriveTypeAutoRun'
    # 0xFF (255) = disable for all drive types including removable
    if ($noAutoRun -ne 255 -and $noAutoRun -ne 0xFF) {
        Add-Finding 'W32-C1' 'AutoRun Not Fully Disabled' 'High' 'FAIL' \
            "NoDriveTypeAutoRun=$noAutoRun (expected 255/0xFF to disable for all drives)" \
            'Disable: reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f'
    } else {
        Add-Finding 'W32-C1' 'AutoRun Disabled for All Drives' 'High' 'PASS' \
            "NoDriveTypeAutoRun=$noAutoRun – AutoRun disabled for all drive types" ''
    }

    # C2 – AutoPlay disabled
    $autoPlayPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers'
    $disableAutoPlay = Get-RegProp $autoPlayPath 'DisableAutoplay'
    $autoPlayGpo     = Get-RegProp 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutoplayfornonVolume'
    if ($disableAutoPlay -ne 1 -and -not $autoPlayGpo) {
        Add-Finding 'W32-C2' 'AutoPlay Not Disabled' 'Med' 'WARN' \
            'AutoPlay is not fully disabled. AutoPlay can be exploited for drive-by execution from removable media.' \
            'Disable via GP: Computer Configuration > Admin Templates > Windows Components > AutoPlay Policies > Turn off AutoPlay'
    } else {
        Add-Finding 'W32-C2' 'AutoPlay Disabled' 'Med' 'PASS' \
            'AutoPlay is disabled (user policy or GPO)' ''
    }

    # C3 – USB storage device access policy
    $usbStorPath    = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices'
    $usbDenyRead    = Get-RegProp $usbStorPath 'Deny_Read'
    $usbDenyWrite   = $null
    if (Test-Path "$usbStorPath\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}") {
        $usbDenyWrite = Get-RegProp "$usbStorPath\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}" 'Deny_Write'
    }

    if (-not $usbDenyRead -and -not $usbDenyWrite) {
        Add-Finding 'W32-C3' 'No Removable Storage Access Restriction' 'High' 'WARN' \
            'No GPO restriction on removable storage read/write access detected' \
            'Configure via GP: Computer Configuration > Admin Templates > System > Removable Storage Access > Deny read/write access to removable disks'
    } elseif ($usbDenyWrite -eq 1) {
        Add-Finding 'W32-C3' 'Removable Storage Write Denied' 'High' 'PASS' \
            "Removable storage write access is denied via policy (Deny_Write=1)" ''
    } else {
        Add-Finding 'W32-C3' 'Removable Storage Policy (Partial)' 'Med' 'WARN' \
            'Some removable storage restrictions are configured but write access may still be permitted' \
            'Review GP: System > Removable Storage Access – enable both Deny_Read and Deny_Write for USB drives'
    }

    # C4 – Recent USB device connections (from registry)
    $usbDevPath = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
    $recentUsb = @()
    if (Test-Path $usbDevPath) {
        Get-ChildItem $usbDevPath -ErrorAction SilentlyContinue | ForEach-Object {
            $devClass = $_.PSChildName
            Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
                $friendlyName = Get-RegProp $_.PSPath 'FriendlyName'
                if ($friendlyName) { $recentUsb += $friendlyName }
            }
        }
    }
    if ($recentUsb.Count -gt 0) {
        Add-Finding 'W32-C4' 'USB Storage Devices in Registry History' 'Med' 'WARN' \
            "$($recentUsb.Count) USB storage device(s) connected historically: $($recentUsb[0..4] -join ' | ')" \
            'Review device history. Unexpected devices may indicate policy bypass or data exfiltration.'
    } else {
        Add-Finding 'W32-C4' 'USB Device History' 'Med' 'PASS' \
            'No USB storage device records found in registry' ''
    }

    # C5 – BitLocker To Go for removable drives
    $bitlockerRemov = Get-RegProp 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' 'RDVDenyWriteAccess'
    $rdvRequire     = Get-RegProp 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' 'RDVEncryptionType'
    if ($bitlockerRemov -eq 1) {
        Add-Finding 'W32-C5' 'BitLocker To Go Required for Removable Drives' 'High' 'PASS' \
            'RDVDenyWriteAccess=1: unencrypted removable drives cannot be written to' ''
    } else {
        Add-Finding 'W32-C5' 'BitLocker To Go Not Enforced' 'High' 'WARN' \
            'Unencrypted removable drives can be freely written to. Data may be exfiltrated or malware introduced via USB.' \
            'Enable via GP: Computer Configuration > Admin Templates > Windows Components > BitLocker Drive Encryption > Removable Data Drives > Deny write access'
    }

    # C6 – Windows Portable Device (WPD) restriction
    $wpdClass = '{eec5ad98-8080-425f-922a-dabf3de3f69a}'
    $wpdPath  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\$wpdClass"
    $wpdDeny  = Get-RegProp $wpdPath 'Deny_Write'
    if ($wpdDeny -ne 1) {
        Add-Finding 'W32-C6' 'WPD (Phone/Camera) Write Access Not Restricted' 'Med' 'WARN' \
            'Windows Portable Devices (smartphones, cameras) write access is not restricted' \
            'Configure via GP: System > Removable Storage Access > Windows Portable Devices – deny write access'
    } else {
        Add-Finding 'W32-C6' 'WPD Write Access Restricted' 'Med' 'PASS' \
            'Windows Portable Device write access is denied via policy' ''
    }
}

Invoke-Checks

# ── Optional Fix ──────────────────────────────────────────────────────────────
if ($Fix) {
    Write-Host "`n[FIX] Applying USB/removable media hardening..." -ForegroundColor Cyan

    # Disable AutoRun
    $noAutoRun = Get-RegProp 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
    if ($noAutoRun -ne 255) {
        If (-not (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer')) {
            New-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Force | Out-Null
        }
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255 -Type DWord -Force
        Write-Host "[FIX] AutoRun disabled for all drive types (NoDriveTypeAutoRun=255)." -ForegroundColor Green
    }
}

# ── Output ────────────────────────────────────────────────────────────────────
if ($Json) {
    @{ script='W32_usb_media_control'; host=$env:COMPUTERNAME; timestamp=(Get-Date -Format 'o'); findings=$script:findings } | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W32 $([char]0x2013) USB & Removable Media Control $([char]0x2013) $env:COMPUTERNAME ===" -ForegroundColor Cyan
    foreach ($f in $script:findings) { Write-Finding $f }
    $fails = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
    $warns = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
    Write-Host ("`nSummary: {0} finding(s), {1} FAIL, {2} WARN" -f $script:findings.Count, $fails, $warns)
}

$exitCode = 0
if (($script:findings | Where-Object { $_.status -eq 'WARN' }).Count -gt 0) { $exitCode = 1 }
if (($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { $exitCode = 2 }
exit $exitCode
