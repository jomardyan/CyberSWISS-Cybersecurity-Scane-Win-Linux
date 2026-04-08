#Requires -Version 5.1
<#
.SYNOPSIS
    W12 – Secure Boot & TPM State (Windows)
.DESCRIPTION
    Checks Secure Boot status, UEFI firmware type, TPM version, and
    HVCI/VBS (Virtualisation-Based Security) readiness.
    Read-only by default. Pass -Fix to apply remediation where available.
.NOTES
    ID       : W12
    Category : Encryption
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
    .\W12_secure_boot_tpm.ps1
    .\W12_secure_boot_tpm.ps1 -Json
    .\W12_secure_boot_tpm.ps1 -Fix
#>
[CmdletBinding()]
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
    # C1 – Secure Boot status
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($sb) {
            Add-Finding 'W12-C1' 'Secure Boot' 'High' 'PASS' 'Secure Boot is enabled and UEFI firmware confirmed' ''
        } else {
            Add-Finding 'W12-C1' 'Secure Boot' 'High' 'FAIL' 'Secure Boot is DISABLED' `
                'Enable Secure Boot in UEFI/BIOS firmware settings'
        }
    } catch [System.PlatformNotSupportedException] {
        Add-Finding 'W12-C1' 'Secure Boot' 'High' 'WARN' 'Secure Boot not supported (legacy BIOS or VM)' `
            'Migrate to UEFI firmware and enable Secure Boot'
    } catch {
        Add-Finding 'W12-C1' 'Secure Boot' 'High' 'WARN' "Cannot check Secure Boot: $_" ''
    }

    # C2 – Firmware type (UEFI vs BIOS)
    try {
        $env_firm = Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control' 'PEFirmwareType' -ErrorAction Stop
        # 1 = BIOS, 2 = UEFI
        if ($env_firm -eq 2) {
            Add-Finding 'W12-C2' 'Firmware Type' 'Med' 'PASS' 'UEFI firmware detected' ''
        } else {
            Add-Finding 'W12-C2' 'Firmware Type' 'Med' 'FAIL' "Legacy BIOS firmware (PEFirmwareType=$env_firm)" `
                'Upgrade system to UEFI firmware for Secure Boot support'
        }
    } catch {
        Add-Finding 'W12-C2' 'Firmware Type' 'Med' 'WARN' 'Could not determine firmware type' ''
    }

    # C3 – TPM version (require 2.0 for Windows 11 compliance)
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        $tpmVer = $tpm.ManufacturerVersionFull
        if ($tpm.TpmPresent) {
            $specVer = $tpm.SpecVersion
            if ($specVer -match '^2\.') {
                Add-Finding 'W12-C3' 'TPM Version' 'Med' 'PASS' "TPM 2.0 present (SpecVersion=$specVer)" ''
            } else {
                Add-Finding 'W12-C3' 'TPM Version' 'Med' 'WARN' "TPM version $specVer (2.0 recommended)" `
                    'Upgrade TPM firmware to 2.0 if supported, or replace hardware'
            }
        } else {
            Add-Finding 'W12-C3' 'TPM Version' 'Med' 'FAIL' 'No TPM detected' `
                'Install a TPM module or enable fTPM in UEFI settings'
        }
    } catch {
        Add-Finding 'W12-C3' 'TPM Version' 'Med' 'WARN' "Cannot read TPM: $_" ''
    }

    # C4 – VBS (Virtualisation-Based Security) running
    try {
        $vbs = Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' 'EnableVirtualizationBasedSecurity' -ErrorAction Stop
        $vbsRunning = Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' 'VirtualizationBasedSecurityStatus' -ErrorAction SilentlyContinue
        if ($vbs -eq 1 -and $vbsRunning -eq 2) {
            Add-Finding 'W12-C4' 'VBS Running' 'High' 'PASS' 'Virtualisation-Based Security is enabled and running' ''
        } elseif ($vbs -eq 1) {
            Add-Finding 'W12-C4' 'VBS Running' 'High' 'WARN' "VBS enabled but status=$vbsRunning (not confirmed running)" `
                'Verify VBS requirements: UEFI, Secure Boot, TPM 2.0, and CPU virtualisation support'
        } else {
            Add-Finding 'W12-C4' 'VBS Running' 'High' 'WARN' 'VBS is not enabled' `
                'Enable via GPO: Computer Config > Admin Templates > System > Device Guard > Turn On VBS'
        }
    } catch {
        Add-Finding 'W12-C4' 'VBS Running' 'High' 'WARN' 'VBS registry keys not found' `
            'Enable Virtualisation-Based Security via Group Policy'
    }
}

Invoke-Checks

if ($Fix) {
    Write-Warning "⚠  -Fix flag: Secure Boot and TPM configuration require UEFI/firmware settings."
    Write-Host "   These cannot be changed from within the running OS." -ForegroundColor Cyan
}

if ($Json) {
    @{ script='W12_secure_boot_tpm'; host=$env:COMPUTERNAME; timestamp=(Get-Date -Format 'o'); findings=$script:findings } | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W12 Secure Boot & TPM – $env:COMPUTERNAME ===" -ForegroundColor Cyan
    foreach ($f in $script:findings) { Write-Finding $f }
    $fails = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
    $warns = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
    Write-Host ("`nSummary: {0} finding(s), {1} FAIL, {2} WARN" -f $script:findings.Count, $fails, $warns)
}

$exitCode = 0
if (($script:findings | Where-Object { $_.status -eq 'WARN' }).Count -gt 0) { $exitCode = 1 }
if (($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { $exitCode = 2 }
exit $exitCode
