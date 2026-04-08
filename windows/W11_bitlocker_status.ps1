#Requires -Version 5.1
<#
.SYNOPSIS
    W11 – BitLocker Drive Encryption Status (Windows)
.DESCRIPTION
    Checks BitLocker protection status on all fixed drives, TPM availability,
    encryption algorithm strength, and key protector types.
    Read-only by default. Pass -Fix to apply remediation where available.
.NOTES
    ID       : W11
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
    .\W11_bitlocker_status.ps1
    .\W11_bitlocker_status.ps1 -Json
    .\W11_bitlocker_status.ps1 -Fix
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
    # C1 – TPM availability
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        if ($tpm.TpmPresent -and $tpm.TpmReady) {
            Add-Finding 'W11-C1' 'TPM Status' 'Med' 'PASS' "TPM Present=$($tpm.TpmPresent) Ready=$($tpm.TpmReady) Version=$($tpm.ManufacturerVersionFull)" ''
        } elseif ($tpm.TpmPresent -and -not $tpm.TpmReady) {
            Add-Finding 'W11-C1' 'TPM Status' 'Med' 'WARN' "TPM present but not ready (TpmEnabled=$($tpm.TpmEnabled))" `
                'Enable and initialise TPM in firmware (UEFI) settings'
        } else {
            Add-Finding 'W11-C1' 'TPM Status' 'Med' 'WARN' 'No TPM detected' `
                'Install TPM module or use USB key protector for BitLocker'
        }
    } catch {
        Add-Finding 'W11-C1' 'TPM Status' 'Med' 'WARN' "Cannot read TPM: $_" 'Run as administrator'
    }

    # C2 – BitLocker status per volume
    $blVolumes = $null
    $usingWmiFallback = $false
    try {
        # Try modern cmdlet first
        $blVolumes = Get-BitLockerVolume -ErrorAction Stop
    } catch {
        # Fallback: WMI – Win32_EncryptableVolume exposes methods, not properties
        try {
            $blVolumes = Get-WmiObject -Namespace root\CIMv2\Security\MicrosoftVolumeEncryption `
                -Class Win32_EncryptableVolume -ErrorAction Stop
            $usingWmiFallback = $true
        } catch {
            Add-Finding 'W11-C2' 'BitLocker Query' 'High' 'WARN' "Cannot query BitLocker: $_" 'Run as administrator with BitLocker feature installed'
            return
        }
    }

    $idx = 1
    foreach ($vol in $blVolumes) {
        if ($usingWmiFallback) {
            # WMI path: call methods to retrieve protection and conversion status
            $drive = $vol.DriveLetter
            try {
                $protResult = $vol.GetProtectionStatus()
                $protStatus = $protResult.ProtectionStatus  # 0=Off, 1=On, 2=Unknown
            } catch {
                $protStatus = 2
            }
            $protOn = ($protStatus -eq 1)
            if ($protOn) {
                Add-Finding "W11-C2-$idx" "BitLocker: $drive" 'High' 'PASS' `
                    "Drive=$drive Status=On (via WMI)" ''
            } else {
                Add-Finding "W11-C2-$idx" "BitLocker: $drive" 'High' 'FAIL' `
                    "Drive=$drive Status=Off/Unknown (ProtectionStatus=$protStatus, via WMI)" `
                    "Enable BitLocker: Enable-BitLocker -MountPoint ""$drive"" -EncryptionMethod XtsAes256 -TpmProtector"
            }
            # WMI does not expose KeyProtector details as properties; emit INFO
            Add-Finding "W11-C3-$idx" "BitLocker Recovery Key: $drive" 'Med' 'INFO' `
                "Key protector details unavailable via WMI fallback - run on system with RSAT/BitLocker cmdlets for full check" ''
        } else {
            $drive   = if ($vol.MountPoint) { $vol.MountPoint } else { $vol.DriveLetter }
            $encPct  = if ($null -ne $vol.EncryptionPercentage) { $vol.EncryptionPercentage } else { 'N/A' }
            $method  = if ($null -ne $vol.EncryptionMethod) { $vol.EncryptionMethod } else { 'Unknown' }
            $protOn  = ($vol.ProtectionStatus -eq 1) -or ($vol.ProtectionStatus -eq 'On')
            if ($protOn) {
                Add-Finding "W11-C2-$idx" "BitLocker: $drive" 'High' 'PASS' `
                    "Drive=$drive Status=On Encrypted=$encPct% Method=$method" ''
            } else {
                Add-Finding "W11-C2-$idx" "BitLocker: $drive" 'High' 'FAIL' `
                    "Drive=$drive Status=Off/Unknown Encrypted=$encPct%" `
                    "Enable BitLocker: Enable-BitLocker -MountPoint ""$drive"" -EncryptionMethod XtsAes256 -TpmProtector"
            }
            # Check for recovery key protector (only available via Get-BitLockerVolume)
            if ($vol.KeyProtector) {
                $hasRecovery = $vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
                if (-not $hasRecovery) {
                    Add-Finding "W11-C3-$idx" "BitLocker Recovery Key: $drive" 'Med' 'WARN' `
                        "No recovery password protector on $drive" `
                        "Add recovery protector: Add-BitLockerKeyProtector -MountPoint ""$drive"" -RecoveryPasswordProtector"
                }
            }
        }
        $idx++
    }
}

Invoke-Checks

if ($Fix) {
    Write-Warning "⚠  -Fix flag: BitLocker encryption cannot be enabled automatically."
    Write-Host "   Enabling BitLocker requires TPM activation, recovery key backup, and restart." -ForegroundColor Cyan
    Write-Host "   Run: Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -TpmProtector" -ForegroundColor Cyan
}

if ($Json) {
    @{ script='W11_bitlocker_status'; host=$env:COMPUTERNAME; timestamp=(Get-Date -Format 'o'); findings=$script:findings } | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W11 BitLocker Status – $env:COMPUTERNAME ===" -ForegroundColor Cyan
    foreach ($f in $script:findings) { Write-Finding $f }
    $fails = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
    $warns = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
    Write-Host ("`nSummary: {0} finding(s), {1} FAIL, {2} WARN" -f $script:findings.Count, $fails, $warns)
}

$exitCode = 0
if (($script:findings | Where-Object { $_.status -eq 'WARN' }).Count -gt 0) { $exitCode = 1 }
if (($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { $exitCode = 2 }
exit $exitCode
