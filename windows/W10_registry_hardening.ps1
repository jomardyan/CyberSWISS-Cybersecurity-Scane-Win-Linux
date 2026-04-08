#Requires -Version 5.1
<#
.SYNOPSIS
    W10 – Registry Permissions & Hardening Check (Windows)
.DESCRIPTION
    Audits critical registry key permissions and hardening settings:
    AutoRun, LSASS protections, NTLMv2, UAC, and other CIS-recommended
    registry values. Read-only by default. Pass -Fix to apply remediation where available.
.NOTES
    ID       : W10
    Category : File/Registry Permissions & Hardening
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
    .\W10_registry_hardening.ps1
    .\W10_registry_hardening.ps1 -Json
    .\W10_registry_hardening.ps1 -Fix
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

function Check-RegistryValue {
    param(
        [string]$Id,
        [string]$Name,
        [string]$Severity,
        [string]$KeyPath,
        [string]$ValueName,
        $ExpectedValue,
        [string]$Description,
        [string]$Remediation
    )
    try {
        $val = Get-ItemPropertyValue -Path $KeyPath -Name $ValueName -ErrorAction Stop
        if ($val -eq $ExpectedValue) {
            Add-Finding $Id $Name $Severity 'PASS' "$Description = $val (expected: $ExpectedValue)" ''
        } else {
            Add-Finding $Id $Name $Severity 'FAIL' "$Description = $val (expected: $ExpectedValue)" $Remediation
        }
    } catch [System.Management.Automation.ItemNotFoundException],
            [System.Management.Automation.PSArgumentException] {
        # Key/value does not exist – treat as misconfigured
        Add-Finding $Id $Name $Severity 'WARN' "$($Description): key/value not found (registry default may apply)" $Remediation
    } catch {
        Add-Finding $Id $Name $Severity 'WARN' "Error reading ${KeyPath}\${ValueName}: $_" ''
    }
}

function Invoke-Checks {
    # C1 – AutoRun disabled
    Check-RegistryValue 'W10-C1' 'AutoRun Disabled' 'High' `
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' `
        255 'NoDriveTypeAutoRun (255=all disabled)' `
        'Set: reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f'

    # C2 – LSASS RunAsPPL (Credential Guard prerequisite)
    Check-RegistryValue 'W10-C2' 'LSASS RunAsPPL' 'High' `
        'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' `
        1 'RunAsPPL (1=Protected Process Light)' `
        'Enable: reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f (requires reboot)'

    # C3 – NTLMv2 only (LmCompatibilityLevel >= 5)
    try {
        $lmLevel = Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' -ErrorAction Stop
        if ($lmLevel -ge 5) {
            Add-Finding 'W10-C3' 'NTLMv2 Only' 'High' 'PASS' "LmCompatibilityLevel=$lmLevel (>= 5, NTLMv2 only)" ''
        } else {
            Add-Finding 'W10-C3' 'NTLMv2 Only' 'High' 'FAIL' "LmCompatibilityLevel=$lmLevel (< 5, weak NTLM allowed)" `
                'Set: reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f'
        }
    } catch {
        Add-Finding 'W10-C3' 'NTLMv2 Only' 'High' 'WARN' 'LmCompatibilityLevel not set (default allows weak NTLM)' `
            'Set LmCompatibilityLevel=5 in HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    }

    # C4 – UAC enabled
    Check-RegistryValue 'W10-C4' 'UAC Enabled' 'High' `
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' `
        1 'EnableLUA (1=UAC enabled)' `
        'Enable UAC: reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f'

    # C5 – UAC Prompt for Admin (ConsentPromptBehaviorAdmin >= 1)
    try {
        $uacBehavior = Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' -ErrorAction Stop
        if ($uacBehavior -ge 1) {
            Add-Finding 'W10-C5' 'UAC Admin Prompt' 'Med' 'PASS' "ConsentPromptBehaviorAdmin=$uacBehavior (prompts for consent)" ''
        } else {
            Add-Finding 'W10-C5' 'UAC Admin Prompt' 'Med' 'FAIL' "ConsentPromptBehaviorAdmin=0 (auto-elevate, no prompt)" `
                'Set to 1 or 2: reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f'
        }
    } catch {
        Add-Finding 'W10-C5' 'UAC Admin Prompt' 'Med' 'WARN' 'ConsentPromptBehaviorAdmin not set' ''
    }

    # C6 – WDigest plaintext password caching disabled
    Check-RegistryValue 'W10-C6' 'WDigest Plaintext Caching' 'Critical' `
        'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' `
        0 'UseLogonCredential (0=disabled, credentials not cached in plaintext)' `
        'Disable: reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f'

    # C7 – Windows Script Host disabled (optional, flag if enabled without justification)
    try {
        $wshEnabled = Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' 'Enabled' -ErrorAction Stop
        if ($wshEnabled -eq 0) {
            Add-Finding 'W10-C7' 'Windows Script Host' 'Low' 'PASS' 'WSH is disabled' ''
        } else {
            Add-Finding 'W10-C7' 'Windows Script Host' 'Low' 'INFO' "WSH is enabled (Enabled=$wshEnabled)" `
                'Consider disabling WSH on endpoints that do not require script execution'
        }
    } catch {
        Add-Finding 'W10-C7' 'Windows Script Host' 'Low' 'INFO' 'WSH setting not found (default=enabled)' `
            'Consider disabling: reg add "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /v Enabled /t REG_DWORD /d 0 /f'
    }

    # C8 – Credential Guard enabled (DeviceGuard)
    try {
        $cgRunning = Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Running' -ErrorAction Stop
        if ($cgRunning -eq 1) {
            Add-Finding 'W10-C8' 'Credential Guard' 'High' 'PASS' 'Credential Guard / HVCI is running' ''
        } else {
            Add-Finding 'W10-C8' 'Credential Guard' 'High' 'WARN' "Credential Guard Running=$cgRunning" `
                'Enable Credential Guard via Device Guard settings or Group Policy'
        }
    } catch {
        Add-Finding 'W10-C8' 'Credential Guard' 'High' 'WARN' 'Credential Guard not detected (key absent)' `
            'Enable Credential Guard on supported hardware via Group Policy'
    }
}

Invoke-Checks

if ($Fix) {
    Write-Warning "⚠  -Fix flag detected. About to apply registry hardening values."
    Write-Warning "   Press Ctrl+C within 10 seconds to abort."
    Start-Sleep 10
    if ($PSCmdlet.ShouldProcess('registry', 'Apply CIS hardening values')) {
        # Disable AutoRun/AutoPlay
        $explorerPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        New-Item -Path $explorerPath -Force -ErrorAction SilentlyContinue | Out-Null
        if (Set-ItemProperty -Path $explorerPath -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord -Force -PassThru -ErrorAction SilentlyContinue) {
            Write-Host "AutoRun disabled." -ForegroundColor Green
        } else { Write-Warning "Failed to set NoDriveTypeAutoRun." }
        # Enable NTLMv2
        $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        if (Set-ItemProperty -Path $lsaPath -Name 'LmCompatibilityLevel' -Value 5 -Type DWord -Force -PassThru -ErrorAction SilentlyContinue) {
            Write-Host "NTLMv2 enforced (LmCompatibilityLevel=5)." -ForegroundColor Green
        } else { Write-Warning "Failed to set LmCompatibilityLevel." }
        # Enable LSASS protection
        if (Set-ItemProperty -Path $lsaPath -Name 'RunAsPPL' -Value 1 -Type DWord -Force -PassThru -ErrorAction SilentlyContinue) {
            Write-Host "LSASS RunAsPPL enabled." -ForegroundColor Green
        } else { Write-Warning "Failed to set RunAsPPL." }
    }
}

if ($Json) {
    @{ script='W10_registry_hardening'; host=$env:COMPUTERNAME; timestamp=(Get-Date -Format 'o'); findings=$script:findings } | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W10 Registry Hardening – $env:COMPUTERNAME ===" -ForegroundColor Cyan
    foreach ($f in $script:findings) { Write-Finding $f }
    $fails = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
    $warns = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
    Write-Host ("`nSummary: {0} finding(s), {1} FAIL, {2} WARN" -f $script:findings.Count, $fails, $warns)
}

$exitCode = 0
if (($script:findings | Where-Object { $_.status -eq 'WARN' }).Count -gt 0) { $exitCode = 1 }
if (($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { $exitCode = 2 }
exit $exitCode
