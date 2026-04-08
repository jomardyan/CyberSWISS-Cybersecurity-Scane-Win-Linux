#Requires -Version 5.1
<#
.SYNOPSIS
    W15 – CIS Baseline Hardening Checks (Windows)
.DESCRIPTION
    Performs a selection of CIS-inspired (without copying proprietary text)
    hardening checks covering remote access, PowerShell logging,
    Windows features, and miscellaneous security settings.
    Read-only by default. Pass -Fix to apply remediation where available.
.NOTES
    ID       : W15
    Category : Baseline Hardening
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
    .\W15_cis_baseline.ps1
    .\W15_cis_baseline.ps1 -Json
    .\W15_cis_baseline.ps1 -Fix
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

function CheckReg {
    param([string]$Id,[string]$Name,[string]$Severity,[string]$Key,[string]$Val,$Expected,[string]$Desc,[string]$Fix)
    try {
        $v = Get-ItemPropertyValue $Key $Val -ErrorAction Stop
        if ($v -eq $Expected) {
            Add-Finding $Id $Name $Severity 'PASS' "$Desc = $v" ''
        } else {
            Add-Finding $Id $Name $Severity 'FAIL' "$Desc = $v (expected $Expected)" $Fix
        }
    } catch {
        Add-Finding $Id $Name $Severity 'WARN' "$($Desc): not set (key absent)" $Fix
    }
}

function Invoke-Checks {
    # C1 – PowerShell Script Block Logging
    CheckReg 'W15-C1' 'PS Script Block Logging' 'High' `
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
        'EnableScriptBlockLogging' 1 'EnableScriptBlockLogging' `
        'Enable: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f'

    # C2 – PowerShell Transcription (Module Logging)
    CheckReg 'W15-C2' 'PS Module Logging' 'Med' `
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' `
        'EnableModuleLogging' 1 'EnableModuleLogging' `
        'Enable: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f'

    # C3 – Constrained Language Mode indicator
    $clm = $ExecutionContext.SessionState.LanguageMode
    if ($clm -eq 'ConstrainedLanguage') {
        Add-Finding 'W15-C3' 'PowerShell Language Mode' 'Med' 'PASS' "LanguageMode=$clm" ''
    } else {
        Add-Finding 'W15-C3' 'PowerShell Language Mode' 'Med' 'INFO' "LanguageMode=$clm (ConstrainedLanguage recommended for endpoints)" `
            'Enforce via WDAC policy or AppLocker'
    }

    # C4 – RDP NLA enforced
    CheckReg 'W15-C4' 'RDP NLA Required' 'High' `
        'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
        'UserAuthentication' 1 'UserAuthentication (1=NLA required)' `
        'Enable NLA: reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f'

    # C5 – RDP encryption level = High (3)
    CheckReg 'W15-C5' 'RDP Encryption Level' 'High' `
        'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
        'MinEncryptionLevel' 3 'MinEncryptionLevel (3=High)' `
        'Set: reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MinEncryptionLevel /t REG_DWORD /d 3 /f'

    # C6 – Anonymous SID/Name translation disabled
    CheckReg 'W15-C6' 'Anonymous SID Translation' 'Med' `
        'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        'AnonymousNameLookup' 0 'AnonymousNameLookup (0=disabled)' `
        'Disable: reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v AnonymousNameLookup /t REG_DWORD /d 0 /f'

    # C7 – Anonymous enumeration of SAM accounts disabled
    CheckReg 'W15-C7' 'Anonymous SAM Enumeration' 'High' `
        'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        'RestrictAnonymousSAM' 1 'RestrictAnonymousSAM (1=disabled)' `
        'Disable: reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f'

    # C8 – Anonymous access to named pipes/shares disabled
    CheckReg 'W15-C8' 'Anonymous Network Access' 'High' `
        'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        'RestrictAnonymous' 1 'RestrictAnonymous (1=restricted)' `
        'Set: reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f'

    # C9 – Safe DLL Search Mode
    CheckReg 'W15-C9' 'Safe DLL Search Mode' 'High' `
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
        'SafeDllSearchMode' 1 'SafeDllSearchMode (1=enabled)' `
        'Enable: reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v SafeDllSearchMode /t REG_DWORD /d 1 /f'

    # C10 – Windows Installer Always Install Elevated
    CheckReg 'W15-C10' 'Installer Elevated Install' 'High' `
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' `
        'AlwaysInstallElevated' 0 'AlwaysInstallElevated (0=disabled)' `
        'Disable: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f'

    # C11 – SMBv1 server feature status (belt-and-suspenders with W07)
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction Stop
        if ($feature.State -eq 'Disabled') {
            Add-Finding 'W15-C11' 'SMB1Protocol Feature' 'Critical' 'PASS' 'SMB1Protocol Windows feature is Disabled' ''
        } else {
            Add-Finding 'W15-C11' 'SMB1Protocol Feature' 'Critical' 'FAIL' "SMB1Protocol feature state: $($feature.State)" `
                'Disable: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart'
        }
    } catch {
        Add-Finding 'W15-C11' 'SMB1Protocol Feature' 'Critical' 'WARN' "Cannot query feature state: $_" 'Run as administrator'
    }

    # C12 – Autoplay/AutoRun for removable media
    CheckReg 'W15-C12' 'AutoPlay Disabled' 'Med' `
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' `
        'NoAutoplayfornonVolume' 1 'NoAutoplayfornonVolume (1=disabled for non-volume)' `
        'Disable via GPO: Computer Config > Admin Templates > Windows Components > AutoPlay Policies'
}

Invoke-Checks

if ($Fix) {
    Write-Warning "⚠  -Fix flag detected. About to apply CIS baseline registry settings."
    Write-Warning "   Press Ctrl+C within 10 seconds to abort."
    Start-Sleep 10
    if ($PSCmdlet.ShouldProcess('registry', 'Apply CIS baseline settings')) {
        # Enable PowerShell ScriptBlock Logging
        $psLogPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        New-Item -Path $psLogPath -Force -ErrorAction SilentlyContinue | Out-Null
        if (Set-ItemProperty -Path $psLogPath -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord -Force -PassThru -ErrorAction SilentlyContinue) {
            Write-Host "PowerShell ScriptBlock Logging enabled." -ForegroundColor Green
        } else { Write-Warning "Failed to enable ScriptBlock Logging." }
        # Enable PowerShell Module Logging
        $psModPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
        New-Item -Path $psModPath -Force -ErrorAction SilentlyContinue | Out-Null
        if (Set-ItemProperty -Path $psModPath -Name 'EnableModuleLogging' -Value 1 -Type DWord -Force -PassThru -ErrorAction SilentlyContinue) {
            Write-Host "PowerShell Module Logging enabled." -ForegroundColor Green
        } else { Write-Warning "Failed to enable Module Logging." }
    }
}

if ($Json) {
    @{ script='W15_cis_baseline'; host=$env:COMPUTERNAME; timestamp=(Get-Date -Format 'o'); findings=$script:findings } | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W15 CIS Baseline Hardening – $env:COMPUTERNAME ===" -ForegroundColor Cyan
    foreach ($f in $script:findings) { Write-Finding $f }
    $fails = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
    $warns = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
    Write-Host ("`nSummary: {0} finding(s), {1} FAIL, {2} WARN" -f $script:findings.Count, $fails, $warns)
}

$exitCode = 0
if (($script:findings | Where-Object { $_.status -eq 'WARN' }).Count -gt 0) { $exitCode = 1 }
if (($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { $exitCode = 2 }
exit $exitCode
