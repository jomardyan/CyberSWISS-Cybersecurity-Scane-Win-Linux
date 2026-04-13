#Requires -Version 5.1
<#
.SYNOPSIS
    W29 – Local Privilege Escalation Posture (Windows)
.DESCRIPTION
    Audits the local endpoint for privilege escalation paths: unquoted service
    paths, weak service permissions, writable PATH directories, AlwaysInstallElevated,
    token privilege abuse, UAC bypass-prone configurations, and weak auto-logon.
.NOTES
    ID       : W29
    Category : Privilege Escalation
    Severity : Critical
    OS       : Windows 10/11, Server 2016+
    Admin    : Yes
    Language : PowerShell 5.1+
    Author   : CyberSWISS Security Team
.PARAMETER Json
    Output results in JSON format.
.PARAMETER Fix
    Apply automated remediation where available (safe fixes only).
.EXAMPLE
    .\W29_privesc_posture.ps1
    .\W29_privesc_posture.ps1 -Json
    .\W29_privesc_posture.ps1 -Fix
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

    # C1 – Unquoted service paths
    $unquotedServices = @()
    try {
        Get-WmiObject Win32_Service -ErrorAction Stop | ForEach-Object {
            $path = $_.PathName
            if ($path -and $path -notmatch '^"' -and $path -match '\s' -and $path -notmatch '^[A-Za-z]:\\Windows\\') {
                $unquotedServices += "$($_.Name): $path"
            }
        }
        if ($unquotedServices.Count -gt 0) {
            Add-Finding 'W29-C1' 'Unquoted Service Paths' 'Critical' 'FAIL' \
                "$($unquotedServices.Count) service(s) with unquoted paths: $($unquotedServices[0..2] -join ' | ')" \
                'Quote each service path: Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\<svc>" -Name ImagePath -Value ''"<path>"'''
        } else {
            Add-Finding 'W29-C1' 'Unquoted Service Paths' 'Critical' 'PASS' \
                'No unquoted service paths found' ''
        }
    } catch {
        Add-Finding 'W29-C1' 'Unquoted Service Paths' 'Critical' 'WARN' "Could not enumerate services: $_" 'Run as administrator'
    }

    # C2 – Writable service binaries
    $writableSvcBins = @()
    try {
        Get-WmiObject Win32_Service -ErrorAction Stop | ForEach-Object {
            $path = $_.PathName -replace '"','' -replace '\s+-.+',''
            $exe = ($path -split ' ')[0]
            if ($exe -and (Test-Path $exe -ErrorAction SilentlyContinue)) {
                $acl = Get-Acl $exe -ErrorAction SilentlyContinue
                if ($acl) {
                    $writableAce = $acl.Access | Where-Object {
                        $_.FileSystemRights -match 'Write|FullControl|Modify' -and
                        $_.AccessControlType -eq 'Allow' -and
                        $_.IdentityReference -notmatch 'TrustedInstaller|SYSTEM|Administrators|NT SERVICE'
                    }
                    if ($writableAce) { $writableSvcBins += $exe }
                }
            }
        }
        if ($writableSvcBins.Count -gt 0) {
            Add-Finding 'W29-C2' 'Writable Service Binaries' 'Critical' 'FAIL' \
                "$($writableSvcBins.Count) writable service binary(ies): $($writableSvcBins[0..2] -join ' | ')" \
                'Fix ACLs: icacls "<path>" /inheritance:d /remove:g "Users" /remove:g "Everyone"'
        } else {
            Add-Finding 'W29-C2' 'Writable Service Binaries' 'Critical' 'PASS' \
                'No writable service binaries found for non-admin users' ''
        }
    } catch {
        Add-Finding 'W29-C2' 'Writable Service Binaries' 'High' 'WARN' "Partial check: $_" 'Run as administrator for full coverage'
    }

    # C3 – AlwaysInstallElevated (MSI privesc)
    $aie32 = Get-RegProp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
    $aie64 = Get-RegProp 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
    if ($aie32 -eq 1 -and $aie64 -eq 1) {
        Add-Finding 'W29-C3' 'AlwaysInstallElevated Enabled' 'Critical' 'FAIL' \
            'Both HKLM and HKCU AlwaysInstallElevated = 1. Any user can install MSI with SYSTEM privileges.' \
            'Set both to 0: reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /t REG_DWORD /d 0 /f'
    } else {
        Add-Finding 'W29-C3' 'AlwaysInstallElevated' 'Critical' 'PASS' \
            'AlwaysInstallElevated is disabled or not configured' ''
    }

    # C4 – Writable directories in system PATH
    $writablePathDirs = @()
    $env:PATH -split ';' | Where-Object { $_ -ne '' } | ForEach-Object {
        $d = $_
        if (Test-Path $d -ErrorAction SilentlyContinue) {
            $acl = Get-Acl $d -ErrorAction SilentlyContinue
            if ($acl) {
                $w = $acl.Access | Where-Object {
                    $_.FileSystemRights -match 'Write|FullControl|Modify' -and
                    $_.AccessControlType -eq 'Allow' -and
                    $_.IdentityReference -match 'Users|Everyone|Authenticated Users'
                }
                if ($w) { $writablePathDirs += $d }
            }
        }
    }
    if ($writablePathDirs.Count -gt 0) {
        Add-Finding 'W29-C4' 'Writable Dirs in System PATH' 'Critical' 'FAIL' \
            "PATH hijack risk – writable by low-priv users: $($writablePathDirs[0..2] -join ' | ')" \
            'Remove write permissions from these PATH directories for unprivileged users.'
    } else {
        Add-Finding 'W29-C4' 'Writable Dirs in System PATH' 'Critical' 'PASS' \
            'No user-writable directories found in system PATH' ''
    }

    # C5 – UAC configuration
    $enableLUA     = Get-RegProp 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
    $consentPrompt = Get-RegProp 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin'

    if ($enableLUA -ne 1) {
        Add-Finding 'W29-C5' 'UAC Disabled' 'Critical' 'FAIL' \
            'EnableLUA = 0: UAC is fully disabled. Privilege separation does not exist.' \
            'Enable UAC: reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f'
    } elseif ($consentPrompt -eq 0) {
        Add-Finding 'W29-C5' 'UAC Auto-Elevate Without Prompt' 'High' 'FAIL' \
            'ConsentPromptBehaviorAdmin = 0: admin operations auto-elevate without any UAC prompt' \
            'Set to 2 (prompt on secure desktop): reg add HKLM\...\System /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f'
    } else {
        Add-Finding 'W29-C5' 'UAC Configuration' 'High' 'PASS' \
            "UAC enabled (EnableLUA=$enableLUA, ConsentPrompt=$consentPrompt)" ''
    }

    # C6 – Auto-logon credentials in registry
    $autoAdminLogon = Get-RegProp 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon'
    if ($autoAdminLogon -eq '1') {
        $alUser = Get-RegProp 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultUserName'
        $alPass = if (Get-RegProp 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultPassword') { '(password set)' } else { '(no password)' }
        Add-Finding 'W29-C6' 'Auto-Logon Enabled' 'Critical' 'FAIL' \
            "AutoAdminLogon=1, user=$alUser, password=$alPass – credentials stored in registry in cleartext" \
            'Disable auto-logon: reg add "HKLM:\...\Winlogon" /v AutoAdminLogon /d 0 /f and clear DefaultPassword'
    } else {
        Add-Finding 'W29-C6' 'Auto-Logon Credentials' 'Critical' 'PASS' \
            'AutoAdminLogon is disabled or not configured' ''
    }

    # C7 – SeImpersonatePrivilege held by non-service accounts
    try {
        $whoamiPriv = whoami /priv 2>$null
        if ($whoamiPriv -match 'SeImpersonatePrivilege\s+\S+\s+Enabled') {
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            if ($currentUser -notmatch 'SYSTEM|NetworkService|LocalService|IIS') {
                Add-Finding 'W29-C7' 'SeImpersonatePrivilege (JuicyPotato)' 'Critical' 'WARN' \
                    "Current process holds SeImpersonatePrivilege as $currentUser – potato-style privesc possible" \
                    'Restrict SeImpersonatePrivilege to SYSTEM and service accounts only via Group Policy.'
            } else {
                Add-Finding 'W29-C7' 'SeImpersonatePrivilege' 'High' 'INFO' \
                    "SeImpersonatePrivilege held by service account $currentUser (expected)" ''
            }
        } else {
            Add-Finding 'W29-C7' 'SeImpersonatePrivilege' 'High' 'PASS' \
                'Current process does not hold SeImpersonatePrivilege' ''
        }
    } catch {
        Add-Finding 'W29-C7' 'SeImpersonatePrivilege' 'High' 'INFO' "Could not check token privileges: $_" ''
    }
}

Invoke-Checks

# ── Optional Fix ──────────────────────────────────────────────────────────────
if ($Fix) {
    Write-Host "`n[FIX] Applying safe automated remediations..." -ForegroundColor Cyan
    # Fix AlwaysInstallElevated
    $aie = Get-RegProp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
    if ($aie -eq 1) {
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -Value 0 -Type DWord -Force
        Set-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -Value 0 -Type DWord -Force
        Write-Host "[FIX] AlwaysInstallElevated disabled." -ForegroundColor Green
    }
    # Enable UAC if disabled
    $lua = Get-RegProp 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
    if ($lua -eq 0) {
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1 -Type DWord -Force
        Write-Host "[FIX] UAC (EnableLUA) re-enabled." -ForegroundColor Green
    }
}

# ── Output ────────────────────────────────────────────────────────────────────
if ($Json) {
    @{ script='W29_privesc_posture'; host=$env:COMPUTERNAME; timestamp=(Get-Date -Format 'o'); findings=$script:findings } | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W29 $([char]0x2013) Local Privilege Escalation Posture $([char]0x2013) $env:COMPUTERNAME ===" -ForegroundColor Cyan
    foreach ($f in $script:findings) { Write-Finding $f }
    $fails = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
    $warns = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
    Write-Host ("`nSummary: {0} finding(s), {1} FAIL, {2} WARN" -f $script:findings.Count, $fails, $warns)
}

$exitCode = 0
if (($script:findings | Where-Object { $_.status -eq 'WARN' }).Count -gt 0) { $exitCode = 1 }
if (($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { $exitCode = 2 }
exit $exitCode
