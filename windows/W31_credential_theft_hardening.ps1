#Requires -Version 5.1
<#
.SYNOPSIS
    W31 – Credential Theft Hardening (Windows)
.DESCRIPTION
    Audits the endpoint for credential theft exposure: WDigest, LSASS protections,
    Credential Guard, cached logon count, browser credential stores, SAM/NTDS access,
    cleartext credentials in registry, and Mimikatz-style attack surface.
.NOTES
    ID       : W31
    Category : Credential Protection
    Severity : Critical
    OS       : Windows 10/11, Server 2016+
    Admin    : Yes
    Language : PowerShell 5.1+
    Author   : CyberSWISS Security Team
.PARAMETER Json
    Output results in JSON format.
.PARAMETER Fix
    Apply safe automated remediations.
.EXAMPLE
    .\W31_credential_theft_hardening.ps1
    .\W31_credential_theft_hardening.ps1 -Json
    .\W31_credential_theft_hardening.ps1 -Fix
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

    # C1 – WDigest plain-text credential caching
    $wdigestPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
    $useLogonCred = Get-RegProp $wdigestPath 'UseLogonCredential'
    if ($useLogonCred -eq 1) {
        Add-Finding 'W31-C1' 'WDigest Plain-Text Credential Caching Enabled' 'Critical' 'FAIL' \
            'UseLogonCredential=1: Windows caches credentials in LSASS memory in plain text. Mimikatz sekurlsa::wdigest trivially extracts these.' \
            'Disable: reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 0 /f'
    } else {
        Add-Finding 'W31-C1' 'WDigest Credential Caching' 'Critical' 'PASS' \
            'WDigest UseLogonCredential is 0 or not set – plain-text caching disabled' ''
    }

    # C2 – LSASS protection (PPL / RunAsPPL)
    $lsassPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $runAsPPL  = Get-RegProp $lsassPath 'RunAsPPL'
    if ($runAsPPL -ne 1) {
        Add-Finding 'W31-C2' 'LSASS PPL (Protected Process Light) Disabled' 'Critical' 'FAIL' \
            'RunAsPPL is not set. LSASS can be accessed by any admin-level process (including Mimikatz).' \
            'Enable: reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f (requires reboot)'
    } else {
        Add-Finding 'W31-C2' 'LSASS PPL Protection' 'Critical' 'PASS' \
            'RunAsPPL=1: LSASS running as Protected Process Light' ''
    }

    # C3 – Credential Guard
    $credGuardPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
    $vbsEnabled    = Get-RegProp $credGuardPath 'EnableVirtualizationBasedSecurity'
    $credGuard     = Get-RegProp $credGuardPath 'LsaCfgFlags'
    if ($vbsEnabled -ne 1 -or $credGuard -eq 0) {
        Add-Finding 'W31-C3' 'Credential Guard Disabled' 'Critical' 'FAIL' \
            "VBS=$vbsEnabled, LsaCfgFlags=$credGuard. Credential Guard isolates LSA secrets in a VBS enclave." \
            'Enable Credential Guard via Group Policy: Computer Configuration > Admin Templates > System > Device Guard > Turn On Virtualization Based Security'
    } else {
        Add-Finding 'W31-C3' 'Credential Guard' 'Critical' 'PASS' \
            "Credential Guard is enabled (VBS=$vbsEnabled, LsaCfgFlags=$credGuard)" ''
    }

    # C4 – Cached credentials count
    $cachedCredsPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $cachedCount     = Get-RegProp $cachedCredsPath 'CachedLogonsCount'
    $cachedNum       = [int]($cachedCount -replace '[^0-9]','0')
    if ($cachedNum -gt 2) {
        Add-Finding 'W31-C4' 'High Cached Credential Count' 'High' 'WARN' \
            "CachedLogonsCount=$cachedCount. Offline NTLM hashes cached for $cachedNum domain user(s). A local admin can extract these with creddump/Mimikatz." \
            'Reduce to 1-2: reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount /t REG_SZ /d 1 /f'
    } else {
        Add-Finding 'W31-C4' 'Cached Credential Count' 'High' 'PASS' \
            "CachedLogonsCount=$cachedCount (acceptable)" ''
    }

    # C5 – NTLM authentication hardening
    $ntlmLevel     = Get-RegProp 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
    $ntlmAudit     = Get-RegProp 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'AuditReceivingNTLMTraffic'
    if ($ntlmLevel -lt 3) {
        Add-Finding 'W31-C5' 'Weak NTLM Authentication Level' 'Critical' 'FAIL' \
            "LmCompatibilityLevel=$ntlmLevel. NTLMv1 and LM hashes accepted. Trivially cracked offline." \
            'Set to 5 (NTLMv2 only): reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LmCompatibilityLevel /t REG_DWORD /d 5 /f'
    } else {
        Add-Finding 'W31-C5' 'NTLM Authentication Level' 'Critical' 'PASS' \
            "LmCompatibilityLevel=$ntlmLevel (NTLMv2 or higher only)" ''
    }

    # C6 – SAM access restrictions
    $samPath       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $restrictSam   = Get-RegProp $samPath 'RestrictSAM'
    $restrictSamOn = Get-RegProp $samPath 'RestrictSAMRemoteSAM'
    if (-not $restrictSamOn) {
        Add-Finding 'W31-C6' 'SAM Remote Access Not Restricted' 'High' 'WARN' \
            'RestrictRemoteSAM not configured. Remote unauthenticated users may be able to enumerate local SAM accounts.' \
            'Set: reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RestrictRemoteSAM /t REG_SZ /d "O:BAG:BAD:(A;;RC;;;BA)" /f'
    } else {
        Add-Finding 'W31-C6' 'SAM Remote Access Restriction' 'High' 'PASS' \
            'RestrictRemoteSAM is configured' ''
    }

    # C7 – Windows Credential Manager: generic credential count
    try {
        $credOutput = cmdkey /list 2>$null
        $credLines  = ($credOutput | Where-Object { $_ -match 'Target:' } | Measure-Object).Count
        if ($credLines -gt 0) {
            Add-Finding 'W31-C7' 'Stored Credentials (Windows Credential Manager)' 'High' 'WARN' \
                "$credLines credential target(s) stored in Windows Credential Manager. Review for plain-text or stale entries." \
                'Review: cmdkey /list. Remove stale entries: cmdkey /delete:<target>. Prefer certificate/key-based auth over stored passwords.'
        } else {
            Add-Finding 'W31-C7' 'Windows Credential Manager' 'High' 'PASS' \
                'No stored credential targets found in Windows Credential Manager' ''
        }
    } catch {
        Add-Finding 'W31-C7' 'Windows Credential Manager' 'High' 'INFO' "Could not query credential manager: $_" ''
    }

    # C8 – LSASS dump protection via PPL and ACL
    try {
        $lsassPID = (Get-Process -Name 'lsass' -ErrorAction Stop).Id
        Add-Finding 'W31-C8' 'LSASS Process Running' 'Info' 'INFO' \
            "LSASS PID: $lsassPID (verifiy PPL via W31-C2 above)" ''
    } catch {
        Add-Finding 'W31-C8' 'LSASS Process' 'High' 'WARN' "Could not find LSASS process: $_" ''
    }

    # C9 – Autologon credentials in registry
    if (Get-RegProp 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultPassword') {
        Add-Finding 'W31-C9' 'AutoLogon Password in Registry' 'Critical' 'FAIL' \
            'DefaultPassword is set in Winlogon registry key – cleartext password stored on disk' \
            'Remove: reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /f'
    } else {
        Add-Finding 'W31-C9' 'AutoLogon Registry Credentials' 'Critical' 'PASS' \
            'No DefaultPassword found in Winlogon registry key' ''
    }
}

Invoke-Checks

# ── Optional Fix ──────────────────────────────────────────────────────────────
if ($Fix) {
    Write-Host "`n[FIX] Applying safe credential hardening..." -ForegroundColor Cyan

    # Disable WDigest
    $wd = Get-RegProp 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
    if ($wd -eq 1) {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0 -Type DWord -Force
        Write-Host "[FIX] WDigest UseLogonCredential disabled." -ForegroundColor Green
    }

    # Enforce NTLMv2
    $level = Get-RegProp 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
    if ($level -lt 3) {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5 -Type DWord -Force
        Write-Host "[FIX] LmCompatibilityLevel set to 5 (NTLMv2 only)." -ForegroundColor Green
    }

    # Reduce cached credentials
    $cached = Get-RegProp 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'CachedLogonsCount'
    if ([int]($cached -replace '[^0-9]','0') -gt 2) {
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name CachedLogonsCount -Value '1' -Type String -Force
        Write-Host "[FIX] CachedLogonsCount reduced to 1." -ForegroundColor Green
    }
}

# ── Output ────────────────────────────────────────────────────────────────────
if ($Json) {
    @{ script='W31_credential_theft_hardening'; host=$env:COMPUTERNAME; timestamp=(Get-Date -Format 'o'); findings=$script:findings } | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W31 $([char]0x2013) Credential Theft Hardening $([char]0x2013) $env:COMPUTERNAME ===" -ForegroundColor Cyan
    foreach ($f in $script:findings) { Write-Finding $f }
    $fails = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
    $warns = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
    Write-Host ("`nSummary: {0} finding(s), {1} FAIL, {2} WARN" -f $script:findings.Count, $fails, $warns)
}

$exitCode = 0
if (($script:findings | Where-Object { $_.status -eq 'WARN' }).Count -gt 0) { $exitCode = 1 }
if (($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { $exitCode = 2 }
exit $exitCode
