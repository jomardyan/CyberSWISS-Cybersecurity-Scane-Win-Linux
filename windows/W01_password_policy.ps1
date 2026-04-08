#Requires -Version 5.1
<#
.SYNOPSIS
    W01 – Password Policy Audit (Windows)
.DESCRIPTION
    Reads the local password policy (min length, complexity, lockout, max age)
    and flags settings that deviate from CIS/NIST baselines.
    Defensive / read-only. No changes are made unless --fix is supplied.
.NOTES
    ID         : W01
    Category   : Accounts & Auth
    Severity   : High
    OS         : Windows 10/11, Windows Server 2016+
    Admin      : Yes (net accounts requires elevation for domain policy)
    Language   : PowerShell 5.1+
    Author     : CyberSWISS Security Team
.PARAMETER Json
    Output results in JSON format for SIEM ingestion.
.PARAMETER Fix
    WARNING: Applies recommended baseline values. Off by default. Use with caution.
.EXAMPLE
    .\W01_password_policy.ps1
    .\W01_password_policy.ps1 -Json
    .\W01_password_policy.ps1 -Fix   # requires admin + explicit intent
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Json,
    [switch]$Fix
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── Helpers ──────────────────────────────────────────────────────────────
$script:findings = [System.Collections.Generic.List[hashtable]]::new()

function Add-Finding {
    param(
        [string]$Id,
        [string]$Name,
        [ValidateSet('Info','Low','Med','High','Critical')]
        [string]$Severity,
        [string]$Status,   # PASS / FAIL / WARN
        [string]$Detail,
        [string]$Remediation
    )
    $script:findings.Add(@{
        id          = $Id
        name        = $Name
        severity    = $Severity
        status      = $Status
        detail      = $Detail
        remediation = $Remediation
        timestamp   = (Get-Date -Format 'o')
    })
}

function Write-Finding {
    param([hashtable]$f)
    $color = switch ($f.status) {
        'PASS' { 'Green'  }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red'    }
        default{ 'White'  }
    }
    Write-Host ("[{0}] [{1}] {2}: {3}" -f $f.status, $f.severity, $f.id, $f.name) -ForegroundColor $color
    if ($f.detail)      { Write-Host "       Detail : $($f.detail)"      }
    if ($f.status -ne 'PASS' -and $f.remediation) {
        Write-Host "       Remedy : $($f.remediation)" -ForegroundColor Cyan
    }
}
#endregion

#region ── Collect Policy ────────────────────────────────────────────────────────
function Get-LocalPasswordPolicy {
    $raw = & net accounts 2>&1
    $policy = @{}
    foreach ($line in $raw) {
        if ($line -match 'Minimum password length\s+:\s+(\S+)')      { $policy['MinLen']     = $Matches[1] }
        if ($line -match 'Maximum password age.*:\s+(\S+)')          { $policy['MaxAge']     = $Matches[1] }
        if ($line -match 'Minimum password age.*:\s+(\S+)')          { $policy['MinAge']     = $Matches[1] }
        if ($line -match 'Password history length\s+:\s+(\S+)')      { $policy['History']    = $Matches[1] }
        if ($line -match 'Lockout threshold\s+:\s+(\S+)')            { $policy['LockThr']    = $Matches[1] }
        if ($line -match 'Lockout duration.*:\s+(\S+)')              { $policy['LockDur']    = $Matches[1] }
        if ($line -match 'Lockout observation window.*:\s+(\S+)')    { $policy['LockWin']    = $Matches[1] }
    }
    return $policy
}

function Get-ComplexityEnabled {
    # secedit /export to temp file; read PasswordComplexity
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        & secedit /export /cfg $tmp /quiet 2>$null | Out-Null
        $content = Get-Content $tmp -ErrorAction SilentlyContinue
        foreach ($line in $content) {
            if ($line -match 'PasswordComplexity\s*=\s*(\d)') { return [int]$Matches[1] }
        }
    } finally {
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    }
    return $null
}
#endregion

#region ── Checks ────────────────────────────────────────────────────────────────
function Invoke-Checks {
    $pol = Get-LocalPasswordPolicy

    # C1 – Minimum password length >= 14 (NIST SP 800-63B / CIS)
    $minLen = if ($pol['MinLen'] -match '^\d+$') { [int]$pol['MinLen'] } else { 0 }
    if ($minLen -ge 14) {
        Add-Finding 'W01-C1' 'Min Password Length' 'High' 'PASS' "MinLen=$minLen (>= 14)" ''
    } elseif ($minLen -ge 8) {
        Add-Finding 'W01-C1' 'Min Password Length' 'High' 'WARN' "MinLen=$minLen (< 14, >= 8)" `
            'Set minimum password length to at least 14 characters via Group Policy or net accounts /MINPWLEN:14'
    } else {
        Add-Finding 'W01-C1' 'Min Password Length' 'High' 'FAIL' "MinLen=$minLen (< 8)" `
            'Set minimum password length to at least 14: net accounts /MINPWLEN:14 or GPO'
    }

    # C2 – Password complexity enabled
    $complexity = Get-ComplexityEnabled
    if ($complexity -eq 1) {
        Add-Finding 'W01-C2' 'Password Complexity' 'High' 'PASS' 'Complexity=Enabled' ''
    } elseif ($null -eq $complexity) {
        Add-Finding 'W01-C2' 'Password Complexity' 'Med' 'WARN' 'Could not determine (run as admin)' `
            'Run script with administrator privileges to check complexity setting'
    } else {
        Add-Finding 'W01-C2' 'Password Complexity' 'High' 'FAIL' 'Complexity=Disabled' `
            'Enable via: Computer Config > Windows Settings > Security Settings > Account Policies > Password Policy'
    }

    # C3 – Maximum password age <= 90 days
    $maxAge = if ($pol['MaxAge'] -match '^\d+$') { [int]$pol['MaxAge'] } else { 999 }
    if ($maxAge -eq 0) {
        Add-Finding 'W01-C3' 'Max Password Age' 'High' 'FAIL' 'MaxAge=0 (never expires)' `
            'Set maximum password age to 90 days: net accounts /MAXPWAGE:90'
    } elseif ($maxAge -le 90) {
        Add-Finding 'W01-C3' 'Max Password Age' 'Med' 'PASS' "MaxAge=${maxAge} days (<= 90)" ''
    } else {
        Add-Finding 'W01-C3' 'Max Password Age' 'Med' 'WARN' "MaxAge=${maxAge} days (> 90)" `
            'Reduce to 90 days: net accounts /MAXPWAGE:90'
    }

    # C4 – Password history >= 24
    $hist = if ($pol['History'] -match '^\d+$') { [int]$pol['History'] } else { 0 }
    if ($hist -ge 24) {
        Add-Finding 'W01-C4' 'Password History' 'Med' 'PASS' "History=$hist (>= 24)" ''
    } else {
        Add-Finding 'W01-C4' 'Password History' 'Med' 'FAIL' "History=$hist (< 24)" `
            'Set password history to 24: net accounts /UNIQUEPW:24'
    }

    # C5 – Account lockout threshold 1-10
    $lt = $pol['LockThr']
    if ($lt -eq 'Never') {
        Add-Finding 'W01-C5' 'Lockout Threshold' 'High' 'FAIL' 'Lockout=Never (disabled)' `
            'Set lockout threshold to 5-10: net accounts /LOCKOUTTHRESHOLD:5'
    } elseif ($lt -match '^\d+$' -and [int]$lt -gt 0 -and [int]$lt -le 10) {
        Add-Finding 'W01-C5' 'Lockout Threshold' 'High' 'PASS' "LockoutThreshold=$lt" ''
    } else {
        Add-Finding 'W01-C5' 'Lockout Threshold' 'High' 'WARN' "LockoutThreshold=$lt (> 10 is too lenient)" `
            'Reduce lockout threshold to <= 10'
    }

    # C6 – Lockout duration >= 15 minutes
    $ld = if ($pol['LockDur'] -match '^\d+$') { [int]$pol['LockDur'] } else { 0 }
    if ($ld -ge 15) {
        Add-Finding 'W01-C6' 'Lockout Duration' 'Med' 'PASS' "LockDur=${ld} min (>= 15)" ''
    } else {
        Add-Finding 'W01-C6' 'Lockout Duration' 'Med' 'FAIL' "LockDur=${ld} min (< 15)" `
            'Set lockout duration to at least 15 minutes: net accounts /LOCKOUTDURATION:15'
    }

    # Optional --fix
    if ($Fix) {
        Write-Warning "⚠  --Fix flag detected. About to apply baseline password policy settings."
        Write-Warning "   This will modify local security policy. Press Ctrl+C within 10 seconds to abort."
        Start-Sleep 10
        if ($PSCmdlet.ShouldProcess('local password policy', 'Apply CIS baseline')) {
            & net accounts /MINPWLEN:14 /MAXPWAGE:90 /UNIQUEPW:24 /LOCKOUTTHRESHOLD:5 /LOCKOUTDURATION:15 | Out-Null
            Write-Host 'Baseline password policy applied.' -ForegroundColor Green
        }
    }
}
#endregion

#region ── Output ────────────────────────────────────────────────────────────────
Invoke-Checks

if ($Json) {
    $result = @{
        script    = 'W01_password_policy'
        host      = $env:COMPUTERNAME
        timestamp = (Get-Date -Format 'o')
        findings  = $script:findings
    }
    $result | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W01 Password Policy Audit – $env:COMPUTERNAME ===" -ForegroundColor Cyan
    foreach ($f in $script:findings) { Write-Finding $f }
    $fails = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
    $warns = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
    Write-Host ("`nSummary: {0} finding(s), {1} FAIL, {2} WARN" -f $script:findings.Count, $fails, $warns)
}

# Exit code: 0=all pass, 1=warnings, 2=failures
$exitCode = 0
if (($script:findings | Where-Object { $_.status -eq 'WARN' }).Count -gt 0) { $exitCode = 1 }
if (($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { $exitCode = 2 }
exit $exitCode
#endregion
