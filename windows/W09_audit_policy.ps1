#Requires -Version 5.1
<#
.SYNOPSIS
    W09 – Windows Audit Policy Check
.DESCRIPTION
    Uses auditpol to enumerate and validate that all recommended audit
    subcategories have Success/Failure auditing enabled per CIS/NIST guidance.
    Read-only by default. Pass -Fix to apply remediation where available.
.NOTES
    ID       : W09
    Category : Logging & Auditing
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
    .\W09_audit_policy.ps1
    .\W09_audit_policy.ps1 -Json
    .\W09_audit_policy.ps1 -Fix
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

# Required subcategories: name -> required_setting (Success, Failure, Success and Failure)
$requiredSubcategories = [ordered]@{
    'Credential Validation'                  = 'Success and Failure'
    'Logon'                                  = 'Success and Failure'
    'Logoff'                                 = 'Success'
    'Account Lockout'                        = 'Failure'
    'Special Logon'                          = 'Success'
    'Process Creation'                       = 'Success'
    'Audit Policy Change'                    = 'Success'
    'Authentication Policy Change'           = 'Success'
    'Security Group Management'              = 'Success'
    'User Account Management'                = 'Success and Failure'
    'Security System Extension'              = 'Success'
    'System Integrity'                       = 'Success and Failure'
    'Sensitive Privilege Use'                = 'Success and Failure'
    'Removable Storage'                      = 'Success and Failure'
    'Handle Manipulation'                    = 'Success'
}

function Parse-AuditPolicy {
    $lines = & auditpol /get /category:* /r 2>&1
    $parsed = @{}
    foreach ($line in $lines) {
        $parts = $line -split ','
        if ($parts.Count -ge 5) {
            $subcat  = $parts[2].Trim()
            $setting = $parts[4].Trim()
            if ($subcat -and $subcat -ne 'Subcategory' -and $subcat -ne 'Machine Name') {
                $parsed[$subcat] = $setting
            }
        }
    }
    return $parsed
}

function Invoke-Checks {
    try {
        $policy = Parse-AuditPolicy
    } catch {
        Add-Finding 'W09-C0' 'Audit Policy Parse' 'High' 'WARN' "Failed to parse auditpol: $_" 'Run as administrator'
        return
    }

    $idx = 1
    foreach ($subcat in $requiredSubcategories.Keys) {
        $required = $requiredSubcategories[$subcat]
        $current  = $policy[$subcat]
        $id       = "W09-C$idx"

        if ($null -eq $current) {
            Add-Finding $id "Audit: $subcat" 'High' 'WARN' "Subcategory not found in auditpol output" `
                "Check: auditpol /get /subcategory:""$subcat"""
        } elseif ($current -eq 'No Auditing') {
            Add-Finding $id "Audit: $subcat" 'High' 'FAIL' `
                "Current: No Auditing | Required: $required" `
                "Enable: auditpol /set /subcategory:""$subcat"" /success:enable /failure:enable"
        } elseif ($required -eq 'Success and Failure' -and $current -ne 'Success and Failure') {
            Add-Finding $id "Audit: $subcat" 'Med' 'WARN' `
                "Current: $current | Required: $required" `
                "Update: auditpol /set /subcategory:""$subcat"" /success:enable /failure:enable"
        } elseif ($required -eq 'Success' -and $current -notmatch 'Success') {
            Add-Finding $id "Audit: $subcat" 'Med' 'FAIL' `
                "Current: $current | Required: $required" `
                "Enable: auditpol /set /subcategory:""$subcat"" /success:enable"
        } elseif ($required -eq 'Failure' -and $current -notmatch 'Failure') {
            Add-Finding $id "Audit: $subcat" 'Med' 'FAIL' `
                "Current: $current | Required: $required" `
                "Enable: auditpol /set /subcategory:""$subcat"" /failure:enable"
        } else {
            Add-Finding $id "Audit: $subcat" 'High' 'PASS' "Current: $current | Required: $required" ''
        }
        $idx++
    }
}

Invoke-Checks

if ($Fix) {
    Write-Warning "⚠  -Fix flag detected. About to enable recommended audit subcategories."
    Write-Warning "   Press Ctrl+C within 10 seconds to abort."
    Start-Sleep 10
    if ($PSCmdlet.ShouldProcess('audit policy', 'Enable recommended subcategories')) {
        $auditSettings = @(
            'Logon', 'Logoff', 'Account Lockout', 'Privilege Use',
            'Process Creation', 'Object Access', 'Policy Change',
            'Security Group Management', 'User Account Management'
        )
        foreach ($cat in $auditSettings) {
            & auditpol /set /subcategory:$cat /success:enable /failure:enable 2>&1 | Out-Null
        }
        Write-Host "Recommended audit subcategories enabled." -ForegroundColor Green
    }
}

if ($Json) {
    @{ script='W09_audit_policy'; host=$env:COMPUTERNAME; timestamp=(Get-Date -Format 'o'); findings=$script:findings } | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W09 Audit Policy – $env:COMPUTERNAME ===" -ForegroundColor Cyan
    foreach ($f in $script:findings) { Write-Finding $f }
    $fails = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
    $warns = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
    Write-Host ("`nSummary: {0} finding(s), {1} FAIL, {2} WARN" -f $script:findings.Count, $fails, $warns)
}

$exitCode = 0
if (($script:findings | Where-Object { $_.status -eq 'WARN' }).Count -gt 0) { $exitCode = 1 }
if (($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { $exitCode = 2 }
exit $exitCode
