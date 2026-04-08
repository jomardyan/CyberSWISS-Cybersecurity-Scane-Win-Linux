#Requires -Version 5.1
<#
.SYNOPSIS
    W02 – Local Administrator Account Review (Windows)
.DESCRIPTION
    Enumerates local users, identifies admin group members, detects the default
    Administrator account status, and flags accounts with stale passwords or
    no password required. Read-only by default. Pass -Fix to apply remediation where available.
.NOTES
    ID       : W02
    Category : Accounts & Auth
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
    .\W02_local_admin_review.ps1
    .\W02_local_admin_review.ps1 -Json
    .\W02_local_admin_review.ps1 -Fix
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
    $color = switch ($f.status) { 'PASS'{'Green'} 'WARN'{'Yellow'} 'FAIL'{'Red'} default{'White'} }
    Write-Host ("[{0}] [{1}] {2}: {3}" -f $f.status,$f.severity,$f.id,$f.name) -ForegroundColor $color
    if ($f.detail)      { Write-Host "       Detail : $($f.detail)" }
    if ($f.status -ne 'PASS' -and $f.remediation) { Write-Host "       Remedy : $($f.remediation)" -ForegroundColor Cyan }
}

#region ── Checks ────────────────────────────────────────────────────────────────
function Invoke-Checks {
    # Enumerate all local users
    $allUsers = Get-LocalUser

    # Get members of local Administrators group
    $adminGroup = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
    $adminNames = $adminGroup | Select-Object -ExpandProperty Name

    # C1 – Built-in Administrator account status
    $builtinAdmin = $allUsers | Where-Object { $_.SID -like 'S-1-5-*-500' } | Select-Object -First 1
    if ($builtinAdmin) {
        if ($builtinAdmin.Enabled) {
            Add-Finding 'W02-C1' 'Built-in Administrator Enabled' 'High' 'FAIL' `
                "Account '$($builtinAdmin.Name)' is enabled" `
                'Disable or rename the built-in Administrator account: Disable-LocalUser -Name Administrator'
        } else {
            Add-Finding 'W02-C1' 'Built-in Administrator Enabled' 'High' 'PASS' `
                "Account '$($builtinAdmin.Name)' is disabled" ''
        }
    }

    # C2 – Built-in Guest account enabled
    $guest = $allUsers | Where-Object { $_.SID -like 'S-1-5-*-501' } | Select-Object -First 1
    if ($guest -and $guest.Enabled) {
        Add-Finding 'W02-C2' 'Guest Account Enabled' 'High' 'FAIL' `
            "Guest account '$($guest.Name)' is enabled" `
            'Disable guest: Disable-LocalUser -Name Guest'
    } else {
        Add-Finding 'W02-C2' 'Guest Account Enabled' 'High' 'PASS' 'Guest account is disabled' ''
    }

    # C3 – Count of non-default admin accounts (> 1 is a warning)
    $nonDefaultAdmins = $adminGroup | Where-Object {
        $_.SID -notlike 'S-1-5-*-500' -and $_.ObjectClass -eq 'User'
    }
    $adminCount = ($nonDefaultAdmins | Measure-Object).Count
    if ($adminCount -gt 2) {
        Add-Finding 'W02-C3' 'Excessive Local Admins' 'High' 'FAIL' `
            "$adminCount non-default admin accounts: $($nonDefaultAdmins.Name -join ', ')" `
            'Remove unnecessary admin accounts from the local Administrators group'
    } elseif ($adminCount -eq 0) {
        Add-Finding 'W02-C3' 'Excessive Local Admins' 'Info' 'PASS' 'No extra local admin accounts' ''
    } else {
        Add-Finding 'W02-C3' 'Excessive Local Admins' 'Med' 'WARN' `
            "$adminCount non-default admin: $($nonDefaultAdmins.Name -join ', ')" `
            'Verify these accounts require administrative privileges'
    }

    # C4 – Accounts with no password required
    $noPwdRequired = $allUsers | Where-Object { $_.PasswordRequired -eq $false -and $_.Enabled }
    if ($noPwdRequired) {
        Add-Finding 'W02-C4' 'Accounts With No Password Required' 'Critical' 'FAIL' `
            "Accounts: $($noPwdRequired.Name -join ', ')" `
            'Enable password requirement: Set-LocalUser -Name <name> -PasswordRequired $true'
    } else {
        Add-Finding 'W02-C4' 'Accounts With No Password Required' 'Critical' 'PASS' 'All accounts require a password' ''
    }

    # C5 – Stale passwords (> 90 days for enabled accounts)
    $stalePwdUsers = $allUsers | Where-Object {
        $_.Enabled -and $_.PasswordLastSet -ne $null -and
        ((Get-Date) - $_.PasswordLastSet).TotalDays -gt 90
    }
    if ($stalePwdUsers) {
        Add-Finding 'W02-C5' 'Stale Passwords (> 90 days)' 'Med' 'WARN' `
            "Accounts: $($stalePwdUsers.Name -join ', ')" `
            'Prompt password reset for these accounts or enforce maximum password age policy'
    } else {
        Add-Finding 'W02-C5' 'Stale Passwords (> 90 days)' 'Med' 'PASS' 'No stale passwords detected' ''
    }

    # C6 – Accounts with passwords set to never expire
    $neverExpire = $allUsers | Where-Object { $_.Enabled -and $_.PasswordExpires -eq $null -and $_.PasswordRequired }
    if ($neverExpire) {
        Add-Finding 'W02-C6' 'Passwords Never Expire' 'Med' 'WARN' `
            "Accounts: $($neverExpire.Name -join ', ')" `
            'Consider enabling password expiration for non-service accounts'
    } else {
        Add-Finding 'W02-C6' 'Passwords Never Expire' 'Med' 'PASS' 'No accounts with non-expiring passwords' ''
    }

    # Emit admin group membership as Info
    Add-Finding 'W02-C7' 'Admin Group Members' 'Info' 'INFO' `
        "Members: $($adminNames -join ', ')" ''
}
#endregion

Invoke-Checks

if ($Fix) {
    Write-Warning "⚠  -Fix flag: No automatic remediation available for local admin review."
    Write-Warning "   Review findings manually. Removing admin accounts requires careful planning."
}

if ($Json) {
    @{ script='W02_local_admin_review'; host=$env:COMPUTERNAME; timestamp=(Get-Date -Format 'o'); findings=$script:findings } | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W02 Local Admin Review – $env:COMPUTERNAME ===" -ForegroundColor Cyan
    foreach ($f in $script:findings) { Write-Finding $f }
    $fails = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
    $warns = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
    Write-Host ("`nSummary: {0} finding(s), {1} FAIL, {2} WARN" -f $script:findings.Count, $fails, $warns)
}

$exitCode = 0
if (($script:findings | Where-Object { $_.status -eq 'WARN' }).Count -gt 0) { $exitCode = 1 }
if (($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { $exitCode = 2 }
exit $exitCode
