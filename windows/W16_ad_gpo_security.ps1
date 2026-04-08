#Requires -Version 5.1
<#
.SYNOPSIS
    W16 – Active Directory & Group Policy Security Audit (Windows)
.DESCRIPTION
    Audits Active Directory domain configuration, Group Policy security settings,
    privileged group membership, Kerberos configuration, LAPS deployment, and
    GPO-deployable security baselines. Works in standalone and AD-joined environments.
    Read-only by default. Pass -Fix to apply remediation where available.
.NOTES
    ID         : W16
    Category   : Active Directory & GPO Security
    Severity   : Critical
    OS         : Windows 10/11, Server 2016+ (domain-joined preferred)
    Admin      : Yes (Domain Admin recommended for full AD checks)
    Language   : PowerShell 5.1+
    Author     : CyberSWISS Security Team
.PARAMETER Json
    Output results in JSON format for SIEM ingestion.
.PARAMETER Fix
    WARNING: Applies recommended baseline values. Off by default. Use with caution.
.EXAMPLE
    .\W16_ad_gpo_security.ps1
    .\W16_ad_gpo_security.ps1 -Json
    .\W16_ad_gpo_security.ps1 -Fix
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
        [string]$Status,   # PASS / FAIL / WARN / INFO
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

#region ── Checks ────────────────────────────────────────────────────────────────
function Invoke-Checks {

    # C1 – Domain membership status
    try {
        $cs = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop
        if ($cs.PartOfDomain) {
            Add-Finding 'W16-C1' 'Domain Membership' 'Info' 'PASS' `
                "Host is domain-joined: $($cs.Domain)" ''
        } else {
            Add-Finding 'W16-C1' 'Domain Membership' 'Info' 'INFO' `
                'Host is NOT domain-joined (standalone). AD checks will be skipped.' `
                'Join the host to an Active Directory domain to enable centralised policy management.'
        }
    } catch {
        Add-Finding 'W16-C1' 'Domain Membership' 'Info' 'WARN' `
            "Unable to query Win32_ComputerSystem: $_" 'Run as administrator.'
    }

    $isDomainJoined = $false
    try { $isDomainJoined = (Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue).PartOfDomain } catch {}

    # C2 – Domain password policy
    if ($isDomainJoined) {
        $rsatAvailable = $null -ne (Get-Command Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue)
        if ($rsatAvailable) {
            try {
                $domainPol = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
                $minLen  = $domainPol.MinPasswordLength
                $maxAge  = $domainPol.MaxPasswordAge.Days
                $detail  = "MinPasswordLength=$minLen, MaxPasswordAge=${maxAge}d"
                if ($minLen -ge 14 -and $maxAge -le 90) {
                    Add-Finding 'W16-C2' 'Domain Password Policy' 'High' 'PASS' $detail ''
                } elseif ($minLen -lt 14) {
                    Add-Finding 'W16-C2' 'Domain Password Policy' 'High' 'FAIL' $detail `
                        'Set domain MinPasswordLength >= 14 via Default Domain Policy GPO.'
                } else {
                    Add-Finding 'W16-C2' 'Domain Password Policy' 'Med' 'WARN' $detail `
                        'Set domain MaxPasswordAge <= 90 days via Default Domain Policy GPO.'
                }
            } catch {
                Add-Finding 'W16-C2' 'Domain Password Policy' 'High' 'WARN' `
                    "RSAT query failed: $_" 'Ensure Domain Admin rights and AD connectivity.'
            }
        } else {
            # Fallback: net accounts /domain
            # net accounts output format: "field name : value" – field names vary by locale.
            # We use positional parsing (last token on lines that contain a numeric value after
            # the last colon) and cross-reference against registry keys for reliable locale-agnostic reads.
            try {
                $raw = & net accounts /domain 2>&1
                $minLen = 0; $maxAge = 999
                # Try locale-neutral registry read first (most reliable)
                # Note: These keys are populated by the Netlogon service on domain members
                # after group policy processing. They may be absent on standalone machines
                # or before the first domain policy application – the positional fallback below
                # handles that case.
                $regMinLen = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' `
                    -Name 'MinimumPasswordLength' -ErrorAction SilentlyContinue)?.MinimumPasswordLength
                $regMaxAge = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' `
                    -Name 'MaximumPasswordAge' -ErrorAction SilentlyContinue)?.MaximumPasswordAge
                if ($null -ne $regMinLen) { $minLen = [int]$regMinLen }
                if ($null -ne $regMaxAge) { $maxAge = [int]$regMaxAge }

                if ($minLen -eq 0 -and $maxAge -eq 999) {
                    # Registry not populated; fall back to parsing net accounts output positionally:
                    # Each relevant line ends with ": <number>" or ": Unlimited"
                    $lines = $raw | Where-Object { $_ -match ':\s+\S' }
                    $values = @($lines | ForEach-Object { ($_ -split ':\s*')[-1].Trim() } |
                                Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ })
                    # net accounts /domain output order is stable: min-len is always before max-age
                    if ($values.Count -ge 2) { $minLen = $values[0]; $maxAge = $values[1] }
                }

                $detail = "MinPasswordLength=$minLen, MaxPasswordAge=${maxAge}d (via net accounts / registry)"
                if ($minLen -ge 14 -and $maxAge -le 90) {
                    Add-Finding 'W16-C2' 'Domain Password Policy' 'High' 'PASS' $detail ''
                } else {
                    Add-Finding 'W16-C2' 'Domain Password Policy' 'High' 'WARN' $detail `
                        'Install RSAT (ActiveDirectory module) for full policy check. Ensure MinLen>=14, MaxAge<=90.'
                }
            } catch {
                Add-Finding 'W16-C2' 'Domain Password Policy' 'High' 'WARN' `
                    'Could not retrieve domain password policy.' `
                    'Install RSAT ActiveDirectory module or run as Domain Admin.'
            }
        }
    } else {
        Add-Finding 'W16-C2' 'Domain Password Policy' 'High' 'INFO' `
            'Skipped – host is not domain-joined.' ''
    }

    # C3 – Privileged AD groups review
    if ($isDomainJoined -and ($null -ne (Get-Command Get-ADGroupMember -ErrorAction SilentlyContinue))) {
        $privilegedGroups = @('Domain Admins','Enterprise Admins','Schema Admins')
        foreach ($groupName in $privilegedGroups) {
            try {
                $members = Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction Stop
                $count   = $members.Count
                $svcAccts = $members | Where-Object { $_.SamAccountName -match 'svc|service|sa_' }
                if ($count -gt 5) {
                    Add-Finding 'W16-C3' "Privileged Group: $groupName" 'Critical' 'WARN' `
                        "$count members (>5 is elevated risk)" `
                        'Review and reduce membership in privileged AD groups to minimum necessary.'
                } elseif ($svcAccts) {
                    Add-Finding 'W16-C3' "Privileged Group: $groupName" 'Critical' 'WARN' `
                        "Service account(s) detected in $($groupName): $($svcAccts.SamAccountName -join ', ')" `
                        'Remove service accounts from Domain Admins. Use dedicated service account tier with least privilege.'
                } else {
                    Add-Finding 'W16-C3' "Privileged Group: $groupName" 'High' 'PASS' `
                        "$count member(s), no obvious service accounts detected." ''
                }
            } catch {
                Add-Finding 'W16-C3' "Privileged Group: $groupName" 'High' 'WARN' `
                    "Could not enumerate ${groupName}: $_" 'Ensure Domain Admin rights.'
            }
        }
    } else {
        Add-Finding 'W16-C3' 'Privileged AD Groups' 'High' 'INFO' `
            'Skipped – not domain-joined or RSAT ActiveDirectory module not available.' `
            'Install RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
    }

    # C4 – LAPS deployment
    $lapsModule   = $null -ne (Get-Module -ListAvailable -Name AdmPwd.PS -ErrorAction SilentlyContinue)
    $lapsDll      = Test-Path "$env:SystemRoot\System32\AdmPwd.dll"
    $lapsNewModule= $null -ne (Get-Module -ListAvailable -Name LAPS -ErrorAction SilentlyContinue)
    if ($lapsModule -or $lapsDll -or $lapsNewModule) {
        Add-Finding 'W16-C4' 'LAPS Deployment' 'High' 'PASS' `
            'LAPS (Local Administrator Password Solution) is installed on this host.' ''
    } else {
        Add-Finding 'W16-C4' 'LAPS Deployment' 'High' 'WARN' `
            'LAPS does not appear to be installed. AdmPwd.dll and LAPS module not found.' `
            'Deploy Microsoft LAPS (or Windows LAPS on Win11/Server 2022) to manage local admin passwords: https://aka.ms/laps'
    }

    # C5 – Kerberos configuration
    if ($isDomainJoined) {
        $kerbPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'
        try {
            $maxTicket = (Get-ItemProperty -Path $kerbPath -Name 'MaxTicketAge'  -ErrorAction SilentlyContinue).MaxTicketAge
            $maxRenew  = (Get-ItemProperty -Path $kerbPath -Name 'MaxRenewAge'   -ErrorAction SilentlyContinue).MaxRenewAge
            $encTypes  = (Get-ItemProperty -Path $kerbPath -Name 'SupportedEncryptionTypes' -ErrorAction SilentlyContinue).SupportedEncryptionTypes

            $details = "MaxTicketAge=$maxTicket h, MaxRenewAge=$maxRenew d, SupportedEncTypes=$encTypes"

            # SupportedEncryptionTypes: 0x18 (24) = AES only; presence of RC4 = 0x4 bit
            $rc4Enabled = $null -eq $encTypes -or (($encTypes -band 0x4) -ne 0)

            if ($rc4Enabled) {
                Add-Finding 'W16-C5' 'Kerberos Configuration' 'High' 'WARN' $details `
                    'RC4 encryption may be enabled for Kerberos. Set SupportedEncryptionTypes=24 (AES128+AES256 only) to disable RC4.'
            } elseif (($null -ne $maxTicket -and $maxTicket -gt 10) -or ($null -ne $maxRenew -and $maxRenew -gt 7)) {
                Add-Finding 'W16-C5' 'Kerberos Configuration' 'Med' 'WARN' $details `
                    'Kerberos ticket lifetime exceeds baseline: MaxTicketAge should be <= 10h, MaxRenewAge <= 7d.'
            } else {
                Add-Finding 'W16-C5' 'Kerberos Configuration' 'High' 'PASS' $details ''
            }
        } catch {
            Add-Finding 'W16-C5' 'Kerberos Configuration' 'High' 'INFO' `
                'Kerberos registry parameters not customised (using domain defaults).' ''
        }
    } else {
        Add-Finding 'W16-C5' 'Kerberos Configuration' 'High' 'INFO' `
            'Skipped – host is not domain-joined.' ''
    }

    # C6 – GPO security baseline applied
    $sysPolPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    try {
        $enableLUA    = (Get-ItemProperty -Path $sysPolPath -Name 'EnableLUA'                  -ErrorAction SilentlyContinue).EnableLUA
        $consentAdmin = (Get-ItemProperty -Path $sysPolPath -Name 'ConsentPromptBehaviorAdmin' -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
        $lsaPath      = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        $lmCompat     = (Get-ItemProperty -Path $lsaPath    -Name 'LmCompatibilityLevel'       -ErrorAction SilentlyContinue).LmCompatibilityLevel

        $issues = [System.Collections.Generic.List[string]]::new()
        if ($enableLUA    -ne 1) { $issues.Add('EnableLUA!=1 (UAC disabled)') }
        if ($consentAdmin -ne 2) { $issues.Add("ConsentPromptBehaviorAdmin=$consentAdmin (expected 2)") }
        if ($lmCompat     -lt 5) { $issues.Add("LmCompatibilityLevel=$lmCompat (expected 5, NTLMv2 only)") }

        $detail = "EnableLUA=$enableLUA, ConsentBehaviorAdmin=$consentAdmin, LmCompatLevel=$lmCompat"
        if ($issues.Count -eq 0) {
            Add-Finding 'W16-C6' 'GPO Security Baseline' 'High' 'PASS' $detail ''
        } else {
            Add-Finding 'W16-C6' 'GPO Security Baseline' 'High' 'FAIL' `
                "$detail | Issues: $($issues -join '; ')" `
                'Apply CIS/STIG GPO baseline. Enable UAC (EnableLUA=1), set ConsentPromptBehaviorAdmin=2, LmCompatibilityLevel=5.'
        }
    } catch {
        Add-Finding 'W16-C6' 'GPO Security Baseline' 'High' 'WARN' `
            "Could not read policy registry keys: $_" 'Run as administrator.'
    }

    # C7 – AD Recycle Bin
    if ($isDomainJoined -and ($null -ne (Get-Command Get-ADOptionalFeature -ErrorAction SilentlyContinue))) {
        try {
            $recycleBin = Get-ADOptionalFeature -Filter { Name -eq 'Recycle Bin Feature' } -ErrorAction Stop
            if ($recycleBin -and $recycleBin.EnabledScopes.Count -gt 0) {
                Add-Finding 'W16-C7' 'AD Recycle Bin' 'Med' 'PASS' `
                    'Active Directory Recycle Bin is enabled.' ''
            } else {
                Add-Finding 'W16-C7' 'AD Recycle Bin' 'Med' 'WARN' `
                    'AD Recycle Bin is NOT enabled. Accidentally deleted objects cannot be easily recovered.' `
                    'Enable via: Enable-ADOptionalFeature -Identity "Recycle Bin Feature" -Scope ForestOrConfigurationSet -Target <domain>'
            }
        } catch {
            Add-Finding 'W16-C7' 'AD Recycle Bin' 'Med' 'WARN' `
                "Could not query AD Optional Features: $_" 'Ensure Domain Admin rights and RSAT.'
        }
    } else {
        Add-Finding 'W16-C7' 'AD Recycle Bin' 'Med' 'INFO' `
            'Skipped – not domain-joined or RSAT ActiveDirectory module not available.' `
            'Install RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
    }
}
#endregion

#region ── Output ────────────────────────────────────────────────────────────────
Invoke-Checks

if ($Fix) {
    Write-Warning "⚠  -Fix flag detected: Applying local GPO-compatible security baseline settings."
    Write-Warning "   Press Ctrl+C within 10 seconds to abort."
    Start-Sleep 10
    if ($PSCmdlet.ShouldProcess('local security policy', 'Apply GPO-compatible baseline')) {
        $sysPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        if (Set-ItemProperty -Path $sysPath -Name 'EnableLUA' -Value 1 -Type DWord -Force -PassThru -ErrorAction SilentlyContinue) {
            Write-Host 'UAC (EnableLUA) enabled.' -ForegroundColor Green
        } else { Write-Warning 'Failed to enable UAC.' }

        if (Set-ItemProperty -Path $sysPath -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Type DWord -Force -PassThru -ErrorAction SilentlyContinue) {
            Write-Host 'UAC consent prompt set to credential prompt (ConsentPromptBehaviorAdmin=2).' -ForegroundColor Green
        } else { Write-Warning 'Failed to set ConsentPromptBehaviorAdmin.' }

        $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        if (Set-ItemProperty -Path $lsaPath -Name 'LmCompatibilityLevel' -Value 5 -Type DWord -Force -PassThru -ErrorAction SilentlyContinue) {
            Write-Host 'NTLMv2 enforced (LmCompatibilityLevel=5).' -ForegroundColor Green
        } else { Write-Warning 'Failed to set LmCompatibilityLevel.' }
    }
}

if ($Json) {
    $result = @{
        script    = 'W16_ad_gpo_security'
        host      = $env:COMPUTERNAME
        timestamp = (Get-Date -Format 'o')
        findings  = $script:findings
    }
    $result | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W16 Active Directory & GPO Security Audit – $env:COMPUTERNAME ===" -ForegroundColor Cyan
    foreach ($f in $script:findings) { Write-Finding $f }
    $fails = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
    $warns = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
    Write-Host ("`nSummary: {0} finding(s), {1} FAIL, {2} WARN" -f $script:findings.Count, $fails, $warns)
}

$exitCode = 0
if (($script:findings | Where-Object { $_.status -eq 'WARN' }).Count -gt 0) { $exitCode = 1 }
if (($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { $exitCode = 2 }
exit $exitCode
#endregion
