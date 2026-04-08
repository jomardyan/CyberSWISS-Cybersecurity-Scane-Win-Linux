#Requires -Version 5.1
<#
.SYNOPSIS
    W22 – Compliance Automation: SOC 2, HIPAA, GDPR (Windows)
.DESCRIPTION
    Automates compliance control verification for SOC 2, HIPAA, and GDPR
    requirements. Checks audit logging, data encryption, access controls,
    data retention, incident response readiness, and change management.
    All checks are read-only observations mapped to specific compliance controls.
    Read-only by default. Pass -Fix to apply remediation where available.
.NOTES
    ID         : W22
    Category   : Compliance Automation
    Severity   : High
    OS         : Windows 10/11, Server 2016+
    Admin      : Yes
    Language   : PowerShell 5.1+
    Author     : CyberSWISS Security Team
.PARAMETER Json
    Output results in JSON format for SIEM ingestion.
.PARAMETER Fix
    WARNING: Applies recommended baseline values. Off by default. Use with caution.
.EXAMPLE
    .\W22_compliance_checks.ps1
    .\W22_compliance_checks.ps1 -Json
    .\W22_compliance_checks.ps1 -Fix
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

    # C1 – Audit logging (SOC 2 CC7.2 / HIPAA §164.312(b))
    try {
        $secLog      = Get-WinEvent -ListLog 'Security' -ErrorAction Stop
        $logEnabled  = $secLog.IsEnabled
        $maxSizeGB   = [math]::Round($secLog.MaximumSizeInBytes / 1GB, 2)

        # Check advanced audit policy for critical categories
        $auditOutput = & auditpol /get /category:* 2>&1
        $logonAudit  = $auditOutput | Where-Object { $_ -imatch 'Logon' -and $_ -imatch 'Success and Failure' }
        $acctAudit   = $auditOutput | Where-Object { $_ -imatch 'Account Management' -and $_ -imatch 'Success' }
        $polAudit    = $auditOutput | Where-Object { $_ -imatch 'Policy Change' -and $_ -imatch 'Success' }

        $issues = [System.Collections.Generic.List[string]]::new()
        if (-not $logEnabled)   { $issues.Add('Security event log is DISABLED') }
        if ($maxSizeGB -lt 1)   { $issues.Add("Security log max size ${maxSizeGB}GB (< 1GB)") }
        if (-not $logonAudit)   { $issues.Add('Logon audit: Success and Failure not enabled') }
        if (-not $acctAudit)    { $issues.Add('Account Management audit not enabled') }
        if (-not $polAudit)     { $issues.Add('Policy Change audit not enabled') }

        $detail = "SecurityLog: Enabled=$logEnabled, MaxSize=${maxSizeGB}GB; Logon=$($null -ne $logonAudit); AcctMgmt=$($null -ne $acctAudit); PolicyChange=$($null -ne $polAudit)"
        if ($issues.Count -eq 0) {
            Add-Finding 'W22-C1' 'Audit Logging [SOC2-CC7.2/HIPAA-164.312b]' 'High' 'PASS' $detail ''
        } elseif ($issues | Where-Object { $_ -match 'DISABLED|Logon' }) {
            Add-Finding 'W22-C1' 'Audit Logging [SOC2-CC7.2/HIPAA-164.312b]' 'High' 'FAIL' `
                "$detail | Issues: $($issues -join '; ')" `
                'Enable Security log. Set max size >= 1GB. Enable audit subcategories: auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable'
        } else {
            Add-Finding 'W22-C1' 'Audit Logging [SOC2-CC7.2/HIPAA-164.312b]' 'High' 'WARN' `
                "$detail | Warnings: $($issues -join '; ')" `
                'Increase Security log max size to >= 1GB. Enable all critical audit categories.'
        }
    } catch {
        Add-Finding 'W22-C1' 'Audit Logging [SOC2-CC7.2/HIPAA-164.312b]' 'High' 'WARN' `
            "Could not query event log or audit policy: $_" 'Run as administrator.'
    }

    # C2 – Data encryption at rest (HIPAA §164.312(a)(2)(iv) / GDPR Art. 32)
    try {
        $blCmd = Get-Command manage-bde -ErrorAction SilentlyContinue
        if ($null -eq $blCmd) {
            Add-Finding 'W22-C2' 'Data Encryption at Rest [HIPAA-164.312a/GDPR-Art32]' 'Critical' 'WARN' `
                'manage-bde not found. Cannot check BitLocker status.' `
                'Ensure BitLocker Drive Encryption is enabled on all fixed drives. Run manage-bde -status.'
        } else {
            $blStatus   = & manage-bde -status 2>&1
            $osProtected = $blStatus | Where-Object { $_ -imatch 'Protection\s*On' }
            $notProtected = $blStatus | Where-Object { $_ -imatch 'Protection\s*Off' }

            # Check EFS policy
            $efsPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\EFS'
            $efsEnabled = (Get-ItemProperty $efsPath -Name 'EfsConfiguration' -ErrorAction SilentlyContinue).EfsConfiguration

            $detail = "BitLocker-Protected-Volumes: $($osProtected.Count), Unprotected: $($notProtected.Count), EFS-PolicyConfig: $efsEnabled"
            if ($osProtected.Count -eq 0) {
                Add-Finding 'W22-C2' 'Data Encryption at Rest [HIPAA-164.312a/GDPR-Art32]' 'Critical' 'FAIL' $detail `
                    'Enable BitLocker on all fixed drives: Enable-BitLocker -MountPoint C: -EncryptionMethod Aes256 -TpmProtector'
            } elseif ($notProtected.Count -gt 0) {
                Add-Finding 'W22-C2' 'Data Encryption at Rest [HIPAA-164.312a/GDPR-Art32]' 'High' 'WARN' $detail `
                    "Enable BitLocker on $($notProtected.Count) unprotected volume(s)."
            } else {
                Add-Finding 'W22-C2' 'Data Encryption at Rest [HIPAA-164.312a/GDPR-Art32]' 'High' 'PASS' $detail ''
            }
        }
    } catch {
        Add-Finding 'W22-C2' 'Data Encryption at Rest [HIPAA-164.312a/GDPR-Art32]' 'Critical' 'WARN' `
            "BitLocker check failed: $_" 'Run as administrator.'
    }

    # C3 – Access control least privilege (SOC 2 CC6.3 / HIPAA §164.312(a)(1))
    try {
        $adminGroup   = [ADSI]"WinNT://./Administrators,group"
        $adminMembers = @($adminGroup.Invoke('Members') | ForEach-Object { ([ADSI]$_).InvokeGet('Name') })
        $guestAcct    = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue

        $uacLua  = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
            -Name 'EnableLUA' -ErrorAction SilentlyContinue).EnableLUA

        $issues = [System.Collections.Generic.List[string]]::new()
        if ($adminMembers.Count -gt 3) { $issues.Add("$($adminMembers.Count) local admin accounts (> 3)") }
        if ($guestAcct -and $guestAcct.Enabled) { $issues.Add('Guest account is ENABLED') }
        if ($uacLua -ne 1) { $issues.Add('UAC (EnableLUA) is disabled') }

        $detail = "LocalAdmins: $($adminMembers.Count) [$($adminMembers -join ', ')], Guest: $($guestAcct.Enabled), UAC: $($uacLua -eq 1)"
        if ($issues.Count -eq 0) {
            Add-Finding 'W22-C3' 'Access Control Least Privilege [SOC2-CC6.3/HIPAA-164.312a]' 'High' 'PASS' $detail ''
        } elseif ($issues | Where-Object { $_ -match 'Guest.*ENABLED|UAC.*disabled' }) {
            Add-Finding 'W22-C3' 'Access Control Least Privilege [SOC2-CC6.3/HIPAA-164.312a]' 'High' 'FAIL' `
                "$detail | Issues: $($issues -join '; ')" `
                'Disable Guest account: Disable-LocalUser Guest. Enable UAC. Reduce admin accounts to <= 3.'
        } else {
            Add-Finding 'W22-C3' 'Access Control Least Privilege [SOC2-CC6.3/HIPAA-164.312a]' 'Med' 'WARN' `
                "$detail | Warnings: $($issues -join '; ')" `
                'Reduce local administrator group membership to minimum required.'
        }
    } catch {
        Add-Finding 'W22-C3' 'Access Control Least Privilege [SOC2-CC6.3/HIPAA-164.312a]' 'High' 'WARN' `
            "Could not check access controls: $_" 'Run as administrator.'
    }

    # C4 – Data retention (SOC 2 CC2.2 / HIPAA §164.312(b))
    try {
        $secLog     = Get-WinEvent -ListLog 'Security' -ErrorAction Stop
        $maxSizeGB  = [math]::Round($secLog.MaximumSizeInBytes / 1GB, 2)
        $retention  = $secLog.LogMode   # AutoBackup, Circular, Retain

        $issues = [System.Collections.Generic.List[string]]::new()
        if ($maxSizeGB -lt 1) { $issues.Add("Security log max size ${maxSizeGB}GB (< 1GB recommended)") }
        if ($retention -eq 'Circular') { $issues.Add("Log retention mode=Circular (events overwritten without archiving)") }

        $detail = "SecurityLog MaxSize=${maxSizeGB}GB, RetentionMode=$retention"
        if ($issues.Count -eq 0) {
            Add-Finding 'W22-C4' 'Data Retention Policy [SOC2-CC2.2/HIPAA-164.312b]' 'High' 'PASS' $detail ''
        } else {
            Add-Finding 'W22-C4' 'Data Retention Policy [SOC2-CC2.2/HIPAA-164.312b]' 'High' 'WARN' `
                "$detail | Issues: $($issues -join '; ')" `
                'Set Security log to AutoBackup or Retain mode. Increase max size >= 1GB. Configure log archiving via Windows Event Forwarding (WEF).'
        }
    } catch {
        Add-Finding 'W22-C4' 'Data Retention Policy [SOC2-CC2.2/HIPAA-164.312b]' 'High' 'WARN' `
            "Could not check log retention: $_" 'Run as administrator.'
    }

    # C5 – Incident response readiness (SOC 2 CC7.3)
    $irIssues = [System.Collections.Generic.List[string]]::new()
    # Windows Defender status
    try {
        $defStatus = Get-MpComputerStatus -ErrorAction Stop
        if (-not $defStatus.AntivirusEnabled)         { $irIssues.Add('Windows Defender AntiVirus disabled') }
        if ($defStatus.AntivirusSignatureAge -gt 7)    { $irIssues.Add("AV signatures $($defStatus.AntivirusSignatureAge) days old (> 7)") }
    } catch {
        $irIssues.Add('Could not query Windows Defender status')
    }
    # Sysmon
    $sysmonKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv'
    $sysmonInstalled = Test-Path $sysmonKey
    if (-not $sysmonInstalled) { $irIssues.Add('Sysmon (SysmonDrv) not installed') }
    # WEF (Windows Event Forwarding)
    $wefSvc = Get-Service -Name Wecsvc -ErrorAction SilentlyContinue
    if ($null -eq $wefSvc -or $wefSvc.Status -ne 'Running') {
        $irIssues.Add('Windows Event Collector (WEF/Wecsvc) not running')
    }

    $detail = "Defender=$(-not ($irIssues | Where-Object { $_ -match 'Defender' })), Sysmon=$sysmonInstalled, WEF=$($wefSvc -and $wefSvc.Status -eq 'Running')"
    if ($irIssues.Count -eq 0) {
        Add-Finding 'W22-C5' 'Incident Response Readiness [SOC2-CC7.3]' 'High' 'PASS' $detail ''
    } elseif ($irIssues | Where-Object { $_ -match 'disabled|Sysmon' }) {
        Add-Finding 'W22-C5' 'Incident Response Readiness [SOC2-CC7.3]' 'High' 'WARN' `
            "$detail | Issues: $($irIssues -join '; ')" `
            'Enable Windows Defender. Deploy Sysmon: https://docs.microsoft.com/sysinternals/downloads/sysmon. Configure WEF for centralised log collection.'
    } else {
        Add-Finding 'W22-C5' 'Incident Response Readiness [SOC2-CC7.3]' 'Med' 'INFO' `
            "$detail | Notes: $($irIssues -join '; ')" `
            'Consider deploying Sysmon and Windows Event Forwarding for enhanced incident detection.'
    }

    # C6 – GDPR data minimisation (GDPR Art. 5)
    $gdprIssues = [System.Collections.Generic.List[string]]::new()
    # Large files in temp/public shares
    $tmpPath = $env:TEMP
    if (Test-Path $tmpPath) {
        $largeTempFiles = Get-ChildItem $tmpPath -Recurse -ErrorAction SilentlyContinue |
            Where-Object { -not $_.PSIsContainer -and $_.Length -gt 500MB }
        if ($largeTempFiles) { $gdprIssues.Add("$($largeTempFiles.Count) file(s) > 500MB in TEMP directory") }
    }
    # IIS log retention
    $iisLogPath = 'C:\inetpub\logs'
    if (Test-Path $iisLogPath) {
        $oldLogs = Get-ChildItem $iisLogPath -Recurse -Filter '*.log' -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-365) }
        if ($oldLogs) { $gdprIssues.Add("$($oldLogs.Count) IIS log file(s) older than 1 year not archived/deleted") }
    }
    # Check for unencrypted PII patterns in IIS document root
    $iisRoot = 'C:\inetpub\wwwroot'
    if (Test-Path $iisRoot) {
        $piiFiles = Get-ChildItem $iisRoot -Recurse -Include '*.csv','*.txt','*.json' -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -gt 1MB }
        if ($piiFiles) { $gdprIssues.Add("$($piiFiles.Count) large data file(s) in IIS web root (possible PII exposure)") }
    }
    if ($gdprIssues.Count -eq 0) {
        Add-Finding 'W22-C6' 'GDPR Data Minimisation [GDPR-Art5]' 'High' 'PASS' `
            'No obvious data minimisation issues detected.' ''
    } else {
        Add-Finding 'W22-C6' 'GDPR Data Minimisation [GDPR-Art5]' 'High' 'WARN' `
            ($gdprIssues -join ' | ') `
            'Review and remove unnecessary personal data. Implement data retention schedules. Encrypt PII at rest. Move sensitive files out of web roots.'
    }

    # C7 – Change management (SOC 2 CC8.1)
    $cmIssues = [System.Collections.Generic.List[string]]::new()
    # Windows Update recent history
    try {
        $updateSession   = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher  = $updateSession.CreateUpdateSearcher()
        $histCount       = $updateSearcher.GetTotalHistoryCount()
        if ($histCount -gt 0) {
            $recentUpdates = $updateSearcher.QueryHistory(0, [Math]::Min($histCount, 50))
            $last30Days    = $recentUpdates | Where-Object {
                $_.Date -gt (Get-Date).AddDays(-30) -and $_.ResultCode -eq 2
            }
            if ($last30Days.Count -eq 0) {
                $cmIssues.Add('No successful Windows Updates in the last 30 days')
            }
        }
    } catch {
        $cmIssues.Add("Could not query Windows Update history: $_")
    }
    # AppLocker / WDAC policies
    $appLockerPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2'
    $wdacPath      = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
    $appLockerEnabled = Test-Path $appLockerPath
    $wdacEnabled      = Test-Path $wdacPath
    if (-not $appLockerEnabled -and -not $wdacEnabled) {
        $cmIssues.Add('No AppLocker or WDAC (Windows Defender Application Control) policies detected')
    }
    # UAC level (software install gate)
    $consentBehavior = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
        -Name 'ConsentPromptBehaviorAdmin' -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
    if ($consentBehavior -eq 0) {
        $cmIssues.Add('ConsentPromptBehaviorAdmin=0 (no UAC prompt for admins; software installs silently)')
    }

    $detail = "AppLocker=$appLockerEnabled, WDAC=$wdacEnabled, ConsentPromptBehaviorAdmin=$consentBehavior"
    if ($cmIssues.Count -eq 0) {
        Add-Finding 'W22-C7' 'Change Management Controls [SOC2-CC8.1]' 'High' 'PASS' $detail ''
    } elseif ($cmIssues | Where-Object { $_ -match 'AppLocker|WDAC' }) {
        Add-Finding 'W22-C7' 'Change Management Controls [SOC2-CC8.1]' 'High' 'WARN' `
            "$detail | Issues: $($cmIssues -join '; ')" `
            'Configure AppLocker or WDAC to control software installation. Enable Windows Update automatic download. Set UAC ConsentPromptBehaviorAdmin >= 1.'
    } else {
        Add-Finding 'W22-C7' 'Change Management Controls [SOC2-CC8.1]' 'Med' 'WARN' `
            "$detail | Warnings: $($cmIssues -join '; ')" `
            'Ensure Windows Updates are applied regularly. Review UAC and software restriction policies.'
    }
}
#endregion

#region ── Output ────────────────────────────────────────────────────────────────
Invoke-Checks

if ($Fix) {
    Write-Warning "⚠  -Fix flag detected: Applying compliance baseline settings."
    Write-Warning "   Press Ctrl+C within 10 seconds to abort."
    Start-Sleep 10
    if ($PSCmdlet.ShouldProcess('audit policy and Windows Update settings', 'Apply compliance baseline')) {
        # Enable Security audit subcategories for Logon and Account Management
        try {
            & auditpol /set /category:"Logon/Logoff"       /success:enable /failure:enable 2>&1 | Out-Null
            & auditpol /set /category:"Account Management" /success:enable /failure:enable 2>&1 | Out-Null
            & auditpol /set /category:"Policy Change"      /success:enable /failure:enable 2>&1 | Out-Null
            Write-Host 'Audit policy: Logon, Account Management, Policy Change categories enabled.' -ForegroundColor Green
        } catch {
            Write-Warning "Failed to set audit policy: $_"
        }
        # Set Security log size to 1GB and AutoBackup mode
        try {
            $secLogKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security'
            Set-ItemProperty -Path $secLogKey -Name 'MaxSize' -Value 1073741824 -Type DWord -Force -ErrorAction SilentlyContinue
            Write-Host 'Security event log max size set to 1GB.' -ForegroundColor Green
        } catch {
            Write-Warning "Failed to set Security log size: $_"
        }
        # Enable Windows Update automatic download (AUOptions=3)
        try {
            $wuPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            if (-not (Test-Path $wuPath)) { New-Item -Path $wuPath -Force | Out-Null }
            Set-ItemProperty -Path $wuPath -Name 'AUOptions'    -Value 3 -Type DWord -Force | Out-Null
            Set-ItemProperty -Path $wuPath -Name 'NoAutoUpdate' -Value 0 -Type DWord -Force | Out-Null
            Write-Host 'Windows Update automatic download enabled (AUOptions=3).' -ForegroundColor Green
        } catch {
            Write-Warning "Failed to configure Windows Update policy: $_"
        }
    }
}

if ($Json) {
    $result = @{
        script    = 'W22_compliance_checks'
        host      = $env:COMPUTERNAME
        timestamp = (Get-Date -Format 'o')
        findings  = $script:findings
    }
    $result | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W22 Compliance Automation: SOC 2 / HIPAA / GDPR – $env:COMPUTERNAME ===" -ForegroundColor Cyan
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
