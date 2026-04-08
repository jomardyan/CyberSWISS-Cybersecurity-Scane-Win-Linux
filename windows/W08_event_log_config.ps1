#Requires -Version 5.1
<#
.SYNOPSIS
    W08 – Windows Event Log Configuration Audit
.DESCRIPTION
    Verifies that key event logs (Security, System, Application) are enabled,
    have adequate maximum size, and that their retention policy is appropriate.
    Also checks advanced audit policy settings.
    Read-only by default. Pass -Fix to apply remediation where available.
.NOTES
    ID       : W08
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
    .\W08_event_log_config.ps1
    .\W08_event_log_config.ps1 -Json
    .\W08_event_log_config.ps1 -Fix
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

# Minimum log sizes in bytes (CIS recommendation)
$minLogSizes = @{
    'Security'    = 1073741824  # 1 GB
    'System'      = 524288000   # 500 MB
    'Application' = 524288000   # 500 MB
}

function Invoke-Checks {
    # C1 – Key event log configuration
    foreach ($logName in @('Security','System','Application')) {
        try {
            $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
            # Enabled check
            if (-not $log.IsEnabled) {
                Add-Finding "W08-C1-$logName" "$logName Log Enabled" 'High' 'FAIL' `
                    "$logName event log is DISABLED" `
                    "Enable: wevtutil sl $logName /e:true"
            } else {
                Add-Finding "W08-C1-$logName" "$logName Log Enabled" 'High' 'PASS' "$logName log is enabled" ''
            }

            # Size check
            $minSize = $minLogSizes[$logName]
            $maxSizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB, 0)
            if ($log.MaximumSizeInBytes -lt $minSize) {
                Add-Finding "W08-C2-$logName" "$logName Log Size" 'Med' 'WARN' `
                    "MaxSize=$($maxSizeMB)MB (< $([math]::Round($minSize/1MB,0))MB recommended)" `
                    "Increase: wevtutil sl $logName /ms:$minSize"
            } else {
                Add-Finding "W08-C2-$logName" "$logName Log Size" 'Med' 'PASS' "MaxSize=$($maxSizeMB)MB (adequate)" ''
            }

            # Retention policy (should not be auto-overwrite without archive for Security log)
            if ($logName -eq 'Security' -and $log.LogMode -eq 'Circular') {
                Add-Finding "W08-C3-$logName" "$logName Retention Policy" 'Med' 'WARN' `
                    'Security log is circular (may overwrite without archiving)' `
                    'Consider archiving to SIEM or enabling log forwarding'
            } else {
                Add-Finding "W08-C3-$logName" "$logName Retention Policy" 'Med' 'PASS' `
                    "LogMode=$($log.LogMode)" ''
            }
        } catch {
            Add-Finding "W08-C1-$logName" "$logName Log Check" 'High' 'WARN' "Error: $_" 'Run as administrator'
        }
    }

    # C4 – Audit policy – key categories via auditpol
    try {
        $auditpol = & auditpol /get /category:* 2>&1
        # Map display name used in output -> canonical category name for /set
        $requiredAudits = @{
            'Logon'              = 'Logon/Logoff'
            'Account Logon'      = 'Account Logon'
            'Object Access'      = 'Object Access'
            'Privilege Use'      = 'Privilege Use'
            'Process Creation'   = 'Detailed Tracking'
            'Policy Change'      = 'Policy Change'
            'Account Management' = 'Account Management'
        }
        foreach ($key in $requiredAudits.Keys) {
            $categoryName = $requiredAudits[$key]
            $found = $auditpol | Where-Object { $_ -match $key }
            if ($found) {
                $isAudited = $found | Where-Object { $_ -match 'Success|Failure' }
                if ($isAudited) {
                    Add-Finding "W08-C4-$($key -replace ' ','')" "Audit Policy: $key" 'High' 'PASS' `
                        ($found | Select-Object -First 1).Trim() ''
                } else {
                    Add-Finding "W08-C4-$($key -replace ' ','')" "Audit Policy: $key" 'High' 'WARN' `
                        "Category '$categoryName' has No Auditing enabled" `
                        "Enable via: auditpol /set /category:""$categoryName"" /success:enable /failure:enable  (see W09 for subcategory tuning)"
                }
            }
        }
    } catch {
        Add-Finding 'W08-C4' 'Audit Policy' 'High' 'WARN' "auditpol error: $_" 'Run as administrator'
    }

    # C5 – Windows Event Forwarding (WEF) configured
    $wefReg = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager' -ErrorAction SilentlyContinue
    if ($wefReg) {
        Add-Finding 'W08-C5' 'Event Forwarding (WEF)' 'Info' 'PASS' 'Event forwarding subscription manager configured' ''
    } else {
        Add-Finding 'W08-C5' 'Event Forwarding (WEF)' 'Med' 'WARN' 'No WEF subscription manager configured' `
            'Consider configuring Windows Event Forwarding to a central SIEM/log collector'
    }
}

Invoke-Checks

if ($Fix) {
    Write-Warning "⚠  -Fix flag detected. About to increase event log maximum sizes."
    Write-Warning "   Press Ctrl+C within 10 seconds to abort."
    Start-Sleep 10
    $logSizes = @{ Security = 1073741824; System = 524288000; Application = 524288000 }
    foreach ($logName in $logSizes.Keys) {
        if ($PSCmdlet.ShouldProcess($logName, 'Set maximum event log size')) {
            $log = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
            if ($log) {
                $log.MaximumSizeInBytes = $logSizes[$logName]
                $log.SaveChanges()
                Write-Host "Set ${logName} log max size to $($logSizes[$logName] / 1MB)MB." -ForegroundColor Green
            }
        }
    }
}

if ($Json) {
    @{ script='W08_event_log_config'; host=$env:COMPUTERNAME; timestamp=(Get-Date -Format 'o'); findings=$script:findings } | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W08 Event Log Configuration – $env:COMPUTERNAME ===" -ForegroundColor Cyan
    foreach ($f in $script:findings) { Write-Finding $f }
    $fails = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
    $warns = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
    Write-Host ("`nSummary: {0} finding(s), {1} FAIL, {2} WARN" -f $script:findings.Count, $fails, $warns)
}

$exitCode = 0
if (($script:findings | Where-Object { $_.status -eq 'WARN' }).Count -gt 0) { $exitCode = 1 }
if (($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { $exitCode = 2 }
exit $exitCode
