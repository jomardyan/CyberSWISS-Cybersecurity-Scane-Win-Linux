#Requires -Version 5.1
<#
.SYNOPSIS
    W14 – Scheduled Tasks Persistence Review (Windows)
.DESCRIPTION
    Enumerates all scheduled tasks, identifies tasks running from unusual
    locations (AppData, Temp, ProgramData), tasks with high privileges,
    and tasks created by non-standard accounts. Read-only defensive inspection.
    Read-only by default. Pass -Fix to apply remediation where available.
.NOTES
    ID       : W14
    Category : Persistence & Scheduled Tasks
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
    .\W14_scheduled_tasks.ps1
    .\W14_scheduled_tasks.ps1 -Json
    .\W14_scheduled_tasks.ps1 -Fix
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
    $color = switch ($f.status) { 'PASS'{'Green'} 'WARN'{'Yellow'} 'FAIL'{'Red'} 'INFO'{'Cyan'} default{'White'} }
    Write-Host ("[{0}] [{1}] {2}: {3}" -f $f.status,$f.severity,$f.id,$f.name) -ForegroundColor $color
    if ($f.detail)      { Write-Host "       Detail : $($f.detail)" }
    if ($f.status -notin 'PASS','INFO' -and $f.remediation) { Write-Host "       Remedy : $($f.remediation)" -ForegroundColor Cyan }
}

# Suspicious execution locations (persistence indicators)
$suspiciousPaths = @(
    'AppData', 'Temp', 'tmp', 'ProgramData', 'Public',
    'Downloads', 'Desktop', '%appdata%', '%temp%', '%public%'
)

# Suspicious actions: encoded commands, script blocks, wscript/cscript
$suspiciousPatterns = @(
    '-EncodedCommand', '-enc ', 'powershell\.exe\s*-', 'cmd\.exe\s*/c',
    'wscript', 'cscript', 'mshta', 'regsvr32', 'rundll32',
    'certutil', 'bitsadmin', 'curl\s*https?://', 'wget\s*https?://'
)

function Invoke-Checks {
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop
    } catch {
        Add-Finding 'W14-C0' 'Scheduled Tasks' 'High' 'WARN' "Cannot enumerate tasks: $_" 'Run as administrator'
        return
    }

    $totalTasks = ($tasks | Measure-Object).Count
    Add-Finding 'W14-C1' 'Total Scheduled Tasks' 'Info' 'INFO' "$totalTasks scheduled tasks found" ''

    $suspiciousFound = 0
    $encodedFound    = 0
    $suspiciousTaskList = [System.Collections.Generic.List[string]]::new()

    foreach ($task in $tasks) {
        $taskPath    = $task.TaskPath
        $taskName    = $task.TaskName
        $state       = $task.State
        $principal   = $task.Principal
        $runLevel    = if ($principal) { $principal.RunLevel } else { 'Unknown' }
        $userId      = if ($principal) { $principal.UserId } else { 'Unknown' }

        # Get task action(s)
        $actions = $task.Actions
        foreach ($action in $actions) {
            $execute  = if ($action.Execute)  { $action.Execute }  else { '' }
            $argument = if ($action.Arguments){ $action.Arguments }else { '' }
            $cmdLine  = "$execute $argument"

            # Check for suspicious paths
            $suspPath = $suspiciousPaths | Where-Object { $cmdLine -ilike "*$_*" }
            if ($suspPath -and $state -ne 'Disabled') {
                $msg = "Task '$taskName' runs from suspicious path ($suspPath): $cmdLine"
                Add-Finding "W14-C2-$suspiciousFound" "Suspicious Task Path: $taskName" 'High' 'WARN' `
                    $msg "Investigate this task: Get-ScheduledTaskInfo -TaskName '$taskName'; disable if unauthorised"
                $suspiciousFound++
                $suspiciousTaskList.Add($taskName)
            }

            # Check for encoded or obfuscated commands (use -imatch for regex patterns)
            $suspCmd = $suspiciousPatterns | Where-Object { $cmdLine -imatch $_ }
            if ($suspCmd) {
                Add-Finding "W14-C3-$encodedFound" "Suspicious Task Command: $taskName" 'High' 'WARN' `
                    "Task '$taskName' uses suspicious pattern '$suspCmd': $($cmdLine.Substring(0,[Math]::Min(200,$cmdLine.Length)))" `
                    "Review task details: Get-ScheduledTask -TaskName '$taskName' | Select *"
                $encodedFound++
                $suspiciousTaskList.Add($taskName)
            }
        }

        # Flag tasks running as SYSTEM with highest run level
        if ($userId -match 'SYSTEM|NT AUTHORITY' -and $runLevel -eq 'Highest' -and $state -ne 'Disabled') {
            # Only flag non-standard (non-Microsoft) task paths
            if ($taskPath -notmatch '\\Microsoft\\') {
                Add-Finding "W14-C4-$taskName" "SYSTEM HighestPriv Task: $taskName" 'Med' 'WARN' `
                    "Task '$taskName' runs as $userId with RunLevel=Highest" `
                    'Verify this task is authorised and required; check task action'
            }
        }
    }

    if ($suspiciousFound -eq 0 -and $encodedFound -eq 0) {
        Add-Finding 'W14-C2' 'Suspicious Task Actions' 'High' 'PASS' 'No obviously suspicious task actions detected' ''
    }
}

Invoke-Checks

if ($Fix) {
    Write-Warning "⚠  -Fix flag: No automatic remediation for scheduled task findings."
    Write-Host "   Removing scheduled tasks automatically could disrupt legitimate operations." -ForegroundColor Cyan
    Write-Host "   Review findings and disable suspicious tasks via: Disable-ScheduledTask -TaskName <name>" -ForegroundColor Cyan
}

if ($Json) {
    @{ script='W14_scheduled_tasks'; host=$env:COMPUTERNAME; timestamp=(Get-Date -Format 'o'); findings=$script:findings } | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W14 Scheduled Tasks Review – $env:COMPUTERNAME ===" -ForegroundColor Cyan
    foreach ($f in $script:findings) { Write-Finding $f }
    $fails = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
    $warns = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
    Write-Host ("`nSummary: {0} finding(s), {1} FAIL, {2} WARN" -f $script:findings.Count, $fails, $warns)
}

$exitCode = 0
if (($script:findings | Where-Object { $_.status -eq 'WARN' }).Count -gt 0) { $exitCode = 1 }
if (($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { $exitCode = 2 }
exit $exitCode
