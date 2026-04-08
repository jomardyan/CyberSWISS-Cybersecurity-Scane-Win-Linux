#Requires -Version 5.1
<#
.SYNOPSIS
    W28 - Backup and Recovery Resilience (Windows)
.DESCRIPTION
    Reviews backup tooling, recent backup evidence, ransomware resilience
    controls, restore-point coverage, backup repository permissions, and
    whether backup data is separated from the system volume.
    Read-only by default. Pass -Fix for future remediation support.
.NOTES
    ID         : W28
    Category   : Resilience & Recovery
    Severity   : High
    OS         : Windows 10/11, Windows Server 2016+
    Admin      : Yes
    Language   : PowerShell 5.1+
    Author     : CyberSWISS Security Team
.PARAMETER Json
    Output results in JSON format for SIEM ingestion.
.PARAMETER Fix
    WARNING: No automatic remediation is currently implemented for this script.
.EXAMPLE
    .\W28_backup_recovery_resilience.ps1
    .\W28_backup_recovery_resilience.ps1 -Json
    .\W28_backup_recovery_resilience.ps1 -Fix
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
    param(
        [string]$Id,
        [string]$Name,
        [ValidateSet('Info','Low','Med','High','Critical')]
        [string]$Severity,
        [string]$Status,
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
    param([hashtable]$Finding)
    $color = switch ($Finding.status) {
        'PASS' { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
        default { 'White' }
    }
    Write-Host ("[{0}] [{1}] {2}: {3}" -f $Finding.status, $Finding.severity, $Finding.id, $Finding.name) -ForegroundColor $color
    if ($Finding.detail) {
        Write-Host "       Detail : $($Finding.detail)"
    }
    if ($Finding.status -ne 'PASS' -and $Finding.remediation) {
        Write-Host "       Remedy : $($Finding.remediation)" -ForegroundColor Cyan
    }
}

function Get-ExistingBackupPaths {
    $paths = @(
        'C:\WindowsImageBackup',
        'C:\Backups',
        'D:\Backups',
        'E:\Backups',
        'F:\Backups'
    )
    return @($paths | Where-Object { Test-Path $_ })
}

function Remove-BroadBackupWriteAcl {
    param([string]$Path)

    $acl = Get-Acl -Path $Path -ErrorAction Stop
    $entriesToRemove = @(
        $acl.Access | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            $_.IdentityReference.Value -match 'Everyone|BUILTIN\\Users|Authenticated Users' -and
            $_.FileSystemRights.ToString() -match 'Write|Modify|FullControl'
        }
    )

    if ($entriesToRemove.Count -eq 0) {
        return $false
    }

    if (-not $acl.AreAccessRulesProtected) {
        $acl.SetAccessRuleProtection($true, $true)
    }

    foreach ($entry in $entriesToRemove) {
        [void]$acl.RemoveAccessRule($entry)
    }

    Set-Acl -Path $Path -AclObject $acl -ErrorAction Stop
    return $true
}

function Invoke-Checks {
    $backupTasks = @()
    $tooling = [System.Collections.Generic.List[string]]::new()
    if (Get-Command wbadmin -ErrorAction SilentlyContinue) {
        $tooling.Add('wbadmin')
    }

    try {
        if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
            $backupTasks = @(
                Get-ScheduledTask -ErrorAction Stop | Where-Object {
                    $_.TaskName -match 'backup|wbadmin|veeam|acronis|recovery' -or
                    $_.TaskPath -match 'backup|veeam|acronis'
                }
            )
        }
    } catch {}

    $backupServices = @()
    try {
        $backupServices = @(
            Get-Service -ErrorAction Stop | Where-Object {
                $_.Name -match 'wbengine|VSS|veeam|acronis|backup' -or
                $_.DisplayName -match 'Backup|Veeam|Acronis|Volume Shadow Copy'
            }
        )
    } catch {}

    if ($backupTasks.Count -gt 0 -or $tooling.Count -gt 0 -or $backupServices.Count -gt 0) {
        $detail = @()
        if ($tooling.Count -gt 0) {
            $detail += "tools=$($tooling -join ', ')"
        }
        if ($backupTasks.Count -gt 0) {
            $detail += "tasks=$((($backupTasks | Select-Object -First 5).TaskName) -join ', ')"
        }
        if ($backupServices.Count -gt 0) {
            $detail += "services=$((($backupServices | Select-Object -First 5).Name) -join ', ')"
        }
        Add-Finding 'W28-C1' 'Backup Tooling and Scheduling' 'High' 'PASS' ($detail -join ' | ') ''
    } else {
        Add-Finding 'W28-C1' 'Backup Tooling and Scheduling' 'High' 'WARN' `
            'No backup tooling, scheduled jobs, or backup-related services were detected.' `
            'Deploy Windows Server Backup, enterprise backup agents, or other managed backup orchestration with monitored schedules.'
    }

    $recentEvidence = [System.Collections.Generic.List[string]]::new()
    try {
        $backupLogs = @(Get-WinEvent -ListLog *Windows-Backup* -ErrorAction SilentlyContinue | Where-Object { $_.IsEnabled })
        foreach ($log in $backupLogs) {
            $recentEvent = Get-WinEvent -FilterHashtable @{ LogName = $log.LogName; StartTime = (Get-Date).AddDays(-7) } -MaxEvents 1 -ErrorAction SilentlyContinue
            if ($recentEvent) {
                $recentEvidence.Add("eventlog=$($log.LogName)")
                break
            }
        }
    } catch {}

    foreach ($path in Get-ExistingBackupPaths) {
        try {
            $item = Get-Item -Path $path -ErrorAction Stop
            if ($item.LastWriteTime -ge (Get-Date).AddDays(-7)) {
                $recentEvidence.Add("path=$path")
            }
        } catch {}
    }

    if ($recentEvidence.Count -gt 0) {
        Add-Finding 'W28-C2' 'Recent Backup Evidence' 'High' 'PASS' `
            ("Recent backup evidence found within 7 days: " + ((@($recentEvidence | Select-Object -Unique -First 10)) -join ', ')) ''
    } else {
        Add-Finding 'W28-C2' 'Recent Backup Evidence' 'High' 'WARN' `
            'No recent backup evidence was found in Windows backup logs or common backup paths within the last 7 days.' `
            'Verify backups are executing successfully and that operators receive alerts for missed or failed jobs.'
    }

    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        switch ([int]$mpPreference.EnableControlledFolderAccess) {
            1 {
                Add-Finding 'W28-C3' 'Controlled Folder Access' 'High' 'PASS' `
                    'Controlled Folder Access is enabled.' ''
            }
            2 {
                Add-Finding 'W28-C3' 'Controlled Folder Access' 'Med' 'WARN' `
                    'Controlled Folder Access is in audit mode only.' `
                    'Move Controlled Folder Access from audit to block mode after validating application allow-lists.'
            }
            default {
                Add-Finding 'W28-C3' 'Controlled Folder Access' 'High' 'WARN' `
                    'Controlled Folder Access is disabled.' `
                    'Consider enabling Defender Controlled Folder Access or an equivalent ransomware-resilience control for sensitive data paths.'
            }
        }
    } catch {
        Add-Finding 'W28-C3' 'Controlled Folder Access' 'Med' 'WARN' `
            "Could not query Defender ransomware protection settings: $_" `
            'Review Defender preferences or the equivalent endpoint protection policy manually.'
    }

    try {
        $vssService = Get-Service -Name VSS -ErrorAction SilentlyContinue
        $shadowCopies = @(Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue)
        $restorePoints = @()
        try {
            $restorePoints = @(Get-ComputerRestorePoint -ErrorAction Stop)
        } catch {}

        if ($shadowCopies.Count -gt 0 -or $restorePoints.Count -gt 0) {
            Add-Finding 'W28-C4' 'Restore Point and Shadow Copy Coverage' 'Med' 'PASS' `
                "ShadowCopies=$($shadowCopies.Count), RestorePoints=$($restorePoints.Count), VSS=$($vssService.Status)" ''
        } elseif ($null -ne $vssService) {
            Add-Finding 'W28-C4' 'Restore Point and Shadow Copy Coverage' 'Med' 'WARN' `
                "VSS service state=$($vssService.Status), but no restore points or shadow copies were found." `
                'Review restore point policy, VSS scheduling, and whether alternate recovery snapshots are maintained elsewhere.'
        } else {
            Add-Finding 'W28-C4' 'Restore Point and Shadow Copy Coverage' 'Info' 'INFO' `
                'VSS service information was not available.' `
                'Review whether shadow copies or restore points are intentionally disabled in favor of another recovery mechanism.'
        }
    } catch {
        Add-Finding 'W28-C4' 'Restore Point and Shadow Copy Coverage' 'Med' 'WARN' `
            "Could not inspect shadow copies or restore points: $_" `
            'Review VSS and restore point configuration manually.'
    }

    $existingBackupPaths = @(Get-ExistingBackupPaths)
    if ($existingBackupPaths.Count -eq 0) {
        Add-Finding 'W28-C5' 'Backup Repository Permissions' 'Info' 'INFO' `
            'No common backup repository paths were found to assess ACLs.' `
            'Review the actual backup destination path or appliance share and ensure write access is tightly restricted.'
    } else {
        $aclIssues = [System.Collections.Generic.List[string]]::new()
        foreach ($path in $existingBackupPaths) {
            try {
                $acl = Get-Acl -Path $path -ErrorAction Stop
                foreach ($entry in $acl.Access) {
                    $identity = $entry.IdentityReference.Value
                    $rights = $entry.FileSystemRights.ToString()
                    if ($identity -match 'Everyone|BUILTIN\\Users|Authenticated Users' -and
                        $rights -match 'Write|Modify|FullControl') {
                        $aclIssues.Add("{0}:{1}:{2}" -f $path, $identity, $rights)
                    }
                }
            } catch {
                $aclIssues.Add("{0}:ACL-read-failed" -f $path)
            }
        }

        if ($aclIssues.Count -gt 0) {
            Add-Finding 'W28-C5' 'Backup Repository Permissions' 'High' 'FAIL' `
                ("Broad write access detected on backup storage: " + ((@($aclIssues | Select-Object -First 10)) -join ' | ')) `
                'Restrict backup paths to backup operators and service accounts only. Remove Everyone/Users write access and enable repository encryption where possible.'
        } else {
            Add-Finding 'W28-C5' 'Backup Repository Permissions' 'Med' 'PASS' `
                ("No broad write ACLs were detected on common backup paths: " + ($existingBackupPaths -join ', ')) ''
        }
    }

    if ($existingBackupPaths.Count -gt 0) {
        $nonSystemPaths = @($existingBackupPaths | Where-Object { $_ -notlike 'C:\*' })
        if ($nonSystemPaths.Count -gt 0) {
            Add-Finding 'W28-C6' 'Backup Location Separation' 'High' 'PASS' `
                ("Backup data exists on non-system path(s): " + ($nonSystemPaths -join ', ')) ''
        } else {
            Add-Finding 'W28-C6' 'Backup Location Separation' 'High' 'WARN' `
                ("Backup data appears to be stored only on the system drive: " + ($existingBackupPaths -join ', ')) `
                'Maintain backup copies on non-system storage, protected network shares, or offline/off-host targets so OS drive compromise does not erase recovery data.'
        }
    } else {
        Add-Finding 'W28-C6' 'Backup Location Separation' 'High' 'WARN' `
            'No local backup destination path was identified.' `
            'Ensure at least one backup copy is separated from the system drive and from the primary administrative boundary.'
    }

    if ($Fix) {
        if ($existingBackupPaths.Count -eq 0) {
            Write-Warning 'No common backup paths were found to harden.'
        } else {
            $updatedPaths = [System.Collections.Generic.List[string]]::new()
            $manualReview = [System.Collections.Generic.List[string]]::new()

            foreach ($path in $existingBackupPaths) {
                try {
                    if ($PSCmdlet.ShouldProcess($path, 'Remove broad non-admin write ACLs from backup storage')) {
                        if (Remove-BroadBackupWriteAcl -Path $path) {
                            $updatedPaths.Add($path)
                        }
                    }
                } catch {
                    $manualReview.Add("{0}: {1}" -f $path, $_.Exception.Message)
                }
            }

            if ($updatedPaths.Count -gt 0) {
                Write-Host ("Hardened backup ACLs on: " + ($updatedPaths -join ', ')) -ForegroundColor Green
            } else {
                Write-Host 'No broad write ACLs needed remediation on the detected backup paths.' -ForegroundColor Cyan
            }

            if ($manualReview.Count -gt 0) {
                Write-Warning ("Manual review still required: " + ($manualReview -join ' | '))
            }
        }

        Write-Warning 'Backup architecture, off-host copies, and restore workflow validation still require environment-specific review.'
    }
}

Invoke-Checks

if ($Json) {
    @{
        script    = 'W28_backup_recovery_resilience'
        host      = $env:COMPUTERNAME
        timestamp = (Get-Date -Format 'o')
        findings  = $script:findings
    } | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W28 Backup and Recovery Resilience - $env:COMPUTERNAME ===" -ForegroundColor Cyan
    foreach ($finding in $script:findings) {
        Write-Finding $finding
    }
    $fails = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
    $warns = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
    Write-Host ("`nSummary: {0} finding(s), {1} FAIL, {2} WARN" -f $script:findings.Count, $fails, $warns)
}

$exitCode = 0
if (($script:findings | Where-Object { $_.status -eq 'WARN' }).Count -gt 0) { $exitCode = 1 }
if (($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { $exitCode = 2 }
exit $exitCode
