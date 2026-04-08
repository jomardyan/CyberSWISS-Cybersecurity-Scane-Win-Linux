#Requires -Version 5.1
<#
.SYNOPSIS
    W04 – Windows Services Audit
.DESCRIPTION
    Enumerates running and auto-start services. Flags services running as
    SYSTEM/LocalSystem with suspicious executable paths, services with
    unquoted paths, and known insecure legacy services.
    Read-only by default. Pass -Fix to apply remediation where available.
.NOTES
    ID       : W04
    Category : Services/Daemons & Insecure Defaults
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
    .\W04_services_audit.ps1
    .\W04_services_audit.ps1 -Json
    .\W04_services_audit.ps1 -Fix
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

# Known legacy/insecure services that should be disabled
$legacyServices = @{
    'Telnet'     = 'Telnet service – plaintext remote access'
    'RemoteRegistry' = 'Remote Registry – allows remote registry modifications'
    'SNMP'       = 'SNMP v1/v2 – known weak authentication'
    'SNMPTrap'   = 'SNMP Trap – associated with legacy SNMP'
    'TlntSvr'    = 'Telnet Server'
    'W3SVC'      = 'IIS – review if not intentionally deployed'
    'WMSvc'      = 'IIS Management – review if not intentionally deployed'
    'SharedAccess'='Internet Connection Sharing – should be disabled'
    'XblGameSave'= 'Xbox Live Game Save – non-enterprise service'
}

function Invoke-Checks {
    # Get all services via WMI for full details
    $allServices = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue

    # C1 – Unquoted service executable paths (privilege escalation indicator)
    $unquoted = $allServices | Where-Object {
        $_.PathName -and
        $_.PathName -notmatch '^"' -and
        $_.PathName -match ' ' -and
        $_.PathName -notmatch '^[A-Z]:\\Windows\\'
    }
    if ($unquoted) {
        foreach ($svc in $unquoted) {
            Add-Finding 'W04-C1' "Unquoted Path: $($svc.Name)" 'High' 'FAIL' `
                "Path: $($svc.PathName)" `
                'Enclose the service ImagePath in double quotes via registry or service configuration'
        }
    } else {
        Add-Finding 'W04-C1' 'Unquoted Service Paths' 'High' 'PASS' 'No unquoted service paths found' ''
    }

    # C2 – Services running as LocalSystem/SYSTEM with non-standard paths
    $systemServices = $allServices | Where-Object {
        $_.StartName -in 'LocalSystem','.\LocalSystem','NT AUTHORITY\SYSTEM' -and
        $_.State -eq 'Running' -and
        $_.PathName -and
        $_.PathName -notmatch '^"?[A-Z]:\\Windows\\'
    }
    if ($systemServices) {
        foreach ($svc in ($systemServices | Select-Object -First 10)) {
            Add-Finding 'W04-C2' "SYSTEM svc non-std path: $($svc.Name)" 'Med' 'WARN' `
                "Path: $($svc.PathName)" `
                'Review whether this service legitimately runs as SYSTEM; prefer a least-privilege service account'
        }
    } else {
        Add-Finding 'W04-C2' 'SYSTEM Services with Non-Standard Paths' 'Med' 'PASS' 'None detected' ''
    }

    # C3 – Known legacy/insecure services that are running or auto-start
    $legacyFound = $false
    foreach ($svcName in $legacyServices.Keys) {
        $svc = $allServices | Where-Object { $_.Name -eq $svcName } | Select-Object -First 1
        if ($svc -and $svc.State -eq 'Running') {
            Add-Finding 'W04-C3' "Legacy Service Running: $svcName" 'High' 'FAIL' `
                $legacyServices[$svcName] `
                "Disable: Stop-Service '$svcName'; Set-Service '$svcName' -StartupType Disabled"
            $legacyFound = $true
        }
    }
    if (-not $legacyFound) {
        Add-Finding 'W04-C3' 'Legacy/Insecure Services' 'High' 'PASS' 'No known legacy services running' ''
    }

    # C4 – Services with writable executable directories (non-admin)
    $writablePathFound = $false
    $runningNonSystem = $allServices | Where-Object { $_.State -eq 'Running' -and $_.PathName }
    foreach ($svc in $runningNonSystem | Select-Object -First 50) {
        $exePath = $svc.PathName -replace '^"([^"]+)".*','$1' -replace '^(\S+).*','$1'
        $dir = Split-Path $exePath -Parent -ErrorAction SilentlyContinue
        if ($dir -and (Test-Path $dir)) {
            $acl = Get-Acl $dir -ErrorAction SilentlyContinue
            if ($acl) {
                $writeRules = $acl.Access | Where-Object {
                    $_.IdentityReference -match 'Everyone|BUILTIN\\Users|Authenticated Users' -and
                    $_.FileSystemRights -match 'Write|FullControl|Modify'
                }
                if ($writeRules) {
                    Add-Finding 'W04-C4' "Writable Service Dir: $($svc.Name)" 'High' 'FAIL' `
                        "Dir: $dir is writable by $($writeRules[0].IdentityReference)" `
                        'Restrict write access to service executable directory'
                    $writablePathFound = $true
                }
            }
        }
    }
    if (-not $writablePathFound) {
        Add-Finding 'W04-C4' 'Service Directory Permissions' 'High' 'PASS' 'No writable service directories detected (sample)' ''
    }

    # C5 – Summary info
    $runningCount = ($allServices | Where-Object { $_.State -eq 'Running' }).Count
    $autoCount    = ($allServices | Where-Object { $_.StartMode -eq 'Auto' }).Count
    Add-Finding 'W04-C5' 'Services Summary' 'Info' 'INFO' `
        "$runningCount running, $autoCount auto-start services" ''
}

Invoke-Checks

if ($Fix) {
    Write-Warning "⚠  -Fix flag detected. About to stop and disable insecure legacy services."
    Write-Warning "   Press Ctrl+C within 10 seconds to abort."
    Start-Sleep 10
    $insecureSvcs = @('telnet','ftpsvc','simptcp','snmptrap','RasAuto','RemoteRegistry')
    foreach ($svcName in $insecureSvcs) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            if ($PSCmdlet.ShouldProcess($svcName, 'Stop and disable service')) {
                Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
                Set-Service  -Name $svcName -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Host "Stopped and disabled: $svcName" -ForegroundColor Green
            }
        }
    }
}

if ($Json) {
    @{ script='W04_services_audit'; host=$env:COMPUTERNAME; timestamp=(Get-Date -Format 'o'); findings=$script:findings } | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W04 Services Audit – $env:COMPUTERNAME ===" -ForegroundColor Cyan
    foreach ($f in $script:findings) { Write-Finding $f }
    $fails = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
    $warns = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
    Write-Host ("`nSummary: {0} finding(s), {1} FAIL, {2} WARN" -f $script:findings.Count, $fails, $warns)
}

$exitCode = 0
if (($script:findings | Where-Object { $_.status -eq 'WARN' }).Count -gt 0) { $exitCode = 1 }
if (($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { $exitCode = 2 }
exit $exitCode
