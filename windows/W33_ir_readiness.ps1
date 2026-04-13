#Requires -Version 5.1
<#
.SYNOPSIS
    W33 – Incident Response Readiness (Windows)
.DESCRIPTION
    Audits the Windows endpoint for IR readiness: Sysmon installation, PowerShell
    logging, Windows Event Log forwarding, log retention policies, time sync,
    crash dump settings, and availability of forensic/triage tools.
.NOTES
    ID       : W33
    Category : Detection & Response
    Severity : High
    OS       : Windows 10/11, Server 2016+
    Admin    : Yes
    Language : PowerShell 5.1+
    Author   : CyberSWISS Security Team
.PARAMETER Json
    Output results in JSON format.
.PARAMETER Fix
    Apply automated remediations where safe.
.EXAMPLE
    .\W33_ir_readiness.ps1
    .\W33_ir_readiness.ps1 -Json
    .\W33_ir_readiness.ps1 -Fix
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

    # C1 – Sysmon installed and running
    $sysmonSvc = Get-Service -Name Sysmon,Sysmon64 -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($sysmonSvc -and $sysmonSvc.Status -eq 'Running') {
        Add-Finding 'W33-C1' "Sysmon Running ($($sysmonSvc.Name))" 'High' 'PASS' \
            "Sysmon service is installed and running (providing process, network, file creation telemetry)" ''
    } elseif ($sysmonSvc) {
        Add-Finding 'W33-C1' "Sysmon Installed but Not Running" 'High' 'WARN' \
            "Sysmon service exists but status is: $($sysmonSvc.Status)" \
            "Start: Start-Service $($sysmonSvc.Name); ensure auto-start: Set-Service $($sysmonSvc.Name) -StartupType Automatic"
    } else {
        Add-Finding 'W33-C1' 'Sysmon Not Installed' 'High' 'FAIL' \
            'Sysmon is not installed. Critical telemetry (process creation, network, registry) is missing.' \
            'Download from https://docs.microsoft.com/sysinternals/sysmon; deploy with config: sysmon -accepteula -i sysmonconfig.xml'
    }

    # C2 – PowerShell Script Block Logging
    $psSBLPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $sblEnabled = Get-RegProp $psSBLPath 'EnableScriptBlockLogging'
    if ($sblEnabled -eq 1) {
        Add-Finding 'W33-C2' 'PowerShell Script Block Logging Enabled' 'High' 'PASS' \
            'ScriptBlockLogging is enabled – all PS script content is logged to EID 4104' ''
    } else {
        Add-Finding 'W33-C2' 'PowerShell Script Block Logging Disabled' 'High' 'FAIL' \
            'EnableScriptBlockLogging not set. Malicious PowerShell activity will not be logged at the script level.' \
            'Enable via GP: Computer Configuration > Admin Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging'
    }

    # C3 – PowerShell Module Logging
    $psModPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    $modEnabled = Get-RegProp $psModPath 'EnableModuleLogging'
    if ($modEnabled -eq 1) {
        Add-Finding 'W33-C3' 'PowerShell Module Logging Enabled' 'Med' 'PASS' \
            'Module logging is enabled – pipeline execution details captured to EID 4103' ''
    } else {
        Add-Finding 'W33-C3' 'PowerShell Module Logging Disabled' 'Med' 'WARN' \
            'EnableModuleLogging not set. Pipeline execution details not logged.' \
            'Enable via GP: PowerShell > Turn on Module Logging; set module names to * for coverage'
    }

    # C4 – Windows Event Log: Security retention size
    try {
        $secLog = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security' -ErrorAction Stop
        $maxSize = Get-RegProp $secLog.PSPath 'MaxSize'
        $maxSizeMB = if ($null -ne $maxSize) { [math]::Round($maxSize / 1MB) } else { 20 }   # default 20MB
        if ($maxSizeMB -lt 200) {
            Add-Finding 'W33-C4' 'Security Event Log Retention Too Small' 'High' 'WARN' \
                "Security log max size: ${maxSizeMB} MB. Events may roll over too quickly to capture incident indicators." \
                'Increase: wevtutil sl Security /ms:524288000  (500 MB), or configure via GP'
        } else {
            Add-Finding 'W33-C4' 'Security Event Log Size Adequate' 'High' 'PASS' \
                "Security log max size: ${maxSizeMB} MB" ''
        }
    } catch {
        Add-Finding 'W33-C4' 'Security Event Log Size' 'High' 'INFO' "Could not read Security log settings: $_" ''
    }

    # C5 – Windows Event Forwarding (WEF) source configured
    $wefSources = Get-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager' -ErrorAction SilentlyContinue
    $wefLegacy  = Get-RegProp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding' 'SubscriptionManager'
    if ($wefSources -or $wefLegacy) {
        Add-Finding 'W33-C5' 'Windows Event Forwarding (WEF) Configured' 'High' 'PASS' \
            'WEF SubscriptionManager policy is set – events are being forwarded to a collector' ''
    } else {
        Add-Finding 'W33-C5' 'Windows Event Forwarding Not Configured' 'High' 'WARN' \
            'No WEF subscription manager found. Logs are local only – lost if endpoint is compromised or reimaged.' \
            'Configure WEF: GP > Computer Configuration > Admin Templates > Windows Components > Event Forwarding > Configure forwarder resource usage'
    }

    # C6 – Windows Time service (w32tm)
    $w32svc = Get-Service -Name W32Time -ErrorAction SilentlyContinue
    if ($w32svc -and $w32svc.Status -eq 'Running') {
        $syncStatus = w32tm /query /status 2>$null | Select-String 'Stratum|Source|Last Sync' | Select-Object -First 3
        Add-Finding 'W33-C6' 'Windows Time Service Running' 'High' 'PASS' \
            "W32Time is running. $($syncStatus -join ' | ')" ''
    } else {
        Add-Finding 'W33-C6' 'Windows Time Service Not Running' 'High' 'FAIL' \
            "W32Time status: $(if ($w32svc) { $w32svc.Status } else { 'not found' }). Accurate timestamps are essential for forensic correlation." \
            'Enable: Start-Service W32Time; w32tm /config /manualpeerlist:pool.ntp.org /syncfromflags:manual /reliable:YES /update'
    }

    # C7 – Memory dump configuration
    $crashCtrlPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
    $dumpType = Get-RegProp $crashCtrlPath 'CrashDumpEnabled'
    $dumpTypes = @{ 0='None'; 1='Complete'; 2='Kernel'; 3='Small (minidump)'; 7='Automatic' }
    $dumpName  = $dumpTypes[[int](if ($null -ne $dumpType) { $dumpType } else { 0 })]
    if ($dumpType -in 1, 2, 7) {
        Add-Finding 'W33-C7' "Memory Dump Configured ($dumpName)" 'Med' 'PASS' \
            "CrashDumpEnabled=$dumpType ($dumpName) – system crash evidence is captured" ''
    } else {
        Add-Finding 'W33-C7' "Memory Dump Not Adequately Configured ($dumpName)" 'Med' 'WARN' \
            "CrashDumpEnabled=$dumpType ($dumpName). Kernel crash evidence may be lost." \
            'Set: reg add HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 2 /f (Kernel dump)'
    }

    # C8 – Forensic CLI tools available in PATH
    $requiredTools = @('Get-FileHash','Get-WinEvent','netstat','ipconfig','tasklist','reg','wevtutil','sigcheck')
    $missingTools  = @()
    foreach ($t in @('netstat','ipconfig','tasklist','reg','wevtutil')) {
        if (-not (Get-Command $t -ErrorAction SilentlyContinue)) { $missingTools += $t }
    }
    if ($missingTools.Count -eq 0) {
        Add-Finding 'W33-C8' 'Core Triage Tools Available' 'Med' 'PASS' \
            "Core Windows triage tools found in PATH" ''
    } else {
        Add-Finding 'W33-C8' 'Missing Triage Tools' 'Med' 'WARN' \
            "Missing tools: $($missingTools -join ', ')" \
            'Ensure Windows system32 is in PATH. Consider installing Sysinternals Suite to C:\Tools'
    }
}

Invoke-Checks

# ── Optional Fix ──────────────────────────────────────────────────────────────
if ($Fix) {
    Write-Host "`n[FIX] Applying IR readiness hardening..." -ForegroundColor Cyan

    # Enable Script Block Logging
    $psSBLPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $sblEnabled = Get-RegProp $psSBLPath 'EnableScriptBlockLogging'
    if ($sblEnabled -ne 1) {
        If (-not (Test-Path $psSBLPath)) { New-Item $psSBLPath -Force | Out-Null }
        Set-ItemProperty -Path $psSBLPath -Name EnableScriptBlockLogging -Value 1 -Type DWord -Force
        Write-Host '[FIX] PowerShell Script Block Logging enabled.' -ForegroundColor Green
    }

    # Enable W32Time
    $w32svc = Get-Service -Name W32Time -ErrorAction SilentlyContinue
    if ($w32svc -and $w32svc.Status -ne 'Running') {
        Start-Service W32Time -ErrorAction SilentlyContinue
        Set-Service  W32Time -StartupType Automatic
        Write-Host '[FIX] W32Time started and set to Automatic.' -ForegroundColor Green
    }

    # Increase Security log to 500 MB if smaller than 200 MB
    try {
        $secLog  = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security' -ErrorAction Stop
        $maxSize = Get-RegProp $secLog.PSPath 'MaxSize'
        if ([int](if ($null -ne $maxSize) { $maxSize } else { 0 }) -lt (200 * 1MB)) {
            wevtutil sl Security /ms:524288000 2>$null
            Write-Host '[FIX] Security event log max size set to 500 MB.' -ForegroundColor Green
        }
    } catch {}
}

# ── Output ────────────────────────────────────────────────────────────────────
if ($Json) {
    @{ script='W33_ir_readiness'; host=$env:COMPUTERNAME; timestamp=(Get-Date -Format 'o'); findings=$script:findings } | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W33 $([char]0x2013) Incident Response Readiness $([char]0x2013) $env:COMPUTERNAME ===" -ForegroundColor Cyan
    foreach ($f in $script:findings) { Write-Finding $f }
    $fails = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
    $warns = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
    Write-Host ("`nSummary: {0} finding(s), {1} FAIL, {2} WARN" -f $script:findings.Count, $fails, $warns)
}

$exitCode = 0
if (($script:findings | Where-Object { $_.status -eq 'WARN' }).Count -gt 0) { $exitCode = 1 }
if (($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { $exitCode = 2 }
exit $exitCode
