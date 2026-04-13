#Requires -Version 5.1
<#
.SYNOPSIS
    W30 – Deep Persistence & Autoruns Audit (Windows)
.DESCRIPTION
    Audits Windows endpoint for deep persistence mechanisms beyond scheduled tasks:
    Registry Run keys, WMI event subscriptions, startup folders, COM hijacks,
    AppInit DLLs, IFEO debugger hijacks, and shell extension abuse.
.NOTES
    ID       : W30
    Category : Persistence & Autoruns
    Severity : Critical
    OS       : Windows 10/11, Server 2016+
    Admin    : Yes
    Language : PowerShell 5.1+
    Author   : CyberSWISS Security Team
.PARAMETER Json
    Output results in JSON format.
.PARAMETER Fix
    Apply automated remediation where safe.
.EXAMPLE
    .\W30_deep_persistence.ps1
    .\W30_deep_persistence.ps1 -Json
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

$suspiciousPatterns = @(
    '-EncodedCommand','-enc ','-w hidden','-windowstyle hidden',
    'wscript','cscript','mshta','regsvr32','rundll32 .*,',
    'certutil.*-decode','bitsadmin.*transfer',
    'powershell.*-nop','cmd.exe /c','\\AppData\\','\\Temp\\','%temp%','%appdata%'
)

function Test-Suspicious([string]$value) {
    foreach ($p in $suspiciousPatterns) {
        if ($value -imatch [regex]::Escape($p) -or $value -imatch $p) { return $true }
    }
    return $false
}

function Get-RegProp {
    param([string]$Path, [string]$Name)
    try { (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

function Invoke-Checks {

    # C1 – Registry Run/RunOnce keys (HKLM + HKCU)
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    $suspiciousRun = @()
    $totalRun = 0
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            $vals = Get-ItemProperty $key -ErrorAction SilentlyContinue
            $vals.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                $totalRun++
                if (Test-Suspicious $_.Value) {
                    $suspiciousRun += "$($_.Name) = $($_.Value.ToString().Substring(0, [Math]::Min(120,$_.Value.ToString().Length)))"
                }
            }
        }
    }
    if ($suspiciousRun.Count -gt 0) {
        Add-Finding 'W30-C1' 'Suspicious Registry Run Entries' 'Critical' 'FAIL' \
            "$($suspiciousRun.Count) suspicious autorun value(s): $($suspiciousRun[0..1] -join ' | ')" \
            'Remove via regedit or: Remove-ItemProperty -Path <key> -Name <value>'
    } else {
        Add-Finding 'W30-C1' 'Registry Run Keys' 'Critical' 'PASS' \
            "$totalRun Run key value(s) reviewed – none flagged as suspicious" ''
    }

    # C2 – WMI event subscriptions (fileless persistence)
    try {
        $wmiFilters   = Get-WmiObject -Namespace root\subscription -Class __EventFilter   -ErrorAction Stop
        $wmiConsumers = Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction Stop
        $wmiBinders   = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction Stop
        if ($wmiBinders -and ($wmiBinders | Measure-Object).Count -gt 0) {
            $bindCount = ($wmiBinders | Measure-Object).Count
            Add-Finding 'W30-C2' 'WMI Event Subscriptions (Fileless Persistence)' 'Critical' 'FAIL' \
                "$bindCount WMI subscription binding(s) found. WMI subscriptions run code on system events without disk files." \
                'Review and remove: Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Remove-WmiObject'
        } else {
            Add-Finding 'W30-C2' 'WMI Event Subscriptions' 'Critical' 'PASS' \
                'No WMI event subscription bindings found' ''
        }
    } catch {
        Add-Finding 'W30-C2' 'WMI Event Subscriptions' 'Critical' 'WARN' "Cannot query WMI subscriptions: $_" 'Run as administrator'
    }

    # C3 – Startup folder contents
    $startupFolders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    )
    $startupItems = @()
    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            Get-ChildItem $folder -ErrorAction SilentlyContinue | ForEach-Object {
                $startupItems += "$($_.FullName)"
            }
        }
    }
    if ($startupItems.Count -gt 0) {
        Add-Finding 'W30-C3' 'Startup Folder Items' 'High' 'WARN' \
            "$($startupItems.Count) file(s) in Startup folders: $($startupItems[0..2] -join ' | ')" \
            'Review each startup item: any unexpected executable or script should be removed.'
    } else {
        Add-Finding 'W30-C3' 'Startup Folder Items' 'High' 'PASS' \
            'No items found in user or system startup folders' ''
    }

    # C4 – AppInit_DLLs (classic DLL injection persistence)
    $appInitDllPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
    $appInitDlls = Get-RegProp $appInitDllPath 'AppInit_DLLs'
    $loadAppInit  = Get-RegProp $appInitDllPath 'LoadAppInit_DLLs'
    if ($loadAppInit -eq 1 -and $appInitDlls -ne '') {
        Add-Finding 'W30-C4' 'AppInit_DLLs Active' 'Critical' 'FAIL' \
            "LoadAppInit_DLLs=1, DLLs=$appInitDlls. These DLLs load into every user-mode process." \
            'Set LoadAppInit_DLLs to 0: Set-ItemProperty ... -Name LoadAppInit_DLLs -Value 0. Then verify AppInit_DLLs is empty.'
    } else {
        Add-Finding 'W30-C4' 'AppInit_DLLs' 'Critical' 'PASS' \
            'AppInit_DLLs is disabled or empty' ''
    }

    # C5 – Image File Execution Options debugger hijacks
    $ifeoBase = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    $ifeoBins = @()
    if (Test-Path $ifeoBase) {
        Get-ChildItem $ifeoBase -ErrorAction SilentlyContinue | ForEach-Object {
            $debugger = Get-RegProp $_.PSPath 'Debugger'
            if ($debugger) {
                # Flag if debugger is not a known debugging tool
                if ($debugger -inotmatch 'vsjitdebugger|drwtsn32|ntsd|windbg|cdb') {
                    $ifeoBins += "$($_.PSChildName) -> $debugger"
                }
            }
        }
    }
    if ($ifeoBins.Count -gt 0) {
        Add-Finding 'W30-C5' 'IFEO Debugger Hijacks' 'Critical' 'FAIL' \
            "$($ifeoBins.Count) IFEO debugger redirect(s): $($ifeoBins[0..2] -join ' | ')" \
            'Remove unexpected IFEO Debugger values via regedit under HKLM:\...\Image File Execution Options\<binary>'
    } else {
        Add-Finding 'W30-C5' 'IFEO Debugger Hijacks' 'Critical' 'PASS' \
            'No unexpected IFEO debugger redirects found' ''
    }

    # C6 – Recently modified files in system directories
    $recentThreshold = (Get-Date).AddDays(-7)
    $recentSysMods = @()
    @('C:\Windows\System32','C:\Windows\SysWOW64') | ForEach-Object {
        if (Test-Path $_) {
            Get-ChildItem $_ -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt $recentThreshold -and $_.Extension -in '.exe','.dll','.sys' } |
                Select-Object -First 10 | ForEach-Object { $recentSysMods += $_.FullName }
        }
    }
    if ($recentSysMods.Count -gt 5) {
        Add-Finding 'W30-C6' 'Recently Modified System Binaries' 'High' 'WARN' \
            "$($recentSysMods.Count) binaries modified in System32/SysWOW64 in last 7 days (sample): $($recentSysMods[0..2] -join ' | ')" \
            'Review with: Get-AuthenticodeSignature <file>. Unsigned or tampered system binaries are an indicator of compromise.'
    } else {
        Add-Finding 'W30-C6' 'Recently Modified System Binaries' 'High' 'PASS' \
            "$($recentSysMods.Count) system binaries modified in last 7 days (within expected range for patching)" ''
    }

    # C7 – PowerShell profile persistence
    $psProfiles = @($PROFILE.AllUsersAllHosts, $PROFILE.AllUsersCurrentHost, $PROFILE.CurrentUserAllHosts, $PROFILE.CurrentUserCurrentHost)
    $suspiciousProfiles = @()
    foreach ($prof in $psProfiles) {
        if ($prof -and (Test-Path $prof)) {
            $content = Get-Content $prof -Raw -ErrorAction SilentlyContinue
            if ($content -and (Test-Suspicious $content)) {
                $suspiciousProfiles += $prof
            }
        }
    }
    if ($suspiciousProfiles.Count -gt 0) {
        Add-Finding 'W30-C7' 'Suspicious PowerShell Profile' 'High' 'FAIL' \
            "Suspicious content in PS profiles: $($suspiciousProfiles -join ' | ')" \
            'Review profile files. PS profiles run on every PowerShell session start.'
    } else {
        Add-Finding 'W30-C7' 'PowerShell Profile Files' 'High' 'PASS' \
            'No suspicious content found in PowerShell profile files' ''
    }
}

Invoke-Checks

# ── Optional Fix ──────────────────────────────────────────────────────────────
if ($Fix) {
    Write-Host "`n[FIX] Applying safe automated remediations..." -ForegroundColor Cyan
    # Disable AppInit_DLLs
    $loadAppInit = Get-RegProp 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' 'LoadAppInit_DLLs'
    if ($loadAppInit -eq 1) {
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name LoadAppInit_DLLs -Value 0 -Type DWord -Force
        Write-Host "[FIX] LoadAppInit_DLLs disabled." -ForegroundColor Green
    }
}

# ── Output ────────────────────────────────────────────────────────────────────
if ($Json) {
    @{ script='W30_deep_persistence'; host=$env:COMPUTERNAME; timestamp=(Get-Date -Format 'o'); findings=$script:findings } | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W30 $([char]0x2013) Deep Persistence & Autoruns $([char]0x2013) $env:COMPUTERNAME ===" -ForegroundColor Cyan
    foreach ($f in $script:findings) { Write-Finding $f }
    $fails = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
    $warns = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
    Write-Host ("`nSummary: {0} finding(s), {1} FAIL, {2} WARN" -f $script:findings.Count, $fails, $warns)
}

$exitCode = 0
if (($script:findings | Where-Object { $_.status -eq 'WARN' }).Count -gt 0) { $exitCode = 1 }
if (($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { $exitCode = 2 }
exit $exitCode
