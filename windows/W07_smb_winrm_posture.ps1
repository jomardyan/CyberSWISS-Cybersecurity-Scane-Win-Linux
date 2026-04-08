#Requires -Version 5.1
<#
.SYNOPSIS
    W07 – SMB / WinRM Posture Check (Windows)
.DESCRIPTION
    Audits SMBv1 status, SMB signing requirements, SMB encryption, and
    WinRM service configuration including authentication methods and TLS usage.
    Read-only by default. Pass -Fix to apply remediation where available.
.NOTES
    ID       : W07
    Category : Network Exposure
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
    .\W07_smb_winrm_posture.ps1
    .\W07_smb_winrm_posture.ps1 -Json
    .\W07_smb_winrm_posture.ps1 -Fix
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

function Invoke-Checks {
    # ── SMB Checks ─────────────────────────────────────────────────────────
    # C1 – SMBv1 disabled
    try {
        $smbv1 = Get-SmbServerConfiguration -ErrorAction Stop | Select-Object -ExpandProperty EnableSMB1Protocol
        if (-not $smbv1) {
            Add-Finding 'W07-C1' 'SMBv1 Status' 'Critical' 'PASS' 'SMBv1 is disabled' ''
        } else {
            Add-Finding 'W07-C1' 'SMBv1 Status' 'Critical' 'FAIL' 'SMBv1 is ENABLED (EternalBlue/WannaCry risk)' `
                'Disable: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force'
        }
    } catch {
        Add-Finding 'W07-C1' 'SMBv1 Status' 'Critical' 'WARN' "Could not check SMBv1: $_" 'Run as administrator'
    }

    # C2 – SMB signing required
    try {
        $smbConfig = Get-SmbServerConfiguration -ErrorAction Stop
        if ($smbConfig.RequireSecuritySignature) {
            Add-Finding 'W07-C2' 'SMB Signing Required' 'High' 'PASS' 'SMB signing is required' ''
        } else {
            Add-Finding 'W07-C2' 'SMB Signing Required' 'High' 'FAIL' 'SMB signing is NOT required (relay attack risk)' `
                'Enable: Set-SmbServerConfiguration -RequireSecuritySignature $true -Force'
        }

        # C3 – SMB encryption
        if ($smbConfig.EncryptData) {
            Add-Finding 'W07-C3' 'SMB Encryption' 'Med' 'PASS' 'SMB encryption is enabled' ''
        } else {
            Add-Finding 'W07-C3' 'SMB Encryption' 'Med' 'WARN' 'SMB encryption is not enabled' `
                'Enable: Set-SmbServerConfiguration -EncryptData $true -Force (may impact legacy clients)'
        }
    } catch {
        Add-Finding 'W07-C2' 'SMB Configuration' 'High' 'WARN' "Error: $_" 'Run as administrator'
    }

    # C4 – SMB shares (world-accessible)
    try {
        $shares = Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -ne 'IPC$' }
        foreach ($share in $shares) {
            $perms = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
            $everyoneAccess = $perms | Where-Object { $_.AccountName -match 'Everyone|BUILTIN\\Users' -and $_.AccessRight -in 'Full','Change' }
            if ($everyoneAccess) {
                Add-Finding "W07-C4-$($share.Name)" "Share Open to Everyone: $($share.Name)" 'High' 'FAIL' `
                    "Share '$($share.Name)' path='$($share.Path)' accessible to Everyone/Users with write" `
                    'Restrict share permissions: Grant-SmbShareAccess or Revoke-SmbShareAccess'
            }
        }
        if (($shares | Measure-Object).Count -gt 0) {
            Add-Finding 'W07-C4-Info' 'SMB Shares' 'Info' 'INFO' `
                "Shares: $(($shares.Name) -join ', ')" ''
        }
    } catch { }

    # ── WinRM Checks ──────────────────────────────────────────────────────────
    $winrmService = Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue

    # C5 – WinRM service state
    if ($winrmService -and $winrmService.Status -eq 'Running') {
        Add-Finding 'W07-C5' 'WinRM Service Running' 'Med' 'WARN' `
            'WinRM is running – verify it is intentionally configured' `
            'If not required, disable: Stop-Service WinRM; Set-Service WinRM -StartupType Disabled'

        # C6 – WinRM authentication – check for Basic auth (sends credentials in plaintext over HTTP)
        try {
            $winrmConfig = winrm get winrm/config/service/auth 2>&1
            if ($winrmConfig -match 'Basic\s*=\s*true') {
                Add-Finding 'W07-C6' 'WinRM Basic Auth' 'High' 'FAIL' `
                    'WinRM Basic authentication is enabled (credentials exposed over HTTP)' `
                    'Disable: winrm set winrm/config/service/auth @{Basic="false"}'
            } else {
                Add-Finding 'W07-C6' 'WinRM Basic Auth' 'High' 'PASS' 'WinRM Basic authentication is disabled' ''
            }
        } catch {
            Add-Finding 'W07-C6' 'WinRM Auth Check' 'High' 'WARN' "Could not read WinRM auth config: $_" ''
        }

        # C7 – WinRM HTTPS listener
        try {
            $httpsListener = winrm enumerate winrm/config/listener 2>&1 | Select-String 'Transport\s*=\s*HTTPS'
            if ($httpsListener) {
                Add-Finding 'W07-C7' 'WinRM HTTPS Listener' 'Med' 'PASS' 'WinRM HTTPS listener is configured' ''
            } else {
                Add-Finding 'W07-C7' 'WinRM HTTPS Listener' 'Med' 'WARN' 'WinRM HTTP (plaintext) listener in use' `
                    'Configure WinRM over HTTPS with a valid certificate'
            }
        } catch { }
    } else {
        Add-Finding 'W07-C5' 'WinRM Service' 'Med' 'PASS' 'WinRM service is not running' ''
    }
}

Invoke-Checks

if ($Fix) {
    Write-Warning "⚠  -Fix flag detected. About to disable SMBv1."
    Write-Warning "   Press Ctrl+C within 10 seconds to abort."
    Start-Sleep 10
    if ($PSCmdlet.ShouldProcess('SMBv1', 'Disable protocol')) {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
        Write-Host "SMBv1 disabled." -ForegroundColor Green
    }
}

if ($Json) {
    @{ script='W07_smb_winrm_posture'; host=$env:COMPUTERNAME; timestamp=(Get-Date -Format 'o'); findings=$script:findings } | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W07 SMB/WinRM Posture – $env:COMPUTERNAME ===" -ForegroundColor Cyan
    foreach ($f in $script:findings) { Write-Finding $f }
    $fails = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
    $warns = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
    Write-Host ("`nSummary: {0} finding(s), {1} FAIL, {2} WARN" -f $script:findings.Count, $fails, $warns)
}

$exitCode = 0
if (($script:findings | Where-Object { $_.status -eq 'WARN' }).Count -gt 0) { $exitCode = 1 }
if (($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { $exitCode = 2 }
exit $exitCode
