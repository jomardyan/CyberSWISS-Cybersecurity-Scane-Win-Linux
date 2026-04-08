#Requires -Version 5.1
<#
.SYNOPSIS
    W17 – Secrets & Credential Exposure Scan (Windows)
.DESCRIPTION
    Scans for hardcoded credentials, exposed API keys, cloud credential files,
    PowerShell history with secrets, registry credential storage, and IIS/web
    application configuration files containing sensitive data.
    Read-only by default. Pass -Fix to apply remediation where available.
.NOTES
    ID         : W17
    Category   : Secrets & Credential Exposure
    Severity   : Critical
    OS         : Windows 10/11, Server 2016+
    Admin      : Yes
    Language   : PowerShell 5.1+
    Author     : CyberSWISS Security Team
.PARAMETER Json
    Output results in JSON format for SIEM ingestion.
.PARAMETER Fix
    WARNING: Applies recommended baseline values. Off by default. Use with caution.
.EXAMPLE
    .\W17_secrets_scan.ps1
    .\W17_secrets_scan.ps1 -Json
    .\W17_secrets_scan.ps1 -Fix
#>
[CmdletBinding()]
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

    # C1 – .env files with secrets in user profiles and IIS paths
    $secretPattern = 'PASSWORD\s*=|SECRET\s*=|API_KEY\s*=|TOKEN\s*='
    $envSearchPaths = @($env:USERPROFILE, 'C:\inetpub') | Where-Object { Test-Path $_ }
    $envFilesFound  = [System.Collections.Generic.List[string]]::new()
    foreach ($searchPath in $envSearchPaths) {
        Get-ChildItem -Path $searchPath -Recurse -Filter '.env' -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $content = Get-Content $_.FullName -ErrorAction SilentlyContinue
                if ($content -match $secretPattern) { $envFilesFound.Add($_.FullName) }
            } catch {}
        }
    }
    if ($envFilesFound.Count -gt 0) {
        Add-Finding 'W17-C1' '.env Files with Secrets' 'Critical' 'FAIL' `
            "$($envFilesFound.Count) .env file(s) contain secret-like patterns: $($envFilesFound -join '; ')" `
            'Remove plaintext secrets from .env files. Use Windows Credential Manager, Azure Key Vault, or environment-level secret stores.'
    } else {
        Add-Finding 'W17-C1' '.env Files with Secrets' 'Critical' 'PASS' `
            'No .env files with obvious secret patterns found in scanned paths.' ''
    }

    # C2 – PowerShell history files containing sensitive keywords
    $historyPattern = 'password|secret|token|apikey|api_key|passwd|credential'
    $historyFiles   = [System.Collections.Generic.List[string]]::new()
    $histPaths      = @()
    # Current user history
    $defaultHist = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $defaultHist) { $histPaths += $defaultHist }
    # All user profiles
    Get-ChildItem 'C:\Users' -ErrorAction SilentlyContinue | ForEach-Object {
        $p = "$($_.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path $p) { $histPaths += $p }
    }
    foreach ($hf in ($histPaths | Select-Object -Unique)) {
        try {
            $content = Get-Content $hf -ErrorAction SilentlyContinue
            if ($content -imatch $historyPattern) { $historyFiles.Add($hf) }
        } catch {}
    }
    if ($historyFiles.Count -gt 0) {
        Add-Finding 'W17-C2' 'PS History Secret Exposure' 'Critical' 'FAIL' `
            "Sensitive keywords found in $($historyFiles.Count) history file(s): $($historyFiles -join '; ')" `
            'Clear affected history files. Avoid passing secrets as command-line arguments. Use SecureString or vaults.'
    } else {
        Add-Finding 'W17-C2' 'PS History Secret Exposure' 'High' 'PASS' `
            'No secret-like keywords found in PowerShell history files.' ''
    }

    # C3 – Registry plaintext credentials
    $regIssues = [System.Collections.Generic.List[string]]::new()
    try {
        $autoLogon = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' `
            -Name 'DefaultPassword' -ErrorAction SilentlyContinue).DefaultPassword
        if (![string]::IsNullOrEmpty($autoLogon)) {
            $regIssues.Add('AutoLogon DefaultPassword is set in Winlogon registry key')
        }
    } catch {}
    $puttyPath = 'HKCU:\Software\SimonTatham\PuTTY\Sessions'
    if (Test-Path $puttyPath) {
        try {
            $sessions = Get-ChildItem $puttyPath -ErrorAction SilentlyContinue
            $pwSessions = $sessions | Where-Object {
                (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ProxyPassword -ne $null -or
                (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).PublicKeyFile -ne $null
            }
            if ($pwSessions) { $regIssues.Add("PuTTY sessions with stored credentials: $($pwSessions.PSChildName -join ', ')") }
        } catch {}
    }
    if ($regIssues.Count -gt 0) {
        Add-Finding 'W17-C3' 'Registry Plaintext Credentials' 'Critical' 'FAIL' `
            ($regIssues -join ' | ') `
            'Remove AutoLogon credentials: clear DefaultPassword in HKLM:\...\Winlogon. Avoid storing passwords in PuTTY session registry.'
    } else {
        Add-Finding 'W17-C3' 'Registry Plaintext Credentials' 'High' 'PASS' `
            'No AutoLogon plaintext passwords or PuTTY credential entries found.' ''
    }

    # C4 – IIS configuration secrets
    $iisConfigFiles = @(
        'C:\inetpub\wwwroot\web.config',
        'C:\Windows\System32\inetsrv\config\applicationHost.config'
    )
    $iisSecretFiles = [System.Collections.Generic.List[string]]::new()
    foreach ($cfgFile in $iisConfigFiles) {
        if (Test-Path $cfgFile) {
            try {
                $content = Get-Content $cfgFile -ErrorAction SilentlyContinue
                if ($content -imatch 'password\s*=' -or $content -imatch 'connectionString.*password') {
                    $iisSecretFiles.Add($cfgFile)
                }
            } catch {}
        }
    }
    if ($iisSecretFiles.Count -gt 0) {
        Add-Finding 'W17-C4' 'IIS Configuration Secrets' 'Critical' 'FAIL' `
            "Plaintext password patterns in IIS config: $($iisSecretFiles -join '; ')" `
            'Encrypt connection strings using aspnet_regiis -pe. Store secrets in Azure Key Vault or Windows DPAPI.'
    } else {
        Add-Finding 'W17-C4' 'IIS Configuration Secrets' 'High' 'PASS' `
            'No obvious plaintext passwords found in IIS configuration files.' ''
    }

    # C5 – Cloud credential files exposed
    $cloudPaths = @(
        @{ Path = "$env:USERPROFILE\.aws\credentials";  Name = 'AWS credentials file' }
        @{ Path = "$env:APPDATA\gcloud";                Name = 'GCloud credentials directory' }
        @{ Path = "$env:USERPROFILE\.azure";            Name = 'Azure credentials directory' }
    )
    $cloudFound = [System.Collections.Generic.List[string]]::new()
    foreach ($cp in $cloudPaths) {
        if (Test-Path $cp.Path) { $cloudFound.Add($cp.Name) }
    }
    if ($cloudFound.Count -gt 0) {
        Add-Finding 'W17-C5' 'Cloud Credential Files' 'High' 'WARN' `
            "Cloud credential files/dirs present: $($cloudFound -join ', ')" `
            'Verify cloud credential files have restrictive ACLs. Use managed identities or credential helpers instead of static key files.'
    } else {
        Add-Finding 'W17-C5' 'Cloud Credential Files' 'Med' 'PASS' `
            'No cloud credential files detected in user profile.' ''
    }

    # C6 – Git repositories with sensitive history / missing .gitignore
    $gitSearchPaths = @('C:\Users', 'C:\inetpub', 'C:\opt') | Where-Object { Test-Path $_ }
    $gitIssues      = [System.Collections.Generic.List[string]]::new()
    foreach ($gPath in $gitSearchPaths) {
        Get-ChildItem -Path $gPath -Recurse -Filter '.git' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $repoRoot     = $_.Parent.FullName
            $gitignorePath = Join-Path $repoRoot '.gitignore'
            if (-not (Test-Path $gitignorePath)) {
                $gitIssues.Add("Missing .gitignore in $repoRoot")
            } else {
                $gi = Get-Content $gitignorePath -ErrorAction SilentlyContinue
                if ($gi -notmatch '\.env') { $gitIssues.Add(".gitignore in $repoRoot does not exclude .env files") }
            }
        }
    }
    if ($gitIssues.Count -gt 0) {
        Add-Finding 'W17-C6' 'Git Repo Secret Controls' 'High' 'WARN' `
            "$($gitIssues.Count) issue(s): $($gitIssues[0..2] -join ' | ')" `
            'Ensure every git repository has a .gitignore that excludes .env, *.key, credentials*, and secrets*.'
    } else {
        Add-Finding 'W17-C6' 'Git Repo Secret Controls' 'Med' 'PASS' `
            'Git repositories found all have .gitignore with .env exclusion, or no repositories found.' ''
    }

    # C7 – Windows Credential Manager check
    try {
        $cmdkeyOutput = & cmdkey /list 2>&1
        $storedCreds  = $cmdkeyOutput | Where-Object { $_ -match 'Target:|User:' }
        $domainCreds  = $cmdkeyOutput | Where-Object { $_ -imatch 'domain|TERMSRV|MicrosoftOffice' }
        if ($domainCreds) {
            Add-Finding 'W17-C7' 'Windows Credential Manager' 'Med' 'WARN' `
                "Stored domain/service credentials found ($($storedCreds.Count) entries). Domain/terminal entries: $($domainCreds.Count)" `
                'Review stored credentials: cmdkey /list. Remove unnecessary entries: cmdkey /delete:<target>. Prefer certificate or MFA-based auth.'
        } elseif ($storedCreds) {
            Add-Finding 'W17-C7' 'Windows Credential Manager' 'Low' 'INFO' `
                "$($storedCreds.Count / 2) credential entry/entries stored in Windows Credential Manager." ''
        } else {
            Add-Finding 'W17-C7' 'Windows Credential Manager' 'Low' 'PASS' `
                'No credentials stored in Windows Credential Manager.' ''
        }
    } catch {
        Add-Finding 'W17-C7' 'Windows Credential Manager' 'Low' 'WARN' `
            "Could not query Credential Manager: $_" 'Run as the target user context.'
    }
}
#endregion

#region ── Output ────────────────────────────────────────────────────────────────
Invoke-Checks

if ($Fix) {
    Write-Warning "⚠  -Fix flag detected: Secrets require manual remediation."
    Write-Warning "   Automated removal of secrets is not performed to avoid data loss."
    Write-Host '   Guidance:' -ForegroundColor Cyan
    Write-Host '   - Use Windows Credential Manager: cmdkey /add:<target> /user:<user> /pass:<pass>' -ForegroundColor Cyan
    Write-Host '   - Azure Key Vault: https://docs.microsoft.com/azure/key-vault/' -ForegroundColor Cyan
    Write-Host '   - HashiCorp Vault: https://www.vaultproject.io/' -ForegroundColor Cyan
    Write-Host '   - See: https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/' -ForegroundColor Cyan
}

if ($Json) {
    $result = @{
        script    = 'W17_secrets_scan'
        host      = $env:COMPUTERNAME
        timestamp = (Get-Date -Format 'o')
        findings  = $script:findings
    }
    $result | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W17 Secrets & Credential Exposure Scan – $env:COMPUTERNAME ===" -ForegroundColor Cyan
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
