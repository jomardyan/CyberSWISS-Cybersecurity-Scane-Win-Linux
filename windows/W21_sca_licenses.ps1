#Requires -Version 5.1
<#
.SYNOPSIS
    W21 – Software Composition Analysis & License Compliance (Windows)
.DESCRIPTION
    Performs Software Composition Analysis (SCA) to identify vulnerable
    third-party packages in .NET (NuGet), Node.js (npm), Python (pip),
    and Ruby (gems). Also checks for copyleft license obligations and
    end-of-life software components.
    Read-only by default. Pass -Fix to apply remediation where available.
.NOTES
    ID         : W21
    Category   : SCA & License Compliance
    Severity   : Med
    OS         : Windows 10/11, Server 2016+
    Admin      : No
    Language   : PowerShell 5.1+
    Author     : CyberSWISS Security Team
.PARAMETER Json
    Output results in JSON format for SIEM ingestion.
.PARAMETER Fix
    WARNING: Applies recommended baseline values. Off by default. Use with caution.
.EXAMPLE
    .\W21_sca_licenses.ps1
    .\W21_sca_licenses.ps1 -Json
    .\W21_sca_licenses.ps1 -Fix
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

    $searchRoots = @("$env:USERPROFILE", 'C:\Projects', 'C:\src', 'C:\code', 'C:\inetpub') |
        Where-Object { Test-Path $_ }

    # C1 – NuGet package vulnerabilities
    $dotnetCmd  = Get-Command dotnet -ErrorAction SilentlyContinue
    $nugetFiles = [System.Collections.Generic.List[string]]::new()
    foreach ($root in $searchRoots) {
        Get-ChildItem -Path $root -Recurse -Include 'packages.config','*.csproj' -ErrorAction SilentlyContinue |
            ForEach-Object { $nugetFiles.Add($_.FullName) }
    }

    # Known vulnerable NuGet packages (name -> vulnerable-if-version-below)
    $vulnerableNuGet = @{
        'log4net'          = [version]'2.0.15'
        'Newtonsoft.Json'  = [version]'13.0.0'
        'BouncyCastle'     = [version]'1.9.0'
    }
    $nugetIssues = [System.Collections.Generic.List[string]]::new()

    foreach ($nf in $nugetFiles) {
        try {
            $content = Get-Content $nf -ErrorAction SilentlyContinue -Raw
            foreach ($pkg in $vulnerableNuGet.Keys) {
                # Match package references: <package id="log4net" version="2.0.8" or <PackageReference Include="log4net" Version="2.0.8"
                if ($content -inotmatch [regex]::Escape($pkg)) { continue }
                # Step 1: find the line that references this package
                $pkgLine = ($content -split "`n") | Where-Object { $_ -imatch [regex]::Escape($pkg) } | Select-Object -First 1
                if (-not $pkgLine) { continue }
                # Step 2: extract the version value from that line
                if ($pkgLine -imatch '(?:version)\s*=\s*"([^"]+)"') {
                    $verStr = $Matches[1] -replace '[^0-9.]', ''
                    try {
                        $ver = [version]$verStr
                        if ($ver -lt $vulnerableNuGet[$pkg]) {
                            $nugetIssues.Add("$pkg $verStr < $($vulnerableNuGet[$pkg]) in $nf")
                        }
                    } catch {}
                }
            }
        } catch {}
    }

    if ($dotnetCmd) {
        try {
            $vulnOutput = & dotnet list package --vulnerable --include-transitive 2>&1
            $critVuln   = $vulnOutput | Where-Object { $_ -imatch 'Critical|High' }
            if ($critVuln) { $nugetIssues.Add("dotnet CLI: $($critVuln.Count) Critical/High NuGet vulnerabilities found") }
        } catch {}
    }

    if ($nugetFiles.Count -eq 0 -and $null -eq $dotnetCmd) {
        Add-Finding 'W21-C1' 'NuGet Package Vulnerabilities' 'High' 'INFO' `
            'No NuGet package files found and dotnet CLI not available.' `
            'Install .NET SDK and run: dotnet list package --vulnerable --include-transitive'
    } elseif ($nugetIssues.Count -gt 0) {
        Add-Finding 'W21-C1' 'NuGet Package Vulnerabilities' 'High' 'FAIL' `
            "$($nugetIssues.Count) vulnerable NuGet package(s): $($nugetIssues[0..3] -join ' | ')" `
            'Update vulnerable packages: dotnet add package <name> --version <safe-version>'
    } else {
        Add-Finding 'W21-C1' 'NuGet Package Vulnerabilities' 'High' 'PASS' `
            "Scanned $($nugetFiles.Count) NuGet file(s); no known vulnerable packages detected." ''
    }

    # C2 – npm packages audit
    $npmCmd      = Get-Command npm -ErrorAction SilentlyContinue
    $packageJsons = [System.Collections.Generic.List[string]]::new()
    foreach ($root in $searchRoots) {
        Get-ChildItem -Path $root -Recurse -Filter 'package.json' -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch 'node_modules' } |
            ForEach-Object { $packageJsons.Add($_.FullName) }
    }
    if ($null -eq $npmCmd) {
        Add-Finding 'W21-C2' 'npm Package Audit' 'High' 'INFO' `
            'npm not found in PATH. Cannot perform npm audit.' `
            'Install Node.js and run: npm audit --json in each project directory.'
    } elseif ($packageJsons.Count -eq 0) {
        Add-Finding 'W21-C2' 'npm Package Audit' 'High' 'INFO' `
            'No package.json files found in scanned paths.' ''
    } else {
        $criticalNpm = 0; $highNpm = 0
        foreach ($pj in $packageJsons) {
            $projDir = Split-Path $pj -Parent
            try {
                $auditJson = & npm audit --json --prefix $projDir 2>&1 | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($auditJson -and $auditJson.metadata) {
                    $criticalNpm += $auditJson.metadata.vulnerabilities.critical
                    $highNpm     += $auditJson.metadata.vulnerabilities.high
                }
            } catch {}
        }
        if ($criticalNpm -gt 0) {
            Add-Finding 'W21-C2' 'npm Package Audit' 'Critical' 'FAIL' `
                "$criticalNpm critical and $highNpm high npm vulnerabilities across $($packageJsons.Count) project(s)" `
                'Run: npm audit fix --force (review changes). Update to patched package versions.'
        } elseif ($highNpm -gt 0) {
            Add-Finding 'W21-C2' 'npm Package Audit' 'High' 'WARN' `
                "$highNpm high-severity npm vulnerabilities across $($packageJsons.Count) project(s)" `
                'Run: npm audit fix in affected project directories.'
        } else {
            Add-Finding 'W21-C2' 'npm Package Audit' 'High' 'PASS' `
                "npm audit: no critical or high vulnerabilities in $($packageJsons.Count) project(s)." ''
        }
    }

    # C3 – Python packages (pip)
    $pipCmd = Get-Command pip -ErrorAction SilentlyContinue
    if ($null -eq $pipCmd) { $pipCmd = Get-Command pip3 -ErrorAction SilentlyContinue }
    # Known vulnerable Python packages (name -> vulnerable-if-version-below)
    $vulnerablePip = @{
        'requests'     = [version]'2.28.0'
        'urllib3'      = [version]'1.26.0'
        'cryptography' = [version]'38.0.0'
        'Pillow'       = [version]'9.0.0'
    }
    if ($null -eq $pipCmd) {
        Add-Finding 'W21-C3' 'Python Package Vulnerabilities' 'High' 'INFO' `
            'pip/pip3 not found in PATH.' `
            'Install Python and run: pip list --outdated. Use pip-audit for vulnerability scanning.'
    } else {
        try {
            $pipList = & $pipCmd.Name list --format=json 2>&1 | ConvertFrom-Json -ErrorAction SilentlyContinue
            $pipIssues = [System.Collections.Generic.List[string]]::new()
            if ($pipList) {
                foreach ($pkg in $vulnerablePip.Keys) {
                    $installed = $pipList | Where-Object { $_.name -ieq $pkg }
                    if ($installed) {
                        try {
                            $ver = [version]($installed.version -replace '[^0-9.]','')
                            if ($ver -lt $vulnerablePip[$pkg]) {
                                $pipIssues.Add("$pkg $($installed.version) < $($vulnerablePip[$pkg])")
                            }
                        } catch {}
                    }
                }
            }
            if ($pipIssues.Count -gt 0) {
                Add-Finding 'W21-C3' 'Python Package Vulnerabilities' 'High' 'WARN' `
                    "Outdated/vulnerable packages: $($pipIssues -join ', ')" `
                    'Upgrade: pip install --upgrade <package>. Use pip-audit for full vulnerability scan.'
            } else {
                Add-Finding 'W21-C3' 'Python Package Vulnerabilities' 'High' 'PASS' `
                    'Checked known vulnerable packages; none detected at vulnerable versions.' ''
            }
        } catch {
            Add-Finding 'W21-C3' 'Python Package Vulnerabilities' 'High' 'WARN' `
                "pip list failed: $_" 'Ensure pip is properly installed and accessible.'
        }
    }

    # C4 – Copyleft licenses
    $copyleftLicenses = @('GPL', 'AGPL', 'LGPL', 'GPL-2.0', 'GPL-3.0', 'AGPL-3.0')
    $copyleftFound    = [System.Collections.Generic.List[string]]::new()
    foreach ($pj in $packageJsons) {
        try {
            $pkgData = Get-Content $pj -ErrorAction SilentlyContinue -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($pkgData -and $pkgData.license) {
                $lic = $pkgData.license.ToString()
                if ($copyleftLicenses | Where-Object { $lic -imatch $_ }) {
                    $copyleftFound.Add("$($pkgData.name) ($lic) in $pj")
                }
            }
        } catch {}
    }
    foreach ($root in $searchRoots) {
        Get-ChildItem -Path $root -Recurse -Filter '*.csproj' -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $content = Get-Content $_.FullName -ErrorAction SilentlyContinue -Raw
                foreach ($lic in $copyleftLicenses) {
                    if ($content -imatch $lic) { $copyleftFound.Add("$($_.FullName): $lic reference") }
                }
            } catch {}
        }
    }
    if ($copyleftFound.Count -gt 0) {
        Add-Finding 'W21-C4' 'Copyleft License Compliance' 'High' 'WARN' `
            "$($copyleftFound.Count) copyleft-licensed component(s): $($copyleftFound[0..2] -join ' | ')" `
            'Review copyleft license obligations. Commercial projects may need legal review. Consider replacing with MIT/Apache/BSD-licensed alternatives.'
    } else {
        Add-Finding 'W21-C4' 'Copyleft License Compliance' 'High' 'PASS' `
            'No copyleft (GPL/AGPL/LGPL) licenses detected in scanned package files.' ''
    }

    # C5 – EOL/outdated runtimes
    $eolIssues = [System.Collections.Generic.List[string]]::new()
    # .NET Framework versions via registry
    $ndpPath = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP'
    if (Test-Path $ndpPath) {
        try {
            Get-ChildItem $ndpPath -ErrorAction SilentlyContinue | ForEach-Object {
                $rel = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Release
                if ($rel -and $rel -lt 528040) { # < .NET 4.8
                    $eolIssues.Add(".NET Framework version may be below 4.8 (Release=$rel). Consider upgrading.")
                }
            }
        } catch {}
    }
    # Node.js EOL
    $nodeCmd = Get-Command node -ErrorAction SilentlyContinue
    if ($nodeCmd) {
        try {
            $nodeVer = & node --version 2>&1
            if ($nodeVer -match 'v(\d+)') {
                $nodeMajor = [int]$Matches[1]
                # Node LTS: 18, 20, 22 are current; < 18 is EOL
                if ($nodeMajor -lt 18) { $eolIssues.Add("Node.js $nodeVer is EOL (< 18 LTS)") }
            }
        } catch {}
    }
    # Python EOL
    $pyCmd = Get-Command python -ErrorAction SilentlyContinue
    if ($null -eq $pyCmd) { $pyCmd = Get-Command python3 -ErrorAction SilentlyContinue }
    if ($pyCmd) {
        try {
            $pyVer = & $pyCmd.Name --version 2>&1
            if ($pyVer -match 'Python (\d+)\.(\d+)') {
                $pyMajor = [int]$Matches[1]; $pyMinor = [int]$Matches[2]
                if ($pyMajor -eq 2 -or ($pyMajor -eq 3 -and $pyMinor -lt 8)) {
                    $eolIssues.Add("Python $pyVer is EOL (< 3.8)")
                }
            }
        } catch {}
    }
    if ($eolIssues.Count -gt 0) {
        Add-Finding 'W21-C5' 'EOL/Outdated Runtimes' 'High' 'WARN' `
            ($eolIssues -join ' | ') `
            'Upgrade EOL runtimes. .NET 6+ LTS recommended. Node.js 18+ or 20+ LTS. Python 3.9+.'
    } else {
        Add-Finding 'W21-C5' 'EOL/Outdated Runtimes' 'High' 'PASS' `
            'No EOL runtime versions detected.' ''
    }

    # C6 – Log4j detection
    $log4jPaths   = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:APPDATA, 'C:\') | Where-Object { $_ -and (Test-Path $_) }
    $log4jFound   = [System.Collections.Generic.List[string]]::new()
    foreach ($lp in $log4jPaths) {
        Get-ChildItem -Path $lp -Recurse -Filter 'log4j*.jar' -ErrorAction SilentlyContinue | ForEach-Object {
            $log4jFound.Add($_.FullName)
        }
    }
    $vulnerableLog4j = $log4jFound | Where-Object {
        $_ -imatch 'log4j-1\.' -or $_ -imatch 'log4j-core-2\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14)\.'
    }
    if ($vulnerableLog4j) {
        Add-Finding 'W21-C6' 'Log4j Vulnerability (CVE-2021-44228)' 'Critical' 'FAIL' `
            "Vulnerable Log4j JAR(s) found: $($vulnerableLog4j -join ' | ')" `
            'CRITICAL: Upgrade log4j-core to 2.17.1+. Remove log4j 1.x entirely. See: https://logging.apache.org/log4j/2.x/security.html'
    } elseif ($log4jFound.Count -gt 0) {
        Add-Finding 'W21-C6' 'Log4j Vulnerability (CVE-2021-44228)' 'High' 'WARN' `
            "Log4j JARs found (verify versions): $($log4jFound -join ' | ')" `
            'Verify log4j-core version is 2.17.1+. Upgrade if below 2.17.1.'
    } else {
        Add-Finding 'W21-C6' 'Log4j Vulnerability (CVE-2021-44228)' 'High' 'PASS' `
            'No Log4j JAR files detected in scanned directories.' ''
    }

    # C7 – Chocolatey packages outdated
    $chocoCmd = Get-Command choco -ErrorAction SilentlyContinue
    if ($null -eq $chocoCmd) {
        Add-Finding 'W21-C7' 'Chocolatey Packages Outdated' 'Low' 'INFO' `
            'Chocolatey (choco) not found in PATH.' `
            'Install Chocolatey from https://chocolatey.org/install and run: choco outdated'
    } else {
        try {
            $chocoOutdated = & choco outdated --no-color 2>&1
            $outdatedLines = $chocoOutdated | Where-Object { $_ -match '^\S+\|' }
            if ($outdatedLines.Count -gt 5) {
                Add-Finding 'W21-C7' 'Chocolatey Packages Outdated' 'Med' 'WARN' `
                    "$($outdatedLines.Count) Chocolatey packages are outdated." `
                    'Run: choco upgrade all -y  (review changes before running in production).'
            } elseif ($outdatedLines.Count -gt 0) {
                Add-Finding 'W21-C7' 'Chocolatey Packages Outdated' 'Low' 'INFO' `
                    "$($outdatedLines.Count) Chocolatey package(s) have updates available." `
                    'Run: choco upgrade <package> or choco upgrade all -y'
            } else {
                Add-Finding 'W21-C7' 'Chocolatey Packages Outdated' 'Low' 'PASS' `
                    'All Chocolatey packages are up to date.' ''
            }
        } catch {
            Add-Finding 'W21-C7' 'Chocolatey Packages Outdated' 'Low' 'WARN' `
                "choco outdated failed: $_" 'Ensure Chocolatey is properly installed.'
        }
    }
}
#endregion

#region ── Output ────────────────────────────────────────────────────────────────
Invoke-Checks

if ($Fix) {
    Write-Warning "⚠  -Fix flag detected: SCA remediation requires package updates (not automated here)."
    Write-Host '   Guidance for common remediation steps:' -ForegroundColor Cyan
    Write-Host '   - NuGet:  dotnet list package --vulnerable --include-transitive' -ForegroundColor Cyan
    Write-Host '             dotnet add package <name> --version <safe-version>' -ForegroundColor Cyan
    Write-Host '   - npm:    npm audit fix  (or npm audit fix --force)' -ForegroundColor Cyan
    Write-Host '   - pip:    pip install pip-audit && pip-audit' -ForegroundColor Cyan
    Write-Host '             pip install --upgrade <vulnerable-package>' -ForegroundColor Cyan
    Write-Host '   - Log4j:  Upgrade to log4j-core 2.17.1+ immediately (CVE-2021-44228)' -ForegroundColor Cyan
}

if ($Json) {
    $result = @{
        script    = 'W21_sca_licenses'
        host      = $env:COMPUTERNAME
        timestamp = (Get-Date -Format 'o')
        findings  = $script:findings
    }
    $result | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W21 Software Composition Analysis & License Compliance – $env:COMPUTERNAME ===" -ForegroundColor Cyan
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
