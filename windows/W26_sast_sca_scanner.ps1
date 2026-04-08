#Requires -Version 5.1
<#
.SYNOPSIS
    W26 – SAST / SCA Code & Dependency Security Scanner (Windows)
.DESCRIPTION
    Performs static application security testing (SAST) and software composition
    analysis (SCA) on Windows — similar to industry-standard SAST/SCA tools:
      C1  – NuGet / npm dependency vulnerability scan (known-bad versions)
      C2  – Hardcoded secrets / credentials in source code and config files
      C3  – C# / .NET security anti-patterns (unsafe, P/Invoke, Marshal)
      C4  – JavaScript / Node.js security anti-patterns (eval, innerHTML, etc.)
      C5  – Insecure cryptographic algorithm usage (MD5, SHA1, DES, RC4)
      C6  – SQL injection patterns in .NET source code
      C7  – Path traversal vulnerability patterns in .NET code
      C8  – Insecure deserialization patterns (BinaryFormatter, JSON eval)
      C9  – Code signing and integrity verification
      C10 – Dependency freshness (stale packages.lock.json / package-lock.json)
    Read-only by default. Pass -Fix to apply remediation where available.
.NOTES
    ID         : W26
    Category   : Code & Dependency Security (SAST/SCA)
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
    .\W26_sast_sca_scanner.ps1
    .\W26_sast_sca_scanner.ps1 -Json
    .\W26_sast_sca_scanner.ps1 -Fix
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

function Search-FilesForPattern {
    param(
        [string[]]$Roots,
        [string[]]$Extensions,
        [string]$Pattern,
        [int]$MaxFiles = 500
    )
    $results = @()
    foreach ($root in $Roots) {
        if (-not (Test-Path $root)) { continue }
        $files = Get-ChildItem -Path $root -Recurse -Include $Extensions -ErrorAction SilentlyContinue |
                 Where-Object { $_.FullName -notmatch '\\(node_modules|\.git|bin|obj|packages)\\' } |
                 Select-Object -First $MaxFiles
        foreach ($file in $files) {
            try {
                if (Select-String -Path $file.FullName -Pattern $Pattern -Quiet -ErrorAction SilentlyContinue) {
                    $results += $file.FullName
                }
            } catch {}
        }
    }
    return $results
}
#endregion

#region ── Scan roots ─────────────────────────────────────────────────────────
$scanRoots = @(
    'C:\inetpub\wwwroot', 'C:\apps', 'C:\websites', 'C:\src', 'C:\projects',
    "$env:USERPROFILE\source"
) | Where-Object { Test-Path $_ }
#endregion

#region ── Checks ────────────────────────────────────────────────────────────────
function Invoke-Checks {

    # C1 – NuGet / npm dependency vulnerability scan ───────────────────────────
    $depVulnIssues = @()

    # Check for known vulnerable NuGet packages
    $vulnNuget = @{
        'Newtonsoft.Json'                 = [version]'13.0.1'
        'System.Text.RegularExpressions' = [version]'4.3.0'
        'Microsoft.AspNet.Mvc'           = [version]'5.2.7'
        'log4net'                        = [version]'2.0.12'
    }

    if ($scanRoots.Count -gt 0) {
        $packagesConfigs = @()
        $csprojFiles     = @()
        foreach ($root in $scanRoots) {
            $packagesConfigs += Get-ChildItem -Path $root -Recurse -Filter 'packages.config' `
                -ErrorAction SilentlyContinue | Select-Object -First 50
            $csprojFiles     += Get-ChildItem -Path $root -Recurse -Filter '*.csproj' `
                -ErrorAction SilentlyContinue | Select-Object -First 50
        }

        foreach ($pkgConfig in $packagesConfigs) {
            try {
                [xml]$xml = Get-Content $pkgConfig.FullName
                foreach ($pkg in $xml.packages.package) {
                    # Flag old/known-vulnerable specific packages
                    if ($pkg.id -eq 'log4net' -and [version]$pkg.version -lt [version]'2.0.14') {
                        $depVulnIssues += "NuGet:$($pkg.id)@$($pkg.version)(log4net<2.0.14)"
                    }
                    if ($pkg.id -match '^Microsoft\.AspNet\.(MVC|Web|Identity)' -and
                        [version]$pkg.version -lt [version]'5.2.9') {
                        $depVulnIssues += "NuGet:$($pkg.id)@$($pkg.version)(update-recommended)"
                    }
                }
            } catch {}
        }
    }

    # Node.js npm deprecated packages
    if ($scanRoots.Count -gt 0) {
        $packageLocks = @()
        foreach ($root in $scanRoots) {
            $packageLocks += Get-ChildItem -Path $root -Recurse -Filter 'package-lock.json' `
                -ErrorAction SilentlyContinue | Select-Object -First 20
        }
        foreach ($lock in $packageLocks) {
            try {
                $content = Get-Content $lock.FullName -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($content) {
                    $deprecatedCount = 0
                    if ($content.packages) {
                        $content.packages.PSObject.Properties | ForEach-Object {
                            if ($_.Value.deprecated) { $deprecatedCount++ }
                        }
                    }
                    if ($deprecatedCount -gt 0) {
                        $depVulnIssues += "npm:$($lock.FullName)($deprecatedCount-deprecated-pkgs)"
                    }
                }
            } catch {}
        }
    }

    if ($depVulnIssues.Count -eq 0) {
        Add-Finding 'W26-C1' 'Dependency Vulnerability Scan' 'High' 'PASS' `
            'No known-vulnerable dependency versions detected in scanned NuGet/npm manifests' ''
    } else {
        Add-Finding 'W26-C1' 'Dependency Vulnerability Scan' 'High' 'FAIL' `
            ("$($depVulnIssues.Count) vulnerable dependency(ies): " + ($depVulnIssues -join ', ')) `
            'Update NuGet packages: Update-Package in Package Manager Console. Run npm audit fix. Integrate GitHub Dependabot or OWASP Dependency-Check into CI/CD.'
    }

    # C2 – Hardcoded secrets in source / config files ─────────────────────────
    $secretPattern = '(?i)(apikey|api_key|api[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key|password|connectionstring)\s*[=:]\s*["''][A-Za-z0-9+/\-_]{8,}["'']'
    $secretFiles   = @()

    if ($scanRoots.Count -gt 0) {
        $exts = @('*.cs', '*.vb', '*.js', '*.ts', '*.py', '*.php', '*.config', '*.json', '*.yaml', '*.yml', '*.xml')
        $secretFiles = Search-FilesForPattern -Roots $scanRoots -Extensions $exts `
            -Pattern $secretPattern -MaxFiles 500
        # Filter out obvious test/placeholder files
        $secretFiles = $secretFiles | Where-Object { $_ -notmatch '(?i)(test|spec|example|sample|mock|fake)' }
    }

    if ($secretFiles.Count -eq 0) {
        Add-Finding 'W26-C2' 'Hardcoded Secrets in Source Code' 'Critical' 'PASS' `
            'No hardcoded credential patterns detected in scanned application files' ''
    } else {
        Add-Finding 'W26-C2' 'Hardcoded Secrets in Source Code' 'Critical' 'FAIL' `
            ("$($secretFiles.Count) file(s) with potential hardcoded secrets: " + (($secretFiles | Select-Object -First 3) -join ', ')) `
            'Replace hardcoded secrets with environment variables, Azure Key Vault, or Windows DPAPI. Use User Secrets for development (dotnet user-secrets). Run git-secrets on git history.'
    }

    # C3 – C# / .NET security anti-patterns ───────────────────────────────────
    $csIssues = @()
    $unsafePattern = '(unsafe\s+class|unsafe\s+void|unsafe\s+static|Marshal\.(Copy|PtrToStructure|AllocHGlobal)|DllImport.*Entrypoint.*"(Cmd|Shell|WinExec)")'
    $legacySerPattern = '(BinaryFormatter|SoapFormatter|NetDataContractSerializer|ObjectStateFormatter|LosFormatter)'
    $weakRandPattern  = 'new\s+Random\s*\(\s*\).*password|new\s+Random\s*\(\s*\).*token|new\s+Random\s*\(\s*\).*key'

    if ($scanRoots.Count -gt 0) {
        $unsafeFiles  = Search-FilesForPattern -Roots $scanRoots -Extensions @('*.cs') -Pattern $unsafePattern
        $serFiles     = Search-FilesForPattern -Roots $scanRoots -Extensions @('*.cs', '*.vb') -Pattern $legacySerPattern
        $randFiles    = Search-FilesForPattern -Roots $scanRoots -Extensions @('*.cs', '*.vb') -Pattern $weakRandPattern

        if ($unsafeFiles.Count -gt 0) { $csIssues += "unsafe-code/dangerous-P/Invoke:$($unsafeFiles.Count)files" }
        if ($serFiles.Count -gt 0)    { $csIssues += "BinaryFormatter/LegacySerializer:$($serFiles.Count)files" }
        if ($randFiles.Count -gt 0)   { $csIssues += "System.Random-for-secrets:$($randFiles.Count)files" }
    }

    if ($csIssues.Count -eq 0) {
        Add-Finding 'W26-C3' 'C#/.NET Security Anti-Patterns' 'High' 'PASS' `
            'No dangerous C#/.NET patterns (BinaryFormatter, unsafe, weak Random) detected' ''
    } else {
        Add-Finding 'W26-C3' 'C#/.NET Security Anti-Patterns' 'High' 'FAIL' `
            ("Security anti-patterns: " + ($csIssues -join ', ')) `
            'Replace BinaryFormatter with System.Text.Json or Protobuf. Use System.Security.Cryptography.RandomNumberGenerator for secure random values. Minimise unsafe code.'
    }

    # C4 – JavaScript/Node.js anti-patterns ───────────────────────────────────
    $jsIssues = @()
    $jsPatterns = @{
        'eval-usage'           = '\beval\s*\('
        'innerHTML-assignment' = 'innerHTML\s*='
        'document.write'       = 'document\.write\s*\('
        'jwt-none-algorithm'   = '(?i)algorithms\s*:\s*\[\s*["\x27]none["\x27]'
        'child_process-exec'   = 'require\(["\x27]child_process["\x27]\).*exec\s*\('
    }

    if ($scanRoots.Count -gt 0) {
        foreach ($patternName in $jsPatterns.Keys) {
            $hits = Search-FilesForPattern -Roots $scanRoots `
                -Extensions @('*.js', '*.ts', '*.mjs') `
                -Pattern $jsPatterns[$patternName]
            if ($hits.Count -gt 0) {
                $jsIssues += "${patternName}:$($hits.Count)files"
            }
        }
    }

    if ($jsIssues.Count -eq 0) {
        Add-Finding 'W26-C4' 'JavaScript/Node.js Security Anti-Patterns' 'High' 'PASS' `
            'No dangerous JavaScript patterns (eval, innerHTML, jwt-none) detected' ''
    } else {
        Add-Finding 'W26-C4' 'JavaScript/Node.js Security Anti-Patterns' 'High' 'FAIL' `
            ("JS security issues: " + ($jsIssues -join ', ')) `
            'Replace eval() with JSON.parse or Function constructor alternatives. Use textContent instead of innerHTML. Use DOMPurify for HTML rendering. Remove jwt none algorithm support.'
    }

    # C5 – Weak cryptographic algorithm usage ────────────────────────────────
    $cryptoIssues = @()
    $weakCryptoPattern = '(?i)(MD5\.Create|SHA1\.Create|new\s+SHA1|new\s+MD5|DES\.Create|TripleDES\.Create|RC2\.Create|RijndaelManaged|HashAlgorithm\.Create\s*\(\s*["\x27]MD5|HashAlgorithm\.Create\s*\(\s*["\x27]SHA1|createHash\s*\(\s*["\x27](md5|sha1))'

    if ($scanRoots.Count -gt 0) {
        $cryptoFiles = Search-FilesForPattern -Roots $scanRoots `
            -Extensions @('*.cs', '*.vb', '*.js', '*.ts', '*.py') `
            -Pattern $weakCryptoPattern
        if ($cryptoFiles.Count -gt 0) {
            $cryptoIssues += "WeakCrypto:$($cryptoFiles.Count)files"
        }
    }

    if ($cryptoIssues.Count -eq 0) {
        Add-Finding 'W26-C5' 'Weak Cryptographic Algorithm Usage' 'High' 'PASS' `
            'No deprecated/weak cryptographic algorithms (MD5/SHA1/DES/RC2/TripleDES) detected' ''
    } else {
        Add-Finding 'W26-C5' 'Weak Cryptographic Algorithm Usage' 'High' 'FAIL' `
            ("Weak crypto in: " + ($cryptoIssues -join ', ')) `
            'Replace MD5/SHA1 with SHA-256 (SHA256.Create()). Replace DES/3DES with AES-256-GCM (AesGcm class). Use BCrypt.Net-Next or Argon2 for password hashing.'
    }

    # C6 – SQL injection patterns in .NET code ────────────────────────────────
    $sqlConcatFiles = Search-FilesForPattern -Roots $scanRoots `
        -Extensions @('*.cs', '*.vb', '*.aspx', '*.ashx') `
        -Pattern '(?i)(SqlCommand|OleDbCommand|NpgsqlCommand)\s*\([^)]*\+|"(SELECT|INSERT|UPDATE|DELETE)\s.*"\s*\+'

    if ($sqlConcatFiles.Count -eq 0) {
        Add-Finding 'W26-C6' 'SQL Injection Patterns in .NET Code' 'Critical' 'PASS' `
            'No raw SQL string concatenation detected in scanned .NET source files' ''
    } else {
        Add-Finding 'W26-C6' 'SQL Injection Patterns in .NET Code' 'Critical' 'FAIL' `
            ("$($sqlConcatFiles.Count) file(s) with SQL string concat: " + (($sqlConcatFiles | Select-Object -First 3) -join ', ')) `
            'Use SqlCommand.Parameters.AddWithValue() for all query parameters. Use Entity Framework LINQ queries or Dapper with parameterised queries.'
    }

    # C7 – Path traversal patterns ────────────────────────────────────────────
    $pathTravFiles = Search-FilesForPattern -Roots $scanRoots `
        -Extensions @('*.cs', '*.vb', '*.aspx') `
        -Pattern '(?i)(File\.(Open|ReadAll|WriteAll)|FileStream|StreamReader)\s*\([^)]*Request\.(QueryString|Form|Params|Path)'

    if ($pathTravFiles.Count -eq 0) {
        Add-Finding 'W26-C7' 'Path Traversal Vulnerability Patterns' 'High' 'PASS' `
            'No path traversal patterns with user-controlled input detected' ''
    } else {
        Add-Finding 'W26-C7' 'Path Traversal Vulnerability Patterns' 'High' 'FAIL' `
            ("$($pathTravFiles.Count) file(s) with path traversal risk: " + (($pathTravFiles | Select-Object -First 3) -join ', ')) `
            'Use Path.GetFullPath() and verify the result starts with an allowed base directory. Use Server.MapPath() carefully. Never use user input directly in file paths.'
    }

    # C8 – Insecure deserialization patterns ──────────────────────────────────
    $deserPattern = '(?i)(BinaryFormatter\.(Serialize|Deserialize)|SoapFormatter\.(Serialize|Deserialize)|JsonConvert\.DeserializeObject.*Request\.|XmlSerializer.*Request\.)'
    $deserFiles   = Search-FilesForPattern -Roots $scanRoots `
        -Extensions @('*.cs', '*.vb') -Pattern $deserPattern

    if ($deserFiles.Count -eq 0) {
        Add-Finding 'W26-C8' 'Insecure Deserialization Patterns' 'Critical' 'PASS' `
            'No insecure deserialization patterns detected in scanned files' ''
    } else {
        Add-Finding 'W26-C8' 'Insecure Deserialization Patterns' 'Critical' 'FAIL' `
            ("$($deserFiles.Count) file(s) with deserialization risk: " + (($deserFiles | Select-Object -First 3) -join ', ')) `
            'Never use BinaryFormatter or SoapFormatter with untrusted data (deprecated in .NET 5+). Use System.Text.Json or Newtonsoft.Json with TypeNameHandling=None. Validate type before deserializing.'
    }

    # C9 – Code signing verification ──────────────────────────────────────────
    $unsignedBinaries = @()
    if ($scanRoots.Count -gt 0) {
        foreach ($root in $scanRoots) {
            Get-ChildItem -Path $root -Recurse -Include '*.exe', '*.dll' `
                -ErrorAction SilentlyContinue | Select-Object -First 50 |
                ForEach-Object {
                    try {
                        $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
                        if ($sig -and $sig.Status -ne 'Valid') {
                            $unsignedBinaries += "$($_.FullName):$($sig.Status)"
                        }
                    } catch {}
                }
        }
    }

    if ($unsignedBinaries.Count -eq 0) {
        Add-Finding 'W26-C9' 'Code Signing and Binary Integrity' 'Med' 'PASS' `
            'All scanned binaries have valid Authenticode signatures (or no binaries found)' ''
    } else {
        Add-Finding 'W26-C9' 'Code Signing and Binary Integrity' 'Med' 'WARN' `
            ("$($unsignedBinaries.Count) unsigned/invalid-signature binary(ies): " + (($unsignedBinaries | Select-Object -First 3) -join ', ')) `
            'Sign all production binaries with a code-signing certificate. Use Strong Name signing for .NET assemblies. Enable WDAC (Windows Defender Application Control) to enforce code integrity.'
    }

    # C10 – Dependency freshness ───────────────────────────────────────────────
    $staleFiles = @()
    $staleDays  = 90
    if ($scanRoots.Count -gt 0) {
        $lockFiles = @()
        foreach ($root in $scanRoots) {
            $lockFiles += Get-ChildItem -Path $root -Recurse `
                -Include 'packages.lock.json', 'package-lock.json', 'yarn.lock', 'Pipfile.lock' `
                -ErrorAction SilentlyContinue | Select-Object -First 20
        }
        foreach ($lf in $lockFiles) {
            $ageDays = ((Get-Date) - $lf.LastWriteTime).Days
            if ($ageDays -gt $staleDays) {
                $staleFiles += "$($lf.FullName)(${ageDays}d old)"
            }
        }
    }

    if ($staleFiles.Count -eq 0) {
        Add-Finding 'W26-C10' 'Dependency Freshness' 'Med' 'PASS' `
            'All lock files have been updated within the last 90 days (or none found)' ''
    } else {
        Add-Finding 'W26-C10' 'Dependency Freshness' 'Med' 'WARN' `
            ("Stale dependency lock file(s): " + ($staleFiles -join ', ')) `
            'Regularly update lock files. Run npm install, dotnet restore, pip-compile. Enable GitHub Dependabot or Renovate for automated dependency update PRs.'
    }
}
#endregion

#region ── Execute & output ──────────────────────────────────────────────────────
Invoke-Checks

if ($Json) {
    @{
        script    = 'W26_sast_sca_scanner'
        host      = $env:COMPUTERNAME
        timestamp = (Get-Date -Format 'o')
        findings  = $script:findings
    } | ConvertTo-Json -Depth 10
} else {
    Write-Host ''
    Write-Host "=== W26 SAST/SCA Code & Dependency Security Scanner – $env:COMPUTERNAME ===" -ForegroundColor Cyan
    foreach ($f in $script:findings) { Write-Finding $f }
    $failCount = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
    $warnCount = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
    Write-Host "`nSummary: $($script:findings.Count) finding(s), $failCount FAIL, $warnCount WARN"
}

$failCount = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
$warnCount = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
if ($failCount -gt 0) { exit 2 }
if ($warnCount -gt 0) { exit 1 }
exit 0
#endregion
