#Requires -Version 5.1
<#
.SYNOPSIS
    W20 – IaC Security Scanning (Windows)
.DESCRIPTION
    Scans Infrastructure-as-Code files for security misconfigurations:
    Dockerfiles, docker-compose, Terraform (.tf), Kubernetes manifests,
    ARM templates, and Bicep files. Detects hardcoded secrets, insecure
    defaults, and missing security controls.
    Read-only by default. Pass -Fix to apply remediation where available.
.NOTES
    ID         : W20
    Category   : IaC Security
    Severity   : High
    OS         : Windows 10/11, Server 2016+
    Admin      : No
    Language   : PowerShell 5.1+
    Author     : CyberSWISS Security Team
.PARAMETER Json
    Output results in JSON format for SIEM ingestion.
.PARAMETER Fix
    WARNING: Applies recommended baseline values. Off by default. Use with caution.
.EXAMPLE
    .\W20_iac_scan.ps1
    .\W20_iac_scan.ps1 -Json
    .\W20_iac_scan.ps1 -Fix
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

# Returns matching file paths under a set of search roots
function Find-IaCFiles {
    param(
        [string[]]$SearchRoots,
        [string]$Filter,
        [string]$NamePattern = $null
    )
    $found = [System.Collections.Generic.List[string]]::new()
    foreach ($root in ($SearchRoots | Where-Object { Test-Path $_ })) {
        Get-ChildItem -Path $root -Recurse -Filter $Filter -ErrorAction SilentlyContinue | ForEach-Object {
            if ($null -eq $NamePattern -or $_.Name -match $NamePattern) {
                $found.Add($_.FullName)
            }
        }
    }
    return $found
}
#endregion

#region ── Checks ────────────────────────────────────────────────────────────────
function Invoke-Checks {

    $searchRoots = @("$env:USERPROFILE", 'C:\Projects', 'C:\src', 'C:\code', 'C:\opt', 'C:\inetpub') |
        Where-Object { Test-Path $_ }

    # C1 – Dockerfile security
    $dockerfiles  = Find-IaCFiles -SearchRoots $searchRoots -Filter 'Dockerfile'
    $dockerfiles += Find-IaCFiles -SearchRoots $searchRoots -Filter 'Dockerfile.*'
    $dockerIssues = [System.Collections.Generic.List[string]]::new()
    foreach ($df in ($dockerfiles | Select-Object -Unique)) {
        try {
            $content = Get-Content $df -ErrorAction SilentlyContinue
            if ($content -imatch '^USER\s+root') {
                $dockerIssues.Add("$($df): runs as root (USER root)")
            }
            if ($content -imatch 'ENV\s+.*(PASSWORD|SECRET|KEY|TOKEN)\s*=') {
                $dockerIssues.Add("$($df): sensitive ENV var (PASSWORD/SECRET/KEY/TOKEN)")
            }
            if ($content -notmatch 'HEALTHCHECK') {
                $dockerIssues.Add("$($df): missing HEALTHCHECK instruction")
            }
            if ($content -imatch '^ADD\s+https?://') {
                $dockerIssues.Add("$($df): ADD from remote URL (use COPY + curl with hash verification)")
            }
        } catch {}
    }
    if ($dockerfiles.Count -eq 0) {
        Add-Finding 'W20-C1' 'Dockerfile Security' 'High' 'INFO' 'No Dockerfiles found in scanned paths.' ''
    } elseif ($dockerIssues.Count -gt 0) {
        Add-Finding 'W20-C1' 'Dockerfile Security' 'High' 'WARN' `
            "$($dockerIssues.Count) issue(s) in $($dockerfiles.Count) Dockerfile(s): $($dockerIssues[0..3] -join ' | ')" `
            'Use non-root USER, avoid ENV secrets (use --secret or vault at runtime), add HEALTHCHECK, avoid remote ADD.'
    } else {
        Add-Finding 'W20-C1' 'Dockerfile Security' 'High' 'PASS' `
            "Scanned $($dockerfiles.Count) Dockerfile(s); no obvious issues detected." ''
    }

    # C2 – docker-compose security
    $composeFiles  = Find-IaCFiles -SearchRoots $searchRoots -Filter 'docker-compose.yml'
    $composeFiles += Find-IaCFiles -SearchRoots $searchRoots -Filter 'docker-compose.yaml'
    $composeFiles += Find-IaCFiles -SearchRoots $searchRoots -Filter 'docker-compose.*.yml'
    $composeIssues = [System.Collections.Generic.List[string]]::new()
    foreach ($cf in ($composeFiles | Select-Object -Unique)) {
        try {
            $content = Get-Content $cf -ErrorAction SilentlyContinue -Raw
            if ($content -imatch 'privileged\s*:\s*true')                                { $composeIssues.Add("$($cf): privileged: true") }
            if ($content -imatch 'network_mode\s*:\s*host')                              { $composeIssues.Add("$($cf): network_mode: host") }
            if ($content -imatch '/etc\b' -and $content -imatch 'volumes')              { $composeIssues.Add("$($cf): /etc volume mount") }
            if ($content -imatch '/var/run/docker\.sock')                                { $composeIssues.Add("$($cf): docker.sock volume mount") }
            if ($content -imatch 'C:\\\\:' -or $content -imatch '"C:/"' -or $content -imatch "'C:/'") {
                $composeIssues.Add("$($cf): C:\ drive volume mount")
            }
        } catch {}
    }
    if ($composeFiles.Count -eq 0) {
        Add-Finding 'W20-C2' 'docker-compose Security' 'High' 'INFO' 'No docker-compose files found in scanned paths.' ''
    } elseif ($composeIssues.Count -gt 0) {
        Add-Finding 'W20-C2' 'docker-compose Security' 'High' 'FAIL' `
            "$($composeIssues.Count) issue(s): $($composeIssues[0..3] -join ' | ')" `
            'Remove privileged mode, host networking, and sensitive volume mounts from docker-compose files.'
    } else {
        Add-Finding 'W20-C2' 'docker-compose Security' 'High' 'PASS' `
            "Scanned $($composeFiles.Count) docker-compose file(s); no obvious issues detected." ''
    }

    # C3 – Terraform security
    $tfFiles  = Find-IaCFiles -SearchRoots $searchRoots -Filter '*.tf'
    $tfIssues = [System.Collections.Generic.List[string]]::new()
    foreach ($tf in $tfFiles) {
        try {
            $content = Get-Content $tf -ErrorAction SilentlyContinue -Raw
            if ($content -imatch '(password|secret|api_key|token)\s*=\s*"[^"${}][^"]{2,}"') {
                $tfIssues.Add("$($tf): possible hardcoded secret in assignment")
            }
            if ($content -imatch 'aws_s3_bucket' -and $content -notmatch 'server_side_encryption_configuration') {
                $tfIssues.Add("$($tf): S3 bucket without server-side encryption")
            }
            if ($content -imatch 'aws_db_instance' -and $content -notmatch 'storage_encrypted\s*=\s*true') {
                $tfIssues.Add("$($tf): aws_db_instance without storage_encrypted = true")
            }
        } catch {}
    }
    if ($tfFiles.Count -eq 0) {
        Add-Finding 'W20-C3' 'Terraform Security' 'High' 'INFO' 'No Terraform (.tf) files found in scanned paths.' ''
    } elseif ($tfIssues.Count -gt 0) {
        Add-Finding 'W20-C3' 'Terraform Security' 'High' 'WARN' `
            "$($tfIssues.Count) issue(s) in $($tfFiles.Count) .tf file(s): $($tfIssues[0..3] -join ' | ')" `
            'Use Terraform variables + AWS Secrets Manager/Key Vault. Enable storage encryption on all data resources.'
    } else {
        Add-Finding 'W20-C3' 'Terraform Security' 'High' 'PASS' `
            "Scanned $($tfFiles.Count) Terraform file(s); no obvious issues detected." ''
    }

    # C4 – Kubernetes manifests
    $k8sFiles  = Find-IaCFiles -SearchRoots $searchRoots -Filter '*.yaml' -NamePattern '(deployment|pod|daemonset|statefulset)'
    $k8sFiles += Find-IaCFiles -SearchRoots $searchRoots -Filter '*.yml'  -NamePattern '(deployment|pod|daemonset|statefulset)'
    $k8sIssues = [System.Collections.Generic.List[string]]::new()
    foreach ($kf in ($k8sFiles | Select-Object -Unique)) {
        try {
            $content = Get-Content $kf -ErrorAction SilentlyContinue -Raw
            if ($content -imatch 'apiVersion' -and $content -imatch 'kind') {
                if ($content -imatch 'privileged\s*:\s*true')         { $k8sIssues.Add("$($kf): privileged: true") }
                if ($content -imatch 'hostPID\s*:\s*true')            { $k8sIssues.Add("$($kf): hostPID: true") }
                if ($content -imatch 'hostNetwork\s*:\s*true')        { $k8sIssues.Add("$($kf): hostNetwork: true") }
                if ($content -notmatch 'securityContext')             { $k8sIssues.Add("$($kf): missing securityContext") }
            }
        } catch {}
    }
    if ($k8sFiles.Count -eq 0) {
        Add-Finding 'W20-C4' 'Kubernetes Manifests' 'High' 'INFO' 'No Kubernetes manifest files found in scanned paths.' ''
    } elseif ($k8sIssues.Count -gt 0) {
        Add-Finding 'W20-C4' 'Kubernetes Manifests' 'High' 'FAIL' `
            "$($k8sIssues.Count) issue(s) in $($k8sFiles.Count) manifest(s): $($k8sIssues[0..3] -join ' | ')" `
            'Remove privileged/hostPID/hostNetwork settings. Add securityContext with runAsNonRoot: true, readOnlyRootFilesystem: true.'
    } else {
        Add-Finding 'W20-C4' 'Kubernetes Manifests' 'High' 'PASS' `
            "Scanned $($k8sFiles.Count) Kubernetes manifest(s); no obvious issues detected." ''
    }

    # C5 – ARM templates
    $armFiles  = Find-IaCFiles -SearchRoots $searchRoots -Filter 'azuredeploy.json'
    $armFiles += Find-IaCFiles -SearchRoots $searchRoots -Filter '*-template.json'
    $armIssues = [System.Collections.Generic.List[string]]::new()
    foreach ($af in ($armFiles | Select-Object -Unique)) {
        try {
            $content = Get-Content $af -ErrorAction SilentlyContinue -Raw
            if ($content -imatch '"type"\s*:\s*"secureString"' -and $content -imatch '"defaultValue"\s*:\s*"[^"]{4,}"') {
                $armIssues.Add("$($af): secureString parameter with non-empty defaultValue (hardcoded secret)")
            }
            if ($content -imatch 'Microsoft.Storage/storageAccounts' -and $content -imatch '"allowBlobPublicAccess"\s*:\s*true') {
                $armIssues.Add("$($af): storage account with allowBlobPublicAccess: true")
            }
        } catch {}
    }
    if ($armFiles.Count -eq 0) {
        Add-Finding 'W20-C5' 'ARM Template Security' 'High' 'INFO' 'No ARM templates found in scanned paths.' ''
    } elseif ($armIssues.Count -gt 0) {
        Add-Finding 'W20-C5' 'ARM Template Security' 'High' 'WARN' `
            "$($armIssues.Count) issue(s) in $($armFiles.Count) ARM template(s): $($armIssues[0..3] -join ' | ')" `
            'Never set defaultValue on secureString parameters. Set allowBlobPublicAccess to false on storage accounts.'
    } else {
        Add-Finding 'W20-C5' 'ARM Template Security' 'High' 'PASS' `
            "Scanned $($armFiles.Count) ARM template(s); no obvious issues detected." ''
    }

    # C6 – Bicep files
    $bicepFiles  = Find-IaCFiles -SearchRoots $searchRoots -Filter '*.bicep'
    $bicepIssues = [System.Collections.Generic.List[string]]::new()
    foreach ($bf in $bicepFiles) {
        try {
            $content = Get-Content $bf -ErrorAction SilentlyContinue -Raw
            if ($content -imatch "@secure\(\)" -and $content -imatch "=\s*'[^']{4,}'") {
                $bicepIssues.Add("$($bf): @secure() param may have hardcoded default value")
            }
            if ($content -imatch 'allowBlobPublicAccess\s*:\s*true') {
                $bicepIssues.Add("$($bf): storage account with allowBlobPublicAccess: true")
            }
            if ($content -imatch 'Microsoft.Storage/storageAccounts' -and $content -notmatch 'requireInfrastructureEncryption\s*:\s*true') {
                $bicepIssues.Add("$($bf): storage account missing requireInfrastructureEncryption: true")
            }
        } catch {}
    }
    if ($bicepFiles.Count -eq 0) {
        Add-Finding 'W20-C6' 'Bicep File Security' 'High' 'INFO' 'No Bicep (.bicep) files found in scanned paths.' ''
    } elseif ($bicepIssues.Count -gt 0) {
        Add-Finding 'W20-C6' 'Bicep File Security' 'High' 'WARN' `
            "$($bicepIssues.Count) issue(s) in $($bicepFiles.Count) Bicep file(s): $($bicepIssues[0..3] -join ' | ')" `
            'Avoid hardcoded secrets in @secure() params. Disable blob public access and enable infrastructure encryption.'
    } else {
        Add-Finding 'W20-C6' 'Bicep File Security' 'High' 'PASS' `
            "Scanned $($bicepFiles.Count) Bicep file(s); no obvious issues detected." ''
    }

    # C7 – IaC tool inventory
    $tools = @(
        @{ Cmd = 'docker';     Name = 'Docker' }
        @{ Cmd = 'terraform';  Name = 'Terraform' }
        @{ Cmd = 'kubectl';    Name = 'kubectl' }
        @{ Cmd = 'helm';       Name = 'Helm' }
        @{ Cmd = 'az';         Name = 'Azure CLI' }
        @{ Cmd = 'aws';        Name = 'AWS CLI' }
    )
    $installedTools = [System.Collections.Generic.List[string]]::new()
    foreach ($tool in $tools) {
        if ($null -ne (Get-Command $tool.Cmd -ErrorAction SilentlyContinue)) {
            try {
                $ver = & $tool.Cmd --version 2>&1 | Select-Object -First 1
                $installedTools.Add("$($tool.Name): $ver")
            } catch {
                $installedTools.Add($tool.Name)
            }
        }
    }
    if ($installedTools.Count -gt 0) {
        Add-Finding 'W20-C7' 'IaC Tool Inventory' 'Info' 'INFO' `
            "Installed IaC tools: $($installedTools -join ' | ')" `
            'Ensure IaC tools are kept up-to-date and access to cloud credentials is appropriately controlled.'
    } else {
        Add-Finding 'W20-C7' 'IaC Tool Inventory' 'Info' 'INFO' `
            'No IaC tools (docker, terraform, kubectl, helm, az, aws) detected in PATH.' ''
    }
}
#endregion

#region ── Output ────────────────────────────────────────────────────────────────
Invoke-Checks

if ($Fix) {
    Write-Warning "⚠  -Fix flag detected: IaC security issues require manual code changes."
    Write-Host '   Guidance:' -ForegroundColor Cyan
    Write-Host '   - Use Checkov (pip install checkov) for automated IaC scanning: checkov -d .' -ForegroundColor Cyan
    Write-Host '   - Use tfsec for Terraform: https://github.com/aquasecurity/tfsec' -ForegroundColor Cyan
    Write-Host '   - Use kube-bench for Kubernetes: https://github.com/aquasecurity/kube-bench' -ForegroundColor Cyan
    Write-Host '   - Azure Security Center can scan ARM/Bicep via CI/CD pipeline integration.' -ForegroundColor Cyan
}

if ($Json) {
    $result = @{
        script    = 'W20_iac_scan'
        host      = $env:COMPUTERNAME
        timestamp = (Get-Date -Format 'o')
        findings  = $script:findings
    }
    $result | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W20 IaC Security Scanning – $env:COMPUTERNAME ===" -ForegroundColor Cyan
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
