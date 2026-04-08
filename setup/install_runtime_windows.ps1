#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$Optional,
    [switch]$SkipPython,
    [switch]$SkipRSAT
)

$ErrorActionPreference = 'Stop'
$RootDir = Split-Path -Parent $PSScriptRoot

function Write-Step {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-WarnLine {
    param([string]$Message)
    Write-Warning $Message
}

function Assert-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an elevated PowerShell session."
    }
}

function Test-CommandExists {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Install-WithWinget {
    param([string[]]$Ids)
    foreach ($id in $Ids) {
        Write-Step "Installing $id with winget"
        winget install --id $id --accept-package-agreements --accept-source-agreements --silent
    }
}

function Install-WithChoco {
    param([string[]]$Packages)
    foreach ($pkg in $Packages) {
        Write-Step "Installing $pkg with Chocolatey"
        choco install $pkg -y
    }
}

function Ensure-Chocolatey {
    if (Test-CommandExists 'choco') {
        return
    }

    Write-Step 'Installing Chocolatey'
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}

function Install-PythonRequirements {
    if ($SkipPython) {
        Write-Step 'Skipping Python package install.'
        return
    }

    if (Test-CommandExists 'py') {
        Write-Step 'Installing Python dependencies from requirements.txt'
        & py -3 -m pip install -r (Join-Path $RootDir 'requirements.txt')
        return
    }

    if (Test-CommandExists 'python') {
        Write-Step 'Installing Python dependencies from requirements.txt'
        & python -m pip install -r (Join-Path $RootDir 'requirements.txt')
        return
    }

    Write-WarnLine 'Python was not found after package installation. Install Python manually, then run pip install -r requirements.txt.'
}

Assert-Administrator

Write-Step 'Checking Windows package managers'
$hasWinget = Test-CommandExists 'winget'
$hasChoco = Test-CommandExists 'choco'

if (-not $hasWinget -and -not $hasChoco) {
    Ensure-Chocolatey
    $hasChoco = Test-CommandExists 'choco'
}

if (-not $SkipRSAT) {
    try {
        Write-Step 'Installing RSAT Active Directory tools'
        Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0' | Out-Null
    } catch {
        Write-WarnLine "RSAT install failed or is not applicable: $($_.Exception.Message)"
    }
}

try {
    if (Get-WindowsOptionalFeature -Online -FeatureName IIS-ManagementConsole -ErrorAction SilentlyContinue) {
        Write-Step 'Enabling IIS management console feature if available'
        Enable-WindowsOptionalFeature -Online -FeatureName IIS-ManagementConsole -All -NoRestart | Out-Null
    }
} catch {
    Write-WarnLine "IIS management feature step failed: $($_.Exception.Message)"
}

$coreWinget = @(
    'Python.Python.3.11',
    'Git.Git',
    'OpenJS.NodeJS.LTS',
    'Microsoft.DotNet.SDK.8'
)
$optionalWinget = @(
    'Docker.DockerDesktop',
    'Kubernetes.kubectl',
    'Helm.Helm',
    'Hashicorp.Terraform'
)

$coreChoco = @(
    'python',
    'git',
    'nodejs-lts',
    'dotnet-8.0-sdk'
)
$optionalChoco = @(
    'docker-desktop',
    'kubernetes-cli',
    'kubernetes-helm',
    'terraform'
)

if ($hasWinget) {
    Install-WithWinget -Ids $coreWinget
    if ($Optional) {
        Install-WithWinget -Ids $optionalWinget
    } else {
        Write-WarnLine 'Skipping optional tooling. Re-run with -Optional for Docker, kubectl, Helm, and Terraform.'
    }
} elseif ($hasChoco) {
    Install-WithChoco -Packages $coreChoco
    if ($Optional) {
        Install-WithChoco -Packages $optionalChoco
    } else {
        Write-WarnLine 'Skipping optional tooling. Re-run with -Optional for Docker, kubectl, Helm, and Terraform.'
    }
}

Install-PythonRequirements

@"

Bootstrap complete.

Manual follow-up may still be needed for:
  - WebAdministration / IIS workloads on systems without IIS
  - Defender / EDR-specific components
  - BitLocker / TPM / Secure Boot dependent checks
  - OpenVAS / Nessus / vendor security tooling

See docs/RUNTIME_REQUIREMENTS.md for the full runtime matrix.
"@ | Write-Host
