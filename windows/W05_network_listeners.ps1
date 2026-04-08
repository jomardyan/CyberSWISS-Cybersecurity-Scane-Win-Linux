#Requires -Version 5.1
<#
.SYNOPSIS
    W05 – Network Listeners & Open Ports (Windows)
.DESCRIPTION
    Enumerates all TCP/UDP listening ports, maps them to owning processes, and
    flags well-known risky ports. Read-only by default. Pass -Fix to apply remediation where available.
.NOTES
    ID       : W05
    Category : Network Exposure
    Severity : High
    OS       : Windows 10/11, Server 2016+
    Admin    : Yes (for full process mapping)
    Language : PowerShell 5.1+
    Author   : CyberSWISS Security Team
.PARAMETER Json
    Output results in JSON format.
.PARAMETER Fix
    WARNING: Applies remediation where available. Read-only by default. Use with caution.
.EXAMPLE
    .\W05_network_listeners.ps1
    .\W05_network_listeners.ps1 -Json
    .\W05_network_listeners.ps1 -Fix
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

# Risky ports: port -> (description, severity)
$riskyPorts = @{
    21   = @('FTP – plaintext file transfer', 'High')
    23   = @('Telnet – plaintext remote access', 'Critical')
    25   = @('SMTP – mail relay (unexpected on endpoints)', 'Med')
    69   = @('TFTP – no authentication', 'High')
    110  = @('POP3 – legacy plaintext mail', 'Med')
    111  = @('RPCbind/portmapper', 'Med')
    135  = @('MS-RPC Endpoint Mapper – often targeted', 'Med')
    137  = @('NetBIOS Name Service', 'Med')
    138  = @('NetBIOS Datagram', 'Med')
    139  = @('NetBIOS Session / SMBv1', 'High')
    143  = @('IMAP – legacy plaintext mail', 'Med')
    161  = @('SNMP – weak authentication (v1/v2)', 'High')
    445  = @('SMB – check if exposed to internet', 'Med')
    512  = @('rexec – insecure remote exec', 'Critical')
    513  = @('rlogin – insecure remote login', 'Critical')
    514  = @('rsh/syslog – plaintext', 'High')
    1433 = @('MS SQL Server – check if internet-exposed', 'Med')
    1521 = @('Oracle DB – check if internet-exposed', 'Med')
    3306 = @('MySQL – check if internet-exposed', 'Med')
    3389 = @('RDP – ensure NLA enabled, not internet-facing', 'Med')
    5985 = @('WinRM HTTP – check if restricted', 'Med')
    5986 = @('WinRM HTTPS – verify cert and access', 'Low')
    6379 = @('Redis – often unauthenticated', 'High')
    27017= @('MongoDB – often unauthenticated', 'High')
}

function Get-ListenersWithProcess {
    $listeners = [System.Collections.Generic.List[hashtable]]::new()

    # Prefer native cmdlets (more reliable and handle UDP correctly)
    $hasTcpCmdlet = $null -ne (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)
    $hasUdpCmdlet = $null -ne (Get-Command Get-NetUDPEndpoint   -ErrorAction SilentlyContinue)

    if ($hasTcpCmdlet) {
        $tcpConns = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
        foreach ($c in $tcpConns) {
            $procName = try { (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).Name } catch { 'Unknown' }
            $listeners.Add(@{ Protocol='TCP'; LocalAddress=$c.LocalAddress; Port=$c.LocalPort; PID=$c.OwningProcess; Process=$procName })
        }
    }

    if ($hasUdpCmdlet) {
        $udpEndpoints = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
        foreach ($u in $udpEndpoints) {
            $procName = try { (Get-Process -Id $u.OwningProcess -ErrorAction SilentlyContinue).Name } catch { 'Unknown' }
            $listeners.Add(@{ Protocol='UDP'; LocalAddress=$u.LocalAddress; Port=$u.LocalPort; PID=$u.OwningProcess; Process=$procName })
        }
    }

    # Fallback: netstat (handles both TCP LISTENING and UDP *:* lines)
    if (-not $hasTcpCmdlet -and -not $hasUdpCmdlet) {
        $raw = & netstat -ano 2>&1
        foreach ($line in $raw) {
            # TCP LISTENING: "  TCP  0.0.0.0:80  0.0.0.0:0  LISTENING  1234"
            if ($line -match '^\s+TCP\s+(\S+):(\d+)\s+\S+\s+LISTENING\s+(\d+)') {
                $localIp = $Matches[1]; $port = [int]$Matches[2]; $pid_ = [int]$Matches[3]
                $procName = try { (Get-Process -Id $pid_ -ErrorAction SilentlyContinue).Name } catch { 'Unknown' }
                $listeners.Add(@{ Protocol='TCP'; LocalAddress=$localIp; Port=$port; PID=$pid_; Process=$procName })
            }
            # UDP listening: "  UDP  0.0.0.0:500  *:*  1234"
            elseif ($line -match '^\s+UDP\s+(\S+):(\d+)\s+\*:\*\s+(\d+)') {
                $localIp = $Matches[1]; $port = [int]$Matches[2]; $pid_ = [int]$Matches[3]
                $procName = try { (Get-Process -Id $pid_ -ErrorAction SilentlyContinue).Name } catch { 'Unknown' }
                $listeners.Add(@{ Protocol='UDP'; LocalAddress=$localIp; Port=$port; PID=$pid_; Process=$procName })
            }
        }
    }

    return $listeners
}

function Invoke-Checks {
    $listeners = Get-ListenersWithProcess
    $listenCount = $listeners.Count

    Add-Finding 'W05-C1' 'Listening Ports Count' 'Info' 'INFO' "$listenCount listening ports detected" ''

    # Flag risky ports
    $flaggedPorts = [System.Collections.Generic.List[string]]::new()
    foreach ($l in $listeners) {
        if ($riskyPorts.ContainsKey($l.Port)) {
            $desc = $riskyPorts[$l.Port][0]
            $sev  = $riskyPorts[$l.Port][1]
            $flaggedPorts.Add($l.Port)
            Add-Finding "W05-C2-$($l.Port)" "Risky Port Open: $($l.Port)/$($l.Protocol)" $sev 'WARN' `
                "Port $($l.Port) ($desc) listening on $($l.LocalAddress) – Process: $($l.Process) (PID $($l.PID))" `
                'Disable or firewall this service if not required. Restrict to specific IPs if needed.'
        }
    }

    if ($flaggedPorts.Count -eq 0) {
        Add-Finding 'W05-C2' 'Risky Ports' 'High' 'PASS' 'No well-known risky ports detected as listeners' ''
    }

    # C3 – Ports listening on 0.0.0.0 (all interfaces) – inventory
    $allInterfaces = $listeners | Where-Object { $_.LocalAddress -in '0.0.0.0','::' }
    if ($allInterfaces) {
        $portList = ($allInterfaces | ForEach-Object { "$($_.Port)/$($_.Protocol)" }) -join ', '
        Add-Finding 'W05-C3' 'Ports Bound to All Interfaces' 'Med' 'WARN' `
            "Ports: $portList" `
            'Review whether services need to listen on all interfaces; bind to specific IPs where possible'
    } else {
        Add-Finding 'W05-C3' 'Ports Bound to All Interfaces' 'Med' 'PASS' 'No ports bound to 0.0.0.0/::]' ''
    }
}

Invoke-Checks

# Full listener list for JSON and optional remediation
$listenerData = Get-ListenersWithProcess

if ($Fix) {
    $portsToBlock = @(
        $listenerData |
            Where-Object {
                $riskyPorts.ContainsKey([int]$_.Port) -and
                $_.LocalAddress -notin @('127.0.0.1', '::1')
            } |
            Select-Object -ExpandProperty Port -Unique
    )

    if ($portsToBlock.Count -eq 0) {
        Write-Host 'No risky non-loopback listener ports were detected for firewall remediation.' -ForegroundColor Cyan
    } elseif (-not (Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue)) {
        Write-Warning 'New-NetFirewallRule is not available. Unable to add Windows Firewall remediation rules.'
    } else {
        foreach ($port in $portsToBlock) {
            foreach ($protocol in 'TCP', 'UDP') {
                $ruleName = "CyberSWISS Block Risky Port $port $protocol"
                if ($PSCmdlet.ShouldProcess($ruleName, "Create inbound block rule for local port $port/$protocol")) {
                    if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
                        New-NetFirewallRule `
                            -DisplayName $ruleName `
                            -Direction Inbound `
                            -Action Block `
                            -Enabled True `
                            -Profile Any `
                            -Protocol $protocol `
                            -LocalPort $port `
                            -Description 'CyberSWISS remediation for risky listening ports' | Out-Null
                    }
                }
            }
        }
        Write-Host ("Applied Windows Firewall block rules for risky ports: " + ($portsToBlock -join ', ')) -ForegroundColor Green
    }
}

if ($Json) {
    @{
        script    = 'W05_network_listeners'
        host      = $env:COMPUTERNAME
        timestamp = (Get-Date -Format 'o')
        findings  = $script:findings
        listeners = $listenerData
    } | ConvertTo-Json -Depth 5
} else {
    Write-Host "`n=== W05 Network Listeners – $env:COMPUTERNAME ===" -ForegroundColor Cyan
    foreach ($f in $script:findings) { Write-Finding $f }
    Write-Host "`n--- All Listening Ports ---"
    $listenerData | Sort-Object Port | Format-Table Protocol,Port,LocalAddress,Process,PID -AutoSize
    $fails = ($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count
    $warns = ($script:findings | Where-Object { $_.status -eq 'WARN' }).Count
    Write-Host ("`nSummary: {0} finding(s), {1} FAIL, {2} WARN" -f $script:findings.Count, $fails, $warns)
}

$exitCode = 0
if (($script:findings | Where-Object { $_.status -eq 'WARN' }).Count -gt 0) { $exitCode = 1 }
if (($script:findings | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { $exitCode = 2 }
exit $exitCode
