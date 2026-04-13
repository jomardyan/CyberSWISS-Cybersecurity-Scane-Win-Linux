# CyberSWISS Script Catalog

> **Internal Use Only** — Defense-Grade Security Audit Platform  
> All scripts are read-only by default. Remediation requires an explicit `--fix` / `-Fix` flag with administrative approval.

---

## Table of Contents

- [Windows Scripts (33)](#windows-scripts-33-powershell-scripts)
- [Linux Scripts (33)](#linux-scripts-33-bash-scripts)
- [Severity Levels](#severity-levels)
- [Runtime Notes](#runtime-notes)

---

## Complete Script Index (66 Scripts)

## Windows Scripts (33 PowerShell Scripts)

| ID  | Name | Category | Severity | Admin | Description |
|-----|------|----------|----------|-------|-------------|
| W01 | Password Policy Audit | Accounts & Auth | High | Y | Checks password min length, complexity, max age, history limits, lockout policies. Validates alignment with organizational baseline (e.g. 14+ char, 90-day max, NTLMv2-only). |
| W02 | Local Admin Review | Accounts & Auth | High | Y | Enumerates local admin group members, identifies stale passwords, disabled accounts, and accounts with no password. Detects unauthorized privilege escalation. |
| W03 | Patch Level & Software Inventory | Patch Management | Critical | Y | Checks Windows update age, pending patches, KB numbers, and installed software versions. Identifies unpatched systems and end-of-life software (Java, .NET, browsers). |
| W04 | Services Audit | Services/Daemons | High | Y | Audits running services for unquoted paths, insecure defaults, writable service directories, and risky permissions. Can disable insecure services with `--fix`. |
| W05 | Network Listeners | Network Exposure | High | Y | Enumerates all TCP/UDP listeners, maps to owning processes, identifies risky ports (23, 21, 3389 exposed). Uses `netstat -anob` or WMI. |
| W06 | Firewall State | Network Exposure | High | Y | Validates Windows Defender Firewall (WDF) profile states, default policies, inbound rules, and rule consistency. Can enable all profiles with `--fix`. |
| W07 | SMB/WinRM Posture | Network Exposure | High | Y | Audits SMBv1 status, SMB signing, encryption, WinRM authentication, and credential delegation. Can disable SMBv1 and enable signing/encryption with `--fix`. |
| W08 | Event Log Configuration | Logging & Auditing | High | Y | Checks Windows Event Log sizes, retention policies, forwarding config (WEF), and log retention days. Can increase log sizes with `--fix`. |
| W09 | Audit Policy | Logging & Auditing | High | Y | Validates auditpol subcategory enablement (Logon, Process Creation, File Access, etc.). Can enable critical audit subcategories with `--fix`. |
| W10 | Registry Hardening | Registry Security | High | Y | Audits critical registry settings: AutoRun disable, LSASS PPL, NTLMv2 enforcement, UAC level, WDigest credential caching, DEP/ASLR status. Can harden with `--fix`. |
| W11 | BitLocker Status | Encryption | High | Y | Checks BitLocker encryption on each volume, TPM status, recovery key backup location, and protector status. Validates full-volume encryption baseline. |
| W12 | Secure Boot & TPM | Boot Security | High | Y | Validates Secure Boot enabled, UEFI firmware, TPM present and active, HVCI/VBS enabled status. Ensures kernel integrity protection. |
| W13 | Defender & EDR | Endpoint Protection | Critical | Y | Checks Windows Defender real-time protection, signature age, tamper protection, cloud protection status. Detects if EDR agent (Crowdstrike, Sentinelone, etc.) is installed and running. |
| W14 | Scheduled Tasks Audit | Persistence Mechanisms | High | Y | Scans scheduled tasks for suspicious paths, commands, hidden tasks. Identifies persistence mechanisms and anomalous task configuration. |
| W15 | CIS Baseline Hardening | Baseline Hardening | High | Y | Validates CIS v1.4+ hardening: PowerShell script block logging, RDP NLA, NTLM settings, SMBv1 feature disabled, UAC enforcement. Can enable logging with `--fix`. |
| W16 | **Active Directory & GPO** | Identity & Access | High | Y | **Specialized for AD-joined systems**: Reads domain password policy, audits Domain Admins/Enterprise Admins/Schema Admins membership, checks LAPS deployment, Kerberos RC4 tickets, UAC, NTLMv2, AD Recycle Bin. `-Fix` writes GPO-compatible registry values. Deployable as GPO Startup Script. |
| W17 | Secrets Scanning | Secrets & Credentials | High | Y | Detects `.env` file leaks, cloud credentials (AWS/Azure/GCP keys), Docker auth credentials, IIS AutoLogon in registry, plain-text passwords in `web.config`. |
| W18 | Attack Surface Management | Network Exposure | High | Y | Enumerates HTTP/HTTPS services, checks security headers (HSTS, CSP, X-Frame-Options), CORS misconfiguration, TRACE method enabled, certificate expiry. |
| W19 | API Endpoint Discovery & DAST | Application Security | High | Y | Discovers web API endpoints on localhost/127.0.0.1, tests for Swagger/OpenAPI exposure, GraphQL introspection, default credentials, admin panels. Basic DAST checks. |
| W20 | IaC Security Scanning | DevSecOps | Medium | Y | Scans Dockerfile, docker-compose.yml, Terraform, CloudFormation/ARM templates, Bicep for misconfigurations: secrets in images, overprivileged containers, hard-coded credentials. |
| W21 | SCA & License Compliance | Open-Source Risk | Medium | Y | Detects vulnerable NuGet/Python packages, copyleft license usage (GPL/AGPL/LGPL), Log4j CVE-2021-44228, end-of-life .NET/Python runtimes. Requires package metadata access. |
| W22 | Compliance Automation | Regulatory Mapping | High | Y | Maps audit findings to SOC 2 Type II controls, HIPAA Security Rule, GDPR requirements. Assesses audit logging, encryption, access control, retention, incident response capabilities. |
| W23 | OpenVAS / External Vulnerability Scan | Vulnerability Management | High | Y | Checks for OpenVAS/Nessus-style tooling, local TLS posture, exposed services, and vulnerability scanner readiness. Provides remediation guidance for scanner coverage and detected risk indicators. |
| W24 | Web Vulnerability Scan | Application Security | High | Y | Audits localhost web services for missing security headers, weak redirects, risky admin paths, and other common web exposure issues. |
| W25 | SQLi Scanner | Application Security | High | Y | Probes local web/database surfaces for SQL injection indicators, unsafe error responses, and weak database exposure. |
| W26 | SAST / SCA Scanner | DevSecOps | High | Y | Reviews local source trees and dependency metadata for insecure coding patterns, vulnerable package versions, wildcard pins, and CI/CD security gaps. |
| W27 | DNS Resolution Security | Network Exposure | High | Y | Reviews Windows DNS client posture, trusted resolver selection, LLMNR/Smart Multi-Homed Name Resolution, NetBIOS over TCP/IP, DoH readiness, and port 53 listener exposure. Can disable LLMNR and Smart Multi-Homed Name Resolution with `-Fix`. |
| W28 | Backup and Recovery Resilience | Resilience & Recovery | High | Y | Audits backup tooling, recent backup evidence, ransomware-resilience controls, restore point and VSS coverage, backup repository ACLs, and backup location separation. |
| W29 | Privilege Escalation Posture | PrivEsc Prevention | Critical | Y | Detects unquoted service paths, writable service binaries, AlwaysInstallElevated registry keys, writable system PATH dirs, UAC disabled, auto-logon credentials, and SeImpersonatePrivilege abuse vectors. Can disable AlwaysInstallElevated and enforce UAC with `-Fix`. |
| W30 | Deep Persistence Detection | Persistence Mechanisms | Critical | Y | Hunts persistence beyond scheduled tasks: suspicious Registry Run/RunOnce keys (HKLM/HKCU/WOW6432), WMI event subscription bindings, startup folder items, AppInit_DLLs, IFEO debugger hijacks, recently modified System32 binaries, and suspicious PowerShell profile files. Can disable LoadAppInit_DLLs with `-Fix`. |
| W31 | Credential Theft Hardening | Credential Protection | Critical | Y | Audits WDigest plain-text caching, LSASS PPL protection, Credential Guard, cached logon count, NTLM authentication level, SAM remote access restrictions, Windows Credential Manager secrets, and AutoLogon registry credentials. Can disable WDigest, enforce NTLMv2, and reduce cached credentials with `-Fix`. |
| W32 | USB & Removable Media Control | Endpoint Controls | High | Y | Checks AutoRun/AutoPlay policy, removable storage write access GPO, USB device history in registry, BitLocker To Go enforcement, and Windows Portable Device write restrictions. Can disable AutoRun with `-Fix`. |
| W33 | Incident Response Readiness | Detection & Response | High | Y | Assesses IR capability: Sysmon presence, PowerShell Script Block/Module logging, WEF forwarding, Security Event Log retention size, Windows Time service, memory dump configuration, and core triage tool availability. Can enable Script Block Logging and W32Time with `-Fix`. |

---

## Linux Scripts (33 Bash Scripts)

| ID  | Name | Category | Severity | Admin | Description |
|-----|------|----------|----------|-------|-------------|
| L01 | Password Policy | Accounts & Auth | High | Y | Audits `/etc/login.defs`, PAM pwquality, faillock settings, password history depth. Validates min length (14+), complexity, max age (90 days), lockout thresholds. Can set policy values with `--fix`. |
| L02 | Sudo & Privileged Users | Accounts & Auth | High | Y | Enumerates accounts with UID 0, sudo group membership, NOPASSWD entries in sudoers, system accounts with login shells. Identifies unauthorized privilege escalation paths. |
| L03 | Patch Level | Patch Management | Critical | Y | Audits pending security/critical updates via apt/dnf/zypper, checks auto-update configuration (unattended-upgrades status). Can apply upgrades with `--fix`. |
| L04 | Services Audit | Services/Daemons | High | Y | Identifies insecure legacy daemons (Telnet, rsh, NIS), failed systemd units, and risky service configurations. Can disable insecure services with `--fix`. |
| L05 | Network Listeners | Network Exposure | High | Y | Enumerates all active TCP/UDP listeners via `ss` or `netstat`, maps to owning processes/users. Flags risky ports (23, 21, 69, 111, 135, 445 exposed to untrusted networks). |
| L06 | Firewall State | Network Exposure | High | Y | Detects firewall presence: ufw, firewalld, iptables, nftables status. Validates default policies and rule counts. Can enable ufw/firewalld with `--fix`. |
| L07 | SSH Posture | Network Exposure | High | N | Audits `sshd_config`: PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords, ciphers, key algorithms, AllowUsers/DenyUsers, X11Forwarding, MaxAuthTries. No admin required for read-only checks. |
| L08 | Auditd & Logging | Logging & Auditing | High | Y | Checks auditd presence, enabled rules, log disk space, rule count, and buffer limits. Validates audit rule coverage for sensitive files and system calls. Can install and enable auditd with `--fix`. |
| L09 | Syslog Configuration | Logging & Auditing | Medium | Y | Audits rsyslog/syslog-ng presence, remote log forwarding configuration, log file permissions, rotation policy. Can enable/configure syslog with `--fix`. |
| L10 | File Permissions (SUID/SGID) | File Permissions | High | Y | Discovers SUID/SGID binaries, world-writable files, `/etc/shadow` permissions, and insecure directory ownership. Flags unusual or dangerous permission patterns. |
| L11 | LUKS Encryption | Encryption | High | Y | Identifies encrypted partitions via `cryptsetup`, validates LUKS configuration, checks swap encryption status, and key size strength. |
| L12 | Secure Boot | Boot Security | High | Y | Validates Secure Boot enabled via `mokutil`, UEFI present, kernel lockdown status, GRUB password protection, and IMA/EVM. |
| L13 | AV & EDR Presence | Endpoint Protection | Critical | N | Detects ClamAV installation, running EDR agents (Crowdstrike Falcon, Sentinelone, etc.), SELinux/AppArmor enforcing mode, and AIDE/FIM presence. |
| L14 | Cron & Persistence | Persistence Mechanisms | High | Y | Audits cron jobs in `/etc/cron.*`, systemd timers, `/etc/rc.local`, and other startup scripts. Identifies suspicious persistence mechanisms. |
| L15 | CIS Baseline Hardening | Baseline Hardening | High | Y | Validates CIS v1.2+ sysctl hardening: kernel IP forwarding, accept_source_route, ICMP redirects, TCP SYN cookies, IPv6 settings, `/tmp` noexec, umask. Can apply hardening with `--fix`. |
| L16 | Secrets Scanning | Secrets & Credentials | High | Y | Detects `.env`, `.git/config`, `docker/config.json` leaks; searches for AWS/Azure/GCP credentials, API keys, private keys in common locations; flags high-entropy strings in config files. |
| L17 | Attack Surface Management | Network Exposure | High | Y | Discovers open ports, maps to services, identifies unusual listeners. Can close risky ports by persisting iptables DROP rules with `--fix` (iptables-persistent). |
| L18 | API Endpoint Discovery & DAST | Application Security | High | Y | Probes localhost for HTTP/HTTPS services (ports 80, 443, 8000-9000), detects Swagger/OpenAPI/GraphQL, checks security headers (HSTS, CSP, X-Frame-Options), tests for TRACE method. |
| L19 | IaC Security Scanning | DevSecOps | Medium | Y | Scans Dockerfile, docker-compose.yml, Terraform, Kubernetes manifests, Helm charts, Ansible playbooks for secrets, overprivileged containers, insecure defaults. |
| L20 | SCA & License Compliance | Open-Source Risk | Medium | Y | Detects vulnerable Python (`pip list`), npm (`npm list`), or system packages via known vulnerability databases. Identifies copyleft licenses (GPL/AGPL/LGPL) and EOL runtimes. |
| L21 | Vulnerability Scanning | Vulnerability Management | High | Y | Enumerates OS CVEs via `/etc/os-release` + CVE databases, checks OpenSSL/SSH/web-server versions, probes for nmap-detectable services, validates CPU mitigations (Spectre/Meltdown). |
| L22 | Compliance Automation | Regulatory Mapping | High | Y | Maps audit findings to SOC 2 Type II controls, HIPAA Security Rule, GDPR Article 32. Assesses logging, encryption, access control, data retention, incident response, change management capabilities. |
| L23 | OpenVAS / External Vulnerability Scan | Vulnerability Management | High | Y | Checks for GVM/OpenVAS/Nessus tooling, local TLS posture, exposed services, and scanner-driven validation readiness. |
| L24 | Web Vulnerability Scan | Application Security | High | Y | Probes local web services for missing headers, weak redirects, suspicious admin paths, and common HTTP hardening gaps. |
| L25 | SQLi Scanner | Application Security | High | Y | Tests local web/database surfaces for SQL injection indicators, unsafe query handling, and exposed database services. |
| L26 | SAST / SCA Scanner | DevSecOps | High | Y | Scans source trees, dependency locks, and package metadata for insecure patterns, vulnerable dependencies, and remediation opportunities. |
| L27 | DNS Resolution Security | Network Exposure | High | Y | Reviews resolver file permissions, upstream DNS trust profile, DNSSEC, encrypted DNS transport, multicast name-resolution exposure, and port 53 listener exposure. Can harden selected `systemd-resolved` settings with `--fix`. |
| L28 | Backup and Recovery Resilience | Resilience & Recovery | High | Y | Audits backup tooling and schedules, recent backup evidence, local backup storage permissions, snapshot coverage, off-host backup indicators, and failed backup services. |
| L29 | Privilege Escalation Posture | PrivEsc Prevention | Critical | Y | Detects NOPASSWD sudo entries, writable root PATH dirs, writable systemd units, polkit CVE-2021-4034 exposure, SUID on GTFOBins binaries, outdated kernel, dangerous capabilities, writable /etc/passwd|shadow|sudoers, Docker group abuse, and NFS no_root_squash exports. Can remove other-write from writable systemd units with `--fix`. |
| L30 | Deep Persistence Detection | Persistence Mechanisms | Critical | Y | Hunts persistence beyond cron: suspicious user-level systemd units, shell profile backdoors (.bashrc/.profile/.zshrc), LD_PRELOAD/ld.so.preload abuse, PAM module tampering, suspicious /etc/profile.d scripts, non-standard AuthorizedKeysFile locations, recently modified system binaries, and suspicious git hooks. |
| L31 | Credential Theft Hardening | Credential Protection | Critical | Y | Audits password hash algorithm (SHA-512/yescrypt), /etc/shadow permissions, SSH private key permissions, unencrypted SSH keys, sudo credential cache timeout, core dump exposure, cleartext credentials in config files, SSH agent forwarding, shell history credential keywords, and ptrace_scope. Can set ptrace_scope=1 and disable core dumps with `--fix`. |
| L32 | USB & Removable Media Control | Endpoint Controls | High | Y | Checks usb_storage module state and blacklist, recent USB device activity in syslog, usbguard daemon status, removable media automount configuration, fstab entries lacking noexec/nosuid, and world-writable removable mount points. Can blacklist usb_storage with `--fix`. |
| L33 | Incident Response Readiness | Detection & Response | High | Y | Assesses IR capability: auditd status and rule count, remote log forwarding (rsyslog/syslog-ng), journal retention, NTP/time-sync presence, coredump collection, forensic triage tool availability, memory acquisition tools (AVML/LiME), IR documentation on endpoint, and Sysmon for Linux. Can enable systemd-timesyncd with `--fix`. |

---

## Runtime Notes

- Full script coverage requires OS-level tooling in addition to Python packages.
- See [RUNTIME_REQUIREMENTS.md](RUNTIME_REQUIREMENTS.md) for the complete runtime dependency matrix.
- Bootstrap installers are available:
  - Linux: `sudo ./setup/install_runtime_linux.sh --optional --yes`
  - Windows: `PowerShell -ExecutionPolicy Bypass -File .\setup\install_runtime_windows.ps1 -Optional`

## GUI Notes

- The GUI supports run/stop control, rerun-failed workflows, multi-format snapshot export, and per-script tooltip help.
- In Fix Mode, the GUI re-runs each script after remediation and reports verified outcomes: what was fixed, what still fails, and whether verification passed.

---

## Severity Levels

| Level | Description |
|-------|-------------|
| **Critical** | Immediate action required; direct exploitation path or major control missing |
| **High** | Significant weakness; should be remediated within days |
| **Med** | Moderate risk; remediate within weeks; may require compensating controls |
| **Low** | Minor deviation; address in next maintenance cycle |
| **Info** | Informational only; no action required |

## Categories

- **Accounts & Auth** – Password policy, MFA indicators, local admin review
- **Patch Level** – Update freshness, pending patches, vulnerable software inventory
- **Services/Daemons** – Insecure defaults, unnecessary services, unquoted paths
- **Network Exposure** – Listeners, firewall posture, SMB/WinRM/SSH configuration
- **Logging & Auditing** – Event log sizes, audit policy, auditd rules, SIEM forwarding
- **File/Registry Perms** – SUID/SGID, world-writable, critical file permissions
- **Encryption** – BitLocker/LUKS, Secure Boot, TPM, kernel integrity
- **Malware Protections** – AV/EDR presence, signature age, AppArmor/SELinux, FIM
- **Persistence** – Scheduled tasks, cron jobs, startup scripts, registry run keys
- **Baseline Hardening** – CIS-inspired sysctl, registry, and OS configuration checks
- **Resilience & Recovery** – Backup coverage, restore paths, snapshot posture, and ransomware recovery readiness
- **PrivEsc Prevention** – Privilege escalation attack paths: SUID, unquoted paths, writable service binaries, AlwaysInstallElevated
- **Credential Protection** – Credential exposure hardening: WDigest, LSASS PPL, hash algorithms, key permissions
- **Endpoint Controls** – Device-level controls: USB policy, removable media, AutoRun, BitLocker To Go
- **Detection & Response** – IR readiness: Sysmon, PowerShell logging, WEF, retention, triage tools
