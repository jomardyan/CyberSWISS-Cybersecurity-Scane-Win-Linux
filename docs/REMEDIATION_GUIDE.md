# CyberSWISS Remediation Guide — Fixing Linux and Windows Audit Findings

Per-finding remediation steps for the issues CyberSWISS reports, covering Linux server
hardening and Windows endpoint hardening, with the commands or policy changes that
resolve each finding and what to verify afterwards.

> All changes should be tested in a non-production environment first and approved through your change management process.

---

## Table of Contents

- [Quick Reference](#quick-reference)
- [Accounts & Authentication](#accounts--authentication)
- [Patch Management](#patch-management)
- [Services Hardening](#services-hardening)
- [Network Hardening](#network-hardening)
- [Logging & Auditing](#logging--auditing)
- [Encryption](#encryption)
- [Malware Protections](#malware-protections)
- [Registry & OS Hardening](#registry--os-hardening)
- [Active Directory & GPO (W16)](#advanced-remediation-active-directory--gpo-w16)
- [OpenVAS / External Scanning (L23, W23)](#advanced-remediation-openvas--external-scanning-l23-w23)
- [Web Vulnerability Scanning (L24, W24)](#advanced-remediation-web-vulnerability-scanning-l24-w24)
- [SQL Injection Scanning (L25, W25)](#advanced-remediation-sql-injection-scanning-l25-w25)
- [SAST / SCA Scanning (L26, W26)](#advanced-remediation-sast--sca-scanning-l26-w26)
- [DNS Resolution Security (L27, W27)](#advanced-remediation-dns-resolution-security-l27-w27)
- [Backup & Recovery Resilience (L28, W28)](#advanced-remediation-backup--recovery-resilience-l28-w28)
- [Vulnerability & Risk Scanning (L21, W21)](#advanced-remediation-vulnerability--risk-scanning-l21-w21)
- [Secrets & Credentials Scanning (L16, W17)](#advanced-remediation-secrets--credentials-scanning-l16-w17)
- [IaC Security Scanning (L19, W20)](#advanced-remediation-iac-security-scanning-l19-w20)
- [Compliance Automation (L22, W22)](#advanced-remediation-compliance-automation-l22-w22)
- [Privilege Escalation Posture (L29, W29)](#advanced-remediation-privilege-escalation-posture-l29-w29)
- [Deep Persistence Detection (L30, W30)](#advanced-remediation-deep-persistence-detection-l30-w30)
- [Credential Theft Hardening (L31, W31)](#advanced-remediation-credential-theft-hardening-l31-w31)
- [USB & Removable Media Control (L32, W32)](#advanced-remediation-usb--removable-media-control-l32-w32)
- [Incident Response Readiness (L33, W33)](#advanced-remediation-incident-response-readiness-l33-w33)
- [Network Listeners & Open Ports (L05, W05)](#network-listeners--open-ports-l05-w05)
- [Windows Firewall (W06)](#windows-firewall-w06)
- [File & Directory Permissions (L10)](#file--directory-permissions-l10)
- [Boot Integrity: Secure Boot & TPM (L12, W12)](#boot-integrity-secure-boot--tpm-l12-w12)
- [Scheduled Task & Cron Persistence (L14, W14)](#scheduled-task--cron-persistence-l14-w14)
- [Attack Surface Reduction (L17, W18)](#attack-surface-reduction-l17-w18)
- [API & Web Endpoint Exposure (L18, W19)](#api--web-endpoint-exposure-l18-w19)
- [Dependency & License Risk (L20)](#dependency--license-risk-l20)
- [Disclaimer](#disclaimer)

---

## Quick Reference

CyberSWISS provides automatic remediation via the `--fix` / `-Fix` flag:

```bash
# Linux: Apply all opt-in fixes
sudo python3 common/runner.py --os linux --fix

# Windows: Apply all opt-in fixes
python .\common\runner.py --os windows -Fix
```

Scripts with fix support apply changes automatically when the flag is provided. Read-only scripts provide guidance only and cannot auto-remediate.

For host preparation before remediation, use the bootstrap installers documented in [RUNTIME_REQUIREMENTS.md](RUNTIME_REQUIREMENTS.md):

```bash
sudo ./setup/install_runtime_linux.sh --optional --yes
```

```powershell
PowerShell -ExecutionPolicy Bypass -File .\setup\install_runtime_windows.ps1 -Optional
```

## Verified Fix Mode

When you run remediation from the GUI with `Fix Mode` enabled, CyberSWISS now performs a verification pass after each fix attempt:

1. Run the script with `--fix` / `-Fix`
2. Re-run the same script in read-only mode
3. Record a fix summary:
   - items fixed
   - items still failing or warning
   - verification failures

This matters because some scripts apply remediation after generating their first set of findings, so the initial run alone is not a trustworthy proof of success.

---

## Accounts & Authentication

### Password Policy (W01 / L01)

**Windows – Set minimum password length to 14:**
```
net accounts /MINPWLEN:14
```
Or via Group Policy: `Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy`

**Linux – Set in /etc/security/pwquality.conf:**
```
minlen = 14
minclass = 3
```

**Linux – Set maximum password age in /etc/login.defs:**
```
PASS_MAX_DAYS   90
PASS_MIN_LEN    14
```

**Linux – Configure account lockout (faillock):**
```bash
# /etc/security/faillock.conf
deny = 5
unlock_time = 900
fail_interval = 900
```

### Privileged Accounts (W02 / L02)

**Disable built-in Administrator (Windows):**
```powershell
Disable-LocalUser -Name Administrator
```

**Disable root direct login (Linux):**
```bash
# Lock root password
passwd -l root
# Disable in SSH:
# PermitRootLogin no  (in /etc/ssh/sshd_config)
```

**Remove extra admin group members (Windows):**
```powershell
Remove-LocalGroupMember -Group "Administrators" -Member "Username"
```

---

## Patch Management

### Windows Patching (W03)

```powershell
# Install pending updates (requires PSWindowsUpdate or WSUS)
Install-Module PSWindowsUpdate -Force
Get-WindowsUpdate -Install -AcceptAll
```

### Linux Patching (L03)

```bash
# Debian/Ubuntu
apt-get update && apt-get upgrade -y
# RHEL/CentOS
yum update -y
# Enable automatic security updates (Debian)
apt-get install unattended-upgrades
dpkg-reconfigure unattended-upgrades
```

---

## Services Hardening

### Disable Legacy Services (W04 / L04)

**Windows:**
```powershell
Stop-Service -Name "TlntSvr" -Force
Set-Service -Name "TlntSvr" -StartupType Disabled
```

**Linux:**
```bash
systemctl stop telnet
systemctl disable telnet
# Remove package
apt-get remove --purge telnet telnetd
```

### Fix Unquoted Service Paths (W04):
```powershell
# Find and fix:
$svc = Get-WmiObject Win32_Service -Filter "Name='ServiceName'"
# Edit the ImagePath in registry to add quotes
Set-ItemProperty "HKLM:\SYSTEM\...\ServiceName" ImagePath '"C:\Program Files\App\app.exe"'
```

---

## Network Hardening

### SMBv1 Disable (W07 / W15)

```powershell
# Disable SMBv1 server
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
# Disable SMBv1 Windows feature
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
```

### SSH Hardening (L07)

Edit `/etc/ssh/sshd_config`:
```
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowUsers specific_user1 specific_user2
```
Then: `systemctl reload sshd`

### Linux Firewall (L06)

```bash
# ufw (Ubuntu/Debian)
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw enable

# firewalld (RHEL)
firewall-cmd --set-default-zone=drop
firewall-cmd --add-service=ssh --permanent
firewall-cmd --reload
```

---

## Logging & Auditing

### Windows Event Log Sizes (W08)

```powershell
# Increase Security log to 1GB
wevtutil sl Security /ms:1073741824
wevtutil sl System   /ms:524288000
```

### Audit Policy (W09)

```cmd
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
```

### Enable auditd (L08)

```bash
# Install
apt-get install auditd audispd-plugins   # Debian
yum install audit                         # RHEL

# Start and enable
systemctl enable --now auditd

# Example rules /etc/audit/rules.d/99-cyberswiss.rules:
-w /etc/passwd -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /var/log/lastlog -p wa -k logins
-a always,exit -F arch=b64 -S execve -k exec
```

---

## Encryption

### BitLocker (W11)

```powershell
# Enable on C: with TPM + recovery key
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -TpmProtector
Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector
# Store recovery key in AD
Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId (Get-BitLockerVolume -MountPoint "C:").KeyProtector[1].KeyProtectorId
```

### LUKS (L11)

```bash
# Encrypt new partition (destructive – backup data first)
cryptsetup luksFormat --cipher aes-xts-plain64 --key-size 512 --hash sha256 /dev/sdX
cryptsetup luksOpen /dev/sdX encrypted_vol
mkfs.ext4 /dev/mapper/encrypted_vol
# Add to /etc/crypttab for auto-mount
```

---

## Malware Protections

### Windows Defender (W13)

```powershell
# Enable real-time protection
Set-MpPreference -DisableRealtimeMonitoring $false
# Update signatures
Update-MpSignature
# Enable tamper protection (via Windows Security GUI or MDM/Intune)
```

### ClamAV (L13)

```bash
apt-get install clamav clamav-daemon
systemctl enable --now clamav-daemon
freshclam
# Schedule daily scan
echo "0 2 * * * root clamscan -r /home --log=/var/log/clamav/daily-scan.log" > /etc/cron.d/clamav-daily
```

---

## Registry & OS Hardening

### Windows Registry (W10 / W15)

```powershell
# Enable LSASS protected process
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f

# Disable WDigest credential caching
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f

# Set NTLMv2 only
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f

# Enable PowerShell script block logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
```

### Linux Sysctl (L15)

```bash
# /etc/sysctl.d/99-cyberswiss.conf
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
kernel.randomize_va_space = 2
kernel.yama.ptrace_scope = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
fs.suid_dumpable = 0

# Apply
sysctl --system
```

---

## Advanced Remediation: Active Directory & GPO (W16)

### Deploy CyberSWISS as GPO Startup Script

Copy `W16_ad_gpo_security.ps1` to your SYSVOL scripts share:

```
\\domain\SYSVOL\domain.name\Policies\{GUID}\Machine\Scripts\Startup\
```

Configure in Group Policy Editor:
1. **Computer Configuration** > **Windows Settings** > **Scripts (Startup/Shutdown)**
2. Add script: `W16_ad_gpo_security.ps1 -Json`
3. Optional: Add `-Fix` flag for automatic hardening remediation

### Enforce Domain Password Policy

```
Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy
```

**Recommended baseline:**
- Minimum password length: 14 characters
- Complexity: Enabled
- Maximum password age: 90 days
- Minimum password age: 1 day
- Password history: 24 remembered passwords

### Deploy LAPS (Local Administrator Password Solution)

```powershell
# Install LAPS Module
Install-Module AdmPwd.PS -Force

# Configure Password Settings (via GPMC):
# Computer Configuration > Policies > Administrative Templates > 
# LAPS > Password Length = 20, Expiration = 30 days

# Delegate schema permissions
Set-AdmPwdComputerSelfPermission -OrgUnit "OU=Servers,DC=domain,DC=com"
```

### Harden Kerberos Encryption

```powershell
# Disable RC4 tickets (enforce AES-256/AES-128 only)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" `
        /v SupportedEncryptionTypes /t REG_DWORD /d 0x7ffffff8 /f

# Enforce AES on domain controllers
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
        /v KdcSupportedEncryptionTypes /t REG_DWORD /d 0xFFFFFFF4 /f
```

---

## Advanced Remediation: OpenVAS / External Scanning (L23, W23)

### Install and Configure OpenVAS / GVM

```bash
# Debian/Ubuntu
sudo apt-get install -y openvas
sudo gvm-setup
sudo gvm-start

# Access the web UI
# https://localhost:9392
```

### Run a Targeted Scan via CLI

```bash
# List available scan configs
gvm-cli socket --xml '<get_configs/>'

# Create a target and start a task
gvm-cli socket --xml '<create_target><name>localhost</name><hosts>127.0.0.1</hosts></create_target>'
```

### Windows — Run Nessus / Tenable via CLI

```powershell
# Export findings from Tenable.io
$Headers = @{ "X-ApiKeys" = "accessKey=$env:TENABLE_ACCESS_KEY; secretKey=$env:TENABLE_SECRET_KEY" }
Invoke-RestMethod -Uri "https://cloud.tenable.com/scans" -Headers $Headers
```

---

## Advanced Remediation: Web Vulnerability Scanning (L24, W24)

### Harden HTTP Security Headers

**Nginx:**
```nginx
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Frame-Options DENY always;
add_header X-Content-Type-Options nosniff always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
```

**Apache:**
```apache
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
Header always set X-Frame-Options "DENY"
Header always set X-Content-Type-Options "nosniff"
Header always set Content-Security-Policy "default-src 'self'"
```

**IIS (Windows):**
```powershell
Add-WebConfigurationProperty -PSPath 'IIS:\' `
  -Filter 'system.webServer/httpProtocol/customHeaders' `
  -Name '.' `
  -Value @{name='X-Frame-Options';value='DENY'}
```

### Disable TRACE / TRACK HTTP Methods

**Apache:**
```apache
TraceEnable Off
```

**Nginx:**
```nginx
if ($request_method = TRACE) { return 405; }
```

---

## Advanced Remediation: SQL Injection Scanning (L25, W25)

### Prevent SQL Injection

**Use parameterized queries:**

```python
# Python (psycopg2)
cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

```java
// Java (JDBC)
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);
```

### Restrict Database Error Responses

**MySQL:**
```sql
-- Never expose SQL errors to end users; use application-level error handling
SET GLOBAL general_log = 'OFF';
```

**PostgreSQL — disable verbose errors in production:**
```ini
# postgresql.conf
client_min_messages = warning
log_min_error_statement = error
```

### Limit Database Exposure

```bash
# Bind MySQL to localhost only
# /etc/mysql/mysql.conf.d/mysqld.cnf
bind-address = 127.0.0.1

# Restrict remote PostgreSQL connections
# /etc/postgresql/*/main/pg_hba.conf
host all all 0.0.0.0/0 reject
```

---

## Advanced Remediation: SAST / SCA Scanning (L26, W26)

### Run Static Analysis Locally

```bash
# Python — Bandit
pip install bandit
bandit -r ./src -ll

# Multi-language — Semgrep
pip install semgrep
semgrep --config=auto ./src
```

### Audit and Fix Vulnerable Dependencies

```bash
# Python
pip install pip-audit
pip-audit

# Node.js
npm audit
npm audit fix

# Ruby
gem install bundler-audit
bundle-audit check --update
```

### Pin Dependency Versions

```txt
# requirements.txt — pin to exact version, not wildcards
requests==2.31.0
cryptography==42.0.5
```

```json
// package.json — avoid ^ or ~ for production dependencies
"dependencies": {
  "express": "4.18.2"
}
```

---

## Advanced Remediation: DNS Resolution Security (L27, W27)

### Disable LLMNR and NetBIOS (Windows)

```powershell
# Disable LLMNR via Group Policy or registry
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f

# Disable NetBIOS over TCP/IP on all adapters
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
$adapters | ForEach-Object { $_.SetTcpipNetbios(2) }
```

### Enable DNS-over-HTTPS / DNS-over-TLS (Linux)

```bash
# systemd-resolved — enable DoH / DoT
# /etc/systemd/resolved.conf
[Resolve]
DNS=1.1.1.1#cloudflare-dns.com 8.8.8.8#dns.google
DNSOverTLS=yes
DNSSEC=yes

systemctl restart systemd-resolved
```

### Validate DNSSEC

```bash
# Test DNSSEC validation
dig @8.8.8.8 +dnssec example.com

# Check for SERVFAIL on tampered responses (expected behaviour with DNSSEC)
dig @1.1.1.1 +dnssec dnssec-failed.org
```

### Harden SPF / DKIM / DMARC

```dns
; SPF record — authorize only listed senders
domain.com. TXT "v=spf1 include:_spf.google.com ~all"

; DMARC record — reject unauthenticated mail
_dmarc.domain.com. TXT "v=DMARC1; p=reject; rua=mailto:dmarc@domain.com"
```

---

## Advanced Remediation: Backup & Recovery Resilience (L28, W28)

### Implement Automated Backups (Linux)

```bash
# Install restic
apt-get install restic

# Initialize a repository
restic -r /mnt/backups/myrepo init

# Back up /data daily
restic -r /mnt/backups/myrepo backup /data

# Schedule via cron
echo '0 1 * * * root restic -r /mnt/backups/myrepo backup /data >> /var/log/restic.log 2>&1' \
  > /etc/cron.d/restic-backup

# Verify backup integrity weekly
echo '0 3 * * 0 root restic -r /mnt/backups/myrepo check >> /var/log/restic.log 2>&1' \
  >> /etc/cron.d/restic-backup
```

### Implement Automated Backups (Windows)

```powershell
# Windows Server Backup
wbadmin start backup -backupTarget:E: -include:C: -allCritical -quiet

# Schedule via Task Scheduler
$trigger = New-ScheduledTaskTrigger -Daily -At 01:00
$action  = New-ScheduledTaskAction -Execute 'wbadmin.exe' `
           -Argument 'start backup -backupTarget:E: -include:C: -allCritical -quiet'
Register-ScheduledTask -TaskName 'DailyBackup' -Trigger $trigger -Action $action -RunLevel Highest
```

### Off-Host / Offsite Backup

```bash
# Sync backups to S3 with encryption
restic -r s3:s3.amazonaws.com/mybucket/myrepo \
  --password-file /etc/restic/password \
  backup /data

# Enforce 3-2-1 rule:
# 3 copies, on 2 different media types, 1 offsite
```

### Test Restore Procedure

```bash
# Restore a specific file from a snapshot
restic -r /mnt/backups/myrepo restore latest --target /tmp/restore-test --path /data/important.txt

# Verify the restored file
diff /data/important.txt /tmp/restore-test/data/important.txt && echo "Restore verified"
```

---

## Advanced Remediation: Vulnerability & Risk Scanning (L21, W21)

### Understand CVE Severity Mapping

- **Critical**: Remote code execution without authentication  
- **High**: Remote code execution with limited conditions  
- **Medium**: Denial of service, limited data disclosure  
- **Low**: Minor functionality loss or information disclosure  

### Remediation Priority Matrix

| Severity | Timeframe | Action |
|----------|-----------|--------|
| Critical | 24 hours | Patch immediately or isolate system |
| High | 7 days | Schedule emergency patching |
| Medium | 30 days | Include in regular patch cycle |
| Low | 90 days | Include in standard maintenance |

### Compare CVE Baselines

```bash
# Establish baseline
sudo python3 common/runner.py --scripts L21 --output cve_baseline.json --save-db

# After applying patches
sudo python3 common/runner.py --scripts L21 --output cve_current.json --diff

# Review drift to confirm patches applied
```

---

## Advanced Remediation: Secrets & Credentials Scanning (L16, W17)

### Respond to Compromised Credentials

**If AWS keys found:**
```bash
# Immediately revoke compromised keys
aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE

# Generate new keys with least-privilege policy
aws iam create-access-key --user-name app-service
aws iam put-user-policy --user-name app-service --policy-name least-privilege --policy-document file://policy.json
```

**If Azure credentials found:**
```powershell
# Revoke immediately
Remove-AzADAppCredential -ApplicationId "00000000-0000-0000-0000-000000000000"

# Create new credentials with minimal TTL
New-AzADAppCredential -ApplicationId "..." -EndDate (Get-Date).AddDays(30)
```

**If Docker credentials found:**
```bash
# Logout and revoke
docker logout registry.company.com

# Use credential helpers for secure storage (Linux)
sudo apt-get install docker-credential-pass
docker-credential-pass configure
```

---

## Advanced Remediation: IaC Security Scanning (L19, W20)

### Remediate Dockerfile Issues

```dockerfile
FROM debian:12-slim AS builder
RUN apt-get update && apt-get install -y build-essential
COPY src /build
RUN make

FROM debian:12-slim
RUN apt-get update && apt-get install -y ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Run as non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

COPY --from=builder /build/app /app/
COPY --chown=appuser:appuser config.toml /app/

USER appuser
WORKDIR /app

HEALTHCHECK --interval=30s --timeout=3s --start-period=40s \
  CMD curl -f http://localhost:8080/health || exit 1

EXPOSE 8080
ENTRYPOINT ["/app/entrypoint"]
```

### Remediate Terraform Misconfigurations

```hcl
# Restrict security group to specific CIDR
resource "aws_security_group" "app" {
  name = "app-sg"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.20.0.0/16"]  # Corporate network only
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Encrypt RDS with backup
resource "aws_db_instance" "app" {
  allocated_storage       = 100
  engine                  = "postgres"
  engine_version          = "15.2"
  instance_class          = "db.t4g.medium"
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.rds.arn
  backup_retention_period = 30
  skip_final_snapshot     = false
  final_snapshot_identifier = "app-backup-${formatdate("YYYY-MM-DD", timestamp())}"
}

# Block S3 public access
resource "aws_s3_bucket_public_access_block" "app" {
  bucket                  = aws_s3_bucket.app.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

---

## Advanced Remediation: Compliance Automation (L22, W22)

### Map Findings to SOC 2 Controls

| CC Control | Requirement | CyberSWISS Script |
|-----------|-------------|------------------|
| CC6.1 | Logical access & authentication | L02, W02: Privilege auditing |
| CC6.2 | Identity & MFA | W01, L01: Password policy enforcement |
| CC7.1 | System monitoring & logging | L08, L09, W08, W09: Audit configuration |
| CC7.2 | Change management | Git/SCM audit trails |
| CC9.2 | Data backup & recovery | L11, W11: Encryption status |

### Map Findings to HIPAA Security Rule

| HIPAA Rule | CyberSWISS Coverage |
|-----------|-------------------|
| 164.312(a)(1) – Access Controls | L02, W02, W16 privilege review |
| 164.312(a)(2)(i) – Audit Logging | L08, L09, W08, W09 |
| 164.312(c)(1) – Encryption at Rest | L11, W11 (LUKS/BitLocker) |
| 164.312(d) – Malware Protection | L04, L13, W04, W13 |
| 164.312(e)(2) – Encryption in Transit | L07, W07 (SSH/TLS hardening) |
| 164.308(a)(1) – Security Program | L22, W22 (compliance mapping) |

### Export Compliance Dashboard

```bash
# Generate compliance report
sudo python3 common/runner.py --os both --scripts L22 W22 \
  --output compliance_report.json

# Parse and create dashboard CSV
python3 -c "
import json, csv
with open('compliance_report.json') as f:
    report = json.load(f)

with open('compliance_dashboard.csv', 'w') as out:
    writer = csv.writer(out)
    writer.writerow(['Script ID', 'Finding ID', 'Severity', 'SOC2', 'HIPAA', 'GDPR'])
    for finding in report['findings']:
        mapping = finding.get('compliance_mapping', {})
        writer.writerow([
            finding['script_id'],
            finding['id'],
            finding['severity'],
            mapping.get('soc2', 'N/A'),
            mapping.get('hipaa', 'N/A'),
            mapping.get('gdpr', 'N/A')
        ])
"
```

---

---

## Advanced Remediation: Privilege Escalation Posture (L29, W29)

### Disable AlwaysInstallElevated (Windows)

```powershell
# Remove the registry keys that allow MSI to install with SYSTEM privileges
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue
Remove-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue
```

### Enforce UAC Prompting (Windows)

```powershell
# Require credential prompt for admin operations (no silent elevation)
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2
```

### Remove NOPASSWD sudo entries (Linux)

```bash
# Audit and remove NOPASSWD grants from sudoers
sudo visudo   # remove or comment-out lines containing NOPASSWD
# Alternatively, remove individual drop-in files:
sudo rm /etc/sudoers.d/<offending-file>
```

### Fix writable PATH directories owned by root (Linux)

```bash
# Remove world-write permission from directories in root's PATH
chmod o-w /path/to/directory
```

### Remove dangerous SUID bits (Linux – GTFOBins)

```bash
# Remove the setuid bit from a binary (test impact first)
sudo chmod u-s /path/to/binary
```

---

## Advanced Remediation: Deep Persistence Detection (L30, W30)

### Disable LoadAppInit_DLLs (Windows)

```powershell
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name 'LoadAppInit_DLLs' -Value 0
```

### Clear AppInit_DLLs (Windows)

```powershell
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name 'AppInit_DLLs' -Value ''
```

### Remove suspicious Image File Execution Options (Windows)

```powershell
# Remove a debugger shim from a target process (replace notepad.exe with the actual target)
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe' -Name 'Debugger'
```

### Review user-level systemd units (Linux)

```bash
# List and review all user-level service units
systemctl --user list-unit-files --type=service
# Disable any unknown service
systemctl --user disable --now <unit-name>
```

### Check shell profile backdoors (Linux)

```bash
# Audit profile files for unexpected commands
cat ~/.bashrc ~/.bash_profile ~/.profile /etc/profile /etc/profile.d/*.sh
# Remove any unexpected lines and reset LD_PRELOAD
unset LD_PRELOAD
# Remove offending profile.d scripts
sudo rm /etc/profile.d/<suspicious>.sh
```

---

## Advanced Remediation: Credential Theft Hardening (L31, W31)

### Disable WDigest cleartext credential caching (Windows)

```powershell
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0
```

### Enable LSASS Protected Process Light (Windows)

```powershell
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1
# Requires a reboot to take effect
```

### Enforce NTLMv2 (Windows)

```powershell
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5
```

### Reduce cached logon count (Windows)

```powershell
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount' -Value '1'
```

### Set ptrace_scope to restrict process memory reads (Linux)

```bash
echo 'kernel.yama.ptrace_scope = 1' | sudo tee /etc/sysctl.d/99-ptrace.conf
sudo sysctl -p /etc/sysctl.d/99-ptrace.conf
```

### Disable core dumps (Linux)

```bash
# /etc/security/limits.conf
echo '* hard core 0' | sudo tee -a /etc/security/limits.conf
echo 'fs.suid_dumpable = 0' | sudo tee -a /etc/sysctl.d/99-coredump.conf
sudo sysctl -p /etc/sysctl.d/99-coredump.conf
```

---

## Advanced Remediation: USB & Removable Media Control (L32, W32)

### Disable USB mass storage module (Linux)

```bash
echo 'blacklist usb_storage' | sudo tee /etc/modprobe.d/disable-usb-storage.conf
echo 'install usb_storage /bin/true' | sudo tee -a /etc/modprobe.d/disable-usb-storage.conf
sudo update-initramfs -u   # Debian/Ubuntu
# Or: sudo dracut --force   # RHEL/Fedora
```

### Disable AutoRun entirely (Windows)

```powershell
# Disable AutoRun for all drive types
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 0xFF
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'DisableAutoplay' -Value 1
```

### Block USB write access via Group Policy (Windows)

```
Computer Configuration > Administrative Templates > System > Removable Storage Access
  > Removable Disks: Deny write access – Enabled
```

Or registry:
```powershell
$usbKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}'
New-Item -Path $usbKey -Force | Out-Null
Set-ItemProperty -Path $usbKey -Name 'Deny_Write' -Value 1
```

### Install USBGuard (Linux)

```bash
sudo apt-get install -y usbguard
# Generate a policy that whitelists currently connected devices
sudo usbguard generate-policy | sudo tee /etc/usbguard/rules.conf
sudo systemctl enable --now usbguard
```

---

## Advanced Remediation: Incident Response Readiness (L33, W33)

### Enable PowerShell Script Block Logging (Windows)

```powershell
$psLogKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $psLogKey -Force | Out-Null
Set-ItemProperty -Path $psLogKey -Name 'EnableScriptBlockLogging' -Value 1
```

### Enable PowerShell Module Logging (Windows)

```powershell
$modLogKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
New-Item -Path $modLogKey -Force | Out-Null
Set-ItemProperty -Path $modLogKey -Name 'EnableModuleLogging' -Value 1
```

### Increase Security event log size (Windows)

```powershell
# Set Security log to 1 GB
wevtutil sl Security /ms:1073741824
```

### Configure WEF subscription (Windows)

```powershell
# Point Security log to a central collector
$subscriptionKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
New-Item -Path $subscriptionKey -Force | Out-Null
Set-ItemProperty -Path $subscriptionKey -Name '1' -Value 'Server=http://<collector>:5985/wsman/SubscriptionManager/WEC,Refresh=60'
```

### Ensure auditd is running (Linux)

```bash
sudo apt-get install -y auditd
sudo systemctl enable --now auditd
```

### Configure remote log forwarding (Linux)

```bash
# rsyslog: forward to a remote SIEM
echo '*.* @<siem-host>:514' | sudo tee /etc/rsyslog.d/99-remote.conf
sudo systemctl restart rsyslog
```

### Install forensic triage tools (Linux)

```bash
sudo apt-get install -y lsof strace tcpdump chkrootkit volatility3
```

### Sync system clock (Linux)

```bash
sudo systemctl enable --now systemd-timesyncd
# Or for ntpd:
sudo apt-get install -y ntp && sudo systemctl enable --now ntp
```

---

## Network Listeners & Open Ports (L05, W05)

Findings: *Listening Ports Count*, *Ports Bound to All Interfaces*, *Risky Ports*,
*Risky Port Open: N*, *SSH on Default Port 22*.

Every listening port is an entry point. The goal is to bind services to the
narrowest interface that still serves their clients, and to close what nothing
needs.

### Identify what owns a port

```bash
# Linux – process and user behind each listener
sudo ss -tulpn
sudo lsof -i :3306
```

```powershell
# Windows – owning process for a listening port
Get-NetTCPConnection -State Listen |
    Select-Object LocalAddress, LocalPort, OwningProcess,
        @{n='Process';e={(Get-Process -Id $_.OwningProcess).ProcessName}}
```

### Bind services to loopback instead of every interface

A service reported as bound to `0.0.0.0` (or `::`) accepts traffic from any
network the host can reach. Where only local clients need it, bind it to
loopback:

```bash
# PostgreSQL – /etc/postgresql/*/main/postgresql.conf
listen_addresses = 'localhost'

# MySQL / MariaDB – /etc/mysql/mysql.conf.d/mysqld.cnf
bind-address = 127.0.0.1

# Redis – /etc/redis/redis.conf
bind 127.0.0.1 ::1
protected-mode yes
```

Restart the service and re-run the check:

```bash
sudo systemctl restart postgresql
sudo python3 common/runner.py --scripts L05
```

### Close ports that nothing needs

```bash
# Linux – stop and mask the unit that owns the port
sudo systemctl disable --now <service>
sudo systemctl mask <service>
```

```powershell
# Windows – stop the service and block the port at the firewall
Stop-Service -Name <service> -Force
Set-Service  -Name <service> -StartupType Disabled
New-NetFirewallRule -DisplayName "Block <port> inbound" -Direction Inbound `
    -LocalPort <port> -Protocol TCP -Action Block
```

### Where a port must stay open, restrict its sources

```bash
# Linux – only the management subnet may reach SSH
sudo ufw allow from 10.0.10.0/24 to any port 22 proto tcp
sudo ufw deny 22/tcp
```

Moving SSH off port 22 reduces log noise from opportunistic scanning but is not
a control on its own — pair it with key-only authentication (see
[SSH Hardening (L07)](#ssh-hardening-l07)).

---

## Windows Firewall (W06)

Findings: *Firewall Profiles*, *Firewall Profile Disabled: N*,
*Default Inbound Allow: N*, *Inbound Allow Rules Count*,
*Inbound Rules Allowing Risky Ports*.

`W06 -Fix` enables the disabled profiles and sets the default inbound action to
Block. The steps below are the manual equivalent plus the rule review that
cannot be automated safely.

### Enable every profile and block inbound by default

```powershell
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True `
    -DefaultInboundAction Block -DefaultOutboundAction Allow

# Verify
Get-NetFirewallProfile |
    Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
```

### Turn on logging so blocked traffic is reviewable

```powershell
Set-NetFirewallProfile -Profile Domain,Private,Public `
    -LogBlocked True -LogMaxSizeKilobytes 16384 `
    -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log"
```

### Review the inbound allow rules

A high allow-rule count usually means accumulated exceptions nobody owns.
List them worst-first and remove what no longer applies:

```powershell
Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
    Get-NetFirewallPortFilter |
    Where-Object { $_.LocalPort -in 445,3389,5985,5986,135,139 } |
    Format-Table -AutoSize

# Remove a rule once its owner has confirmed it is obsolete
Remove-NetFirewallRule -DisplayName "<rule name>"
```

Scope the rules that must stay to the addresses that legitimately need them:

```powershell
Set-NetFirewallRule -DisplayName "Remote Desktop - User Mode (TCP-In)" `
    -RemoteAddress 10.0.10.0/24
```

### Enforce via GPO

Computer Configuration → Policies → Windows Settings → Security Settings →
Windows Defender Firewall with Advanced Security. Setting the profile state and
default inbound action here prevents local administrators from disabling it.

---

## File & Directory Permissions (L10)

Findings: *Permission: /etc/shadow*, *World-Writable Files*,
*World-Writable Dirs (no sticky)*, *SUID Binaries*, *Unexpected SUID Binaries*,
*SGID Binaries Count*, *Unowned Files*.

### Restore permissions on sensitive files

```bash
sudo chmod 0644 /etc/passwd  /etc/group
sudo chmod 0640 /etc/shadow  /etc/gshadow
sudo chown root:root  /etc/passwd /etc/group
sudo chown root:shadow /etc/shadow /etc/gshadow

# Verify
stat -c '%a %U:%G %n' /etc/passwd /etc/shadow /etc/group /etc/gshadow
```

### World-writable files and directories

```bash
# Locate them (excluding pseudo filesystems)
sudo find / -xdev -type f -perm -0002 -not -path "/proc/*" -ls
sudo find / -xdev -type d -perm -0002 ! -perm -1000 -ls

# Remove world-write from files
sudo find / -xdev -type f -perm -0002 -exec chmod o-w {} +

# Shared directories that must stay writable need the sticky bit,
# so users cannot delete each other's files
sudo chmod +t /path/to/shared/dir
```

### SUID / SGID review

Do not strip SUID blindly — `sudo`, `su`, `passwd`, `mount`, and `ping` need it.
Compare against the distribution's own manifest and investigate the remainder:

```bash
sudo find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -ls > /tmp/suid.txt

# Debian/Ubuntu – which package owns each binary?
while read -r path; do dpkg -S "$path" 2>/dev/null || echo "UNPACKAGED: $path"; done \
    < <(sudo find / -xdev -perm -4000 -type f)

# RHEL/CentOS – verify against the RPM database
rpm -Vf /usr/bin/<binary>
```

Remove the bit only from binaries that have no business holding it:

```bash
sudo chmod u-s /path/to/binary     # SUID
sudo chmod g-s /path/to/binary     # SGID
```

### Unowned files

Files whose UID/GID no longer resolves are usually left behind by deleted
accounts and can become a privilege-escalation foothold:

```bash
sudo find / -xdev \( -nouser -o -nogroup \) -ls
sudo chown root:root /path/to/file      # or delete if genuinely orphaned
```

---

## Boot Integrity: Secure Boot & TPM (L12, W12)

Findings (Linux): *Secure Boot*, *GRUB Password Protected*, *Kernel Lockdown*,
*Kernel Module Loading*, *IMA Enabled*, *dmesg Restriction*.
Findings (Windows): *Firmware Type*, *Secure Boot*, *TPM Version*, *VBS Running*.

Boot integrity cannot be fixed from userspace alone — several steps require
firmware access and a reboot. Plan a maintenance window.

### Linux

```bash
# Confirm the current state
mokutil --sb-state
cat /sys/kernel/security/lockdown

# Password-protect GRUB so boot parameters cannot be edited at the console
sudo grub-mkpasswd-pbkdf2          # copy the resulting grub.pbkdf2.sha512 hash
sudo tee /etc/grub.d/40_custom >/dev/null <<'EOF'
set superusers="admin"
password_pbkdf2 admin grub.pbkdf2.sha512.10000.<hash>
EOF
sudo update-grub        # Debian/Ubuntu
sudo grub2-mkconfig -o /boot/grub2/grub.cfg   # RHEL/CentOS
```

```bash
# Restrict kernel log access to root (hides pointers useful for exploitation)
echo 'kernel.dmesg_restrict = 1' | sudo tee /etc/sysctl.d/99-dmesg.conf
sudo sysctl --system

# Prevent further module loading once boot is complete (irreversible until reboot)
echo 'kernel.modules_disabled = 1' | sudo tee /etc/sysctl.d/99-modules.conf
```

> `modules_disabled=1` blocks every subsequent `modprobe`. Confirm that all
> required modules (storage, network, monitoring agents) load during boot first.

Secure Boot itself is enabled in firmware (UEFI setup → Secure Boot → Enabled)
and requires the kernel and any out-of-tree modules to be signed.

### Windows

```powershell
# State
Confirm-SecureBootUEFI
Get-Tpm
Get-CimInstance -ClassName Win32_DeviceGuard `
    -Namespace root\Microsoft\Windows\DeviceGuard |
    Select-Object VirtualizationBasedSecurityStatus, SecurityServicesRunning
```

- **Firmware Type = Legacy/BIOS** — Secure Boot needs UEFI. Convert the disk
  with `MBR2GPT.exe /convert /allowFullOS`, then switch the firmware to UEFI.
- **TPM missing or 1.2** — enable the TPM/PTT/fTPM in firmware; upgrade to 2.0
  where the platform supports it. BitLocker and Credential Guard depend on it.
- **VBS not running** — enable Virtualization-Based Security:

```powershell
$path = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
New-Item -Path $path -Force | Out-Null
Set-ItemProperty -Path $path -Name EnableVirtualizationBasedSecurity -Value 1 -Type DWord
Set-ItemProperty -Path $path -Name RequirePlatformSecurityFeatures  -Value 3 -Type DWord
# Reboot required
```

Enforce via GPO: Computer Configuration → Administrative Templates → System →
Device Guard → *Turn On Virtualization Based Security*.

---

## Scheduled Task & Cron Persistence (L14, W14)

Findings (Linux): *System Cron Entries*, *User Crontab: N*,
*Suspicious Cron Entry in N*, *Systemd Timers*,
*Systemd Units in User Directories*, *rc.local Active*,
*Shell Init Files*, *Suspicious Shell Init Commands*.
Findings (Windows): *Scheduled Tasks*, *Suspicious Task Command: N*,
*Suspicious Task Path: N*, *SYSTEM HighestPriv Task: N*.

These findings are **detections, not misconfigurations** — the scripts are
read-only here by design. Triage each hit before removing anything: a match may
be a legitimate deployment job.

### Triage checklist

1. Who owns the entry, and does that account still exist?
2. When was it created — does it correlate with a known change?
3. What does it execute: a signed binary in a standard path, or an encoded
   command, a download-and-run, or something in a world-writable directory?
4. Is the same entry present on comparable hosts?

### Linux

```bash
# Inventory every schedule surface
sudo ls -la /etc/cron.d/ /etc/cron.{hourly,daily,weekly,monthly}/
sudo cat /etc/crontab
for u in $(cut -f1 -d: /etc/passwd); do sudo crontab -l -u "$u" 2>/dev/null; done
systemctl list-timers --all
sudo ls -la /etc/systemd/system/ /run/systemd/system/ ~/.config/systemd/user/

# Remove a confirmed-malicious entry
sudo crontab -r -u <user>            # entire user crontab
sudo rm /etc/cron.d/<file>
sudo systemctl disable --now <timer>.timer && sudo rm /etc/systemd/system/<timer>.timer
sudo systemctl daemon-reload
```

Restrict who may schedule work at all:

```bash
# Allow-list model: only listed users may use cron/at
echo 'root' | sudo tee /etc/cron.allow
sudo rm -f /etc/cron.deny
sudo chmod 600 /etc/cron.allow
```

Also inspect shell init files, a common persistence spot:

```bash
sudo grep -RnE 'curl|wget|base64|nc |/dev/tcp' \
    /etc/profile /etc/profile.d/ /etc/bash.bashrc /root/.bashrc /home/*/.bashrc
```

### Windows

```powershell
# Inventory, newest first
Get-ScheduledTask | Get-ScheduledTaskInfo |
    Sort-Object LastRunTime -Descending | Select-Object -First 40

# What does a task actually execute?
(Get-ScheduledTask -TaskName '<name>').Actions |
    Select-Object Execute, Arguments, WorkingDirectory

# Export for offline review / evidence
Export-ScheduledTask -TaskName '<name>' | Out-File "$env:TEMP\<name>.xml"

# Remove once confirmed malicious
Unregister-ScheduledTask -TaskName '<name>' -Confirm:$false
```

Enable task auditing so future changes are recorded:

```powershell
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
# Event IDs 4698 (created), 4699 (deleted), 4702 (updated)
```

---

## Attack Surface Reduction (L17, W18)

Findings (Linux): *Internet-Facing Interfaces*,
*Sensitive Services Bound to 0.0.0.0*, *Risky Open Ports*,
*Web Server Versions*, *SSL/TLS Certificate Expiry*,
*DNS Zone Transfer (AXFR)*, *IPv6 Attack Surface*.
Findings (Windows): *Remote Desktop (RDP)*, *WinRM Listener Security*,
*File Share Exposure*, *Unnecessary Services Running*,
*Windows Features Attack Surface*, *Risky Inbound Firewall Rules*, *ASR Rules*.

### Linux

```bash
# Stop leaking software versions from HTTP responses
# nginx – /etc/nginx/nginx.conf
server_tokens off;
# Apache – /etc/apache2/conf-enabled/security.conf
ServerTokens Prod
ServerSignature Off
```

```bash
# Refuse zone transfers to arbitrary clients (BIND – named.conf.options)
options {
    allow-transfer { 10.0.10.5; };   # secondaries only
};
```

```bash
# Disable IPv6 where it is unused and unmanaged
echo 'net.ipv6.conf.all.disable_ipv6 = 1'     | sudo tee /etc/sysctl.d/99-ipv6.conf
echo 'net.ipv6.conf.default.disable_ipv6 = 1' | sudo tee -a /etc/sysctl.d/99-ipv6.conf
sudo sysctl --system
```

Renew certificates before expiry and automate it:

```bash
sudo certbot renew --dry-run
systemctl list-timers certbot.timer
```

### Windows

```powershell
# RDP: require Network Level Authentication, or disable it entirely
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
    -Name UserAuthentication -Value 1
# Disable RDP where it is not needed
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
    -Name fDenyTSConnections -Value 1

# WinRM: HTTPS listener only, no Basic auth, no unencrypted traffic
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false
Set-Item WSMan:\localhost\Service\Auth\Basic       -Value $false

# Remove shares nobody owns (never remove ADMIN$, C$, IPC$ blindly)
Get-SmbShare | Where-Object { $_.Name -notin 'ADMIN$','C$','IPC$' }
Remove-SmbShare -Name '<share>' -Force

# Remove unused features
Get-WindowsOptionalFeature -Online | Where-Object State -eq 'Enabled'
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
```

Enable Attack Surface Reduction rules in block mode (start in audit mode and
review for a week before enforcing):

```powershell
# Block credential stealing from LSASS
Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 `
    -AttackSurfaceReductionRules_Actions Enabled
# Block Office child processes
Add-MpPreference -AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a `
    -AttackSurfaceReductionRules_Actions Enabled
```

---

## API & Web Endpoint Exposure (L18, W19)

Findings (Linux): *Local HTTP/HTTPS Services*, *HTTP Security Headers*,
*CORS Misconfiguration*, *HTTP TRACE Method*, *HTTPS Redirect*,
*API Documentation Endpoints Exposed*, *Admin/Debug Endpoints*.
Findings (Windows): *Local HTTP/HTTPS Services*, *HTTP Security Headers*,
*CORS Misconfiguration*, *Exposed API Documentation*,
*Admin/Debug Endpoints Exposed*, *IIS Security Configuration*,
*TLS Certificate Expiry*.

Header and TRACE remediation is shared with
[Web Vulnerability Scanning (L24, W24)](#advanced-remediation-web-vulnerability-scanning-l24-w24);
the items below are specific to API exposure.

### Do not ship API documentation to production

Swagger UI, OpenAPI JSON, GraphQL introspection, and `/actuator` hand an
attacker a complete map of the surface.

```python
# FastAPI – disable the docs outside development
app = FastAPI(
    docs_url=None if ENV == "production" else "/docs",
    redoc_url=None,
    openapi_url=None if ENV == "production" else "/openapi.json",
)
```

```yaml
# Spring Boot – expose only the health endpoint
management:
  endpoints:
    web:
      exposure:
        include: health
  endpoint:
    health:
      show-details: never
```

```javascript
// Apollo / GraphQL – no introspection or playground in production
const server = new ApolloServer({
  schema,
  introspection: process.env.NODE_ENV !== 'production',
});
```

Or block the paths at the reverse proxy, so the decision does not depend on the
application:

```nginx
location ~* ^/(swagger|swagger-ui|api-docs|openapi\.json|graphql|actuator|debug|\.env) {
    return 404;
}
```

### Fix permissive CORS

`Access-Control-Allow-Origin: *` combined with
`Access-Control-Allow-Credentials: true` lets any site read authenticated
responses. Reflecting the request's `Origin` is equally unsafe.

```nginx
# Explicit allow-list, never a wildcard alongside credentials
set $cors_origin "";
if ($http_origin ~* ^https://(app|admin)\.example\.com$) { set $cors_origin $http_origin; }
add_header Access-Control-Allow-Origin      $cors_origin always;
add_header Access-Control-Allow-Credentials true        always;
add_header Vary                             Origin      always;
```

### Require HTTPS

```nginx
server {
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;
}
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

### IIS specifics

```powershell
# Remove version-disclosing headers
Remove-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' `
    -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -AtElement @{name='X-Powered-By'}

# Turn off directory browsing and detailed errors
Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse `
    -Name enabled -Value $false -PSPath 'MACHINE/WEBROOT/APPHOST'
Set-WebConfigurationProperty -Filter /system.webServer/httpErrors `
    -Name errorMode -Value 'DetailedLocalOnly' -PSPath 'MACHINE/WEBROOT/APPHOST'
```

Track certificate expiry with the same scan — *TLS Certificate Expiry* warns
before the outage, not after.

---

## Dependency & License Risk (L20)

Findings: *Package Manager Versions*, *Python Package CVE Check*,
*Node.js Package Audit*, *Ruby Gems Security*, *Log4j Vulnerable JARs*,
*Copyleft License Detection*, *End-of-Life OS / Container Base Image*.

Deep SAST/SCA remediation is covered in
[SAST / SCA Scanning (L26, W26)](#advanced-remediation-sast--sca-scanning-l26-w26).
The items below are what L20 specifically flags.

### Patch vulnerable dependencies

```bash
# Python
pip install --upgrade pip-audit && pip-audit --fix

# Node.js – prefer the non-breaking pass first
npm audit fix
npm audit fix --force       # review the resulting major bumps before merging

# Ruby
bundle update --conservative
bundle exec bundle-audit check --update
```

### Log4Shell (CVE-2021-44228)

```bash
# Locate every vulnerable JAR, including ones bundled inside other archives
sudo find / -name "log4j-core-*.jar" 2>/dev/null
```

Upgrade to log4j-core **2.17.1 or later** (2.3.2 for Java 6, 2.12.4 for Java 7).
Removing the `JndiLookup` class is a stop-gap only, for hosts that genuinely
cannot be upgraded today:

```bash
zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
```

### Copyleft licences

GPL/AGPL/LGPL components in a product you distribute create obligations that
are a legal question, not a technical one. Route each finding to whoever owns
licence compliance, and record the decision:

```bash
# Produce the inventory to hand over
pip-licenses --format=markdown --with-urls > licences-python.md
npx license-checker --summary > licences-node.txt
```

Where the obligation is unacceptable, replace the component with a
permissively licensed equivalent, or isolate it behind a network boundary so it
is not distributed.

### End-of-life runtimes and base images

An EOL runtime receives no security fixes, so every future CVE against it stays
open permanently. Track the upgrade as planned work:

```bash
# Container base images – rebuild on a supported tag
docker pull debian:12-slim
docker build --pull -t myapp:latest .

# Check the host's own support window
lsb_release -a
cat /etc/os-release
```


---

## Disclaimer

All remediation steps must be validated in your specific environment.  
Some changes (e.g., `modules_disabled`, `fs.suid_dumpable`) may affect application functionality.  
Always have a rollback plan before applying system-wide hardening changes.
