# CyberSWISS Remediation Guide

> This guide provides **detailed remediation steps** for findings produced by CyberSWISS audit scripts.  
> All changes should be tested in a non-production environment first and approved through your change management process.

---

## Quick Reference

CyberSWISS provides automatic remediation via the `--fix` / `-Fix` flag:

```bash
# Linux: Apply all opt-in fixes
sudo python3 common/runner.py --os linux --fix

# Windows: Apply all opt-in fixes  
python .\common\runner.py --os windows -Fix
```

Scripts with fix support are marked with ✅. Read-only scripts (marked ❌) provide guidance only and cannot auto-remediate.

For host preparation before remediation, use the bootstrap installers documented in [RUNTIME_REQUIREMENTS.md](/home/jomar/infrascan/CyberSWISS---Cybersecurity-Scaner-/docs/RUNTIME_REQUIREMENTS.md):

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

## Disclaimer

- Automatic remediation coverage varies by script and by host capabilities.
- Some scripts only provide guidance even when a fix flag exists.
- A successful remediation command does not guarantee the target control is fully compliant until a verification audit passes.

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

## Disclaimer

All remediation steps must be validated in your specific environment.  
Some changes (e.g., `modules_disabled`, `fs.suid_dumpable`) may affect application functionality.  
Always have a rollback plan before applying system-wide hardening changes.
