# CyberSWISS Runtime Requirements

> This document lists all dependencies required for full script coverage.  
> `pip install -r requirements.txt` installs Python packages only and is not sufficient for complete audit results.

---

## Table of Contents

- [Core Requirements](#core-requirements)
- [Linux Components](#linux-components)
- [Windows Components](#windows-components)
- [Script Family to Tool Mapping](#script-family-to-tool-mapping)
- [Practical Limitations](#practical-limitation)

---

This repository has two dependency layers:

1. Python packages from [`requirements.txt`](../requirements.txt)
2. OS-level tools used by the audit scripts themselves

Bootstrap scripts are included for convenience:

- Linux: [`setup/install_runtime_linux.sh`](../setup/install_runtime_linux.sh)
- Windows: [`setup/install_runtime_windows.ps1`](../setup/install_runtime_windows.ps1)

## Core Requirements

Required on all platforms:

- Python 3.9+
- Bash 4+ for Linux scripts
- PowerShell 5.1+ for Windows scripts
- Administrative privileges when running remediation or privileged audits

Python install:

```bash
pip install -r requirements.txt
```

GUI requirement:

- Linux GUI usage needs `tkinter` support, usually via `python3-tk`

## Linux Components

Minimum common tools:

- `bash`
- `python3`
- `python3-tk` for `common/gui.py`
- `curl`
- `openssl`
- `iproute2` (`ss`)
- `iptables`
- `nftables`
- `sudo`

Recommended packages for broad script coverage:

- `nmap`
- `nikto`
- `auditd`
- `rsyslog`
- `logrotate`
- `ufw`
- `firewalld`
- `cryptsetup`
- `mokutil`
- `clamav`
- `aide`
- `mysql-client`
- `postgresql-client`
- `redis-tools`
- `docker.io` or Docker Engine
- `terraform`
- `kubectl`
- `helm`
- `ansible`
- `openvas` / `gvm`

Debian/Ubuntu example:

```bash
sudo apt-get update
sudo apt-get install -y \
  python3 python3-pip python3-tk bash curl openssl iproute2 iptables nftables sudo \
  nmap nikto auditd rsyslog logrotate ufw firewalld cryptsetup mokutil clamav aide \
  mysql-client postgresql-client redis-tools docker.io terraform kubectl helm ansible
```

Bootstrap example:

```bash
sudo ./setup/install_runtime_linux.sh --optional --yes
```

RHEL/CentOS/Fedora example:

```bash
sudo dnf install -y \
  python3 python3-pip python3-tkinter bash curl openssl iproute iptables nftables sudo \
  nmap nikto audit rsyslog logrotate firewalld cryptsetup mokutil clamav aide \
  mysql postgresql redis docker terraform kubernetes-client helm ansible
```

Notes:

- Some packages are distribution-specific and may live in EPEL or third-party repos.
- `nikto`, `terraform`, `kubectl`, `helm`, and `openvas/gvm` are often not in the base distro repo.
- Some scripts detect tool presence and degrade gracefully, but full findings require the tools to be installed.

## Windows Components

Base requirements:

- Windows PowerShell 5.1+
- Administrator PowerShell session
- Windows Defender Firewall / NetSecurity cmdlets
- Python 3.9+ if using the Python runner, API, or GUI

Recommended for full Windows script coverage:

- RSAT Active Directory PowerShell module
- IIS `WebAdministration` module if IIS is present
- `python` + `pip`
- `node` + `npm`
- `.NET SDK` or `dotnet`
- `choco` (Chocolatey), if you want package inventory/remediation guidance coverage

Windows optional platform features/tools detected by scripts:

- BitLocker / `manage-bde`
- TPM / Secure Boot support
- Defender / EDR components
- Active Directory cmdlets on domain-joined systems

Example setup notes:

- Install Python from python.org and ensure `python` and `pip` are on `PATH`
- Install RSAT:
  `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0`
- Install Node.js and .NET SDK if you want SCA/IaC/dev tooling coverage

Bootstrap example:

```powershell
PowerShell -ExecutionPolicy Bypass -File .\setup\install_runtime_windows.ps1 -Optional
```

## Script Family to Tool Mapping

Useful mapping for missing findings:

- `L06` firewall checks/remediation: `ufw`, `firewalld`, `iptables`, `nftables`
- `L08`, `L22`: `auditd` / `auditctl`
- `L09`: `rsyslog`, `logrotate`
- `L11`: `cryptsetup`, `dmsetup`
- `L12`: `mokutil`
- `L13`, `L22`: `clamav`, `aide`, `tripwire`, `wazuh`-style tooling
- `L18`, `L24`, `L25`: `curl`
- `L19`: `terraform`, `ansible`, `kubectl`, `helm`, `docker`
- `L20`, `L26`: `pip`, `pip3`, `npm`, `gem`, `bundler-audit`
- `L21`: `openssl`, `nmap`, `nikto`
- `L23`: `openvas` / `gvm`, `nessus`, `openssl`
- `L27`: `systemd-resolved` / `resolvectl`, optionally `unbound`, `ss`
- `L28`: backup tooling such as `restic`/`borg`/`rsnapshot`, plus snapshot tools like `snapper`, `timeshift`, `zfs`, `btrfs-progs`, `lvm2`

## Practical Limitation

Installing every dependency does not guarantee every script will return rich findings.
Some checks depend on the target host actually running the relevant technologies:

- Docker / Kubernetes / Terraform projects
- Web services on localhost
- Databases such as MySQL, PostgreSQL, Redis
- IIS, Active Directory, BitLocker, Defender, or domain-joined features on Windows

The dependency list here ensures the tooling exists. The target environment still needs to contain the technology being audited.
