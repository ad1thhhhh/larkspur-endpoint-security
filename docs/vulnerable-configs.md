# Intentional Vulnerable Configurations

This document records all deliberate misconfigurations applied to the laboratory
endpoints. These weaknesses are intentional, controlled, and confined to the
isolated lab environment.

> ⚠️ **Warning:** Never apply these configurations to production systems.

---

## Linux Endpoint (192.168.100.6)

### 1. Weak Local User Account
```bash
sudo useradd -m labuser
echo "labuser:password123" | sudo chpasswd
```
**Weakness:** Trivially guessable password susceptible to dictionary attack.
**ATT&CK:** T1110 (Brute Force)

### 2. NOPASSWD Sudo Access
```bash
echo "labuser ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers
```
**Weakness:** Eliminates credential barrier for root access.
**ATT&CK:** T1548.003 (Sudo and Sudo Caching)

### 3. SSH Password Authentication Enabled
```bash
# /etc/ssh/sshd_config
PasswordAuthentication yes
```
**Weakness:** Exposes endpoint to remote brute force.
**ATT&CK:** T1021.004 (Remote Services: SSH)

---

## Windows Endpoint (192.168.100.20)

### 1. Weak Local Administrator Account
```powershell
net user labadmin Password1 /add
net localgroup Administrators labadmin /add
```
**Weakness:** Weak shared local admin credential.
**ATT&CK:** T1078 (Valid Accounts)

### 2. Windows Defender Disabled
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```
**Weakness:** Removes host-based malware detection.

### 3. Windows Firewall Disabled
```powershell
netsh advfirewall set allprofiles state off
```
**Weakness:** Removes host-based network filtering.

### 4. Unrestricted PowerShell Execution Policy
```powershell
Set-ExecutionPolicy Unrestricted -Force
```
**Weakness:** Allows unsigned script execution.
**ATT&CK:** T1059.001 (PowerShell)

---

## Restoration Steps

### Linux
```bash
sudo userdel -r labuser
sudo visudo  # remove the labuser NOPASSWD line
sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart ssh
```

### Windows
```powershell
Set-MpPreference -DisableRealtimeMonitoring $false
netsh advfirewall set allprofiles state on
net user labadmin /delete
Set-ExecutionPolicy RemoteSigned -Force
```
