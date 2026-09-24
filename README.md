# Machine Reports

A collection of penetration testing writeups from HackTheBox and other lab environments, documented in a consistent professional report format for portfolio purposes.

Each report follows a standard structure: Executive Summary → Scope → Methodology → Findings → Remediation → Appendix, mirroring real-world penetration test deliverables rather than informal walkthroughs.

---

## Reports by Track

Click a track to expand its machine list.

<details open>
<summary><strong>Intro to Red Team</strong> </summary>

| Machine | OS | Difficulty | Key Techniques | Report |
| ------- | -- | ---------- | ---------------- | ------ |
| GoodGames | Linux | Easy | SQLi, SSTI, Docker privesc | [Report](./htb/intro-to-red-team/goodgames/README.md) |
| Writeup | Linux | Easy | SQLi (CVE-2019-9053), Hash Cracking, PATH Hijacking | [Report](./htb/intro-to-red-team/writeup/README.md) |
| Precious | Linux | Easy | Command Injection (CVE-2022-25765), Cleartext Creds, Insecure Deserialization | [Report](./htb/intro-to-red-team/precious/README.md) |
| Driver | Windows | Easy | Default creds, NTLM Hash Capture, Hash Cracking, Printer privesc (CVE-2019-19363)| [Report](./htb/intro-to-red-team/driver/README.md) |
| BoardLight | Linux | Easy | Default Creds, Subdomain enum, Dolibarr RCE (CVE-2023-30253), Cleartext creds/reuse, Enlightenment privesc (CVE-2022-37706) | [Report](./htb/intro-to-red-team/boardlight/README.md) | 
| TwoMillion | Linux | Easy | JavaScript Deobfuscation, API Enumeration, Command Injection, System Enumeraton, CVE-2023-0386 | [Report](./htb/intro-to-red-team/twomillion/README.md) |
| SteamCloud | Linux | Easy | Exploiting Kuberenetes | [Report](./htb/intro-to-red-team/steamcloud/README.md) |
|Certified|Windows|Medium|Active Directory enumeration with Bloodhound, Active Directory enumeration with Certipy, Active Directory ACL and DACL abuse, Exploiting ADSC misconfigurations|[Report](./htb/intro-to-red-team/certified/README.md)|
|Administrator|Windows|Medium|Active Directory enumeration with Bloodhound, Abusing ACLS & DACLs in Active Directory, Performing DCSync attacks|[Report](./htb/intro-to-red-team/administrator/README.md)|


</details>


<details open>
<summary><strong>Active Directory Exploitation</strong> </summary>

| Machine | OS | Difficulty | Key Techniques | Report |
| ------- | -- | ---------- | ---------------- | ------ |
| EscapeTwo| Windows | Easy | Active Directory enumeration using Bloodhound, Abuse of misconfigured Active Directory Certificate Services (ADSC), Manipulation of file headers magic bytes, Abusing ACLS & DACLS in Active Directory | [Report](./htb/active_directory_exploitation/escapetwo/README.md) |

</details>

---

## Skills Index

A cross-reference of techniques demonstrated across all reports, useful for reviewers scanning for specific competencies.

<details open>
<summary>Expand skills index</summary>

| Skill / Technique | Machines |
| ------------------ | -------- |
| SQL Injection | GoodGames, Writeup |
| Server-Side Template Injection (SSTI) | GoodGames |
| Command Injection | Precious, TwoMillion |
| Insecure Deserialization | Precious |
| Docker / Container Privilege Escalation | GoodGames |
| PATH Hijacking / Uncontrolled Search Path | Writeup |
| Hash Cracking | Writeup, Driver |
| Cleartext Credential Discovery | Precious, BoardLight, TwoMillion |
| Default password (Basic Authentication | Driver, BoardLight |
| NTLM Hash Capture (Responder) | Driver |
| Credential Reuse | Goodgames, Writeup, Precious, Driver, BoardLight, TwoMillion |
| Subdomain Enumeration | BoardLight |
| JavaScript Deobfuscation | TwoMillion |
| API Enumeration | TwoMillion |


</details>

---

## Report Format

All reports in this repo follow the structure defined in [`TEMPLATE.md`](./TEMPLATE.md), including:

- Executive Summary
- Scope & Methodology
- Findings Overview (with severity breakdown)
- Attack Chain Walkthrough
- Technical Findings Details (CWE, CVSS, remediation, evidence)
- Remediation Summary (short/medium/long term)
- Appendix (severity definitions, exploited hosts, credentials, command log, references)

---

## Disclaimer

All reports document activity performed against intentionally vulnerable, isolated lab environments (HackTheBox, or equivalent authorized platforms) for educational and portfolio purposes only. No techniques described here were used against systems without authorization.
