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
| GoodGames | Linux | Easy | SQLi, SSTI, Docker privesc | [Report](./htb/intro-to-read-team/goodgames/README.md) |
| Writeup | Linux | Easy | SQLi (CVE-2019-9053), Hash Cracking, PATH Hijacking | [Report](./htb/intro-to-read-team/writeup/README.md) |
| Precious | Linux | Easy | Command Injection (CVE-2022-25765), Cleartext Creds, Insecure Deserialization | [Report](./htb/intro-to-read-team/precious/README.md) |
| Driver | Windows | Easy | Default creds, NTLM Hash Capture, Hash Cracking, Printer privesc (CVE-2019-19363)| [Report](./htb/intro-to-read-team/driver/README.md) |
| BoardLight | Linux | Easy | Default Creds, Subdomain enum, Dolibarr RCE (CVE-2023-30253), Cleartext creds/reuse, Enlightenment privesc (CVE-2022-37706) | [Report](./htb/intro-to-read-team/boardlightREADME.md) | 

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
| Command Injection | Precious |
| Insecure Deserialization | Precious |
| Docker / Container Privilege Escalation | GoodGames |
| PATH Hijacking / Uncontrolled Search Path | Writeup |
| Hash Cracking | Writeup, Driver |
| Cleartext Credential Discovery | Precious, BoardLight |
| Default password (Basic Authentication | Driver, BoardLight |
| NTLM Hash Capture (Responder) | Driver |
| Credential Reuse | Goodgames, Writeup, Precious, Driver, BoardLight |
| Subdomain Enumeration | BoardLight |


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
