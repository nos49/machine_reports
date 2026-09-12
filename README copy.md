# Machine Reports

A collection of penetration testing writeups from HackTheBox and other lab environments, documented in a consistent professional report format for portfolio purposes.

Each report follows a standard structure: Executive Summary → Scope → Methodology → Findings → Remediation → Appendix, mirroring real-world penetration test deliverables rather than informal walkthroughs.

---

## Reports by Track

Click a track to expand its machine list. New tracks are added here once I actually start them — nothing is pre-listed as a placeholder.

<details open>
<summary><strong>Intro to Red Team</strong> (3)</summary>

| Machine | OS | Difficulty | Key Techniques | Report |
| ------- | -- | ---------- | ---------------- | ------ |
| GoodGames | Linux | Easy | SQLi, SSTI, Docker privesc | [Report](./intro-to-red-team/goodgames/README.md) |
| Writeup | Linux | Easy | SQLi (CVE-2019-9053), Hash Cracking, PATH Hijacking | [Report](./intro-to-red-team/writeup/README.md) |
| Precious | Linux | Easy | Command Injection (CVE-2022-25765), Cleartext Creds, Insecure Deserialization | [Report](./intro-to-red-team/precious/README.md) |

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
| Hash Cracking | Writeup |
| Cleartext Credential Discovery | Precious |

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

## Adding a New Report

**If it belongs to the track currently in progress:**
1. Create a folder: `<track-folder>/<machine-name>/`
2. Copy `TEMPLATE.md` into it as `README.md` and fill it in
3. Add an `images/` subfolder inside it and commit screenshots there directly, using relative paths (`./images/screenshot.png`)
4. Add a row to that track's table above
5. Add any new techniques to the Skills Index

**If it's the first machine in a brand-new track:**
1. Do all of the above, plus add a new `<details>` block under "Reports by Track" for that track before adding its first row

---

## Disclaimer

All reports document activity performed against intentionally vulnerable, isolated lab environments (HackTheBox, or equivalent authorized platforms) for educational and portfolio purposes only. No techniques described here were used against systems without authorization.
