# Machine Reports

A collection of penetration testing writeups from HackTheBox and other lab environments, documented in a consistent professional report format for portfolio purposes.

Each report follows a standard structure: Executive Summary → Scope → Methodology → Findings → Remediation → Appendix, mirroring real-world penetration test deliverables rather than informal walkthroughs.

---

## Index

### HackTheBox

| Machine | OS | Difficulty | Category | Key Techniques | Report |
| ------- | -- | ---------- | -------- | --------------- | ------ |
| GoodGames | Linux | Easy | Web | SQLi, SSTI, Docker privesc | [Report](./htb/goodgames/README.md) |
| Writeup | Linux | Esay | Web | Blind time-based SQLi, Hashcat, Process privesc | [Report](./htb/writeup/README.md)


---

## Skills Index

A quick-reference cross-index of techniques demonstrated across all reports, useful for reviewers scanning for specific competencies.

| Skill / Technique | Machines |
| ------------------ | -------- |
| SQL Injection | GoodGames |
| Server-Side Template Injection (SSTI) | GoodGames |
| Docker / Container Privilege Escalation | GoodGames |
| Blind time-based SQL Injection | Writeup | 
| Hashcat | Writeup |
| Process Privilege Escalation | Writeup |


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
