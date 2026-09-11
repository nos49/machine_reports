# [Machine Name] — [Platform] Report

| Difficulty | OS | Category |
| ---------- | -- | -------- |
| [Easy/Medium/Hard] | [Linux/Windows] | [Web/AD/Pwn/Misc] |

> Writeup of a retired [Machine Name] machine, published for educational/portfolio purposes.

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

**Target:** `[Machine Name] / IP: [X.X.X.X]`
**Platform:** `[HackTheBox / Playground / Other]`
**Date Completed:** `[DATE]`
**Assessment Type:** `[Web Application / Active Directory / Network]`
**Approach:** `Black box` — tested with `no prior knowledge`.

[2-4 sentence summary: who performed the assessment, what was tested, what was found at a high level, and the overall risk conclusion.]

---

## Scope

| Host / URL / IP Address | Description |
| ------------------------- | ------------- |
| `[hostname(s) / IP]` | `Target machine — [OS/service type]` |

> Testing was restricted to the host(s) listed above, consistent with the platform's rules of engagement.

---

## Approach / Methodology

1. **Reconnaissance** — passive/active information gathering on the target.
2. **Scanning & Enumeration** — port/service discovery and fingerprinting.
3. **Vulnerability Analysis** — identifying exploitable misconfigurations or CVEs.
4. **Exploitation** — gaining an initial foothold.
5. **Privilege Escalation** — moving from low-privilege access to admin/root.
6. **Post-Exploitation** — validating impact, capturing flags/evidence, cleanup.

---

## Tools Used

| Tool | Purpose |
| ---- | ------- |
| `[Tool]` | `[What it was used for]` |

---

## Assessment Summary (Findings Overview)

[1-2 sentence summary of the overall attack path and risk conclusion.]

| Severity | Count |
| -------- | ----- |
| Critical | [#] |
| High | [#] |
| Medium | [#] |
| Low | [#] |
| Informational | [#] |

| # | Severity | Finding Name |
| - | -------- | ------------- |
| 1 | [Severity] | [Finding Name] |

*(Full detail on each finding is in the [Technical Findings Details](#technical-findings-details) section below.)*

---

## Attack Chain Walkthrough

> This section documents the full path from unauthenticated access to final compromise, step by step, with commands and evidence. Redact real credentials/sensitive data; lab IPs are fine to show.

### 1.1. Reconnaissance

```
[command]
```

**Findings:** [what was discovered]

### [Continue numbering phases as the attack chain progresses — recon, enumeration, initial foothold, privesc, etc.]

---

## Technical Findings Details

Duplicate this block for each finding, ordered by severity (highest first).

### 1. [Finding Name] — [Severity]

| Field | Details |
| ----- | ------- |
| **CWE** | [CWE-XXX: Name] |
| **CVSS 3.1 Score** | [Score] — `[Vector string]` |
| **Description (Incl. Root Cause)** | [Explain the vulnerability and the underlying misconfiguration that caused it.] |
| **Security Impact** | [Explain what an attacker could achieve by exploiting this.] |
| **Affected Host(s)** | [IP:Port / hostname] |
| **Remediation** | - [Actionable fix 1]<br>- [Actionable fix 2] |
| **References** | [MITRE ATT&CK / vendor advisory link — omit CVE if this is a custom app flaw or misconfiguration rather than a versioned product vulnerability] |

**Evidence:**
```
[command that demonstrates the finding]
```
`[Insert screenshot: describe what it shows]`

---

## Remediation Summary

### Short Term

- **Finding #[N] ([Name])** – [Quick, low-effort fix]

### Medium Term

- **Finding #[N] ([Name])** – [Moderate-effort remediation or process change]

### Long Term

- [Strategic recommendation, e.g., periodic vulnerability assessments]
- [Strategic recommendation, e.g., patch management process improvements]

---

## Lessons Learned / Skills Demonstrated

**Skill/Technique 1:**
[Professional-tone description of the technique and outcome.]

**Skill/Technique 2:**
[Professional-tone description of the technique and outcome.]

---

## Appendix

### A. Finding Severity Definitions

| Rating | Definition |
| ------ | ---------- |
| **Critical** | Exploitation leads to full system/domain compromise with little to no effort or prerequisites. |
| **High** | Exploitation causes substantial harm to confidentiality, integrity, or availability. |
| **Medium** | Exploitation has a moderate impact, or a high-impact issue with limited exposure. |
| **Low** | Exploitation causes minimal impact to operations. |
| **Info** | An observation or improvement opportunity; not itself a vulnerability. |

### B. Exploited Hosts

| Host | Method | Notes |
| ---- | ------ | ----- |
| `[IP/hostname]` | `[technique]` | `[e.g., Initial access]` |

### C. Compromised Users / Credentials

| Username | Method | Notes |
| -------- | ------ | ----- |
| `[user]` | `[how obtained]` | `[what access it granted]` |

### D. Command Reference Log

```
[Consolidated list of every command run during the assessment, in order]
```

### E. References

- [MITRE ATT&CK: T[XXXX] — Technique Name](https://attack.mitre.org/techniques/T[XXXX]/)
- [Official [Platform] Machine Page](https://[link])

> **Note on CVEs:** [State whether any CVEs apply. If findings are custom application logic flaws or misconfigurations rather than known vulnerabilities in versioned third-party software, note that explicitly rather than omitting the field silently.]
