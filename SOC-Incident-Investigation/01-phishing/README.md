# Incident Report — Phishing (Spearphishing Attachment)

**Analyst:** Thanmayee Manchikanti · **Date:** 2026-04-12 · **Severity:** HIGH · **Status:** CLOSED  
**Source:** [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) · CLI replay: [`logs/sample-excerpt.txt`](./logs/sample-excerpt.txt)

---

## Summary (5W)

| | |
|--|--|
| **What** | Malicious **DOCM** opened by user; **WINWORD.EXE** spawned encoded **PowerShell**; failed logons from external IP after execution (credential testing). |
| **Who** | **jsmith** on **DESKTOP-ACCT-01** · Actor infrastructure **203.0.113.88** (failed logons per excerpt). |
| **When** | **2026-04-10** ~**14:22–14:23** UTC (excerpt). |
| **Where** | Windows endpoint; Security / process telemetry (parsed export style in repo). |
| **Why / impact** | Initial access and execution; risk of credential abuse and follow-on activity. |

---

## Attack Timeline

| Time (UTC) | Event |
|------------|--------|
| 14:22:01–14:22:03 | **4625** failed logons; **SourceNetworkAddress** **203.0.113.88** |
| 14:22:41 | **WINWORD.EXE** opens **Invoice_*.docm** |
| 14:23:09 | **WINWORD.EXE** → **powershell.exe -NoP -enc** … |

---

## Key Findings

- **Office → PowerShell** with encoded command matches macro-driven execution.
- **4625** failures cluster on **203.0.113.88** immediately after document activity — consistent with testing harvested credentials.
- Full IOCs and enrichment: [`ioc-enrichment.md`](./ioc-enrichment.md).

---

## Indicators of Compromise (IOCs)

| Type | Value |
|------|--------|
| IP | **203.0.113.88** (logon source in excerpt) |
| Host | **DESKTOP-ACCT-01** |
| User | **corp\jsmith** |
| Behavior | **WINWORD.EXE** → **powershell.exe** (encoded) |

Defend in reports: **203[.]0[.]113[.]88**.

---

## Root Cause

User executed a **macro-enabled** attachment; controls did not block **Office child processes** launching **encoded PowerShell** before damage.

---

## Remediation

| Priority | Action |
|----------|--------|
| P1 | Isolate **DESKTOP-ACCT-01**; reset **jsmith** credentials; revoke sessions |
| P2 | Block IOC **IP**/domains from [`ioc-enrichment.md`](./ioc-enrichment.md) at perimeter |
| P3 | Tighten **macro** policy; phishing awareness |

---

## Evidence

Screenshots (`./screenshots/`):

| File | Shows |
|------|--------|
| [`phishing_document.png`](./screenshots/phishing_document.png) | Document / delivery context |
| [`powershell_execution.png`](./screenshots/powershell_execution.png) | PowerShell execution chain |
| [`attacker_ip.png`](./screenshots/attacker_ip.png) | Network / IP indicator |

![phishing](./screenshots/phishing_document.png)

![powershell](./screenshots/powershell_execution.png)

![ip](./screenshots/attacker_ip.png)

---

**Queries:** [`queries.md`](./queries.md) · **Enrichment:** [`ioc-enrichment.md`](./ioc-enrichment.md)
