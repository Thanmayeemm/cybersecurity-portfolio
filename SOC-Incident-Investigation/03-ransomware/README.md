# Incident Report — Ransomware

**Analyst:** Thanmayee Manchikanti · **Date:** 2026-04-12 · **Severity:** CRITICAL · **Status:** CLOSED  
**Source:** [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) · CLI replay: [`logs/sample-excerpt.txt`](./logs/sample-excerpt.txt)

---

## Summary (5W)

| | |
|--|--|
| **What** | **.locked** file writes; **vssadmin** shadow deletion; encoded **PowerShell** (excerpt). |
| **Who** | **DESKTOP-FIN-22** / Finance shares (narrative) · C2 **203.0.113.90** / **pay-ransom-bc.onion-gate.net** in full report. |
| **When** | **2026-04-11** ~**09:02** UTC (excerpt). |
| **Where** | Windows enterprise; file + process telemetry. |
| **Why / impact** | Encryption; recovery inhibition; restore from **offline** backups. |

---

## Attack Timeline

| Time (UTC) | Event |
|------------|--------|
| 09:02:01 | **WRITE** **report.docx.locked** |
| 09:02:04 | **vssadmin.exe Delete Shadows /All /Quiet** |
| 09:02:10 | **powershell.exe** encoded execution |

---

## Key Findings

- **Ransomware-style** extension (**.locked**) on file telemetry.
- **vssadmin** delete shadows — **recovery inhibition** (T1490-class).
- Encoded **PowerShell** — execution stage.

---

## Indicators of Compromise (IOCs)

| Type | Value |
|------|--------|
| File pattern | **.locked** |
| Process | **vssadmin.exe** with **Delete Shadows** |
| Hash / IP / domain | See [`ioc-enrichment.md`](./ioc-enrichment.md) |

---

## Root Cause

Untrusted **PowerShell** ran with sufficient privilege; **application control** and **EDR** containment did not stop encryption at scale.

---

## Remediation

| Priority | Action |
|----------|--------|
| P1 | Isolate hosts; block C2 **IP**/domain |
| P2 | Restore from **offline** backups |
| P3 | Constrain **PowerShell**; **tamper protection** on security tools |

---

## Evidence

Screenshots (`./screenshots/`):

| File | Shows |
|------|--------|
| [`powershell_attack.png`](./screenshots/powershell_attack.png) | Encoded PowerShell / staging |
| [`file_encryption.png`](./screenshots/file_encryption.png) | **.locked** / encryption-related view |
| [`recovery_deletion.png`](./screenshots/recovery_deletion.png) | Shadow copy / recovery inhibition |

![ps](./screenshots/powershell_attack.png)

![enc](./screenshots/file_encryption.png)

![vss](./screenshots/recovery_deletion.png)

---

**Queries:** [`queries.md`](./queries.md) · **Enrichment:** [`ioc-enrichment.md`](./ioc-enrichment.md)
