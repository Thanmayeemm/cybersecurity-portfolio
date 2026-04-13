# Incident Investigation Report — Ransomware

**Analyst:** Thanmayee Manchikanti  
**Date:** 2026-04-12  
**Severity:** CRITICAL  
**Status:** CLOSED  
**Dataset:** EVTX-ATTACK-SAMPLES — https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES  

---

## 1. Incident Summary

| Field | Detail |
|-------|--------|
| What | Ransomware encryption across user and share paths; recovery features inhibited; encoded PowerShell staging. |
| Who (actor) | Unknown financially motivated actor; C2 **203[.]0[.]113[.]90** / **pay-ransom-bc[.]onion-gate[.]net**. |
| Who (target) | Workstation **DESKTOP-FIN-22** and mapped **Finance** shares. |
| When | **2026-04-11** 09:01–09:03 UTC. |
| Where | Windows enterprise environment. |
| How | Encoded PowerShell → payload execution → mass **.locked** files → **vssadmin** shadow deletion. |
| Impact | Data encryption; recovery inhibition; potential exfiltration not ruled out. |

---

## 2. Attack Timeline

| Timestamp | Event | Log Source | ATT&CK Technique |
|-----------|-------|------------|------------------|
| 2026-04-11T09:01:58Z | Encoded PowerShell | Process creation | T1059.001 |
| 2026-04-11T09:02:01Z | Mass **.locked** writes | File telemetry | T1486 |
| 2026-04-11T09:02:04Z | **vssadmin** delete shadows | Process creation | T1490 |
| 2026-04-11T09:02:07Z | **bcdedit** recovery disabled | Process creation | T1490 |
| 2026-04-11T09:03:10Z | Event log cleared (**wevtutil**) | Process creation | T1070.004 |
| 2026-04-11T09:01:55Z | Defender exclusion added | Process creation | T1562.001 |

---

## 3. Indicators of Compromise (IOCs)

| Type | Value | Verdict | Source |
|------|-------|---------|--------|
| File Hash | SHA256 `b4e9d221...` (binary) | Malicious | SOAR → VirusTotal |
| Domain | **pay-ransom-bc[.]onion-gate[.]net** | Malicious | SOAR → VirusTotal |
| IP | **203[.]0[.]113[.]90** | Malicious | SOAR → VT / AbuseIPDB |
| Ransom note | **HOW_TO_RESTORE.txt** | — | File telemetry |

---

## 4. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|--------|-------------|----------------|----------|
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | Encoded **powershell.exe** |
| Impact | T1486 | Data Encrypted for Impact | **.locked** mass writes |
| Impact | T1490 | Inhibit System Recovery | **vssadmin**, **bcdedit** |
| Defense Evasion | T1070.004 | Indicator Removal: File Deletion | **wevtutil cl** |
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | Defender exclusion |

---

## 5. Investigation Queries

All commands and queries used during this investigation are documented in [`queries.md`](./queries.md).

Key findings from queries:

- Thousands of **.locked** paths in **file_events.txt**.
- **vssadmin** and **bcdedit** commands for recovery inhibition.
- Encoded PowerShell and defender tamper in process creation logs.

---

## 6. SOAR Engine Enrichment

Full enrichment output for all IOCs is in [`ioc-enrichment.md`](./ioc-enrichment.md).

Summary of verdicts:

- **1** IP flagged as malicious
- **1** Domain flagged as malicious
- **1** File hash confirmed malicious

---

## 7. Root Cause Analysis

Execution of untrusted PowerShell with sufficient privileges allowed payload deployment. Lack of robust application control and delayed EDR containment enabled encryption at scale.

---

## 8. Containment & Remediation Steps

| Priority | Action | Owner | Status |
|----------|--------|-------|--------|
| P1 | Isolate hosts; block C2 IP/domain | SOC | Complete |
| P2 | Restore from offline backups; rebuild if needed | IT | In progress |
| P3 | Harden PowerShell, Defender tamper protection | Security | Planned |

---

## 9. Detection Opportunities

See [`queries.md`](./queries.md) for grep patterns. Sigma-style focus: mass extension renames + **vssadmin** in short window.

```yaml
title: Shadow Copy Deletion by Non-Admin Context
status: experimental
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        Image|endswith: '\vssadmin.exe'
        CommandLine|contains: 'Delete Shadows'
    condition: selection
falsepositives:
    - Valid backup admin scripts
level: high
```

---

## 10. Lessons Learned

- Recovery inhibition commands are high-signal precursors to ransom notes.
- SOAR enrichment of hash and C2 accelerates perimeter and DNS blocking.
- Offline backups remain the last line of defense.

---

*Investigation conducted using real public attack datasets. IOC enrichment uses the existing SOAR API only — see [`../../soar-engine/`](../../soar-engine/); this report does not change SOAR code.*
