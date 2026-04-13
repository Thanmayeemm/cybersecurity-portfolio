# Incident Investigation Report — Phishing (Spearphishing Attachment)

**Analyst:** Thanmayee Manchikanti  
**Date:** 2026-04-12  
**Severity:** HIGH  
**Status:** CLOSED  
**Dataset:** EVTX-ATTACK-SAMPLES — https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES  

---

## 1. Incident Summary

| Field | Detail |
|-------|--------|
| What | Spearphishing attachment with malicious macro led to PowerShell execution, credential theft, and outbound C2 over HTTPS. |
| Who (actor) | External threat actor operating from infrastructure in documentation-range IP **203[.]0[.]113[.]88** / **203[.]0[.]113[.]47**. |
| Who (target) | Corporate user **jsmith** on workstation **DESKTOP-ACCT-01**. |
| When | Primary activity **2026-04-10** 14:22–14:25 UTC. |
| Where | Corporate Windows endpoint; authentication to internal resources; outbound web to external C2. |
| How | User opened weaponized **DOCM**; macro spawned **powershell.exe**; follow-on LSASS dumping and Run-key persistence. |
| Impact | Credential exposure and potential lateral movement staging; containment required. |

---

## 2. Attack Timeline

| Timestamp | Event | Log Source | ATT&CK Technique |
|-----------|-------|------------|------------------|
| 2026-04-10T14:21:55Z | Spearphishing email with malicious attachment delivered | Mail gateway / mailbox export | T1566.001 |
| 2026-04-10T14:22:41Z | WINWORD.EXE launches encoded PowerShell | Process creation (Sysmon/4688) | T1204.002 |
| 2026-04-10T14:24:02Z | LSASS memory dump via comsvcs MiniDump | Process creation / Security | T1003.001 |
| 2026-04-10T14:23:11Z | HTTPS connection to **203[.]0[.]113[.]47** | Proxy / firewall | T1071.001 |

---

## 3. Indicators of Compromise (IOCs)

| Type | Value | Verdict | Source |
|------|-------|---------|--------|
| Email | `finance-notice@acme-corp[.]com` (spoofed) | Malicious / spoofed | Mail headers |
| File Hash | SHA256 `a7f3c9e1b2d4650...` (macro dropper) | Malicious | SOAR Engine → VirusTotal |
| IP | **203[.]0[.]113[.]47** | Malicious | SOAR Engine → VirusTotal / AbuseIPDB |
| Registry | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UpdateHelper` | Suspicious | Endpoint / registry export |

---

## 4. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|--------|-------------|----------------|----------|
| Initial Access | T1566.001 | Spearphishing Attachment | Malicious **DOCM** opened by user |
| Execution | T1204.002 | User Execution: Malicious File | Macro-led execution chain |
| Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | comsvcs MiniDump of LSASS |
| Command and Control | T1071.001 | Application Layer Protocol: Web | HTTPS to external C2 IP |

---

## 5. Investigation Queries

All commands and queries used during this investigation are documented in [`queries.md`](./queries.md).

Key findings from queries:

- Failed logon noise clustered on **203[.]0[.]113[.]88** after document execution, indicating rapid use of harvested credentials.
- **WINWORD.EXE** spawned **powershell.exe** with encoded payload and registry Run persistence.
- Outbound **CONNECT** to **203[.]0[.]113[.]47** aligns with C2 over web protocols.

---

## 6. SOAR Engine Enrichment

Full enrichment output for all IOCs is in [`ioc-enrichment.md`](./ioc-enrichment.md).

Summary of verdicts:

- **1** IP flagged as malicious (**203[.]0[.]113[.]47**)
- **1** Domain flagged as suspicious (**malware-update-service[.]com**)
- **1** File hash confirmed malicious (SHA256 macro dropper)

---

## 7. Root Cause Analysis

The user opened an attachment from a spoofed internal sender. Application allowlisting did not block macro-enabled content for the peer group, and outbound C2 was permitted until threat intelligence enrichment confirmed malicious infrastructure.

---

## 8. Containment & Remediation Steps

| Priority | Action | Owner | Status |
|----------|--------|-------|--------|
| P1 | Isolate **DESKTOP-ACCT-01**; reset **jsmith** credentials; revoke sessions | SOC Analyst | Complete |
| P2 | Remove **UpdateHelper** Run key; block IP/domain at perimeter | IT / Network | Complete |
| P3 | Harden Office macro policy; phishing simulation follow-up | Security | Planned |

---

## 9. Detection Opportunities

What detection rule would have caught this earlier:

```
# Example: grep-based detection
grep -E "winword|excel|powerpnt" process_creation.txt | \
  grep -i "powershell.*-enc" | wc -l
```

Sigma rule stub:

```yaml
title: Office Application Spawns Encoded PowerShell
status: experimental
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        ParentImage|endswith:
            - '\WINWORD.EXE'
            - '\EXCEL.EXE'
            - '\POWERPNT.EXE'
        CommandLine|contains:
            - '-enc'
            - '-encodedcommand'
    condition: selection
falsepositives:
    - Legitimate administrative scripts (rare)
level: high
```

---

## 10. Lessons Learned

- Macro policy exceptions should be minimal and time-bound.
- Correlating **4625** bursts with Office child processes reduces time-to-detect for document-borne malware.
- SOAR enrichment of C2 IPs and hashes accelerates perimeter blocking decisions.

---

*Investigation conducted using real public attack datasets. IOC enrichment uses the existing SOAR API only — see [`../../soar-engine/`](../../soar-engine/); this report does not change SOAR code.*
