# Incident Investigation Report — [INCIDENT TYPE]

**Analyst:** Thanmayee Manchikanti  
**Date:** [DATE]  
**Severity:** [CRITICAL / HIGH / MEDIUM / LOW]  
**Status:** [CLOSED]  
**Dataset:** [Source name + link]  

---

## 1. Incident Summary

| Field | Detail |
|-------|--------|
| What | |
| Who (actor) | |
| Who (target) | |
| When | |
| Where | |
| How | |
| Impact | |

---

## 2. Attack Timeline

| Timestamp | Event | Log Source | ATT&CK Technique |
|-----------|-------|------------|-----------------|
| | | | |

---

## 3. Indicators of Compromise (IOCs)

| Type | Value | Verdict | Source |
|------|-------|---------|--------|
| IP | | | SOAR Engine → VirusTotal / AbuseIPDB |
| Domain | | | SOAR Engine → VirusTotal |
| File Hash | | | SOAR Engine → VirusTotal |
| Username | | | Internal logs |

---

## 4. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|--------|-------------|----------------|----------|
| | | | |

---

## 5. Investigation Queries

All commands and queries used during this investigation are documented in [`queries.md`](./queries.md).

Key findings from queries:
- 
- 
- 

---

## 6. SOAR Engine Enrichment

Full enrichment output for all IOCs is in [`ioc-enrichment.md`](./ioc-enrichment.md).

Summary of verdicts:
- [X] IPs flagged as malicious
- [X] Domains flagged as malicious  
- [X] File hashes confirmed malicious

---

## 7. Root Cause Analysis

[2–3 sentences describing what enabled this attack — misconfiguration, user action, missing control, etc.]

---

## 8. Containment & Remediation Steps

| Priority | Action | Owner | Status |
|----------|--------|-------|--------|
| P1 | | SOC Analyst | |
| P2 | | | |
| P3 | | | |

---

## 9. Detection Opportunities

What detection rule would have caught this earlier:

```
# Example: grep-based detection
grep -E "Failed password.*([0-9]{1,3}\.){3}[0-9]{1,3}" /var/log/auth.log | \
  awk '{print $11}' | sort | uniq -c | sort -rn | awk '$1 > 5'
```

Sigma rule stub:
```yaml
title: [Detection Name]
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 
        [field]: [value]
    condition: selection
falsepositives:
    - 
level: high
```

---

## 10. Lessons Learned

- 
- 
- 

---

*Investigation conducted using real public attack datasets. IOC enrichment uses the existing SOAR API only — see [`../soar-engine/`](../soar-engine/) for how to run it; this report does not change SOAR code.*
