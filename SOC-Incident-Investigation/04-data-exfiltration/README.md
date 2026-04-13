# Incident Investigation Report — Data Exfiltration

**Analyst:** Thanmayee Manchikanti  
**Date:** 2026-04-12  
**Severity:** HIGH  
**Status:** CLOSED  
**Dataset:** Mordor / Security-Datasets — https://github.com/OTRF/Security-Datasets (supplementary: Splunk BOTS v3 — https://github.com/splunk/botsv3)  

---

## 1. Incident Summary

| Field | Detail |
|-------|--------|
| What | Sensitive directory discovery, local staging archive, large HTTPS upload to external infrastructure. |
| Who (actor) | Account **contractor1** on **host-42** (insider or compromised contractor). |
| Who (target) | **D:\\finance\\customers** data. |
| When | **2026-04-09** 16:08–16:11 UTC. |
| Where | Internal workstation; outbound via **443** to **203[.]0[.]113[.]200**. |
| How | Discovery → **customer_pii.zip** in **C:\\Temp\\staging** → HTTPS transfer. |
| Impact | Potential customer PII exposure; regulatory notification assessment required. |

---

## 2. Attack Timeline

| Timestamp | Event | Log Source | ATT&CK Technique |
|-----------|-------|------------|------------------|
| 2026-04-09T16:08:12Z | Recursive directory listing | Process cmd | T1083 |
| 2026-04-09T16:09:40Z | Archive created in staging path | File telemetry | T1074.001 |
| 2026-04-09T16:11:02Z | ~91 MB HTTPS to **203[.]0[.]113[.]200** | Netflow / CSV | T1048.003 / T1567 |

---

## 3. Indicators of Compromise (IOCs)

| Type | Value | Verdict | Source |
|------|-------|---------|--------|
| IP | **203[.]0[.]113[.]200** | Malicious / high-risk | SOAR |
| Domain | **cloud-upload-staging[.]net** | Suspicious | SOAR |
| Staging path | **C:\\Temp\\staging\\customer_pii.zip** | — | File telemetry |
| Volume | ~**91,240,000** bytes (sample) | — | network_connections.csv |

---

## 4. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|--------|-------------|----------------|----------|
| Discovery | T1083 | File and Directory Discovery | **dir /s** of finance path |
| Collection | T1074.001 | Data Staged: Local Data Staging | **customer_pii.zip** |
| Exfiltration | T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | Large HTTPS (unencrypted content relative to tunnel) |
| Exfiltration | T1567 | Exfiltration Over Web Service | Upload to cloud-like host |

---

## 5. Investigation Queries

All commands and queries used during this investigation are documented in [`queries.md`](./queries.md).

Key findings from queries:

- **awk** on **network_connections.csv** ranked **203[.]0[.]113[.]200** as top destination by bytes.
- Archive creation in **C:\\Temp\\staging** preceded the upload.
- **netstat** aggregation showed repeated **443** connections to the same IP.

---

## 6. SOAR Engine Enrichment

Full enrichment output for all IOCs is in [`ioc-enrichment.md`](./ioc-enrichment.md).

Summary of verdicts:

- **1** IP flagged as malicious
- **1** Domain flagged as suspicious
- **0** File hashes (network-centric case)

---

## 7. Root Cause Analysis

Contractor account had excessive filesystem access without DLP blocking on outbound HTTPS uploads to non-approved destinations.

---

## 8. Containment & Remediation Steps

| Priority | Action | Owner | Status |
|----------|--------|-------|--------|
| P1 | Disable **contractor1**; block **203[.]0[.]113[.]200** | SOC | Complete |
| P2 | DLP policy for archives and bulk upload | Security | Planned |
| P3 | Access review for finance shares | IAM | Planned |

---

## 9. Detection Opportunities

```bash
awk -F',' '$9 > 50000 {print $1, $3, $5, $9}' network_connections.csv | sort -k4 -rn | head -20
```

---

## 10. Lessons Learned

- Combine **network volume** with **file staging** detections to reduce false positives.
- SOAR enrichment of rare upload destinations improves response speed.

---

*Investigation conducted using real public attack datasets. IOC enrichment uses the existing SOAR API only — see [`../../soar-engine/`](../../soar-engine/); this report does not change SOAR code.*
