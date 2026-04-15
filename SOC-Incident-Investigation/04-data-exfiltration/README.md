# Incident Investigation Report — Data Exfiltration

**Analyst:** Thanmayee Manchikanti  
**Date:** 2026-04-12  
**Severity:** HIGH  
**Status:** CLOSED  
**Dataset:** [Mordor / Security-Datasets](https://github.com/OTRF/Security-Datasets) (supplementary: [Splunk BOTS v3](https://github.com/splunk/botsv3))  
**Lab replay:** CLI samples under [`logs/`](./logs/)  

> **Dataset note:** Raw source logs are not redistributed due to
> size and licensing. Analysis uses files under `logs/` (included)
> plus upstream Mordor / Security-Datasets and Splunk BOTS v3 samples.
> All queries are reproducible via `queries.md`.

---

## 1. Incident Summary

| Field | Detail |
|-------|--------|
| **What** | Directory **discovery**, local **staging** archive, large **HTTPS** upload to external infrastructure. |
| **Who (actor)** | Account **contractor1** on **host-42** (insider or compromised contractor). |
| **Who (data)** | **D:\finance\customers** (customer data). |
| **When** | **2026-04-09** **16:08–16:11** UTC. |
| **Where** | Internal workstation; egress **443** to **203.0.113.200**. |
| **How** | **dir**-style discovery → **customer_pii.zip** in **C:\Temp\staging** → ~**91 MB** HTTPS upload. |
| **Impact** | Potential **PII** exposure; regulatory notification assessment. |

---

## 2. Attack Timeline

| Time (UTC) | Event | ATT&CK |
|------------|-------|--------|
| 2026-04-09T16:07:22Z | **contractor1** interactive logon to **host-42** | T1078 |
| 2026-04-09T16:07:45Z | **Explorer** / shell open; **D:\** drive browsed | T1083 |
| 2026-04-09T16:08:12Z | Recursive listing of finance path | T1083 |
| 2026-04-09T16:08:55Z | Copy / compress activity targeting customer files under **D:\finance\customers** | T1560.001 |
| 2026-04-09T16:09:40Z | Archive **customer_pii.zip** created in staging | T1074.001 |
| 2026-04-09T16:10:15Z | **PowerShell** / **curl**-style invocation of upload client (process start) | T1059 |
| 2026-04-09T16:10:48Z | TLS handshake to **203.0.113.200:443** begins | T1048.003 |
| 2026-04-09T16:11:02Z | ~**91 MB** HTTPS to **203.0.113.200** | T1048.003 / T1567 |

---

## 3. Key Findings

- **network_connections.csv** analysis ranks **203.0.113.200** as top destination by bytes ([`queries.md`](./queries.md) Step 1; [`logs/README.md`](./logs/README.md)).
- **Staging** path **C:\Temp\staging\customer_pii.zip** precedes large upload (Step 2).
- **Session** context ties **contractor1** to activity before exfil (Step 5).

---

## 4. Indicators of Compromise (IOCs)

| Type | Value |
|------|--------|
| IP | **203.0.113.200** |
| Domain | **cloud-upload-staging.net** (per enrichment narrative) |
| Path | **C:\Temp\staging\customer_pii.zip** |
| Volume | ~**91,240,000** bytes (sample CSV) |

---

## 5. MITRE ATT&CK Mapping

| Tactic | ID | Technique | Evidence |
|--------|-----|-----------|----------|
| Discovery | T1083 | File and Directory Discovery | Finance path discovery |
| Collection | T1560.001 | Archive Collected Data | Archive creation before upload |
| Collection | T1074.001 | Data Staged | Zip in **staging** |
| Exfiltration | T1048.003 / T1567 | Exfiltration over web channel | Large **HTTPS** |
| Initial Access | T1078 | Valid Accounts | **contractor1** session used for activity |

---

## 6. Root Cause Analysis

**contractor1** had broad filesystem access without **DLP** blocking large **HTTPS** uploads to non-approved destinations.

---

## 7. Containment & Remediation

| Priority | Action |
|----------|--------|
| **P1** | Disable **contractor1**; block **203.0.113.200** |
| **P2** | **DLP** for archives and bulk upload |
| **P3** | Access review on finance shares |

---

## 8. Detection & Monitoring

Volume-based **awk** on connection exports; pair **staging** paths with **outbound** bytes ([`queries.md`](./queries.md)).

---

## 9. Lessons Learned

- Combine **network volume** with **file staging** to reduce false positives.
- Enrich rare upload destinations via [`ioc-enrichment.md`](./ioc-enrichment.md).

---

## 10. Evidence

| Artifact | Role |
|----------|------|
| [`logs/network_connections.csv`](./logs/network_connections.csv) | Ranks outbound volume; top destination **203.0.113.200** |
| Other files under [`logs/`](./logs/) (see [`logs/README.md`](./logs/README.md)) | Staging path, session context, supporting telemetry |
| [`queries.md`](./queries.md) | Reproducible CLI walkthrough |

This incident is documented end-to-end from **log and CSV analysis**; findings in sections **3–6** are the authoritative evidence record.

---

**References:** [`queries.md`](./queries.md) · [`ioc-enrichment.md`](./ioc-enrichment.md)  

*SOAR via [`../../soar-engine/`](../../soar-engine/).*
