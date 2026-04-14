# Incident Investigation Report — Insider Threat

**Analyst:** Thanmayee Manchikanti  
**Date:** 2026-04-12  
**Severity:** HIGH  
**Status:** CLOSED  
**Dataset:** Mordor / Security-Datasets — https://github.com/OTRF/Security-Datasets  

---

## 1. Incident Summary

| Field | Detail |
|-------|--------|
| What | Valid employee account used for after-hours bulk access to sensitive repositories and large personal-email exfiltration. |
| Who (actor) | **jsmith** (insider threat investigation — HR/legal notified). |
| Who (target) | **sensitive_data**, **finance** shares, **S3** archive. |
| When | **2026-04-07** 19:30–20:45 UTC. |
| Where | VPN **198[.]51[.]100[.]44**; services: file share, cloud, SMTP. |
| How | Legitimate credentials; abuse of access to **customers.csv** and **q4.zip**; external **gmail** attachment. |
| Impact | Potential customer and financial data exposure; HR and legal review. |

---

## 2. Attack Timeline

| Timestamp | Event | Log Source | ATT&CK Technique |
|-----------|-------|------------|------------------|
| 2026-04-07T19:30:01Z | VPN session established | vpn.log | T1078 |
| 2026-04-07T19:42:01Z | After-hours read of **customers.csv** | access_log | T1213 |
| 2026-04-07T20:11:33Z | **q4.zip** read from finance share | access_log | T1213 |
| 2026-04-07T20:40:00Z | **S3** object read | cloud_audit | T1530 |
| 2026-04-07T20:45:02Z | Large message to **gmail[.]com** | email_log | T1048 |

---

## 3. Indicators of Compromise (IOCs)

| Type | Value | Verdict | Source |
|------|-------|---------|--------|
| User | **jsmith** | Policy violation | Internal logs |
| IP | **198[.]51[.]100[.]44** (VPN) | Suspicious context | SOAR (peripheral) |
| Volume | **412** file touches; **8.1 MB** email | — | Aggregations |
| Resource | **sensitive_data/customers.csv**, **finance/q4.zip** | — | access_log |

---

## 4. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|--------|-------------|----------------|----------|
| Initial Access | T1078 | Valid Accounts | **jsmith** VPN + app sessions |
| Collection | T1213 | Data from Information Repositories | Share and repo reads |
| Collection | T1530 | Data from Cloud Storage Object | **S3** GetObject |
| Exfiltration | T1048 | Exfiltration Over Alternative Protocol | SMTP to personal webmail |

---

## 5. Investigation Queries

All commands and queries used during this investigation are documented in [`queries.md`](./queries.md).

Key findings from queries:

- After-hours **grep** hits on **sensitive_data**/**finance**.
- **jsmith** exceeded **100** file access events in the window.
- **grep -P** mail log showed **>5 MB** outbound to **gmail[.]com**.

---

## 6. SOAR Engine Enrichment

Full enrichment output for all IOCs is in [`ioc-enrichment.md`](./ioc-enrichment.md).

Summary of verdicts:

- **1** IP assessed as **suspicious** (VPN source — contextual)
- **0** Domains used as primary malicious indicators (consumer webmail)
- **0** File hashes (insider narrative)

---

## 7. Root Cause Analysis

Excessive standing access to customer and finance data without just-in-time controls allowed bulk collection and exfiltration via approved email channel.

---

## 8. Containment & Remediation Steps

| Priority | Action | Owner | Status |
|----------|--------|-------|--------|
| P1 | Suspend **jsmith** access; preserve mail and endpoint | SOC + HR | Complete |
| P2 | DLP blocking for attachments **>5 MB** to webmail | Security | Planned |
| P3 | JIT access to **sensitive_data** | IAM | Planned |

---

## 9. Detection Opportunities

```bash
awk -F'T' '$2 < "08:00" || $2 > "18:00" {print $0}' access_log.txt | grep "sensitive_data"
```

---

## 10. Lessons Learned

- UEBA: after-hours volume anomalies merit automated tickets.
- SOAR IP enrichment supports VPN geolocation checks but does not replace HR/legal process.

---

## Visual evidence (portfolio)

Optional screenshots (after-hours CLI, SIEM/admin view, SOAR IOC): see [`screenshots/README.md`](./screenshots/README.md) and [`../SCREENSHOTS-GUIDE.md`](../SCREENSHOTS-GUIDE.md).

---

*Investigation conducted using real public attack datasets. IOC enrichment uses the existing SOAR API only — see [`../../soar-engine/`](../../soar-engine/); this report does not change SOAR code.*
