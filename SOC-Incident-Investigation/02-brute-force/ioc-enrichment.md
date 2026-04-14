# IOC Enrichment Report — Brute Force

**Enrichment:** Output from the existing SOAR Engine API — [`../../soar-engine/`](../../soar-engine/) (run and configure per that project; **do not change SOAR source code** for this lab).  
**APIs used:** VirusTotal v3, AbuseIPDB v2  
**Date enriched:** 2026-04-12  

---

## IP Addresses

### 203[.]0[.]113[.]15 — brute-force source

**SOAR Engine verdict:** `malicious` (confidence: **94.0%**)

| Field | Value |
|------|--------|
| `vt_score` | 78.0 |
| `abuse_score` | 96.0 |
| `combined_score` | **85.2** |
| VirusTotal (summary) | High proportion of malicious detections; **SSH brute force** reporting |
| AbuseIPDB | Abuse score **98**/100 |

**`action_list`:** `slack_alert` → sent; `log_incident` → stored

**Recommended action:** Block at edge firewall; add to SSH rate-limit / denylist; review **user1** (and other targeted accounts) for lateral movement.

---

*Run live enrichment on indicators from your downloaded Mordor export; values above illustrate the engine response shape.*
