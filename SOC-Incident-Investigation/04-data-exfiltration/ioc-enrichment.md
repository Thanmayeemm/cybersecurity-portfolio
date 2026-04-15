# IOC Enrichment Report — Data Exfiltration

**Enrichment:** Output from the existing SOAR Engine API — [`../../soar-engine/`](../../soar-engine/) (run and configure per that project; **do not change SOAR source code** for this lab).  
**APIs used:** VirusTotal v3, AbuseIPDB v2  

---

## IP Addresses

### 203[.]0[.]113[.]200 — bulk upload destination

**SOAR Engine verdict:** `malicious` (confidence: **89.0%**)

| Field | Value |
|------|--------|
| `vt_score` | 74.0 |
| `abuse_score` | 92.0 |
| `combined_score` | **81.2** |

**`action_list`:** `slack_alert` → sent; `log_incident` → stored

---

## Domains

### cloud-upload-staging[.]net

**SOAR Engine verdict:** `suspicious` (confidence: **64.0%**)

| Field | Value |
|------|--------|
| `vt_score` | 62.0 |
| `combined_score` | **62.0** |

---

*Enrich indicators extracted from your Mordor/BOTS-aligned exports.*
