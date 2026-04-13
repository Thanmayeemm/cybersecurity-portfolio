# IOC Enrichment Report — Insider Threat

**Enrichment:** Output from the existing SOAR Engine API — [`../../soar-engine/`](../../soar-engine/) (run and configure per that project; **do not change SOAR source code** for this lab).  
**APIs used:** VirusTotal v3, AbuseIPDB v2  
**Date enriched:** 2026-04-12  

---

## IP Addresses

### 198[.]51[.]100[.]44 — VPN source (context)

**SOAR Engine verdict:** `suspicious` (confidence: **58.0%**)

| Field | Value |
|------|--------|
| `vt_score` | 45.0 |
| `abuse_score` | 62.0 |
| `combined_score` | **51.8** |

**Note:** Low confidence alone — combine with HR and UEBA context for insider cases.

---

## Domains

### gmail[.]com (recipient)

**SOAR Engine verdict:** `benign` (confidence: **72.0%** — expected for major provider)

**Finding:** Domain reputation is not the signal; **DLP** and policy violations drive this case.

---

*Use SOAR for peripheral network IOCs; primary evidence remains access and mail logs.*
