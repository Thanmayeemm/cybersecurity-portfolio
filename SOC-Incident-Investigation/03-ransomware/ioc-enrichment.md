# IOC Enrichment Report — Ransomware

**Enrichment:** Output from the existing SOAR Engine API — [`../../soar-engine/`](../../soar-engine/) (run and configure per that project; **do not change SOAR source code** for this lab).  
**APIs used:** VirusTotal v3, AbuseIPDB v2  
**Date enriched:** 2026-04-12  

---

## File Hashes

### SHA256: `b4e9d221...` (64 hex — ransomware binary)

**SOAR Engine verdict:** `malicious` (confidence: **91.0%**)

| Field | Value |
|------|--------|
| `vt_score` | 88.0 |
| `combined_score` | **88.0** |

**VirusTotal (summary):** Ransomware family tags across multiple engines.

---

## Domains

### pay-ransom-bc[.]onion-gate[.]net

**SOAR Engine verdict:** `malicious` (confidence: **87.5%**)

| Field | Value |
|------|--------|
| `vt_score` | 85.0 |
| `combined_score` | **85.0** |

---

## IP Addresses

### 203[.]0[.]113[.]90

**SOAR Engine verdict:** `malicious` (confidence: **92.0%**)

| Field | Value |
|------|--------|
| `vt_score` | 80.0 |
| `abuse_score` | 94.0 |
| `combined_score` | **85.6** |

**`action_list`:** `slack_alert` → sent; `log_incident` → stored

---

## Registry (internal — not VT-enriched)

| Key / value | Notes |
|-------------|--------|
| `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` modified | Tamper attempt per process log |

---

*Enrich live IOCs from your EVTX-derived exports via `POST /analyze`.*
