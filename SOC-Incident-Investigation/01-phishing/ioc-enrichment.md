# IOC Enrichment Report — Phishing

**Enrichment:** Output from the existing SOAR Engine API — [`../../soar-engine/`](../../soar-engine/) (run and configure per that project; **do not change SOAR source code** for this lab).  
**APIs used:** VirusTotal v3, AbuseIPDB v2  
**Date enriched:** 2026-04-12  

**Response shape (aligned with `POST /analyze`):** `enrichment` contains `vt_score`, `abuse_score`, `combined_score` (0–100), `weights_applied`; `decision` contains `verdict`, `severity`, `confidence_percent`; `action_list` lists automated actions (for example `slack_alert`, `log_incident`).

---

## IP Addresses

### 203[.]0[.]113[.]47 — C2 server candidate

**SOAR Engine verdict:** `malicious` (confidence: **94.2%**)

| Field | Value |
|------|--------|
| `vt_score` | 82.0 |
| `abuse_score` | 96.0 |
| `combined_score` | **93.6** (weights: VirusTotal **0.6**, AbuseIPDB **0.4**) |
| VirusTotal (summary) | High vendor detection ratio; categories include **command-and-control** |
| AbuseIPDB | Abuse score **96**/100; recent community reports |

**`action_list` (example):** `slack_alert` → sent; `log_incident` → stored (`incident_id` 1042)

**Recommended action:** Block at perimeter firewall; add to threat-intel blocklist; review outbound HTTPS to this destination in proxy logs.

---

## File Hashes

### SHA256: `a7f3c9e1b2d4...` (64 hex chars — representative)

**SOAR Engine verdict:** `malicious` (confidence: **88.9%**)

| Field | Value |
|------|--------|
| `vt_score` | 79.5 |
| `abuse_score` | 0.0 (N/A for file hash) |
| `combined_score` | **79.5** |

**VirusTotal (summary):** Malware family classification **trojan** / **dropper** across multiple engines.

**`action_list`:** `slack_alert` → sent; `log_incident` → stored

---

## Domains

### malware-update-service[.]com — staging / C2 hostname

**SOAR Engine verdict:** `suspicious` (confidence: **61.2%**)

| Field | Value |
|------|--------|
| `vt_score` | 58.0 |
| `abuse_score` | 0.0 (domain-only enrichment path) |
| `combined_score` | **58.0** |

**VirusTotal (summary):** Mixed signals; **phishing**/**C2** tags in some vendors; **newly registered** domain risk.

**`action_list`:** `slack_alert` → sent (medium severity playbook)

---

## Usernames / email (internal — not SOAR-enriched)

| Value | Notes |
|-------|--------|
| `finance-notice@acme-corp[.]com` (spoofed sender) | Correlate with mail gateway; **sender** logged in **Incident 01** `README.md` IOC table |

---

*Run live enrichment against indicators extracted from your downloaded EVTX samples via the SOAR API; values above are representative of engine output format.*
