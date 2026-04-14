# SOC Incident Investigation Lab

This portfolio demonstrates **hands-on security operations work** using **real, publicly available attack datasets** (not self-authored fiction). Each case follows a disciplined analyst workflow: triage, log review with **Linux CLI tooling**, indicator extraction, **MITRE ATT&CK** mapping, formal reporting, and **IOC enrichment** through the repository’s **custom SOAR engine** ([`../soar-engine/`](../soar-engine/)), which integrates **VirusTotal** and **AbuseIPDB** with automated alerting and incident logging.

The lab covers **six** incident themes: **phishing**, **brute-force authentication**, **ransomware**, **data exfiltration**, **malware infection (network-focused evidence)**, and **insider threat**.

### Scope (what this folder changes)

- **All work for this lab lives under `SOC-Incident-Investigation/`** (reports, queries, `ioc-enrichment.md`, logs notes, screenshots).
- The **[SOAR engine](../soar-engine/)** **stays as its own project**: you **run** it from that folder (see its README) and **call into** it over HTTP (`POST /analyze`). This investigation lab does not merge with or replace that codebase.
- This lab **does not modify** SOAR source code, config, or dependencies. Enrichment here means **calling the API** and recording or summarizing responses in each incident’s `ioc-enrichment.md`.

---

## Investigation index

| # | Incident Type | Dataset Source | ATT&CK Techniques | Severity | Status |
|---|---------------|----------------|-------------------|----------|--------|
| 01 | Phishing | [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | T1566.001, T1204.002, T1003.001, T1071.001 | High | Documented |
| 02 | Brute force | [Mordor / Security-Datasets](https://github.com/OTRF/Security-Datasets) | T1110.001, T1078, T1021.001 | High | Documented |
| 03 | Ransomware | [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | T1059.001, T1486, T1490, T1070.004, T1562.001 | Critical | Documented |
| 04 | Data exfiltration | [Mordor / Security-Datasets](https://github.com/OTRF/Security-Datasets) (supplementary: [Splunk BOTS v3](https://github.com/splunk/botsv3)) | T1083, T1074.001, T1048.003, T1567 | High | Documented |
| 05 | Malware infection | [Malware Traffic Analysis](https://www.malware-traffic-analysis.net) | T1189, T1055, T1547.001, T1071.001 | High | Documented |
| 06 | Insider threat | [Mordor / Security-Datasets](https://github.com/OTRF/Security-Datasets) | T1078, T1213, T1530, T1048 | High | Documented |

---

## Tools and methodology

| Area | Approach |
|------|------------|
| **Log analysis** | Linux CLI: `grep`, `awk`, `sort`, `uniq`, `cut`, `jq` (where JSON is available) |
| **IOC enrichment** | Custom SOAR Engine — [`../soar-engine/`](../soar-engine/) (VirusTotal v3 + AbuseIPDB v2, weighted combined score, verdict, Slack + SQLite actions) |
| **Framework** | MITRE ATT&CK (enterprise) |
| **Reporting** | Standard sections: 5W summary, timeline, IOC table, MITRE mapping, queries, SOAR enrichment summary, root cause, containment, detection opportunities, lessons learned |

---

## Public data sources

| Source | Link |
|--------|------|
| EVTX-ATTACK-SAMPLES | https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES |
| Mordor Security Datasets | https://github.com/OTRF/Security-Datasets |
| Splunk BOTS v3 | https://github.com/splunk/botsv3 |
| Malware Traffic Analysis | https://www.malware-traffic-analysis.net |

Further notes and credits: [`datasets/README.md`](./datasets/README.md).

---

## SOAR integration

> **Note:** Indicators of compromise from these investigations are **submitted to the existing SOAR service** in this repository (`POST /analyze` on the running app — see the SOAR project’s own README for setup). Enrichment returns normalized **VirusTotal** and **AbuseIPDB** scores, a **combined (0–100) risk score**, a **verdict** (`benign` / `suspicious` / `malicious`), **confidence**, and **response actions**. Summaries and representative API-style output for each case appear in that incident’s **`ioc-enrichment.md`**. **No changes to the SOAR codebase are required for this lab.**

---

## Folder guide

| Path | Purpose |
|------|---------|
| [`investigation-template.md`](./investigation-template.md) | Blank report template for new investigations |
| [`01-phishing/`](./01-phishing/) … [`06-insider-threat/`](./06-insider-threat/) | One folder per incident: `README.md` (full report), `queries.md`, `ioc-enrichment.md`, `logs/source.md`, `screenshots/` |

---
