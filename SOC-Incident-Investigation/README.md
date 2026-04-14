# SOC Incident Investigation Lab

This portfolio demonstrates **hands-on security operations work** grounded in **public, documented attack datasets** (EVTX-ATTACK-SAMPLES, Mordor Security-Datasets, Malware Traffic Analysis, and related sources listed below). Each case follows a disciplined analyst workflow: triage, log review with **Linux CLI tooling** (and Windows tools where noted), indicator extraction, **MITRE ATT&CK** mapping, formal reporting, and **IOC enrichment** through the repository’s **custom SOAR engine** ([`../soar-engine/`](../soar-engine/)), which integrates **VirusTotal** and **AbuseIPDB** with automated alerting and incident logging.

**Lab samples:** Where noted (for example **02-brute-force**), the repo includes **small synthetic log excerpts** so you can replay commands offline. Those excerpts are **OpenSSH-style** teaching files and are **labeled** in-folder; they do not replace the cited public datasets for full realism.

The lab covers **six** incident themes: **phishing**, **brute-force authentication**, **ransomware**, **data exfiltration**, **malware infection (network-focused evidence)**, and **insider threat**.

### Scope (what this folder changes)

- **All work for this lab lives under `SOC-Incident-Investigation/`** (reports, queries, `ioc-enrichment.md`, optional `logs/`, screenshots).
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
| **Log analysis** | Linux CLI: `grep`, `awk`, `sort`, `uniq`, `cut`, `jq` (where JSON is available); Windows Event Viewer for EVTX-backed cases |
| **IOC enrichment** | Custom SOAR Engine — [`../soar-engine/`](../soar-engine/) (VirusTotal v3 + AbuseIPDB v2, weighted combined score, verdict, Slack + SQLite actions) |
| **Framework** | MITRE ATT&CK (enterprise) |
| **Reporting** | Standard sections: 5W summary, timeline, IOC table, MITRE mapping, queries, SOAR enrichment summary, root cause, containment, detection opportunities, lessons learned |
| **Visual evidence** | Optional PNGs per incident — see [`SCREENSHOTS-GUIDE.md`](./SCREENSHOTS-GUIDE.md) |
| **New to log analysis?** | Step-by-step simulation order, prerequisites, and safety — [`BEGINNER-LAB-GUIDE.md`](./BEGINNER-LAB-GUIDE.md) |

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
| [`SCREENSHOTS-GUIDE.md`](./SCREENSHOTS-GUIDE.md) | **When and what to screenshot** for each incident (portfolio checklist) |
| [`BEGINNER-LAB-GUIDE.md`](./BEGINNER-LAB-GUIDE.md) | **Start here** if you are new: how to simulate each incident, prerequisites, suggested order |
| [`01-phishing/`](./01-phishing/) … [`06-insider-threat/`](./06-insider-threat/) | Per incident: `README.md` (report), `queries.md`, `ioc-enrichment.md`, optional `logs/README.md` (data provenance), `screenshots/` (see each folder’s `README.md`) |

**Evidence layout**

- **`logs/`** — Not all incidents ship raw logs (large EVTX/PCAP stay in upstream repos). Each incident that uses external files documents provenance in **`logs/README.md`** where present. **02-brute-force** includes [`logs/sample-auth.log`](./02-brute-force/logs/sample-auth.log); **04-data-exfiltration** includes small CSV/text samples under [`04-data-exfiltration/logs/`](./04-data-exfiltration/logs/) for repeatable CLI practice.
- **`screenshots/`** — Add your own PNGs; filenames suggested in [`SCREENSHOTS-GUIDE.md`](./SCREENSHOTS-GUIDE.md).

---
