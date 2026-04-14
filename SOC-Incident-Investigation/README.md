# SOC Incident Investigation Lab

Hands-on SOC investigation portfolio built from public datasets and reproducible CLI workflows.  
Each case follows: **triage → log analysis → IOC extraction → report → enrichment**.

This lab integrates with the repository’s SOAR service at [`../soar-engine/`](../soar-engine/) using `POST /analyze` (VirusTotal + AbuseIPDB scoring). The investigation folders do not modify SOAR source code.

---

## Investigation Index

| # | Incident | Dataset | Severity | Status |
|---|----------|---------|----------|--------|
| 01 | Phishing | [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | High | Complete |
| 02 | Brute force | [Mordor / Security-Datasets](https://github.com/OTRF/Security-Datasets) | High | Complete |
| 03 | Ransomware | [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | Critical | Complete |
| 04 | Data exfiltration | [Mordor / Security-Datasets](https://github.com/OTRF/Security-Datasets) (+ [Splunk BOTS v3](https://github.com/splunk/botsv3)) | High | Complete |
| 05 | Malware infection | [Malware Traffic Analysis](https://www.malware-traffic-analysis.net) | High | Complete |
| 06 | Insider threat | [Mordor / Security-Datasets](https://github.com/OTRF/Security-Datasets) | High | Complete |

---

## Method

| Area | Approach |
|------|----------|
| Log analysis | Linux CLI (`grep`, `awk`, `sort`, `uniq`, `cut`, `jq`), plus Event Viewer where needed |
| Framework | MITRE ATT&CK mapping per incident |
| Reporting | Standard format: Summary (5W), Timeline, Findings, IOCs, Root Cause, Remediation, Evidence |
| Enrichment | SOAR API (`POST /analyze`) with VT + AbuseIPDB-backed scoring |

---

## What Is in This Folder

| Path | Purpose |
|------|---------|
| [`01-phishing/`](./01-phishing/) … [`06-insider-threat/`](./06-insider-threat/) | Per-incident reports and analysis artifacts |
| [`BEGINNER-LAB-GUIDE.md`](./BEGINNER-LAB-GUIDE.md) | Step-by-step starter guide |
| [`SCREENSHOTS-GUIDE.md`](./SCREENSHOTS-GUIDE.md) | What to capture and when |
| [`VALIDATION-NOTES.md`](./VALIDATION-NOTES.md) | Query-to-conclusion review notes |
| [`investigation-template.md`](./investigation-template.md) | Template for new cases |
| [`datasets/README.md`](./datasets/README.md) | Public dataset sources and usage notes |

---

## Evidence Notes

- Some incidents include small **labeled sample excerpts** for offline replay.
- Large raw EVTX/PCAP artifacts remain in upstream public sources.
- Screenshots are referenced per incident from `./screenshots/<file>.png`.

---

*Analyst: Thanmayee Manchikanti — SOC operations, investigation, and security automation portfolio work.*
