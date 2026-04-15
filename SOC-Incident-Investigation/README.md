# SOC Incident Investigation Lab

## About This Lab

This lab documents hands-on SOC investigations
using public datasets, reproducible CLI workflows, and MITRE ATT&CK
mapping. Each case simulates a real analyst workflow: triage → log
analysis → IOC extraction → report → enrichment.

This lab is designed to integrate with a SOAR service via
`POST /analyze` (VirusTotal + AbuseIPDB scoring) once the
`../soar-engine/` component is complete. The investigation folders do not modify SOAR source code.

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

**ATT&CK coverage:** T1566 · T1059 · T1110 · T1486 · T1048 · T1078
· T1204 — mapped per incident in each report.

**Severity scale:** Critical = confirmed destructive impact ·
High = active exploitation risk · Medium = suspicious, unconfirmed

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

## Reproducibility Notes

- Sample log excerpts for each incident are included for offline
  replay (`logs/sample-excerpt.txt` per incident folder; incident **02**
  uses `logs/sample-auth.log`).
- Large raw EVTX/PCAP artifacts are sourced from the upstream public
  datasets listed in `datasets/README.md` — download instructions
  are included there.
- Where present, portfolio screenshots live under each incident’s
  `./screenshots/` folder; optional additions or retakes follow
  `SCREENSHOTS-GUIDE.md`.

---
