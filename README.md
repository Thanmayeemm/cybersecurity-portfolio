# Cybersecurity Portfolio

**Thanmayee Manchikanti** — cybersecurity analyst focused on SOC operations, threat detection, and security automation.

This repository is a single workspace for defensive security projects: incident-style investigations backed by public datasets, a SOAR-style enrichment engine, detection tooling, and dashboards.

---

## Projects

| Project | Description |
|---------|-------------|
| [**SOC Incident Investigation Lab**](SOC-Incident-Investigation/) | Six hands-on investigations (phishing through insider threat) using public datasets, reproducible CLI log analysis, MITRE ATT&CK mapping per report, and **[beginner lab guide](SOC-Incident-Investigation/BEGINNER-LAB-GUIDE.md)**. **[Dataset sources and CLI replay](SOC-Incident-Investigation/datasets/README.md)** document upstream data and offline excerpt workflows. IOC enrichment is described alongside each case for use with the SOAR engine when integrated. |
| [**SOAR Engine**](soar-engine/) | Flask API: ingest IPs, domains, and hashes → VirusTotal + AbuseIPDB → risk score → verdict → Slack + SQLite. |
| [**SOC Threat Detection Engine**](SOC-Threat-Detection-Engine/) | Python detectors for brute force, suspicious logins, and suspicious endpoint processes from auth-style logs. |
| [**SOC Security Dashboard**](SOC-Security-Dashboard/) | Matplotlib dashboard over generated security event CSVs. |
| [**cyber-portfolio**](cyber-portfolio/) | Next.js + Tailwind personal site (deploy separately; points at this repo for code links). |
| [**soc-dashboard**](soc-dashboard/) | Optional full-stack dashboard experiment (Dockerized frontend/backend). |

**Pipeline:** Investigations in `SOC-Incident-Investigation/` are designed to integrate with `soar-engine` via `POST /analyze` (VirusTotal + AbuseIPDB scoring) once that component is wired end-to-end; each investigation documents IOCs and enrichment paths so reporting stays consistent when SOAR is connected.

---

## Skills

Security incident response · SOC workflows · Log analysis · Detection engineering · Python automation · MITRE ATT&CK · Threat intelligence enrichment

---

## Tech

Python · Flask · SQLite · Linux CLI · GitHub · Next.js (portfolio site)
