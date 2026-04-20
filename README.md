# Cybersecurity Portfolio

**Thanmayee Manchikanti** — cybersecurity engineer focused on SOC operations, threat detection, and security automation.

This repository is a single workspace for defensive security projects: incident-style investigations backed by public datasets, a SOAR-style enrichment engine, detection tooling, and dashboards.

**Primary project — [SOAR Engine](soar-engine/):** Flask threat-intel pipeline (VirusTotal, AbuseIPDB, Slack, SQLite). Start here if you want the automation code.

---

## Projects

| Project | Description |
|---------|-------------|
| [**SOAR Engine**](soar-engine/) | **Featured:** Flask API — ingest IPs, domains, and hashes → VirusTotal + AbuseIPDB → risk score → verdict → Slack + SQLite. |
| [**SOC Incident Investigation Lab**](SOC-Incident-Investigation/) | Six hands-on investigations (phishing through insider threat) using public datasets, CLI log analysis, MITRE ATT&CK mapping, IOC enrichment via the SOAR engine, optional **[screenshot checklist](SOC-Incident-Investigation/SCREENSHOTS-GUIDE.md)**, and a **[beginner lab guide](SOC-Incident-Investigation/BEGINNER-LAB-GUIDE.md)** (how to simulate each case). |
| [**SOC Threat Detection Engine**](SOC-Threat-Detection-Engine/) | Python detectors for brute force, suspicious logins, and suspicious endpoint processes from auth-style logs. |
| [**SOC Security Dashboard**](SOC-Security-Dashboard/) | Matplotlib dashboard over generated security event CSVs. |
| [**cyber-portfolio**](cyber-portfolio/) | Next.js + Tailwind personal site (deploy separately; points at this repo for code links). |
| [**soc-dashboard**](soc-dashboard/) | Optional full-stack dashboard experiment (Dockerized frontend/backend). |

**Pipeline:** Investigations in `SOC-Incident-Investigation/` are designed to feed extracted IOCs into `soar-engine` (`POST /analyze`) so enrichment and reporting stay consistent end-to-end.

---

## Skills

Security incident response · SOC workflows · Log analysis · Detection engineering · Python automation · MITRE ATT&CK · Threat intelligence enrichment

---

## Tech

Python · Flask · SQLite · Linux CLI · GitHub · Next.js (portfolio site)
