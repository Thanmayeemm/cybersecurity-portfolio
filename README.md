# Cybersecurity Portfolio

This repository contains **realistic, SOC-style incident investigations** designed to demonstrate practical skills in:
- **SIEM log analysis and correlation**
- **Incident response documentation**
- **Detection engineering (Splunk/Sigma-style rules)**
- **Threat hunting and scoping**
- **MITRE ATT&CK mapping**

---

## SOC Incident Investigation Lab

All SOC cases live under `SOC-Incident-Investigation/` and include:
- **SIEM-style multi-source logs** (identity, endpoint, Windows events, firewall/proxy, cloud, DLP, etc.)
- **Analyst notes** (`analysis.txt`)
- **Formal investigation reports** (`investigation-report.md`) with timeline + root cause + containment/remediation
- **Detection rules** (`detection-rule.md`)
- **Attack diagrams** (`attack-diagram.md`) for quick understanding

### Incident Cases

- **Incident 1 – Phishing / Credential Theft / Account Compromise**  
  Folder: `SOC-Incident-Investigation/incident-1-phishing/`
- **Incident 2 – Brute Force Login Attack (Failures → Success)**  
  Folder: `SOC-Incident-Investigation/incident-2-bruteforce/`
- **Incident 3 – Malware Infection (EDR + C2 Connections)**  
  Folder: `SOC-Incident-Investigation/incident-3-malware/`
- **Incident 4 – Ransomware (Encryption + Recovery Inhibition)**  
  Folder: `SOC-Incident-Investigation/incident-4-ransomware/`
- **Incident 5 – Data Exfiltration (Unsanctioned Cloud Storage + DLP)**  
  Folder: `SOC-Incident-Investigation/incident-5-data-exfiltration/`
- **Incident 6 – Insider Threat (Privileged Misuse + Exfil Attempts)**  
  Folder: `SOC-Incident-Investigation/incident-6-insider-threat/`

---

## Skills Demonstrated

- **SOC triage and investigation workflows**
- **Event correlation across multiple log sources**
- **IOC extraction and scoping**
- **Detection rule creation and tuning**
- **Incident reporting using enterprise terminology**

---

## How to Use This Repo

- Start in `SOC-Incident-Investigation/` and open any incident folder.
- Read `incident-logs.txt` first, then `analysis.txt`, then the full `investigation-report.md`.
- Review `detection-rule.md` to see how you would detect similar behavior in a SIEM.
