# SOC Incident Investigation Lab

This folder contains a set of **realistic, enterprise-style SOC incident investigations**. Each incident is documented the way a SOC analyst/SOC engineer would typically capture an investigation:

- `incident-logs.txt`: SIEM-style multi-source log excerpts (identity, endpoint, Windows, firewall/proxy, cloud, DLP, etc.)
- `analysis.txt`: analyst reasoning, pivots, and conclusions
- `investigation-report.md`: incident report with timeline, root cause, containment, remediation, and MITRE ATT&CK mapping
- `detection-rule.md`: SIEM detection example (Splunk SPL / Sigma-style logic) + tuning notes
- `attack-diagram.md`: high-level attack flow diagram

---

## Incident Cases

- **Incident 1 – Phishing / Credential Theft / Account Compromise**  
  `incident-1-phishing/`
- **Incident 2 – Brute Force Login Attack (Failures → Success)**  
  `incident-2-bruteforce/`
- **Incident 3 – Malware Infection (EDR + C2 Connections)**  
  `incident-3-malware/`
- **Incident 4 – Ransomware (Encryption + Recovery Inhibition)**  
  `incident-4-ransomware/`
- **Incident 5 – Data Exfiltration (Unsanctioned Cloud Storage + DLP)**  
  `incident-5-data-exfiltration/`
- **Incident 6 – Insider Threat (Privileged Misuse + Exfil Attempts)**  
  `incident-6-insider-threat/`

---

## Skills Demonstrated

- SOC triage and investigation workflows
- SIEM correlation and log analysis
- Detection engineering and alert tuning
- Threat hunting/scoping and IOC management
- MITRE ATT&CK mapping and incident documentation
