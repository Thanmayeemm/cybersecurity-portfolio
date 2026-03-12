# Incident 4 - Ransomware

This case simulates a SOC-led investigation of a **ransomware encryption event** impacting a user workstation and an HR file share.

## Scenario (Simulated)

- A user opens a macro-enabled document (`.docm`) disguised as an invoice.
- Microsoft Word spawns PowerShell to download and run a payload.
- The malware attempts to **delete shadow copies**, **disable recovery**, and **clear logs**.
- Files are rapidly renamed/encrypted with a new extension (`.locked`) and a ransom note is created.

## What’s included

- `incident-logs.txt`: SIEM-style Windows, Sysmon, EDR, file server, and firewall/proxy logs.
- `analysis.txt`: How the SOC validated ransomware behavior and scoped impact.
- `investigation-report.md`: Professional incident report with timeline, root cause, containment, remediation, and MITRE mapping.
- `detection-rule.md`: Splunk-style correlation rule for early ransomware detection.
- `attack-diagram.md`: High-level attack flow diagram.

## Outcome (Simulated)

The SOC isolated the endpoint, restricted file share access, blocked external infrastructure, preserved evidence, and initiated recovery from backups. Follow-on hunting found no additional impacted hosts in the simulated dataset.
