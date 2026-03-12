# Incident 5 - Data Exfiltration

This case simulates a SOC investigation into a **suspected data exfiltration attempt** using an **unsanctioned cloud storage service**.

## Scenario (Simulated)

- A finance user stages sensitive files by creating a ZIP archive.
- The user logs into a personal cloud storage app (Dropbox personal) and begins uploading files.
- Proxy/firewall telemetry shows large outbound transfers, and DLP detects/blocks a PII (SSN) upload attempt.

## What’s included

- `incident-logs.txt`: Proxy, firewall, DLP, CASB, EDR, and Windows events correlated into a realistic SIEM narrative.
- `analysis.txt`: Analyst workflow for validation, scoping, and determining likely root cause.
- `investigation-report.md`: Report with timeline, investigation steps, root cause, containment, remediation, and MITRE mapping.
- `detection-rule.md`: Splunk-style detection logic for large uploads to unsanctioned cloud services.
- `attack-diagram.md`: High-level attack flow diagram.

## Outcome (Simulated)

DLP blocked at least one high-risk upload, and the SOC applied containment controls (cloud app restrictions and evidence preservation) while scoping what data may have successfully left the environment.
