# Incident 6 - Insider Threat

This case simulates a SOC investigation of a **high-risk insider threat** scenario involving **privileged access misuse** and attempted **sensitive data exfiltration**.

## Scenario (Simulated)

- After-hours VPN access is followed by privileged actions on a workstation.
- The user modifies Active Directory privileged group membership.
- The user queries and exports sensitive payroll/PII data from a finance database.
- The user stages data into a ZIP archive and attempts to exfiltrate via USB and external email (blocked/alerted by DLP).

## What’s included

- `incident-logs.txt`: Windows Security, AD group change, DB audit, DLP, EDR, and VPN logs.
- `analysis.txt`: SOC reasoning and investigation workflow.
- `investigation-report.md`: Detailed report with timeline, root cause, containment, remediation, and MITRE mapping.
- `detection-rule.md`: Splunk correlation rule example for privileged misuse + sensitive export + exfil attempts.
- `attack-diagram.md`: High-level attack flow diagram.

## Outcome (Simulated)

The SOC reversed unauthorized privileged changes, contained the endpoint and account, preserved evidence, and escalated to HR/legal per insider threat procedures. DLP controls prevented removable media transfer in the simulated dataset.
