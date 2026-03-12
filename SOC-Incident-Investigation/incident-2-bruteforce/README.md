# Incident 2 - Brute Force Login Attack

This case simulates a realistic SOC investigation of a **brute force / password guessing** attack against an enterprise identity environment (Microsoft Entra ID + on-prem AD + VPN).

---

## Scenario

The SOC receives an alert that a user account has experienced **many failed logins** followed by a **successful login** from the same external IP. The successful authentication occurs using a **legacy authentication protocol (IMAP)**, and the attacker then successfully authenticates to the corporate VPN.

---

## What you’ll find in this folder

- `incident-logs.txt`: Simulated Entra ID sign-in logs, Windows Security events (4625/4624), VPN auth logs, and firewall context showing failure bursts followed by a success.
- `analysis.txt`: Analyst reasoning explaining why this pattern is suspicious and how it was validated.
- `investigation-report.md`: Full incident response documentation (summary, timeline, IOC, technique, MITRE mapping, containment, remediation).
- `detection-rule.md`: A SIEM-style correlation rule to detect **multiple failed logins within a short time window** followed by a success.

---

## Outcome (Simulated)

The SOC confirmed a brute-force style authentication pattern and responded by:
- Disabling/locking the impacted account and forcing a password reset
- Revoking active sessions/tokens
- Blocking the attacking IP where possible
- Recommending disabling legacy authentication and enforcing MFA/Conditional Access

No confirmed data exfiltration is shown in the provided log window, but risk is elevated due to successful VPN access and warrants additional internal telemetry review.
