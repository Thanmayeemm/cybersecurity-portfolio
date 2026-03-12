# Security Incident Response Report

**Incident Type:** Insider Threat / Privileged Misuse + Attempted Data Exfiltration  
**Severity:** High  
**Affected Systems:** Active Directory, FinanceDB (SQL Server), Endpoint (IT-LT-007), VPN, DLP  
**Impacted User:** ACME\\t.brown  
**Detection Source:** UEBA Alert + DLP Enforcement + DB Audit Logs  
**Report Prepared By:** Security Operations Center (SOC)  

---

## Incident Summary

On **2026-03-12**, the SOC investigated anomalous after-hours activity by **ACME\\t.brown**. UEBA flagged unusual privileged access patterns, and DLP controls blocked an attempted transfer of sensitive data to removable media. Investigation revealed:

- An **AD group membership change** adding a service account to **Domain Admins**
- **Database queries and exports** from finance/payroll tables
- **Data staging** via compression into `export.zip`
- **Attempted exfiltration** via USB (blocked) and external email attachment (alerted/blocked)

The activity used legitimate administrative tools and valid credentials, consistent with insider misuse or a serious policy violation requiring HR/legal coordination.

---

## Detection Source

- **UEBA**: “Unusual privileged access to sensitive data” (after-hours + cross-system access)
- **DLP**: Blocked removable media transfer of sensitive ZIP; alerted on external email attachment attempt
- **Database Audit**: Sensitive table access and export events
- **AD Security Logs**: Group membership modification event (4728)

---

## Attack Timeline

| Time (UTC) | Event |
|------------|------|
| 00:56 | VPN logon from home ISP (203.0.113.55) |
| 00:58 | Interactive logon to IT-LT-007 |
| 01:03 | AD change: `svc-backup` added to Domain Admins |
| 01:05–01:06 | SQL queries against payroll/employee tables; export to CSV |
| 01:06 | Archive created: `export.zip` |
| 01:07 | DLP blocks attempted copy of ZIP to USB |
| 01:08 | DLP alerts on attempted external email attachment |
| 01:12 | UEBA correlates events and raises High severity alert |

---

## Investigation Steps

1) **Validate and correlate alerts**
- Confirmed UEBA, DLP, AD, and DB audit events aligned by user (`t.brown`), host (`IT-LT-007`), and time window.

2) **Review privileged activity**
- Verified AD event 4728 and captured change context (workstation, source IP, target account).
- Determined whether a valid change request existed for Domain Admins membership modification.

3) **Review sensitive data access**
- Examined DB audit statements, row counts, and export activity.
- Identified tables accessed and potential data sensitivity (payroll + SSN).

4) **Confirm data staging and exfil attempts**
- Confirmed `sqlcmd.exe` export to `C:\\Temp\\payroll_export.csv`
- Confirmed `7z.exe` archive creation `export.zip`
- Reviewed DLP enforcement on USB and outbound email.

5) **Scope and hunt**
- Searched for:
  - Additional group membership changes by `t.brown`
  - Other hosts performing `sqlcmd` exports
  - Other attempted transfers of `export.zip` or similar archives

6) **Preserve evidence**
- Preserved endpoint telemetry and relevant logs for HR/legal chain-of-custody handling.

---

## Root Cause

Most likely root cause is **insider misuse of privileged access** (or unauthorized administrative actions) to access and attempt to remove sensitive payroll/PII data using native administrative tooling. No malware indicators are present in the dataset; the activity is consistent with valid-user tooling misuse.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|-------|-----------|----|----------|
| Privilege Escalation | Account Manipulation | T1098 | Adding `svc-backup` to Domain Admins |
| Collection | Data from Information Repositories | T1213 | Queries against finance/payroll DB |
| Collection | Archive Collected Data | T1560 | ZIP archive creation (`export.zip`) |
| Exfiltration | Exfiltration to Removable Media | T1025 | Attempted USB copy (blocked) |
| Exfiltration | Exfiltration Over Email | T1048.003 (related) | Attempted external email attachment (alerted/blocked) |

---

## Containment Actions

- Immediately removed unauthorized Domain Admins membership change and reviewed all recent privileged group modifications.
- Suspended or restricted `t.brown` account pending investigation; forced password reset and revoked sessions.
- Quarantined the endpoint `IT-LT-007` for evidence collection.
- Preserved exported files (`payroll_export.csv`, `export.zip`) under controlled access.
- Coordinated escalation to HR/legal per insider threat procedures.

---

## Remediation Actions

### Access Controls
- Implement just-in-time privileged access (PAM) for Domain Admins.
- Require approvals and ticketing for group membership changes; alert on high-risk group modifications.

### Data Protection
- Strengthen DLP for sensitive DB exports and bulk data access.
- Enforce removable media controls and external email restrictions for sensitive attachments.

### Monitoring Improvements
- Alert on:
  - `sqlcmd.exe` usage against sensitive databases
  - Bulk exports (BULK EXPORT) and high row-count queries
  - After-hours privileged actions and cross-system correlation (UEBA)

---

## Outcome

DLP controls prevented removable media transfer in the simulated dataset and flagged attempted email exfiltration. Privileged changes were reversed and the investigation was escalated to the appropriate stakeholders. Additional hunting was performed to ensure no other systems were impacted.
