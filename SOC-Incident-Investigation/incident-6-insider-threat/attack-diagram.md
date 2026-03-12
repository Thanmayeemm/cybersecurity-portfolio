## Attack Diagram (Insider Threat)

```text
After-hours access
   |
   | VPN login from residential ISP
   v
Workstation activity (IT-LT-007)
   |
   | Privileged recon / admin tooling
   | - PowerShell group enumeration
   v
Privilege misuse
   |
   | AD change: add svc-backup to Domain Admins
   v
Sensitive data access
   |
   | SQL queries + export payroll/employee data to CSV
   v
Data staging
   |
   | Compress export.zip (7z.exe)
   v
Exfil attempts
   |
   | USB copy attempt (blocked by DLP)
   | External email attachment attempt (alerted/blocked)
   v
SOC response
   |
   | Revert privileged changes, restrict user, preserve evidence, escalate
```
