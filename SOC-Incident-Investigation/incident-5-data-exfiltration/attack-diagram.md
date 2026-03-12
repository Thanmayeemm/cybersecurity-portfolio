## Attack Diagram (Data Exfiltration)

```text
User (ACME\\a.nguyen) on FIN-LT-033
   |
   | Accesses sensitive finance/PII files
   v
Data staging
   |
   | Creates archive: Q1_Finance.zip (7z.exe)
   v
Unsanctioned cloud app usage (Dropbox personal)
   |
   | Login + multiple upload attempts
   v
Outbound web uploads
   |
   | Proxy/Firewall: large Bytes Out to Dropbox infra
   v
DLP enforcement
   |
   | Flags/blocks PII upload attempt (SSN patterns)
   v
SOC response
   |
   | Block app/domain, preserve evidence, scope data loss
```
