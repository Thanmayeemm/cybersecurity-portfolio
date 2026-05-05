# Resume-ready bullets — AWS CIS assessment lab (Prowler)

Use verbatim or tailor for job descriptions. Metrics reflect **`cis_2.0_aws`** scoped scans (73 checks); totals include findings beyond the six scripted lab misconfigurations.

- Ran **Prowler 5.24.2** against a personal AWS lab account using **`cis_2.0_aws`**, exporting **HTML + JSON-OCSF** evidence and CIS compliance CSVs for auditable before/after comparison.
- Delivered **~9.6% relative reduction in FAIL findings** on the selected scope (**83 → 75** FAIL rows; **15 → 17** PASS) after scripted remediation and validation passes (`introduce-misconfigs` / `remediate`).
- Designed **six CIS-aligned deliberate misconfigurations** (S3 exposure, IAM policy attachment, CloudTrail coverage, SSH ingress, password policy, root MFA posture) with **idempotent AWS CLI** bash automation and **PowerShell runners** for Windows/Git Bash parity.
- Authored an **analyst-grade assessment report** mapping findings to **severity**, **attacker impact narratives**, and **MITRE ATT&CK**, plus standalone **remediation runbooks** aligned to CIS AWS Foundations expectations.
- Distinguished **controlled lab findings** from **residual account baseline gaps** (e.g., Access Analyzer, Config, monitoring) to mirror real CSPM triage and prioritization.
