# Resume-ready bullets — AWS CIS assessment lab (Prowler)

Use verbatim or tailor for job descriptions. Metrics below reflect the **2026-04-22** `cis_2.0_aws` **before-remediation** export (`reports/before-metrics.json`); run `scripts/run-after-audit.ps1` after root MFA to refresh post-remediation numbers.

- Ran **Prowler 5.24.2** (`cis_2.0_aws`, 73 checks) across **all commercial regions**, exporting **HTML + JSON-OCSF**, normalizing machine output for parsing, and summarizing **95** assessment rows (**75 FAIL**, **17 PASS**, **3 MANUAL**) with severity-ranked **top failed controls** for triage.
- Built **idempotent AWS CLI** introduce/remediate automation (PowerShell + bash) for a **six-control CIS lab** (S3 exposure, IAM admin attachment, CloudTrail scope, SSH ingress, password policy, root MFA verification path) and documented a **full before/after evidence trail** under `reports/` for audit-style review.
