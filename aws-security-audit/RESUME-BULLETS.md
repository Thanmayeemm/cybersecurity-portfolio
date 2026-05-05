# Resume-ready bullets — AWS CIS assessment lab (Prowler)

Metrics below come from **`reports/before-metrics.json`** vs **`reports/after-metrics.json`** (`cis_2.0_aws`, 73 checks); totals are OCSF row counts for the CIS pack in this account.

- Ran **Prowler 5.24.2** with **`cis_2.0_aws`** across regions, exporting **HTML + JSON-OCSF**, normalizing artifacts for parsers, and comparing **before/after remediated state**: **95** rows with **75 → 74 FAIL** and **17 → 18 PASS** (~**1.3%** relative FAIL reduction), with clear documentation when **manual controls** (e.g., **root MFA**) could not be closed due to **Console / permission constraints**.
- Built **repeatable bash + PowerShell** lab automation (**introduce / remediate**), evidence under **`reports/`**, and an **audit-style narrative** (scope, deltas, CIS mapping, MFA caveats) suitable for cloud security **GRC**, **SOC-adjacent**, or **CSPM** interview stories.
