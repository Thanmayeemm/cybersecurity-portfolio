# Resume-ready bullets — AWS CIS assessment lab (Prowler)

Metrics below come from **`reports/before-metrics.json`** vs **`reports/after-metrics.json`** (`cis_2.0_aws`, 73 checks); totals are OCSF row counts for the CIS pack in this account.

- Ran **Prowler 5.24.2** with **`cis_2.0_aws`** across regions, exporting **HTML + JSON-OCSF**, normalizing artifacts for parsers, and comparing **before/after remediated state**: **95** CIS rows (FAIL+PASS+MANUAL) with **75 → 73 FAIL** and **17 → 19 PASS** (~**2.67%** relative FAIL reduction), with clear documentation when **manual controls** (e.g., **root MFA**) could not be closed due to **Console / permission constraints**.
- Built **bash + PowerShell runners** for **introduce / remediate** so the lab steps run the same way every time, evidence under **`reports/`**, and an **audit-style narrative** (scope, deltas, CIS mapping, MFA caveats) suitable for cloud security **GRC**, **SOC-adjacent**, or **CSPM** interview stories.
