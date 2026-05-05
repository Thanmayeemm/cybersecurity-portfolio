# AWS Security Audit with Prowler

## Overview

This project demonstrates a practical AWS security audit workflow using Prowler to identify cloud misconfigurations, apply targeted remediations, and measure security posture changes with before/after evidence.

The focus is to simulate realistic security issues in a controlled lab and document remediation outcomes in a professional, interview-ready format.

## Tools Used

- Prowler
- AWS CLI
- PowerShell scripts

## Methodology

1. Introduced deliberate cloud misconfigurations in a lab account.
2. Ran an initial Prowler scan (before).
3. Applied remediation scripts and configuration fixes.
4. Ran a post-remediation Prowler scan (after).

Notes:
- The initial scan evidence includes a broader run snapshot.
- The post-remediation comparison in the formal report uses the CIS-aligned project metrics (`reports/before-metrics.json` vs `reports/after-metrics.json`).

## Results

- Broader initial scan snapshot (evidence screenshot): **123 failed, 95 passed**
- CIS-aligned comparison (from metrics JSON used in report):
  - Before: **75 failed, 17 passed, 3 manual**
  - After: **73 failed, 19 passed, 3 manual**

This shows measurable improvement in the audited control set, with reduced failed findings and increased passed findings after remediation.

## Key Findings

- IAM misconfigurations and administrative privilege exposure
- S3 access control / public exposure risk
- Logging and monitoring gaps (CloudTrail/CloudWatch coverage)
- Root MFA not enabled (critical finding)

## Limitation

Root MFA could not be enabled during this engagement due to account/session constraints.  
This reflects real-world enterprise conditions where engineers often operate with scoped access and require privileged account-owner workflows for root-level controls.

## Screenshots

Before scan evidence:

![Before scan](./screenshots/prowler-findings-before.png)
![Before scan overview](./screenshots/prowler-findings-before-overview.png)

After scan evidence:

![After scan](./screenshots/prowler-findings-after.png)
![After scan overview](./screenshots/prowler-findings-after-overview.png)

## Conclusion

The project demonstrates a realistic cloud security audit lifecycle: detection, remediation, and validation. Security posture improved with a measurable reduction in failed findings, while remaining high-impact gaps were clearly identified for prioritized follow-up. This is directly aligned with real-world cloud security auditing and governance workflows.
