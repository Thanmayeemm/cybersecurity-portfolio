# AWS Security Audit with Prowler

## Overview

This project captures a hands-on AWS security assessment using Prowler to identify misconfigurations, apply targeted remediation, and validate posture changes with before/after evidence.

The scope is intentionally lab-based but follows the same flow used in real audits: define controls, collect evidence, remediate prioritized risk, and clearly document residual gaps.

## Tools Used

- Prowler
- AWS CLI
- PowerShell scripts

## Methodology

1. Established a controlled misconfiguration baseline in a lab AWS account.
2. Executed a pre-remediation Prowler scan and captured baseline evidence.
3. Applied scoped remediation actions for prioritized CIS control gaps.
4. Executed a post-remediation Prowler scan to validate control movement.

Notes:
- The initial scan evidence includes a broader run snapshot.
- The post-remediation comparison in the formal report uses the CIS-aligned project metrics (`reports/before-metrics.json` vs `reports/after-metrics.json`).
- One practical challenge during execution was environment setup and rerun consistency (especially around scan outputs), which is why the workflow emphasizes repeatable scripts and evidence capture.

## Remediation Scope (Important Context)

This assessment focused on remediating high-impact CIS controls such as IAM, root MFA, S3 exposure, and network access. Remaining findings reflect additional controls outside the scoped remediation set for this lab.

Remediation in this project was intentionally scoped to demonstrate targeted risk reduction, not full account hardening across all AWS services and regions.

## Results

- Broader initial scan snapshot (evidence screenshot): **123 failed, 95 passed**
- CIS-aligned comparison (from metrics JSON used in report):
  - Before: **75 failed, 17 passed, 3 manual**
  - After: **73 failed, 19 passed, 3 manual**

These numbers reflect what was observed in this scoped audit run, with measurable improvement in the prioritized controls after remediation.

Remaining FAIL findings in the after scan are expected for this lab scope and primarily represent controls not included in the remediation subset.

## Key Findings

- IAM misconfigurations and administrative privilege exposure
- S3 access control / public exposure risk
- Logging and monitoring gaps (CloudTrail/CloudWatch coverage)
- Root MFA not enabled (critical finding)

## Limitation

Root MFA could not be enabled during this engagement due to account/session constraints.  
This reflects a common enterprise operating model where engineering and security teams work through scoped IAM access, while root-level actions require separate privileged approval and execution paths.
In other words, the technical fix is straightforward, but ownership and access boundaries can still delay closure.

## What I Would Do in a Production Environment

- Enable continuous monitoring with AWS Security Hub and GuardDuty.
- Implement automated remediation workflows using AWS Lambda and AWS Config Rules for repeatable control enforcement.
- Integrate cloud security findings into a SIEM pipeline for centralized alerting, triage, and incident response.
- Apply organization-wide preventive guardrails with AWS Organizations and Service Control Policies (SCPs).

## Screenshots

Before-scan evidence:

![Before scan](./screenshots/prowler-findings-before.png)
![Before scan overview](./screenshots/prowler-findings-before-overview.png)

After-scan evidence:

![After scan](./screenshots/prowler-findings-after.png)
![After scan overview](./screenshots/prowler-findings-after-overview.png)

## Conclusion

This project shows a practical assess-remediate-verify cycle with real constraints and measurable movement in scoped controls. It also leaves a clear record of what remains open, which is often the most important part of communicating security work in operational teams.
