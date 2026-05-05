# AWS Security Audit Report - CIS 2.0 (Prowler)

**Prepared by:** Thanmayee Manchikanti  
**Assessment date:** 2026-05-04  
**Scope:** AWS lab account assessed with Prowler against CIS AWS Foundations Benchmark `cis_2.0_aws` (73 checks).

## Executive Summary

This assessment evaluates the AWS lab environment after controlled misconfiguration testing and remediation. Prowler was used as the primary cloud security posture assessment tool to measure baseline and post-remediation control status.

The key risk themes identified were:
- **IAM privilege hygiene** (administrative policy exposure),
- **S3 public access governance** controls,
- **CloudTrail/logging coverage** across regions,
- **Root identity protection (MFA)**.

After remediation, the environment shows measurable improvement in control outcomes, with a reduction in failed findings and an increase in passed findings. Root MFA remains an open critical issue due to account/session restrictions, and is documented as a realistic operational constraint.

## Tools and Method

- **Tool:** Prowler 5.24.2
- **Framework:** `cis_2.0_aws`
- **Outputs:** HTML and JSON-OCSF (sanitized JSON copy for parsing)
- **Evidence files:**
  - `reports/before-report.html`
  - `reports/before-report.json`
  - `reports/before-metrics.json`
  - `reports/after-report.html`
  - `reports/after-report.json`
  - `reports/after-metrics.json`

## Before vs After Comparison

| Metric | Before | After | Improvement |
|--------|-------:|------:|------------:|
| FAIL | 75 | 74 | -1 |
| PASS | 17 | 18 | +1 |
| MANUAL | 3 | 3 | 0 |

**Measured outcome:** FAIL findings decreased by **1** and PASS findings increased by **1**.  
**Relative FAIL reduction:** \((75 - 74) / 75 = 1.33\%\).

## Remediation Summary

The remediation phase focused on reversing deliberate high-risk lab misconfigurations and restoring CIS-aligned baseline controls:

- **S3 bucket policy and exposure controls**
  - Removed public exposure configuration and restored S3 public access protections.
- **Security group restrictions**
  - Revoked broad SSH ingress (`0.0.0.0/0`) and cleaned up lab security group state.
- **Logging / CloudTrail posture**
  - Removed intentionally misconfigured trail artifacts used for lab simulation; logging controls remain an area for further hardening to achieve stronger CIS alignment.
- **IAM policy tightening**
  - Removed/remediated lab IAM privilege misconfiguration and restored account password policy baseline.

## Root MFA Finding (Critical)

Root MFA was identified as a **critical** finding.

Remediation was attempted as part of the audit workflow but could not be completed due to **account-level/session restrictions** on root credential operations in the current access context. This reflects a common enterprise reality where auditors and engineers operate under scoped IAM sessions without direct root-level authority.

### Recommendation

- Enable root MFA through an approved privileged access path with account-owner/root authentication.
- Enforce MFA requirements consistently for all privileged identities (root, admin roles, and high-impact IAM users).

## Conclusion

The AWS security audit demonstrates a practical before/after security validation workflow using Prowler and evidence-driven remediation. The post-remediation assessment shows a measurable reduction in risk exposure (**FAIL 75 -> 74; PASS 17 -> 18**) and improved control posture.

Residual high-impact findings, especially root MFA and broader logging/monitoring coverage, should be prioritized in the next hardening cycle to move from lab-grade remediation to production-grade governance.

## Evidence Note

Current screenshot evidence:
- Before scan: `screenshots/prowler-findings-before.png`
- Before scan (assessment overview): `screenshots/prowler-findings-before-overview.png`
- After scan: `screenshots/prowler-findings-after.png`
- After scan (assessment overview): `screenshots/prowler-findings-after-overview.png`

Recommended additional evidence to add:
- Root MFA configuration/access-constraint screenshot.
