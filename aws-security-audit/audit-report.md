# AWS Security Audit Report - CIS 2.0 (Prowler)

**Prepared by:** Thanmayee Manchikanti  
**Assessment date:** 2026-05-04  
**Scope:** AWS lab account assessed with Prowler against CIS AWS Foundations Benchmark `cis_2.0_aws` (73 checks).

## Executive Summary

This assessment covers the AWS lab after controlled misconfiguration testing and remediation. Prowler is the main tool I used to compare baseline vs post-remediation check results.

The key risk themes identified were:
- **IAM privilege hygiene** (administrative policy exposure),
- **S3 public access governance** controls,
- **CloudTrail/logging coverage** across regions,
- **Root identity protection (MFA)**.

After remediation, there is a reduction in failing checks on the CIS extract (FAIL 75→73, PASS 17→19; MANUAL stays at 3). Root MFA remains an open critical issue due to account/session restrictions, and is documented as a realistic operational constraint.

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
| FAIL | 75 | 73 | -2 |
| PASS | 17 | 19 | +2 |
| MANUAL | 3 | 3 | 0 |

**Measured outcome:** FAIL findings decreased by **2** and PASS findings increased by **2**.  
**Relative FAIL reduction:** \((75 - 73) / 75 = 2.67\%\).

The FAIL count did not decrease dramatically because remediation in this engagement was intentionally scoped to high-impact CIS controls rather than full-account hardening. Corrective actions prioritized critical areas such as **IAM privilege exposure**, **root MFA**, **S3 exposure**, and **network access risk**. Remaining FAIL findings are valid security gaps, but they largely map to additional controls outside the defined remediation scope for this lab.

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
- Enforce MFA for root, admin roles, and other high-impact IAM users.

## Conclusion

The AWS security audit runs a before/after CIS assessment using Prowler. I used before/after scan output as evidence when remediating; the metrics extract shows **FAIL 75 → 73** and **PASS 17 → 19** — fewer failing checks on the CIS pack with re-scan proof.

Residual high-impact findings, especially root MFA and broader logging/monitoring coverage, should be next on the list if this account were headed toward production — the lab work closed the misconfigs I introduced, not every gap Prowler still flags.

## Evidence Note

Current screenshot evidence:
- Before scan: `screenshots/prowler-findings-before.png`
- Before scan (assessment overview): `screenshots/prowler-findings-before-overview.png`
- After scan: `screenshots/prowler-findings-after.png`
- After scan (assessment overview): `screenshots/prowler-findings-after-overview.png`

Recommended additional evidence to add:
- Root MFA configuration/access-constraint screenshot.
