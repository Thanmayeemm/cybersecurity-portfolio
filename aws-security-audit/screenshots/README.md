# Screenshots

This folder holds **evidence screenshots** for the AWS CIS Foundations audit lab.

## What to capture

- **Prowler CLI output** before remediation (terminal scroll or saved log export).
- **Prowler CLI output** after remediation (same checks, showing PASS/FAIL changes).
- **AWS Console — root MFA:** IAM → **My security credentials** (signed in as root) → **Multi-factor authentication (MFA)** showing **Assigned** (virtual or hardware device). Redact account-specific details if you publish this portfolio.
- Optional: **AWS Console** views that corroborate critical findings (S3 public access, IAM attachments, CloudTrail settings, security group rules, account password policy).

## Naming convention (suggested)

- `prowler-findings-before.png` — primary “before” evidence referenced in `audit-report.md`
- `prowler-findings-after.png` — primary “after” evidence referenced in `audit-report.md`

Store additional images with descriptive filenames (for example `s3-block-public-access-before.png`). Do not commit secrets, access keys, or session tokens; redact account-specific identifiers if you publish publicly.
