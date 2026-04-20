# Screenshots

This folder holds **evidence screenshots** for the AWS CIS Foundations audit lab.

## What to capture

- **Prowler CLI output** before remediation (terminal scroll or saved log export).
- **Prowler CLI output** after remediation (same checks, showing PASS/FAIL changes).
- Optional: **AWS Console** views that corroborate critical findings (S3 public access, IAM attachments, CloudTrail settings, security group rules, account password policy, root MFA status).

## Naming convention (suggested)

- `prowler-findings-before.png` — primary “before” evidence referenced in `audit-report.md`
- `prowler-findings-after.png` — primary “after” evidence referenced in `audit-report.md`

Store additional images with descriptive filenames (for example `s3-block-public-access-before.png`). Do not commit secrets, access keys, or session tokens; redact account-specific identifiers if you publish publicly.
