# AWS Console evidence

Use this subfolder for **optional** console screenshots that support Prowler findings (for example: S3 Block Public Access disabled, IAM user with `AdministratorAccess` attached directly, single-region CloudTrail, security group ingress on TCP/22 from `0.0.0.0/0`, account password policy absent or below CIS minimum, root MFA not enabled).

## Tips

- Crop to the relevant panel; avoid full-screen captures with unrelated navigation data.
- Redact account IDs and ARNs if needed; placeholders in the written report already use `<YOUR_ACCOUNT_ID>` style tokens.
- Cross-reference filenames in `audit-report.md` only after the images exist so links stay accurate.
