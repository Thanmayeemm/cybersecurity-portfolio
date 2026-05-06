# Scripts Overview — AWS Security Audit Lab

This folder contains automation scripts used to simulate and remediate cloud misconfigurations for the AWS CIS audit lab.

## Scripts

### `introduce-misconfigs.sh` / `run-introduce.ps1`
Introduces deliberate misconfigurations to simulate insecure cloud conditions:
- S3 public access enabled
- IAM user with excessive privileges
- Security group with open SSH (`0.0.0.0/0`)
- CloudTrail misconfiguration

### `remediate.sh` / `run-remediate.ps1`
Reverts misconfigurations and applies security best practices:
- Removes public access from S3
- Restricts IAM privileges
- Locks down security group rules
- Enables proper logging configurations

## Purpose

These scripts are designed to:
- Recreate the same insecure baseline in the lab when I need to re-run the exercise
- Support before/after validation using Prowler
- Mirror the introduce → scan → remediate → scan loop documented in the audit report

## Note

Root MFA is not automated and must be configured manually via AWS Console.
