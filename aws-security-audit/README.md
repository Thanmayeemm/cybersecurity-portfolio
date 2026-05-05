# AWS Security Audit — CIS AWS Foundations Benchmark v2.0

**One-line summary:** A CIS AWS Foundations Benchmark v2.0.0-aligned cloud security assessment using **Prowler 4.x** against a deliberately instrumented AWS lab account, with formal reporting, remediation automation, and before/after verification evidence.

## Why this project exists

This project fills a **cloud security gap** in the broader portfolio by demonstrating practical **CIS Benchmark** literacy beyond theory: configuring a reproducible non-compliant baseline, running an open-source **CSPM** scanner, translating results into **risk-rated findings**, and closing the loop with **remediation and re-validation**. It is intentionally scoped to a **free-tier lab account** and should not be treated as production security advice without organizational context.

## Tools used

- **Prowler 4.x** — open-source security assessment of AWS accounts (CIS-aligned checks used for this work)
- **AWS CLI v2** — reproducible misconfiguration introduction and remediation
- **Python 3.x** — runtime environment commonly used to install/run Prowler in local assessment workflows

## Methodology overview

The lab begins by establishing a **known-bad baseline** aligned to six CIS controls spanning S3 public exposure, IAM attachment hygiene, CloudTrail regional coverage, overly permissive security group ingress, root MFA, and account password policy. **Prowler** is executed to collect automated evidence of FAIL conditions, and key findings are **manually validated** in the AWS Console where screenshots improve defensibility. After evidence capture, **remediation scripts** reverse the automated changes and console steps address controls that cannot be safely automated (notably **root MFA**). A second Prowler run provides a **before/after** comparison for the portfolio artifact set.

## Key findings summary

| ID | CIS control (v2.0.0) | Severity | Topic |
|----|----------------------|----------|-------|
| 1 | **2.1.1** | High | S3 Block Public Access / public bucket policy |
| 2 | **1.16** | Critical | IAM user with direct `AdministratorAccess` |
| 3 | **3.1** | High | CloudTrail not enabled for all regions (single-region trail) |
| 4 | **5.2** | High | Security group SSH open to `0.0.0.0/0` |
| 5 | **1.1** | Critical | Root MFA not enabled |
| 6 | **1.5** | Medium | Account password policy missing / below CIS minimum |

Full narrative, attacker impact analysis, and verification placeholders are documented in **[audit-report.md](./audit-report.md)**.

## Before / after Prowler comparison (evidence placeholders)

| Stage | Evidence artifact | Notes |
|------|-------------------|-------|
| Before remediation | `screenshots/prowler-findings-before.png` | Terminal or exported Prowler output after introducing misconfigurations |
| After remediation | `screenshots/prowler-findings-after.png` | Repeat scan after fixes; expect improved PASS coverage for targeted CIS checks |

Raw output placeholder (do not fabricate results):

```
[PLACEHOLDER: paste actual Prowler output here]
```

## How to reproduce this audit in your own AWS free-tier account

1. **Create a dedicated lab account or OU** (strongly recommended). Do not run misconfiguration scripts against production.
2. **Configure AWS CLI v2** credentials for the lab account (`aws sts get-caller-identity`).
3. **Choose** a globally unique `<YOUR_BUCKET_NAME>`, a **region** (for example `us-east-1`), and a **security group name** for the scripts.
4. **Run** `scripts/introduce-misconfigs.sh` with environment variables set (see script header). Complete the **root MFA lab precondition** manually per `misconfigurations/setup-notes.md` if needed.
5. **Install/run Prowler 4.x** using your preferred Python workflow and execute a CIS-oriented scan relevant to your install method.
6. **Capture** “before” screenshots under `screenshots/` (and optional console shots under `screenshots/aws-console-evidence/`).
7. **Run** `scripts/remediate.sh` **after** before-evidence is captured (it changes account state). Complete **root MFA enrollment** in the Console.
8. **Re-run Prowler**, capture “after” screenshots, and update `audit-report.md` placeholders with authentic output snippets.

### Windows (recommended path)

On Windows, plain `bash` often launches **WSL**, which may be broken. Use **Git Bash** or the wrappers below.

**One-time:** allow local scripts (PowerShell):

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

**Introduce misconfigs** (from repo root; optional env overrides):

```powershell
cd <path-to-your-git-clone>   # folder that contains aws-security-audit\
# Optional; otherwise the script picks a random cis-lab-* bucket name:
# $env:BUCKET_NAME = "your-globally-unique-bucket-name"
$env:REGION = "us-east-1"
$env:SG_NAME = "cis-lab-ssh-open"
.\aws-security-audit\scripts\run-introduce.ps1
```

Copy the **`BUCKET_NAME`** printed in the summary (or set `$env:BUCKET_NAME` yourself before running so you remember it).

**Prowler (before)** — install once with Python 3:

```powershell
python -m pip install prowler
prowler aws
```

Save terminal output / screenshots to `screenshots/` and paste excerpts into `audit-report.md` where marked.

**Remediate** (same `BUCKET_NAME`, `REGION`, `SG_NAME` as introduce):

```powershell
$env:BUCKET_NAME = "<same-as-introduce>"
$env:REGION = "us-east-1"
$env:SG_NAME = "cis-lab-ssh-open"
.\aws-security-audit\scripts\run-remediate.ps1
```

Then in the **AWS Console**: enable **root MFA** (required for CIS 1.1). Re-run **Prowler** and update the “after” evidence.

Supporting references:

- `misconfigurations/setup-notes.md` — what was introduced and why
- `remediation-steps.md` — junior-analyst-friendly fixes and verification guidance
- `audit-report.md` — formal assessment narrative

## Skills demonstrated

- Cloud security auditing in AWS (lab-scoped)
- CIS Benchmark compliance assessment (AWS Foundations v2.0.0 framing)
- AWS IAM, S3, CloudTrail, and VPC security groups (practical hardening patterns)
- Prowler (open-source CSPM) for evidence collection
- Attacker impact analysis tied to realistic cloud threat scenarios
- Formal security report writing with traceable evidence placeholders

## Repository link

This folder is part of the portfolio monorepo: **[cybersecurity-portfolio README](../README.md)**  
Upstream GitHub repository: `https://github.com/Thanmayeemm/cybersecurity-portfolio`
