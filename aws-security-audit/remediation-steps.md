# Remediation steps — CIS AWS Foundations Benchmark v2.0.0 (lab findings)

This document is a **standalone remediation runbook** for the six deliberate misconfigurations described in `misconfigurations/setup-notes.md`. It is written so a junior analyst can execute fixes safely in a **lab account** and verify PASS/FAIL transitions using Prowler and/or AWS Config/Security Hub alignment.

**Global placeholders:** Replace `<YOUR_REGION>`, `<YOUR_BUCKET_NAME>`, `<YOUR_ACCOUNT_ID>`, `<YOUR_TRAIL_NAME>`, `<YOUR_SG_ID>`, and `<YOUR_IAM_USER_NAME>` with your environment’s values. Do not paste secrets into tickets.

---

## Finding 1 — CIS 2.1.1 (S3 Block Public Access + public bucket policy)

### Fix (AWS Console)

1. Open **Amazon S3** → **Buckets** → select `<YOUR_BUCKET_NAME>`.
2. **Permissions** → **Block public access (bucket settings)** → **Edit** → enable **Block all public access** → save.
3. **Permissions** → **Bucket policy** → **Delete** if a public policy exists.
4. **Objects** → delete test objects if you no longer need them (optional).

### Fix (AWS CLI — equivalent)

```bash
aws s3api delete-bucket-policy --bucket "<YOUR_BUCKET_NAME>"
aws s3api put-public-access-block \
  --bucket "<YOUR_BUCKET_NAME>" \
  --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

### Verify

- **Prowler:** Re-run the CIS check family covering S3 public access / Block Public Access. Expect **PASS** when Block Public Access is enabled and no public bucket policy remains.
- **AWS Config / Security Hub:** If enabled, rules aligned to **S3 bucket public read/prohibited** and **Block Public Access** should move to **COMPLIANT** after propagation.

### Time to fix (estimate)

- **10–20 minutes** (including validation and a repeat scan)

### Ongoing monitoring

- **AWS Config:** Yes — commonly available managed rules for S3 public access posture (org-dependent).
- **AWS Security Hub:** Yes — when Security Hub standards include CIS controls for S3 exposure (depends on enabled standard and region rollout).

---

## Finding 2 — CIS 1.16 (AdministratorAccess attached directly to an IAM user)

### Fix (AWS Console)

1. Open **IAM** → **Users** → select `<YOUR_IAM_USER_NAME>`.
2. **Permissions** → remove **`AdministratorAccess`** (managed policy).
3. If the lab user is no longer needed: **Security credentials** delete access keys; **Delete user**.

Preferred production pattern: attach least-privilege policies to **groups** and/or require **assumed roles** with time-bounded credentials.

### Fix (AWS CLI — equivalent)

```bash
aws iam detach-user-policy \
  --user-name "<YOUR_IAM_USER_NAME>" \
  --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"
aws iam delete-user --user-name "<YOUR_IAM_USER_NAME>"
```

(Delete access keys and inline policies first if the user delete fails.)

### Verify

- **Prowler:** Re-run CIS-aligned IAM checks for **directly attached high-risk policies** / policy attachment patterns per Prowler’s CIS mapping.
- **AWS Config / Security Hub:** Many environments use related IAM hygiene checks; exact rule IDs vary by standard version.

### Time to fix (estimate)

- **15–30 minutes** (more if the user owns operational dependencies)

### Ongoing monitoring

- **AWS Config:** Partial — IAM policy drift checks vary; not all attachment patterns have perfect managed-rule coverage.
- **AWS Security Hub:** Often **yes** for CIS-derived IAM controls when enabled, but verify the enabled standard and controls list.

---

## Finding 3 — CIS 3.1 (CloudTrail enabled in all regions / multi-Region trail expectation)

### Fix (AWS Console)

1. Open **CloudTrail** → **Trails** → create or edit a trail intended for organization/account logging.
2. Enable **multi-Region trail** (all regions) per your security baseline.
3. Ensure the S3 logs bucket policy permits CloudTrail delivery and follows least privilege.
4. Start logging and confirm recent delivery.

### Fix (AWS CLI — illustrative pattern)

Use `create-trail` / `update-trail` with multi-Region trail enabled and a dedicated logs bucket:

```bash
aws cloudtrail update-trail \
  --name "<YOUR_TRAIL_NAME>" \
  --is-multi-region-trail
aws cloudtrail start-logging --name "<YOUR_TRAIL_NAME>"
```

### Verify

- **Prowler:** Re-run CIS **3.1** mapping checks; expect **PASS** when a compliant multi-Region trail configuration is present per Prowler’s implementation.
- **AWS Config / Security Hub:** CloudTrail-related managed rules commonly evaluate trail existence and multi-Region properties (standard-dependent).

### Time to fix (estimate)

- **30–90 minutes** (bucket policy + organizational logging decisions can extend this)

### Ongoing monitoring

- **AWS Config:** Yes — strong coverage for CloudTrail configuration in many managed rule sets.
- **AWS Security Hub:** Yes — commonly included in CIS Security Hub control packs (enablement-dependent).

---

## Finding 4 — CIS 5.2 (SSH ingress from 0.0.0.0/0)

### Fix (AWS Console)

1. Open **EC2** → **Security Groups** → select `<YOUR_SECURITY_GROUP_NAME>`.
2. **Inbound rules** → remove **SSH (22)** from **`0.0.0.0/0`**.
3. Replace with **least privilege**: specific CIDRs, **bastion** pattern, or **SSM**-based access where appropriate.

### Fix (AWS CLI — equivalent)

```bash
aws ec2 revoke-security-group-ingress \
  --group-id "<YOUR_SG_ID>" \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0
```

### Verify

- **Prowler:** Re-run CIS **5.2** checks; expect **PASS** when no administrative ports are open to the world per the check definition.
- **AWS Config / Security Hub:** Frequently includes **security group open to the world** rules (varies by port classification).

### Time to fix (estimate)

- **10–20 minutes** (longer if application teams must migrate access patterns)

### Ongoing monitoring

- **AWS Config:** Yes — popular managed rules exist for overly permissive SG ingress.
- **AWS Security Hub:** Yes — commonly included in CSPM standards (enablement-dependent).

---

## Finding 5 — CIS 1.1 (root MFA not enabled)

### Fix (AWS Console)

1. Sign in as **root** (only in a controlled lab scenario).
2. **Account** → **Security credentials** → **Multi-factor authentication (MFA)**.
3. Enroll **virtual MFA** or use **hardware MFA** per policy.

### Fix (AWS CLI)

Root MFA enrollment is typically performed in the **Console**. Do not rely on ad hoc CLI workarounds outside documented AWS guidance.

### Verify

- **Prowler:** Re-run CIS **1.1** checks; expect **PASS** when root MFA is present.
- **AWS Config / Security Hub:** Root MFA checks exist in multiple CSPM packs (standard-dependent).

### Time to fix (estimate)

- **10–20 minutes** (excluding organizational approval workflows)

### Ongoing monitoring

- **AWS Config:** Yes — common managed rules for root MFA (org-dependent).
- **AWS Security Hub:** Yes — frequently included in CIS-related standards (enablement-dependent).

---

## Finding 6 — CIS 1.5 (password policy minimum length ≥ 14)

### Fix (AWS Console)

1. Open **IAM** → **Account settings** → **Password policy** → **Edit**.
2. Set **minimum password length** to **14** (or higher) and align complexity settings to organizational policy.

### Fix (AWS CLI — equivalent)

```bash
aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --require-symbols \
  --require-numbers \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --max-password-age 90 \
  --password-reuse-prevention 24
```

### Verify

- **Prowler:** Re-run CIS **1.5** checks; expect **PASS** when minimum length meets benchmark expectations.
- **AWS Config / Security Hub:** IAM password policy rules exist in multiple CSPM packs (standard-dependent).

### Time to fix (estimate)

- **10–15 minutes** (longer if IAM users must rotate passwords immediately)

### Ongoing monitoring

- **AWS Config:** Yes — password policy drift checks are common.
- **AWS Security Hub:** Yes — commonly included in CIS-related standards (enablement-dependent).
