# Deliberate misconfigurations — lab setup (pre-Prowler)

This document lists **six intentional misconfigurations** introduced into a **dedicated AWS free-tier lab account** before running Prowler against the CIS AWS Foundations Benchmark v2.0.0. These settings are **not** appropriate for production workloads.

**Operational note:** Some controls (notably **root MFA**) cannot be reliably automated from a script without already having root MFA or other privileged session constraints. Use the **Console** path where indicated, or rely on the account already meeting the “misconfigured” state (for example, root MFA never enrolled).

---

## Summary table

| # | Misconfiguration | AWS service | CIS AWS Foundations Benchmark v2.0.0 control (violated) |
|---|------------------|-------------|--------------------------------------------------------|
| 1 | Public S3 exposure with account and bucket **Block Public Access** disabled | Amazon S3 | **2.1.1** — Ensure all S3 buckets have block public access enabled |
| 2 | IAM user with **`AdministratorAccess`** attached **directly** to the user | AWS IAM | **1.16** — Ensure IAM policies are attached only to groups or roles |
| 3 | CloudTrail **not** enabled **for all regions** (single-region trail only) | AWS CloudTrail | **3.1** — Ensure CloudTrail is enabled in all regions |
| 4 | Security group allows **SSH (TCP/22)** from **`0.0.0.0/0`** | Amazon EC2 (VPC security groups) | **5.2** — Ensure no security groups allow ingress from `0.0.0.0/0` to remote server administration ports |
| 5 | **Root account** has **no MFA** enrolled | AWS IAM (root user) | **1.1** — Ensure MFA is enabled for the root user |
| 6 | **No account password policy** (or policy weaker than CIS minimum, for example length &lt; 14) | AWS IAM (account password policy) | **1.5** — Ensure IAM password policy requires minimum length of 14 or greater |

---

## 1. Public S3 bucket with Block Public Access disabled

**Misconfiguration name:** Public-read object exposure via bucket policy and disabled Block Public Access  
**AWS service affected:** Amazon S3  
**CIS control violated:** **2.1.1** — Ensure all S3 buckets have block public access enabled  

**How to create it**

- **Console:** S3 → Buckets → **Create bucket** → uncheck **Block all public access** (confirm) → create bucket → **Permissions** → **Bucket policy** allowing `s3:GetObject` to `"Principal": "*"` on `arn:aws:s3:::<bucket>/*` → optionally upload a test object.
- **CLI (illustrative):** Disable all four Block Public Access flags, then attach a public-read bucket policy for object GET. Use `scripts/introduce-misconfigs.sh` for an idempotent example.

**Why it was chosen**

Disabling Block Public Access and granting anonymous `GetObject` makes **object data directly reachable from the Internet** without credentials. This is a common **data-exfiltration and sensitive-file disclosure** path (for example backups, reports, or mislabeled “internal” assets) and is frequently flagged by CSPM tools and breach post-mortems.

---

## 2. IAM user with AdministratorAccess policy attached directly

**Misconfiguration name:** Standalone IAM user with `AdministratorAccess` attached at user scope  
**AWS service affected:** AWS IAM  
**CIS control violated:** **1.16** — Ensure IAM policies are attached only to groups or roles  

**How to create it**

- **Console:** IAM → **Users** → **Create user** → attach **AWS managed policy** `AdministratorAccess` directly to the user (not via a group).
- **CLI:** `aws iam create-user` followed by `aws iam attach-user-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --user-name <user>`.

**Why it was chosen**

Direct attachment of **full-administrator** permissions to a long-lived IAM user increases **credential theft blast radius** (a single leaked access key or console password becomes account-wide compromise). It also **bypasses group-based governance** (onboarding, reviews, and automated removal patterns are harder to enforce).

---

## 3. CloudTrail logging disabled in at least one region (no multi-Region trail)

**Misconfiguration name:** Only a **single-region** CloudTrail trail (multi-Region logging not enabled)  
**AWS service affected:** AWS CloudTrail  
**CIS control violated:** **3.1** — Ensure CloudTrail is enabled in all regions  

**How to create it**

- **Console:** CloudTrail → **Create trail** → disable **multi-Region trail** (leave it **off**) → configure a logs bucket → start logging.
- **CLI:** `aws cloudtrail create-trail` with `--no-is-multi-region-trail` (and `--is-multi-region-trail` omitted), then `aws cloudtrail start-logging`.

**Why it was chosen**

Without a **multi-Region** trail, activity in “quiet” regions or unexpected regional API usage is easier to **miss in centralized detection and investigations**. An attacker can **probe or operate in non-default regions** with reduced forensic visibility compared to a baseline where all regions are covered consistently.

---

## 4. Security group with TCP/22 open to 0.0.0.0/0

**Misconfiguration name:** Internet-wide SSH ingress  
**AWS service affected:** Amazon EC2 (VPC security groups)  
**CIS control violated:** **5.2** — Ensure no security groups allow ingress from `0.0.0.0/0` to remote server administration ports  

**How to create it**

- **Console:** EC2 → **Security Groups** → **Create security group** → inbound rule: **SSH**, source **`0.0.0.0/0`**.
- **CLI:** `aws ec2 authorize-security-group-ingress` with `IpProtocol=tcp`, `FromPort=22`, `ToPort=22`, `CidrIp=0.0.0.0/0`.

**Why it was chosen**

Unrestricted SSH exposure enables **internet-wide password guessing**, **credential stuffing**, and **known-vulnerability exploitation** against any reachable instance attached to the group. Even one compromised instance can become a **pivot point** for lateral movement inside the VPC depending on IAM roles and network reachability.

---

## 5. Root account with no MFA enabled

**Misconfiguration name:** Root user without MFA  
**AWS service affected:** AWS IAM (root user)  
**CIS control violated:** **1.1** — Ensure MFA is enabled for the root user  

**How to create it**

- **Console (typical lab path):** Sign in as **root** → **Account** (top right) → **Security credentials** → **Multi-factor authentication (MFA)** → ensure **MFA is not active** (if MFA is already enabled, removing it requires an MFA sign-in and is **not** recommended outside a controlled lab).
- **CLI:** There is **no safe, universally automatable** CLI path to remove root MFA in all account states; treat this as a **manual lab precondition** or validate the existing state.

**Why it was chosen**

The **root principal** can alter **account-level security settings** (billing, recovery, some IAM constraints, support plans) and is a **high-value target**. Without MFA, **password-only compromise** of root credentials can lead to **full account takeover** and destructive changes that are difficult to roll back.

---

## 6. No password policy set (or weaker than CIS minimum)

**Misconfiguration name:** Missing IAM account password policy (or minimum length below CIS recommendation)  
**AWS service affected:** AWS IAM (account password policy)  
**CIS control violated:** **1.5** — Ensure IAM password policy requires minimum length of 14 or greater  

**How to create it**

- **Console:** IAM → **Account settings** → **Password policy** → **Delete** (or set minimum length **below 14** in weaker configurations).
- **CLI:** `aws iam delete-account-password-policy` (idempotent if no policy exists).

**Why it was chosen**

Without a strong account password policy, **console passwords** for IAM users (and password-based workflows) can remain **short, simple, and easily guessed**, increasing risk of **credential-based takeover**, especially when combined with **no MFA** on sensitive principals.
