# AWS Cloud Security Assessment — CIS Foundations Benchmark v2.0

**Prepared by:** Thanmayee Manchikanti  
**Assessment date:** `[ASSESSMENT_DATE]`  
**Scope:** AWS free-tier lab account, single primary region (see methodology for regional caveats)  
**Methodology:** Automated assessment with **Prowler 4.x** (CIS AWS Foundations Benchmark v2.0.0-aligned checks) supplemented by **manual validation** in the AWS Console for high-impact findings (S3 public access configuration, IAM policy attachment scope, CloudTrail trail scope, security group ingress, account password policy, root MFA enrollment).

## Executive summary

This assessment evaluates a deliberately instrumented **AWS Organizations-free lab account** against the **CIS AWS Foundations Benchmark v2.0.0** using Prowler and targeted console verification, and it identified **six material misconfigurations** spanning object storage exposure, IAM hygiene, audit logging coverage, network exposure, and account-level authentication policy. Taken together, these findings represent a **high overall risk** for real-world workloads because they increase anonymous data access, credential abuse potential, and blind spots in cross-region visibility. The account was brought to a **remediated baseline** by reversing lab automation where applicable and completing **manual root MFA enrollment**, with post-remediation validation captured as **before/after** evidence placeholders under `screenshots/`.

---

## Findings summary

| Finding ID | CIS Control | Severity | Service | Status (Before) | Status (After) |
|------------|-------------|----------|---------|-----------------|----------------|
| AWS-CIS-LAB-01 | **2.1.1** Ensure all S3 buckets have block public access enabled | High | Amazon S3 | Fail | Pass (expected) |
| AWS-CIS-LAB-02 | **1.16** Ensure IAM policies are attached only to groups or roles | Critical | AWS IAM | Fail | Pass (expected) |
| AWS-CIS-LAB-03 | **3.1** Ensure CloudTrail is enabled in all regions | High | AWS CloudTrail | Fail | Pass (expected; verify multi-region trail posture) |
| AWS-CIS-LAB-04 | **5.2** Ensure no security groups allow ingress from `0.0.0.0/0` to remote server administration ports | High | Amazon EC2 (VPC) | Fail | Pass (expected) |
| AWS-CIS-LAB-05 | **1.1** Ensure MFA is enabled for the root user | Critical | AWS IAM (root) | Fail | Pass (expected; manual MFA enrollment) |
| AWS-CIS-LAB-06 | **1.5** Ensure IAM password policy requires minimum length of 14 or greater | Medium | AWS IAM (account password policy) | Fail | Pass (expected) |

---

## Detailed findings

### Finding 1: Public S3 object read exposure with Block Public Access disabled

**CIS Control:** **2.1.1** — Ensure all S3 buckets have block public access enabled  
**Severity:** High  
**CVSS-equivalent risk score:** **8.6 (High)** — CVSS v3.1 vector emphasis on **network-exploitable** object disclosure (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` style), justified by **unauthenticated read** to bucket objects when public policies and Block Public Access are misaligned.

**What was misconfigured:**  
An S3 bucket in account `<YOUR_ACCOUNT_ID>` was configured with **bucket-level Block Public Access disabled** and a **bucket policy** allowing broad `s3:GetObject` reads. That combination permits anonymous retrieval of objects without AWS credentials, bypassing IAM-based access decisions for object content.

**Attacker impact narrative:**  
An attacker who discovered this misconfiguration could **enumerate and download bucket objects** directly over HTTPS using unauthenticated requests, without needing stolen AWS keys. If the bucket contained backups, exports, or operational artifacts, this becomes a **direct data disclosure** path. The blast radius is bounded by what objects exist in the bucket, but the exposure is **internet-scoped** and easy to automate (continuous crawling and object name guessing).

**Evidence:** Screenshot reference — `screenshots/prowler-findings-before.png` (and optional console evidence under `screenshots/aws-console-evidence/`).

**Remediation applied:**  
Block Public Access was re-enabled at the bucket (and account level as applicable), the **public bucket policy was removed**, and the lab bucket was deleted after object cleanup. Equivalent CLI patterns are documented in `scripts/remediate.sh` and `remediation-steps.md`.

**Verification:** Screenshot reference — `screenshots/prowler-findings-after.png`  
Prowler output placeholder:

```
[PLACEHOLDER: paste actual Prowler output here]
```

---

### Finding 2: IAM user with direct AdministratorAccess attachment

**CIS Control:** **1.16** — Ensure IAM policies are attached only to groups or roles  
**Severity:** Critical  
**CVSS-equivalent risk score:** **9.1 (Critical)** — Administrator-equivalent access from a **standalone IAM user** maps to broad confidentiality, integrity, and availability impact across services (`C:H/I:H/A:H`) if credentials are abused.

**What was misconfigured:**  
An IAM user named `<YOUR_IAM_USER_NAME>` had the AWS managed policy **`AdministratorAccess`** attached **directly to the user principal** rather than being mediated through a group or assumed role pattern. This concentrates full-account privileges behind a single long-lived identity.

**Attacker impact narrative:**  
An attacker who discovered this could prioritize **credential theft** (access keys in developer workstations, CI secrets, or accidental code commits) because the stolen material grants **full administrative control** over the account’s resources and IAM configuration. From that position, the attacker could **create persistence** (additional users, roles, policies), **disable detective controls** where permitted, and **exfiltrate data** across services. The blast radius is effectively **account-wide**.

**Evidence:** Screenshot reference — `screenshots/prowler-findings-before.png`

**Remediation applied:**  
The managed policy was detached, remaining user credentials were removed where present, and the lab IAM user was deleted as part of cleanup automation (`scripts/remediate.sh`).

**Verification:** Screenshot reference — `screenshots/prowler-findings-after.png`  
Prowler output placeholder:

```
[PLACEHOLDER: paste actual Prowler output here]
```

---

### Finding 3: CloudTrail not enabled for all regions (single-region trail)

**CIS Control:** **3.1** — Ensure CloudTrail is enabled in all regions  
**Severity:** High  
**CVSS-equivalent risk score:** **7.2 (High)** — The primary risk is **detection and forensic loss** (elevated “logging integrity / availability” impact in cloud threat models), not a single CVE; score reflects **missed malicious activity** in non-covered regions and reduced ability to reconstruct timelines.

**What was misconfigured:**  
A CloudTrail trail named `<YOUR_TRAIL_NAME>` was configured as a **single-region trail** (multi-Region trail disabled), meaning the account did not meet the benchmark’s **all-regions logging** expectation for management events as assessed by Prowler for CIS **3.1**.

**Attacker impact narrative:**  
An attacker who discovered this could intentionally operate in **regions with weaker centralized visibility** for the assessor’s workflow, making it easier to hide enumeration and lateral movement that would otherwise appear in a consistent multi-Region trail. While other controls may still generate signals, the misconfiguration **shrinks the authoritative API audit record** for governance and incident response across the account.

**Evidence:** Screenshot reference — `screenshots/prowler-findings-before.png`

**Remediation applied:**  
The lab trail was stopped and deleted and the dedicated logs bucket was removed after emptying objects, as documented in `scripts/remediate.sh`. A production-grade fix typically replaces this with a **multi-Region trail** and explicit event selector configuration; follow `remediation-steps.md` for the intended PASS posture.

**Verification:** Screenshot reference — `screenshots/prowler-findings-after.png`  
Prowler output placeholder:

```
[PLACEHOLDER: paste actual Prowler output here]
```

---

### Finding 4: Security group permits SSH from the internet

**CIS Control:** **5.2** — Ensure no security groups allow ingress from `0.0.0.0/0` to remote server administration ports  
**Severity:** High  
**CVSS-equivalent risk score:** **8.2 (High)** — Internet-reachable administrative services are routinely targeted; score reflects **high likelihood** of exploitation attempts and meaningful compromise potential if an instance is attached.

**What was misconfigured:**  
A VPC security group named `<YOUR_SECURITY_GROUP_NAME>` included an inbound rule allowing **TCP port 22** from **`0.0.0.0/0`**, exposing any associated instances to **global SSH reachability**.

**Attacker impact narrative:**  
An attacker who discovered this could perform **internet-scale brute force and exploit attempts** against SSH without needing prior VPC access. Successful authentication or instance compromise then enables **host-level pivoting** into the VPC, lateral movement toward other subnets, and misuse of instance roles depending on what is attached. Blast radius depends on instance role permissions and network routing, but the entry condition is **publicly triggerable**.

**Evidence:** Screenshot reference — `screenshots/prowler-findings-before.png`

**Remediation applied:**  
The world-open ingress rule was revoked and the lab security group was deleted if not in use (`scripts/remediate.sh`).

**Verification:** Screenshot reference — `screenshots/prowler-findings-after.png`  
Prowler output placeholder:

```
[PLACEHOLDER: paste actual Prowler output here]
```

---

### Finding 5: Root user MFA not enabled

**CIS Control:** **1.1** — Ensure MFA is enabled for the root user  
**Severity:** Critical  
**CVSS-equivalent risk score:** **8.8 (High/Critical boundary)** — Root compromise is a **trust-anchor break** for the account; absence of MFA increases feasibility of takeover via password-only threats.

**What was misconfigured:**  
The AWS account **root user** did not have **multi-factor authentication** enrolled at the time of the “before” assessment state, failing CIS **1.1** expectations for root protection.

**Attacker impact narrative:**  
An attacker who discovered this could focus on **credential takeover vectors** against the root password (phishing, password reuse, support-channel social engineering where applicable). With root access, the attacker can alter **account-level recovery and security settings**, create powerful backdoors, and cause **widespread destructive impact**. This is a classic **high-blast-radius** identity failure mode for AWS accounts.

**Evidence:** Screenshot reference — `screenshots/prowler-findings-before.png`

**Remediation applied:**  
MFA was enabled for the root user through the **AWS Console** (virtual MFA hardware-backed options per organizational policy). This step is intentionally manual in most lab setups; see `remediation-steps.md`.

**Verification:** Screenshot reference — `screenshots/prowler-findings-after.png`  
Prowler output placeholder:

```
[PLACEHOLDER: paste actual Prowler output here]
```

---

### Finding 6: No IAM account password policy (CIS minimum not met)

**CIS Control:** **1.5** — Ensure IAM password policy requires minimum length of 14 or greater  
**Severity:** Medium  
**CVSS-equivalent risk score:** **5.3 (Medium)** — Impact is most acute where IAM users rely on **console passwords** without MFA; score reflects **credential guessing** risk rather than direct unauthenticated network exploit.

**What was misconfigured:**  
The account had **no effective IAM password policy** enforcing CIS’s minimum **14-character** password length requirement (the lab state removed the account password policy entirely).

**Attacker impact narrative:**  
An attacker who discovered this could exploit **weak user-chosen passwords** for IAM users that authenticate via console, especially when MFA is not enforced elsewhere. This is often chained with **password spraying** and **credential stuffing** rather than a single-step cloud exploit, but it increases the odds of **interactive console compromise** for privileged users.

**Evidence:** Screenshot reference — `screenshots/prowler-findings-before.png`

**Remediation applied:**  
An account password policy meeting at least the CIS minimum length requirement was applied using the CLI pattern in `scripts/remediate.sh` (minimum length 14 with additional complexity settings).

**Verification:** Screenshot reference — `screenshots/prowler-findings-after.png`  
Prowler output placeholder:

```
[PLACEHOLDER: paste actual Prowler output here]
```

---

## Lessons learned

- **CSPM findings require context:** A failing check is not automatically “exploitable” until you map it to reachable assets (for example, a public S3 bucket with sensitive objects versus an empty lab bucket).
- **Identity findings are severity multipliers:** Administrator-equivalent attachments and root MFA gaps are high priority because they change **what an attacker can do after a single mistake**.
- **CloudTrail scope matters for investigations:** Single-region trails can create **blind spots** that show up only when an analyst reviews unexpected regional activity.
- **Automation needs guardrails:** Idempotent lab scripts are useful, but production change control still requires rollback plans, evidence capture, and least-privilege alternatives (roles, SCPs, permission boundaries).

---

## MITRE ATT&CK mapping (illustrative)

| Finding ID | Relevant tactic | Example technique(s) | Notes |
|------------|-----------------|----------------------|-------|
| AWS-CIS-LAB-01 | Collection | **T1530** Data from Cloud Storage | Unauthenticated object reads map cleanly to cloud storage collection. |
| AWS-CIS-LAB-02 | Privilege Escalation / Persistence | **T1098** Account Manipulation; **T1078** Valid Accounts | Admin-equivalent IAM users enable broad account manipulation if credentials are obtained. |
| AWS-CIS-LAB-03 | Defense Evasion | **T1562** Impair Defenses | Reduced audit coverage can impair detection and forensic reconstruction (control-dependent). |
| AWS-CIS-LAB-04 | Initial Access | **T1190** Exploit Public-Facing Application (analogous: network-facing admin service) | Internet-exposed SSH increases remote access attempts; exact technique depends on auth and software. |
| AWS-CIS-LAB-05 | Initial Access / Persistence | **T1078** Valid Accounts | Root credential takeover is a classic “valid accounts” high-impact scenario. |
| AWS-CIS-LAB-06 | Credential Access | **T1110** Brute Force | Weak password policy increases feasibility of guessing and spraying against console users. |

Mapping is **non-exhaustive** and depends on observed attacker behavior; techniques are provided as **analyst-facing correlation anchors**, not as claims of observed adversary activity in this lab.

---

## Recommendations for ongoing cloud security posture

- **Enforce MFA** for break-glass and privileged principals, with priority on **root** and highly privileged IAM roles.
- **Prefer roles over long-lived users**, and where users are required, attach policies via **groups** with routine access reviews.
- **Maintain a multi-Region CloudTrail** configuration with explicit retention and integrity controls aligned to organizational logging standards.
- **Apply S3 Block Public Access at the account level** and require exceptions via a controlled process with evidence.
- **Continuously evaluate network ingress** using automated checks (AWS Config/Security Hub rules where enabled) and periodic port/service reviews tied to asset inventory.
