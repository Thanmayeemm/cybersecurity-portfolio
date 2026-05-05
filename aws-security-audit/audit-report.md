# AWS Cloud Security Assessment — CIS Foundations Benchmark v2.0

**Prepared by:** Thanmayee Manchikanti  
**Assessment date:** 2026-05-05  
**Scope:** Personal AWS lab account (`<AWS_ACCOUNT_ID>`); automated scan across **all commercial regions** for Prowler-selected checks (see caveats below).

## Purpose and scope (unchanged intent)

This repository documents a **controlled CIS-aligned security assessment lab**, not a generic “full cloud audit” product. **Six deliberate misconfigurations** were introduced via `scripts/introduce-misconfigs.sh` to simulate common CIS failures (S3 exposure, IAM attachment hygiene, CloudTrail coverage, SSH ingress, root MFA, password policy). **Prowler** then measures **many additional** CIS-related checks in the same account. Therefore:

- **Lab findings** = the six scripted scenarios and their remediation story.  
- **Prowler findings** = broader compliance signal (e.g., Access Analyzer, AWS Config, CloudWatch) that may remain **FAIL** independent of the lab narrative until the account is hardened to production standards.

**Methodology:** **Prowler 5.24.2** (`py -3.11 -m prowler`) with compliance framework **`cis_2.0_aws`** (**73 checks** in this run). Outputs are JSON-OCSF (machine-readable) + HTML (human-readable). Windows hosts should set UTF-8 (`PYTHONUTF8=1`) to avoid console encoding errors during the scan.

## Executive summary

Prowler **before remediation** reported **83 FAIL**, **15 PASS**, and **3 MANUAL** findings across **101** total rows in the OCSF export (CIS 2.0 AWS pack). **After scripted remediation** (`scripts/remediate.sh` / `run-remediate.ps1`) and **without** enabling **root MFA** in the Console yet, the **after** scan reported **75 FAIL**, **17 PASS**, and **3 MANUAL** across **95** rows. That is **8 fewer FAIL** findings (**~9.6%** relative reduction in FAIL count) and **2 additional PASS** findings for this compliance scope.

The **six lab misconfigurations** drove measurable movement in related areas (for example, **S3 Block Public Access** and the dedicated **lab IAM user** no longer appeared among the highest-severity failures after remediation). **Root MFA** and **residual account-wide gaps** (for example, IAM Access Analyzer, Config, monitoring) remain visible in Prowler until addressed separately. **CloudTrail** posture changed from “misconfigured trail present” to **no trails** after lab cleanup—so CIS logging checks may still **FAIL** until a **production-appropriate multi-Region trail** is built.

**Primary evidence artifacts:** `reports/before-report.html`, `reports/before-report.json` (JSON-OCSF copy of `before-report.ocsf.json`), `reports/after-report.html`, `reports/after-report.json`, plus summarized metrics in `reports/before-metrics.json` and `reports/after-metrics.json`.

---

## Prowler measurement summary

### Before remediation (baseline with lab misconfigurations)

| Metric | Value |
|--------|------:|
| Total finding rows (OCSF) | 101 |
| FAIL | 83 |
| PASS | 15 |
| MANUAL | 3 |
| MUTED | 0 |
| WARN | *Not reported separately* (see `warn_note` in metrics JSON) |

**Top failing themes (from `reports/before-metrics.json`):** IAM (**AdministratorAccess** / administrative policies), **root MFA**, **S3 Block Public Access** (lab bucket and account), consistent with the introduced lab state plus baseline account gaps.

### After remediation (scripted lab reversal; root MFA not yet enabled)

| Metric | Value |
|--------|------:|
| Total finding rows (OCSF) | 95 |
| FAIL | 75 |
| PASS | 17 |
| MANUAL | 3 |
| MUTED | 0 |

**Delta:** FAIL **−8**, PASS **+2**, total rows **−6**.

**Relative improvement (FAIL count):** \((83 − 75) / 83 \approx 9.6\%\).

### Before vs after (high level)

| Measure | Before | After | Change |
|---------|-------:|------:|--------|
| FAIL | 83 | 75 | −8 |
| PASS | 15 | 17 | +2 |
| Total rows | 101 | 95 | −6 |

**Interpretation:** Scripted remediation removed the **lab S3 bucket**, **lab IAM user with direct AdministratorAccess**, **single-region CloudTrail trail** (and logs bucket), **world-open SSH security group**, and restored a **CIS-minimum password policy**. The **after** scan still flags **root MFA** (expected until Console enrollment) and may flag **CloudTrail multi-region** because **no trail** exists post-cleanup. Separately, checks such as **IAM Access Analyzer**, **AWS Config**, and **CloudWatch** alarms remain outside the six-lab scope but still influence FAIL counts.

---

## Findings summary (six lab scenarios — CIS mapping)

| Finding ID | CIS Control | Severity | Service | Lab intent — Before | After scripted remediation |
|------------|-------------|----------|---------|----------------------|----------------------------|
| AWS-CIS-LAB-01 | **2.1.1** Block public access (S3) | High | Amazon S3 | Introduced public-read posture | **Lab bucket removed**; BPA-related failures cleared for that bucket |
| AWS-CIS-LAB-02 | **1.16** Policies attached only to groups/roles | Critical | AWS IAM | **`cis-lab-admin-user`** + direct `AdministratorAccess` | **Lab user removed** (policy attachment eliminated for that user) |
| AWS-CIS-LAB-03 | **3.1** CloudTrail enabled in all regions | High | CloudTrail | Single-region trail | **Trail and logs bucket removed** (logging posture changed; **replace** with compliant multi-Region trail for PASS) |
| AWS-CIS-LAB-04 | **5.2** No world-open admin ports | High | EC2 / VPC | SSH `0.0.0.0/0` | **Rule/SG remediated** per script |
| AWS-CIS-LAB-05 | **1.1** Root MFA | Critical | IAM (root) | No MFA (lab / account state) | **Still FAIL** until **root MFA** enabled in Console |
| AWS-CIS-LAB-06 | **1.5** Password policy ≥ 14 | Medium | IAM (account) | Policy removed in lab | **Policy restored** via remediation script |

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

**Evidence:** Primary exports — `reports/before-report.html`, `reports/before-report.json`; summarized counts — `reports/before-metrics.json`. Optional screenshots — `screenshots/` and `screenshots/aws-console-evidence/`.

**Remediation applied:**  
Block Public Access was re-enabled at the bucket (and account level as applicable), the **public bucket policy was removed**, and the lab bucket was deleted after object cleanup. Equivalent CLI patterns are documented in `scripts/remediate.sh` and `remediation-steps.md`.

**Verification:** After scan exports — `reports/after-report.html`, `reports/after-report.json`; summarized counts — `reports/after-metrics.json`.

---

### Finding 2: IAM user with direct AdministratorAccess attachment

**CIS Control:** **1.16** — Ensure IAM policies are attached only to groups or roles  
**Severity:** Critical  
**CVSS-equivalent risk score:** **9.1 (Critical)** — Administrator-equivalent access from a **standalone IAM user** maps to broad confidentiality, integrity, and availability impact across services (`C:H/I:H/A:H`) if credentials are abused.

**What was misconfigured:**  
An IAM user named `<YOUR_IAM_USER_NAME>` had the AWS managed policy **`AdministratorAccess`** attached **directly to the user principal** rather than being mediated through a group or assumed role pattern. This concentrates full-account privileges behind a single long-lived identity.

**Attacker impact narrative:**  
An attacker who discovered this could prioritize **credential theft** (access keys in developer workstations, CI secrets, or accidental code commits) because the stolen material grants **full administrative control** over the account’s resources and IAM configuration. From that position, the attacker could **create persistence** (additional users, roles, policies), **disable detective controls** where permitted, and **exfiltrate data** across services. The blast radius is effectively **account-wide**.

**Evidence:** Before scan exports — `reports/before-report.html`, `reports/before-report.json`; `reports/before-metrics.json`.

**Remediation applied:**  
The managed policy was detached, remaining user credentials were removed where present, and the lab IAM user was deleted as part of cleanup automation (`scripts/remediate.sh`).

**Verification:** After scan exports — `reports/after-report.html`, `reports/after-report.json`; summarized counts — `reports/after-metrics.json`.

---

### Finding 3: CloudTrail not enabled for all regions (single-region trail)

**CIS Control:** **3.1** — Ensure CloudTrail is enabled in all regions  
**Severity:** High  
**CVSS-equivalent risk score:** **7.2 (High)** — The primary risk is **detection and forensic loss** (elevated “logging integrity / availability” impact in cloud threat models), not a single CVE; score reflects **missed malicious activity** in non-covered regions and reduced ability to reconstruct timelines.

**What was misconfigured:**  
A CloudTrail trail named `<YOUR_TRAIL_NAME>` was configured as a **single-region trail** (multi-Region trail disabled), meaning the account did not meet the benchmark’s **all-regions logging** expectation for management events as assessed by Prowler for CIS **3.1**.

**Attacker impact narrative:**  
An attacker who discovered this could intentionally operate in **regions with weaker centralized visibility** for the assessor’s workflow, making it easier to hide enumeration and lateral movement that would otherwise appear in a consistent multi-Region trail. While other controls may still generate signals, the misconfiguration **shrinks the authoritative API audit record** for governance and incident response across the account.

**Evidence:** Before scan exports — `reports/before-report.html`, `reports/before-report.json`; `reports/before-metrics.json`.

**Remediation applied:**  
The lab trail was stopped and deleted and the dedicated logs bucket was removed after emptying objects, as documented in `scripts/remediate.sh`. A production-grade fix typically replaces this with a **multi-Region trail** and explicit event selector configuration; follow `remediation-steps.md` for the intended PASS posture.

**Verification:** After scan exports — `reports/after-report.html`, `reports/after-report.json`; summarized counts — `reports/after-metrics.json`.

---

### Finding 4: Security group permits SSH from the internet

**CIS Control:** **5.2** — Ensure no security groups allow ingress from `0.0.0.0/0` to remote server administration ports  
**Severity:** High  
**CVSS-equivalent risk score:** **8.2 (High)** — Internet-reachable administrative services are routinely targeted; score reflects **high likelihood** of exploitation attempts and meaningful compromise potential if an instance is attached.

**What was misconfigured:**  
A VPC security group named `<YOUR_SECURITY_GROUP_NAME>` included an inbound rule allowing **TCP port 22** from **`0.0.0.0/0`**, exposing any associated instances to **global SSH reachability**.

**Attacker impact narrative:**  
An attacker who discovered this could perform **internet-scale brute force and exploit attempts** against SSH without needing prior VPC access. Successful authentication or instance compromise then enables **host-level pivoting** into the VPC, lateral movement toward other subnets, and misuse of instance roles depending on what is attached. Blast radius depends on instance role permissions and network routing, but the entry condition is **publicly triggerable**.

**Evidence:** Before scan exports — `reports/before-report.html`, `reports/before-report.json`; `reports/before-metrics.json`.

**Remediation applied:**  
The world-open ingress rule was revoked and the lab security group was deleted if not in use (`scripts/remediate.sh`).

**Verification:** After scan exports — `reports/after-report.html`, `reports/after-report.json`; summarized counts — `reports/after-metrics.json`.

---

### Finding 5: Root user MFA not enabled

**CIS Control:** **1.1** — Ensure MFA is enabled for the root user  
**Severity:** Critical  
**CVSS-equivalent risk score:** **8.8 (High/Critical boundary)** — Root compromise is a **trust-anchor break** for the account; absence of MFA increases feasibility of takeover via password-only threats.

**What was misconfigured:**  
The AWS account **root user** did not have **multi-factor authentication** enrolled at the time of the “before” assessment state, failing CIS **1.1** expectations for root protection.

**Attacker impact narrative:**  
An attacker who discovered this could focus on **credential takeover vectors** against the root password (phishing, password reuse, support-channel social engineering where applicable). With root access, the attacker can alter **account-level recovery and security settings**, create powerful backdoors, and cause **widespread destructive impact**. This is a classic **high-blast-radius** identity failure mode for AWS accounts.

**Evidence:** Before scan exports — `reports/before-report.html`, `reports/before-report.json`; `reports/before-metrics.json`.

**Remediation applied:**  
**Outstanding at time of after-scan:** root MFA was **not yet enrolled** in the AWS Console (virtual or hardware MFA per policy). The **after** Prowler export still lists **`iam_root_mfa_enabled`** / **`iam_root_hardware_mfa_enabled`** as **FAIL** until this step is completed. See `remediation-steps.md` for Console steps.

**Verification:** After scan exports — `reports/after-report.html`, `reports/after-report.json`; summarized counts — `reports/after-metrics.json`. Re-run Prowler after MFA enrollment to close these checks.

---

### Finding 6: No IAM account password policy (CIS minimum not met)

**CIS Control:** **1.5** — Ensure IAM password policy requires minimum length of 14 or greater  
**Severity:** Medium  
**CVSS-equivalent risk score:** **5.3 (Medium)** — Impact is most acute where IAM users rely on **console passwords** without MFA; score reflects **credential guessing** risk rather than direct unauthenticated network exploit.

**What was misconfigured:**  
The account had **no effective IAM password policy** enforcing CIS’s minimum **14-character** password length requirement (the lab state removed the account password policy entirely).

**Attacker impact narrative:**  
An attacker who discovered this could exploit **weak user-chosen passwords** for IAM users that authenticate via console, especially when MFA is not enforced elsewhere. This is often chained with **password spraying** and **credential stuffing** rather than a single-step cloud exploit, but it increases the odds of **interactive console compromise** for privileged users.

**Evidence:** Before scan exports — `reports/before-report.html`, `reports/before-report.json`; `reports/before-metrics.json`.

**Remediation applied:**  
An account password policy meeting at least the CIS minimum length requirement was applied using the CLI pattern in `scripts/remediate.sh` (minimum length 14 with additional complexity settings).

**Verification:** After scan exports — `reports/after-report.html`, `reports/after-report.json`; summarized counts — `reports/after-metrics.json`.

---

## Conclusion

This engagement demonstrates a **full audit lifecycle** on a personal lab account: **instrument misconfiguration**, **measure with Prowler** (`cis_2.0_aws`), **remediate with automation**, **re-measure**, and **document** evidence under `reports/`. Quantitatively, FAIL findings dropped **8** on this scope (**~9.6%** relative improvement), with clear removal of the **S3** and **lab IAM user** failure modes reflected in the **before-metrics** vs **after-metrics** summaries. Qualitatively, the account remains a **lab**: residual FAILs (for example **root MFA**, **CloudTrail** reinstatement, **Access Analyzer**, **Config**, **monitoring**) illustrate the gap between **demo fixes** and **production-ready** CIS posture.

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
