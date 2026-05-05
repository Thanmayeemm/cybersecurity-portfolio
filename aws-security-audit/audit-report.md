# AWS Cloud Security Assessment — CIS Foundations Benchmark v2.0

**Prepared by:** Thanmayee Manchikanti  
**Assessment date:** 2026-04-22  
**Scope:** Personal AWS lab account (`<AWS_ACCOUNT_ID>`); automated scan across **all commercial regions** for Prowler-selected checks (see caveats below).

## Purpose and scope (unchanged intent)

This repository documents a **controlled CIS-aligned security assessment lab**, not a generic “full cloud audit” product. **Six deliberate misconfigurations** were introduced via `scripts/introduce-misconfigs.sh` to simulate common CIS failures (S3 exposure, IAM attachment hygiene, CloudTrail coverage, SSH ingress, root MFA, password policy). **Prowler** then measures **many additional** CIS-related checks in the same account. Therefore:

- **Lab findings** = the six scripted scenarios and their remediation story.  
- **Prowler findings** = broader compliance signal (e.g., Access Analyzer, AWS Config, CloudWatch) that may remain **FAIL** independent of the lab narrative until the account is hardened to production standards.

**Methodology:** **Prowler 5.24.2** (`py -3.11 -m prowler`) with compliance framework **`cis_2.0_aws`** (**73 checks** in this run). **Output formats:** Prowler 5 accepts `-M` / `--output-formats` values `html` and `json-ocsf` (there is no plain `json` mode). This project saves **`reports/before-report.json`** as a **sanitized, single-array** copy of the OCSF export (`scripts/sanitize_prowler_ocsf.py`) for parsing and tooling parity with a “JSON report” workflow. Windows hosts should set UTF-8 (`PYTHONUTF8=1`) to avoid console encoding errors during the scan (or use `scripts/run-prowler-cis.ps1`, which deletes prior exports first to avoid invalid concatenated files).

## Executive summary

**Phase 1 (before audit, 2026-04-22):** Prowler **before scripted remediation** reported **75 FAIL**, **17 PASS**, and **3 MANUAL** findings across **95** total rows in the OCSF export (CIS 2.0 AWS pack). **WARN** is not a separate Prowler OCSF status; see `warn_note` in `reports/before-metrics.json`.

**Phase 2 (remediation):** `scripts/run-remediate.ps1` / `remediate.sh` was executed with lab parameters (`BUCKET_NAME`, `REGION`, `SG_NAME`) aligned to the introduce script. Idempotent cleanup covers the lab S3 bucket, IAM user, single-region CloudTrail trail and logs bucket, world-open SSH security group (if present), and restores a **CIS-minimum account password policy**. **Root MFA cannot be automated here** and remains a **manual Console** step.

**Phase 3–4 (after audit & comparison — completed):** **`scripts/run-after-audit.ps1`** was executed after scripted remediation. **Without root MFA enrollment:** Prowler reported **74 FAIL**, **18 PASS**, and **3 MANUAL** across **95** OCSF rows — **1 fewer FAIL** and **1 additional PASS** versus the before capture (relative reduction in FAIL count: \((75 - 74) / 75 \approx 1.3\%\)).

**Root MFA:** Enrollment was **not completed** in this engagement because **root Console access / permissions** did not allow MFA setup from the operator’s context (typical when day-to-day work uses an **IAM user** such as `lab-cli-user` rather than the **root user**). CIS **1.1** therefore remains **FAIL** in the after export until the **account owner signs in as root** (or equivalent recovery path) and assigns MFA.

**Primary evidence artifacts:** Before — `reports/before-report.html`, `reports/before-report.json`, `reports/before-metrics.json`. After — `reports/after-report.html`, `reports/after-report.json`, `reports/after-metrics.json`.

---

## Prowler measurement summary

### Before remediation (baseline — 2026-04-22 capture)

| Metric | Value |
|--------|------:|
| Total finding rows (OCSF) | 95 |
| FAIL | 75 |
| PASS | 17 |
| MANUAL | 3 |
| MUTED | 0 |
| WARN | *Not reported separately* (see `warn_note` in metrics JSON) |

**Top failed checks (severity-sorted excerpts from `reports/before-metrics.json`):**

1. **IAM — `iam_aws_attached_policy_no_administrative_privileges` (Critical):** administrative policy allowing `*:*` is attached (lab / account state).
2. **IAM — `iam_root_hardware_mfa_enabled` / `iam_root_mfa_enabled` (Critical):** root MFA not enrolled.
3. **CloudTrail — `cloudtrail_multi_region_enabled` (High):** no multi-Region trail with logging (expected after lab trail removal until a compliant trail is created).

**Simple reading of the six lab themes:** public S3 / BPA, IAM admin attachment hygiene, CloudTrail coverage, SSH from `0.0.0.0/0`, root MFA, and account password policy — measured together with broader CIS surface (Access Analyzer, Config, CloudWatch, etc.).

### After remediation (post-`run-remediate.ps1` + `run-after-audit.ps1`, MFA not enrolled)

| Metric | Value |
|--------|------:|
| Total finding rows (OCSF) | 95 |
| FAIL | 74 |
| PASS | 18 |
| MANUAL | 3 |
| MUTED | 0 |

**Delta:** FAIL **−1**, PASS **+1**, total rows **0** (same CIS export shape).

**Relative improvement (FAIL count):** \((75 − 74) / 75 \approx 1.3\%\).

**Highlight (from `reports/after-metrics.json` top FAIL excerpts):** **`iam_root_hardware_mfa_enabled`** no longer surfaces in the severity-ranked top five excerpts; **`iam_root_mfa_enabled`** remains **Critical / FAIL**. **`iam_aws_attached_policy_no_administrative_privileges`** remains **FAIL** — likely **non-lab** principals still carry administrative attachments (for example the assessment IAM user or roles); triage with IAM Access Analyzer / CSPM resource detail, not only the removed lab user.

### Before vs after (high level)

| Measure | Before | After | Change |
|---------|-------:|------:|-------:|
| FAIL | 75 | 74 | −1 |
| PASS | 17 | 18 | +1 |
| Total rows | 95 | 95 | 0 |

**Interpretation:** Scripted remediation plus re-scan produced a **modest net improvement** on this export (one row moved **FAIL → PASS**) while **root MFA** stayed **FAIL** because MFA could not be enrolled under the operator’s available **root / permission** path. **CloudTrail**, **Access Analyzer**, **Config**, and **CloudWatch** buckets remain **FAIL** in a thin lab until logging and detective controls are stood up to production-style baselines.

---

## Findings summary (six lab scenarios — CIS mapping)

| Finding ID | CIS Control | Severity | Service | Lab intent — Before | After scripted remediation |
|------------|-------------|----------|---------|----------------------|----------------------------|
| AWS-CIS-LAB-01 | **2.1.1** Block public access (S3) | High | Amazon S3 | Introduced public-read posture | **Lab bucket removed**; BPA-related failures cleared for that bucket |
| AWS-CIS-LAB-02 | **1.16** Policies attached only to groups/roles | Critical | AWS IAM | **`cis-lab-admin-user`** + direct `AdministratorAccess` | **Lab user removed** (policy attachment eliminated for that user) |
| AWS-CIS-LAB-03 | **3.1** CloudTrail enabled in all regions | High | CloudTrail | Single-region trail | **Trail and logs bucket removed** (logging posture changed; **replace** with compliant multi-Region trail for PASS) |
| AWS-CIS-LAB-04 | **5.2** No world-open admin ports | High | EC2 / VPC | SSH `0.0.0.0/0` | **Rule/SG remediated** per script |
| AWS-CIS-LAB-05 | **1.1** Root MFA | Critical | IAM (root) | No MFA (lab / account state) | **Still FAIL** — root MFA **not enrolled**; enrollment **blocked** from operator context (use **root sign-in** / account owner when permitted) |
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
**Outstanding at time of after-scan:** root MFA was **not enrolled**. The operator could not complete enrollment due to **permissions / access path** (assessment performed with an **IAM user**; **root Console** enrollment is a separate, account-owner step). The **after** export still shows **`iam_root_mfa_enabled` as FAIL** at minimum; see **`reports/after-metrics.json`** for the live excerpt set. See `remediation-steps.md` for Console steps once **root access** is available.

**Verification:** After scan exports — `reports/after-report.html`, `reports/after-report.json`; summarized counts — `reports/after-metrics.json`. Re-run **`run-after-audit.ps1`** after root MFA is assigned to close CIS **1.1** rows.

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

This engagement follows a **real audit lifecycle**: **controlled misconfigurations** (introduce), **CIS-aligned measurement** with Prowler (`cis_2.0_aws`), **automated remediation** for reversible lab resources, then **re-measure** (`run-after-audit.ps1`). **Before:** **95** rows, **75 FAIL**, **17 PASS**, **3 MANUAL**. **After:** **95** rows, **74 FAIL**, **18 PASS**, **3 MANUAL** — roughly **1.3%** relative reduction in FAIL count with **root MFA intentionally outstanding** due to enrollment constraints. Qualitatively, the account remains a **lab**: residual FAILs for **CloudTrail**, **Access Analyzer**, **Config**, and **monitoring** illustrate the gap between **scripted reversal** and **production-ready** CIS posture.

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
