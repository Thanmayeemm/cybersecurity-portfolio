# Incident Investigation Report — Brute Force (Password Guessing)

**Analyst:** Thanmayee Manchikanti  
**Date:** 2026-04-12  
**Severity:** HIGH  
**Status:** CLOSED  
**Evidence:** Lab sample [`logs/sample-auth.log`](./logs/sample-auth.log) (OpenSSH-style excerpt for offline replay); methodology aligns with **Mordor / Security-Datasets** — https://github.com/OTRF/Security-Datasets  

---

## 1. Incident Summary

| Field | Detail |
|-------|--------|
| **What** | Internet-sourced **SSH password guessing** against **srv-sshd**, culminating in a **successful password authentication** to a valid local account. |
| **Who (affected)** | Targeted accounts **admin**, **root**, and **user1** (plus invalid user probe **guest**). **user1** is **confirmed compromised** (successful authentication). **admin** and **root** were probed but did not show a successful password in the analyzed window. |
| **When** | **2026-04-10** UTC, **08:14:03** (first failed attempt in sample) through **08:15:52** (successful login). |
| **Where** | Linux host **srv-sshd**; evidence from **`auth.log`** (OpenSSH **sshd** entries). |
| **How** | A single external address (**203.0.113.15**) generated a **high volume** of **Failed password** events across multiple usernames, consistent with **automated guessing**, followed by **Accepted password** for **user1** from the **same** source IP. |
| **Impact** | **Account compromise** of **user1** with interactive SSH access; risk of **follow-on activity** (persistence, lateral movement) until credentials are rotated and the session is contained. |

---

## 2. Attack Timeline

| Time (UTC, 2026-04-10) | Event | Notes |
|------------------------|-------|--------|
| **08:14:03** | First **Failed password** observed | Attack window opens; **admin** from **203.0.113.15** |
| **08:14:03 – 08:14:57** | **Repeated failed attempts** | **20** failures from **203.0.113.15**; rapid rotation across **admin**, **root**, **user1**, and **guest** (invalid user) |
| **08:14:58 – 08:15:00** | Additional failures from **198.51.100.3** | Lower volume (**3** failures); secondary scan or noise — correlate separately |
| **08:15:52** | **Successful compromise** | **Accepted password** for **user1** from **203.0.113.15** (port **44140**) |

---

## 3. Key Findings

- **Concentrated source:** The majority of failed authentication attempts originated from **203.0.113.15**, indicating a single prioritized brute-force source rather than distributed noise.
- **High frequency:** Attempts occurred **seconds apart** across rotating usernames, consistent with **automation** (T1110.001 — password guessing).
- **Broad targeting:** Failures spanned **admin**, **root**, **user1**, and an **invalid user (guest)** probe — typical of dictionary-style guessing against common names.
- **Confirmed compromise:** An **Accepted password** for **user1** from **203.0.113.15** after the failure burst indicates **valid credentials** were obtained for that account (T1078 — valid accounts).

Repeatable queries: [`queries.md`](./queries.md).

---

## 4. Indicators of Compromise (IOCs)

| Type | Value |
|------|--------|
| **Attacker IP** | **203.0.113.15** (same IP for bulk failures and successful login) |
| **Secondary IP** | **198.51.100.3** (failed attempts only in sample — triage before blocking) |
| **Targeted usernames** | **admin**, **root**, **user1**; invalid probe **guest** |
| **Compromised account** | **user1** |
| **Time window** | **2026-04-10**, **08:14:03 – 08:15:52** UTC |
| **Success indicator** | **Accepted password** for **user1** at **08:15:52** UTC |

Defanged for written reports: **203[.]0[.]113[.]15**, **198[.]51[.]100[.]3**.  
Enrichment record: [`ioc-enrichment.md`](./ioc-enrichment.md).

---

## 5. MITRE ATT&CK Mapping

| Tactic | ID | Technique | Evidence |
|--------|-----|-----------|----------|
| Credential Access | T1110.001 | Brute Force: Password Guessing | Sustained **Failed password** from **203.0.113.15** |
| Defense Evasion / Persistence | T1078 | Valid Accounts | **Accepted password** for **user1** |

---

## 6. Root Cause Analysis

Internet-exposed **SSH** accepted **password-based** authentication without **sufficient rate limiting**, **account lockout**, or **key-only** policy enforcement. That allowed automated guessing to continue until a **weak or reused password** for **user1** succeeded.

---

## 7. Containment & Remediation

| Priority | Action |
|----------|--------|
| **P1** | Block **203.0.113.15** at the perimeter; terminate active **user1** sessions; **force password reset** and review **sudo** / group membership for **user1** |
| **P2** | Prefer **SSH public-key** authentication; disable **password** authentication where policy allows; apply **fail2ban** or equivalent **rate limiting** |
| **P3** | **MFA** for privileged and remote-access paths; review **admin** / **root** exposure |
| **P4** | **Monitoring and alerting:** alert on **failed SSH** thresholds per source IP and **correlate** with **Accepted password** from the same IP within a short window |
| **P5** | **Account lockout** or progressive backoff policies aligned with organizational risk (balance lockout vs. availability) |

---

## 8. Detection Opportunity

Correlate **high failed-authentication volume** from a single source with **successful authentication** from that same source within minutes — suitable for SIEM rules or host-based tooling (see [`queries.md`](./queries.md) for CLI patterns).

---

## 9. Lessons Learned

- Rank **source IPs** by failed volume before deep session review.
- Treat **post-success** activity as **incident scope expansion** until containment is verified.
- Enrich attacker IPs via SOAR (**[`ioc-enrichment.md`](./ioc-enrichment.md)**) to support **automated blocking** decisions.

---

## 10. Evidence (screenshots)

The following captures support the analysis documented above (CLI triage on [`logs/sample-auth.log`](./logs/sample-auth.log)).

| # | Description | File |
|---|-------------|------|
| 1 | Failed login activity / listing | [`failed_logins.png`](./screenshots/failed_logins.png) |
| 2 | Attacker IP identification (per-IP failure counts) | [`attacker_ip.png`](./screenshots/attacker_ip.png) |
| 3 | Successful login (compromise) | [`successful_login.png`](./screenshots/successful_login.png) |

![Failed SSH password attempts](./screenshots/failed_logins.png)

![Attacker IP ranked by failed attempts](./screenshots/attacker_ip.png)

![Accepted password — successful login](./screenshots/successful_login.png)

---

*Investigation methodology follows public dataset practices (Mordor). The bundled log excerpt is synthetic for offline practice. SOAR enrichment uses the existing API — [`../../soar-engine/`](../../soar-engine/).*
