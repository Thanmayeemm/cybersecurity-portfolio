# Incident Report — Brute Force (SSH Password Guessing)

**Analyst:** Thanmayee Manchikanti · **Date:** 2026-04-12 · **Severity:** HIGH · **Status:** CLOSED  
**Source:** [Mordor / Security-Datasets](https://github.com/OTRF/Security-Datasets) · **Lab log:** [`logs/sample-auth.log`](./logs/sample-auth.log) (synthetic OpenSSH-style excerpt)

---

## Summary (5W)

| | |
|--|--|
| **What** | High-volume **Failed password** from one public IP, then **Accepted password** for a valid account. |
| **Who** | **Attacker:** **203.0.113.15** · **secondary:** **198.51.100.3** (fewer failures) · **Accounts:** **admin**, **root**, **user1** (+ invalid **guest**) · **Compromised:** **user1**. |
| **When** | **2026-04-10** **08:14:03**–**08:15:52** UTC. |
| **Where** | **srv-sshd**; evidence from `auth.log`-style lines. |
| **Why / impact** | Valid SSH session under **user1**; treat as account compromise until reset and containment. |

---

## Attack Timeline

| Time (UTC) | Event |
|------------|--------|
| 08:14:03–08:14:57 | **20** failures from **203.0.113.15**; **3** from **198.51.100.3** |
| 08:15:52 | **Accepted password** for **user1** from **203.0.113.15** |

---

## Key Findings

- Single dominant source IP (**203.0.113.15**) and rapid rotation across usernames — **password guessing** (automation).
- **Accepted password** immediately after failure burst — **brute-then-success**.
- Repeatable commands: [`queries.md`](./queries.md) (includes **BusyBox** / **GNU grep** and **awk** fallbacks).

---

## Indicators of Compromise (IOCs)

| Type | Value |
|------|--------|
| IP | **203.0.113.15** |
| IP | **198.51.100.3** (contextual) |
| User | **user1** (success) |
| Window | **08:14:03** – **08:15:52** UTC |

Defanged: **203[.]0[.]113[.]15**, **198[.]51[.]100[.]3**.  
**Enrichment:** [`ioc-enrichment.md`](./ioc-enrichment.md)

---

## Root Cause

**SSH** accepted **password** authentication without adequate **rate limiting** / **lockout** / **key-only** policy, allowing guessing until a password worked.

---

## Remediation

| Priority | Action |
|----------|--------|
| P1 | Block **203.0.113.15**; kill sessions; force **user1** credential reset |
| P2 | Prefer **SSH keys**; disable password auth where policy allows; **fail2ban** or equivalent |
| P3 | Alert on **failed SSH** volume per IP correlated with **Accepted** from same IP |

---

## Evidence

Screenshots (`./screenshots/`):

| File | Shows |
|------|--------|
| [`failed_logins.png`](./screenshots/failed_logins.png) | Failed password lines |
| [`attacker_ip.png`](./screenshots/attacker_ip.png) | Per-IP failure counts |
| [`successful_login.png`](./screenshots/successful_login.png) | **Accepted password** for **user1** |

![failed](./screenshots/failed_logins.png)

![ip](./screenshots/attacker_ip.png)

![ok](./screenshots/successful_login.png)

---

**Queries:** [`queries.md`](./queries.md) · **Enrichment:** [`ioc-enrichment.md`](./ioc-enrichment.md)
