# Incident Investigation Report — Brute Force (Password Guessing)

**Analyst:** Thanmayee Manchikanti  
**Date:** 2026-04-12  
**Severity:** HIGH  
**Status:** CLOSED  
**Dataset:** Mordor / Security-Datasets — https://github.com/OTRF/Security-Datasets  

---

## 1. Incident Summary

| Field | Detail |
|-------|--------|
| What | High-volume SSH password guessing against internet-facing service, followed by successful authentication. |
| Who (actor) | External host **203[.]0[.]113[.]15**. |
| Who (target) | Accounts **admin**, **deploy**, **root** on **srv-sshd**. |
| When | **2026-04-10** 08:14–08:16 UTC (see [`queries.md`](./queries.md)). |
| Where | Linux bastion / SSH server; internal correlation via **192[.]168[.]10[.]44** (NAT or jump host). |
| How | Automated guessing → **Accepted password** for **deploy**. |
| Impact | Valid account compromise; potential lateral movement via RDP or SSH tunnels. |

---

## 2. Attack Timeline

| Timestamp | Event | Log Source | ATT&CK Technique |
|-----------|-------|------------|------------------|
| 2026-04-10T08:14:22Z | Burst of failed passwords | `/var/log/auth.log` | T1110.001 |
| 2026-04-10T08:15:41Z | Successful password for **deploy** | `/var/log/auth.log` | T1078 |
| 2026-04-10T08:16:10Z | RDP session (if correlated) | Windows Security / RDP | T1021.001 |

---

## 3. Indicators of Compromise (IOCs)

| Type | Value | Verdict | Source |
|------|-------|---------|--------|
| IP | **203[.]0[.]113[.]15** | Malicious | SOAR Engine → VirusTotal / AbuseIPDB |
| Username | **deploy** (successful) | Compromised | Internal logs |
| Time window | 08:14–08:16 UTC | — | auth.log |
| Success | **2026-04-10T08:15:41Z** | Accepted | auth.log |

---

## 4. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|--------|-------------|----------------|----------|
| Credential Access | T1110.001 | Brute Force: Password Guessing | Hundreds of **Failed password** |
| Defense Evasion / Persistence | T1078 | Valid Accounts | Successful **deploy** login |
| Lateral Movement | T1021.001 | Remote Services: Remote Desktop Protocol | Post-SSH RDP pivot (if observed) |

---

## 5. Investigation Queries

All commands and queries used during this investigation are documented in [`queries.md`](./queries.md).

Key findings from queries:

- **203[.]0[.]113[.]15** produced **847** failed attempts in the sample window.
- **Accepted password** for **deploy** immediately after the failure burst.
- **>10** failures threshold tripped for single IP.

---

## 6. SOAR Engine Enrichment

Full enrichment output for all IOCs is in [`ioc-enrichment.md`](./ioc-enrichment.md).

Summary of verdicts:

- **1** IP flagged as malicious (**203[.]0[.]113[.]15**)
- **0** Domains flagged (SSH IP-only case)
- **0** File hashes (not applicable)

---

## 7. Root Cause Analysis

SSH exposed to the internet without strict rate limiting or key-only authentication allowed sustained password guessing until a weak or reused credential succeeded.

---

## 8. Containment & Remediation Steps

| Priority | Action | Owner | Status |
|----------|--------|-------|--------|
| P1 | Block **203[.]0[.]113[.]15**; force reset **deploy** | SOC Analyst | Complete |
| P2 | Enforce key-based auth; disable password SSH | IT | Planned |
| P3 | Enable MFA on jump hosts; review RDP exposure | Security | Planned |

---

## 9. Detection Opportunities

What detection rule would have caught this earlier:

```bash
# Count failed logins per source IP
grep "Failed password" /var/log/auth.log | \
  grep -oP 'from \K[\d.]+' | sort | uniq -c | sort -rn
```

Sigma rule stub:

```yaml
title: SSH Brute Force Then Success
status: experimental
logsource:
    product: linux
    service: auth
detection:
    selection_fail:
        - 'Failed password'
    selection_ok:
        - 'Accepted password'
    condition: selection_fail and selection_ok
falsepositives:
    - Legitimate lockout recovery
level: high
```

---

## 10. Lessons Learned

- Edge rate limiting and geo blocking reduce brute-force noise.
- SOAR enrichment of attacker IPs improves confidence for automated blocking.
- Account **deploy** should be privileged with MFA only.

---

*Investigation conducted using real public attack datasets. IOC enrichment uses the existing SOAR API only — see [`../../soar-engine/`](../../soar-engine/); this report does not change SOAR code.*
