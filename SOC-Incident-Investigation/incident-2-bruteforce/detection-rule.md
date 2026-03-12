# Detection Rule - Brute Force Login (Failures Followed by Success)

## Goal

Detect user accounts that experience **multiple failed authentication attempts** within a short period, followed by a **successful login** from the same source IP (high-confidence brute force/credential guessing).

---

## SIEM Correlation Logic (Generic)

**Trigger when:**
- Same `user` AND same `src_ip`
- `failed_logins >= 10` within `5 minutes`
- AND a `success_login` occurs within `10 minutes` of the first failure

**Recommended fields:**
- `timestamp`, `user`, `src_ip`, `result` (success/failure), `application`, `client_app`/`protocol`, `geo`, `mfa_applied`, `risk`

---

## Example (Splunk SPL)

```spl
index=auth (sourcetype="azuread:signin" OR sourcetype="windows:security" OR sourcetype="vpn:auth")
| eval outcome=case(match(Result,"Success") OR EventCode=4624 OR Result="Allow","success",
                    match(Result,"Failure") OR EventCode=4625 OR Result="Deny","failure",
                    true(),"other")
| where outcome IN ("success","failure")
| stats earliest(_time) as first_seen latest(_time) as last_seen
        count(eval(outcome="failure")) as failed_count
        count(eval(outcome="success")) as success_count
        values(application) as apps values(client_app) as client_apps values(geo) as geos
        by user src_ip
| where failed_count >= 10 AND success_count >= 1 AND (last_seen - first_seen) <= 600
| eval severity=case(failed_count>=25,"high", failed_count>=15,"medium", true(),"low")
| table first_seen last_seen user src_ip failed_count success_count severity apps client_apps geos
```

---

## Tuning / False Positive Reduction

- Exclude known corporate egress IPs / trusted VPN exit nodes.
- Increase threshold for high-volume internet-facing services.
- Require “uncommon geo” or “legacy authentication” for higher confidence:
  - `client_app IN ("IMAP4","POP3","SMTP")`
  - `mfa_applied=false`

---

## Response Playbook (What to Do When This Fires)

- Validate the success event (same user/IP, time correlation).
- Check if MFA/Conditional Access was bypassed (legacy auth).
- Contain: lock account, reset password, revoke sessions, block IP, disable legacy auth.
