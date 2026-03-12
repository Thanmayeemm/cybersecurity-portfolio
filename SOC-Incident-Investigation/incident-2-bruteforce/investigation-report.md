# Security Incident Response Report

**Incident Type:** Brute Force / Password Guessing → Account Compromise Attempt  
**Severity:** High  
**Affected Systems:** Microsoft Entra ID (Azure AD), Exchange Online (IMAP), VPN Gateway  
**Impacted User:** j.doe@acme-corp.com (SamAccountName: jdoe)  
**Detection Source:** SIEM Correlation Alert (Multiple Failures → Success)  
**Report Prepared By:** Security Operations Center (SOC)  

---

## 1. Incident Summary

On **2026-03-09**, the SOC identified a brute force login pattern targeting **j.doe@acme-corp.com**. Authentication logs showed **20+ failed login attempts** from a single external IP (**185.225.73.19**) followed by a **successful login** using **legacy authentication (IMAP4)**. Shortly after the successful authentication, the same IP successfully authenticated to the **corporate VPN**, establishing a remote session.

The combination of high failure volume, rapid success, suspicious geo-location, and legacy protocol usage indicates likely password guessing/credential stuffing with a valid password eventually obtained.

---

## 2. Timeline of Events

| Time (UTC) | Event |
|------------|------|
| 02:11 | Repeated Azure AD sign-in failures begin (legacy IMAP) from 185.225.73.19 |
| 02:11–02:15 | DC logs multiple 4625 failures for `jdoe` from 185.225.73.19 |
| 02:15 | Azure AD sign-in succeeds for `j.doe@acme-corp.com` (single factor; MFA not applied) |
| 02:15 | VPN authentication succeeds from the same IP; session established |
| 02:16 | Exchange Online IMAP access observed from same source IP |
| 02:25 | SOC containment actions initiated (account lock/reset; session revoke; block IP) |

---

## 3. Indicators of Compromise (IOC)

### Suspicious IP Address
- **185.225.73.19** (External)  
  - Observed: repeated failures then success, VPN access, IMAP mailbox access

### Targeted Account
- **j.doe@acme-corp.com** / `jdoe`

### Suspicious Authentication Protocol
- **Legacy authentication (IMAP4 / IMAPS)** to Exchange Online

---

## 4. Log Analysis

### Identity / Cloud Authentication (Entra ID)
Evidence shows rapid failures followed by success from the same IP:
- Multiple **Failure** events for `j.doe@acme-corp.com` from `185.225.73.19` within ~5 minutes
- A **Success** event at `2026-03-09T02:15:11Z`
- `AuthenticationRequirement=singleFactorAuthentication`
- `MFARequired=false` / `ConditionalAccess=NotApplied`
- Risk flagged as **high**

### Windows Security (Domain Controller)
The domain controller recorded:
- **4625** (failed logon) events with `Status=0xC000006A` (bad password)
- **4624** (successful logon) immediately after, consistent with eventual password success

### VPN Gateway
VPN logs confirm network entry:
- Multiple **Deny** events for invalid credentials
- A subsequent **Allow** with session details and assigned internal IP (`10.70.14.23`)

---

## 5. Attack Technique

The activity aligns with a brute force/password guessing attack against a single user. The attacker likely:
- Automated repeated credential attempts from one external IP
- Used **legacy authentication** endpoints (IMAP) to bypass MFA/Conditional Access gaps
- After obtaining a valid password, authenticated successfully and attempted network access via VPN

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|-------|-----------|----|----------|
| Credential Access | Brute Force | T1110 | 20+ failures followed by success from same IP |
| Credential Access | Password Spraying | T1110.003 | Pattern consistent with automated password attempts (single user in this dataset) |
| Defense Evasion | Use of Legacy Authentication | (Related) | Legacy IMAP observed; MFA/CA not applied |
| Initial Access | Valid Accounts | T1078 | Successful authentication and VPN access using valid credentials |

---

## 7. Containment Actions

- Disabled or temporarily locked the impacted account `jdoe`
- Forced password reset and revoked active sessions / refresh tokens
- Blocked source IP **185.225.73.19** at edge firewall/VPN where feasible
- Disabled **legacy authentication** for Exchange Online (IMAP/POP) for the tenant or at least for high-value accounts
- Reviewed recent sign-ins and VPN session activity for lateral movement attempts

---

## 8. Remediation Steps

### Identity Hardening
- Enforce MFA for all users; validate Conditional Access policies apply to all client apps (including legacy)
- Disable legacy auth protocols (IMAP/POP/SMTP AUTH) unless required; if required, restrict by IP and enforce app passwords/modern auth alternatives
- Enable risk-based sign-in policies and alerts for high-risk authentications

### Monitoring & Detection Improvements
- Alert on:
  - High failure counts per user or per IP in short windows
  - “failures followed by success” correlation
  - Any legacy-auth success from uncommon geographies
- Monitor VPN logons from high-risk IPs and unusual countries

### User & Account Hygiene
- Require strong passwords and deny known breached passwords
- Educate users on reporting unexpected MFA prompts and suspicious account activity

---

## 9. Outcome

The SOC contained the incident by revoking sessions, resetting credentials, and blocking the attacker IP. No confirmed data exfiltration was observed in the provided log window; however, risk was elevated due to successful VPN access, so follow-up reviews of endpoint and internal network telemetry were performed to ensure no persistence or lateral movement occurred.
