
# Security Incident Response Report

**Incident Type:** Phishing → Credential Theft → Account Compromise  
**Severity:** High  
**Affected System:** Microsoft 365 / Corporate Email  
**Impacted User:** j.smith@acme-corp.com  
**Detection Source:** SIEM Alert – Suspicious Foreign Login  
**Report Prepared By:** Security Operations Center (SOC)

---

## 1. Incident Summary

On March 5, 2026, the Security Operations Center detected suspicious login activity involving the corporate account **j.smith@acme-corp.com**. Investigation determined that the user received a phishing email impersonating Microsoft Security. The email contained a malicious link directing the user to a fraudulent Microsoft 365 login page designed to harvest credentials.

After the victim submitted their credentials, the attacker authenticated from a foreign IP address located in Russia. The attacker accessed the user’s mailbox and created a malicious email forwarding rule to redirect emails to an external ProtonMail address.

---

## 2. Timeline of Events

| Time (UTC) | Event |
|------------|------|
| 09:13 | Phishing email delivered to user mailbox |
| 09:14 | User clicked phishing link |
| 09:14 | User entered credentials on phishing site |
| 09:20 | Attacker authenticated using stolen credentials |
| 09:21 | Attacker accessed Microsoft Exchange mailbox |
| 09:21 | Attacker created malicious forwarding rule |
| 09:25 | SIEM alert triggered for suspicious login location |

---

## 3. Indicators of Compromise (IOC)

### Malicious Domains

- microsoft365-login-security.com  
- login-microsoft365-security.net  
- office365-verification-alert.com  

### Suspicious IP Addresses

**185.193.127.44**  
Country: Russia  
Purpose: Hosting phishing infrastructure

**102.165.34.19**  
Country: Russia  
Purpose: Attacker login activity  
Threat Reputation: Credential stuffing campaigns

### Suspicious Email Account

finance.audit@protonmail.com

---

## 4. Log Analysis

### Email Logs

The phishing email originated from the domain **microsoft-secure365.com**, which failed authentication checks.

- SPF: Fail  
- DKIM: None  
- DMARC: Fail  

These failures indicate the email was spoofed.

### Endpoint Logs

User accessed the phishing site using a web browser.

Process: chrome.exe  
URL: https://microsoft365-login-security.com/verify-session  
Event: Credential Submission  
Risk Score: High

### Authentication Logs

User: j.smith@acme-corp.com  
Source IP: 102.165.34.19  
Location: Moscow, Russia  
Authentication Method: Password  
MFA Status: Not satisfied  
Risk Level: High

### Mailbox Logs

Rule Name: ForwardToExternal  
Forward To: finance.audit@protonmail.com

This rule forwards emails externally, indicating potential data exfiltration.

---

## 5. Attacker Behavior

### Initial Access
The attacker delivered a phishing email impersonating Microsoft security alerts.

### Credential Harvesting
The victim entered credentials into a fake Microsoft login page.

### Account Takeover
The attacker used stolen credentials to authenticate successfully.

### Persistence
The attacker created a mailbox forwarding rule to maintain access.

### Data Exfiltration
Emails were forwarded to an external ProtonMail address.

---

## 6. MITRE ATT&CK Mapping

| Technique | ID |
|----------|----|
| Phishing | T1566 |
| Credential Harvesting | T1056 |
| Valid Accounts | T1078 |
| Email Collection | T1114 |
| Exfiltration via Email Forwarding | T1020 |

---

## 7. Containment Actions

- Reset compromised user password
- Revoke active authentication sessions
- Remove malicious mailbox forwarding rules
- Block malicious IP addresses
- Block phishing domains at DNS and email gateway

---

## 8. Remediation Recommendations

### Identity Security
- Enforce MFA for all accounts
- Implement conditional access policies
- Enable impossible travel detection alerts

### Email Security
- Deploy advanced phishing detection
- Implement email sandboxing
- Enforce DMARC reject policies

### Monitoring
- Monitor mailbox rule creation
- Detect logins from high‑risk regions
- Alert on VPN/TOR login activity

### Security Awareness
- Conduct phishing awareness training
- Run simulated phishing exercises

---

## 9. Lessons Learned

- The phishing email bypassed email filtering controls.
- MFA was not enforced or was bypassed.
- Mailbox rule creation was not immediately detected.

Strengthening email security, enforcing MFA, and improving user awareness will significantly reduce similar attacks.
