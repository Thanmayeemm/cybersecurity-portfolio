# SOC Incident Investigation Lab

A simulated **Security Operations Center (SOC) investigation** focused on analyzing a phishing attack that resulted in credential theft and unauthorized account access. This project demonstrates how security analysts investigate security incidents using enterprise-style logs and SIEM analysis techniques.

---

# Project Overview

The **SOC Incident Investigation Lab** simulates a real-world phishing attack targeting a corporate employee. The objective of this project is to demonstrate the process used by Security Operations Center analysts to detect, investigate, and respond to security incidents.

The lab includes:

- Realistic enterprise security logs
- Phishing email analysis
- SIEM-style log investigation
- Indicators of compromise (IOC) identification
- Attack timeline reconstruction
- Detection engineering rules

This project mirrors the workflow used by **SOC Analysts, Incident Responders, and Detection Engineers** when investigating security events in enterprise environments.

---

# Incident Scenario

An employee in the finance department received a phishing email impersonating the **Microsoft Security Team**. The email warned of a suspicious login attempt and instructed the user to verify their account through a provided link.

The link redirected the victim to a **fraudulent Microsoft login page**, where the user unknowingly entered their credentials.

Shortly afterward:

- The attacker logged into the corporate account from a **foreign IP address**
- The attacker accessed the user's mailbox
- A **malicious email forwarding rule** was created
- Emails were redirected to an external ProtonMail account

The suspicious activity triggered a **SIEM alert for unusual login behavior**, prompting an investigation by the SOC team.

---

# Investigation Process

The following steps were performed during the investigation:

### 1. Email Analysis
- Reviewed phishing email headers
- Verified SPF, DKIM, and DMARC failures
- Identified suspicious sender domains

### 2. Endpoint Investigation
- Examined endpoint logs for browser activity
- Identified user access to a known phishing domain

### 3. Authentication Log Analysis
- Detected login from an abnormal geographic location
- Identified successful authentication without MFA

### 4. Mailbox Activity Review
- Detected creation of a malicious email forwarding rule
- Identified external email exfiltration

### 5. Timeline Reconstruction
- Correlated logs across multiple systems
- Built a full attack timeline

### 6. Detection Engineering
- Developed SIEM detection rules to identify similar attacks in the future

---

# Tools Used

This lab simulates investigation workflows using tools commonly used in enterprise security environments.

| Tool | Purpose |
|-----|------|
| SIEM (Splunk / QRadar style logs) | Log analysis and threat detection |
| Email Security Logs | Phishing investigation |
| Endpoint Logs (EDR-style) | User activity investigation |
| Firewall Logs | Network traffic monitoring |
| Threat Intelligence | IOC validation |
| MITRE ATT&CK Framework | Attack technique classification |

---

# Skills Demonstrated

This project demonstrates practical cybersecurity skills including:

- SOC incident investigation
- Phishing attack analysis
- SIEM log analysis
- Threat detection
- Indicators of compromise identification
- Timeline reconstruction
- Detection engineering
- MITRE ATT&CK mapping
- Incident response documentation

These skills align with responsibilities commonly required for:

- SOC Analyst
- Cybersecurity Analyst
- Threat Detection Engineer
- Incident Response Analyst

---

# Key Learnings

This lab highlights several important cybersecurity concepts:

### Phishing is a primary initial access vector
Attackers frequently impersonate trusted services such as Microsoft to trick users into revealing credentials.

### Credential theft enables account takeover
Once credentials are compromised, attackers can bypass perimeter defenses using legitimate authentication.

### Mailbox rules are a common persistence technique
Attackers often create forwarding rules to maintain access to sensitive communications.

### SIEM correlation is critical for detection
Correlating logs from email systems, endpoints, and identity providers is essential to identify attack patterns.

### Security awareness training is important
User education remains a key defense against phishing attacks.

---

# Project Structure
