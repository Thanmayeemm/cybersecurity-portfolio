
# SIEM Detection Rules – Phishing Credential Theft Incident

Prepared by: Security Detection Engineering Team  
Platform Assumption: Splunk / QRadar-like SIEM  
Purpose: Detect phishing-based credential theft and account takeover activities.

---

## 1. Rule Name
**Suspicious Foreign Login (Impossible Travel)**

### Description
Detects authentication events where a user logs in from a geographic location that differs significantly from their normal login region.

### Detection Logic
Trigger an alert when a user successfully authenticates from a foreign country that is not part of the organization's allowed regions.

### Example Log Query (Splunk)
```
index=auth_logs EventType=LoginSuccess
| stats count by user, src_ip, location
| where location!="United States"
```

### MITRE ATT&CK Technique
T1078 – Valid Accounts

### Severity
High

---

## 2. Rule Name
**Mailbox Forwarding Rule Created**

### Description
Detects creation of new mailbox forwarding rules which attackers commonly use for persistence and email exfiltration.

### Detection Logic
Alert when a mailbox rule is created that forwards emails to an external domain.

### Example Log Query (Splunk)
```
index=o365_logs EventType=InboxRuleCreated
| search ForwardTo!="*@acme-corp.com"
```

### MITRE ATT&CK Technique
T1114 – Email Collection

### Severity
High

---

## 3. Rule Name
**Access to Known Phishing Domain**

### Description
Detects internal users accessing domains flagged as phishing or newly registered suspicious domains.

### Detection Logic
Alert when endpoint or proxy logs show access to domains in a phishing threat intelligence list.

### Example Log Query (Splunk)
```
index=proxy_logs
| search url IN ("microsoft365-login-security.com","login-microsoft365-security.net","office365-verification-alert.com")
```

### MITRE ATT&CK Technique
T1566 – Phishing

### Severity
Medium

---

## 4. Rule Name
**Credential Submission to Suspicious Domain**

### Description
Detects possible credential harvesting by identifying browser events where users submit credentials to suspicious domains.

### Detection Logic
Trigger when endpoint telemetry shows credential submission to domains categorized as phishing.

### Example Log Query (Splunk)
```
index=endpoint_logs EventType=CredentialSubmission
| search DomainCategory="Phishing"
```

### MITRE ATT&CK Technique
T1056 – Credential Harvesting

### Severity
Critical

---

## 5. Rule Name
**Suspicious Login Followed by Mailbox Rule Creation**

### Description
Detects account takeover patterns where a foreign login is followed by mailbox rule creation.

### Detection Logic
Correlate login events with mailbox rule creation events within a short time window.

### Example Log Query (Splunk)
```
index=auth_logs EventType=LoginSuccess location!="United States"
| join user [
    search index=o365_logs EventType=InboxRuleCreated
]
```

### MITRE ATT&CK Technique
T1078 – Valid Accounts  
T1114 – Email Collection

### Severity
Critical

---

## Summary

These detection rules help identify common indicators of phishing-driven account takeover attacks:

- Suspicious foreign authentication activity
- Access to phishing domains
- Credential harvesting attempts
- Mailbox rule persistence
- Correlated attack behaviors

Deploying these rules within SIEM platforms such as Splunk or QRadar significantly improves detection of phishing-based compromises.
