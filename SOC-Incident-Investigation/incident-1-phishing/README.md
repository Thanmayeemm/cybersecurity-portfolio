# Phishing Incident Investigation

## Scenario

A user received a phishing email pretending to be a password reset notification.  
The user clicked the malicious link and entered their credentials on a fake login page.

Shortly after, a login attempt from a foreign IP address triggered a security alert.

## Investigation Steps

1. Review authentication logs
2. Analyze email header information
3. Identify suspicious IP address
4. Confirm credential compromise

## Indicators of Compromise

• Suspicious IP address  
• Malicious phishing domain  
• Foreign login activity

## Outcome

The compromised account was secured by resetting the password and blocking the attacker IP address.

A SIEM detection rule was created to detect similar login anomalies in the future.
