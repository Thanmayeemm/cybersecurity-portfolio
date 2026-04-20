# Cybersecurity Portfolio — Thanmayee Manchikanti

Security engineer focused on SOC automation, threat detection,
incident investigation, and cloud security. This portfolio
demonstrates end-to-end security engineering work across four
projects, each covering a distinct skill area.

**Portfolio site:** https://thanmayee-portfolio-ttbb.vercel.app/
**LinkedIn:** https://www.linkedin.com/in/thanmayeemanchikanti

---

## Projects

### 1. Automated Threat Intelligence & SOAR Engine
**[→ soar-engine/](./soar-engine/)**

Production-style security automation pipeline: ingest IOC data
(IP, domain, file hash), enrich via VirusTotal v3 and AbuseIPDB v2,
apply a weighted risk-scoring model, and trigger automated response
workflows — Slack alerting and SQLite incident logging.

**Stack:** Python · Flask · SQLite · REST APIs · Slack Webhooks
**Key capabilities:**
- Configurable verdict engine: benign / suspicious / malicious
- Combined risk score (0–100) with confidence weighting
- Analyst-facing web dashboard and incident log
- SOAR-style enrich → decide → respond playbook

---

### 2. SOC Incident Investigation Lab
**[→ SOC-Incident-Investigation/](./SOC-Incident-Investigation/)**

Hands-on incident investigation portfolio using real public attack
datasets (EVTX-ATTACK-SAMPLES, Mordor Security Datasets, Splunk BOTS v3,
malware-traffic-analysis.net). Covers six attack types with reproducible
CLI workflows, IOC extraction, MITRE ATT&CK mapping, SOAR enrichment
integration, and formal analyst-grade reporting.

**Incidents covered:** Phishing · Brute force · Ransomware ·
Data exfiltration · Malware infection · Insider threat

**Tools:** Linux CLI (grep, awk, sort, uniq, jq) · MITRE ATT&CK ·
SOAR Engine (IOC enrichment via VirusTotal + AbuseIPDB)

**Each investigation includes:**
- Evidence-based attack timeline reconstruction
- IOC extraction and SOAR enrichment output
- MITRE ATT&CK technique mapping with T-codes
- Detection opportunity and Sigma rule stub
- Root cause analysis and remediation steps
- Analyst notes with genuine findings and lessons learned

---

### 3. Detection Engineering Lab *(in progress)*
**[→ detection-engineering-lab/](./detection-engineering-lab/)**

Sigma detection rules written for the six ATT&CK techniques identified
in the SOC investigation lab above. Each rule is translated to Splunk
SPL and validated against real EVTX-ATTACK-SAMPLES log data. Includes
false positive analysis and tuning notes per rule.

**Rules:** Brute force SSH · Ransomware VSS deletion · Phishing macro
execution · Data staging · Malware C2 beaconing · Insider after-hours
access

**Stack:** Sigma · Splunk SPL · EVTX-ATTACK-SAMPLES · MITRE ATT&CK

---

### 4. AWS Cloud Security Audit *(in progress)*
**[→ aws-security-audit/](./aws-security-audit/)**

CIS AWS Foundations Benchmark assessment of a live AWS environment
using Prowler. Identifies critical and high-severity misconfigurations
including public S3 exposure, over-permissive IAM policies, disabled
CloudTrail, and unrestricted security group rules. Includes formal
findings report and post-remediation re-audit.

**Stack:** AWS · Prowler · CIS Benchmark v2.0 · IAM · CloudTrail · S3

---

## Skills

| Area | Tools & Technologies |
|------|---------------------|
| Security operations | Incident triage · IOC analysis · MITRE ATT&CK · Log forensics · Detection rule writing |
| Threat intelligence | VirusTotal · AbuseIPDB · IOC enrichment · Threat scoring |
| SIEM & detection | Splunk SPL · Sigma rules · EVTX log analysis |
| Automation & SOAR | Python · Flask · REST APIs · Slack Webhooks · Security workflow automation |
| Cloud security | AWS · Prowler · CIS Benchmark · IAM hardening · CloudTrail |
| CLI & systems | Linux CLI · grep · awk · jq · SQLite · Bash |
| Frameworks | MITRE ATT&CK · CIS Controls · NIST CSF |

---

## Repository structure

```
cybersecurity-portfolio/
├── soar-engine/                  # SOAR pipeline — featured project
├── SOC-Incident-Investigation/   # 6-incident investigation lab
├── detection-engineering-lab/    # Sigma rules + Splunk (in progress)
├── aws-security-audit/           # AWS CIS audit with Prowler (in progress)
└── archive/                      # Earlier work (SOC-Dashboard, Threat-Detection-Engine)
```

---

*Open to security engineer, detection engineer, and SOC automation roles.*
