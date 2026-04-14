# Public Datasets Used in This Investigation Lab

Investigations are grounded in **real, publicly available** attack datasets (below). **Exception:** [`02-brute-force/logs/sample-auth.log`](../02-brute-force/logs/sample-auth.log) is a **small, labeled synthetic** OpenSSH-style excerpt for **offline CLI practice** only; it does not replace Mordor exports for full realism.

For **portfolio screenshots** of your analysis, see [`../SCREENSHOTS-GUIDE.md`](../SCREENSHOTS-GUIDE.md).

---

## EVTX-ATTACK-SAMPLES
- **Repository:** https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- **What it is:** Pre-recorded Windows Event Log (EVTX) files of real attack techniques, each mapped to MITRE ATT&CK
- **Used in:** Incident 01 (Phishing), Incident 03 (Ransomware)
- **Maintained by:** Samir Bousseaden (security researcher, Elastic)

## Mordor Security Datasets
- **Repository:** https://github.com/OTRF/Security-Datasets
- **What it is:** Pre-recorded security events from simulated adversarial techniques in controlled lab environments
- **Used in:** Incident 02 (Brute Force), Incident 04 (Data Exfiltration), Incident 06 (Insider Threat)
- **Maintained by:** Open Threat Research Forge

## Splunk BOTS v3
- **Repository:** https://github.com/splunk/botsv3
- **What it is:** Boss of the SOC competition dataset — realistic enterprise attack scenarios
- **Used in:** Incident 04 (Data Exfiltration) — supplementary
- **Note:** Full dataset requires Splunk instance; sample events available on GitHub

## Malware Traffic Analysis
- **Site:** https://www.malware-traffic-analysis.net
- **What it is:** Real PCAP captures of malware network traffic with documented IOCs
- **Used in:** Incident 05 (Malware Infection) — network evidence
- **Note:** All files are password-protected as a safety measure (password: infected)
