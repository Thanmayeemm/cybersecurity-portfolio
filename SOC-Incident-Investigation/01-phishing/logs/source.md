# Log source — Incident 01 (Phishing)

**Dataset:** EVTX-ATTACK-SAMPLES  
**Repository:** https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES  

**Credit:** Samir Bousseaden — Windows Event Log captures mapped to MITRE ATT&CK for research and training.

**Local files in this folder**

| File | Description |
|------|-------------|
| `sample-excerpt.txt` | Representative parsed lines from Security and Sysmon-style process output for **training and demonstration**. IPs use **RFC 5737** documentation ranges (`198[.]51[.]100[.]0/24`, `203[.]0[.]113[.]0/24`) and are not live targets. |

**How to obtain primary evidence:** Clone the upstream repository and select spearphishing / credential-access related samples (for example spearphishing attachment, LSASS-related, and outbound web protocol activity). Convert or export EVTX to text for CLI analysis as needed.
