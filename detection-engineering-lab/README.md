# Detection Engineering Lab

**Status: In progress**

Writing 6 Sigma detection rules covering the ATT&CK techniques
from the SOC investigation lab — one rule per incident type.
Each rule will be translated to Splunk SPL and validated against
real EVTX-ATTACK-SAMPLES log data.

**Rules being written:**
- Brute force SSH authentication (T1110.001)
- Ransomware pre-encryption behaviour — VSS deletion (T1490)
- Phishing macro execution chain (T1204.002)
- Data staging before exfiltration (T1074.001)
- Malware C2 beacon pattern (T1071.001)
- Insider after-hours file access (T1078)

**Stack:** Sigma · Splunk SPL · EVTX-ATTACK-SAMPLES · MITRE ATT&CK

*Rules, SPL translations, Splunk validation screenshots,
and false positive analysis will be committed here.*
