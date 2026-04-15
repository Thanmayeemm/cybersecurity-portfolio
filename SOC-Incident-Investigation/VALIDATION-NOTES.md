# Analyst validation notes (internal)

Concise review of **queries vs conclusions** for the investigation lab. **No methodology changes** are required for portfolio use; items below are transparency for reviewers.

| Incident | Commands | Conclusion alignment | Notes |
|----------|------------|----------------------|--------|
| **01 Phishing** | `grep` on parsed EVTX text; pipe-delimited process lines | Failed logons → Office→PS → C2 → LSASS chain matches narrative | Timeline in README is **chronological**; IOC table defers full hash to **`ioc-enrichment.md`**. |
| **02 Brute force** | `grep` / `uniq` on `sample-auth.log` | Counts and **Accepted** line match [`logs/sample-auth.log`](./02-brute-force/logs/sample-auth.log) | Lab sample is **synthetic**; Mordor exports scale counts up only. |
| **03 Ransomware** | File/process `grep` patterns | **.locked** + recovery inhibition + tamper = coherent ransomware story | Tied to EVTX-ATTACK-SAMPLES practice, not one fixed file in-repo. |
| **04 Exfiltration** | `awk` on column **9** for bytes | Matches [`logs/network_connections.csv`](./04-data-exfiltration/logs/network_connections.csv) layout | Evidence is **CSV + CLI** in the incident report (no PNGs). |
| **05 Malware** | `grep`/`awk` on text exports from PCAP workflow | Beacon + persistence + process anomaly narrative holds | Analyze PCAP on **isolated VM** only. |
| **06 Insider** | `awk` time filters; volume counts | After-hours + bulk access + mail exfil story is consistent | Some public logs need **strict timestamp format**; align exported text with `queries.md` examples before running. |

**Consistency rule:** Published IOCs use **documentation IPs** (RFC 5737 ranges) in reports; enrichment details live in each **`ioc-enrichment.md`**.
