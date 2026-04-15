# Dataset Sources

This folder documents the public datasets used across all six
incidents. All datasets are freely available; no raw files are
redistributed in this repository.

## Datasets Used

| Incident | Dataset | Source | Access |
|---|---|---|---|
| 01 Phishing | EVTX-ATTACK-SAMPLES | github.com/sbousseaden/EVTX-ATTACK-SAMPLES | Clone repo, use Security/*.evtx |
| 02 Brute Force | Mordor / Security-Datasets | github.com/OTRF/Security-Datasets | Download JSON/EVTX per scenario |
| 03 Ransomware | EVTX-ATTACK-SAMPLES | github.com/sbousseaden/EVTX-ATTACK-SAMPLES | Clone repo, use Ransomware/*.evtx |
| 04 Data Exfil | Mordor + Splunk BOTS v3 | github.com/OTRF/Security-Datasets + botsdataset.splunkresearch.com | Download per linked scenario |
| 05 Malware | Malware Traffic Analysis | malware-traffic-analysis.net | Download PCAP + alerts per exercise |
| 06 Insider Threat | Mordor / Security-Datasets | github.com/OTRF/Security-Datasets | Download JSON/EVTX per scenario |

## CLI Replay

Each incident folder includes a small labeled extract suitable for offline CLI replay without downloading
the full dataset (`logs/sample-excerpt.txt`; incident **02** uses `logs/sample-auth.log`). Use these commands to work through the excerpts:

```bash
# Filter by event ID
grep "EventID=4625" logs/sample-excerpt.txt

# Extract unique source IPs
grep -oP 'SourceNetworkAddress[\s:=]+\K[\d.]+' logs/sample-excerpt.txt | sort | uniq -c | sort -rn

# Extract process names
grep -oP 'ProcessName[\s:=]+\K\S+' logs/sample-excerpt.txt | sort | uniq -c

# Parse JSON logs with jq (Mordor datasets)
cat logs/sample-excerpt.txt | jq '[.[] | {time: .EventTime, user: .SubjectUserName, event: .EventID}]'
```

## Licensing

All datasets are published for research and educational use.
Check each upstream repository for its specific license before
redistribution. This portfolio uses only small labeled excerpts
for reproducibility.
