# SOC Threat Detection Engine (Beginner-Friendly SOC Automation)

This project is a small **SOC detection automation** lab that demonstrates how a cybersecurity engineer/SOC analyst can:
- Parse authentication logs
- Detect brute force attacks
- Flag suspicious logins from unusual IP ranges
- Detect suspicious process execution patterns (simulated endpoint telemetry)
- Combine results into a simple investigation report

The scripts are intentionally **beginner friendly**, but use realistic SOC terminology and detection logic.

---

## Project Structure

`SOC-Threat-Detection-Engine/`
- `login_logs.csv`: sample authentication dataset (normal activity + attacks)
- `detect_bruteforce.py`: detects brute force attempts (failed threshold in a time window)
- `detect_suspicious_ips.py`: flags successful logins from unusual/foreign IP ranges (simulated)
- `detect_malware_process.py`: simulates endpoint process logs and flags suspicious tools/behavior
- `generate_report.py`: combines detector outputs into a single investigation report
- `sample_output.txt`: example output from running the scripts

---

## How SOC analysts use log detection

In a SOC, alerts come from many sources (identity, endpoint, firewall/proxy, cloud). Analysts typically:
- **Triage**: confirm the alert is real and high confidence
- **Pivot**: search by user, IP, host, timestamp, hash, domain
- **Correlate**: connect events across log sources (e.g., failed logins + later success)
- **Contain**: isolate hosts, disable accounts, block IPs/domains
- **Remediate**: fix root cause (MFA, disable legacy auth, improve monitoring)

These scripts simulate that workflow in a simplified way.

---

## Requirements

- Python 3.9+ (standard library only; no external dependencies)

---

## How to run

From the repository root:

```bash
python SOC-Threat-Detection-Engine/detect_bruteforce.py
python SOC-Threat-Detection-Engine/detect_suspicious_ips.py
python SOC-Threat-Detection-Engine/detect_malware_process.py
python SOC-Threat-Detection-Engine/generate_report.py
```

---

## Skills Demonstrated

- Log parsing and normalization
- Detection engineering (threshold + time window logic)
- Basic threat hunting pivots (IP/user)
- Reporting and SOC communication
- Python automation fundamentals for security operations

---

## Example results

See `sample_output.txt` for an example run showing:
- Brute force detection from a single IP
- Suspicious foreign IP successful logins
- Suspicious endpoint process executions (PowerShell + Mimikatz patterns)
