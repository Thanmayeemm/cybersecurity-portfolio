# SOC Security Dashboard (Python Visualization Project)

This project simulates how SOC teams use dashboards to quickly understand security posture and active threats.

It includes:
- A **log generator** that produces realistic security events (`generate_logs.py`)
- A **dashboard** that visualizes key metrics using matplotlib (`dashboard.py`)
- A sample dataset (`security_logs.csv`) with **100+** log entries
- A human-readable alert rollup (`alerts_summary.txt`)

---

## Project Structure

`SOC-Security-Dashboard/`
- `security_logs.csv`: sample logs (timestamp, event_type, source_ip, username, status)
- `generate_logs.py`: generates fresh sample logs automatically
- `dashboard.py`: visualizes failed logins, suspicious IP activity, malware detections, and event frequency
- `alerts_summary.txt`: summary of notable alerts detected from the logs

---

## How SOC teams use dashboards

Dashboards help analysts:
- Spot spikes (e.g., sudden **FAILED_LOGIN** bursts)
- Identify high-risk trends (e.g., repeated **SUSPICIOUS_IP** events)
- Track endpoint detections (e.g., **MALWARE_DETECTED** counts)
- Monitor activity volume over time (line charts can reveal attack windows)

---

## How to run

From the repository root:

```bash
python SOC-Security-Dashboard/generate_logs.py
python SOC-Security-Dashboard/dashboard.py
```

If you’re running in an environment without a GUI, use:

```bash
python SOC-Security-Dashboard/dashboard.py --save
```

That writes a PNG chart file (`dashboard_charts.png`) in the same folder.

---

## What the charts represent

- **Failed logins by user (bar chart)**: shows which accounts are getting targeted most.
- **Event type distribution (pie chart)**: shows the proportion of each event type in the dataset.
- **Event frequency over time (line chart)**: highlights spikes that may indicate an active incident window.
- **Suspicious IP activity (bar chart)**: shows which source IPs generate the most `SUSPICIOUS_IP` events.

---

## Skills demonstrated

- Security log generation and normalization
- SOC-style metric building and aggregation
- Python automation for security operations
- Basic visualization for SOC reporting
