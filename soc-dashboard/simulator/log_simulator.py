#!/usr/bin/env python3
"""
SOC Log Simulator - Generates fake security alerts and POSTs them to the API.
Run the backend first, then: python log_simulator.py
"""
import random
import time
import argparse
from datetime import datetime, timedelta

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    raise

API_BASE = "http://localhost:8000/api/v1"

SEVERITIES = ["critical", "high", "medium", "low", "info"]

ALERT_TEMPLATES = [
    # Failed logins
    ("failed_login", "high", "Multiple failed login attempts for user {user} from {ip}"),
    ("failed_login", "medium", "Failed SSH login attempt from {ip}"),
    ("failed_login", "critical", "Brute force login attempt detected from {ip}"),
    # Malware
    ("malware_detection", "critical", "Malware detected: {malware} on host {ip}"),
    ("malware_detection", "high", "Suspicious process blocked: {malware}"),
    ("malware_detection", "medium", "Potential malware signature match from {ip}"),
    # Phishing
    ("phishing", "high", "Phishing email detected - malicious link blocked"),
    ("phishing", "medium", "Suspicious email attachment quarantined from {ip}"),
    ("phishing", "critical", "Credential harvesting attempt detected from {ip}"),
    # Suspicious IP
    ("suspicious_ip", "high", "Suspicious outbound connection to known C2 server from {ip}"),
    ("suspicious_ip", "medium", "Unusual port scan activity from {ip}"),
    ("suspicious_ip", "critical", "Traffic to Tor exit node from {ip}"),
    # Brute force
    ("brute_force", "critical", "RDP brute force attack from {ip}"),
    ("brute_force", "high", "Repeated authentication failures from {ip}"),
]

FAKE_IPS = [
    "192.168.1.105", "10.0.0.42", "172.16.0.88", "203.0.113.17", "198.51.100.23",
    "185.220.101.44", "45.33.32.156", "89.248.167.131", "77.91.124.90", "51.68.180.2",
]

FAKE_USERS = ["admin", "svc_backup", "root", "apache", "www-data", "postgres"]

MALWARE_NAMES = ["Emotet", "TrickBot", "Cobalt Strike", "Mimikatz", "Ransomware.WannaCry", "Trojan.Generic"]

def random_ts_within_last_hours(hours=24):
    return (datetime.utcnow() - timedelta(hours=random.uniform(0, hours))).isoformat() + "Z"

def generate_alert():
    alert_type, severity, desc_tpl = random.choice(ALERT_TEMPLATES)
    ip = random.choice(FAKE_IPS)
    desc = desc_tpl.format(
        ip=ip,
        user=random.choice(FAKE_USERS),
        malware=random.choice(MALWARE_NAMES),
    )
    return {
        "severity": severity,
        "source_ip": ip,
        "alert_type": alert_type,
        "description": desc,
        "timestamp": random_ts_within_last_hours(1),
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default=API_BASE, help="API base URL")
    parser.add_argument("--interval", type=float, default=2.0, help="Seconds between alerts")
    parser.add_argument("--count", type=int, default=0, help="Number of alerts to send (0 = infinite)")
    args = parser.parse_args()
    url = f"{args.api.rstrip('/')}/alerts"
    sent = 0
    try:
        while args.count == 0 or sent < args.count:
            payload = generate_alert()
            r = requests.post(url, json=payload, timeout=5)
            if r.status_code in (200, 201):
                sent += 1
                print(f"[{sent}] {payload['severity'].upper()} {payload['alert_type']} from {payload['source_ip']}")
            else:
                print(f"Error {r.status_code}: {r.text}")
            if args.count == 0 or sent < args.count:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\nStopped. Sent {sent} alerts.")
    except requests.exceptions.ConnectionError:
        print("Could not connect to API. Is the backend running on", args.api, "?")

if __name__ == "__main__":
    main()
