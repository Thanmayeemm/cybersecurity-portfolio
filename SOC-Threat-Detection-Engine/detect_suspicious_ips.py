"""
detect_suspicious_ips.py

Beginner-friendly SOC detector:
- Reads authentication logs from login_logs.csv
- Flags SUCCESS logins coming from "unusual" (simulated foreign) IP ranges

In a real SOC, you'd use:
- GeoIP enrichment (country/ASN)
- Known corporate IP allowlists (VPN egress, office ranges)
- Risk signals (MFA, device posture, impossible travel)
"""

from __future__ import annotations

import csv
import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Sequence


LOG_FILE = Path(__file__).with_name("login_logs.csv")


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    username: str
    source_ip: str
    status: str


def parse_iso8601_utc(ts: str) -> datetime:
    ts = ts.strip()
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)


def read_login_csv(path: Path) -> List[AuthEvent]:
    events: List[AuthEvent] = []
    with path.open("r", encoding="utf-8", newline="") as f:
        raw_lines = [line for line in f if line.strip() and not line.lstrip().startswith("#")]
    reader = csv.DictReader(raw_lines)
    for row in reader:
        events.append(
            AuthEvent(
                timestamp=parse_iso8601_utc(row["timestamp"]),
                username=(row["username"] or "").strip(),
                source_ip=(row["source_ip"] or "").strip(),
                status=(row["status"] or "").strip().upper(),
            )
        )
    events.sort(key=lambda e: e.timestamp)
    return events


# "Expected" corporate ranges (simulated): internal RFC1918 + a pretend VPN egress range (TEST-NET-1).
EXPECTED_RANGES: Sequence[ipaddress._BaseNetwork] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.2.0/24"),  # documentation range used here as "corporate VPN egress"
)

# Simulated high-risk "foreign" ranges seen in campaigns (examples)
SUSPICIOUS_RANGES: Sequence[ipaddress._BaseNetwork] = (
    ipaddress.ip_network("185.0.0.0/8"),
    ipaddress.ip_network("91.0.0.0/8"),
    ipaddress.ip_network("102.0.0.0/8"),
    ipaddress.ip_network("194.0.0.0/8"),
)


def ip_in_any_range(ip: str, ranges: Iterable[ipaddress._BaseNetwork]) -> bool:
    ip_obj = ipaddress.ip_address(ip)
    return any(ip_obj in net for net in ranges)


def detect_suspicious_success_logins(events: Iterable[AuthEvent]) -> List[AuthEvent]:
    """
    Flags SUCCESS events where the source_ip is outside expected ranges,
    and falls within one of the simulated suspicious/foreign ranges.
    """
    findings: List[AuthEvent] = []
    for e in events:
        if e.status != "SUCCESS":
            continue

        try:
            if ip_in_any_range(e.source_ip, EXPECTED_RANGES):
                continue
            if ip_in_any_range(e.source_ip, SUSPICIOUS_RANGES):
                findings.append(e)
        except ValueError:
            # If source_ip is malformed, ignore here (could alert in a real pipeline)
            continue

    return findings


def main() -> int:
    events = read_login_csv(LOG_FILE)
    findings = detect_suspicious_success_logins(events)

    print("=== Suspicious IP Login Detection ===")
    print(f"Log source: {LOG_FILE.name}")
    print("Rule: flag SUCCESS logins from simulated foreign IP ranges (not in expected corporate ranges)\n")

    if not findings:
        print("No suspicious successful logins detected.")
        return 0

    print(f"Findings: {len(findings)}")
    for e in findings:
        print(f"- Suspicious SUCCESS login | time={e.timestamp:%Y-%m-%d %H:%M:%SZ} user={e.username} src_ip={e.source_ip}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

