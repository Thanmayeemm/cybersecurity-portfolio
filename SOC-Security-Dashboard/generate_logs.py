"""
generate_logs.py

Beginner-friendly SOC log generator.

What it does:
- Generates a realistic-looking security log CSV with common SOC event types:
  FAILED_LOGIN, SUCCESS_LOGIN, MALWARE_DETECTED, SUSPICIOUS_IP, DATA_TRANSFER
- Writes output to security_logs.csv in the same folder as this script.

Why it matters:
- SOC dashboards and detections need data. This script provides repeatable sample data
  without needing a live SIEM/EDR environment.
"""

from __future__ import annotations

import csv
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List


OUT_FILE = Path(__file__).with_name("security_logs.csv")
SUMMARY_FILE = Path(__file__).with_name("alerts_summary.txt")


EVENT_TYPES = [
    "FAILED_LOGIN",
    "SUCCESS_LOGIN",
    "MALWARE_DETECTED",
    "SUSPICIOUS_IP",
    "DATA_TRANSFER",
]


USERS = [
    "jsmith",
    "apatel",
    "mjohnson",
    "awilson",
    "ngarcia",
    "rbrown",
    "tturner",
    "klee",
    "dchen",
    "sali",
]


INTERNAL_IPS = [
    "10.10.5.23",
    "10.10.9.11",
    "10.10.7.19",
    "10.10.8.44",
    "10.10.6.31",
    "10.10.2.12",
]


# "Foreign / suspicious" IP examples (commonly seen in investigations)
SUSPICIOUS_IPS = [
    "185.225.73.19",
    "102.165.34.19",
    "91.214.124.77",
    "194.58.117.25",
    "45.83.64.10",
]


@dataclass(frozen=True)
class LogEvent:
    timestamp: datetime
    event_type: str
    source_ip: str
    username: str
    status: str


def iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def pick_event_type(rng: random.Random) -> str:
    """
    Choose event types with a realistic distribution.
    Login events are most common; malware is rarer.
    """
    roll = rng.random()
    if roll < 0.45:
        return "SUCCESS_LOGIN"
    if roll < 0.72:
        return "FAILED_LOGIN"
    if roll < 0.86:
        return "DATA_TRANSFER"
    if roll < 0.95:
        return "SUSPICIOUS_IP"
    return "MALWARE_DETECTED"


def build_status(event_type: str, rng: random.Random) -> str:
    """
    Map event_type to a simple status field.
    """
    if event_type == "FAILED_LOGIN":
        return "FAILED"
    if event_type == "SUCCESS_LOGIN":
        return "SUCCESS"
    if event_type == "MALWARE_DETECTED":
        return "DETECTED"
    if event_type == "SUSPICIOUS_IP":
        return "ALERT"
    if event_type == "DATA_TRANSFER":
        # Often "ALLOWED" unless blocked by DLP, etc.
        return "ALLOWED" if rng.random() < 0.85 else "BLOCKED"
    return "INFO"


def generate_events(*, count: int = 120, seed: int = 1337) -> List[LogEvent]:
    """
    Create a time-ordered list of events across the last ~24 hours.
    Includes explicit "attack-like" sequences so dashboards show interesting spikes.
    """
    rng = random.Random(seed)

    start = datetime.now(timezone.utc) - timedelta(hours=24)
    events: List[LogEvent] = []

    # 1) Baseline activity
    for i in range(count - 20):
        ts = start + timedelta(minutes=10 * i) + timedelta(seconds=rng.randint(0, 40))
        et = pick_event_type(rng)

        # Most normal events come from internal ranges
        if et in {"FAILED_LOGIN", "SUCCESS_LOGIN", "DATA_TRANSFER"}:
            ip = rng.choice(INTERNAL_IPS)
        else:
            ip = rng.choice(SUSPICIOUS_IPS)

        user = rng.choice(USERS)
        status = build_status(et, rng)
        events.append(LogEvent(ts, et, ip, user, status))

    # 2) Add a brute force spike (many failed logins from one suspicious IP)
    bf_ip = "185.225.73.19"
    bf_user = "jsmith"
    bf_start = start + timedelta(hours=12, minutes=14)
    for j in range(8):
        ts = bf_start + timedelta(seconds=12 * j)
        events.append(LogEvent(ts, "FAILED_LOGIN", bf_ip, bf_user, "FAILED"))
    events.append(LogEvent(bf_start + timedelta(seconds=120), "SUCCESS_LOGIN", bf_ip, bf_user, "SUCCESS"))

    # 3) Add a malware detection cluster
    mw_start = start + timedelta(hours=18, minutes=5)
    for k in range(3):
        ts = mw_start + timedelta(minutes=2 * k)
        events.append(LogEvent(ts, "MALWARE_DETECTED", "194.58.117.25", rng.choice(USERS), "DETECTED"))

    # Sort by time
    events.sort(key=lambda e: e.timestamp)
    return events


def write_csv(path: Path, events: List[LogEvent]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "event_type", "source_ip", "username", "status"])
        for e in events:
            writer.writerow([iso_utc(e.timestamp), e.event_type, e.source_ip, e.username, e.status])


def write_alerts_summary(path: Path, events: List[LogEvent]) -> None:
    """
    Create a simple text summary (like a SOC daily roll-up).
    """
    # Aggregate counts for common SOC questions
    event_counts: dict[str, int] = {}
    failed_by_user: dict[str, int] = {}
    failed_by_ip: dict[str, int] = {}
    suspicious_ip_events: dict[str, int] = {}
    malware_events: List[LogEvent] = []
    blocked_transfers: List[LogEvent] = []

    for e in events:
        event_counts[e.event_type] = event_counts.get(e.event_type, 0) + 1
        if e.event_type == "FAILED_LOGIN":
            failed_by_user[e.username] = failed_by_user.get(e.username, 0) + 1
            failed_by_ip[e.source_ip] = failed_by_ip.get(e.source_ip, 0) + 1
        if e.event_type == "SUSPICIOUS_IP":
            suspicious_ip_events[e.source_ip] = suspicious_ip_events.get(e.source_ip, 0) + 1
        if e.event_type == "MALWARE_DETECTED":
            malware_events.append(e)
        if e.event_type == "DATA_TRANSFER" and e.status == "BLOCKED":
            blocked_transfers.append(e)

    start = events[0].timestamp if events else datetime.now(timezone.utc)
    end = events[-1].timestamp if events else datetime.now(timezone.utc)

    # Simple threshold: >5 failed logins per IP (overall) to highlight likely brute force sources.
    bf_candidates = sorted(
        [(ip, cnt) for ip, cnt in failed_by_ip.items() if cnt > 5],
        key=lambda kv: (-kv[1], kv[0]),
    )

    top_failed_users = sorted(failed_by_user.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
    top_susp_ips = sorted(suspicious_ip_events.items(), key=lambda kv: (-kv[1], kv[0]))[:5]

    lines: List[str] = []
    lines.append("SOC Alerts Summary (Sample Dataset)")
    lines.append("=================================")
    lines.append(f"Dataset: {OUT_FILE.name}")
    lines.append(f"Time range (UTC): {start:%Y-%m-%d %H:%MZ} to {end:%Y-%m-%d %H:%MZ}")
    lines.append(f"Total events: {len(events)}")
    lines.append("")

    lines.append("Event counts:")
    for k, v in sorted(event_counts.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"- {k}: {v}")
    lines.append("")

    lines.append("High-priority alerts:")
    if bf_candidates:
        lines.append("1) Potential brute force sources (FAILED_LOGIN > 5):")
        for ip, cnt in bf_candidates[:5]:
            lines.append(f"   - {ip}: {cnt} failed logins")
    else:
        lines.append("1) Potential brute force sources: none")

    lines.append("2) Suspicious IP events (top sources):")
    if top_susp_ips:
        for ip, cnt in top_susp_ips:
            lines.append(f"   - {ip}: {cnt} SUSPICIOUS_IP events")
    else:
        lines.append("   - none")

    lines.append("3) Malware detections:")
    if malware_events:
        lines.append(f"   - total: {len(malware_events)}")
        for e in malware_events[:3]:
            lines.append(f"   - {iso_utc(e.timestamp)} user={e.username} src_ip={e.source_ip} status={e.status}")
    else:
        lines.append("   - none")

    lines.append("4) Data transfer blocks:")
    if blocked_transfers:
        lines.append(f"   - blocked transfers: {len(blocked_transfers)}")
        for e in blocked_transfers[:5]:
            lines.append(f"   - {iso_utc(e.timestamp)} user={e.username} src_ip={e.source_ip} status=BLOCKED")
    else:
        lines.append("   - none")

    lines.append("")
    lines.append("Top targeted users (FAILED_LOGIN):")
    if top_failed_users:
        for user, cnt in top_failed_users:
            lines.append(f"- {user}: {cnt} failed logins")
    else:
        lines.append("- none")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    events = generate_events(count=120, seed=1337)
    write_csv(OUT_FILE, events)
    write_alerts_summary(SUMMARY_FILE, events)
    print(f"Wrote {len(events)} events to {OUT_FILE}")
    print(f"Wrote summary to {SUMMARY_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

