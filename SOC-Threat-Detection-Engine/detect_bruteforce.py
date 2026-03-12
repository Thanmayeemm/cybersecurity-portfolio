"""
detect_bruteforce.py

Beginner-friendly SOC detector:
- Reads authentication logs from login_logs.csv
- Detects brute force attempts as:
    "more than 5 FAILED logins from the same source IP within a short time window"

This is a simplified example of what a SIEM correlation search would do.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


LOG_FILE = Path(__file__).with_name("login_logs.csv")


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    username: str
    source_ip: str
    status: str  # "SUCCESS" or "FAILED"


def parse_iso8601_utc(ts: str) -> datetime:
    """
    Parse timestamps like: 2026-03-11T09:14:01Z
    """
    ts = ts.strip()
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)


def read_login_csv(path: Path) -> List[AuthEvent]:
    """
    Reads login_logs.csv and returns normalized AuthEvent records.

    Note: This parser ignores blank lines and comment lines starting with '#'.
    """
    events: List[AuthEvent] = []

    with path.open("r", encoding="utf-8", newline="") as f:
        # Skip comment/blank lines before the CSV header (if any)
        raw_lines = [line for line in f if line.strip() and not line.lstrip().startswith("#")]

    reader = csv.DictReader(raw_lines)
    for row in reader:
        if not row:
            continue
        events.append(
            AuthEvent(
                timestamp=parse_iso8601_utc(row["timestamp"]),
                username=(row["username"] or "").strip(),
                source_ip=(row["source_ip"] or "").strip(),
                status=(row["status"] or "").strip().upper(),
            )
        )

    # Sort by time to make time-window logic easier
    events.sort(key=lambda e: e.timestamp)
    return events


def detect_bruteforce(
    events: Iterable[AuthEvent],
    *,
    window: timedelta = timedelta(minutes=5),
    failed_threshold: int = 5,
) -> List[Dict[str, object]]:
    """
    Returns a list of detections.

    Detection rule:
    - For each source IP, count FAILED events in a rolling time window.
    - Trigger when FAILED count is > failed_threshold within the window.

    We also include the most common usernames targeted in that window.
    """
    # Collect events per IP
    events_by_ip: Dict[str, List[AuthEvent]] = {}
    for e in events:
        events_by_ip.setdefault(e.source_ip, []).append(e)

    detections: List[Dict[str, object]] = []

    for ip, ip_events in events_by_ip.items():
        # Sliding window pointers
        start = 0
        failed_count = 0

        # Track FAILED status in the current window using a simple queue-like approach
        # We will recompute failed_count per window for clarity (still fine for small datasets)
        for end in range(len(ip_events)):
            # Move the start pointer until we're within the window
            while ip_events[end].timestamp - ip_events[start].timestamp > window:
                start += 1

            window_slice = ip_events[start : end + 1]
            failed_in_window = [x for x in window_slice if x.status == "FAILED"]
            failed_count = len(failed_in_window)

            if failed_count > failed_threshold:
                # Summarize usernames targeted
                user_counts: Dict[str, int] = {}
                for x in failed_in_window:
                    user_counts[x.username] = user_counts.get(x.username, 0) + 1

                top_users = sorted(user_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
                detections.append(
                    {
                        "source_ip": ip,
                        "window_start": window_slice[0].timestamp,
                        "window_end": window_slice[-1].timestamp,
                        "failed_count": failed_count,
                        "targeted_users": top_users,
                    }
                )
                # Avoid spamming duplicate detections for the same burst:
                # Jump the start forward a bit once we have a detection.
                start = end

    return detections


def format_detection(d: Dict[str, object]) -> str:
    ws = d["window_start"].strftime("%Y-%m-%d %H:%M:%SZ")
    we = d["window_end"].strftime("%Y-%m-%d %H:%M:%SZ")
    users = ", ".join([f"{u}({c})" for u, c in d["targeted_users"]]) or "n/a"
    return (
        f"- BRUTEFORCE suspected from {d['source_ip']} | "
        f"FAILED={d['failed_count']} in window {ws} → {we} | targeted_users={users}"
    )


def main() -> int:
    events = read_login_csv(LOG_FILE)
    detections = detect_bruteforce(events, window=timedelta(minutes=5), failed_threshold=5)

    print("=== Brute Force Detection ===")
    print(f"Log source: {LOG_FILE.name}")
    print(f"Rule: FAILED > 5 from same IP within 5 minutes\n")

    if not detections:
        print("No brute force patterns detected.")
        return 0

    print(f"Detections: {len(detections)}")
    for d in detections:
        print(format_detection(d))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

