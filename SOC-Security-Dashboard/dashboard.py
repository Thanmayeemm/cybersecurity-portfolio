"""
dashboard.py

Simple SOC dashboard (matplotlib) that visualizes security events from security_logs.csv.

Charts included (as requested):
- Bar chart: failed logins by user
- Pie chart: event type distribution
- Line chart: event frequency over time (per hour)
- Extra bar chart: suspicious IP activity (top source IPs)

How to use:
    python SOC-Security-Dashboard/dashboard.py

Optional:
    python SOC-Security-Dashboard/dashboard.py --save
This saves PNG files instead of opening a window (helpful on headless systems).
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

import matplotlib.pyplot as plt


LOG_FILE = Path(__file__).with_name("security_logs.csv")


@dataclass(frozen=True)
class SecurityEvent:
    timestamp: datetime
    event_type: str
    source_ip: str
    username: str
    status: str


def parse_iso8601_utc(ts: str) -> datetime:
    # Expected format: 2026-03-11T08:00:12Z
    ts = ts.strip()
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)


def read_events(path: Path) -> List[SecurityEvent]:
    events: List[SecurityEvent] = []
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            events.append(
                SecurityEvent(
                    timestamp=parse_iso8601_utc(row["timestamp"]),
                    event_type=(row["event_type"] or "").strip(),
                    source_ip=(row["source_ip"] or "").strip(),
                    username=(row["username"] or "").strip(),
                    status=(row["status"] or "").strip(),
                )
            )
    events.sort(key=lambda e: e.timestamp)
    return events


def hour_bucket(dt: datetime) -> datetime:
    return dt.replace(minute=0, second=0, microsecond=0)


def build_metrics(events: List[SecurityEvent]) -> Dict[str, object]:
    """
    Transform raw logs into the aggregated metrics used by the dashboard.
    """
    event_counts = Counter(e.event_type for e in events)

    failed_by_user = Counter(e.username for e in events if e.event_type == "FAILED_LOGIN")

    suspicious_ip_counts = Counter(e.source_ip for e in events if e.event_type == "SUSPICIOUS_IP")

    # Events per hour (line chart)
    per_hour: Dict[datetime, int] = defaultdict(int)
    for e in events:
        per_hour[hour_bucket(e.timestamp)] += 1
    per_hour_sorted: List[Tuple[datetime, int]] = sorted(per_hour.items(), key=lambda kv: kv[0])

    malware_count = event_counts.get("MALWARE_DETECTED", 0)

    return {
        "event_counts": event_counts,
        "failed_by_user": failed_by_user,
        "suspicious_ip_counts": suspicious_ip_counts,
        "per_hour_sorted": per_hour_sorted,
        "malware_count": malware_count,
        "total_events": len(events),
    }


def plot_dashboard(metrics: Dict[str, object], *, save: bool) -> None:
    event_counts: Counter = metrics["event_counts"]  # type: ignore[assignment]
    failed_by_user: Counter = metrics["failed_by_user"]  # type: ignore[assignment]
    suspicious_ip_counts: Counter = metrics["suspicious_ip_counts"]  # type: ignore[assignment]
    per_hour_sorted: List[Tuple[datetime, int]] = metrics["per_hour_sorted"]  # type: ignore[assignment]

    fig, axes = plt.subplots(2, 2, figsize=(14, 9))
    fig.suptitle("SOC Security Dashboard (Sample Logs)", fontsize=16)

    # 1) Bar chart: failed logins by user
    ax = axes[0][0]
    if failed_by_user:
        users = [u for u, _ in failed_by_user.most_common(8)]
        counts = [failed_by_user[u] for u in users]
        ax.bar(users, counts, color="#d9534f")
        ax.set_title("Failed logins by user")
        ax.set_ylabel("Count")
        ax.tick_params(axis="x", rotation=30)
    else:
        ax.text(0.5, 0.5, "No FAILED_LOGIN events", ha="center", va="center")
        ax.set_axis_off()

    # 2) Pie chart: event type distribution
    ax = axes[0][1]
    labels = list(event_counts.keys())
    sizes = list(event_counts.values())
    ax.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=140)
    ax.set_title("Event type distribution")

    # 3) Line chart: events per hour
    ax = axes[1][0]
    if per_hour_sorted:
        xs = [t for t, _ in per_hour_sorted]
        ys = [c for _, c in per_hour_sorted]
        ax.plot(xs, ys, marker="o", linewidth=2, color="#0275d8")
        ax.set_title("Event frequency over time (per hour)")
        ax.set_xlabel("Hour (UTC)")
        ax.set_ylabel("Events")
        ax.tick_params(axis="x", rotation=30)
    else:
        ax.text(0.5, 0.5, "No events to plot", ha="center", va="center")
        ax.set_axis_off()

    # 4) Bar chart: suspicious IP activity (top)
    ax = axes[1][1]
    if suspicious_ip_counts:
        ips = [ip for ip, _ in suspicious_ip_counts.most_common(6)]
        counts = [suspicious_ip_counts[ip] for ip in ips]
        ax.barh(ips, counts, color="#f0ad4e")
        ax.set_title("Suspicious IP activity (top source IPs)")
        ax.set_xlabel("Count")
    else:
        ax.text(0.5, 0.5, "No SUSPICIOUS_IP events", ha="center", va="center")
        ax.set_axis_off()

    plt.tight_layout(rect=[0, 0.03, 1, 0.95])

    if save:
        out = Path(__file__).with_name("dashboard_charts.png")
        plt.savefig(out, dpi=160)
        print(f"Saved charts to {out}")
    else:
        plt.show()


def main() -> int:
    parser = argparse.ArgumentParser(description="SOC Security Dashboard (matplotlib)")
    parser.add_argument("--save", action="store_true", help="Save charts to PNG instead of showing a window")
    args = parser.parse_args()

    if not LOG_FILE.exists():
        print(f"Missing {LOG_FILE}. Run generate_logs.py first.")
        return 1

    events = read_events(LOG_FILE)
    metrics = build_metrics(events)

    print("=== Dashboard Summary ===")
    print(f"Log source: {LOG_FILE.name}")
    print(f"Total events: {metrics['total_events']}")
    print(f"MALWARE_DETECTED: {metrics['malware_count']}")
    print()

    plot_dashboard(metrics, save=args.save)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

