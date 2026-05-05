#!/usr/bin/env python3
"""Summarize Prowler JSON-OCSF export: counts and top failed checks by severity."""
from __future__ import annotations

import json
import sys
from collections import Counter

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def service_name(item: dict) -> str:
    res = item.get("resources") or []
    if res and isinstance(res[0], dict):
        g = res[0].get("group") or {}
        if isinstance(g, dict) and g.get("name"):
            return str(g["name"])
        meta = (res[0].get("data") or {}).get("metadata") or {}
        if meta.get("type"):
            return str(meta["type"])
    return str((item.get("metadata") or {}).get("event_code") or "aws")


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: parse_prowler_ocsf.py <report.ocsf.json>", file=sys.stderr)
        sys.exit(2)
    path = sys.argv[1]
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        print("Expected JSON array of findings", file=sys.stderr)
        sys.exit(1)

    status_counts: Counter[str] = Counter()
    for item in data:
        code = (item.get("status_code") or "").upper()
        if code in ("FAIL", "PASS", "MUTED", "MANUAL"):
            status_counts[code] += 1
        else:
            status_counts["OTHER"] += 1

    total = len(data)
    fails = [i for i in data if (i.get("status_code") or "").upper() == "FAIL"]

    def sort_fail(item: dict) -> tuple[int, str]:
        sev = (item.get("severity") or "informational").lower()
        return (SEVERITY_RANK.get(sev, 99), item.get("message") or "")

    fails_sorted = sorted(fails, key=sort_fail)
    top5 = fails_sorted[:5]

    out = {
        "total_findings": total,
        "pass": status_counts.get("PASS", 0),
        "fail": status_counts.get("FAIL", 0),
        "manual": status_counts.get("MANUAL", 0),
        "muted": status_counts.get("MUTED", 0),
        "warn_note": "Prowler OCSF uses PASS/FAIL/MANUAL/MUTED; no separate WARN count.",
        "top_5_failed": [
            {
                "severity": i.get("severity"),
                "service": service_name(i),
                "check_code": (i.get("metadata") or {}).get("event_code"),
                "description": (i.get("message") or "")[:500],
            }
            for i in top5
        ],
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
