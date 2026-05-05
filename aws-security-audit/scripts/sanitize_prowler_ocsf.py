#!/usr/bin/env python3
"""Write a valid single-array copy of a Prowler OCSF JSON file (handles duplicated appends)."""
from __future__ import annotations

import json
import sys


def first_array(raw: str) -> list:
    raw = raw.strip()
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return data
    except json.JSONDecodeError:
        pass
    if not raw.startswith("["):
        raise ValueError("Expected JSON array")
    depth = 0
    for i, ch in enumerate(raw):
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return json.loads(raw[: i + 1])
    raise ValueError("Unclosed JSON array")


def main() -> None:
    if len(sys.argv) != 3:
        print("Usage: sanitize_prowler_ocsf.py <in.ocsf.json> <out.json>", file=sys.stderr)
        sys.exit(2)
    _, src, dst = sys.argv
    with open(src, encoding="utf-8") as f:
        raw = f.read()
    data = first_array(raw)
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


if __name__ == "__main__":
    main()
