#!/usr/bin/env python3
"""Replace 12-digit AWS account IDs and standard IAM ARNs in text/json files."""
from __future__ import annotations

import re
import sys
from pathlib import Path


def redact(content: str) -> str:
    content = re.sub(r"\b\d{12}\b", "<AWS_ACCOUNT_ID>", content)
    content = re.sub(
        r"arn:aws:iam::\d{12}:", r"arn:aws:iam::<AWS_ACCOUNT_ID>:", content
    )
    content = re.sub(
        r"arn:aws:(sts|organizations)::\d{12}:",
        lambda m: f"arn:aws:{m.group(1)}::<AWS_ACCOUNT_ID>:",
        content,
    )
    return content


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: redact_aws_identifiers.py <file.json|txt|html>", file=sys.stderr)
        sys.exit(2)
    path = Path(sys.argv[1])
    raw = path.read_text(encoding="utf-8")
    out = redact(raw)
    if out != raw:
        path.write_text(out, encoding="utf-8")


if __name__ == "__main__":
    main()
