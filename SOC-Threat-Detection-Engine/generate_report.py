"""
generate_report.py

SOC automation mini-project:
- Runs multiple simple detectors
- Produces a combined "investigation report" summary on the console

This mimics a SOC workflow where multiple detections/alerts are aggregated
into a single incident view.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List

# Import the detectors as Python modules (keeps everything in one project folder)
import detect_bruteforce
import detect_suspicious_ips
import detect_malware_process


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def main() -> int:
    print("=== SOC Threat Detection Engine - Investigation Report ===")
    print(f"Generated: {utc_now()}")
    print(f"Dataset: {Path(detect_bruteforce.LOG_FILE).name}")
    print()

    # 1) Brute force detector
    auth_events = detect_bruteforce.read_login_csv(detect_bruteforce.LOG_FILE)
    bf = detect_bruteforce.detect_bruteforce(auth_events)

    # 2) Suspicious IP successful login detector
    auth_events2 = detect_suspicious_ips.read_login_csv(detect_suspicious_ips.LOG_FILE)
    sus = detect_suspicious_ips.detect_suspicious_success_logins(auth_events2)

    # 3) Malware process detector (simulated endpoint telemetry)
    endpoint_events = detect_malware_process.build_sample_endpoint_events()
    mp_findings = []
    for e in endpoint_events:
        reasons = detect_malware_process.is_suspicious(e)
        if reasons:
            mp_findings.append((e, reasons))

    # Report summary
    print("## Executive summary")
    summary_lines: List[str] = []
    if bf:
        summary_lines.append(f"- Brute force activity detected: {len(bf)} burst(s)")
    if sus:
        summary_lines.append(f"- Suspicious successful logins from unusual IP ranges: {len(sus)} event(s)")
    if mp_findings:
        summary_lines.append(f"- Suspicious endpoint process execution: {len(mp_findings)} event(s)")
    if not summary_lines:
        summary_lines.append("- No high-confidence detections in the current dataset.")

    for line in summary_lines:
        print(line)

    print("\n## Findings (details)")

    print("\n### 1) Brute force detections")
    if not bf:
        print("None.")
    else:
        for d in bf:
            print(detect_bruteforce.format_detection(d))

    print("\n### 2) Suspicious successful logins")
    if not sus:
        print("None.")
    else:
        for e in sus:
            print(f"- time={e.timestamp:%Y-%m-%d %H:%M:%SZ} user={e.username} src_ip={e.source_ip}")

    print("\n### 3) Suspicious endpoint processes (simulated)")
    if not mp_findings:
        print("None.")
    else:
        for e, reasons in mp_findings:
            print(f"- time={e.timestamp:%Y-%m-%d %H:%M:%SZ} host={e.host} user={e.user} proc={e.process_name}")
            for r in reasons:
                print(f"  - {r}")

    print("\n## Recommended next steps (SOC playbook)")
    print("- Validate suspicious logins with MFA/device context and user verification.")
    print("- Block high-risk IPs and review identity protections (MFA, legacy auth, conditional access).")
    print("- For endpoint findings, isolate affected hosts and collect triage artifacts (process tree, network, file hashes).")
    print("- Add SIEM correlation rules and tune thresholds based on baseline behavior.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

