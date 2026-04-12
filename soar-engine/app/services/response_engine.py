"""
SOAR response layer: simulated IP block, Slack alerts, and SQLite incident logging.

Playbooks:
  malicious  → block_ip (IPv4/IPv6 only) + slack_alert + log_incident
  suspicious → slack_alert + log_incident
  benign     → log_incident only
"""
from __future__ import annotations

import logging
from typing import Any

from app.models import incident as incident_model
from app.utils import api_clients
from app.utils.logger import log_with_extra, setup_logging
from app.utils.slack_alerts import send_slack_alert

logger = setup_logging(__name__)


def block_ip(ip: str, reason: str = "") -> dict[str, Any]:
    """Simulate perimeter block (production: firewall/WAF API)."""
    log_with_extra(
        logger,
        logging.INFO,
        "action_block_ip",
        ip=ip,
        reason=reason,
        simulated=True,
    )
    return {"action": "block_ip", "target": ip, "status": "simulated_ok", "detail": reason}


def log_incident_db(
    indicator: str,
    verdict: str,
    severity: str,
    action_summary: str,
) -> dict[str, Any]:
    """Persist incident to SQLite."""
    row_id = incident_model.insert_incident(
        indicator=indicator,
        verdict=verdict,
        severity=severity,
        action_taken=action_summary,
    )
    log_with_extra(
        logger,
        logging.INFO,
        "action_log_incident",
        incident_id=row_id,
        indicator=indicator,
        verdict=verdict,
    )
    return {"action": "log_incident", "incident_id": row_id, "status": "stored"}


def _slack_extra_context(
    combined_score: float | None,
    vt_score: float | None,
    abuse_score: float | None,
) -> str:
    parts = []
    if combined_score is not None:
        parts.append(f"Combined score: *{combined_score}*")
    if vt_score is not None:
        parts.append(f"VirusTotal score: *{vt_score}*")
    if abuse_score is not None:
        parts.append(f"AbuseIPDB score: *{abuse_score}*")
    return "\n".join(parts) if parts else ""


def run_playbook(
    *,
    indicator: str,
    indicator_type: str,
    verdict: str,
    severity: str,
    confidence_percent: float,
    combined_score: float | None = None,
    vt_score: float | None = None,
    abuse_score: float | None = None,
) -> dict[str, Any]:
    """
    Execute verdict playbook and return steps plus a flat action_list for APIs.
    """
    steps: list[dict[str, Any]] = []
    parts: list[str] = []

    extra_ctx = _slack_extra_context(combined_score, vt_score, abuse_score)

    if verdict == "malicious":
        if api_clients.is_ip_indicator(indicator_type):
            steps.append(
                block_ip(indicator, reason=f"malicious verdict (combined={combined_score})")
            )
            parts.append("block_ip")
        else:
            log_with_extra(
                logger,
                logging.INFO,
                "block_skipped_non_ip",
                indicator=indicator,
                indicator_type=indicator_type,
            )
            steps.append(
                {
                    "action": "block_ip",
                    "status": "skipped",
                    "reason": "only IP indicators are blocked in this simulation",
                }
            )
            parts.append("block_skipped")

        # Slack only for suspicious/malicious (never for benign)
        steps.append(
            send_slack_alert(
                title="SOAR: Malicious indicator",
                indicator=indicator,
                indicator_type=indicator_type,
                verdict=verdict,
                severity=severity,
                confidence_percent=confidence_percent,
                extra_lines=extra_ctx or None,
            )
        )
        parts.append("slack_alert")

        steps.append(
            log_incident_db(
                indicator,
                verdict,
                severity,
                ";".join(parts + ["db_log"]),
            )
        )
        parts.append("db_log")

    elif verdict == "suspicious":
        steps.append(
            send_slack_alert(
                title="SOAR: Suspicious indicator",
                indicator=indicator,
                indicator_type=indicator_type,
                verdict=verdict,
                severity=severity,
                confidence_percent=confidence_percent,
                extra_lines=extra_ctx or None,
            )
        )
        parts.append("slack_alert")
        steps.append(
            log_incident_db(indicator, verdict, severity, "slack_alert;db_log")
        )
        parts.append("db_log")

    else:
        steps.append(log_incident_db(indicator, verdict, severity, "log_only"))
        parts.append("db_log")

    action_list = []
    for s in steps:
        entry: dict[str, Any] = {"action": s.get("action", "unknown")}
        if "status" in s:
            entry["status"] = s["status"]
        if s.get("reason"):
            entry["reason"] = s["reason"]
        if s.get("detail"):
            entry["detail"] = s["detail"]
        if s.get("incident_id") is not None:
            entry["incident_id"] = s["incident_id"]
        if s.get("target"):
            entry["target"] = s["target"]
        if s.get("http_status") is not None:
            entry["http_status"] = s["http_status"]
        action_list.append(entry)

    log_with_extra(
        logger,
        logging.INFO,
        "playbook_complete",
        verdict=verdict,
        indicator=indicator,
        summary=";".join(parts),
        step_count=len(steps),
    )

    return {
        "playbook": verdict,
        "summary": ";".join(parts),
        "steps": steps,
        "action_list": action_list,
    }
