"""
Slack Incoming Webhook delivery for SOAR alerts.

Success is HTTP 200 with response body exactly "ok" (Slack Incoming Webhooks spec).
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import requests

from app import config
from app.utils.logger import log_with_extra, setup_logging

logger = setup_logging(__name__)


def mask_webhook_url(url: str) -> str:
    """Mask secret path for logs (never log full webhook URL)."""
    if not url or not url.strip():
        return "(empty)"
    try:
        p = urlparse(url.strip())
        if not p.scheme or not p.netloc:
            return "(invalid URL shape)"
        # Typical: https://hooks.slack.com/services/T000/B000/xxxx
        path = p.path or ""
        parts = [x for x in path.split("/") if x]
        if len(parts) >= 3 and p.netloc.endswith("slack.com"):
            tail = parts[-1]
            shown = tail[:4] + "..." if len(tail) > 4 else "****"
            return f"{p.scheme}://{p.netloc}/.../{shown}"
        return f"{p.scheme}://{p.netloc}{path[:20]}..." if len(path) > 20 else f"{p.scheme}://{p.netloc}{path}"
    except Exception:
        return "(unparseable URL)"


def is_valid_slack_webhook_url(url: str) -> tuple[bool, str]:
    """
    Basic validation for Incoming Webhook URLs.
    Returns (ok, error_message).
    """
    if not url or not url.strip():
        return False, "URL is empty"
    u = url.strip()
    if not u.lower().startswith("https://"):
        return False, "URL must start with https://"
    try:
        p = urlparse(u)
    except Exception as e:
        return False, f"invalid URL: {e}"
    host = (p.netloc or "").lower().split(":")[0]
    if host != "hooks.slack.com":
        return False, f"unexpected host {p.netloc!r} (expected hooks.slack.com)"
    if "/services/" not in (p.path or ""):
        return False, "path must include /services/ (Incoming Webhook URL)"
    return True, ""


def send_slack_alert(
    *,
    title: str,
    indicator: str,
    indicator_type: str,
    verdict: str,
    severity: str,
    confidence_percent: float,
    extra_lines: str | None = None,
) -> dict[str, Any]:
    """
    Post an alert to Slack. Only call for suspicious/malicious verdicts (enforced in playbooks).

    Returns playbook-style dict (status: sent|skipped|failed).
    """
    logger.info(
        "Slack alert triggered | verdict=%s indicator=%s type=%s",
        verdict,
        indicator,
        indicator_type,
    )
    log_with_extra(
        logger,
        logging.INFO,
        "slack_alert_triggered",
        verdict=verdict,
        indicator=indicator,
        indicator_type=indicator_type,
        severity=severity,
        confidence_percent=confidence_percent,
    )

    url = config.SLACK_WEBHOOK_URL
    if not url:
        reason = "SLACK_WEBHOOK_URL not set or empty after loading .env"
        logger.warning("Slack alert failed: %s", reason)
        log_with_extra(logger, logging.WARNING, "slack_alert_failed", reason=reason)
        return {
            "action": "slack_alert",
            "status": "skipped",
            "reason": reason,
        }

    ok_url, url_err = is_valid_slack_webhook_url(url)
    if not ok_url:
        reason = f"invalid webhook URL: {url_err}"
        logger.warning("Slack alert failed: %s | masked=%s", reason, mask_webhook_url(url))
        log_with_extra(
            logger,
            logging.WARNING,
            "slack_alert_failed",
            reason=reason,
            webhook_masked=mask_webhook_url(url),
        )
        return {
            "action": "slack_alert",
            "status": "failed",
            "detail": reason,
        }

    logger.info("Slack webhook target (masked): %s", mask_webhook_url(url))

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        f"*{title}*",
        f"Indicator: `{indicator}`",
        f"Type: {indicator_type}",
        f"Verdict: {verdict}",
        f"Severity: {severity}",
        f"Confidence: {confidence_percent:.1f}%",
        f"Timestamp (UTC): {ts}",
    ]
    if extra_lines:
        lines.append(extra_lines)
    text = "\n".join(lines)

    payload = {"text": text}
    payload_json = json.dumps(payload, ensure_ascii=False)
    # Log payload (safe: no secrets; indicator may be sensitive but user asked for debug)
    log_with_extra(
        logger,
        logging.DEBUG,
        "slack_request_payload",
        payload_keys=list(payload.keys()),
        text_length=len(text),
        text_preview=text[:500] if len(text) <= 500 else text[:500] + "...",
    )
    logger.debug("Slack request JSON payload: %s", payload_json[:2000])

    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": "SOAR-Engine/1.0",
    }

    try:
        resp = requests.post(
            url,
            data=payload_json.encode("utf-8"),
            headers=headers,
            timeout=config.SLACK_WEBHOOK_TIMEOUT_SECONDS,
        )
        body = (resp.text or "").lstrip("\ufeff").strip()
        log_with_extra(
            logger,
            logging.INFO,
            "slack_api_response",
            http_status=resp.status_code,
            response_body=body[:500],
            response_length=len(resp.text or ""),
        )
        logger.info(
            "Slack HTTP response | status=%s body=%r",
            resp.status_code,
            body[:200],
        )

        # Slack Incoming Webhooks: success == HTTP 200 and body exactly "ok" (plain text)
        if resp.status_code == 200 and body == "ok":
            logger.info("Slack alert sent successfully")
            log_with_extra(
                logger,
                logging.INFO,
                "slack_alert_sent_successfully",
                indicator=indicator,
                verdict=verdict,
            )
            return {
                "action": "slack_alert",
                "status": "sent",
                "http_status": resp.status_code,
            }

        reason = f"HTTP {resp.status_code} body={body!r}" if body else f"HTTP {resp.status_code} empty body"
        if resp.status_code == 200 and body != "ok":
            reason = (
                f"HTTP 200 but body is not 'ok' (got {body!r}) — "
                "check payload format or webhook revocation"
            )
        logger.error("Slack alert failed: %s", reason)
        log_with_extra(
            logger,
            logging.ERROR,
            "slack_alert_failed",
            reason=reason,
            http_status=resp.status_code,
            response_body=body[:500],
        )
        return {
            "action": "slack_alert",
            "status": "failed",
            "http_status": resp.status_code,
            "detail": reason,
        }

    except requests.exceptions.Timeout as e:
        reason = f"webhook timeout after {config.SLACK_WEBHOOK_TIMEOUT_SECONDS}s"
        logger.error("Slack alert failed: %s (%s)", reason, e)
        log_with_extra(logger, logging.ERROR, "slack_alert_failed", reason=reason, error=str(e))
        return {"action": "slack_alert", "status": "failed", "detail": reason}

    except requests.exceptions.InvalidURL as e:
        reason = f"invalid URL: {e}"
        logger.error("Slack alert failed: %s", reason)
        return {"action": "slack_alert", "status": "failed", "detail": reason}

    except requests.exceptions.RequestException as e:
        reason = f"network error: {e}"
        logger.error("Slack alert failed: %s", reason)
        log_with_extra(logger, logging.ERROR, "slack_alert_failed", reason=reason, error=str(e))
        return {"action": "slack_alert", "status": "failed", "detail": reason}


def log_slack_env_status() -> None:
    """Log masked Slack webhook configuration at startup (INFO)."""
    url = config.SLACK_WEBHOOK_URL
    if url:
        ok, err = is_valid_slack_webhook_url(url)
        logger.info(
            "Slack integration: URL loaded from env | masked=%s valid=%s %s",
            mask_webhook_url(url),
            ok,
            f"({err})" if not ok else "",
        )
    else:
        logger.info("Slack integration: SLACK_WEBHOOK_URL not set — alerts will be skipped")
