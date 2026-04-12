"""
External threat intelligence API clients: VirusTotal and AbuseIPDB.

Features:
  - Granular indicator types (ipv4, ipv6, domain, md5, sha1, sha256)
  - Exponential backoff with optional Retry-After for rate limits (429)
  - Normalized scores from real API payloads (not placeholders when HTTP 200)
  - Robust error handling for timeouts and malformed JSON
"""
from __future__ import annotations

import ipaddress
import logging
import re
import time
from typing import Any
from urllib.parse import quote

import requests

from app import config
from app.utils.logger import log_with_extra, setup_logging

logger = setup_logging(__name__)


def _response_preview(resp: requests.Response | None, max_len: int = 500) -> str:
    """Safe snippet for logs (no secrets expected in VT/Abuse bodies)."""
    if resp is None or resp.text is None:
        return ""
    t = resp.text.strip()
    if len(t) > max_len:
        return t[:max_len] + "..."
    return t

# Returned by detect_indicator_type
IndicatorType = str

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSE_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def detect_indicator_type(indicator: str) -> IndicatorType:
    """
    Classify input as ipv4, ipv6, domain, md5, sha1, sha256, or unknown.
    """
    raw = indicator.strip()
    if not raw:
        return "unknown"

    try:
        ip = ipaddress.ip_address(raw)
        return "ipv6" if ip.version == 6 else "ipv4"
    except ValueError:
        pass

    if re.fullmatch(r"[a-fA-F0-9]{32}", raw):
        return "md5"
    if re.fullmatch(r"[a-fA-F0-9]{40}", raw):
        return "sha1"
    if re.fullmatch(r"[a-fA-F0-9]{64}", raw):
        return "sha256"

    if _DOMAIN_RE.match(raw) or (raw.startswith("*.") and _DOMAIN_RE.match(raw[2:])):
        return "domain"

    if re.fullmatch(r"[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?", raw) and "." in raw:
        return "domain"

    return "unknown"


def is_ip_indicator(itype: str) -> bool:
    return itype in ("ipv4", "ipv6")


def vt_route_for_type(itype: str) -> str | None:
    """Map granular type to VirusTotal URL segment category."""
    if is_ip_indicator(itype):
        return "ip"
    if itype == "domain":
        return "domain"
    if itype in ("md5", "sha1", "sha256"):
        return "hash"
    return None


def _sleep_backoff(attempt: int, response: requests.Response | None, service: str) -> None:
    """Wait before retry: Retry-After (429) or capped exponential backoff."""
    delay: float
    if response is not None and response.status_code == 429:
        ra = response.headers.get("Retry-After")
        if ra:
            try:
                delay = min(float(ra), config.API_RETRY_BACKOFF_MAX_SECONDS)
                log_with_extra(
                    logger,
                    logging.WARNING,
                    f"{service} rate limited, honoring Retry-After",
                    retry_after_seconds=delay,
                    attempt=attempt,
                )
                time.sleep(delay)
                return
            except ValueError:
                pass
    delay = min(
        config.API_RETRY_BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)),
        config.API_RETRY_BACKOFF_MAX_SECONDS,
    )
    log_with_extra(
        logger,
        logging.WARNING,
        f"{service} backing off before retry",
        delay_seconds=round(delay, 2),
        attempt=attempt,
    )
    time.sleep(delay)


def _is_transient_status(code: int | None) -> bool:
    if code is None:
        return True
    return code in (408, 429, 500, 502, 503, 504)


def _request_with_retries(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    service: str,
) -> requests.Response | None:
    """HTTP request with exponential backoff and transient error retries."""
    last_exc: Exception | None = None
    last_resp: requests.Response | None = None

    for attempt in range(1, config.API_MAX_RETRIES + 1):
        try:
            resp = requests.request(
                method,
                url,
                headers=headers,
                params=params,
                timeout=config.REQUEST_TIMEOUT_SECONDS,
            )
            last_resp = resp

            if _is_transient_status(resp.status_code) and attempt < config.API_MAX_RETRIES:
                log_with_extra(
                    logger,
                    logging.WARNING,
                    f"{service} transient HTTP {resp.status_code}, will retry",
                    service=service,
                    attempt=attempt,
                    status_code=resp.status_code,
                )
                _sleep_backoff(attempt, resp, service)
                continue
            return resp

        except requests.exceptions.Timeout as e:
            last_exc = e
            log_with_extra(
                logger,
                logging.WARNING,
                f"{service} timeout",
                service=service,
                attempt=attempt,
                error=str(e),
            )
        except requests.exceptions.RequestException as e:
            last_exc = e
            log_with_extra(
                logger,
                logging.WARNING,
                f"{service} request error",
                service=service,
                attempt=attempt,
                error=str(e),
            )

        if attempt < config.API_MAX_RETRIES:
            _sleep_backoff(attempt, None, service)

    if last_exc:
        log_with_extra(
            logger,
            logging.ERROR,
            f"{service} failed after retries",
            service=service,
            error=str(last_exc),
        )
    elif last_resp is not None:
        log_with_extra(
            logger,
            logging.ERROR,
            f"{service} exhausted retries with HTTP {last_resp.status_code}",
            service=service,
            status_code=last_resp.status_code,
        )
    return None


def _vt_parse_stats(body: dict[str, Any]) -> dict[str, Any]:
    """
    Parse VirusTotal v3 entity JSON into scores from last_analysis_stats.

    vt_score: 0–100 from (malicious + 0.5*suspicious) / total_engines
    """
    stats = body.get("data", {}).get("attributes", {}).get("last_analysis_stats")
    if not isinstance(stats, dict):
        return {
            "risk_score": 0.0,
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "undetected_count": 0,
            "timeout_count": 0,
            "total_engines": 0,
        }

    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    timeouts = int(stats.get("timeout", 0) or 0)
    total = malicious + suspicious + harmless + undetected + timeouts

    if total <= 0:
        score = 0.0
    else:
        score = ((malicious * 1.0) + (suspicious * 0.5)) / total * 100.0
        score = min(100.0, max(0.0, score))

    return {
        "risk_score": round(score, 2),
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "harmless_count": harmless,
        "undetected_count": undetected,
        "timeout_count": timeouts,
        "total_engines": total,
    }


def _vt_url_for_indicator(indicator: str, route: str) -> str:
    """Build VT URL with path encoding (domains, IPv6)."""
    if route == "ip":
        enc = quote(indicator, safe=":")
        return f"{VT_BASE}/ip_addresses/{enc}"
    if route == "domain":
        enc = quote(indicator, safe=".")
        return f"{VT_BASE}/domains/{enc}"
    if route == "hash":
        return f"{VT_BASE}/files/{indicator.lower()}"
    raise ValueError(f"invalid route {route}")


def virustotal_lookup(indicator: str, indicator_type: IndicatorType) -> dict[str, Any]:
    """
    Query VirusTotal v3 for IP, domain, or file hash.

    On HTTP 200 with valid data, returns parsed detection-based scores.
    """
    route = vt_route_for_type(indicator_type)
    if route is None:
        return {
            "risk_score": 0.0,
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_engines": 0,
            "error": "unsupported indicator type for VirusTotal",
        }

    if route == "hash":
        indicator = normalize_hash_for_vt(indicator)

    if not config.VIRUSTOTAL_API_KEY:
        reason = "VIRUSTOTAL_API_KEY not configured or empty"
        logger.error("VirusTotal API failed: %s", reason)
        log_with_extra(logger, logging.ERROR, "virustotal_api_failed", reason=reason, indicator=indicator)
        return {
            "risk_score": 0.0,
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_engines": 0,
            "error": reason,
        }

    url = _vt_url_for_indicator(indicator, route)
    headers = {
        "x-apikey": config.VIRUSTOTAL_API_KEY,
        "Accept": "application/json",
    }

    logger.debug(
        "VirusTotal request using key (masked=%s)",
        config.mask_secret(config.VIRUSTOTAL_API_KEY),
    )
    log_with_extra(
        logger,
        logging.INFO,
        "virustotal_request",
        method="GET",
        url=url,
        indicator=indicator,
        indicator_type=indicator_type,
        route=route,
        header_x_apikey_present=True,
    )

    resp = _request_with_retries("GET", url, headers=headers, service="virustotal")
    if resp is None:
        reason = "request failed after retries (network or repeated transient errors)"
        logger.error("VirusTotal API failed: %s", reason)
        log_with_extra(logger, logging.ERROR, "virustotal_api_failed", reason=reason, url=url)
        return {
            "risk_score": 0.0,
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_engines": 0,
            "error": reason,
        }

    log_with_extra(
        logger,
        logging.INFO,
        "virustotal_http_response",
        http_status=resp.status_code,
        body_preview=_response_preview(resp),
    )

    try:
        body = resp.json()
    except ValueError:
        reason = f"invalid JSON response (HTTP {resp.status_code})"
        logger.error("VirusTotal API failed: %s preview=%s", reason, _response_preview(resp, 200))
        log_with_extra(logger, logging.ERROR, "virustotal_api_failed", reason=reason, status=resp.status_code)
        return {
            "risk_score": 0.0,
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_engines": 0,
            "error": reason,
        }

    if resp.status_code == 404:
        logger.info(
            "VirusTotal: no data for indicator (HTTP 404) — scores legitimately zero"
        )
        return {
            "risk_score": 0.0,
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_engines": 0,
            "not_found": True,
            "error": "not found in VirusTotal (no prior submissions)",
        }

    if resp.status_code != 200:
        err_obj = body.get("error", {})
        err = err_obj.get("message", resp.text[:300]) if isinstance(err_obj, dict) else resp.text[:300]
        reason = f"HTTP {resp.status_code}: {err}"
        logger.error("VirusTotal API failed: %s", reason)
        log_with_extra(
            logger,
            logging.ERROR,
            "virustotal_api_failed",
            reason=reason,
            status=resp.status_code,
            body_preview=_response_preview(resp, 400),
        )
        return {
            "risk_score": 0.0,
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_engines": 0,
            "error": reason,
        }

    parsed = _vt_parse_stats(body)
    log_with_extra(
        logger,
        logging.INFO,
        "virustotal_enrichment_parsed",
        indicator=indicator,
        vt_score=parsed["risk_score"],
        malicious=parsed["malicious_count"],
        suspicious=parsed["suspicious_count"],
        total_engines=parsed["total_engines"],
    )
    return {
        "risk_score": parsed["risk_score"],
        "detection_count": parsed["malicious_count"],
        "suspicious_count": parsed["suspicious_count"],
        "total_engines": parsed["total_engines"],
        "malicious_count": parsed["malicious_count"],
        "harmless_count": parsed["harmless_count"],
        "undetected_count": parsed["undetected_count"],
    }


def abuseipdb_lookup(ip: str) -> dict[str, Any]:
    """
    AbuseIPDB v2 /check — returns abuseConfidenceScore (0–100) and report counts.
    """
    if not config.ABUSEIPDB_API_KEY:
        reason = "ABUSEIPDB_API_KEY not configured or empty"
        logger.error("AbuseIPDB API failed: %s", reason)
        log_with_extra(logger, logging.ERROR, "abuseipdb_api_failed", reason=reason, ip=ip)
        return {
            "risk_score": 0.0,
            "reports": 0,
            "error": reason,
        }

    headers = {
        "Key": config.ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90",
        "verbose": "",
    }

    logger.debug(
        "AbuseIPDB request using key (masked=%s)",
        config.mask_secret(config.ABUSEIPDB_API_KEY),
    )
    log_with_extra(
        logger,
        logging.INFO,
        "abuseipdb_request",
        method="GET",
        url=ABUSE_CHECK_URL,
        ip=ip,
        params_keys=list(params.keys()),
        header_Key_present=True,
    )

    resp = _request_with_retries(
        "GET",
        ABUSE_CHECK_URL,
        headers=headers,
        params=params,
        service="abuseipdb",
    )

    if resp is None:
        reason = "request failed after retries (network or repeated transient errors)"
        logger.error("AbuseIPDB API failed: %s", reason)
        log_with_extra(logger, logging.ERROR, "abuseipdb_api_failed", reason=reason, ip=ip)
        return {"risk_score": 0.0, "reports": 0, "error": reason}

    log_with_extra(
        logger,
        logging.INFO,
        "abuseipdb_http_response",
        http_status=resp.status_code,
        body_preview=_response_preview(resp),
    )

    try:
        body = resp.json()
    except ValueError:
        reason = f"invalid JSON response (HTTP {resp.status_code})"
        logger.error("AbuseIPDB API failed: %s preview=%s", reason, _response_preview(resp, 200))
        return {"risk_score": 0.0, "reports": 0, "error": reason}

    if resp.status_code != 200:
        errors = body.get("errors")
        msg = (
            errors[0].get("detail", resp.text[:300])
            if isinstance(errors, list) and errors
            else resp.text[:300]
        )
        reason = f"HTTP {resp.status_code}: {msg}"
        logger.error("AbuseIPDB API failed: %s", reason)
        log_with_extra(
            logger,
            logging.ERROR,
            "abuseipdb_api_failed",
            reason=reason,
            status=resp.status_code,
            body_preview=_response_preview(resp, 400),
        )
        return {
            "risk_score": 0.0,
            "reports": 0,
            "error": reason,
        }

    data = body.get("data", {})
    if not isinstance(data, dict):
        reason = "unexpected response shape (missing data object)"
        logger.error("AbuseIPDB API failed: %s", reason)
        return {"risk_score": 0.0, "reports": 0, "error": reason}

    score = float(data.get("abuseConfidenceScore", 0) or 0)
    reports = int(data.get("totalReports", 0) or 0)
    score = min(100.0, max(0.0, score))

    log_with_extra(
        logger,
        logging.INFO,
        "abuseipdb_enrichment_parsed",
        ip=ip,
        abuse_score=score,
        reports=reports,
    )

    return {
        "risk_score": score,
        "reports": reports,
        "abuse_confidence_score": score,
    }


def normalize_hash_for_vt(indicator: str) -> str:
    return indicator.strip().lower()
