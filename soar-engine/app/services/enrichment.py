"""
Merge VirusTotal and AbuseIPDB into a unified enrichment record.

For IP indicators (ipv4/ipv6), combined_score is a weighted average:
  weight_vt * vt_score + weight_abuse * abuse_score (defaults 0.6 / 0.4).

For domain and file hashes, AbuseIPDB is skipped; combined_score equals vt_score.
"""
from __future__ import annotations

import logging
from typing import Any

from app import config
from app.utils import api_clients
from app.utils.logger import log_with_extra, setup_logging

logger = setup_logging(__name__)


def enrich_indicator(indicator: str) -> dict[str, Any]:
    """
    Run TI lookups and return normalized scores and granular indicator_type.
    """
    raw = indicator.strip()
    itype = api_clients.detect_indicator_type(raw)

    if itype == "unknown":
        return {
            "indicator": raw,
            "indicator_type": itype,
            "vt_score": 0.0,
            "abuse_score": None,
            "combined_score": 0.0,
            "weights_applied": None,
            "raw": {"error": "invalid or unsupported indicator format"},
        }

    vt = api_clients.virustotal_lookup(raw, itype)
    vt_score = float(vt.get("risk_score", 0.0) or 0.0)

    abuse_score: float | None = None
    if api_clients.is_ip_indicator(itype):
        ab = api_clients.abuseipdb_lookup(raw)
        abuse_score = float(ab.get("risk_score", 0.0) or 0.0)
        abuse_raw = ab
    else:
        abuse_raw = {"skipped": "AbuseIPDB applies to IPv4/IPv6 only"}

    th = config.load_thresholds()
    wv = float(th.get("weight_vt", 0.6))
    wa = float(th.get("weight_abuse", 0.4))

    if api_clients.is_ip_indicator(itype) and abuse_score is not None:
        combined = wv * vt_score + wa * abuse_score
        weights_applied = {"virus_total": wv, "abuseipdb": wa}
    else:
        combined = vt_score
        weights_applied = {"virus_total": 1.0, "abuseipdb": 0.0, "note": "AbuseIPDB not used for this indicator type"}

    result = {
        "indicator": raw,
        "indicator_type": itype,
        "vt_score": round(vt_score, 2),
        "abuse_score": round(abuse_score, 2) if abuse_score is not None else None,
        "combined_score": round(min(100.0, max(0.0, combined)), 2),
        "weights_applied": weights_applied,
        "raw": {
            "virustotal": vt,
            "abuseipdb": abuse_raw,
        },
    }

    log_with_extra(
        logger,
        logging.INFO,
        "enrichment_complete",
        indicator=raw,
        indicator_type=itype,
        vt_score=result["vt_score"],
        abuse_score=result["abuse_score"],
        combined_score=result["combined_score"],
    )
    return result
