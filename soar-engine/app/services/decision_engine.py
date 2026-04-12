"""
Rule-based decision engine: map combined TI scores to verdict, severity, confidence.

Thresholds come from config/thresholds.json (malicious_min, suspicious_min).

- Verdict: benign | suspicious | malicious
- Severity: low | medium | high (aligned with verdict tier)
- Confidence: 0–100 (percent), higher when the score sits clearly inside a band
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from app import config
from app.utils.logger import log_with_extra, setup_logging

logger = setup_logging(__name__)


@dataclass
class DecisionResult:
    verdict: str
    severity: str
    confidence_percent: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "severity": self.severity,
            "confidence": round(self.confidence_percent, 1),
            "confidence_percent": round(self.confidence_percent, 1),
        }


class ThreatDecisionEngine:
    """
    Classify threats using configurable score thresholds on a 0–100 combined scale.
    """

    def __init__(self, thresholds: dict[str, Any] | None = None):
        self.thresholds = thresholds or config.load_thresholds()

    def classify(self, combined_score: float) -> DecisionResult:
        malicious_min = float(self.thresholds.get("malicious_min", 70))
        suspicious_min = float(self.thresholds.get("suspicious_min", 40))

        score = max(0.0, min(100.0, float(combined_score)))

        if score >= malicious_min:
            verdict = "malicious"
            severity = "high"
            # Stronger signal as score approaches 100
            span = 100.0 - malicious_min + 1e-6
            confidence_percent = 55.0 + (min(score, 100.0) - malicious_min) / span * 45.0

        elif score >= suspicious_min:
            verdict = "suspicious"
            severity = "medium"
            span = malicious_min - suspicious_min + 1e-6
            confidence_percent = 50.0 + (score - suspicious_min) / span * 40.0

        else:
            verdict = "benign"
            severity = "low"
            span = suspicious_min + 1e-6
            confidence_percent = 55.0 + (1.0 - score / span) * 40.0

        confidence_percent = min(99.5, max(35.0, confidence_percent))

        result = DecisionResult(
            verdict=verdict,
            severity=severity,
            confidence_percent=confidence_percent,
        )
        log_with_extra(
            logger,
            logging.INFO,
            "decision_engine_verdict",
            combined_score=score,
            verdict=verdict,
            severity=severity,
            confidence_percent=result.confidence_percent,
            malicious_min=malicious_min,
            suspicious_min=suspicious_min,
        )
        return result
