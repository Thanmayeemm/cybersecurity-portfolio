"""Metrics REST API for dashboard panels."""
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from ..database import get_db
from ..models import Alert
from ..schemas import MetricsResponse

router = APIRouter(prefix="/metrics", tags=["metrics"])

CUTOFF = timedelta(hours=24)


@router.get("", response_model=MetricsResponse)
def get_metrics(db: Session = Depends(get_db)):
    """Aggregated metrics for dashboard panels (last 24h)."""
    since = datetime.utcnow() - CUTOFF

    # Alerts by severity
    severity_counts = (
        db.query(Alert.severity, func.count(Alert.id))
        .filter(Alert.timestamp >= since)
        .group_by(Alert.severity)
        .all()
    )
    alerts_by_severity = {s: c for s, c in severity_counts}

    # Failed logins
    failed_logins = (
        db.query(func.count(Alert.id))
        .filter(Alert.timestamp >= since, Alert.alert_type == "failed_login")
        .scalar()
        or 0
    )

    # Top suspicious IPs (by alert count)
    top_ips = (
        db.query(Alert.source_ip, func.count(Alert.id).label("count"))
        .filter(Alert.timestamp >= since)
        .group_by(Alert.source_ip)
        .order_by(func.count(Alert.id).desc())
        .limit(10)
        .all()
    )
    top_suspicious_ips = [{"ip": ip, "count": c} for ip, c in top_ips]

    # Malware count
    malware_count = (
        db.query(func.count(Alert.id))
        .filter(Alert.timestamp >= since, Alert.alert_type == "malware_detection")
        .scalar()
        or 0
    )

    # Phishing count
    phishing_count = (
        db.query(func.count(Alert.id))
        .filter(Alert.timestamp >= since, Alert.alert_type == "phishing")
        .scalar()
        or 0
    )

    # Total alerts 24h
    total_alerts_24h = (
        db.query(func.count(Alert.id)).filter(Alert.timestamp >= since).scalar() or 0
    )

    return MetricsResponse(
        alerts_by_severity=alerts_by_severity,
        failed_logins_count=failed_logins,
        top_suspicious_ips=top_suspicious_ips,
        malware_count=malware_count,
        phishing_count=phishing_count,
        total_alerts_24h=total_alerts_24h,
    )
