"""Pydantic schemas for API."""
from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional


class AlertBase(BaseModel):
    severity: str
    source_ip: str
    alert_type: str
    description: Optional[str] = None


class AlertCreate(AlertBase):
    timestamp: Optional[datetime] = None


class AlertResponse(AlertBase):
    id: int
    timestamp: datetime
    created_at: datetime

    class Config:
        from_attributes = True


class MetricsResponse(BaseModel):
    alerts_by_severity: dict
    failed_logins_count: int
    top_suspicious_ips: list
    malware_count: int
    phishing_count: int
    total_alerts_24h: int
