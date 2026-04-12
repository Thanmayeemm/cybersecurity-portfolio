"""SQLAlchemy models for SOC dashboard."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, Enum
from sqlalchemy.ext.declarative import declarative_base
import enum

Base = declarative_base()


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertType(str, enum.Enum):
    FAILED_LOGIN = "failed_login"
    MALWARE_DETECTION = "malware_detection"
    PHISHING = "phishing"
    SUSPICIOUS_IP = "suspicious_ip"
    BRUTE_FORCE = "brute_force"
    DATA_EXFILTRATION = "data_exfiltration"
    RANSOMWARE = "ransomware"
    OTHER = "other"


class Alert(Base):
    """Security alert model."""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    severity = Column(String(20), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    alert_type = Column(String(50), nullable=False, index=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
