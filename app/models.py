from pydantic import BaseModel, Field, validator, ConfigDict
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from enum import Enum
from uuid import uuid4
import ipaddress


# ==========================================================
# Alert Models
# ==========================================================

class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertType(str, Enum):
    BRUTE_FORCE = "Brute Force"
    MALWARE = "Malware"
    PHISHING = "Phishing"
    DDOS = "DDoS"
    UNAUTHORIZED_ACCESS = "Unauthorized Access"
    RANSOMWARE = "Ransomware"


class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Alert(BaseModel):
    alert_type: AlertType = Field(..., example="Brute Force")
    source_ip: str = Field(..., example="192.168.1.100")
    severity: SeverityLevel = Field(..., example="high")
    timestamp: datetime = Field(..., example="2026-06-22T10:00:00Z")
    description: Optional[str] = Field(
        default=None,
        example="Multiple failed login attempts detected."
    )
    destination_ip: Optional[str] = Field(
        default=None,
        example="10.0.0.5"
    )
    port: Optional[int] = Field(
        default=None,
        example=22,
        ge=1,
        le=65535
    )

    @validator("source_ip", "destination_ip")
    def validate_ip(cls, value):
        if value is None:
            return value
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise ValueError("Invalid IP address format")
        return value


class NormalizedAlert(BaseModel):
    alert_id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Unique identifier for each alert"
    )
    alert_type: str
    source_ip: str
    severity: str
    timestamp: datetime
    normalized_timestamp: str
    description: Optional[str] = None
    destination_ip: Optional[str] = None
    port: Optional[int] = None
    risk_score: Optional[float] = None
    risk_level: Optional[RiskLevel] = None
    action_taken: Optional[str] = None
    enrichment_data: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)


# ==========================================================
# Case Management Models
# ==========================================================

class CaseStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


class TimelineEvent(BaseModel):
    timestamp: str
    event: str
    detail: str


class Case(BaseModel):
    case_id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Unique case identifier"
    )
    alert_id: str
    alert_type: str
    source_ip: str
    severity: str
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    action_taken: Optional[str] = None
    status: CaseStatus = CaseStatus.OPEN
    assigned_to: Optional[str] = None
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    timeline: List[TimelineEvent] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)