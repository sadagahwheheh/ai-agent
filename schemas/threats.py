"""
Module 4: Threat and Incident Schemas.
Represents threat assessments and incident records from Backend Security Core.
"""
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from schemas.identifiers import EventId, IncidentId, ThreatId, ZoneId


class ThreatSeverity(str, Enum):
    """Allowed risk/threat levels per Master Development Prompt."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class Threat(BaseModel):
    """Authoritative threat evaluation record."""
    model_config = ConfigDict(extra="ignore")

    threat_id: ThreatId = Field(description="Unique threat identifier, e.g. THR-5501")
    incident_id: Optional[IncidentId] = Field(default=None, description="Linked incident ID")
    severity: ThreatSeverity = Field(description="Threat severity level: HIGH, MEDIUM, LOW, UNKNOWN")
    score: Optional[float] = Field(default=None, description="Numeric severity score [0.0 - 1.0]")
    reason: Optional[str] = Field(default=None, description="Backend threat explanation")
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("score")
    @classmethod
    def validate_score(cls, v: Optional[float]) -> Optional[float]:
        if v is not None and not (0.0 <= v <= 1.0):
            raise ValueError(f"Score must be between 0.0 and 1.0, got {v}")
        return v


class Incident(BaseModel):
    """Correlated security incident record."""
    model_config = ConfigDict(extra="ignore")

    incident_id: IncidentId = Field(description="Unique incident identifier, e.g. INC-8821")
    title: str = Field(description="Incident description or title")
    status: str = Field(default="OPEN", description="Incident status (OPEN, INVESTIGATING, CLOSED)")
    zone_id: Optional[ZoneId] = Field(default=None, description="Originating zone identifier")
    start_time: str = Field(description="Incident initiation timestamp")
    end_time: Optional[str] = Field(default=None, description="Incident closure timestamp")
    associated_events: List[EventId] = Field(default_factory=list, description="Linked event IDs")
    associated_threat_id: Optional[ThreatId] = Field(default=None, description="Linked threat evaluation ID")
