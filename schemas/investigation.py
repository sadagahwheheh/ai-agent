"""
Module 4: Investigation Schemas.
Defines InvestigationRequest, TimelineItem, InvestigationResult, and canonical InvestigationStatus.
"""
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from schemas.identifiers import (
    CameraId,
    EntityId,
    EventId,
    EvidenceId,
    IncidentId,
    InvestigationId,
    UserId,
    ZoneId,
)


class InvestigationStatus(str, Enum):
    """Permitted investigation lifecycle statuses per Master Development Prompt."""
    COMPLETED = "COMPLETED"
    PROCESSING = "PROCESSING"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    CONFLICTED_EVIDENCE = "CONFLICTED_EVIDENCE"
    FAILED = "FAILED"


class TimeRange(BaseModel):
    """Temporal search filter specification."""
    model_config = ConfigDict(extra="ignore")

    start: Optional[str] = Field(default=None, description="Start timestamp ISO-8601 or reference string")
    end: Optional[str] = Field(default=None, description="End timestamp ISO-8601 or reference string")


class InvestigationRequest(BaseModel):
    """
    Inbound investigation query request forwarded by Backend gateway.
    Only genuinely available criteria are populated. Never invent filters.
    """
    model_config = ConfigDict(extra="ignore")

    investigation_id: InvestigationId = Field(description="Unique investigation identifier, e.g. INV-2026-001")
    query: str = Field(description="User natural-language query or investigation prompt")
    time_range: Optional[TimeRange] = Field(default=None, description="Optional time bounding filter")
    camera_ids: Optional[List[CameraId]] = Field(default=None, description="Target camera scope")
    zone_ids: Optional[List[ZoneId]] = Field(default=None, description="Target zone scope")
    incident_id: Optional[IncidentId] = Field(default=None, description="Reference incident if investigating alert")
    user_id: Optional[UserId] = Field(default=None, description="Requesting operator ID")

    @field_validator("query")
    @classmethod
    def validate_query(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Query cannot be empty")
        return v.strip()


class TimelineItem(BaseModel):
    """
    Chronological observation item in the incident timeline.
    Preserves exact source timestamp without fabrication.
    """
    model_config = ConfigDict(extra="ignore")

    timestamp: str = Field(description="Exact observation timestamp")
    description: str = Field(description="Description of verified observation or note")
    camera_id: Optional[CameraId] = Field(default=None, description="Camera observing event")
    event_id: Optional[EventId] = Field(default=None, description="Associated event ID")
    evidence_id: Optional[EvidenceId] = Field(default=None, description="Associated evidence ID")
    entity_id: Optional[EntityId] = Field(default=None, description="Tracked entity ID token (not personal identity)")
    is_verified: bool = Field(default=True, description="Whether observation is grounded in verified evidence")
    event_type: Optional[str] = Field(default=None, description="Type of event if observed")
    zone_id: Optional[ZoneId] = Field(default=None, description="Associated spatial zone")
    confidence: Optional[float] = Field(default=None, description="Confidence score if available")
    source: Optional[str] = Field(default=None, description="Source sensor or subsystem")
    verification_status: Optional[str] = Field(default=None, description="Verification state")
    is_gap: bool = Field(default=False, description="Flag indicating an observation blind-spot or unmonitored window")


class InvestigationResult(BaseModel):
    """
    Authoritative investigation outcome returned to Backend.
    Enforces strict distinction between observed facts, inferences, and unknown information.
    """
    model_config = ConfigDict(extra="ignore")

    investigation_id: InvestigationId = Field(description="Unique investigation identifier")
    status: InvestigationStatus = Field(description="Status of investigation")
    answer: str = Field(description="Evidence-grounded narrative summary")
    observed_facts: List[str] = Field(default_factory=list, description="Concrete verified facts only")
    inferences: List[str] = Field(default_factory=list, description="Reasoned deductions based on policy/context")
    timeline: List[TimelineItem] = Field(default_factory=list, description="Chronological event sequence")
    evidence_ids: List[EvidenceId] = Field(default_factory=list, description="Traceable evidence references")
    confidence: Optional[float] = Field(
        default=None,
        description="Calculated investigation confidence [0.0 - 1.0]. None if unavailable."
    )
    unknowns: List[str] = Field(default_factory=list, description="Explicitly unverified or unobservable items")
    limitations: List[str] = Field(default_factory=list, description="Sensor blind-spots or camera downtime limitations")

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: Optional[float]) -> Optional[float]:
        if v is not None:
            if not (0.0 <= v <= 1.0):
                raise ValueError(f"Confidence must be between 0.0 and 1.0, got {v}")
        return v

    @field_validator("answer")
    @classmethod
    def validate_answer(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Answer cannot be empty")
        return v.strip()
