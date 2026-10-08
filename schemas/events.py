"""
Module 4: Event Schema.
Represents an indexed security event extracted by video intelligence (Module 3) and mediated by Backend (Module 2).
"""
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from schemas.identifiers import CameraId, EntityId, EventId, EvidenceId, ZoneId


class Event(BaseModel):
    """
    Authoritative security event model.
    entity_id represents a visual tracking trajectory token, NOT a verified personal identity.
    """
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    event_id: EventId = Field(description="Unique event identifier, e.g. EVT-1029")
    camera_id: CameraId = Field(description="Observing camera identifier, e.g. CAM-03")
    timestamp: str = Field(description="Original observation timestamp preserved as recorded")
    event_type: str = Field(description="Type of observed event, e.g. person_detected, vehicle_entry")
    
    # Optional context & tracking
    entity_id: Optional[EntityId] = Field(
        default=None,
        description="Tracked entity ID across frames/cameras. NOT a personal identity."
    )
    zone_id: Optional[ZoneId] = Field(
        default=None,
        description="Spatial zone where event occurred, e.g. ZONE-04"
    )
    confidence: Optional[float] = Field(
        default=None,
        description="Detection confidence [0.0 - 1.0]. None if unavailable."
    )
    evidence_id: Optional[EvidenceId] = Field(
        default=None,
        description="Associated evidence snapshot/clip ID if already linked"
    )
    source: str = Field(
        default="video_intelligence",
        description="Authoritative source producing this event"
    )
    status: str = Field(
        default="OBSERVED",
        description="Observation status: OBSERVED, UNVERIFIED, CONFLICTED"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional event attributes (bounding boxes, classifications, etc.)"
    )

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: Optional[float]) -> Optional[float]:
        if v is not None:
            if not (0.0 <= v <= 1.0):
                raise ValueError(f"Confidence must be between 0.0 and 1.0, got {v}")
        return v

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Timestamp cannot be empty")
        return v
