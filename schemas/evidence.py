"""
Module 4: Evidence Schema.
Represents an evidence artifact (clip reference, image snapshot, sensory record) linked to events and cameras.
"""
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from schemas.identifiers import CameraId, EventId, EvidenceId


class Evidence(BaseModel):
    """
    Authoritative evidence item model.
    Provides verifiable provenance for conclusions and timelines.
    """
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    @model_validator(mode="before")
    @classmethod
    def populate_timestamp_start(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "timestamp_start" not in data and "timestamp" in data:
                data["timestamp_start"] = data["timestamp"]
        return data

    evidence_id: EvidenceId = Field(description="Unique evidence identifier, e.g. EVD-4091")
    camera_id: CameraId = Field(description="Observing camera identifier, e.g. CAM-03")
    timestamp_start: str = Field(description="Observation start timestamp preserved as recorded")
    timestamp_end: Optional[str] = Field(
        default=None,
        description="Observation end timestamp (for video clips/intervals)"
    )
    source_video: Optional[str] = Field(
        default=None,
        description="Storage URI or video stream identifier"
    )
    clip_reference: Optional[str] = Field(
        default=None,
        description="Reference link or key to specific clip / keyframe"
    )
    event_id: Optional[EventId] = Field(
        default=None,
        description="Associated event identifier, e.g. EVT-1029"
    )
    confidence: Optional[float] = Field(
        default=None,
        description="Evidence quality or detection confidence [0.0 - 1.0]. None if unavailable."
    )
    verification_status: str = Field(
        default="UNVERIFIED",
        description="Verification state: VERIFIED, UNVERIFIED, CONFLICTED, FAILED"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional evidence provenance metadata (hash, sensor info, operator notes)"
    )

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: Optional[float]) -> Optional[float]:
        if v is not None:
            if not (0.0 <= v <= 1.0):
                raise ValueError(f"Confidence must be between 0.0 and 1.0, got {v}")
        return v

    @field_validator("timestamp_start")
    @classmethod
    def validate_timestamp_start(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("timestamp_start cannot be empty")
        return v
