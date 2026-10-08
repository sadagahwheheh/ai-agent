"""
Module 4: Copilot Schemas.
Defines CopilotQueryRequest, CopilotQueryResponse, and CopilotIntentType.
Enforces canonical identifiers and strict fact/inference/unknown triad separation.
"""
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from schemas.identifiers import (
    CameraId,
    EntityId,
    EvidenceId,
    IncidentId,
    InvestigationId,
    UserId,
    ZoneId,
)
from schemas.investigation import TimeRange


class CopilotIntentType(str, Enum):
    """Categorization of operator queries for targeted resolution."""
    INCIDENT_INQUIRY = "INCIDENT_INQUIRY"
    ENTITY_TRACKING = "ENTITY_TRACKING"
    CAMERA_STATUS = "CAMERA_STATUS"
    ZONE_ACTIVITY = "ZONE_ACTIVITY"
    SECURITY_POLICY = "SECURITY_POLICY"
    TIMELINE_INQUIRY = "TIMELINE_INQUIRY"
    GENERAL_INVESTIGATION = "GENERAL_INVESTIGATION"


class CopilotQueryRequest(BaseModel):
    """
    Inbound natural-language operator query forwarded from Backend Security Core.
    """
    model_config = ConfigDict(extra="ignore")

    query: str = Field(description="Natural-language security question or instruction")
    session_id: Optional[str] = Field(default=None, description="Optional conversational session ID")
    investigation_id: Optional[InvestigationId] = Field(default=None, description="Optional associated investigation")
    incident_id: Optional[IncidentId] = Field(default=None, description="Optional associated incident")
    camera_ids: Optional[List[CameraId]] = Field(default=None, description="Scope camera IDs if specified")
    zone_ids: Optional[List[ZoneId]] = Field(default=None, description="Scope zone IDs if specified")
    entity_id: Optional[EntityId] = Field(default=None, description="Tracked entity token if specified")
    time_range: Optional[TimeRange] = Field(default=None, description="Optional temporal bounding window")
    user_id: Optional[UserId] = Field(default=None, description="Operator user ID submitting query")

    @field_validator("query")
    @classmethod
    def validate_query(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Copilot query cannot be empty or whitespace only")
        return v.strip()


class CopilotQueryResponse(BaseModel):
    """
    Structured, evidence-grounded response to security operator query.
    Enforces strict separation between observed facts, inferences, and unknowns.
    """
    model_config = ConfigDict(extra="ignore")

    query: str = Field(description="Original operator query")
    answer: str = Field(description="Evidence-grounded concise answer")
    intent_type: CopilotIntentType = Field(
        default=CopilotIntentType.GENERAL_INVESTIGATION,
        description="Resolved query intent classification"
    )
    observed_facts: List[str] = Field(
        default_factory=list,
        description="Directly verified facts from authoritative events/evidence"
    )
    inferences: List[str] = Field(
        default_factory=list,
        description="Contextual or policy deductions explicitly identified as inferences"
    )
    unknowns: List[str] = Field(
        default_factory=list,
        description="Unverified information, blind-spots, or missing evidence declarations"
    )
    evidence_ids: List[EvidenceId] = Field(
        default_factory=list,
        description="Directly referenced evidence IDs"
    )
    confidence: Optional[float] = Field(
        default=None,
        description="Confidence score [0.0 - 1.0]. None if evidence is insufficient."
    )
    suggested_followups: List[str] = Field(
        default_factory=list,
        description="Proactive follow-up queries or recommended operator actions"
    )
    limitations: List[str] = Field(
        default_factory=list,
        description="Operational limitations such as camera downtime or blind spots"
    )

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
