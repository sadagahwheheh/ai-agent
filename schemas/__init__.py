"""
Module 4: Schemas.
Exports all canonical identifiers, Pydantic contracts, and shared data models.
"""
from schemas.identifiers import (
    CameraId,
    ZoneId,
    EventId,
    IncidentId,
    EvidenceId,
    InvestigationId,
    ThreatId,
    EntityId,
    UserId,
    MemoryId,
    CANONICAL_ID_FIELDS,
)
from schemas.events import Event
from schemas.evidence import Evidence
from schemas.investigation import (
    InvestigationRequest,
    InvestigationResult,
    InvestigationStatus,
    TimelineItem,
    TimeRange,
)
from schemas.memory import SecurityMemory
from schemas.cameras import Camera, CameraHealthState
from schemas.threats import Threat, ThreatSeverity, Incident
from schemas.copilot import (
    CopilotIntentType,
    CopilotQueryRequest,
    CopilotQueryResponse,
)

__all__ = [
    # Canonical Identifiers
    "CameraId",
    "ZoneId",
    "EventId",
    "IncidentId",
    "EvidenceId",
    "InvestigationId",
    "ThreatId",
    "EntityId",
    "UserId",
    "MemoryId",
    "CANONICAL_ID_FIELDS",
    # Event & Evidence
    "Event",
    "Evidence",
    # Investigation
    "InvestigationRequest",
    "InvestigationResult",
    "InvestigationStatus",
    "TimelineItem",
    "TimeRange",
    # Memory
    "SecurityMemory",
    # Cameras & Threats
    "Camera",
    "CameraHealthState",
    "Threat",
    "ThreatSeverity",
    "Incident",
    # Copilot
    "CopilotIntentType",
    "CopilotQueryRequest",
    "CopilotQueryResponse",
]

