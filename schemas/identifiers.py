"""
Module 4: Canonical Identifiers & Common Types.
Defines canonical identifier names and validation rules.
"""
from typing import Annotated
from pydantic import BeforeValidator, Field


def validate_canonical_id(val: str) -> str:
    """Ensure identifier is a non-empty stripped string."""
    if not isinstance(val, str):
        raise ValueError(f"Identifier must be a string, got {type(val).__name__}")
    cleaned = val.strip()
    if not cleaned:
        raise ValueError("Identifier cannot be empty or whitespace only")
    return cleaned


# Canonical identifier types
CameraId = Annotated[str, BeforeValidator(validate_canonical_id), Field(description="Canonical camera_id, e.g. CAM-03")]
ZoneId = Annotated[str, BeforeValidator(validate_canonical_id), Field(description="Canonical zone_id, e.g. ZONE-04")]
EventId = Annotated[str, BeforeValidator(validate_canonical_id), Field(description="Canonical event_id, e.g. EVT-1029")]
IncidentId = Annotated[str, BeforeValidator(validate_canonical_id), Field(description="Canonical incident_id, e.g. INC-8821")]
EvidenceId = Annotated[str, BeforeValidator(validate_canonical_id), Field(description="Canonical evidence_id, e.g. EVD-4091")]
InvestigationId = Annotated[str, BeforeValidator(validate_canonical_id), Field(description="Canonical investigation_id, e.g. INV-2026-001")]
ThreatId = Annotated[str, BeforeValidator(validate_canonical_id), Field(description="Canonical threat_id, e.g. THR-5501")]
EntityId = Annotated[str, BeforeValidator(validate_canonical_id), Field(description="Canonical entity_id tracking token (NOT real identity), e.g. ENT-902")]
UserId = Annotated[str, BeforeValidator(validate_canonical_id), Field(description="Canonical user_id, e.g. USR-108")]
MemoryId = Annotated[str, BeforeValidator(validate_canonical_id), Field(description="Canonical memory_id, e.g. MEM-301")]

CANONICAL_ID_FIELDS = [
    "camera_id",
    "zone_id",
    "event_id",
    "incident_id",
    "evidence_id",
    "investigation_id",
    "threat_id",
    "entity_id",
    "user_id",
    "memory_id",
]
