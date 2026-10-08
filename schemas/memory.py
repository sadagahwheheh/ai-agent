"""
Module 4: Security Context Memory Schema.
Represents auditable security context memory (camera names, zones, shifts, operating policies).
"""
from typing import Any, Dict, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator

from schemas.identifiers import MemoryId


class SecurityMemory(BaseModel):
    """
    Structured security context memory item.
    Enables spatial/temporal context reasoning without blind faith.
    """
    model_config = ConfigDict(extra="ignore")

    memory_id: MemoryId = Field(description="Unique memory item identifier, e.g. MEM-301")
    type: str = Field(description="Context category, e.g. camera_mapping, zone_policy, shift_schedule")
    value: Union[Dict[str, Any], str] = Field(description="Structured context data or policy rule")
    source: str = Field(description="Auditable source of the memory (e.g. facility_map_v1, security_sop)")
    created_at: str = Field(description="Creation timestamp preserved as recorded")
    updated_at: str = Field(description="Last update timestamp preserved as recorded")
    status: str = Field(
        default="ACTIVE",
        description="Lifecycle status: ACTIVE, ARCHIVED, CONFLICTED, SUPERSEDED"
    )

    @field_validator("type", "source")
    @classmethod
    def validate_non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Field cannot be empty")
        return v.strip()
