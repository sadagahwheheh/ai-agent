"""
Module 4: Camera Schemas.
Represents camera metadata and authoritative camera health states.
"""
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict, Field

from schemas.identifiers import CameraId, ZoneId


class CameraHealthState(str, Enum):
    """Permitted camera operational states per Master Development Prompt."""
    CONNECTED = "CONNECTED"
    OFFLINE = "OFFLINE"
    DEGRADED = "DEGRADED"
    UNKNOWN = "UNKNOWN"


class Camera(BaseModel):
    """Authoritative camera information returned by Backend Security Core."""
    model_config = ConfigDict(extra="ignore")

    camera_id: CameraId = Field(description="Unique camera identifier, e.g. CAM-03")
    name: str = Field(description="Descriptive camera location name")
    zone_id: Optional[ZoneId] = Field(default=None, description="Assigned zone identifier")
    status: CameraHealthState = Field(
        default=CameraHealthState.CONNECTED,
        description="Health/connectivity status: CONNECTED, OFFLINE, DEGRADED, UNKNOWN"
    )
    coverage_area: Optional[str] = Field(default=None, description="Observed geographical or spatial area")
    fps: Optional[int] = Field(default=None, description="Configured frame rate")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional device metadata")
