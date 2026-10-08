"""
Module 4: Realtime Investigation Status & Failure Handling (Step 17).
Manages lifecycle telemetry reporting to Backend Security Core (Module 2).
Enforces permitted canonical progress stages and resilient error handling:
  investigation.started
  investigation.searching_events
  investigation.searching_cameras
  investigation.tracking_entity
  investigation.building_timeline
  investigation.verifying_evidence
  investigation.completed
  investigation.insufficient_evidence
  investigation.failed
"""
import logging
from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)


class CanonicalInvestigationStage(str, Enum):
    """Permitted canonical progress stages per Backend Security Core contract."""
    STARTED = "investigation.started"
    SEARCHING_EVENTS = "investigation.searching_events"
    SEARCHING_CAMERAS = "investigation.searching_cameras"
    TRACKING_ENTITY = "investigation.tracking_entity"
    BUILDING_TIMELINE = "investigation.building_timeline"
    VERIFYING_EVIDENCE = "investigation.verifying_evidence"
    COMPLETED = "investigation.completed"
    INSUFFICIENT_EVIDENCE = "investigation.insufficient_evidence"
    FAILED = "investigation.failed"


class FailureCategory(str, Enum):
    """Structured categories for investigation failure handling."""
    VALIDATION_FAILURE = "VALIDATION_FAILURE"
    BACKEND_UNAVAILABLE = "BACKEND_UNAVAILABLE"
    TIMEOUT = "TIMEOUT"
    STAGE_FAILURE = "STAGE_FAILURE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class InvestigationStatusLog(BaseModel):
    """Record of an emitted realtime status event."""
    model_config = ConfigDict(extra="ignore", frozen=True)

    investigation_id: str
    stage: str
    message: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    success: bool = True
    error_detail: Optional[str] = None


class InvestigationStatusReporter:
    """
    Coordinates realtime lifecycle status emission and error isolation.
    Guarantees that telemetry failures never crash the investigation pipeline.
    """

    # Mapping from internal pipeline stage names to canonical Backend stages
    STAGE_MAP: Dict[str, CanonicalInvestigationStage] = {
        "intent_understanding": CanonicalInvestigationStage.STARTED,
        "incident_identification": CanonicalInvestigationStage.SEARCHING_EVENTS,
        "event_retrieval": CanonicalInvestigationStage.SEARCHING_EVENTS,
        "camera_retrieval": CanonicalInvestigationStage.SEARCHING_CAMERAS,
        "entity_retrieval": CanonicalInvestigationStage.TRACKING_ENTITY,
        "cross_camera_correlation": CanonicalInvestigationStage.TRACKING_ENTITY,
        "timeline_construction": CanonicalInvestigationStage.BUILDING_TIMELINE,
        "security_context": CanonicalInvestigationStage.BUILDING_TIMELINE,
        "risk_reasoning": CanonicalInvestigationStage.VERIFYING_EVIDENCE,
        "evidence_verification": CanonicalInvestigationStage.VERIFYING_EVIDENCE,
        "confidence_evaluation": CanonicalInvestigationStage.VERIFYING_EVIDENCE,
    }

    def __init__(self, backend_client: Any):
        self.backend_client = backend_client
        self.history: List[InvestigationStatusLog] = []

    async def report_stage(
        self,
        investigation_id: str,
        internal_stage_name: str,
        message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Translates internal stage to canonical stage and emits telemetry.
        Returns True if successful, False if Backend was unreachable (does not raise).
        """
        canonical_stage = self.STAGE_MAP.get(
            internal_stage_name, CanonicalInvestigationStage.SEARCHING_EVENTS
        )
        msg = message or f"Executing {internal_stage_name.replace('_', ' ')}"
        meta = metadata or {}
        meta["internal_stage"] = internal_stage_name
        meta["canonical_stage"] = canonical_stage.value

        return await self._emit(investigation_id, f"investigation.{internal_stage_name}", msg, meta)



    async def report_started(
        self,
        investigation_id: str,
        message: str = "Investigation pipeline initiated",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Emits investigation.started lifecycle event."""
        return await self._emit(
            investigation_id,
            CanonicalInvestigationStage.STARTED.value,
            message,
            metadata,
        )

    async def report_completed(
        self,
        investigation_id: str,
        message: str = "Investigation completed successfully",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Emits investigation.completed terminal event."""
        return await self._emit(
            investigation_id,
            CanonicalInvestigationStage.COMPLETED.value,
            message,
            metadata,
        )

    async def report_insufficient_evidence(
        self,
        investigation_id: str,
        message: str = "Investigation concluded: insufficient evidence",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Emits investigation.insufficient_evidence terminal event."""
        return await self._emit(
            investigation_id,
            CanonicalInvestigationStage.INSUFFICIENT_EVIDENCE.value,
            message,
            metadata,
        )

    async def report_failed(
        self,
        investigation_id: str,
        error_message: str,
        category: FailureCategory = FailureCategory.STAGE_FAILURE,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Emits investigation.failed terminal event with error classification."""
        meta = metadata or {}
        meta["failure_category"] = category.value
        meta["error_message"] = error_message

        return await self._emit(
            investigation_id,
            CanonicalInvestigationStage.FAILED.value,
            f"Investigation failed: {error_message}",
            meta,
        )

    async def _emit(
        self,
        investigation_id: str,
        stage: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Internal dispatcher with exception containment."""
        meta = metadata or {}
        try:
            if hasattr(self.backend_client, "send_realtime_status"):
                await self.backend_client.send_realtime_status(
                    investigation_id=investigation_id,
                    stage=stage,
                    message=message,
                    metadata=meta,
                )
            self.history.append(
                InvestigationStatusLog(
                    investigation_id=investigation_id,
                    stage=stage,
                    message=message,
                    metadata=meta,
                    success=True,
                )
            )
            return True
        except Exception as exc:
            logger.warning(
                "Telemetry reporting failed for %s (%s): %s",
                investigation_id,
                stage,
                exc,
            )
            self.history.append(
                InvestigationStatusLog(
                    investigation_id=investigation_id,
                    stage=stage,
                    message=message,
                    metadata=meta,
                    success=False,
                    error_detail=str(exc),
                )
            )
            return False
