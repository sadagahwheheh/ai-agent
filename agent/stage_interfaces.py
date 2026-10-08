"""
Module 4: Investigation Stage Interfaces and Default Handlers.
Defines modular contracts for each stage in the 12-stage investigation pipeline.
Each stage strictly preserves original data and never hallucinates missing information.
"""
from abc import ABC, abstractmethod
from typing import Any, Optional

from agent.context import InvestigationContext, InvestigationState
from integration.backend_client import BackendClient
from schemas.investigation import TimelineItem


class BaseInvestigationStage(ABC):
    """Abstract base class for all investigation pipeline stages."""

    @property
    @abstractmethod
    def stage_name(self) -> str:
        """Name of the stage for telemetry and audit logs."""
        pass

    @abstractmethod
    async def execute(self, context: InvestigationContext, backend_client: Any) -> None:
        """Execute stage logic on the context."""
        pass


# =============================================================================
# STAGE 1: INTENT UNDERSTANDING
# =============================================================================

class IntentUnderstandingStage(BaseInvestigationStage):
    """Parses user query into structured search intent."""

    @property
    def stage_name(self) -> str:
        return "intent_understanding"

    async def execute(self, context: InvestigationContext, backend_client: Any) -> None:
        query_lower = context.request.original_query.lower()
        context.intent = {
            "raw_query": context.request.original_query,
            "target_cameras": context.request.camera_ids or [],
            "target_zones": context.request.zone_ids or [],
            "incident_id": context.request.incident_id,
            "is_temporal": context.request.has_time_filter,
            "keywords": [w for w in ["person", "car", "entry", "breach", "gate", "threat"] if w in query_lower]
        }


# =============================================================================
# STAGE 2: INCIDENT IDENTIFICATION
# =============================================================================

class IncidentIdentificationStage(BaseInvestigationStage):
    """Identifies and loads incident metadata if referenced."""

    @property
    def stage_name(self) -> str:
        return "incident_identification"

    async def execute(self, context: InvestigationContext, backend_client: Any) -> None:
        incident_id = context.request.incident_id
        if incident_id:
            try:
                incident_data = await backend_client.get_incident(incident_id)
                context.incident = incident_data
                context.observed_facts.append(
                    f"Referenced incident {incident_id} identified: {incident_data.get('title', 'Untitled')}"
                )
            except Exception:
                context.unknowns.append(f"Incident {incident_id} details could not be retrieved from Backend.")
        else:
            context.incident = None


# =============================================================================
# STAGE 3: EVENT RETRIEVAL
# =============================================================================

class EventRetrievalStage(BaseInvestigationStage):
    """Queries indexed security events from Backend Security Core using EventRetrievalService."""

    @property
    def stage_name(self) -> str:
        return "event_retrieval"

    async def execute(self, context: InvestigationContext, backend_client: Any) -> None:
        from investigation.event_search import EventRetrievalService, RetrievalStatus

        service = EventRetrievalService(backend_client)
        result = await service.search(
            time_range=context.request.time_range,
            camera_ids=context.request.camera_ids,
            zone_ids=context.request.zone_ids,
            incident_id=context.request.incident_id,
        )

        if result.status == RetrievalStatus.BACKEND_UNAVAILABLE:
            context.mark_failed(f"Backend unavailable: {result.error_message}")
            return
        elif result.status == RetrievalStatus.RETRIEVAL_FAILURE:
            context.mark_failed(f"Failed to retrieve events: {result.error_message}")
            return

        context.events = [e.model_dump() for e in result.events]
        for evt in context.events:
            evt_id = evt.get("event_id")
            cam_id = evt.get("camera_id")
            evt_type = evt.get("event_type")
            ts = evt.get("timestamp")
            context.observed_facts.append(
                f"Observed event {evt_id} ({evt_type}) on camera {cam_id} at {ts}"
            )


# =============================================================================
# STAGE 4: CAMERA RETRIEVAL
# =============================================================================

class CameraRetrievalStage(BaseInvestigationStage):
    """Queries camera metadata and operational health states."""

    @property
    def stage_name(self) -> str:
        return "camera_retrieval"

    async def execute(self, context: InvestigationContext, backend_client: Any) -> None:
        cams_to_fetch = set(context.request.camera_ids or [])
        for evt in context.events:
            if "camera_id" in evt:
                cams_to_fetch.add(evt["camera_id"])

        for cam_id in cams_to_fetch:
            try:
                cam = await backend_client.get_camera(cam_id)
                context.cameras[cam_id] = cam
                status = cam.get("status", "UNKNOWN")
                if status == "OFFLINE":
                    context.limitations.append(
                        f"{cam_id} was OFFLINE during the observation period; activity cannot be reliably determined."
                    )
            except Exception:
                context.cameras[cam_id] = {"camera_id": cam_id, "status": "UNKNOWN"}
                context.limitations.append(f"Camera data unavailable for {cam_id}.")


# =============================================================================
# STAGE 5: ENTITY RETRIEVAL
# =============================================================================

class EntityRetrievalStage(BaseInvestigationStage):
    """Extracts tracked entity tokens across events (NEVER fabricates person identity)."""

    @property
    def stage_name(self) -> str:
        return "entity_retrieval"

    async def execute(self, context: InvestigationContext, backend_client: Any) -> None:
        entities = set()
        for evt in context.events:
            ent = evt.get("entity_id")
            if ent:
                entities.add(ent)
        context.entities = sorted(list(entities))
        if not context.entities and context.events:
            context.unknowns.append("Tracked entity IDs not available for observed events.")


# =============================================================================
# STAGE 6: CROSS-CAMERA CORRELATION
# =============================================================================

class CrossCameraCorrelationStage(BaseInvestigationStage):
    """Correlates tracked entity trajectories across cameras using EntityCorrelationEngine."""

    @property
    def stage_name(self) -> str:
        return "cross_camera_correlation"

    async def execute(self, context: InvestigationContext, backend_client: Any) -> None:
        from investigation.entity_correlation import EntityCorrelationEngine

        result = EntityCorrelationEngine.correlate(
            events=context.events,
            evidence=context.verified_evidence
        )

        for traj in result.trajectories:
            if traj.is_cross_camera:
                context.correlations.append(traj.model_dump())
                context.inferences.append(traj.description)

        for lim in result.limitations:
            if lim not in context.limitations:
                context.limitations.append(lim)

        for conf in result.conflicts:
            if conf not in context.unknowns:
                context.unknowns.append(conf)


# =============================================================================
# STAGE 7: TIMELINE CONSTRUCTION
# =============================================================================

class TimelineConstructionStage(BaseInvestigationStage):
    """Builds chronological timeline preserving exact original timestamps via TimelineEngine."""

    @property
    def stage_name(self) -> str:
        return "timeline_construction"

    async def execute(self, context: InvestigationContext, backend_client: Any) -> None:
        from investigation.timeline import TimelineEngine

        result = TimelineEngine.construct(
            events=context.events,
            evidence=context.verified_evidence,
            time_range=context.request.time_range,
        )
        context.timeline = result.timeline
        for lim in result.temporal_limitations:
            if lim not in context.limitations:
                context.limitations.append(lim)
        for conf in result.conflicting_timestamps:
            if conf not in context.unknowns:
                context.unknowns.append(conf)


# =============================================================================
# STAGE 8: SECURITY CONTEXT
# =============================================================================

class SecurityContextStage(BaseInvestigationStage):
    """Applies security context memory (spatial mappings, zone policies) using PersistentSecurityMemoryService and SecurityContextReasoningEngine."""

    @property
    def stage_name(self) -> str:
        return "security_context"

    async def execute(self, context: InvestigationContext, backend_client: Any) -> None:
        from memory.persistent_memory import PersistentSecurityMemoryService
        from reasoning.context_reasoning import SecurityContextReasoningEngine

        memories = []
        service = PersistentSecurityMemoryService(backend_client)
        try:
            memories = await service.list_all(status="ACTIVE")
            context.security_memories = [m.model_dump() for m in memories]
        except Exception:
            context.limitations.append("Security context unavailable.")

        reasoning_result = SecurityContextReasoningEngine.reason(
            events=context.events,
            evidence=context.verified_evidence,
            memories=memories,
            timeline=context.timeline,
            correlations=context.correlations,
            time_range=context.request.time_range,
            incident=context.incident,
        )

        context.security_contexts = [c.model_dump() for c in reasoning_result.security_contexts]

        for fact in reasoning_result.observed_facts:
            if fact not in context.observed_facts:
                context.observed_facts.append(fact)

        for inf in reasoning_result.inferences:
            if inf not in context.inferences:
                context.inferences.append(inf)

        for unk in reasoning_result.unknowns:
            if unk not in context.unknowns:
                context.unknowns.append(unk)

        for lim in reasoning_result.limitations:
            if lim not in context.limitations:
                context.limitations.append(lim)


# =============================================================================
# STAGE 9: RISK REASONING
# =============================================================================

class RiskReasoningStage(BaseInvestigationStage):
    """Reasons about threat levels using EvidenceGroundedRiskReasoningEngine and Backend threat assessments."""

    @property
    def stage_name(self) -> str:
        return "risk_reasoning"

    async def execute(self, context: InvestigationContext, backend_client: Any) -> None:
        from reasoning.risk_reasoning import EvidenceGroundedRiskReasoningEngine

        backend_threat = None
        if context.incident and "associated_threat_id" in context.incident:
            threat_id = context.incident["associated_threat_id"]
            try:
                backend_threat = await backend_client.get_threat(threat_id)
                context.risk_assessment = backend_threat
            except Exception:
                context.unknowns.append(f"Threat evaluation for {threat_id} unavailable.")

        risk_result = EvidenceGroundedRiskReasoningEngine.reason(
            events=context.events,
            evidence=context.verified_evidence,
            memories=context.security_memories,
            timeline=context.timeline,
            correlations=context.correlations,
            cameras=context.cameras,
            backend_threat=backend_threat,
            time_range=context.request.time_range,
        )

        for inf in risk_result.inferences:
            if inf not in context.inferences:
                context.inferences.append(inf)

        for unk in risk_result.unknowns:
            if unk not in context.unknowns:
                context.unknowns.append(unk)

        for lim in risk_result.limitations:
            if lim not in context.limitations:
                context.limitations.append(lim)


# =============================================================================
# STAGE 10: EVIDENCE VERIFICATION
# =============================================================================

class EvidenceVerificationStage(BaseInvestigationStage):
    """Verifies evidence items, tracks provenance, and evaluates evidence sufficiency."""

    @property
    def stage_name(self) -> str:
        return "evidence_verification"

    async def execute(self, context: InvestigationContext, backend_client: Any) -> None:
        from evidence.retrieval import EvidenceRetrievalService
        from evidence.sufficiency import EvidenceSufficiencyEngine

        event_ids = [e.get("event_id") for e in context.events if e.get("event_id")]
        ev_service = EvidenceRetrievalService(backend_client)
        ev_result = await ev_service.get_for_events(event_ids)

        if ev_result.has_data:
            context.verified_evidence = [item.model_dump() for item in ev_result.evidence_items]
            context.evidence_ids = [item.evidence_id for item in ev_result.evidence_items]
        else:
            context.verified_evidence = []
            context.evidence_ids = []

        # Evaluate sufficiency using the deterministic Evidence Sufficiency Engine
        sufficiency_result = EvidenceSufficiencyEngine.evaluate(
            evidence_items=context.verified_evidence,
            events=context.events,
            cameras=context.cameras
        )

        for limit in sufficiency_result.limitations:
            if limit not in context.limitations:
                context.limitations.append(limit)

        for missing in sufficiency_result.missing_information:
            if missing not in context.unknowns:
                context.unknowns.append(missing)

        if sufficiency_result.is_conflicted:
            context.mark_conflicted_evidence(
                sufficiency_result.limitations[0] if sufficiency_result.limitations else "Conflicting evidence detected."
            )
        elif sufficiency_result.is_insufficient:
            context.mark_insufficient_evidence(
                sufficiency_result.limitations[0] if sufficiency_result.limitations else "I don't know — insufficient evidence."
            )

        # Track evidence provenance
        from evidence.provenance import EvidenceProvenanceEngine

        prov_result = EvidenceProvenanceEngine.track_provenance(
            evidence=context.verified_evidence,
            events=context.events,
            answer=context.answer,
            confidence=context.confidence,
            correlations=context.correlations,
            timeline=context.timeline,
            sufficiency_result=sufficiency_result,
        )
        context.provenance = [item.model_dump() for item in prov_result.items]
        for lim in prov_result.limitations:
            if lim not in context.limitations:
                context.limitations.append(lim)


# =============================================================================
# STAGE 11: CONFIDENCE EVALUATION
# =============================================================================

class ConfidenceEvaluationStage(BaseInvestigationStage):
    """Evaluates investigation confidence from authoritative data using InvestigationConfidenceEngine."""

    @property
    def stage_name(self) -> str:
        return "confidence_evaluation"

    async def execute(self, context: InvestigationContext, backend_client: Any) -> None:
        from reasoning.confidence_evaluation import InvestigationConfidenceEngine

        if context.state in (InvestigationState.INSUFFICIENT_EVIDENCE, InvestigationState.CONFLICTED_EVIDENCE):
            context.confidence = None
            return

        conf_res = InvestigationConfidenceEngine.evaluate(
            events=context.events,
            evidence=context.verified_evidence,
            timeline=context.timeline,
            correlations=context.correlations,
            security_context_result={"has_conflict": any("conflict" in lim.lower() for lim in context.limitations)},
        )

        context.confidence = conf_res.confidence
        for lim in conf_res.limitations:
            if lim not in context.limitations:
                context.limitations.append(lim)
