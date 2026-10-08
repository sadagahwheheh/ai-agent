"""
Module 4: Investigation Confidence Evaluation Layer.
Calculates investigation confidence deterministically from available authoritative signals:
AI video confidence, tracking confidence, evidence quality, cross-camera consistency,
source reliability, temporal consistency, policy/context certainty, and evidence sufficiency.
Enforces the Anti-Hallucination and Non-Fabrication rules:
- Confidence MUST NEVER be random or fabricated.
- Missing signals remain omitted; if confidence cannot be determined, returns "Confidence unavailable."
- Confidence is strictly separate from risk (HIGH risk != high confidence, LOW risk != low confidence).
"""
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Union
from pydantic import BaseModel, ConfigDict, Field

from evidence.sufficiency import EvidenceSufficiencyEngine, SufficiencyResult, SufficiencyStatus
from investigation.entity_correlation import CorrelationStatus, EntityCorrelationTrajectory
from schemas.events import Event
from schemas.evidence import Evidence
from schemas.investigation import TimelineItem


class ConfidenceStatus(str, Enum):
    """Permitted outcomes of confidence evaluation."""
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    CONFLICTED = "CONFLICTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class ConfidenceResult(BaseModel):
    """
    Structured outcome of deterministic confidence evaluation.
    Preserves all contributing factors and upstream citations without hallucinating values.
    """
    model_config = ConfigDict(extra="ignore", frozen=True)

    confidence: Optional[float] = None
    confidence_status: ConfidenceStatus = ConfidenceStatus.UNAVAILABLE
    contributing_factors: Dict[str, float] = Field(default_factory=dict)
    evidence_ids: List[str] = Field(default_factory=list)
    event_ids: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    message: str = "Confidence unavailable."


class InvestigationConfidenceEngine:
    """
    Deterministic confidence evaluation engine.
    Executes the CONFIDENCE step in the core chain:
      OBSERVATION -> EVENT -> CONTEXT -> POLICY -> RISK -> EVIDENCE -> CONFIDENCE
    """

    @classmethod
    def evaluate(
        cls,
        events: Optional[Sequence[Union[Event, Dict[str, Any]]]] = None,
        evidence: Optional[Sequence[Union[Evidence, Dict[str, Any]]]] = None,
        timeline: Optional[Sequence[Union[TimelineItem, Dict[str, Any]]]] = None,
        timeline_result: Optional[Any] = None,
        correlations: Optional[Sequence[Union[EntityCorrelationTrajectory, Dict[str, Any]]]] = None,
        correlation_result: Optional[Any] = None,
        security_context_result: Optional[Any] = None,
        sufficiency_result: Optional[Union[SufficiencyResult, Dict[str, Any]]] = None,
        source_reliabilities: Optional[Dict[str, float]] = None,
        risk_result: Optional[Any] = None,
    ) -> ConfidenceResult:
        """
        Calculates confidence strictly from authoritative inputs.
        Never fabricates or guesses missing signals.
        """
        events_list = [e if isinstance(e, Event) else Event.model_validate(e) for e in (events or [])]
        evidence_list = [ev if isinstance(ev, Evidence) else Evidence.model_validate(ev) for ev in (evidence or [])]
        timeline_list = list(timeline or [])
        correlation_list = list(correlations or [])

        event_ids = [e.event_id for e in events_list if e.event_id]
        evidence_ids = [ev.evidence_id for ev in evidence_list if ev.evidence_id]

        limitations: List[str] = []
        contributing_factors: Dict[str, float] = {}

        # =====================================================================
        # 1. BASE OBSERVATION CHECK
        # =====================================================================
        if not events_list and not evidence_list:
            limitations.append("Confidence unavailable — no observation events or evidence.")
            return ConfidenceResult(
                confidence=None,
                confidence_status=ConfidenceStatus.INSUFFICIENT_EVIDENCE,
                contributing_factors={},
                evidence_ids=[],
                event_ids=[],
                limitations=limitations,
                message="Confidence unavailable.",
            )

        # =====================================================================
        # 2. EVIDENCE SUFFICIENCY EVALUATION
        # =====================================================================
        if sufficiency_result is not None:
            if isinstance(sufficiency_result, dict):
                suff_status = sufficiency_result.get("status")
                is_conflicted = suff_status == SufficiencyStatus.CONFLICTED or suff_status == "CONFLICTED"
                is_insufficient = suff_status == SufficiencyStatus.INSUFFICIENT or suff_status == "INSUFFICIENT"
            else:
                is_conflicted = sufficiency_result.is_conflicted
                is_insufficient = sufficiency_result.is_insufficient
        else:
            evaluated_suff = EvidenceSufficiencyEngine.evaluate(
                evidence_items=evidence_list,
                events=events_list,
            )
            is_conflicted = evaluated_suff.is_conflicted
            is_insufficient = evaluated_suff.is_insufficient

        if is_conflicted:
            limitations.append("Confidence unavailable — conflicting evidence detected.")
            return ConfidenceResult(
                confidence=None,
                confidence_status=ConfidenceStatus.CONFLICTED,
                contributing_factors={},
                evidence_ids=evidence_ids,
                event_ids=event_ids,
                limitations=limitations,
                message="Confidence unavailable.",
            )

        if is_insufficient:
            limitations.append("Confidence unavailable — insufficient evidence.")
            return ConfidenceResult(
                confidence=None,
                confidence_status=ConfidenceStatus.INSUFFICIENT_EVIDENCE,
                contributing_factors={},
                evidence_ids=evidence_ids,
                event_ids=event_ids,
                limitations=limitations,
                message="Confidence unavailable.",
            )

        # =====================================================================
        # 3. SIGNAL EXTRACTION (ONLY ACTUALLY SUPPLIED SIGNALS)
        # =====================================================================

        # (a) AI Video Confidence (from Event.confidence)
        event_confidences = [e.confidence for e in events_list if e.confidence is not None]
        if event_confidences:
            avg_ai_conf = sum(event_confidences) / len(event_confidences)
            contributing_factors["ai_video_confidence"] = round(avg_ai_conf, 4)

        # (b) Tracking Confidence (from Event.metadata or observation confidence)
        tracking_confs = []
        for e in events_list:
            if isinstance(e.metadata, dict):
                tc = e.metadata.get("tracking_confidence")
                if tc is not None and isinstance(tc, (int, float)):
                    tracking_confs.append(float(tc))
        if tracking_confs:
            avg_track_conf = sum(tracking_confs) / len(tracking_confs)
            contributing_factors["tracking_confidence"] = round(avg_track_conf, 4)

        # (c) Evidence Quality (from Evidence.confidence or Evidence.metadata)
        ev_confidences = []
        for ev in evidence_list:
            if ev.confidence is not None:
                ev_confidences.append(ev.confidence)
            elif isinstance(ev.metadata, dict):
                eq = ev.metadata.get("quality") or ev.metadata.get("evidence_quality")
                if eq is not None and isinstance(eq, (int, float)):
                    ev_confidences.append(float(eq))
        if ev_confidences:
            avg_ev_conf = sum(ev_confidences) / len(ev_confidences)
            contributing_factors["evidence_quality"] = round(avg_ev_conf, 4)

        # (d) Source Reliability (ONLY when explicitly supplied)
        if source_reliabilities:
            valid_src_scores = [
                float(score) for score in source_reliabilities.values()
                if isinstance(score, (int, float)) and 0.0 <= score <= 1.0
            ]
            if valid_src_scores:
                avg_src_rel = sum(valid_src_scores) / len(valid_src_scores)
                contributing_factors["source_reliability"] = round(avg_src_rel, 4)

        # (e) Temporal Consistency (from timeline)
        if timeline_result is not None:
            if hasattr(timeline_result, "conflicting_timestamps") and timeline_result.conflicting_timestamps:
                limitations.append("Confidence unavailable — conflicting timeline timestamps.")
                return ConfidenceResult(
                    confidence=None,
                    confidence_status=ConfidenceStatus.CONFLICTED,
                    contributing_factors={},
                    evidence_ids=evidence_ids,
                    event_ids=event_ids,
                    limitations=limitations,
                    message="Confidence unavailable.",
                )
            if hasattr(timeline_result, "gaps") and timeline_result.gaps:
                contributing_factors["temporal_consistency"] = 0.85
            elif hasattr(timeline_result, "timeline") and timeline_result.timeline:
                contributing_factors["temporal_consistency"] = 1.0
        elif timeline_list:
            contributing_factors["temporal_consistency"] = 1.0

        # (f) Cross-Camera Consistency (from correlations)
        if correlation_result is not None:
            if hasattr(correlation_result, "status"):
                if correlation_result.status == CorrelationStatus.CONFLICTED:
                    limitations.append("Confidence unavailable — conflicting cross-camera tracking.")
                    return ConfidenceResult(
                        confidence=None,
                        confidence_status=ConfidenceStatus.CONFLICTED,
                        contributing_factors={},
                        evidence_ids=evidence_ids,
                        event_ids=event_ids,
                        limitations=limitations,
                        message="Confidence unavailable.",
                    )
            if hasattr(correlation_result, "trajectories") and correlation_result.trajectories:
                contributing_factors["cross_camera_consistency"] = 1.0
        elif correlation_list:
            for corr in correlation_list:
                status = corr.status if isinstance(corr, EntityCorrelationTrajectory) else corr.get("status")
                if status == CorrelationStatus.CONFLICTED or status == "CONFLICTED":
                    limitations.append("Confidence unavailable — conflicting cross-camera tracking.")
                    return ConfidenceResult(
                        confidence=None,
                        confidence_status=ConfidenceStatus.CONFLICTED,
                        contributing_factors={},
                        evidence_ids=evidence_ids,
                        event_ids=event_ids,
                        limitations=limitations,
                        message="Confidence unavailable.",
                    )
            contributing_factors["cross_camera_consistency"] = 1.0

        # (g) Policy / Context Certainty (from security_context_result)
        if security_context_result is not None:
            has_conflict = False
            if isinstance(security_context_result, dict):
                has_conflict = security_context_result.get("has_conflict", False)
            elif hasattr(security_context_result, "has_conflict"):
                has_conflict = security_context_result.has_conflict

            if has_conflict:
                contributing_factors["context_certainty"] = 0.5
            else:
                contributing_factors["context_certainty"] = 1.0

        # =====================================================================
        # 4. DETERMINISTIC CONFIDENCE CALCULATION
        # =====================================================================
        # If no confidence signals were supplied at all
        if not contributing_factors:
            limitations.append("Confidence unavailable — no authoritative confidence signals provided.")
            return ConfidenceResult(
                confidence=None,
                confidence_status=ConfidenceStatus.UNAVAILABLE,
                contributing_factors={},
                evidence_ids=evidence_ids,
                event_ids=event_ids,
                limitations=limitations,
                message="Confidence unavailable.",
            )

        # Deterministic arithmetic mean of all actually supplied signals
        total_score = sum(contributing_factors.values())
        count = len(contributing_factors)
        raw_confidence = total_score / count
        calculated_confidence = round(max(0.0, min(1.0, raw_confidence)), 2)

        return ConfidenceResult(
            confidence=calculated_confidence,
            confidence_status=ConfidenceStatus.AVAILABLE,
            contributing_factors=contributing_factors,
            evidence_ids=evidence_ids,
            event_ids=event_ids,
            limitations=limitations,
            message=f"Confidence calculated as {calculated_confidence:.2f} based on {count} authoritative signal(s).",
        )
