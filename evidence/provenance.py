"""
Module 4: Evidence Provenance Layer.
Ensures every investigation conclusion is strictly traceable back to authoritative evidence sources:
ANSWER -> REASON -> EVIDENCE ID -> EVENT ID -> CAMERA ID -> TIMESTAMP -> ORIGINAL VIDEO / REFERENCE.
Enforces non-fabrication rules:
- Preserves exact original timestamps without modification or rounding.
- Only uses camera_id supplied by authoritative data; never infers camera identity.
- Only references source_video or clip_reference when actually supplied.
- Never fabricates IDs, paths, timestamps, or confidence.
"""
from typing import Any, Dict, List, Optional, Sequence, Union
from pydantic import BaseModel, ConfigDict, Field

from evidence.sufficiency import SufficiencyResult, SufficiencyStatus
from investigation.entity_correlation import EntityCorrelationTrajectory
from schemas.events import Event
from schemas.evidence import Evidence
from schemas.investigation import TimelineItem



class EvidenceProvenanceItem(BaseModel):
    """
    Traceable provenance link connecting a conclusion/finding to its authoritative evidence root.
    Preserves: ANSWER -> REASON -> EVIDENCE ID -> EVENT ID -> CAMERA ID -> TIMESTAMP -> ORIGINAL VIDEO/REF.
    """
    model_config = ConfigDict(extra="ignore", frozen=True)

    evidence_id: Optional[str] = None
    event_id: Optional[str] = None
    camera_id: Optional[str] = None
    timestamp: Optional[str] = None
    source_video: Optional[str] = None
    clip_reference: Optional[str] = None
    reason: Optional[str] = None
    answer_reference: Optional[str] = None
    confidence: Optional[float] = None
    verification_status: Optional[str] = None
    zone_id: Optional[str] = None
    entity_id: Optional[str] = None
    is_conflicted: bool = False


class ProvenanceTrackingResult(BaseModel):
    """
    Structured outcome of evidence provenance analysis.
    Ensures complete auditable linkage for all investigation conclusions.
    """
    model_config = ConfigDict(extra="ignore", frozen=True)

    items: List[EvidenceProvenanceItem] = Field(default_factory=list)
    answer: Optional[str] = None
    evidence_ids: List[str] = Field(default_factory=list)
    event_ids: List[str] = Field(default_factory=list)
    camera_ids: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    is_sufficient: bool = True
    has_conflict: bool = False


class EvidenceProvenanceEngine:
    """
    Deterministic evidence provenance tracking engine.
    Constructs auditable provenance chains from authoritative investigation signals.
    """

    @classmethod
    def track_provenance(
        cls,
        evidence: Optional[Sequence[Union[Evidence, Dict[str, Any]]]] = None,
        events: Optional[Sequence[Union[Event, Dict[str, Any]]]] = None,
        answer: Optional[str] = None,
        reason: Optional[str] = None,
        confidence: Optional[float] = None,
        confidence_result: Optional[Any] = None,
        correlations: Optional[Sequence[Union[EntityCorrelationTrajectory, Dict[str, Any]]]] = None,
        timeline: Optional[Sequence[Union[TimelineItem, Dict[str, Any]]]] = None,
        sufficiency_result: Optional[Union[SufficiencyResult, Dict[str, Any]]] = None,
    ) -> ProvenanceTrackingResult:
        """
        Builds complete, traceable provenance links connecting conclusions to evidence.
        """
        evidence_list = []
        for ev in (evidence or []):
            if isinstance(ev, Evidence):
                evidence_list.append(ev)
            elif isinstance(ev, dict):
                try:
                    evidence_list.append(Evidence.model_validate(ev))
                except Exception:
                    evidence_list.append(ev)
            else:
                evidence_list.append(ev)

        events_list = [e if isinstance(e, Event) else Event.model_validate(e) for e in (events or [])]
        correlation_list = list(correlations or [])
        timeline_list = list(timeline or [])

        limitations: List[str] = []
        has_conflict = False

        # Extract confidence from Step 13 result if supplied, without recalculating
        resolved_confidence: Optional[float] = confidence
        if resolved_confidence is None and confidence_result is not None:
            if hasattr(confidence_result, "confidence"):
                resolved_confidence = confidence_result.confidence
            elif isinstance(confidence_result, dict):
                resolved_confidence = confidence_result.get("confidence")


        # =====================================================================
        # 1. MISSING EVIDENCE RULE
        # =====================================================================
        if not evidence_list:
            missing_msg = "Evidence provenance unavailable — supporting evidence was not provided."
            limitations.append(missing_msg)
            return ProvenanceTrackingResult(
                items=[],
                answer=answer,
                evidence_ids=[],
                event_ids=[e.event_id for e in events_list if e.event_id],
                camera_ids=list(dict.fromkeys([e.camera_id for e in events_list if e.camera_id])),
                limitations=limitations,
                is_sufficient=False,
                has_conflict=False,
            )

        # =====================================================================
        # 2. INSUFFICIENT / CONFLICTED EVIDENCE EVALUATION
        # =====================================================================
        is_sufficient = True
        if sufficiency_result is not None:
            if isinstance(sufficiency_result, SufficiencyResult):
                if sufficiency_result.is_conflicted:
                    has_conflict = True
                    limitations.append("Conflicting evidence detected in provenance chain.")
                if sufficiency_result.is_insufficient:
                    is_sufficient = False
                    limitations.append("Evidence sufficiency evaluation indicates insufficient evidence.")
            elif isinstance(sufficiency_result, dict):
                stat = sufficiency_result.get("status")
                if stat in (SufficiencyStatus.CONFLICTED, "CONFLICTED"):
                    has_conflict = True
                    limitations.append("Conflicting evidence detected in provenance chain.")
                if stat in (SufficiencyStatus.INSUFFICIENT, "INSUFFICIENT"):
                    is_sufficient = False
                    limitations.append("Evidence sufficiency evaluation indicates insufficient evidence.")

        # Map events by event_id for fast lookup
        events_by_id: Dict[str, Event] = {}
        for evt in events_list:
            if evt.event_id:
                events_by_id[evt.event_id] = evt

        # Map correlation entity tokens
        entity_by_event: Dict[str, str] = {}
        for corr in correlation_list:
            ent = corr.entity_id if isinstance(corr, EntityCorrelationTrajectory) else corr.get("entity_id")
            ev_ids = corr.event_ids if isinstance(corr, EntityCorrelationTrajectory) else corr.get("event_ids", [])
            for eid in ev_ids:
                if ent and eid:
                    entity_by_event[eid] = ent

        provenance_items: List[EvidenceProvenanceItem] = []
        collected_evidence_ids: List[str] = []
        collected_event_ids: List[str] = []
        collected_camera_ids: List[str] = []

        # =====================================================================
        # 3. BUILD PROVENANCE CHAINS PER EVIDENCE ITEM
        # =====================================================================
        for ev in evidence_list:
            ev_dict = ev.model_dump() if isinstance(ev, Evidence) else dict(ev)
            ev_id = str(ev_dict.get("evidence_id", "UNKNOWN_EVIDENCE"))
            collected_evidence_ids.append(ev_id)

            # Match associated event
            ev_linked_event_id = ev_dict.get("event_id")
            matched_event = events_by_id.get(ev_linked_event_id) if ev_linked_event_id else None
            ev_event_id = ev_linked_event_id or (matched_event.event_id if matched_event else None)
            if ev_event_id and ev_event_id not in collected_event_ids:
                collected_event_ids.append(ev_event_id)

            # Camera ID preservation
            raw_cam = ev_dict.get("camera_id")
            ev_camera_id = (str(raw_cam).strip() if raw_cam and str(raw_cam).strip() else None) or (matched_event.camera_id if matched_event else None)
            if not ev_camera_id:
                limitations.append(f"Camera origin unavailable for evidence {ev_id}.")
            elif ev_camera_id not in collected_camera_ids:
                collected_camera_ids.append(ev_camera_id)

            # Timestamp preservation - strictly original, never rounded or guessed
            raw_ts = ev_dict.get("timestamp_start") or ev_dict.get("timestamp")
            ev_timestamp = (str(raw_ts).strip() if raw_ts and str(raw_ts).strip() else None) or (matched_event.timestamp if matched_event else None)
            if not ev_timestamp:
                limitations.append(f"Timestamp unavailable for evidence {ev_id}.")

            # Video/Clip reference preservation - strictly original when actually supplied
            raw_video = ev_dict.get("source_video")
            ev_source_video = str(raw_video).strip() if raw_video and str(raw_video).strip() else None
            raw_clip = ev_dict.get("clip_reference")
            ev_clip_reference = str(raw_clip).strip() if raw_clip and str(raw_clip).strip() else None

            # Reason preservation
            item_reason = reason
            if not item_reason and matched_event:
                item_reason = f"Observation {matched_event.event_type} on camera {ev_camera_id or 'UNKNOWN'} grounded by evidence {ev_id}."
            elif not item_reason:
                item_reason = f"Evidence {ev_id} supports conclusion."

            # Conflict tracking
            is_item_conflicted = ev_dict.get("verification_status") == "CONFLICTED"
            if is_item_conflicted:
                has_conflict = True
                limitations.append(f"Evidence {ev_id} is marked with CONFLICTED verification status.")

            # Entity token preservation without identity fabrication
            ev_entity = None
            if matched_event and matched_event.entity_id:
                ev_entity = matched_event.entity_id
            elif ev_event_id and ev_event_id in entity_by_event:
                ev_entity = entity_by_event[ev_event_id]

            # Zone preservation
            ev_metadata = ev_dict.get("metadata", {}) if isinstance(ev_dict.get("metadata"), dict) else {}
            ev_zone = matched_event.zone_id if matched_event and matched_event.zone_id else ev_metadata.get("zone_id")

            item_conf = resolved_confidence if resolved_confidence is not None else ev_dict.get("confidence")

            item = EvidenceProvenanceItem(
                evidence_id=ev_id,
                event_id=ev_event_id,
                camera_id=ev_camera_id,
                timestamp=ev_timestamp,
                source_video=ev_source_video,
                clip_reference=ev_clip_reference,
                reason=item_reason,
                answer_reference=answer,
                confidence=item_conf,
                verification_status=ev_dict.get("verification_status"),
                zone_id=ev_zone,
                entity_id=ev_entity,
                is_conflicted=is_item_conflicted,
            )
            provenance_items.append(item)

        # Deduplicate limitations while preserving order
        unique_limitations = list(dict.fromkeys(limitations))

        return ProvenanceTrackingResult(
            items=provenance_items,
            answer=answer,
            evidence_ids=collected_evidence_ids,
            event_ids=collected_event_ids,
            camera_ids=collected_camera_ids,
            limitations=unique_limitations,
            is_sufficient=is_sufficient,
            has_conflict=has_conflict,
        )
