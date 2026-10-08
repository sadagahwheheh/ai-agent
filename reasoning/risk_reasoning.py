"""
Module 4: Evidence-Grounded Risk Reasoning Engine.
Synthesizes authoritative events, evidence, timeline, security context, and explicit policy
to determine evidence-grounded risk levels (HIGH, MEDIUM, LOW, UNKNOWN).
Enforces the Backend Authority Rule: Backend threat assessments remain authoritative.
Strictly separates OBSERVED FACTS, CONTEXT, POLICY, INFERENCES, and UNKNOWNS.
Never invents risk levels, policies, identities, or unobserved events.
"""
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Union
from pydantic import BaseModel, ConfigDict, Field

from evidence.sufficiency import EvidenceSufficiencyEngine, SufficiencyStatus
from investigation.entity_correlation import EntityCorrelationTrajectory
from investigation.timeline import parse_timestamp_safe
from reasoning.context_reasoning import SecurityContextItem, SecurityContextReasoningResult
from schemas.events import Event
from schemas.evidence import Evidence
from schemas.investigation import TimelineItem
from schemas.memory import SecurityMemory
from schemas.threats import Threat, ThreatSeverity


class ReasoningStatus(str, Enum):
    """Permitted outcomes of risk reasoning."""
    DETERMINED = "DETERMINED"
    UNKNOWN = "UNKNOWN"
    CONFLICTED = "CONFLICTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class RiskReasoningResult(BaseModel):
    """
    Structured outcome of evidence-grounded risk reasoning.
    Strictly separates observed facts, context, policy, inferences, and unknowns.
    """
    model_config = ConfigDict(extra="ignore", frozen=True)

    risk_level: ThreatSeverity = ThreatSeverity.UNKNOWN
    risk_reason: str
    observed_facts: List[str] = Field(default_factory=list)
    context: List[str] = Field(default_factory=list)
    policy_context: List[str] = Field(default_factory=list)
    inferences: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    event_ids: List[str] = Field(default_factory=list)
    unknowns: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    backend_severity: Optional[ThreatSeverity] = None
    reasoning_status: ReasoningStatus = ReasoningStatus.UNKNOWN


class EvidenceGroundedRiskReasoningEngine:
    """
    Deterministic risk reasoning engine.
    Executes the RISK step in the core chain:
      OBSERVATION -> EVENT -> CONTEXT -> POLICY -> RISK -> EVIDENCE -> CONFIDENCE
    """

    # Authoritative breach indicators
    HIGH_RISK_KEYWORDS = {
        "perimeter_breach",
        "forced_entry",
        "weapon",
        "lockdown_breach",
        "intrusion",
        "breach",
        "unauthorized_entry",
    }

    # Operational anomaly indicators
    MEDIUM_RISK_KEYWORDS = {
        "after_hours",
        "loitering",
        "tailgating",
        "unescorted",
        "dwell_anomaly",
        "suspicious_movement",
    }

    # Routine / authorized activity indicators
    LOW_RISK_KEYWORDS = {
        "authorized",
        "badge_verified",
        "routine",
        "patrol",
        "scheduled",
    }

    @classmethod
    def reason(
        cls,
        events: Optional[Sequence[Union[Event, Dict[str, Any]]]] = None,
        evidence: Optional[Sequence[Union[Evidence, Dict[str, Any]]]] = None,
        security_context_result: Optional[Union[SecurityContextReasoningResult, Dict[str, Any]]] = None,
        memories: Optional[Sequence[Union[SecurityMemory, Dict[str, Any]]]] = None,
        timeline: Optional[Sequence[Union[TimelineItem, Dict[str, Any]]]] = None,
        correlations: Optional[Sequence[Union[EntityCorrelationTrajectory, Dict[str, Any]]]] = None,
        cameras: Optional[Dict[str, Dict[str, Any]]] = None,
        backend_threat: Optional[Union[Threat, Dict[str, Any]]] = None,
        time_range: Optional[Dict[str, Any]] = None,
        supplied_policies: Optional[Sequence[Dict[str, Any]]] = None,
    ) -> RiskReasoningResult:
        """
        Determines evidence-grounded risk level based strictly on available facts and context.
        """
        events_list = [e if isinstance(e, Event) else Event.model_validate(e) for e in (events or [])]
        evidence_list = [ev if isinstance(ev, Evidence) else Evidence.model_validate(ev) for ev in (evidence or [])]
        memories_list = [m if isinstance(m, SecurityMemory) else SecurityMemory.model_validate(m) for m in (memories or [])]
        correlation_list = list(correlations or [])
        timeline_list = list(timeline or [])
        cameras_map = dict(cameras or {})

        event_ids = [e.event_id for e in events_list]
        evidence_ids = [ev.evidence_id for ev in evidence_list]

        observed_facts: List[str] = []
        context_items: List[str] = []
        policy_items: List[str] = []
        inferences: List[str] = []
        unknowns: List[str] = []
        limitations: List[str] = []

        # Parse backend threat if supplied
        parsed_backend_severity: Optional[ThreatSeverity] = None
        backend_threat_id: Optional[str] = None
        if backend_threat:
            if isinstance(backend_threat, Threat):
                parsed_backend_severity = backend_threat.severity
                backend_threat_id = backend_threat.threat_id
            elif isinstance(backend_threat, dict):
                sev_raw = backend_threat.get("severity")
                if sev_raw:
                    try:
                        parsed_backend_severity = ThreatSeverity(str(sev_raw).upper())
                    except ValueError:
                        parsed_backend_severity = ThreatSeverity.UNKNOWN
                backend_threat_id = backend_threat.get("threat_id")

        # =====================================================================
        # 1. OBSERVED FACTS EXTRACTION (Directly from events/evidence)
        # =====================================================================
        for evt in events_list:
            fact_str = f"Event {evt.event_id} ({evt.event_type}) observed on camera {evt.camera_id} at {evt.timestamp}"
            if evt.zone_id:
                fact_str += f" in zone {evt.zone_id}"
            if evt.entity_id:
                fact_str += f" with tracked entity token {evt.entity_id}"
            observed_facts.append(fact_str)

        for ev in evidence_list:
            if ev.verification_status == "VERIFIED":
                fact_str = f"Evidence {ev.evidence_id} verified from camera {ev.camera_id} at {ev.timestamp_start}"
                observed_facts.append(fact_str)

        # =====================================================================
        # 2. CAMERA / BLIND-SPOT RULE
        # =====================================================================
        # If any observing camera is OFFLINE, area was not reliably observable
        offline_cams = set()
        for cid, cdata in cameras_map.items():
            if isinstance(cdata, dict) and cdata.get("status") == "OFFLINE":
                offline_cams.add(cid)

        # Check if events/evidence occurred on an offline camera or cameras list has offline
        cams_in_events = {e.camera_id for e in events_list} | {ev.camera_id for ev in evidence_list}
        observed_on_offline = cams_in_events.intersection(offline_cams)

        if offline_cams and (observed_on_offline or not events_list):
            blind_spot_msg = "I don't know — the area was not reliably observable during that period."
            limitations.append(blind_spot_msg)
            for off_cam in sorted(offline_cams):
                unknowns.append(f"Camera {off_cam} was OFFLINE; activity during this interval unmonitored.")

            return RiskReasoningResult(
                risk_level=ThreatSeverity.UNKNOWN,
                risk_reason=blind_spot_msg,
                observed_facts=observed_facts,
                context=context_items,
                policy_context=policy_items,
                inferences=[],
                evidence_ids=evidence_ids,
                event_ids=event_ids,
                unknowns=unknowns,
                limitations=limitations,
                backend_severity=parsed_backend_severity,
                reasoning_status=ReasoningStatus.INSUFFICIENT_EVIDENCE,
            )

        # =====================================================================
        # 3. BASE EVIDENCE AVAILABILITY (Fail-safe check)
        # =====================================================================
        if not events_list and not evidence_list:
            insufficient_msg = "I don't know — insufficient evidence."
            return RiskReasoningResult(
                risk_level=ThreatSeverity.UNKNOWN,
                risk_reason=insufficient_msg,
                observed_facts=[],
                context=[],
                policy_context=[],
                inferences=[],
                evidence_ids=[],
                event_ids=[],
                unknowns=["Required observation events and evidence are unavailable."],
                limitations=[insufficient_msg],
                backend_severity=parsed_backend_severity,
                reasoning_status=ReasoningStatus.INSUFFICIENT_EVIDENCE,
            )

        # =====================================================================
        # 4. EVIDENCE SUFFICIENCY ENGINE INTEGRATION
        # =====================================================================
        sufficiency = EvidenceSufficiencyEngine.evaluate(
            evidence_items=evidence_list,
            events=events_list,
            cameras=cameras_map,
        )

        if sufficiency.is_conflicted:
            conflict_msg = "Conflicting evidence detected."
            limitations.append(conflict_msg)
            limitations.extend(sufficiency.limitations)
            unknowns.extend(sufficiency.contradictions)
            return RiskReasoningResult(
                risk_level=ThreatSeverity.UNKNOWN,
                risk_reason=conflict_msg,
                observed_facts=observed_facts,
                context=context_items,
                policy_context=policy_items,
                inferences=[],
                evidence_ids=evidence_ids,
                event_ids=event_ids,
                unknowns=unknowns or ["Contradictory evidence prevents reliable risk evaluation."],
                limitations=limitations,
                backend_severity=parsed_backend_severity,
                reasoning_status=ReasoningStatus.CONFLICTED,
            )

        verified_evidence_items = [ev for ev in evidence_list if ev.verification_status == "VERIFIED"]

        # An event without verified evidence cannot determine risk
        if sufficiency.is_insufficient or not verified_evidence_items:
            insufficient_msg = "I don't know — insufficient evidence."
            limitations.append(insufficient_msg)
            limitations.extend(sufficiency.limitations)
            unknowns.extend(sufficiency.missing_information)
            if not verified_evidence_items and "No verified evidence available." not in unknowns:
                unknowns.append("No verified evidence available to support risk determination.")

            return RiskReasoningResult(
                risk_level=ThreatSeverity.UNKNOWN,
                risk_reason=insufficient_msg,
                observed_facts=observed_facts,
                context=context_items,
                policy_context=policy_items,
                inferences=[],
                evidence_ids=evidence_ids,
                event_ids=event_ids,
                unknowns=unknowns or ["Insufficient evidence to support risk evaluation."],
                limitations=limitations,
                backend_severity=parsed_backend_severity,
                reasoning_status=ReasoningStatus.INSUFFICIENT_EVIDENCE,
            )

        # =====================================================================
        # 5. CONTEXT & POLICY INTEGRATION (Step 10 & 11)
        # =====================================================================
        # Process security context result if passed
        if security_context_result:
            if isinstance(security_context_result, dict):
                ctx_items = security_context_result.get("security_context", [])
                has_ctx_conflict = security_context_result.get("has_conflict", False)
            else:
                ctx_items = security_context_result.security_context
                has_ctx_conflict = security_context_result.has_conflict

            if has_ctx_conflict:
                limitations.append("Security context conflict detected.")

            for item in ctx_items:
                item_dict = item if isinstance(item, dict) else item.model_dump()
                cat = item_dict.get("category")
                stmt = item_dict.get("statement")
                src = item_dict.get("source")
                if cat in ("zone_policy", "supplied_policy"):
                    policy_items.append(f"{stmt} (Source: {src})")
                else:
                    context_items.append(f"{stmt} (Source: {src})")

        # Process direct memories
        for mem in memories_list:
            if mem.type in ("zone_policy", "access_policy"):
                policy_items.append(f"Policy for {mem.type}: {mem.value} (Source: {mem.source})")
            elif mem.type == "camera_mapping" and isinstance(mem.value, dict):
                cid = mem.value.get("camera_id")
                loc = mem.value.get("location") or mem.value.get("name")
                context_items.append(f"Camera {cid} located at '{loc}' (Source: {mem.source})")

        # Process supplied authoritative policies
        if supplied_policies:
            for p in supplied_policies:
                zid = p.get("zone_id")
                pol = p.get("policy") or p.get("rule")
                src = p.get("source", "supplied_authoritative")
                if zid and pol:
                    policy_items.append(f"Zone {zid} policy: '{pol}' (Source: {src})")

        # =====================================================================
        # 6. TEMPORAL RULE & TIMELINE INTEGRATION (Step 8)
        # =====================================================================
        if time_range:
            tr_start = time_range.get("start") or time_range.get("start_time")
            tr_end = time_range.get("end") or time_range.get("end_time")
            dt_start = parse_timestamp_safe(tr_start) if tr_start else None
            dt_end = parse_timestamp_safe(tr_end) if tr_end else None

            temporal_mismatch = False
            for evt in events_list:
                evt_dt = parse_timestamp_safe(evt.timestamp)
                if evt_dt is None:
                    limitations.append(f"Temporal relevance cannot be established for event {evt.event_id}.")
                    temporal_mismatch = True
                else:
                    if dt_start and evt_dt < dt_start:
                        limitations.append(f"Event {evt.event_id} precedes investigation window.")
                        temporal_mismatch = True
                    if dt_end and evt_dt > dt_end:
                        limitations.append(f"Event {evt.event_id} succeeds investigation window.")
                        temporal_mismatch = True

            if not temporal_mismatch and (dt_start or dt_end):
                context_items.append(f"Temporal relevance verified within {tr_start} - {tr_end}.")

        if timeline_list:
            inferences.append(f"Timeline chronological sequence verified ({len(timeline_list)} items).")

        # =====================================================================
        # 7. CROSS-CAMERA / ENTITY CORRELATION INTEGRATION (Step 9)
        # =====================================================================
        for corr in correlation_list:
            if isinstance(corr, EntityCorrelationTrajectory):
                ent_token = corr.entity_id
                cams = list(corr.camera_ids)
            elif isinstance(corr, dict):
                ent_token = corr.get("entity_id")
                cams = corr.get("camera_ids", [])
            else:
                continue

            if len(cams) > 1 and ent_token:
                inferences.append(
                    f"Tracked entity entity_id={ent_token} observed across cameras: {', '.join(sorted(cams))}."
                )

        # Entity identity protection - NEVER convert to real identity
        for evt in events_list:
            if evt.entity_id:
                identity_unk = f"Tracked entity {evt.entity_id} identity cannot be verified from sensor telemetry alone."
                if identity_unk not in unknowns:
                    unknowns.append(identity_unk)

        # =====================================================================
        # 8. RISK DETERMINATION (Evidence-Grounded & Policy-Driven)
        # =====================================================================
        # If Backend Threat assessment is already available -> Backend Authority Rule applies
        if parsed_backend_severity is not None:
            sev_str = parsed_backend_severity.value if hasattr(parsed_backend_severity, "value") else str(parsed_backend_severity)
            backend_reason = (
                f"Authoritative Backend Security Core assessment established severity as {sev_str}"
            )
            if backend_threat_id:
                backend_reason += f" (Threat ID: {backend_threat_id})."
            else:
                backend_reason += "."

            inferences.append(backend_reason)
            return RiskReasoningResult(
                risk_level=parsed_backend_severity,
                risk_reason=backend_reason,
                observed_facts=observed_facts,
                context=context_items,
                policy_context=policy_items,
                inferences=inferences,
                evidence_ids=evidence_ids,
                event_ids=event_ids,
                unknowns=unknowns,
                limitations=limitations,
                backend_severity=parsed_backend_severity,
                reasoning_status=ReasoningStatus.DETERMINED,
            )

        # Check Policy Rule: If no policy context exists, record limitation
        if not policy_items:
            missing_pol_msg = "No applicable security policy or context supplied; risk level cannot be determined reliably."
            limitations.append(missing_pol_msg)
            insufficient_msg = "I don't know — insufficient evidence."
            return RiskReasoningResult(
                risk_level=ThreatSeverity.UNKNOWN,
                risk_reason=insufficient_msg,
                observed_facts=observed_facts,
                context=context_items,
                policy_context=[],
                inferences=inferences,
                evidence_ids=evidence_ids,
                event_ids=event_ids,
                unknowns=unknowns or ["Operating policies for observed events are unrecorded."],
                limitations=limitations,
                backend_severity=None,
                reasoning_status=ReasoningStatus.UNKNOWN,
            )

        # Evaluate risk level based on verified events and authoritative policy context
        high_evidence = False
        medium_evidence = False
        low_evidence = False
        reasons: List[str] = []

        combined_policy_text = " ".join(policy_items).lower()

        for evt in events_list:
            evt_type_lower = evt.event_type.lower()

            # High risk indicators
            if any(k in evt_type_lower for k in cls.HIGH_RISK_KEYWORDS) or "lockdown" in combined_policy_text:
                high_evidence = True
                reasons.append(f"Event {evt.event_id} represents a verified critical security violation.")

            # Medium risk indicators
            elif any(k in evt_type_lower for k in cls.MEDIUM_RISK_KEYWORDS) or "restricted" in combined_policy_text:
                medium_evidence = True
                reasons.append(f"Event {evt.event_id} represents a verified operational policy deviation.")

            # Low risk indicators
            elif any(k in evt_type_lower for k in cls.LOW_RISK_KEYWORDS) or "authorized" in combined_policy_text:
                low_evidence = True
                reasons.append(f"Event {evt.event_id} conforms to verified authorized policy.")

        if high_evidence:
            assigned_risk = ThreatSeverity.HIGH
            reason_text = f"HIGH risk determined: {'; '.join(reasons)}"
            inferences.append(reason_text)
            status = ReasoningStatus.DETERMINED
        elif medium_evidence:
            assigned_risk = ThreatSeverity.MEDIUM
            reason_text = f"MEDIUM risk determined: {'; '.join(reasons)}"
            inferences.append(reason_text)
            status = ReasoningStatus.DETERMINED
        elif low_evidence:
            assigned_risk = ThreatSeverity.LOW
            reason_text = f"LOW risk determined: {'; '.join(reasons)}"
            inferences.append(reason_text)
            status = ReasoningStatus.DETERMINED
        else:
            # Evidence exists but event nature cannot be classified under supplied policy
            assigned_risk = ThreatSeverity.UNKNOWN
            reason_text = "I don't know — insufficient evidence."
            limitations.append("Observed events could not be deterministically evaluated against supplied policy.")
            status = ReasoningStatus.UNKNOWN

        return RiskReasoningResult(
            risk_level=assigned_risk,
            risk_reason=reason_text,
            observed_facts=observed_facts,
            context=context_items,
            policy_context=policy_items,
            inferences=inferences,
            evidence_ids=evidence_ids,
            event_ids=event_ids,
            unknowns=unknowns,
            limitations=limitations,
            backend_severity=None,
            reasoning_status=status,
        )
