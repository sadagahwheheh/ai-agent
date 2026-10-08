"""
Module 4: Security-Context Reasoning Engine.
Combines authoritative investigation evidence with persistent security context memory.
Enforces strict segregation: OBSERVED FACTS, SECURITY CONTEXT, INFERENCES, UNKNOWNS,
SOURCE REFERENCES, CONFLICTS, and LIMITATIONS.
Never fabricates policies, identities, rules, or movement.
"""
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
from pydantic import BaseModel, ConfigDict, Field

from investigation.entity_correlation import EntityCorrelationTrajectory
from investigation.timeline import parse_timestamp_safe
from memory.validation import SecurityMemoryValidator
from schemas.events import Event
from schemas.evidence import Evidence
from schemas.investigation import TimelineItem
from schemas.memory import SecurityMemory


class SecurityContextItem(BaseModel):
    """Grounded security context record with verifiable provenance."""
    model_config = ConfigDict(extra="ignore", frozen=True)

    context_id: str
    category: str
    statement: str
    source: str
    memory_id: Optional[str] = None
    camera_id: Optional[str] = None
    zone_id: Optional[str] = None
    event_id: Optional[str] = None
    evidence_id: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    status: Optional[str] = None
    is_conflict: bool = False

    @property
    def timestamp(self) -> Optional[str]:
        """Timestamp alias preserving created_at."""
        return self.created_at


class SecurityContextReasoningResult(BaseModel):
    """
    Structured outcome of security-context reasoning.
    Strictly separates direct observations, context from memory/policy, inferences, unknowns,
    source references, conflicts, and limitations.
    """
    model_config = ConfigDict(extra="ignore", frozen=True)

    observed_facts: List[str] = Field(default_factory=list)
    security_context: List[SecurityContextItem] = Field(default_factory=list)
    inferences: List[str] = Field(default_factory=list)
    unknowns: List[str] = Field(default_factory=list)
    source_references: List[str] = Field(default_factory=list)
    conflicts: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    has_conflict: bool = False
    conflict_message: Optional[str] = None
    is_sufficient: bool = True

    @property
    def security_contexts(self) -> List[SecurityContextItem]:
        """Plural alias for convenience."""
        return self.security_context


class SecurityContextReasoningEngine:
    """
    Deterministic reasoning engine establishing evidence-grounded security context.
    Executes the CONTEXT step of the core chain:
      OBSERVATION -> EVENT -> CONTEXT -> POLICY -> RISK -> EVIDENCE -> CONFIDENCE
    """

    @classmethod
    def reason(
        cls,
        events: Optional[Sequence[Union[Event, Dict[str, Any]]]] = None,
        evidence: Optional[Sequence[Union[Evidence, Dict[str, Any]]]] = None,
        memories: Optional[Sequence[Union[SecurityMemory, Dict[str, Any]]]] = None,
        timeline: Optional[Sequence[Union[TimelineItem, Dict[str, Any]]]] = None,
        correlations: Optional[Sequence[Union[EntityCorrelationTrajectory, Dict[str, Any]]]] = None,
        time_range: Optional[Dict[str, Any]] = None,
        incident: Optional[Dict[str, Any]] = None,
        supplied_policies: Optional[Sequence[Dict[str, Any]]] = None,
    ) -> SecurityContextReasoningResult:
        """
        Synthesizes observed facts, security context memory, and deterministic inferences.
        """
        events_list = [e if isinstance(e, Event) else Event.model_validate(e) for e in (events or [])]
        evidence_list = [ev if isinstance(ev, Evidence) else Evidence.model_validate(ev) for ev in (evidence or [])]
        memories_list = [m if isinstance(m, SecurityMemory) else SecurityMemory.model_validate(m) for m in (memories or [])]
        timeline_list = list(timeline or [])
        correlation_list = list(correlations or [])

        observed_facts: List[str] = []
        security_contexts: List[SecurityContextItem] = []
        inferences: List[str] = []
        unknowns: List[str] = []
        source_references: List[str] = []
        conflicts_list: List[str] = []
        limitations: List[str] = []
        has_conflict = False
        conflict_msg: Optional[str] = None

        # 1. Base observation check (Anti-hallucination fail-safe)
        if not events_list and not evidence_list:
            return SecurityContextReasoningResult(
                observed_facts=[],
                security_context=[],
                inferences=[],
                unknowns=["Required observation evidence is unavailable."],
                source_references=[],
                conflicts=[],
                limitations=["I don't know — insufficient evidence."],
                has_conflict=False,
                is_sufficient=False,
            )

        # =====================================================================
        # 2. OBSERVED FACTS (Strictly from authoritative events/evidence only)
        # =====================================================================
        cams_in_events = set()
        zones_in_events = set()
        entities_in_events = set()

        for evt in events_list:
            cams_in_events.add(evt.camera_id)
            if evt.zone_id:
                zones_in_events.add(evt.zone_id)
            if evt.entity_id:
                entities_in_events.add(evt.entity_id)

            fact_str = f"Event {evt.event_id} ({evt.event_type}) observed on camera {evt.camera_id} at {evt.timestamp}"
            if evt.zone_id:
                fact_str += f" in zone {evt.zone_id}"
            if evt.entity_id:
                fact_str += f" with tracked entity token {evt.entity_id}"
            observed_facts.append(fact_str)

            if evt.source:
                source_references.append(f"event:{evt.event_id} ({evt.source})")

        for ev in evidence_list:
            if ev.verification_status == "VERIFIED":
                fact_str = f"Evidence {ev.evidence_id} verified from camera {ev.camera_id} at {ev.timestamp_start}"
                ev_zone = ev.metadata.get("zone_id") if isinstance(ev.metadata, dict) else None
                if ev_zone:
                    fact_str += f" in zone {ev_zone}"
                    zones_in_events.add(ev_zone)
                observed_facts.append(fact_str)
                cams_in_events.add(ev.camera_id)

                src = ev.source_video or ev.clip_reference or "verified_evidence"
                source_references.append(f"evidence:{ev.evidence_id} ({src})")

        # =====================================================================
        # 3. TEMPORAL CONTEXT CHECKING (Respecting Timeline timestamps)
        # =====================================================================
        if time_range:
            tr_start_raw = time_range.get("start") or time_range.get("start_time")
            tr_end_raw = time_range.get("end") or time_range.get("end_time")
            dt_start = parse_timestamp_safe(tr_start_raw) if tr_start_raw else None
            dt_end = parse_timestamp_safe(tr_end_raw) if tr_end_raw else None

            temporal_mismatch_found = False
            for evt in events_list:
                evt_dt = parse_timestamp_safe(evt.timestamp)
                if evt_dt is None:
                    limitations.append(
                        f"Temporal relevance cannot be established for event {evt.event_id}: missing or unparseable timestamp '{evt.timestamp}'."
                    )
                    temporal_mismatch_found = True
                else:
                    if dt_start and evt_dt < dt_start:
                        limitations.append(
                            f"Temporal context mismatch: event {evt.event_id} timestamp '{evt.timestamp}' precedes investigation window start '{tr_start_raw}'."
                        )
                        temporal_mismatch_found = True
                    if dt_end and evt_dt > dt_end:
                        limitations.append(
                            f"Temporal context mismatch: event {evt.event_id} timestamp '{evt.timestamp}' succeeds investigation window end '{tr_end_raw}'."
                        )
                        temporal_mismatch_found = True

            if not temporal_mismatch_found and (dt_start or dt_end):
                observed_facts.append(
                    f"Temporal context verified within investigation window ({tr_start_raw or 'earliest'} to {tr_end_raw or 'latest'})."
                )

        # =====================================================================
        # 4. SECURITY CONTEXT (Persistent Memory & Supplied Policy/Context)
        # =====================================================================
        valid_memories: List[SecurityMemory] = []
        for mem in memories_list:
            if not mem.source or not mem.source.strip():
                limitations.append(f"Security memory {mem.memory_id} rejected: missing auditable source.")
            else:
                valid_memories.append(mem)

        # Detect conflicting memories
        mem_validation = SecurityMemoryValidator.find_conflicts(valid_memories)
        conflicted_mem_ids = set()
        if mem_validation.has_conflict:
            has_conflict = True
            conflict_msg = "Security context conflict detected."
            limitations.append(conflict_msg)
            for conf in mem_validation.conflicts:
                conflicted_mem_ids.add(conf.memory_id_a)
                conflicted_mem_ids.add(conf.memory_id_b)
                conflict_desc = (
                    f"Conflict between memory {conf.memory_id_a} (Source: {conf.source_a}) "
                    f"and memory {conf.memory_id_b} (Source: {conf.source_b}): {conf.reason}"
                )
                conflicts_list.append(conflict_desc)
                limitations.append(conflict_desc)

        cam_locations: Dict[str, Tuple[str, str, str]] = {}
        zone_policies: Dict[str, Tuple[str, str, str]] = {}
        shift_schedules: List[Tuple[str, str, str, str]] = []

        for mem in valid_memories:
            is_item_conflicted = mem.memory_id in conflicted_mem_ids
            source_references.append(f"memory:{mem.memory_id} ({mem.source})")

            if mem.type == "camera_mapping" and isinstance(mem.value, dict):
                cid = mem.value.get("camera_id")
                loc = mem.value.get("location") or mem.value.get("name")
                if cid and loc:
                    ctx_item = SecurityContextItem(
                        context_id=f"CTX-{mem.memory_id}",
                        category="camera_mapping",
                        statement=f"Camera {cid} is positioned at location '{loc}'",
                        source=mem.source,
                        memory_id=mem.memory_id,
                        camera_id=cid,
                        created_at=mem.created_at,
                        updated_at=mem.updated_at,
                        status=mem.status,
                        is_conflict=is_item_conflicted
                    )
                    security_contexts.append(ctx_item)
                    if not is_item_conflicted:
                        cam_locations[cid] = (loc, mem.source, mem.memory_id)

            elif mem.type == "zone_policy" and isinstance(mem.value, dict):
                zid = mem.value.get("zone_id")
                pol = mem.value.get("policy") or mem.value.get("rule")
                if zid and pol:
                    ctx_item = SecurityContextItem(
                        context_id=f"CTX-{mem.memory_id}",
                        category="zone_policy",
                        statement=f"Zone {zid} operates under policy: '{pol}'",
                        source=mem.source,
                        memory_id=mem.memory_id,
                        zone_id=zid,
                        created_at=mem.created_at,
                        updated_at=mem.updated_at,
                        status=mem.status,
                        is_conflict=is_item_conflicted
                    )
                    security_contexts.append(ctx_item)
                    if not is_item_conflicted:
                        zone_policies[zid] = (pol, mem.source, mem.memory_id)

            elif mem.type == "shift_schedule" and isinstance(mem.value, dict):
                shift_name = mem.value.get("shift", "Shift")
                hours = mem.value.get("hours", "")
                ctx_item = SecurityContextItem(
                    context_id=f"CTX-{mem.memory_id}",
                    category="shift_schedule",
                    statement=f"Operating schedule for {shift_name}: {hours}",
                    source=mem.source,
                    memory_id=mem.memory_id,
                    created_at=mem.created_at,
                    updated_at=mem.updated_at,
                    status=mem.status,
                    is_conflict=is_item_conflicted
                )
                security_contexts.append(ctx_item)
                if not is_item_conflicted:
                    shift_schedules.append((shift_name, hours, mem.source, mem.memory_id))

            else:
                val_str = str(mem.value)
                ctx_item = SecurityContextItem(
                    context_id=f"CTX-{mem.memory_id}",
                    category=mem.type,
                    statement=f"Security context ({mem.type}): {val_str}",
                    source=mem.source,
                    memory_id=mem.memory_id,
                    created_at=mem.created_at,
                    updated_at=mem.updated_at,
                    status=mem.status,
                    is_conflict=is_item_conflicted
                )
                security_contexts.append(ctx_item)

        # Process supplied authoritative policies
        if supplied_policies:
            for i, p in enumerate(supplied_policies):
                zid = p.get("zone_id")
                pol = p.get("policy") or p.get("rule")
                src = p.get("source") or "supplied_policy_authoritative"
                pol_id = p.get("policy_id", f"SUP-POL-{i+1}")
                if zid and pol:
                    ctx_item = SecurityContextItem(
                        context_id=f"CTX-{pol_id}",
                        category="supplied_policy",
                        statement=f"Zone {zid} operates under policy: '{pol}'",
                        source=src,
                        zone_id=zid,
                        status="ACTIVE",
                    )
                    security_contexts.append(ctx_item)
                    source_references.append(f"policy:{pol_id} ({src})")
                    if zid not in zone_policies:
                        zone_policies[zid] = (pol, src, pol_id)

        # Process incident metadata context
        if incident:
            inc_id = incident.get("incident_id")
            title = incident.get("title", "Untitled incident")
            src = incident.get("source", "incident_metadata")
            zid = incident.get("zone_id")
            ctx_item = SecurityContextItem(
                context_id=f"CTX-INC-{inc_id or 'UNKNOWN'}",
                category="incident_context",
                statement=f"Referenced incident {inc_id or 'UNKNOWN'}: {title}",
                source=src,
                zone_id=zid,
                status="ACTIVE",
            )
            security_contexts.append(ctx_item)
            source_references.append(f"incident:{inc_id or 'UNKNOWN'} ({src})")

        # Fail-safe when security context is absent
        if not valid_memories and not supplied_policies and not incident:
            limitations.append("Security context unavailable.")

        # =====================================================================
        # 5. DETERMINISTIC INFERENCES (Fact + Context Deductions)
        # =====================================================================
        # Camera location inferences
        for cid in sorted(cams_in_events):
            if cid in cam_locations:
                loc, src, mid = cam_locations[cid]
                inferences.append(
                    f"Observations on camera {cid} occurred at location '{loc}' (Context: {mid}, Source: {src})."
                )
            else:
                if has_conflict and any(
                    isinstance(m.value, dict) and m.value.get("camera_id") == cid and m.memory_id in conflicted_mem_ids
                    for m in valid_memories
                ):
                    unknowns.append(
                        f"Physical location mapping for camera {cid} cannot be reliably inferred due to conflicting security memory."
                    )
                else:
                    unknowns.append(
                        f"Physical location mapping for camera {cid} is unrecorded in security context memory."
                    )

        # Zone policy inferences
        for zid in sorted(zones_in_events):
            if zid in zone_policies:
                pol, src, mid = zone_policies[zid]
                inferences.append(
                    f"Activity in zone {zid} is subject to configured policy '{pol}' (Context: {mid}, Source: {src})."
                )
            else:
                if has_conflict and any(
                    isinstance(m.value, dict) and m.value.get("zone_id") == zid and m.memory_id in conflicted_mem_ids
                    for m in valid_memories
                ):
                    unknowns.append(
                        f"Operating policy rules for zone {zid} cannot be reliably inferred due to conflicting security memory."
                    )
                else:
                    unknowns.append(
                        f"Operating policy rules for zone {zid} are unrecorded in security context memory."
                    )

        # Cross-camera trajectory inferences (from Step 9 correlations)
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
                cams_str = ", ".join(sorted(cams))
                inferences.append(
                    f"Tracked entity entity_id={ent_token} was observed across multiple cameras: {cams_str}."
                )

        # Timeline chronological synthesis inference (if timeline provided)
        if timeline_list:
            inferences.append(
                f"Timeline established with {len(timeline_list)} chronological observation entries."
            )

        # Entity identity protection - NEVER fabricate person identity
        for ent in sorted(entities_in_events):
            unknowns.append(
                f"Tracked entity {ent} identity cannot be verified from sensor telemetry alone."
            )

        # Deterministic sorting for sources
        source_references = sorted(list(dict.fromkeys(source_references)))

        return SecurityContextReasoningResult(
            observed_facts=observed_facts,
            security_context=security_contexts,
            inferences=inferences,
            unknowns=unknowns,
            source_references=source_references,
            conflicts=conflicts_list,
            limitations=limitations,
            has_conflict=has_conflict,
            conflict_message=conflict_msg,
            is_sufficient=True,
        )
