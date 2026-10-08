"""
Module 4: Evidence Sufficiency Engine.
Evaluates whether available evidence is sufficient, insufficient, or conflicted
to support an investigation conclusion without inventing or assuming facts.
"""
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Union
from pydantic import BaseModel, ConfigDict, Field

from schemas.events import Event
from schemas.evidence import Evidence


class SufficiencyStatus(str, Enum):
    """Permitted sufficiency evaluation outcomes."""
    SUFFICIENT = "SUFFICIENT"
    INSUFFICIENT = "INSUFFICIENT"
    CONFLICTED = "CONFLICTED"


class SufficiencyResult(BaseModel):
    """
    Structured outcome of evidence sufficiency evaluation.
    Enforces deterministic evaluation and strict provenance without hallucination.
    """
    model_config = ConfigDict(extra="ignore", frozen=True)

    status: SufficiencyStatus
    reasons: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    missing_information: List[str] = Field(default_factory=list)
    contradictions: List[str] = Field(default_factory=list)

    @property
    def is_sufficient(self) -> bool:
        return self.status == SufficiencyStatus.SUFFICIENT

    @property
    def is_insufficient(self) -> bool:
        return self.status == SufficiencyStatus.INSUFFICIENT

    @property
    def is_conflicted(self) -> bool:
        return self.status == SufficiencyStatus.CONFLICTED


class EvidenceSufficiencyEngine:
    """
    Deterministic engine evaluating evidence quality, completeness, and consistency.
    Executes the 6 core checks defined in the Master Development Prompt:
      1. Is relevant evidence available?
      2. Is the timestamp reliable?
      3. Is the camera/source known?
      4. Was the event actually observed?
      5. Is there enough evidence to support the conclusion?
      6. Is there contradictory evidence?
    """

    @classmethod
    def evaluate(
        cls,
        evidence_items: Optional[Sequence[Union[Evidence, Dict[str, Any]]]] = None,
        events: Optional[Sequence[Union[Event, Dict[str, Any]]]] = None,
        cameras: Optional[Dict[str, Any]] = None,
        target_scope: Optional[Dict[str, Any]] = None,
    ) -> SufficiencyResult:
        """
        Evaluate available evidence and event sets deterministically.
        Never fabricates missing evidence or assumes unobserved events.
        """
        evidence_list = list(evidence_items or [])
        events_list = list(events or [])
        camera_map = cameras or {}

        reasons: List[str] = []
        limitations: List[str] = []
        missing_info: List[str] = []
        contradictions: List[str] = []
        valid_evidence_ids: List[str] = []

        # =====================================================================
        # CHECK 1: Availability of Evidence / Events
        # =====================================================================
        if not evidence_list and not events_list:
            return SufficiencyResult(
                status=SufficiencyStatus.INSUFFICIENT,
                reasons=["No evidence items or observed events were supplied."],
                evidence_ids=[],
                limitations=["I don't know — insufficient evidence."],
                missing_information=["Observation evidence and indexed events are absent for this scope."],
                contradictions=[],
            )

        # =====================================================================
        # CHECK 2: Timestamp Reliability
        # =====================================================================
        items_with_unreliable_ts = 0
        total_items = len(evidence_list) + len(events_list)

        for item in evidence_list:
            item_dict = item.model_dump() if isinstance(item, Evidence) else item
            eid = item_dict.get("evidence_id", "UNKNOWN_EVIDENCE")
            ts = item_dict.get("timestamp_start") or item_dict.get("timestamp")
            if not ts or not str(ts).strip():
                items_with_unreliable_ts += 1
                missing_info.append(f"Evidence {eid} is missing a timestamp.")
            else:
                if eid != "UNKNOWN_EVIDENCE":
                    valid_evidence_ids.append(eid)

        for evt in events_list:
            evt_dict = evt.model_dump() if isinstance(evt, Event) else evt
            ev_id = evt_dict.get("event_id", "UNKNOWN_EVENT")
            ts = evt_dict.get("timestamp")
            if not ts or not str(ts).strip():
                items_with_unreliable_ts += 1
                missing_info.append(f"Event {ev_id} is missing a timestamp.")

        if total_items > 0 and items_with_unreliable_ts == total_items:
            return SufficiencyResult(
                status=SufficiencyStatus.INSUFFICIENT,
                reasons=["All supplied evidence items lack reliable timestamps."],
                evidence_ids=[],
                limitations=["I don't know — insufficient evidence."],
                missing_information=missing_info,
                contradictions=[],
            )

        # =====================================================================
        # CHECK 3: Camera / Source Known and Observable
        # =====================================================================
        items_with_unknown_camera = 0
        all_cams = set()

        for item in evidence_list:
            item_dict = item.model_dump() if isinstance(item, Evidence) else item
            cam_id = item_dict.get("camera_id")
            if not cam_id or not str(cam_id).strip():
                items_with_unknown_camera += 1
                missing_info.append(f"Evidence {item_dict.get('evidence_id')} has unknown camera source.")
            else:
                all_cams.add(cam_id)

        for evt in events_list:
            evt_dict = evt.model_dump() if isinstance(evt, Event) else evt
            cam_id = evt_dict.get("camera_id")
            if not cam_id or not str(cam_id).strip():
                items_with_unknown_camera += 1
                missing_info.append(f"Event {evt_dict.get('event_id')} has unknown camera source.")
            else:
                all_cams.add(cam_id)

        # Check camera health for blind spots
        offline_cams = set()
        for cid in all_cams:
            if cid in camera_map:
                cam_info = camera_map[cid]
                status = (
                    cam_info.get("status")
                    if isinstance(cam_info, dict)
                    else getattr(cam_info, "status", "UNKNOWN")
                )
                if str(status).upper() == "OFFLINE":
                    offline_cams.add(cid)
                    limitations.append(
                        f"Camera {cid} was OFFLINE during the observation period; activity cannot be reliably verified."
                    )

        if total_items > 0 and items_with_unknown_camera == total_items:
            return SufficiencyResult(
                status=SufficiencyStatus.INSUFFICIENT,
                reasons=["All supplied observations have unknown camera origins."],
                evidence_ids=[],
                limitations=["I don't know — insufficient evidence."],
                missing_information=missing_info,
                contradictions=[],
            )

        # If all cameras involved were offline
        if all_cams and offline_cams == all_cams:
            return SufficiencyResult(
                status=SufficiencyStatus.INSUFFICIENT,
                reasons=["All observation sources were OFFLINE."],
                evidence_ids=[],
                limitations=["I don't know — the area was not reliably observable during that period."],
                missing_information=["Camera coverage unavailable due to offline devices."],
                contradictions=[],
            )

        # =====================================================================
        # CHECK 4: Observation and Verification Integrity
        # =====================================================================
        unverified_events_count = 0
        unverified_evidence_count = 0

        for evt in events_list:
            evt_dict = evt.model_dump() if isinstance(evt, Event) else evt
            evt_status = str(evt_dict.get("status", "")).upper()
            if evt_status in ("UNVERIFIED", "FAILED", "SUSPECT"):
                unverified_events_count += 1
                missing_info.append(f"Event {evt_dict.get('event_id')} is unverified or marked suspect.")

        for item in evidence_list:
            item_dict = item.model_dump() if isinstance(item, Evidence) else item
            v_status = str(item_dict.get("verification_status", "")).upper()
            if v_status in ("FAILED", "SUSPECT"):
                unverified_evidence_count += 1
                missing_info.append(f"Evidence {item_dict.get('evidence_id')} verification status is {v_status}.")

        # =====================================================================
        # CHECK 5: Contradictory Evidence Detection
        # =====================================================================
        # Look for explicit contradiction flags or conflicting states
        for item in evidence_list:
            item_dict = item.model_dump() if isinstance(item, Evidence) else item
            v_status = str(item_dict.get("verification_status", "")).upper()
            if v_status == "CONFLICTED":
                contradictions.append(
                    f"Evidence {item_dict.get('evidence_id')} is flagged with CONFLICTED status."
                )
            if item_dict.get("metadata", {}).get("conflict") is True:
                contradictions.append(
                    f"Evidence {item_dict.get('evidence_id')} has contradictory metadata recorded."
                )

        for evt in events_list:
            evt_dict = evt.model_dump() if isinstance(evt, Event) else evt
            evt_status = str(evt_dict.get("status", "")).upper()
            if evt_status == "CONFLICTED":
                contradictions.append(
                    f"Event {evt_dict.get('event_id')} is flagged with CONFLICTED observation status."
                )
            if evt_dict.get("metadata", {}).get("conflict") is True:
                contradictions.append(
                    f"Event {evt_dict.get('event_id')} metadata contains contradictory sensor flags."
                )

        # Check for logical contradictions across events (e.g. mutually exclusive actions at same second)
        entity_time_map: Dict[str, List[Dict[str, Any]]] = {}
        for evt in events_list:
            evt_dict = evt.model_dump() if isinstance(evt, Event) else evt
            ent = evt_dict.get("entity_id")
            ts = evt_dict.get("timestamp")
            action = evt_dict.get("event_type") or evt_dict.get("metadata", {}).get("action")
            if ent and ts and action:
                key = f"{ent}@{ts}"
                entity_time_map.setdefault(key, []).append(evt_dict)

        for key, matching_events in entity_time_map.items():
            if len(matching_events) > 1:
                cams = {e.get("camera_id") for e in matching_events if e.get("camera_id")}
                # If same entity reported at multiple distinct cameras at exact same timestamp
                if len(cams) > 1:
                    contradictions.append(
                        f"Spatial impossibility: Entity reported on multiple cameras ({', '.join(cams)}) at identical timestamp ({key.split('@')[1]})."
                    )

        if contradictions:
            return SufficiencyResult(
                status=SufficiencyStatus.CONFLICTED,
                reasons=["Contradictory evidence or mutually exclusive observations detected."],
                evidence_ids=valid_evidence_ids,
                limitations=["Conflicting evidence detected."],
                missing_information=missing_info,
                contradictions=contradictions,
            )

        # =====================================================================
        # CHECK 6: Sufficiency Assessment
        # =====================================================================
        # Check if enough verified, reliable items remain
        verified_events = [
            e for e in events_list
            if str((e.model_dump() if isinstance(e, Event) else e).get("status", "")).upper() == "OBSERVED"
        ]
        verified_evidence = [
            ev for ev in evidence_list
            if str((ev.model_dump() if isinstance(ev, Evidence) else ev).get("verification_status", "")).upper() == "VERIFIED"
        ]

        if not verified_events and not verified_evidence:
            if not missing_info:
                missing_info.append("Observations lack verification.")
            return SufficiencyResult(
                status=SufficiencyStatus.INSUFFICIENT,
                reasons=["No verified events or evidence items available."],
                evidence_ids=[],
                limitations=["I don't know — insufficient evidence."],
                missing_information=missing_info,
                contradictions=[],
            )

        # If we have verified events/evidence, reliable timestamps, and known sources
        reasons.append(
            f"Sufficient evidence available: {len(verified_events)} verified event(s) and {len(verified_evidence)} verified evidence item(s)."
        )
        return SufficiencyResult(
            status=SufficiencyStatus.SUFFICIENT,
            reasons=reasons,
            evidence_ids=valid_evidence_ids,
            limitations=limitations,
            missing_information=missing_info,
            contradictions=[],
        )
