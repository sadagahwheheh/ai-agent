"""
Module 4: Cross-Camera / Entity Correlation Engine.
Correlates observations of the same tracked entity across cameras strictly using
authoritative tracking identifiers (entity_id) supplied by video intelligence.
Enforces the Identity Rule: entity_id is a tracking token, NEVER a real-world identity.
"""
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Union
from pydantic import BaseModel, ConfigDict, Field

from investigation.timeline import TimelineEngine, parse_timestamp_safe
from schemas.events import Event
from schemas.evidence import Evidence
from schemas.investigation import TimelineItem


class CorrelationStatus(str, Enum):
    """Permitted correlation statuses."""
    CORRELATED = "CORRELATED"
    NOT_CORRELATED = "NOT_CORRELATED"
    INSUFFICIENT_TRACKING = "INSUFFICIENT_TRACKING"
    CONFLICTED = "CONFLICTED"


class CorrelatedObservation(BaseModel):
    """Single verified observation of a tracked entity."""
    model_config = ConfigDict(extra="ignore", frozen=True)

    entity_id: str = Field(description="Tracked entity ID token (NOT a personal identity)")
    camera_id: str = Field(description="Camera where entity was observed")
    timestamp: str = Field(description="Exact observation timestamp")
    event_id: Optional[str] = Field(default=None, description="Linked event ID")
    evidence_id: Optional[str] = Field(default=None, description="Linked evidence ID")
    zone_id: Optional[str] = Field(default=None, description="Zone identifier if available")
    confidence: Optional[float] = Field(default=None, description="Detection confidence")
    event_type: Optional[str] = Field(default=None, description="Observation event type")
    verification_status: Optional[str] = Field(default=None, description="Verification status")


class EntityCorrelationTrajectory(BaseModel):
    """
    Chronological trajectory of a single tracked entity across one or more cameras.
    Does NOT infer real-world personal identity or fabricate intermediate movement.
    """
    model_config = ConfigDict(extra="ignore", frozen=True)

    entity_id: str
    status: CorrelationStatus
    observations: List[CorrelatedObservation] = Field(default_factory=list)
    camera_ids: List[str] = Field(default_factory=list)
    event_ids: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    observation_count: int = 0
    camera_count: int = 0
    is_cross_camera: bool = False
    timeline: List[TimelineItem] = Field(default_factory=list)
    description: str = ""
    limitations: List[str] = Field(default_factory=list)


class CrossCameraCorrelationResult(BaseModel):
    """Overall outcome of cross-camera entity correlation analysis."""
    model_config = ConfigDict(extra="ignore", frozen=True)

    status: CorrelationStatus
    trajectories: List[EntityCorrelationTrajectory] = Field(default_factory=list)
    total_entities_tracked: int = 0
    cross_camera_entities: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    conflicts: List[str] = Field(default_factory=list)


class EntityCorrelationEngine:
    """
    Deterministic cross-camera correlation engine.
    Strictly groups observations by authoritative entity_id without hallucinating identities.
    """

    @classmethod
    def correlate(
        cls,
        events: Optional[Sequence[Union[Event, Dict[str, Any]]]] = None,
        evidence: Optional[Sequence[Union[Evidence, Dict[str, Any]]]] = None,
        target_entity_id: Optional[str] = None,
    ) -> CrossCameraCorrelationResult:
        """
        Correlates events and evidence by entity_id across cameras.
        """
        events_list = list(events or [])
        evidence_list = list(evidence or [])

        # Link evidence by event_id
        ev_by_event: Dict[str, str] = {}
        for ev in evidence_list:
            ev_dict = ev.model_dump() if isinstance(ev, Evidence) else ev
            ev_event = ev_dict.get("event_id")
            ev_id = ev_dict.get("evidence_id")
            if ev_event and ev_id and ev_event not in ev_by_event:
                ev_by_event[ev_event] = ev_id

        # 1. Group observations strictly by authoritative entity_id
        observations_by_entity: Dict[str, List[Dict[str, Any]]] = {}
        untracked_count = 0

        for raw_evt in events_list:
            evt = raw_evt.model_dump() if isinstance(raw_evt, Event) else raw_evt
            ent_id = evt.get("entity_id")

            if not ent_id or not str(ent_id).strip():
                untracked_count += 1
                continue

            cleaned_ent = str(ent_id).strip()
            if target_entity_id and cleaned_ent != target_entity_id.strip():
                continue

            observations_by_entity.setdefault(cleaned_ent, []).append(evt)

        # 2. Check for insufficient tracking evidence
        if not observations_by_entity:
            limitation = "Entity correlation unavailable — insufficient tracking evidence."
            return CrossCameraCorrelationResult(
                status=CorrelationStatus.INSUFFICIENT_TRACKING,
                trajectories=[],
                total_entities_tracked=0,
                cross_camera_entities=[],
                limitations=[limitation],
                conflicts=[]
            )

        trajectories: List[EntityCorrelationTrajectory] = []
        cross_camera_ents: List[str] = []
        all_conflicts: List[str] = []
        overall_limitations: List[str] = []

        if untracked_count > 0:
            overall_limitations.append(
                f"{untracked_count} observed event(s) lacked authoritative tracking identifiers."
            )

        # 3. Process each entity deterministically
        for ent_id in sorted(observations_by_entity.keys()):
            raw_obs = observations_by_entity[ent_id]

            # Parse and sort chronologically
            parsed_obs = []
            for item in raw_obs:
                raw_ts = item.get("timestamp", "")
                dt = parse_timestamp_safe(raw_ts)
                eid = item.get("event_id")
                ev_id = ev_by_event.get(eid) if eid else item.get("evidence_id")

                obs = CorrelatedObservation(
                    entity_id=ent_id,
                    camera_id=item.get("camera_id", "UNKNOWN_CAM"),
                    timestamp=raw_ts,
                    event_id=eid,
                    evidence_id=ev_id,
                    zone_id=item.get("zone_id"),
                    confidence=item.get("confidence"),
                    event_type=item.get("event_type"),
                    verification_status=item.get("status", "OBSERVED")
                )
                parsed_obs.append((dt, raw_ts, obs, item))

            parsed_obs.sort(key=lambda x: (x[0] or 0, x[1], x[2].camera_id))

            # Detect simultaneous conflict (same entity at 2 distinct cameras at exact same timestamp)
            ts_cam_map: Dict[str, str] = {}
            entity_conflicts = []
            for dt, raw_ts, obs, _ in parsed_obs:
                prev_cam = ts_cam_map.get(raw_ts)
                if prev_cam and prev_cam != obs.camera_id:
                    msg = (
                        f"Tracking conflict for entity {ent_id}: simultaneous observation "
                        f"on cameras {prev_cam} and {obs.camera_id} at timestamp {raw_ts}."
                    )
                    entity_conflicts.append(msg)
                    all_conflicts.append(msg)
                ts_cam_map[raw_ts] = obs.camera_id

            sorted_observations = [p[2] for p in parsed_obs]
            unique_cameras = list(dict.fromkeys([o.camera_id for o in sorted_observations]))
            event_ids = [o.event_id for o in sorted_observations if o.event_id]
            evidence_ids = [o.evidence_id for o in sorted_observations if o.evidence_id]

            # Determine trajectory status
            if entity_conflicts:
                traj_status = CorrelationStatus.CONFLICTED
            elif len(unique_cameras) > 1:
                traj_status = CorrelationStatus.CORRELATED
                cross_camera_ents.append(ent_id)
            else:
                traj_status = CorrelationStatus.NOT_CORRELATED

            # Factual description without hallucinated movement
            if len(unique_cameras) > 1:
                desc = (
                    f"Tracked entity entity_id={ent_id} was observed across multiple cameras: "
                    f"{', '.join(unique_cameras)}."
                )
            else:
                desc = (
                    f"Tracked entity entity_id={ent_id} was observed on camera {unique_cameras[0]}."
                )

            # Build trajectory timeline using TimelineEngine
            traj_events = [p[3] for p in parsed_obs]
            timeline_res = TimelineEngine.construct(events=traj_events, gap_threshold_seconds=None)

            traj = EntityCorrelationTrajectory(
                entity_id=ent_id,
                status=traj_status,
                observations=sorted_observations,
                camera_ids=unique_cameras,
                event_ids=event_ids,
                evidence_ids=evidence_ids,
                observation_count=len(sorted_observations),
                camera_count=len(unique_cameras),
                is_cross_camera=len(unique_cameras) > 1,
                timeline=timeline_res.timeline,
                description=desc,
                limitations=entity_conflicts
            )
            trajectories.append(traj)

        # 4. Overall status
        if all_conflicts:
            overall_status = CorrelationStatus.CONFLICTED
        elif cross_camera_ents:
            overall_status = CorrelationStatus.CORRELATED
        else:
            overall_status = CorrelationStatus.NOT_CORRELATED

        return CrossCameraCorrelationResult(
            status=overall_status,
            trajectories=trajectories,
            total_entities_tracked=len(trajectories),
            cross_camera_entities=cross_camera_ents,
            limitations=overall_limitations,
            conflicts=all_conflicts
        )
