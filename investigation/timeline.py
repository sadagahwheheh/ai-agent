"""
Module 4: Incident Timeline Engine.
Constructs chronological timelines strictly from authoritative events and evidence.
Supports deterministic temporal reasoning, missing observation gap tracking,
and preserves original timestamps without fabrication.
"""
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Union
from pydantic import BaseModel, ConfigDict, Field

from schemas.events import Event
from schemas.evidence import Evidence
from schemas.investigation import TimelineItem, TimeRange


def parse_timestamp_safe(ts: Optional[str]) -> Optional[datetime]:
    """Deterministically parse an ISO timestamp string into a timezone-aware datetime."""
    if not ts or not isinstance(ts, str) or not ts.strip():
        return None
    cleaned = ts.strip()
    try:
        # Standard ISO parse (supports 'Z' in Python 3.11+)
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


class TimelineConstructionResult(BaseModel):
    """Structured result of timeline construction."""
    model_config = ConfigDict(extra="ignore", frozen=True)

    timeline: List[TimelineItem] = Field(default_factory=list)
    total_events: int = 0
    verified_count: int = 0
    gap_count: int = 0
    temporal_limitations: List[str] = Field(default_factory=list)
    conflicting_timestamps: List[str] = Field(default_factory=list)
    invalid_timestamps: List[str] = Field(default_factory=list)


class TimelineEngine:
    """
    Chronological ordering and temporal reasoning engine.
    Never fabricates events, timestamps, movement, or identities.
    """

    @classmethod
    def construct(
        cls,
        events: Optional[Sequence[Union[Event, Dict[str, Any]]]] = None,
        evidence: Optional[Sequence[Union[Evidence, Dict[str, Any]]]] = None,
        time_range: Optional[Union[TimeRange, Dict[str, str]]] = None,
        gap_threshold_seconds: Optional[int] = 300,
    ) -> TimelineConstructionResult:
        """
        Construct a chronological timeline from supplied events and evidence.
        Flags unmonitored gaps as 'NO VERIFIED OBSERVATION AVAILABLE'.
        """
        events_list = list(events or [])
        evidence_list = list(evidence or [])

        # Index evidence by event_id for fast linking
        evidence_by_event: Dict[str, List[Dict[str, Any]]] = {}
        for ev in evidence_list:
            ev_dict = ev.model_dump() if isinstance(ev, Evidence) else ev
            ev_id = ev_dict.get("event_id")
            if ev_id:
                evidence_by_event.setdefault(ev_id, []).append(ev_dict)

        timeline_items: List[TimelineItem] = []
        invalid_ts: List[str] = []
        conflicting_ts: List[str] = []
        limitations: List[str] = []

        # 1. Parse events and map into TimelineItems
        parsed_entries = []
        for raw_evt in events_list:
            evt = raw_evt.model_dump() if isinstance(raw_evt, Event) else raw_evt
            eid = evt.get("event_id", "UNKNOWN_EVENT")
            raw_ts = evt.get("timestamp")
            parsed_dt = parse_timestamp_safe(raw_ts)

            if not raw_ts or parsed_dt is None:
                invalid_ts.append(f"Event {eid} contains invalid or unparseable timestamp: '{raw_ts}'")
                continue

            # Check linked evidence
            linked_ev = evidence_by_event.get(eid, [])
            ev_id = linked_ev[0].get("evidence_id") if linked_ev else evt.get("evidence_id")

            desc = f"Event '{evt.get('event_type')}' observed on camera {evt.get('camera_id')}"
            if evt.get("zone_id"):
                desc += f" in zone {evt.get('zone_id')}"

            item = TimelineItem(
                timestamp=raw_ts,  # strictly preserves original timestamp
                description=desc,
                camera_id=evt.get("camera_id"),
                event_id=eid,
                evidence_id=ev_id,
                entity_id=evt.get("entity_id"),
                is_verified=str(evt.get("status", "")).upper() == "OBSERVED",
                event_type=evt.get("event_type"),
                zone_id=evt.get("zone_id"),
                confidence=evt.get("confidence"),
                source=evt.get("source", "video_intelligence"),
                verification_status=evt.get("status", "OBSERVED"),
                is_gap=False
            )
            parsed_entries.append((parsed_dt, raw_ts, item))

        # 2. Sort deterministically (primary: datetime, secondary: raw_ts, tertiary: event_id)
        parsed_entries.sort(key=lambda x: (x[0], x[1], x[2].event_id or ""))

        # 3. Detect conflicting timestamps (e.g. same entity in two distinct cameras at same second)
        entity_times: Dict[str, Dict[str, str]] = {}
        for dt, raw_ts, item in parsed_entries:
            if item.entity_id:
                prev_cam = entity_times.get(item.entity_id, {}).get(raw_ts)
                if prev_cam and prev_cam != item.camera_id:
                    conflict_desc = (
                        f"Temporal/spatial conflict: entity {item.entity_id} observed simultaneously "
                        f"at {raw_ts} on both {prev_cam} and {item.camera_id}"
                    )
                    conflicting_ts.append(conflict_desc)
                    limitations.append("Conflicting timestamps detected across camera observations.")
                entity_times.setdefault(item.entity_id, {})[raw_ts] = item.camera_id or "UNKNOWN_CAM"

        # 4. Handle Empty Timeline Case
        if not parsed_entries:
            start_str = None
            if time_range:
                start_str = time_range.start if isinstance(time_range, TimeRange) else time_range.get("start")

            empty_marker = TimelineItem(
                timestamp=start_str or "UNSPECIFIED",
                description="NO VERIFIED OBSERVATION AVAILABLE",
                is_verified=False,
                is_gap=True
            )
            return TimelineConstructionResult(
                timeline=[empty_marker],
                total_events=0,
                verified_count=0,
                gap_count=1,
                temporal_limitations=["No verified observations available for the requested period."],
                conflicting_timestamps=[],
                invalid_timestamps=invalid_ts,
            )

        # 5. Insert Missing Observation Gaps where appropriate
        start_bound: Optional[datetime] = None
        end_bound: Optional[datetime] = None
        if time_range:
            tr_start = time_range.start if isinstance(time_range, TimeRange) else time_range.get("start")
            tr_end = time_range.end if isinstance(time_range, TimeRange) else time_range.get("end")
            start_bound = parse_timestamp_safe(tr_start)
            end_bound = parse_timestamp_safe(tr_end)

        gap_count = 0
        final_timeline: List[TimelineItem] = []

        # Check gap at beginning of time window
        if start_bound and gap_threshold_seconds:
            first_dt = parsed_entries[0][0]
            if (first_dt - start_bound).total_seconds() > gap_threshold_seconds:
                final_timeline.append(
                    TimelineItem(
                        timestamp=tr_start or str(start_bound),
                        description="NO VERIFIED OBSERVATION AVAILABLE",
                        is_verified=False,
                        is_gap=True
                    )
                )
                gap_count += 1

        # Process entries and inter-event gaps
        for i in range(len(parsed_entries)):
            current_dt, _, current_item = parsed_entries[i]
            final_timeline.append(current_item)

            if i < len(parsed_entries) - 1:
                next_dt, _, _ = parsed_entries[i + 1]
                gap_seconds = (next_dt - current_dt).total_seconds()
                if gap_threshold_seconds and gap_seconds > gap_threshold_seconds:
                    gap_ts_str = (current_dt + timedelta(seconds=1)).isoformat()
                    final_timeline.append(
                        TimelineItem(
                            timestamp=gap_ts_str,
                            description="NO VERIFIED OBSERVATION AVAILABLE",
                            is_verified=False,
                            is_gap=True
                        )
                    )
                    gap_count += 1

        # Check gap at end of time window
        if end_bound and gap_threshold_seconds:
            last_dt = parsed_entries[-1][0]
            if (end_bound - last_dt).total_seconds() > gap_threshold_seconds:
                final_timeline.append(
                    TimelineItem(
                        timestamp=(last_dt + timedelta(seconds=1)).isoformat(),
                        description="NO VERIFIED OBSERVATION AVAILABLE",
                        is_verified=False,
                        is_gap=True
                    )
                )
                gap_count += 1

        verified_count = sum(1 for item in final_timeline if item.is_verified and not item.is_gap)

        return TimelineConstructionResult(
            timeline=final_timeline,
            total_events=len(parsed_entries),
            verified_count=verified_count,
            gap_count=gap_count,
            temporal_limitations=limitations,
            conflicting_timestamps=conflicting_ts,
            invalid_timestamps=invalid_ts,
        )

    # =========================================================================
    # TEMPORAL FILTERING OPERATIONS
    # =========================================================================

    @classmethod
    def filter_before(cls, items: Sequence[TimelineItem], before_timestamp: str) -> List[TimelineItem]:
        """Returns items occurring strictly before the target timestamp."""
        target_dt = parse_timestamp_safe(before_timestamp)
        if not target_dt:
            return list(items)
        results = []
        for item in items:
            item_dt = parse_timestamp_safe(item.timestamp)
            if item_dt and item_dt < target_dt:
                results.append(item)
        return results

    @classmethod
    def filter_after(cls, items: Sequence[TimelineItem], after_timestamp: str) -> List[TimelineItem]:
        """Returns items occurring strictly after the target timestamp."""
        target_dt = parse_timestamp_safe(after_timestamp)
        if not target_dt:
            return list(items)
        results = []
        for item in items:
            item_dt = parse_timestamp_safe(item.timestamp)
            if item_dt and item_dt > target_dt:
                results.append(item)
        return results

    @classmethod
    def filter_between(cls, items: Sequence[TimelineItem], start_timestamp: str, end_timestamp: str) -> List[TimelineItem]:
        """Returns items occurring within [start, end] inclusive."""
        start_dt = parse_timestamp_safe(start_timestamp)
        end_dt = parse_timestamp_safe(end_timestamp)
        if not start_dt or not end_dt:
            return list(items)
        results = []
        for item in items:
            item_dt = parse_timestamp_safe(item.timestamp)
            if item_dt and (start_dt <= item_dt <= end_dt):
                results.append(item)
        return results

    @classmethod
    def filter_exact(cls, items: Sequence[TimelineItem], exact_timestamp: str) -> List[TimelineItem]:
        """Returns items matching the exact timestamp."""
        cleaned = exact_timestamp.strip()
        target_dt = parse_timestamp_safe(cleaned)
        results = []
        for item in items:
            if item.timestamp == cleaned:
                results.append(item)
            elif target_dt:
                item_dt = parse_timestamp_safe(item.timestamp)
                if item_dt == target_dt:
                    results.append(item)
        return results

    @classmethod
    def filter_last_n_minutes(cls, items: Sequence[TimelineItem], reference_time: str, minutes: int) -> List[TimelineItem]:
        """Returns items occurring within the last N minutes prior to reference_time."""
        ref_dt = parse_timestamp_safe(reference_time)
        if not ref_dt or minutes <= 0:
            return list(items)
        start_dt = ref_dt - timedelta(minutes=minutes)
        results = []
        for item in items:
            item_dt = parse_timestamp_safe(item.timestamp)
            if item_dt and (start_dt <= item_dt <= ref_dt):
                results.append(item)
        return results

    @classmethod
    def filter_last_n_hours(cls, items: Sequence[TimelineItem], reference_time: str, hours: int) -> List[TimelineItem]:
        """Returns items occurring within the last N hours prior to reference_time."""
        return cls.filter_last_n_minutes(items, reference_time, minutes=hours * 60)
