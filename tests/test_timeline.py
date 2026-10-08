"""
Tests for Module 4 Incident Timeline Engine.
Validates chronological ordering, timestamp preservation, temporal filtering,
unmonitored gap detection, conflicting timestamp handling, zero hallucination,
and integration with schemas, retrieval layer, and orchestrator.
"""
import pytest

from agent.orchestrator import InvestigationOrchestrator
from evidence.retrieval import EvidenceRetrievalService
from integration.mock_client import MockBackendClient
from investigation.event_search import EventRetrievalService
from investigation.timeline import (
    TimelineConstructionResult,
    TimelineEngine,
    parse_timestamp_safe,
)
from schemas.events import Event
from schemas.evidence import Evidence
from schemas.investigation import (
    InvestigationRequest,
    InvestigationStatus,
    TimelineItem,
    TimeRange,
)


def sample_events():
    return [
        Event(
            event_id="EVT-2",
            camera_id="CAM-05",
            timestamp="2026-10-08T10:43:02Z",
            event_type="restricted_zone_entry",
            entity_id="ENT-902",
            status="OBSERVED"
        ),
        Event(
            event_id="EVT-1",
            camera_id="CAM-03",
            timestamp="2026-10-08T10:42:13Z",
            event_type="person_detected",
            entity_id="ENT-902",
            status="OBSERVED"
        ),
        Event(
            event_id="EVT-3",
            camera_id="CAM-07",
            timestamp="2026-10-08T10:44:01Z",
            event_type="door_opened",
            entity_id="ENT-902",
            status="OBSERVED"
        ),
    ]


def test_1_chronological_event_ordering():
    """Verify events provided out-of-order are sorted chronologically."""
    events = sample_events()
    res = TimelineEngine.construct(events=events, gap_threshold_seconds=None)
    assert res.total_events == 3
    timestamps = [item.timestamp for item in res.timeline]
    assert timestamps == [
        "2026-10-08T10:42:13Z",
        "2026-10-08T10:43:02Z",
        "2026-10-08T10:44:01Z",
    ]


def test_2_timestamp_preservation():
    """Verify the original timestamp string is preserved verbatim without alteration."""
    raw_ts = "2026-10-08T10:42:13.123456Z"
    events = [
        Event(
            event_id="EVT-RAW",
            camera_id="CAM-03",
            timestamp=raw_ts,
            event_type="person_detected",
            status="OBSERVED"
        )
    ]
    res = TimelineEngine.construct(events=events, gap_threshold_seconds=None)
    assert res.timeline[0].timestamp == raw_ts


def test_3_before_filtering():
    """Verify filter_before returns only events prior to target timestamp."""
    events = sample_events()
    res = TimelineEngine.construct(events=events, gap_threshold_seconds=None)
    filtered = TimelineEngine.filter_before(res.timeline, "2026-10-08T10:43:00Z")
    assert len(filtered) == 1
    assert filtered[0].event_id == "EVT-1"


def test_4_after_filtering():
    """Verify filter_after returns only events subsequent to target timestamp."""
    events = sample_events()
    res = TimelineEngine.construct(events=events, gap_threshold_seconds=None)
    filtered = TimelineEngine.filter_after(res.timeline, "2026-10-08T10:43:00Z")
    assert len(filtered) == 2
    assert [f.event_id for f in filtered] == ["EVT-2", "EVT-3"]


def test_5_during_filtering():
    """Verify during/between returns events strictly within window inclusive."""
    events = sample_events()
    res = TimelineEngine.construct(events=events, gap_threshold_seconds=None)
    filtered = TimelineEngine.filter_between(
        res.timeline,
        start_timestamp="2026-10-08T10:42:00Z",
        end_timestamp="2026-10-08T10:43:10Z"
    )
    assert len(filtered) == 2
    assert [f.event_id for f in filtered] == ["EVT-1", "EVT-2"]


def test_6_between_filtering():
    """Verify between operation on timeline items."""
    events = sample_events()
    res = TimelineEngine.construct(events=events, gap_threshold_seconds=None)
    filtered = TimelineEngine.filter_between(
        res.timeline,
        start_timestamp="2026-10-08T10:43:02Z",
        end_timestamp="2026-10-08T10:44:01Z"
    )
    assert len(filtered) == 2
    assert [f.event_id for f in filtered] == ["EVT-2", "EVT-3"]


def test_7_exact_timestamp_filtering():
    """Verify filter_exact returns matching item."""
    events = sample_events()
    res = TimelineEngine.construct(events=events, gap_threshold_seconds=None)
    filtered = TimelineEngine.filter_exact(res.timeline, "2026-10-08T10:43:02Z")
    assert len(filtered) == 1
    assert filtered[0].event_id == "EVT-2"


def test_8_time_range_filtering():
    """Verify bounding by time_range in construct."""
    events = sample_events()
    tr = TimeRange(start="2026-10-08T10:40:00Z", end="2026-10-08T10:50:00Z")
    res = TimelineEngine.construct(events=events, time_range=tr, gap_threshold_seconds=None)
    assert res.total_events == 3


def test_9_last_n_minutes_filtering():
    """Verify filter_last_n_minutes calculates relative window correctly."""
    events = sample_events()
    res = TimelineEngine.construct(events=events, gap_threshold_seconds=None)
    # Reference at 10:44:30Z, last 2 minutes -> [10:42:30Z, 10:44:30Z]
    filtered = TimelineEngine.filter_last_n_minutes(res.timeline, "2026-10-08T10:44:30Z", minutes=2)
    assert len(filtered) == 2
    assert [f.event_id for f in filtered] == ["EVT-2", "EVT-3"]


def test_10_last_n_hours_filtering():
    """Verify filter_last_n_hours calculates hours window."""
    events = sample_events()
    res = TimelineEngine.construct(events=events, gap_threshold_seconds=None)
    filtered = TimelineEngine.filter_last_n_hours(res.timeline, "2026-10-08T11:00:00Z", hours=1)
    assert len(filtered) == 3


def test_11_missing_evidence_period():
    """Verify gap > threshold produces 'NO VERIFIED OBSERVATION AVAILABLE' marker."""
    events = [
        Event(
            event_id="EVT-1",
            camera_id="CAM-03",
            timestamp="2026-10-08T10:00:00Z",
            event_type="person_detected",
            status="OBSERVED"
        ),
        Event(
            event_id="EVT-2",
            camera_id="CAM-05",
            timestamp="2026-10-08T10:30:00Z",  # 30 minute gap
            event_type="door_opened",
            status="OBSERVED"
        )
    ]
    res = TimelineEngine.construct(events=events, gap_threshold_seconds=300)
    assert res.gap_count >= 1
    gap_items = [i for i in res.timeline if i.is_gap]
    assert len(gap_items) >= 1
    assert gap_items[0].description == "NO VERIFIED OBSERVATION AVAILABLE"
    assert gap_items[0].is_verified is False


def test_12_invalid_timestamp_handling():
    """Verify events with invalid timestamps are tracked in invalid_timestamps without crash."""
    events = [
        Event(
            event_id="EVT-VALID",
            camera_id="CAM-03",
            timestamp="2026-10-08T10:42:13Z",
            event_type="person_detected"
        ),
        {
            "event_id": "EVT-BAD",
            "camera_id": "CAM-03",
            "timestamp": "NOT_A_TIMESTAMP",
            "event_type": "motion"
        }
    ]
    res = TimelineEngine.construct(events=events, gap_threshold_seconds=None)
    assert res.total_events == 1
    assert len(res.invalid_timestamps) == 1
    assert "EVT-BAD" in res.invalid_timestamps[0]


def test_13_conflicting_timestamps():
    """Verify simultaneous observation of same entity on distinct cameras is flagged."""
    events = [
        Event(
            event_id="EVT-A",
            camera_id="CAM-03",
            entity_id="ENT-902",
            timestamp="2026-10-08T10:42:13Z",
            event_type="person_detected"
        ),
        Event(
            event_id="EVT-B",
            camera_id="CAM-07",  # Different camera, identical timestamp
            entity_id="ENT-902",
            timestamp="2026-10-08T10:42:13Z",
            event_type="person_detected"
        )
    ]
    res = TimelineEngine.construct(events=events, gap_threshold_seconds=None)
    assert len(res.conflicting_timestamps) > 0
    assert any("ENT-902" in c for c in res.conflicting_timestamps)


def test_14_duplicate_timestamps():
    """Verify identical timestamps are sorted deterministically using event_id secondary key."""
    events = [
        Event(
            event_id="EVT-Z",
            camera_id="CAM-03",
            timestamp="2026-10-08T10:42:13Z",
            event_type="entry"
        ),
        Event(
            event_id="EVT-A",
            camera_id="CAM-03",
            timestamp="2026-10-08T10:42:13Z",
            event_type="scan"
        )
    ]
    res = TimelineEngine.construct(events=events, gap_threshold_seconds=None)
    assert len(res.timeline) == 2
    assert res.timeline[0].event_id == "EVT-A"
    assert res.timeline[1].event_id == "EVT-Z"


def test_15_empty_timeline():
    """Verify empty input returns single gap marker with standard limitation."""
    res = TimelineEngine.construct(events=[])
    assert len(res.timeline) == 1
    assert res.timeline[0].is_gap is True
    assert res.timeline[0].description == "NO VERIFIED OBSERVATION AVAILABLE"
    assert res.verified_count == 0


def test_16_no_fabricated_events():
    """Verify TimelineEngine never synthesizes fake events not present in source input."""
    events = [
        Event(
            event_id="EVT-ONLY",
            camera_id="CAM-03",
            timestamp="2026-10-08T10:42:13Z",
            event_type="person_detected"
        )
    ]
    res = TimelineEngine.construct(events=events, gap_threshold_seconds=None)
    assert len(res.timeline) == 1
    assert res.timeline[0].event_id == "EVT-ONLY"


def test_17_entity_id_remains_an_identifier_only():
    """Verify entity_id is retained as a token and never converted to personal identity."""
    events = [
        Event(
            event_id="EVT-1",
            camera_id="CAM-03",
            entity_id="ENT-902",
            timestamp="2026-10-08T10:42:13Z",
            event_type="person_detected"
        )
    ]
    res = TimelineEngine.construct(events=events, gap_threshold_seconds=None)
    item = res.timeline[0]
    assert item.entity_id == "ENT-902"
    # Description contains camera and event, not hallucinated person name
    assert "John" not in item.description
    assert "person_detected" in item.description


def test_18_compatibility_with_existing_schemas():
    """Verify TimelineItem instances created can be serialized and deserialized cleanly."""
    events = sample_events()
    res = TimelineEngine.construct(events=events, gap_threshold_seconds=None)
    for item in res.timeline:
        dumped = item.model_dump()
        reconstructed = TimelineItem.model_validate(dumped)
        assert reconstructed == item


@pytest.mark.asyncio
async def test_19_compatibility_with_retrieval_layer():
    """Verify events and evidence fetched by retrieval layer feed directly into TimelineEngine."""
    client = MockBackendClient()
    evt_service = EventRetrievalService(client)
    ev_service = EvidenceRetrievalService(client)

    evt_res = await evt_service.search(camera_ids=["CAM-03"])
    ev_res = await ev_service.get_for_events([e.event_id for e in evt_res.events])

    timeline_res = TimelineEngine.construct(
        events=evt_res.events,
        evidence=ev_res.evidence_items
    )
    assert timeline_res.total_events >= 1
    assert timeline_res.timeline[0].evidence_id == "EVD-4091"


@pytest.mark.asyncio
async def test_20_compatibility_with_orchestrator():
    """Verify InvestigationOrchestrator generates a fully grounded chronological timeline."""
    client = MockBackendClient()
    orchestrator = InvestigationOrchestrator(backend_client=client)

    req = InvestigationRequest(
        investigation_id="INV-TL-TEST",
        query="Investigate sequence of events",
        incident_id="INC-8821"
    )
    result = await orchestrator.orchestrate(req)
    assert result.status == InvestigationStatus.COMPLETED
    assert len(result.timeline) >= 2
    # Verify chronological sequence
    t1 = result.timeline[0].timestamp
    t2 = result.timeline[1].timestamp
    assert t1 <= t2
