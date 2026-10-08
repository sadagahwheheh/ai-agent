"""
Tests for Module 4 Shared Schemas and Identifiers.
Validates Pydantic contracts, canonical IDs, serialization, bounds checking, and status constraints.
"""
import pytest
from pydantic import ValidationError

from schemas import (
    Camera,
    CameraHealthState,
    Event,
    Evidence,
    Incident,
    InvestigationRequest,
    InvestigationResult,
    InvestigationStatus,
    SecurityMemory,
    Threat,
    ThreatSeverity,
    TimelineItem,
    TimeRange,
)


def test_canonical_id_validation():
    # Valid IDs with whitespace stripping
    event = Event(
        event_id="  EVT-1029  ",
        camera_id=" CAM-03 ",
        timestamp="2026-10-08T10:42:13Z",
        event_type="person_detected"
    )
    assert event.event_id == "EVT-1029"
    assert event.camera_id == "CAM-03"

    # Reject empty string ID
    with pytest.raises(ValidationError):
        Event(
            event_id="   ",
            camera_id="CAM-03",
            timestamp="2026-10-08T10:42:13Z",
            event_type="person_detected"
        )


def test_event_schema_serialization_and_optional_fields():
    # Optional fields default to None or defaults
    event = Event(
        event_id="EVT-1029",
        camera_id="CAM-03",
        timestamp="2026-10-08T10:42:13Z",
        event_type="person_detected",
        entity_id="ENT-902",
        zone_id="ZONE-01",
        confidence=0.95
    )
    dumped = event.model_dump()
    assert dumped["event_id"] == "EVT-1029"
    assert dumped["entity_id"] == "ENT-902"
    assert dumped["confidence"] == 0.95
    assert dumped["source"] == "video_intelligence"
    assert dumped["status"] == "OBSERVED"

    # JSON roundtrip
    json_str = event.model_dump_json()
    reconstructed = Event.model_validate_json(json_str)
    assert reconstructed == event

    # Confidence validation bounds
    with pytest.raises(ValidationError):
        Event(
            event_id="EVT-1",
            camera_id="CAM-1",
            timestamp="2026-10-08T10:00:00Z",
            event_type="test",
            confidence=1.5
        )
    with pytest.raises(ValidationError):
        Event(
            event_id="EVT-1",
            camera_id="CAM-1",
            timestamp="2026-10-08T10:00:00Z",
            event_type="test",
            confidence=-0.1
        )


def test_evidence_schema():
    evidence = Evidence(
        evidence_id="EVD-4091",
        camera_id="CAM-03",
        timestamp_start="2026-10-08T10:42:13Z",
        clip_reference="storage://clips/CAM-03/20261008_104213.mp4",
        confidence=0.92,
        verification_status="VERIFIED"
    )
    assert evidence.evidence_id == "EVD-4091"
    assert evidence.timestamp_end is None

    # Empty timestamp_start rejected
    with pytest.raises(ValidationError):
        Evidence(
            evidence_id="EVD-4091",
            camera_id="CAM-03",
            timestamp_start="   "
        )


def test_investigation_request_schema():
    req = InvestigationRequest(
        investigation_id="INV-001",
        query="What happened at the main gate?",
        time_range=TimeRange(start="2026-10-08T10:00:00Z", end="2026-10-08T11:00:00Z"),
        camera_ids=["CAM-03"],
        zone_ids=["ZONE-01"]
    )
    assert req.investigation_id == "INV-001"
    assert req.time_range.start == "2026-10-08T10:00:00Z"

    # Reject empty query
    with pytest.raises(ValidationError):
        InvestigationRequest(
            investigation_id="INV-001",
            query="   "
        )


def test_investigation_result_statuses():
    # Valid statuses
    valid_statuses = [
        InvestigationStatus.COMPLETED,
        InvestigationStatus.PROCESSING,
        InvestigationStatus.INSUFFICIENT_EVIDENCE,
        InvestigationStatus.CONFLICTED_EVIDENCE,
        InvestigationStatus.FAILED,
    ]
    for status in valid_statuses:
        res = InvestigationResult(
            investigation_id="INV-001",
            status=status,
            answer=f"Test answer for status {status.value}",
            observed_facts=["Person detected at CAM-03."],
            inferences=["Unauthorized movement observed."],
            timeline=[
                TimelineItem(
                    timestamp="2026-10-08T10:42:13Z",
                    camera_id="CAM-03",
                    description="Person detected at Main Gate",
                    event_id="EVT-1029",
                    entity_id="ENT-902"
                )
            ],
            confidence=0.88
        )
        assert res.status == status
        assert len(res.timeline) == 1
        assert res.timeline[0].entity_id == "ENT-902"

    # Invalid status rejected
    with pytest.raises(ValidationError):
        InvestigationResult(
            investigation_id="INV-001",
            status="INVALID_STATUS",
            answer="Should fail"
        )


def test_security_memory_schema():
    mem = SecurityMemory(
        memory_id="MEM-301",
        type="camera_mapping",
        value={"camera_id": "CAM-03", "location": "Main Gate"},
        source="facility_map_v1",
        created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00Z",
        status="ACTIVE"
    )
    assert mem.memory_id == "MEM-301"
    assert mem.value["location"] == "Main Gate"

    # Empty source rejected
    with pytest.raises(ValidationError):
        SecurityMemory(
            memory_id="MEM-301",
            type="camera_mapping",
            value="some value",
            source="",
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-01-01T00:00:00Z"
        )


def test_camera_and_threat_schemas():
    cam = Camera(
        camera_id="CAM-04",
        name="Perimeter East",
        status=CameraHealthState.OFFLINE
    )
    assert cam.status == CameraHealthState.OFFLINE

    threat = Threat(
        threat_id="THR-5501",
        incident_id="INC-8821",
        severity=ThreatSeverity.HIGH,
        score=0.91,
        reason="Zone violation"
    )
    assert threat.severity == ThreatSeverity.HIGH

    inc = Incident(
        incident_id="INC-8821",
        title="Restricted zone breach",
        start_time="2026-10-08T10:42:00Z",
        associated_events=["EVT-1029"],
        associated_threat_id="THR-5501"
    )
    assert inc.incident_id == "INC-8821"
    assert len(inc.associated_events) == 1
