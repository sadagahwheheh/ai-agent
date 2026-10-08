"""
Tests for Module 4 Cross-Camera / Entity Correlation Engine.
Validates multi-camera grouping, chronological ordering, identity protection,
preservation of source identifiers, zero-fabrication rules, and compatibility with the orchestrator.
"""
import pytest

from agent.orchestrator import InvestigationOrchestrator
from evidence.retrieval import EvidenceRetrievalService
from evidence.sufficiency import EvidenceSufficiencyEngine, SufficiencyStatus
from integration.mock_client import MockBackendClient
from investigation.entity_correlation import (
    CorrelationStatus,
    CrossCameraCorrelationResult,
    EntityCorrelationEngine,
    EntityCorrelationTrajectory,
)
from investigation.event_search import EventRetrievalService
from schemas.events import Event
from schemas.evidence import Evidence
from schemas.investigation import InvestigationRequest, InvestigationStatus


def test_1_same_entity_across_two_cameras():
    """Verify observations of the same entity on two cameras are correlated."""
    events = [
        Event(
            event_id="EVT-1",
            camera_id="CAM-03",
            timestamp="2026-10-08T10:42:13Z",
            event_type="person_detected",
            entity_id="ENT-902",
            status="OBSERVED"
        ),
        Event(
            event_id="EVT-2",
            camera_id="CAM-05",
            timestamp="2026-10-08T10:43:02Z",
            event_type="restricted_zone_entry",
            entity_id="ENT-902",
            status="OBSERVED"
        )
    ]
    res = EntityCorrelationEngine.correlate(events=events)
    assert res.status == CorrelationStatus.CORRELATED
    assert len(res.trajectories) == 1
    traj = res.trajectories[0]
    assert traj.entity_id == "ENT-902"
    assert traj.is_cross_camera is True
    assert traj.camera_ids == ["CAM-03", "CAM-05"]
    assert traj.status == CorrelationStatus.CORRELATED


def test_2_same_entity_across_multiple_cameras():
    """Verify correlation across three or more cameras."""
    events = [
        Event(event_id="E1", camera_id="CAM-01", timestamp="2026-10-08T10:00:00Z", event_type="entry", entity_id="ENT-X"),
        Event(event_id="E2", camera_id="CAM-02", timestamp="2026-10-08T10:02:00Z", event_type="hallway", entity_id="ENT-X"),
        Event(event_id="E3", camera_id="CAM-03", timestamp="2026-10-08T10:05:00Z", event_type="exit", entity_id="ENT-X"),
    ]
    res = EntityCorrelationEngine.correlate(events=events)
    assert res.status == CorrelationStatus.CORRELATED
    traj = res.trajectories[0]
    assert traj.camera_count == 3
    assert traj.camera_ids == ["CAM-01", "CAM-02", "CAM-03"]


def test_3_chronological_cross_camera_ordering():
    """Verify observations delivered out-of-order are sorted strictly chronologically."""
    events = [
        Event(event_id="E2", camera_id="CAM-05", timestamp="2026-10-08T10:43:02Z", event_type="b", entity_id="ENT-1"),
        Event(event_id="E1", camera_id="CAM-03", timestamp="2026-10-08T10:42:13Z", event_type="a", entity_id="ENT-1"),
    ]
    res = EntityCorrelationEngine.correlate(events=events)
    traj = res.trajectories[0]
    assert traj.observations[0].event_id == "E1"
    assert traj.observations[1].event_id == "E2"
    assert traj.observations[0].timestamp < traj.observations[1].timestamp


def test_4_different_entity_ids_remain_separate():
    """Verify distinct entity_ids are never merged or blended together."""
    events = [
        Event(event_id="E1", camera_id="CAM-03", timestamp="2026-10-08T10:42:13Z", event_type="a", entity_id="ENT-A"),
        Event(event_id="E2", camera_id="CAM-05", timestamp="2026-10-08T10:43:02Z", event_type="b", entity_id="ENT-B"),
    ]
    res = EntityCorrelationEngine.correlate(events=events)
    assert res.total_entities_tracked == 2
    ent_ids = [t.entity_id for t in res.trajectories]
    assert ent_ids == ["ENT-A", "ENT-B"]
    # Neither is cross-camera individually
    assert all(not t.is_cross_camera for t in res.trajectories)


def test_5_missing_entity_id():
    """Verify events lacking entity_id are excluded from tracking and noted in limitations."""
    events = [
        Event(event_id="E1", camera_id="CAM-03", timestamp="2026-10-08T10:42:13Z", event_type="a", entity_id="ENT-1"),
        Event(event_id="E2", camera_id="CAM-05", timestamp="2026-10-08T10:43:02Z", event_type="b", entity_id=None),
    ]
    res = EntityCorrelationEngine.correlate(events=events)
    assert res.total_entities_tracked == 1
    assert any("lacked authoritative tracking identifiers" in lim for lim in res.limitations)


def test_6_conflicting_entity_ids():
    """Verify spatial/temporal impossibility for same entity is flagged as CONFLICTED."""
    events = [
        Event(event_id="E1", camera_id="CAM-03", timestamp="2026-10-08T10:42:13Z", event_type="a", entity_id="ENT-1"),
        Event(event_id="E2", camera_id="CAM-07", timestamp="2026-10-08T10:42:13Z", event_type="b", entity_id="ENT-1"),
    ]
    res = EntityCorrelationEngine.correlate(events=events)
    assert res.status == CorrelationStatus.CONFLICTED
    assert len(res.conflicts) > 0
    assert res.trajectories[0].status == CorrelationStatus.CONFLICTED


def test_7_missing_tracking_information():
    """Verify when no events contain tracking tokens, returns INSUFFICIENT_TRACKING."""
    events = [
        Event(event_id="E1", camera_id="CAM-03", timestamp="2026-10-08T10:42:13Z", event_type="a", entity_id=None),
    ]
    res = EntityCorrelationEngine.correlate(events=events)
    assert res.status == CorrelationStatus.INSUFFICIENT_TRACKING
    assert "Entity correlation unavailable — insufficient tracking evidence." in res.limitations


def test_8_preservation_of_event_id():
    """Verify event_id is preserved on every correlated observation."""
    events = [
        Event(event_id="EVT-SPECIFIC-ID", camera_id="CAM-03", timestamp="2026-10-08T10:42:13Z", event_type="a", entity_id="ENT-1")
    ]
    res = EntityCorrelationEngine.correlate(events=events)
    assert res.trajectories[0].observations[0].event_id == "EVT-SPECIFIC-ID"


def test_9_preservation_of_evidence_id():
    """Verify evidence_id is preserved and linked to observation."""
    events = [
        Event(event_id="EVT-1", camera_id="CAM-03", timestamp="2026-10-08T10:42:13Z", event_type="a", entity_id="ENT-1", evidence_id="EVD-4091")
    ]
    evidence = [
        Evidence(evidence_id="EVD-4091", camera_id="CAM-03", timestamp_start="2026-10-08T10:42:13Z", event_id="EVT-1")
    ]
    res = EntityCorrelationEngine.correlate(events=events, evidence=evidence)
    assert res.trajectories[0].observations[0].evidence_id == "EVD-4091"
    assert "EVD-4091" in res.trajectories[0].evidence_ids


def test_10_preservation_of_camera_id():
    """Verify camera_id is preserved on every observation."""
    events = [
        Event(event_id="EVT-1", camera_id="CAM-03", timestamp="2026-10-08T10:42:13Z", event_type="a", entity_id="ENT-1"),
        Event(event_id="EVT-2", camera_id="CAM-05", timestamp="2026-10-08T10:43:02Z", event_type="b", entity_id="ENT-1")
    ]
    res = EntityCorrelationEngine.correlate(events=events)
    cams = [o.camera_id for o in res.trajectories[0].observations]
    assert cams == ["CAM-03", "CAM-05"]


def test_11_preservation_of_timestamps():
    """Verify exact original timestamps are maintained."""
    raw_ts = "2026-10-08T10:42:13.999Z"
    events = [
        Event(event_id="EVT-1", camera_id="CAM-03", timestamp=raw_ts, event_type="a", entity_id="ENT-1")
    ]
    res = EntityCorrelationEngine.correlate(events=events)
    assert res.trajectories[0].observations[0].timestamp == raw_ts


def test_12_no_identity_inference():
    """Verify description only references tracking token entity_id and never real-world names."""
    events = [
        Event(event_id="EVT-1", camera_id="CAM-03", timestamp="2026-10-08T10:42:13Z", event_type="a", entity_id="ENT-902"),
        Event(event_id="EVT-2", camera_id="CAM-05", timestamp="2026-10-08T10:43:02Z", event_type="b", entity_id="ENT-902")
    ]
    res = EntityCorrelationEngine.correlate(events=events)
    desc = res.trajectories[0].description
    assert "entity_id=ENT-902" in desc
    assert "person" not in desc.lower() or "tracked entity" in desc.lower()
    assert "suspect" not in desc.lower()
    assert "employee" not in desc.lower()


def test_13_no_fabricated_movement():
    """Verify description states observations without fabricating physical transitions."""
    events = [
        Event(event_id="EVT-1", camera_id="CAM-03", timestamp="2026-10-08T10:42:13Z", event_type="a", entity_id="ENT-1"),
        Event(event_id="EVT-2", camera_id="CAM-05", timestamp="2026-10-08T10:43:02Z", event_type="b", entity_id="ENT-1")
    ]
    res = EntityCorrelationEngine.correlate(events=events)
    desc = res.trajectories[0].description
    assert "was observed across multiple cameras" in desc
    assert "walked from" not in desc
    assert "ran from" not in desc


def test_14_insufficient_tracking_handling():
    """Verify empty events list produces INSUFFICIENT_TRACKING."""
    res = EntityCorrelationEngine.correlate(events=[])
    assert res.status == CorrelationStatus.INSUFFICIENT_TRACKING
    assert len(res.trajectories) == 0


def test_15_conflicted_tracking_handling():
    """Verify multiple conflicts in trajectory are captured in result."""
    events = [
        Event(event_id="E1", camera_id="CAM-01", timestamp="2026-10-08T10:00:00Z", event_type="a", entity_id="ENT-1"),
        Event(event_id="E2", camera_id="CAM-02", timestamp="2026-10-08T10:00:00Z", event_type="b", entity_id="ENT-1"),
    ]
    res = EntityCorrelationEngine.correlate(events=events)
    assert res.status == CorrelationStatus.CONFLICTED
    assert len(res.conflicts) == 1


def test_16_deterministic_correlation():
    """Verify that multiple runs with identical inputs produce identical outcomes."""
    events = [
        Event(event_id="E2", camera_id="CAM-05", timestamp="2026-10-08T10:43:02Z", event_type="b", entity_id="ENT-1"),
        Event(event_id="E1", camera_id="CAM-03", timestamp="2026-10-08T10:42:13Z", event_type="a", entity_id="ENT-1"),
    ]
    res1 = EntityCorrelationEngine.correlate(events=events)
    res2 = EntityCorrelationEngine.correlate(events=events)
    assert res1.status == res2.status
    assert res1.trajectories[0].camera_ids == res2.trajectories[0].camera_ids


def test_17_compatibility_with_timeline_engine():
    """Verify trajectory embeds TimelineEngine output cleanly."""
    events = [
        Event(event_id="E1", camera_id="CAM-03", timestamp="2026-10-08T10:42:13Z", event_type="a", entity_id="ENT-1"),
        Event(event_id="E2", camera_id="CAM-05", timestamp="2026-10-08T10:43:02Z", event_type="b", entity_id="ENT-1"),
    ]
    res = EntityCorrelationEngine.correlate(events=events)
    traj = res.trajectories[0]
    assert len(traj.timeline) == 2
    assert traj.timeline[0].timestamp < traj.timeline[1].timestamp


@pytest.mark.asyncio
async def test_18_compatibility_with_evidence_sufficiency_engine():
    """Verify correlated events pass EvidenceSufficiencyEngine evaluation."""
    events = [
        Event(event_id="EVT-1029", camera_id="CAM-03", timestamp="2026-10-08T10:42:13Z", event_type="a", entity_id="ENT-902", status="OBSERVED")
    ]
    evidence = [
        Evidence(evidence_id="EVD-4091", camera_id="CAM-03", timestamp_start="2026-10-08T10:42:13Z", verification_status="VERIFIED")
    ]
    res = EntityCorrelationEngine.correlate(events=events, evidence=evidence)
    sufficiency = EvidenceSufficiencyEngine.evaluate(evidence_items=evidence, events=events)
    assert sufficiency.status == SufficiencyStatus.SUFFICIENT
    assert res.trajectories[0].entity_id == "ENT-902"


@pytest.mark.asyncio
async def test_19_compatibility_with_investigation_orchestrator():
    """Verify orchestrator runs entity correlation stage producing cross-camera inferences."""
    client = MockBackendClient()
    orchestrator = InvestigationOrchestrator(backend_client=client)

    req = InvestigationRequest(
        investigation_id="INV-CORR-TEST",
        query="Investigate movement of entity ENT-902",
        incident_id="INC-8821"
    )
    result = await orchestrator.orchestrate(req)
    assert result.status == InvestigationStatus.COMPLETED
    # Check that inferences include cross-camera entity correlation
    assert any("ENT-902" in inf for inf in result.inferences)
    assert any("CAM-03" in inf and "CAM-05" in inf for inf in result.inferences)
