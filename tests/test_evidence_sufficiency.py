"""
Tests for Module 4 Evidence Sufficiency Engine.
Validates the 6 core checks: availability, timestamp reliability, source identity,
observation verification, contradiction detection, and sufficiency assessment.
"""
import pytest

from evidence.sufficiency import (
    EvidenceSufficiencyEngine,
    SufficiencyResult,
    SufficiencyStatus,
)
from schemas.events import Event
from schemas.evidence import Evidence


def test_1_sufficient_evidence():
    """Verify clean, verified evidence items return SUFFICIENT status."""
    events = [
        Event(
            event_id="EVT-1029",
            camera_id="CAM-03",
            timestamp="2026-10-08T10:42:13Z",
            event_type="person_detected",
            status="OBSERVED"
        )
    ]
    evidence = [
        Evidence(
            evidence_id="EVD-4091",
            camera_id="CAM-03",
            timestamp_start="2026-10-08T10:42:13Z",
            verification_status="VERIFIED"
        )
    ]
    result = EvidenceSufficiencyEngine.evaluate(evidence_items=evidence, events=events)
    assert result.status == SufficiencyStatus.SUFFICIENT
    assert result.is_sufficient is True
    assert "EVD-4091" in result.evidence_ids
    assert len(result.reasons) > 0


def test_2_no_evidence():
    """Verify empty evidence and event collections produce INSUFFICIENT status with standard limitation."""
    result = EvidenceSufficiencyEngine.evaluate(evidence_items=[], events=[])
    assert result.status == SufficiencyStatus.INSUFFICIENT
    assert result.is_insufficient is True
    assert "I don't know — insufficient evidence." in result.limitations
    assert len(result.missing_information) > 0


def test_3_missing_timestamp():
    """Verify items lacking valid timestamps are flagged and lead to INSUFFICIENT status."""
    evidence = [
        {
            "evidence_id": "EVD-BAD-TS",
            "camera_id": "CAM-03",
            "timestamp_start": "",  # missing timestamp
            "verification_status": "VERIFIED"
        }
    ]
    result = EvidenceSufficiencyEngine.evaluate(evidence_items=evidence)
    assert result.status == SufficiencyStatus.INSUFFICIENT
    assert any("timestamp" in m.lower() for m in result.missing_information)


def test_4_unknown_camera_source():
    """Verify observations with unknown camera origins are flagged."""
    evidence = [
        {
            "evidence_id": "EVD-NO-CAM",
            "camera_id": "",  # missing camera ID
            "timestamp_start": "2026-10-08T10:42:13Z",
            "verification_status": "VERIFIED"
        }
    ]
    result = EvidenceSufficiencyEngine.evaluate(evidence_items=evidence)
    assert result.status == SufficiencyStatus.INSUFFICIENT
    assert any("camera source" in m.lower() for m in result.missing_information)


def test_5_event_not_verified():
    """Verify events marked UNVERIFIED do not satisfy sufficiency threshold."""
    events = [
        Event(
            event_id="EVT-UNVERIFIED",
            camera_id="CAM-03",
            timestamp="2026-10-08T10:42:13Z",
            event_type="motion_detected",
            status="UNVERIFIED"
        )
    ]
    result = EvidenceSufficiencyEngine.evaluate(events=events, evidence_items=[])
    assert result.status == SufficiencyStatus.INSUFFICIENT
    assert result.is_insufficient is True
    assert any("unverified" in m.lower() for m in result.missing_information)


def test_6_insufficient_evidence_when_sources_offline():
    """Verify that when cameras are OFFLINE, blind-spot limitation is enforced."""
    events = [
        Event(
            event_id="EVT-1029",
            camera_id="CAM-04",
            timestamp="2026-10-08T10:42:13Z",
            event_type="person_detected",
            status="OBSERVED"
        )
    ]
    cameras = {
        "CAM-04": {"camera_id": "CAM-04", "status": "OFFLINE"}
    }
    result = EvidenceSufficiencyEngine.evaluate(events=events, cameras=cameras)
    assert result.status == SufficiencyStatus.INSUFFICIENT
    assert any("not reliably observable" in lim.lower() for lim in result.limitations)


def test_7_contradictory_evidence_explicit_flag():
    """Verify that explicit CONFLICTED verification status produces CONFLICTED result."""
    evidence = [
        Evidence(
            evidence_id="EVD-4091",
            camera_id="CAM-03",
            timestamp_start="2026-10-08T10:42:13Z",
            verification_status="CONFLICTED"
        )
    ]
    result = EvidenceSufficiencyEngine.evaluate(evidence_items=evidence)
    assert result.status == SufficiencyStatus.CONFLICTED
    assert result.is_conflicted is True
    assert "Conflicting evidence detected." in result.limitations
    assert len(result.contradictions) > 0


def test_8_multiple_evidence_items_correlation():
    """Verify handling of multiple coherent evidence items."""
    evidence = [
        Evidence(
            evidence_id="EVD-4091",
            camera_id="CAM-03",
            timestamp_start="2026-10-08T10:42:13Z",
            verification_status="VERIFIED"
        ),
        Evidence(
            evidence_id="EVD-4092",
            camera_id="CAM-05",
            timestamp_start="2026-10-08T10:43:02Z",
            verification_status="VERIFIED"
        )
    ]
    events = [
        Event(
            event_id="EVT-1029",
            camera_id="CAM-03",
            timestamp="2026-10-08T10:42:13Z",
            event_type="person_detected",
            status="OBSERVED"
        )
    ]
    result = EvidenceSufficiencyEngine.evaluate(evidence_items=evidence, events=events)
    assert result.status == SufficiencyStatus.SUFFICIENT
    assert "EVD-4091" in result.evidence_ids
    assert "EVD-4092" in result.evidence_ids


def test_9_incomplete_evidence():
    """Verify evidence marked FAILED verification results in INSUFFICIENT."""
    evidence = [
        Evidence(
            evidence_id="EVD-FAILED",
            camera_id="CAM-03",
            timestamp_start="2026-10-08T10:42:13Z",
            verification_status="FAILED"
        )
    ]
    result = EvidenceSufficiencyEngine.evaluate(evidence_items=evidence)
    assert result.status == SufficiencyStatus.INSUFFICIENT


def test_10_no_fabricated_evidence():
    """Verify engine returns only real supplied evidence IDs and never invents synthetic ones."""
    events = [
        Event(
            event_id="EVT-1029",
            camera_id="CAM-03",
            timestamp="2026-10-08T10:42:13Z",
            event_type="person_detected",
            status="OBSERVED"
        )
    ]
    result = EvidenceSufficiencyEngine.evaluate(events=events, evidence_items=[])
    assert result.status == SufficiencyStatus.SUFFICIENT
    assert result.evidence_ids == []  # No fake evidence IDs created


def test_11_deterministic_result():
    """Verify that multiple consecutive runs with identical inputs produce identical results."""
    events = [
        Event(
            event_id="EVT-1029",
            camera_id="CAM-03",
            timestamp="2026-10-08T10:42:13Z",
            event_type="person_detected",
            status="OBSERVED"
        )
    ]
    res1 = EvidenceSufficiencyEngine.evaluate(events=events)
    res2 = EvidenceSufficiencyEngine.evaluate(events=events)
    assert res1.status == res2.status
    assert res1.reasons == res2.reasons
    assert res1.limitations == res2.limitations


def test_12_spatial_contradiction_detection():
    """Verify that reporting the exact same entity at two different cameras simultaneously flags CONFLICTED."""
    events = [
        Event(
            event_id="EVT-1",
            camera_id="CAM-03",
            entity_id="ENT-902",
            timestamp="2026-10-08T10:42:13Z",
            event_type="person_detected",
            status="OBSERVED"
        ),
        Event(
            event_id="EVT-2",
            camera_id="CAM-07",  # different camera at exact same timestamp
            entity_id="ENT-902",
            timestamp="2026-10-08T10:42:13Z",
            event_type="person_detected",
            status="OBSERVED"
        )
    ]
    result = EvidenceSufficiencyEngine.evaluate(events=events)
    assert result.status == SufficiencyStatus.CONFLICTED
    assert result.is_conflicted is True
    assert any("Spatial impossibility" in c for c in result.contradictions)
