"""
Tests for Module 4: Step 14 - Evidence Provenance Layer.
Covers all 20 required test scenarios:
1. complete provenance chain
2. evidence_id preservation
3. event_id preservation
4. camera_id preservation
5. timestamp preservation
6. source_video preservation
7. clip_reference preservation
8. reason preservation
9. confidence preservation
10. missing evidence handling
11. missing timestamp handling
12. missing camera handling
13. conflicted evidence preservation
14. insufficient evidence handling
15. cross-camera provenance
16. no fabricated IDs
17. no fabricated timestamps
18. no fabricated video references
19. deterministic provenance
20. compatibility with Steps 1–13
"""
import pytest

from evidence.provenance import (
    EvidenceProvenanceEngine,
    EvidenceProvenanceItem,
    ProvenanceTrackingResult,
)
from evidence.sufficiency import SufficiencyResult, SufficiencyStatus
from investigation.entity_correlation import CorrelationStatus, EntityCorrelationTrajectory
from reasoning.confidence_evaluation import ConfidenceResult, ConfidenceStatus
from schemas.events import Event
from schemas.evidence import Evidence
from schemas.investigation import TimelineItem


@pytest.fixture
def sample_event():
    return Event(
        event_id="EVT-PROV-101",
        camera_id="CAM-01",
        timestamp="2026-10-08T10:00:00Z",
        event_type="perimeter_breach",
        confidence=0.95,
        status="OBSERVED",
        zone_id="Z-01",
        entity_id="ENT-77"
    )


@pytest.fixture
def sample_evidence():
    return Evidence(
        evidence_id="EVI-PROV-201",
        event_id="EVT-PROV-101",
        camera_id="CAM-01",
        timestamp_start="2026-10-08T10:00:00Z",
        source_video="s3://streams/cam01/20261008_100000.mp4",
        clip_reference="clip_frame_402.jpg",
        confidence=0.90,
        verification_status="VERIFIED"
    )


# 1. complete provenance chain
def test_complete_provenance_chain(sample_event, sample_evidence):
    answer = "Perimeter breach observed at North Gate."
    reason = "Video clip confirms motion across boundary."

    result = EvidenceProvenanceEngine.track_provenance(
        evidence=[sample_evidence],
        events=[sample_event],
        answer=answer,
        reason=reason,
        confidence=0.92
    )

    assert len(result.items) == 1
    item = result.items[0]
    # Chain: ANSWER -> REASON -> EVIDENCE ID -> EVENT ID -> CAMERA ID -> TIMESTAMP -> ORIGINAL VIDEO/REF
    assert item.answer_reference == answer
    assert item.reason == reason
    assert item.evidence_id == "EVI-PROV-201"
    assert item.event_id == "EVT-PROV-101"
    assert item.camera_id == "CAM-01"
    assert item.timestamp == "2026-10-08T10:00:00Z"
    assert item.source_video == "s3://streams/cam01/20261008_100000.mp4"
    assert item.clip_reference == "clip_frame_402.jpg"
    assert item.confidence == 0.92


# 2. evidence_id preservation
def test_evidence_id_preservation(sample_event, sample_evidence):
    result = EvidenceProvenanceEngine.track_provenance(
        evidence=[sample_evidence],
        events=[sample_event]
    )

    assert result.evidence_ids == ["EVI-PROV-201"]
    assert result.items[0].evidence_id == "EVI-PROV-201"


# 3. event_id preservation
def test_event_id_preservation(sample_event, sample_evidence):
    result = EvidenceProvenanceEngine.track_provenance(
        evidence=[sample_evidence],
        events=[sample_event]
    )

    assert result.event_ids == ["EVT-PROV-101"]
    assert result.items[0].event_id == "EVT-PROV-101"


# 4. camera_id preservation
def test_camera_id_preservation(sample_event, sample_evidence):
    result = EvidenceProvenanceEngine.track_provenance(
        evidence=[sample_evidence],
        events=[sample_event]
    )

    assert result.camera_ids == ["CAM-01"]
    assert result.items[0].camera_id == "CAM-01"


# 5. timestamp preservation
def test_timestamp_preservation(sample_event, sample_evidence):
    result = EvidenceProvenanceEngine.track_provenance(
        evidence=[sample_evidence],
        events=[sample_event]
    )

    # Exact timestamp without modification or rounding
    assert result.items[0].timestamp == "2026-10-08T10:00:00Z"


# 6. source_video preservation
def test_source_video_preservation(sample_event, sample_evidence):
    result = EvidenceProvenanceEngine.track_provenance(
        evidence=[sample_evidence],
        events=[sample_event]
    )

    assert result.items[0].source_video == "s3://streams/cam01/20261008_100000.mp4"


# 7. clip_reference preservation
def test_clip_reference_preservation(sample_event, sample_evidence):
    result = EvidenceProvenanceEngine.track_provenance(
        evidence=[sample_evidence],
        events=[sample_event]
    )

    assert result.items[0].clip_reference == "clip_frame_402.jpg"


# 8. reason preservation
def test_reason_preservation(sample_event, sample_evidence):
    custom_reason = "Operator audit verified boundary tripwire activation."
    result = EvidenceProvenanceEngine.track_provenance(
        evidence=[sample_evidence],
        events=[sample_event],
        reason=custom_reason
    )

    assert result.items[0].reason == custom_reason


# 9. confidence preservation
def test_confidence_preservation(sample_event, sample_evidence):
    conf_res = ConfidenceResult(
        confidence=0.87,
        confidence_status=ConfidenceStatus.AVAILABLE,
        contributing_factors={"ai_video_confidence": 0.87}
    )

    result = EvidenceProvenanceEngine.track_provenance(
        evidence=[sample_evidence],
        events=[sample_event],
        confidence_result=conf_res
    )

    # Preserves Step 13 confidence without modification
    assert result.items[0].confidence == 0.87


# 10. missing evidence handling
def test_missing_evidence_handling(sample_event):
    result = EvidenceProvenanceEngine.track_provenance(
        evidence=[],
        events=[sample_event],
        answer="Suspicious movement observed."
    )

    assert result.items == []
    assert result.is_sufficient is False
    assert "Evidence provenance unavailable — supporting evidence was not provided." in result.limitations


# 11. missing timestamp handling
def test_missing_timestamp_handling():
    evidence_no_ts = {
        "evidence_id": "EVI-NOTS-1",
        "camera_id": "CAM-01",
        "timestamp_start": None,
        "verification_status": "VERIFIED"
    }

    result = EvidenceProvenanceEngine.track_provenance(
        evidence=[evidence_no_ts],
        events=[]
    )

    # Timestamp must not be guessed or fabricated
    assert result.items[0].timestamp is None
    assert any("Timestamp unavailable" in lim for lim in result.limitations)


# 12. missing camera handling
def test_missing_camera_handling():
    evidence_no_cam = {
        "evidence_id": "EVI-NOCAM-1",
        "camera_id": None,
        "timestamp_start": "2026-10-08T10:00:00Z",
        "verification_status": "VERIFIED"
    }

    result = EvidenceProvenanceEngine.track_provenance(
        evidence=[evidence_no_cam],
        events=[]
    )

    # Camera must not be guessed or fabricated
    assert result.items[0].camera_id is None
    assert any("Camera origin unavailable" in lim for lim in result.limitations)


# 13. conflicted evidence preservation
def test_conflicted_evidence_preservation(sample_event):
    conflicted_evidence = Evidence(
        evidence_id="EVI-CONF-99",
        event_id="EVT-PROV-101",
        camera_id="CAM-01",
        timestamp_start="2026-10-08T10:00:00Z",
        verification_status="CONFLICTED"
    )

    result = EvidenceProvenanceEngine.track_provenance(
        evidence=[conflicted_evidence],
        events=[sample_event]
    )

    # Contradictory evidence is NOT hidden or removed
    assert result.has_conflict is True
    assert len(result.items) == 1
    assert result.items[0].evidence_id == "EVI-CONF-99"
    assert result.items[0].is_conflicted is True
    assert any("CONFLICTED verification status" in lim for lim in result.limitations)


# 14. insufficient evidence handling(sample_event, sample_evidence):
def test_insufficient_evidence_handling(sample_event, sample_evidence):
    suff_res = SufficiencyResult(
        status=SufficiencyStatus.INSUFFICIENT,
        reasons=["Coverage incomplete"],
        limitations=["I don't know — insufficient evidence."]
    )

    result = EvidenceProvenanceEngine.track_provenance(
        evidence=[sample_evidence],
        events=[sample_event],
        sufficiency_result=suff_res
    )

    assert result.is_sufficient is False
    assert any("insufficient evidence" in lim for lim in result.limitations)


# 15. cross-camera provenance
def test_cross_camera_provenance():
    ev1 = Evidence(
        evidence_id="EVI-C1",
        event_id="EVT-C1",
        camera_id="CAM-01",
        timestamp_start="2026-10-08T10:00:00Z",
        verification_status="VERIFIED"
    )
    ev2 = Evidence(
        evidence_id="EVI-C2",
        event_id="EVT-C2",
        camera_id="CAM-02",
        timestamp_start="2026-10-08T10:05:00Z",
        verification_status="VERIFIED"
    )
    evt1 = Event(
        event_id="EVT-C1",
        camera_id="CAM-01",
        timestamp="2026-10-08T10:00:00Z",
        event_type="person_detection",
        entity_id="ENT-88"
    )
    evt2 = Event(
        event_id="EVT-C2",
        camera_id="CAM-02",
        timestamp="2026-10-08T10:05:00Z",
        event_type="person_detection",
        entity_id="ENT-88"
    )
    traj = EntityCorrelationTrajectory(
        entity_id="ENT-88",
        status=CorrelationStatus.CORRELATED,
        camera_ids=["CAM-01", "CAM-02"],
        event_ids=["EVT-C1", "EVT-C2"]
    )

    result = EvidenceProvenanceEngine.track_provenance(
        evidence=[ev1, ev2],
        events=[evt1, evt2],
        correlations=[traj]
    )

    assert len(result.items) == 2
    cams = {it.camera_id for it in result.items}
    assert cams == {"CAM-01", "CAM-02"}
    for it in result.items:
        assert it.entity_id == "ENT-88"
        # Does not fabricate real-world personal identity
        assert not any("John" in str(it.entity_id) for _ in [1])


# 16. no fabricated IDs
def test_no_fabricated_ids(sample_event):
    evidence_item = Evidence(
        evidence_id="EVI-REAL-1",
        event_id=None,  # event_id is None
        camera_id="CAM-01",
        timestamp_start="2026-10-08T10:00:00Z",
        verification_status="VERIFIED"
    )

    result = EvidenceProvenanceEngine.track_provenance(
        evidence=[evidence_item],
        events=[]
    )

    assert result.items[0].evidence_id == "EVI-REAL-1"
    assert result.items[0].event_id is None


# 17. no fabricated timestamps
def test_no_fabricated_timestamps():
    evidence_item = Evidence(
        evidence_id="EVI-RAW-1",
        camera_id="CAM-01",
        timestamp_start="2026-10-08T10:14:27.123456Z",
        verification_status="VERIFIED"
    )

    result = EvidenceProvenanceEngine.track_provenance(
        evidence=[evidence_item],
        events=[]
    )

    # Must preserve exact original timestamp without rounding
    assert result.items[0].timestamp == "2026-10-08T10:14:27.123456Z"


# 18. no fabricated video references
def test_no_fabricated_video_references(sample_event):
    evidence_item = Evidence(
        evidence_id="EVI-NOVIDEO-1",
        event_id="EVT-PROV-101",
        camera_id="CAM-01",
        timestamp_start="2026-10-08T10:00:00Z",
        source_video=None,
        clip_reference=None,
        verification_status="VERIFIED"
    )

    result = EvidenceProvenanceEngine.track_provenance(
        evidence=[evidence_item],
        events=[sample_event]
    )

    assert result.items[0].source_video is None
    assert result.items[0].clip_reference is None


# 19. deterministic provenance
def test_deterministic_provenance(sample_event, sample_evidence):
    res1 = EvidenceProvenanceEngine.track_provenance(
        evidence=[sample_evidence],
        events=[sample_event],
        answer="Breach verified.",
        reason="Video clip matches."
    )
    res2 = EvidenceProvenanceEngine.track_provenance(
        evidence=[sample_evidence],
        events=[sample_event],
        answer="Breach verified.",
        reason="Video clip matches."
    )

    assert res1.model_dump() == res2.model_dump()


# 20. compatibility with Steps 1–13
def test_compatibility_with_steps_1_to_13(sample_event, sample_evidence):
    timeline_item = TimelineItem(
        timestamp="2026-10-08T10:00:00Z",
        camera_id="CAM-01",
        event_id="EVT-PROV-101",
        description="Observation on CAM-01"
    )
    suff_res = SufficiencyResult(
        status=SufficiencyStatus.SUFFICIENT,
        reasons=["All verified"]
    )
    conf_res = ConfidenceResult(
        confidence=0.91,
        confidence_status=ConfidenceStatus.AVAILABLE
    )

    result = EvidenceProvenanceEngine.track_provenance(
        evidence=[sample_evidence],
        events=[sample_event],
        timeline=[timeline_item],
        sufficiency_result=suff_res,
        confidence_result=conf_res,
        answer="Access violation identified.",
        reason="Sensor snapshot confirms intrusion."
    )

    assert result.is_sufficient is True
    assert result.has_conflict is False
    assert len(result.items) == 1
    assert result.items[0].confidence == 0.91
    assert result.items[0].evidence_id == "EVI-PROV-201"
