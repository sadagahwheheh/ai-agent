"""
Tests for Module 4: Step 13 - Investigation Confidence Evaluation Layer.
Covers all 18 required test scenarios:
1. confidence from valid supplied signals
2. deterministic calculation
3. repeated input produces same result
4. missing AI confidence
5. missing tracking confidence
6. missing evidence quality
7. missing source reliability
8. insufficient evidence
9. conflicted evidence
10. temporal consistency
11. cross-camera consistency
12. policy/context certainty
13. confidence unavailable handling
14. confidence remains separate from risk
15. no random confidence
16. no fabricated confidence
17. evidence/event reference preservation
18. compatibility with Steps 1–12
"""
import pytest

from evidence.sufficiency import SufficiencyResult, SufficiencyStatus
from investigation.entity_correlation import CorrelationStatus, EntityCorrelationTrajectory
from reasoning.confidence_evaluation import (
    ConfidenceResult,
    ConfidenceStatus,
    InvestigationConfidenceEngine,
)
from reasoning.context_reasoning import SecurityContextReasoningResult
from reasoning.risk_reasoning import ReasoningStatus, RiskReasoningResult
from schemas.events import Event
from schemas.evidence import Evidence
from schemas.investigation import TimelineItem
from schemas.threats import ThreatSeverity


@pytest.fixture
def sample_event():
    return Event(
        event_id="EVT-CONF-101",
        camera_id="CAM-01",
        timestamp="2026-10-08T10:00:00Z",
        event_type="perimeter_breach",
        confidence=0.90,
        status="OBSERVED",
        metadata={"tracking_confidence": 0.85}
    )


@pytest.fixture
def sample_evidence():
    return Evidence(
        evidence_id="EVI-CONF-201",
        event_id="EVT-CONF-101",
        camera_id="CAM-01",
        timestamp_start="2026-10-08T10:00:00Z",
        confidence=0.80,
        verification_status="VERIFIED"
    )


# 1. confidence from valid supplied signals
def test_confidence_from_valid_supplied_signals(sample_event, sample_evidence):
    result = InvestigationConfidenceEngine.evaluate(
        events=[sample_event],
        evidence=[sample_evidence]
    )

    assert result.confidence_status == ConfidenceStatus.AVAILABLE
    assert result.confidence is not None
    assert 0.0 <= result.confidence <= 1.0
    assert "ai_video_confidence" in result.contributing_factors
    assert "tracking_confidence" in result.contributing_factors
    assert "evidence_quality" in result.contributing_factors


# 2. deterministic calculation
def test_deterministic_calculation():
    event = Event(
        event_id="EVT-CALC-1",
        camera_id="CAM-01",
        timestamp="2026-10-08T10:00:00Z",
        event_type="person_detection",
        confidence=0.80,
        status="OBSERVED"
    )
    evidence = Evidence(
        evidence_id="EVI-CALC-1",
        event_id="EVT-CALC-1",
        camera_id="CAM-01",
        timestamp_start="2026-10-08T10:00:00Z",
        confidence=0.70,
        verification_status="VERIFIED"
    )

    result = InvestigationConfidenceEngine.evaluate(
        events=[event],
        evidence=[evidence]
    )

    assert result.confidence_status == ConfidenceStatus.AVAILABLE
    # Arithmetic mean of 0.80 and 0.70 = 0.75
    assert result.confidence == 0.75


# 3. repeated input produces same result
def test_repeated_input_produces_same_result(sample_event, sample_evidence):
    res1 = InvestigationConfidenceEngine.evaluate(
        events=[sample_event],
        evidence=[sample_evidence]
    )
    res2 = InvestigationConfidenceEngine.evaluate(
        events=[sample_event],
        evidence=[sample_evidence]
    )

    assert res1.model_dump() == res2.model_dump()


# 4. missing AI confidence
def test_missing_ai_confidence(sample_evidence):
    event_no_conf = Event(
        event_id="EVT-NOCONF-1",
        camera_id="CAM-01",
        timestamp="2026-10-08T10:00:00Z",
        event_type="person_detection",
        confidence=None,
        status="OBSERVED"
    )

    result = InvestigationConfidenceEngine.evaluate(
        events=[event_no_conf],
        evidence=[sample_evidence]
    )

    assert "ai_video_confidence" not in result.contributing_factors
    assert "evidence_quality" in result.contributing_factors
    assert result.confidence == 0.80


# 5. missing tracking confidence
def test_missing_tracking_confidence(sample_evidence):
    event_no_track = Event(
        event_id="EVT-NOTRACK-1",
        camera_id="CAM-01",
        timestamp="2026-10-08T10:00:00Z",
        event_type="person_detection",
        confidence=0.90,
        status="OBSERVED",
        metadata={}
    )

    result = InvestigationConfidenceEngine.evaluate(
        events=[event_no_track],
        evidence=[sample_evidence]
    )

    assert "tracking_confidence" not in result.contributing_factors


# 6. missing evidence quality
def test_missing_evidence_quality(sample_event):
    evidence_no_conf = Evidence(
        evidence_id="EVI-NOCONF-1",
        event_id="EVT-CONF-101",
        camera_id="CAM-01",
        timestamp_start="2026-10-08T10:00:00Z",
        confidence=None,
        verification_status="VERIFIED",
        metadata={}
    )

    result = InvestigationConfidenceEngine.evaluate(
        events=[sample_event],
        evidence=[evidence_no_conf]
    )

    assert "evidence_quality" not in result.contributing_factors
    assert "ai_video_confidence" in result.contributing_factors


# 7. missing source reliability
def test_missing_source_reliability(sample_event, sample_evidence):
    result = InvestigationConfidenceEngine.evaluate(
        events=[sample_event],
        evidence=[sample_evidence],
        source_reliabilities=None
    )

    assert "source_reliability" not in result.contributing_factors


# 8. insufficient evidence
def test_insufficient_evidence(sample_event):
    # Pass sufficiency result marked as INSUFFICIENT
    suff = SufficiencyResult(
        status=SufficiencyStatus.INSUFFICIENT,
        reasons=["Missing verified evidence"],
        limitations=["I don't know — insufficient evidence."]
    )

    result = InvestigationConfidenceEngine.evaluate(
        events=[sample_event],
        evidence=[],
        sufficiency_result=suff
    )

    assert result.confidence_status == ConfidenceStatus.INSUFFICIENT_EVIDENCE
    assert result.confidence is None
    assert "Confidence unavailable" in result.message


# 9. conflicted evidence
def test_conflicted_evidence(sample_event, sample_evidence):
    suff = SufficiencyResult(
        status=SufficiencyStatus.CONFLICTED,
        reasons=["Contradictory observations"],
        limitations=["Conflicting evidence detected."]
    )

    result = InvestigationConfidenceEngine.evaluate(
        events=[sample_event],
        evidence=[sample_evidence],
        sufficiency_result=suff
    )

    assert result.confidence_status == ConfidenceStatus.CONFLICTED
    assert result.confidence is None
    assert "Confidence unavailable" in result.message


# 10. temporal consistency
def test_temporal_consistency(sample_event, sample_evidence):
    timeline = [
        TimelineItem(
            timestamp="2026-10-08T10:00:00Z",
            camera_id="CAM-01",
            event_id="EVT-CONF-101",
            description="Verified observation"
        )
    ]

    result = InvestigationConfidenceEngine.evaluate(
        events=[sample_event],
        evidence=[sample_evidence],
        timeline=timeline
    )

    assert "temporal_consistency" in result.contributing_factors


# 11. cross-camera consistency
def test_cross_camera_consistency(sample_event, sample_evidence):
    trajectory = EntityCorrelationTrajectory(
        entity_id="ENT-404",
        status=CorrelationStatus.CORRELATED,
        camera_ids=["CAM-01", "CAM-02"],
        event_ids=["EVT-CONF-101", "EVT-CONF-102"],
        description="Cross-camera observation across CAM-01, CAM-02"
    )

    result = InvestigationConfidenceEngine.evaluate(
        events=[sample_event],
        evidence=[sample_evidence],
        correlations=[trajectory]
    )

    assert "cross_camera_consistency" in result.contributing_factors


# 12. policy/context certainty
def test_policy_context_certainty(sample_event, sample_evidence):
    sec_ctx = SecurityContextReasoningResult(
        observed_facts=["Observed on CAM-01"],
        security_context=[],
        has_conflict=False
    )

    result = InvestigationConfidenceEngine.evaluate(
        events=[sample_event],
        evidence=[sample_evidence],
        security_context_result=sec_ctx
    )

    assert "context_certainty" in result.contributing_factors


# 13. confidence unavailable handling
def test_confidence_unavailable_handling():
    # Events and evidence provided, but absolutely no confidence numbers
    event_empty = Event(
        event_id="EVT-EMPTY-1",
        camera_id="CAM-01",
        timestamp="2026-10-08T10:00:00Z",
        event_type="person_detection",
        confidence=None,
        status="OBSERVED"
    )
    evidence_empty = Evidence(
        evidence_id="EVI-EMPTY-1",
        event_id="EVT-EMPTY-1",
        camera_id="CAM-01",
        timestamp_start="2026-10-08T10:00:00Z",
        confidence=None,
        verification_status="VERIFIED"
    )

    result = InvestigationConfidenceEngine.evaluate(
        events=[event_empty],
        evidence=[evidence_empty]
    )

    assert result.confidence is None
    assert result.confidence_status == ConfidenceStatus.UNAVAILABLE
    assert result.message == "Confidence unavailable."


# 14. confidence remains separate from risk
def test_confidence_remains_separate_from_risk():
    # Case A: HIGH risk with low sensor confidence (0.4)
    event_high_risk = Event(
        event_id="EVT-HIGH",
        camera_id="CAM-01",
        timestamp="2026-10-08T10:00:00Z",
        event_type="perimeter_breach",
        confidence=0.40,
        status="OBSERVED"
    )
    ev_high_risk = Evidence(
        evidence_id="EVI-HIGH",
        event_id="EVT-HIGH",
        camera_id="CAM-01",
        timestamp_start="2026-10-08T10:00:00Z",
        confidence=0.40,
        verification_status="VERIFIED"
    )
    risk_high = RiskReasoningResult(
        risk_level=ThreatSeverity.HIGH,
        risk_reason="High risk breach",
        reasoning_status=ReasoningStatus.DETERMINED
    )

    res_high = InvestigationConfidenceEngine.evaluate(
        events=[event_high_risk],
        evidence=[ev_high_risk],
        risk_result=risk_high
    )
    assert res_high.confidence == 0.40

    # Case B: LOW risk with high sensor confidence (0.95)
    event_low_risk = Event(
        event_id="EVT-LOW",
        camera_id="CAM-01",
        timestamp="2026-10-08T10:00:00Z",
        event_type="badge_verified_entry",
        confidence=0.95,
        status="OBSERVED"
    )
    ev_low_risk = Evidence(
        evidence_id="EVI-LOW",
        event_id="EVT-LOW",
        camera_id="CAM-01",
        timestamp_start="2026-10-08T10:00:00Z",
        confidence=0.95,
        verification_status="VERIFIED"
    )
    risk_low = RiskReasoningResult(
        risk_level=ThreatSeverity.LOW,
        risk_reason="Low risk routine",
        reasoning_status=ReasoningStatus.DETERMINED
    )

    res_low = InvestigationConfidenceEngine.evaluate(
        events=[event_low_risk],
        evidence=[ev_low_risk],
        risk_result=risk_low
    )
    assert res_low.confidence == 0.95


# 15. no random confidence
def test_no_random_confidence(sample_event, sample_evidence):
    results = [
        InvestigationConfidenceEngine.evaluate(
            events=[sample_event],
            evidence=[sample_evidence]
        ).confidence
        for _ in range(10)
    ]

    assert len(set(results)) == 1


# 16. no fabricated confidence
def test_no_fabricated_confidence():
    # When signals are missing, confidence is not made up
    result = InvestigationConfidenceEngine.evaluate(
        events=[],
        evidence=[]
    )

    assert result.confidence is None
    assert result.confidence_status == ConfidenceStatus.INSUFFICIENT_EVIDENCE
    assert result.message == "Confidence unavailable."


# 17. evidence/event reference preservation
def test_evidence_event_reference_preservation(sample_event, sample_evidence):
    result = InvestigationConfidenceEngine.evaluate(
        events=[sample_event],
        evidence=[sample_evidence]
    )

    assert result.event_ids == ["EVT-CONF-101"]
    assert result.evidence_ids == ["EVI-CONF-201"]


# 18. compatibility with Steps 1–12
def test_compatibility_with_steps_1_to_12(sample_event, sample_evidence):
    timeline_item = TimelineItem(
        timestamp="2026-10-08T10:00:00Z",
        camera_id="CAM-01",
        event_id="EVT-CONF-101",
        description="Observation verified"
    )
    trajectory = EntityCorrelationTrajectory(
        entity_id="ENT-404",
        status=CorrelationStatus.CORRELATED,
        camera_ids=["CAM-01", "CAM-02"],
        event_ids=["EVT-CONF-101"]
    )
    sec_ctx = SecurityContextReasoningResult(
        observed_facts=["Observed on CAM-01"],
        security_context=[],
        has_conflict=False
    )
    suff_res = SufficiencyResult(
        status=SufficiencyStatus.SUFFICIENT,
        reasons=["Sufficient evidence"],
        evidence_ids=["EVI-CONF-201"]
    )
    risk_res = RiskReasoningResult(
        risk_level=ThreatSeverity.HIGH,
        risk_reason="Breach verified",
        reasoning_status=ReasoningStatus.DETERMINED
    )

    result = InvestigationConfidenceEngine.evaluate(
        events=[sample_event],
        evidence=[sample_evidence],
        timeline=[timeline_item],
        correlations=[trajectory],
        security_context_result=sec_ctx,
        sufficiency_result=suff_res,
        risk_result=risk_res
    )

    assert result.confidence_status == ConfidenceStatus.AVAILABLE
    assert result.confidence is not None
    assert len(result.contributing_factors) >= 4
