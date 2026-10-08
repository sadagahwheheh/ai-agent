"""
Tests for Module 4: Step 12 - Evidence-Grounded Risk Reasoning Engine.
Covers all 20 required test scenarios:
1. HIGH risk with sufficient evidence
2. MEDIUM risk with sufficient evidence
3. LOW risk with sufficient evidence
4. UNKNOWN risk with insufficient evidence
5. UNKNOWN risk with unavailable evidence
6. conflicted evidence handling
7. backend severity preservation
8. supplied policy context
9. missing policy context
10. security-context integration
11. timeline integration
12. evidence sufficiency integration
13. cross-camera integration
14. observed facts vs inference separation
15. unknown handling
16. blind-spot handling
17. no fabricated risk
18. no fabricated evidence
19. no fabricated policy
20. deterministic risk reasoning
"""
import pytest

from integration.mock_client import MockBackendClient
from investigation.entity_correlation import EntityCorrelationTrajectory
from investigation.timeline import TimelineEngine
from reasoning.context_reasoning import SecurityContextItem, SecurityContextReasoningResult
from reasoning.risk_reasoning import (
    EvidenceGroundedRiskReasoningEngine,
    ReasoningStatus,
    RiskReasoningResult,
)
from schemas.events import Event
from schemas.evidence import Evidence
from schemas.investigation import TimelineItem
from schemas.memory import SecurityMemory
from schemas.threats import Threat, ThreatSeverity


@pytest.fixture
def mock_client():
    return MockBackendClient()


@pytest.fixture
def verified_breach_event():
    return Event(
        event_id="EVT-BREACH-01",
        camera_id="CAM-01",
        timestamp="2026-10-08T10:00:00Z",
        event_type="perimeter_breach",
        zone_id="Z-01",
        entity_id="ENT-404",
        confidence=0.95,
        status="OBSERVED"
    )


@pytest.fixture
def verified_breach_evidence():
    return Evidence(
        evidence_id="EVI-BREACH-01",
        event_id="EVT-BREACH-01",
        camera_id="CAM-01",
        timestamp_start="2026-10-08T10:00:00Z",
        verification_status="VERIFIED"
    )


@pytest.fixture
def standard_policy():
    return [
        {
            "zone_id": "Z-01",
            "policy": "Strict perimeter boundary: unauthorized breach strictly prohibited",
            "source": "facility_security_plan_v1"
        }
    ]


# 1. HIGH risk with sufficient evidence
def test_high_risk_with_sufficient_evidence(verified_breach_event, verified_breach_evidence, standard_policy):
    result = EvidenceGroundedRiskReasoningEngine.reason(
        events=[verified_breach_event],
        evidence=[verified_breach_evidence],
        supplied_policies=standard_policy
    )

    assert result.risk_level == ThreatSeverity.HIGH
    assert result.reasoning_status == ReasoningStatus.DETERMINED
    assert "HIGH" in result.risk_reason
    assert "perimeter_breach" in result.risk_reason or "critical security violation" in result.risk_reason


# 2. MEDIUM risk with sufficient evidence
def test_medium_risk_with_sufficient_evidence():
    event = Event(
        event_id="EVT-MED-01",
        camera_id="CAM-01",
        timestamp="2026-10-08T10:30:00Z",
        event_type="after_hours_entry",
        zone_id="Z-01",
        status="OBSERVED"
    )
    evidence = Evidence(
        evidence_id="EVI-MED-01",
        event_id="EVT-MED-01",
        camera_id="CAM-01",
        timestamp_start="2026-10-08T10:30:00Z",
        verification_status="VERIFIED"
    )
    policy = [
        {
            "zone_id": "Z-01",
            "policy": "Restricted zone operating rules apply",
            "source": "sop_v1"
        }
    ]

    result = EvidenceGroundedRiskReasoningEngine.reason(
        events=[event],
        evidence=[evidence],
        supplied_policies=policy
    )

    assert result.risk_level == ThreatSeverity.MEDIUM
    assert result.reasoning_status == ReasoningStatus.DETERMINED
    assert "MEDIUM" in result.risk_reason


# 3. LOW risk with sufficient evidence
def test_low_risk_with_sufficient_evidence():
    event = Event(
        event_id="EVT-LOW-01",
        camera_id="CAM-01",
        timestamp="2026-10-08T09:00:00Z",
        event_type="badge_verified_entry",
        zone_id="Z-01",
        status="OBSERVED"
    )
    evidence = Evidence(
        evidence_id="EVI-LOW-01",
        event_id="EVT-LOW-01",
        camera_id="CAM-01",
        timestamp_start="2026-10-08T09:00:00Z",
        verification_status="VERIFIED"
    )
    policy = [
        {
            "zone_id": "Z-01",
            "policy": "Authorized badge holders permitted entry",
            "source": "badge_access_policy"
        }
    ]

    result = EvidenceGroundedRiskReasoningEngine.reason(
        events=[event],
        evidence=[evidence],
        supplied_policies=policy
    )

    assert result.risk_level == ThreatSeverity.LOW
    assert result.reasoning_status == ReasoningStatus.DETERMINED
    assert "LOW" in result.risk_reason


# 4. UNKNOWN risk with insufficient evidence
def test_unknown_risk_with_insufficient_evidence(verified_breach_event, standard_policy):
    # Evidence unverified / insufficient
    unverified_evidence = Evidence(
        evidence_id="EVI-UNVERIFIED",
        event_id="EVT-BREACH-01",
        camera_id="CAM-01",
        timestamp_start="2026-10-08T10:00:00Z",
        verification_status="UNVERIFIED"
    )

    result = EvidenceGroundedRiskReasoningEngine.reason(
        events=[verified_breach_event],
        evidence=[unverified_evidence],
        supplied_policies=standard_policy
    )

    assert result.risk_level == ThreatSeverity.UNKNOWN
    assert result.reasoning_status == ReasoningStatus.INSUFFICIENT_EVIDENCE
    assert result.risk_reason == "I don't know — insufficient evidence."
    assert "I don't know — insufficient evidence." in result.limitations


# 5. UNKNOWN risk with unavailable evidence
def test_unknown_risk_with_unavailable_evidence(standard_policy):
    result = EvidenceGroundedRiskReasoningEngine.reason(
        events=[],
        evidence=[],
        supplied_policies=standard_policy
    )

    assert result.risk_level == ThreatSeverity.UNKNOWN
    assert result.reasoning_status == ReasoningStatus.INSUFFICIENT_EVIDENCE
    assert result.risk_reason == "I don't know — insufficient evidence."
    assert result.observed_facts == []


# 6. conflicted evidence handling
def test_conflicted_evidence_handling(verified_breach_event, standard_policy):
    conflicted_evidence = [
        Evidence(
            evidence_id="EVI-CONF-1",
            event_id="EVT-BREACH-01",
            camera_id="CAM-01",
            timestamp_start="2026-10-08T10:00:00Z",
            verification_status="CONFLICTED"
        )
    ]

    result = EvidenceGroundedRiskReasoningEngine.reason(
        events=[verified_breach_event],
        evidence=conflicted_evidence,
        supplied_policies=standard_policy
    )

    assert result.risk_level == ThreatSeverity.UNKNOWN
    assert result.reasoning_status == ReasoningStatus.CONFLICTED
    assert result.risk_reason == "Conflicting evidence detected."
    assert "Conflicting evidence detected." in result.limitations


# 7. backend severity preservation
def test_backend_severity_preservation(verified_breach_event, verified_breach_evidence, standard_policy):
    # Authoritative Backend threat evaluates severity as MEDIUM
    backend_threat = Threat(
        threat_id="THR-AUTH-777",
        severity=ThreatSeverity.MEDIUM,
        score=0.55,
        reason="Security core threat evaluation downgraded severity"
    )

    result = EvidenceGroundedRiskReasoningEngine.reason(
        events=[verified_breach_event],
        evidence=[verified_breach_evidence],
        backend_threat=backend_threat,
        supplied_policies=standard_policy
    )

    # Backend severity MUST be preserved
    assert result.risk_level == ThreatSeverity.MEDIUM
    assert result.backend_severity == ThreatSeverity.MEDIUM
    assert "Authoritative Backend Security Core assessment established severity as MEDIUM" in result.risk_reason


# 8. supplied policy context
def test_supplied_policy_context(verified_breach_event, verified_breach_evidence):
    supplied_policies = [
        {
            "zone_id": "Z-01",
            "policy": "Emergency lockdown in effect: all entries prohibited",
            "source": "incident_commander"
        }
    ]

    result = EvidenceGroundedRiskReasoningEngine.reason(
        events=[verified_breach_event],
        evidence=[verified_breach_evidence],
        supplied_policies=supplied_policies
    )

    assert len(result.policy_context) >= 1
    assert any("Emergency lockdown in effect" in p and "incident_commander" in p for p in result.policy_context)
    assert result.risk_level == ThreatSeverity.HIGH


# 9. missing policy context
def test_missing_policy_context(verified_breach_event, verified_breach_evidence):
    # No policy supplied
    result = EvidenceGroundedRiskReasoningEngine.reason(
        events=[verified_breach_event],
        evidence=[verified_breach_evidence],
        supplied_policies=[]
    )

    assert result.risk_level == ThreatSeverity.UNKNOWN
    assert result.reasoning_status == ReasoningStatus.UNKNOWN
    assert result.risk_reason == "I don't know — insufficient evidence."
    assert any("No applicable security policy or context supplied" in lim for lim in result.limitations)


# 10. security-context integration
def test_security_context_integration(verified_breach_event, verified_breach_evidence):
    ctx_res = SecurityContextReasoningResult(
        observed_facts=["Event observed on camera CAM-01"],
        security_context=[
            SecurityContextItem(
                context_id="CTX-01",
                category="camera_mapping",
                statement="Camera CAM-01 covers North Perimeter",
                source="site_plan_v1",
                camera_id="CAM-01"
            ),
            SecurityContextItem(
                context_id="CTX-02",
                category="zone_policy",
                statement="Zone Z-01 operates under policy: 'Lockdown active'",
                source="security_director",
                zone_id="Z-01"
            )
        ],
        inferences=["Observations occurred at North Perimeter."],
        unknowns=[],
        limitations=[]
    )

    result = EvidenceGroundedRiskReasoningEngine.reason(
        events=[verified_breach_event],
        evidence=[verified_breach_evidence],
        security_context_result=ctx_res
    )

    assert any("North Perimeter" in c for c in result.context)
    assert any("Lockdown active" in p for p in result.policy_context)
    assert result.risk_level == ThreatSeverity.HIGH


# 11. timeline integration
def test_timeline_integration(verified_breach_event, verified_breach_evidence, standard_policy):
    timeline_items = [
        TimelineItem(
            timestamp="2026-10-08T10:00:00Z",
            camera_id="CAM-01",
            event_id="EVT-BREACH-01",
            description="Breach observed"
        )
    ]

    result = EvidenceGroundedRiskReasoningEngine.reason(
        events=[verified_breach_event],
        evidence=[verified_breach_evidence],
        timeline=timeline_items,
        supplied_policies=standard_policy
    )

    assert any("Timeline chronological sequence verified" in inf for inf in result.inferences)


# 12. evidence sufficiency integration
def test_evidence_sufficiency_integration(verified_breach_event, standard_policy):
    # No evidence provided for event
    result = EvidenceGroundedRiskReasoningEngine.reason(
        events=[verified_breach_event],
        evidence=[],
        supplied_policies=standard_policy
    )

    assert result.risk_level == ThreatSeverity.UNKNOWN
    assert result.reasoning_status == ReasoningStatus.INSUFFICIENT_EVIDENCE
    assert result.risk_reason == "I don't know — insufficient evidence."


# 13. cross-camera integration
def test_cross_camera_integration(verified_breach_event, verified_breach_evidence, standard_policy):
    trajectory = EntityCorrelationTrajectory(
        entity_id="ENT-404",
        status="CORRELATED",
        camera_ids=["CAM-01", "CAM-02"],
        event_ids=["EVT-BREACH-01", "EVT-BREACH-02"],
        description="Cross-camera observation across CAM-01, CAM-02"
    )

    result = EvidenceGroundedRiskReasoningEngine.reason(
        events=[verified_breach_event],
        evidence=[verified_breach_evidence],
        correlations=[trajectory],
        supplied_policies=standard_policy
    )

    assert any("Tracked entity entity_id=ENT-404 observed across cameras: CAM-01, CAM-02." in inf for inf in result.inferences)
    # Never fabricates personal identity
    assert not any("John" in text for text in result.observed_facts + result.inferences)
    assert any("identity cannot be verified from sensor telemetry alone" in u for u in result.unknowns)


# 14. observed facts vs inference separation
def test_observed_facts_vs_inference_separation(verified_breach_event, verified_breach_evidence, standard_policy):
    result = EvidenceGroundedRiskReasoningEngine.reason(
        events=[verified_breach_event],
        evidence=[verified_breach_evidence],
        supplied_policies=standard_policy
    )

    for fact in result.observed_facts:
        assert "Event EVT-BREACH-01" in fact or "Evidence EVI-BREACH-01" in fact
        assert "HIGH risk determined" not in fact

    for inf in result.inferences:
        assert "Event EVT-BREACH-01 (perimeter_breach)" not in inf


# 15. unknown handling
def test_unknown_handling(verified_breach_event, verified_breach_evidence, standard_policy):
    result = EvidenceGroundedRiskReasoningEngine.reason(
        events=[verified_breach_event],
        evidence=[verified_breach_evidence],
        supplied_policies=standard_policy
    )

    assert any("Tracked entity ENT-404 identity cannot be verified" in u for u in result.unknowns)


# 16. blind-spot handling
def test_blind_spot_handling(verified_breach_event, verified_breach_evidence, standard_policy):
    cameras = {
        "CAM-01": {"camera_id": "CAM-01", "status": "OFFLINE"}
    }

    result = EvidenceGroundedRiskReasoningEngine.reason(
        events=[verified_breach_event],
        evidence=[verified_breach_evidence],
        cameras=cameras,
        supplied_policies=standard_policy
    )

    assert result.risk_level == ThreatSeverity.UNKNOWN
    assert result.reasoning_status == ReasoningStatus.INSUFFICIENT_EVIDENCE
    assert result.risk_reason == "I don't know — the area was not reliably observable during that period."
    assert "I don't know — the area was not reliably observable during that period." in result.limitations
    assert any("Camera CAM-01 was OFFLINE" in u for u in result.unknowns)


# 17. no fabricated risk
def test_no_fabricated_risk():
    result = EvidenceGroundedRiskReasoningEngine.reason(
        events=[],
        evidence=[]
    )

    assert result.risk_level == ThreatSeverity.UNKNOWN
    assert result.risk_reason == "I don't know — insufficient evidence."


# 18. no fabricated evidence
def test_no_fabricated_evidence(verified_breach_event, standard_policy):
    result = EvidenceGroundedRiskReasoningEngine.reason(
        events=[verified_breach_event],
        evidence=[],
        supplied_policies=standard_policy
    )

    assert result.evidence_ids == []
    assert result.risk_level == ThreatSeverity.UNKNOWN


# 19. no fabricated policy
def test_no_fabricated_policy(verified_breach_event, verified_breach_evidence):
    result = EvidenceGroundedRiskReasoningEngine.reason(
        events=[verified_breach_event],
        evidence=[verified_breach_evidence],
        supplied_policies=[]
    )

    assert result.policy_context == []
    assert result.risk_level == ThreatSeverity.UNKNOWN
    assert any("No applicable security policy or context supplied" in lim for lim in result.limitations)


# 20. deterministic risk reasoning
def test_deterministic_risk_reasoning(verified_breach_event, verified_breach_evidence, standard_policy):
    res1 = EvidenceGroundedRiskReasoningEngine.reason(
        events=[verified_breach_event],
        evidence=[verified_breach_evidence],
        supplied_policies=standard_policy
    )
    res2 = EvidenceGroundedRiskReasoningEngine.reason(
        events=[verified_breach_event],
        evidence=[verified_breach_evidence],
        supplied_policies=standard_policy
    )

    assert res1.model_dump() == res2.model_dump()
