"""
Tests for Module 4 Unknown / Hallucination Protection Engine (Step 16).
Validates Absolute No-Hallucination Triad compliance, personal identity protection,
phantom identifier filtering, blind-spot safety, triad reclassification, and insufficient evidence fallbacks.
"""
import pytest

from agent.context import InvestigationContext
from reasoning.hallucination_guard import (
    HallucinationGuard,
    HallucinationGuardResult,
    HallucinationViolationType,
)
from schemas.investigation import (
    InvestigationRequest,
    InvestigationResult,
    InvestigationStatus,
    TimelineItem,
)
from agent.request_handler import InvestigationRequestHandler


@pytest.fixture
def base_context():
    raw_req = InvestigationRequest(
        investigation_id="INV-GUARD-001",
        query="Investigate gate breach",
        camera_ids=["CAM-03", "CAM-04"],
    )
    prepared_req = InvestigationRequestHandler.validate_and_prepare(raw_req)
    ctx = InvestigationContext(investigation_id="INV-GUARD-001", request=prepared_req)

    ctx.cameras = {
        "CAM-03": {"camera_id": "CAM-03", "status": "CONNECTED"},
        "CAM-04": {"camera_id": "CAM-04", "status": "OFFLINE"},
    }
    ctx.events = [
        {
            "event_id": "EVT-1029",
            "camera_id": "CAM-03",
            "entity_id": "ENT-902",
            "timestamp": "2026-10-08T10:42:13Z",
        }
    ]
    ctx.verified_evidence = [
        {"evidence_id": "EVD-4091", "event_id": "EVT-1029", "camera_id": "CAM-03"}
    ]
    ctx.evidence_ids = ["EVD-4091"]
    return ctx


# =============================================================================
# 1. IDENTITY HALLUCINATION PROTECTION TESTS
# =============================================================================

def test_guard_sanitizes_identity_in_observed_facts():
    """Detects and sanitizes real-world names in observed facts."""
    res = InvestigationResult(
        investigation_id="INV-GUARD-001",
        status=InvestigationStatus.COMPLETED,
        answer="Person was detected at gate.",
        observed_facts=["Person named John Doe entered the facility at CAM-03."],
        inferences=[],
        timeline=[],
        evidence_ids=["EVD-4091"],
        confidence=0.9,
    )
    guard_res = HallucinationGuard.validate_and_sanitize(res)
    assert not guard_res.is_clean
    assert any(v.violation_type == HallucinationViolationType.IDENTITY_FABRICATION for v in guard_res.violations)
    # The personal name must be stripped/sanitized
    assert "John Doe" not in guard_res.sanitized_result.observed_facts[0]


def test_guard_sanitizes_identity_in_answer():
    """Detects real-world name in answer and enforces unknown declaration."""
    res = InvestigationResult(
        investigation_id="INV-GUARD-001",
        status=InvestigationStatus.COMPLETED,
        answer="The suspect John Smith was identified fleeing through the corridor.",
        observed_facts=["Entity ENT-902 observed on CAM-03."],
        inferences=[],
        timeline=[],
        evidence_ids=["EVD-4091"],
        confidence=0.9,
    )
    guard_res = HallucinationGuard.validate_and_sanitize(res)
    assert not guard_res.is_clean
    assert "John Smith" not in guard_res.sanitized_result.answer
    assert any("Personal real-world identity cannot be determined" in u for u in guard_res.sanitized_result.unknowns)


# =============================================================================
# 2. TRIAD RECLASSIFICATION TESTS
# =============================================================================

def test_guard_reclassifies_inference_markers_out_of_observed_facts():
    """Statements containing inference words like 'unauthorized' or 'likely' are moved to inferences."""
    res = InvestigationResult(
        investigation_id="INV-GUARD-001",
        status=InvestigationStatus.COMPLETED,
        answer="Investigation summary.",
        observed_facts=[
            "Entity ENT-902 entered through CAM-03.",
            "Entry was unauthorized based on perimeter policy.",
            "Suspect likely breached perimeter fence.",
        ],
        inferences=[],
        timeline=[],
        evidence_ids=["EVD-4091"],
        confidence=0.88,
    )
    guard_res = HallucinationGuard.validate_and_sanitize(res)
    assert len(guard_res.sanitized_result.observed_facts) == 1
    assert "Entity ENT-902 entered through CAM-03." in guard_res.sanitized_result.observed_facts
    # Reclassified into inferences
    assert len(guard_res.sanitized_result.inferences) == 2
    assert any(v.violation_type == HallucinationViolationType.TRIAD_MISCLASSIFICATION for v in guard_res.violations)


# =============================================================================
# 3. BLIND-SPOT & OFFLINE CAMERA SAFETY TESTS
# =============================================================================

def test_guard_enforces_offline_camera_limitations(base_context):
    """Offline cameras are recorded in limitations and never claimed as clear."""
    res = InvestigationResult(
        investigation_id="INV-GUARD-001",
        status=InvestigationStatus.COMPLETED,
        answer="No activity occurred on CAM-04.",
        observed_facts=["CAM-04 area was clear and nothing happened."],
        inferences=[],
        timeline=[],
        evidence_ids=["EVD-4091"],
        confidence=0.9,
    )
    guard_res = HallucinationGuard.validate_and_sanitize(res, context=base_context)
    # Must enforce offline limitation
    assert any("CAM-04 was unavailable" in lim for lim in guard_res.sanitized_result.limitations)
    # Unsafe negative assertion must be eliminated from facts
    assert len(guard_res.sanitized_result.observed_facts) == 0
    # Must declare unknown
    assert any("CAM-04 cannot be determined" in u for u in guard_res.sanitized_result.unknowns)


# =============================================================================
# 4. PHANTOM IDENTIFIER FILTERING TESTS
# =============================================================================

def test_guard_removes_phantom_evidence_ids(base_context):
    """Evidence IDs that are not present in authoritative context are stripped."""
    res = InvestigationResult(
        investigation_id="INV-GUARD-001",
        status=InvestigationStatus.COMPLETED,
        answer="Investigation answer.",
        observed_facts=["Entity observed."],
        inferences=[],
        timeline=[],
        evidence_ids=["EVD-4091", "EVD-9999"],  # EVD-9999 is fabricated/phantom
        confidence=0.85,
    )
    guard_res = HallucinationGuard.validate_and_sanitize(res, context=base_context)
    assert "EVD-4091" in guard_res.sanitized_result.evidence_ids
    assert "EVD-9999" not in guard_res.sanitized_result.evidence_ids
    assert any(v.violation_type == HallucinationViolationType.PHANTOM_IDENTIFIER for v in guard_res.violations)


# =============================================================================
# 5. INSUFFICIENT EVIDENCE FALLBACK TESTS
# =============================================================================

def test_guard_enforces_insufficient_evidence_contract():
    """INSUFFICIENT_EVIDENCE status enforces exact canonical phrasing and clears confidence."""
    res = InvestigationResult(
        investigation_id="INV-GUARD-001",
        status=InvestigationStatus.INSUFFICIENT_EVIDENCE,
        answer="We think something happened but we are not sure.",
        observed_facts=[],
        inferences=[],
        timeline=[],
        evidence_ids=[],
        confidence=0.6,  # Misaligned confidence score
    )
    guard_res = HallucinationGuard.validate_and_sanitize(res)
    assert guard_res.sanitized_result.answer == "I don't know — insufficient evidence to determine this reliably."
    assert guard_res.sanitized_result.confidence is None
    assert any(v.violation_type == HallucinationViolationType.CONFIDENCE_MISALIGNMENT for v in guard_res.violations)
