"""
Tests for Module 4 AI Security Copilot (Step 15).
Validates natural-language query resolution, canonical token parsing, intent classification,
Absolute No-Hallucination Triad compliance, personal identity protection, and structured responses.
"""
import pytest
from unittest.mock import AsyncMock

from copilot.engine import SecurityCopilotEngine
from copilot.intent import CopilotIntentAnalyzer
from integration.mock_client import MockBackendClient
from schemas.copilot import (
    CopilotIntentType,
    CopilotQueryRequest,
    CopilotQueryResponse,
)


@pytest.fixture
def mock_client():
    return MockBackendClient()


@pytest.fixture
def copilot_engine(mock_client):
    return SecurityCopilotEngine(backend_client=mock_client)


# =============================================================================
# 1. INTENT ANALYZER TESTS
# =============================================================================

def test_intent_analyzer_extracts_tokens():
    req = CopilotQueryRequest(
        query="Trace movement of ENT-902 from CAM-03 to CAM-05 in ZONE-04 for incident INC-8821"
    )
    analysis = CopilotIntentAnalyzer.analyze(req)
    assert "ENT-902" in analysis["entities"]
    assert "CAM-03" in analysis["cameras"]
    assert "CAM-05" in analysis["cameras"]
    assert "ZONE-04" in analysis["zones"]
    assert "INC-8821" in analysis["incidents"]


def test_intent_analyzer_flags_personal_identity_query():
    req = CopilotQueryRequest(
        query="Who is the person identified as ENT-902? What is their name?"
    )
    analysis = CopilotIntentAnalyzer.analyze(req)
    assert analysis["asks_personal_identity"] is True


def test_intent_analyzer_categorizes_camera_status():
    req = CopilotQueryRequest(query="What is the health and status of camera CAM-03?")
    analysis = CopilotIntentAnalyzer.analyze(req)
    assert analysis["intent_type"] == CopilotIntentType.CAMERA_STATUS


def test_intent_analyzer_categorizes_policy_inquiry():
    req = CopilotQueryRequest(query="What is the restricted hours security policy for ZONE-04?")
    analysis = CopilotIntentAnalyzer.analyze(req)
    assert analysis["intent_type"] == CopilotIntentType.SECURITY_POLICY


# =============================================================================
# 2. COPILOT ENGINE FUNCTIONAL TESTS
# =============================================================================

@pytest.mark.asyncio
async def test_copilot_camera_status_query(copilot_engine):
    """Copilot reports camera operational statuses and flags offline cameras."""
    res = await copilot_engine.query({"query": "Check status of CAM-03 and CAM-04"})
    assert isinstance(res, CopilotQueryResponse)
    assert res.intent_type == CopilotIntentType.CAMERA_STATUS
    assert any("CAM-03" in f for f in res.observed_facts)
    assert any("CAM-04" in f for f in res.observed_facts)
    # CAM-04 is offline in mock fixtures; must be flagged in limitations
    assert any("OFFLINE" in lim for lim in res.limitations)
    assert len(res.suggested_followups) > 0


@pytest.mark.asyncio
async def test_copilot_security_policy_query(copilot_engine):
    """Copilot returns active security policies from security context memory."""
    res = await copilot_engine.query({"query": "What are the active policies for ZONE-04?"})
    assert isinstance(res, CopilotQueryResponse)
    assert res.intent_type == CopilotIntentType.SECURITY_POLICY
    assert any("ZONE-04" in f for f in res.observed_facts)
    assert res.confidence is not None


@pytest.mark.asyncio
async def test_copilot_entity_tracking_query(copilot_engine):
    """Copilot tracks entity movement across cameras with verified evidence."""
    res = await copilot_engine.query({"query": "Where did entity ENT-902 go?"})
    assert isinstance(res, CopilotQueryResponse)
    assert res.intent_type == CopilotIntentType.ENTITY_TRACKING
    assert any("ENT-902" in f for f in res.observed_facts)
    assert "EVD-4091" in res.evidence_ids
    assert len(res.inferences) > 0
    assert "CAM-03 -> CAM-05" in res.inferences[0]
    assert res.confidence is not None


@pytest.mark.asyncio
async def test_copilot_identity_hallucination_refusal(copilot_engine):
    """Copilot strictly refuses to fabricate real-world personal identity."""
    res = await copilot_engine.query({"query": "Who is ENT-902 and what is his real name?"})
    assert isinstance(res, CopilotQueryResponse)
    # Must declare UNKNOWN for identity
    assert any("Personal real-world identity cannot be determined" in u for u in res.unknowns)
    # Answer must include disclaimer
    assert "cannot be determined" in res.answer.lower()


@pytest.mark.asyncio
async def test_copilot_incident_inquiry(copilot_engine):
    """Copilot summarizes incident details, associated threats, and correlated events."""
    res = await copilot_engine.query({"query": "Tell me about incident INC-8821"})
    assert isinstance(res, CopilotQueryResponse)
    assert res.intent_type == CopilotIntentType.INCIDENT_INQUIRY
    assert any("INC-8821" in f for f in res.observed_facts)
    assert any("THR-5501" in f for f in res.observed_facts)
    assert len(res.evidence_ids) > 0
    assert res.confidence is not None


@pytest.mark.asyncio
async def test_copilot_zone_activity(copilot_engine):
    """Copilot queries activity in designated zones."""
    res = await copilot_engine.query({"query": "What activity occurred in ZONE-01?"})
    assert isinstance(res, CopilotQueryResponse)
    assert res.intent_type == CopilotIntentType.ZONE_ACTIVITY
    assert len(res.observed_facts) > 0


@pytest.mark.asyncio
async def test_copilot_unknown_entity_insufficient_evidence(copilot_engine):
    """Copilot returns insufficient evidence for nonexistent entity without hallucinating."""
    res = await copilot_engine.query({"query": "Where did ENT-999 go?"})
    assert isinstance(res, CopilotQueryResponse)
    assert "insufficient evidence" in res.answer.lower()
    assert any("ENT-999" in u for u in res.unknowns)
    assert res.confidence is None


@pytest.mark.asyncio
async def test_copilot_backend_client_integration(mock_client):
    """Verify backend client query_copilot method integrates cleanly."""
    res_dict = await mock_client.query_copilot({"query": "Status of CAM-03"})
    assert isinstance(res_dict, dict)
    assert "observed_facts" in res_dict
    assert "answer" in res_dict
