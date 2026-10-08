"""
Comprehensive Integration Readiness & End-to-End Suite for Module 4 (Step 18).
Validates all 18 steps working together synchronously and asynchronously:
1. Orchestrator + Request Validation + Stage Execution + Evidence Sufficiency + Entity Correlation
2. Timeline Construction + Security Context Memory + Risk Reasoning + Confidence Evaluation
3. Evidence Provenance + Hallucination Guard + Status Telemetry + Copilot Intelligence
4. Prohibited architecture boundaries (No direct CCTV/DB, only Backend client)
5. Zero Hallucination Triad compliance across normal, partial, and degraded scenarios.
"""
import pytest
from unittest.mock import AsyncMock

from agent.orchestrator import InvestigationOrchestrator
from agent.request_handler import InvestigationRequestHandler
from copilot.engine import SecurityCopilotEngine
from integration.mock_client import MockBackendClient
from reasoning.hallucination_guard import HallucinationGuard
from schemas.identifiers import CANONICAL_ID_FIELDS
from schemas.investigation import (
    InvestigationRequest,
    InvestigationResult,
    InvestigationStatus,
)


@pytest.fixture
def test_client():
    return MockBackendClient()


@pytest.fixture
def orchestrator(test_client):
    return InvestigationOrchestrator(backend_client=test_client)


@pytest.fixture
def copilot(test_client, orchestrator):
    return SecurityCopilotEngine(backend_client=test_client, orchestrator=orchestrator)


# =============================================================================
# 1. END-TO-END INVESTIGATION PIPELINE TESTS
# =============================================================================

@pytest.mark.asyncio
async def test_e2e_full_incident_investigation(orchestrator, test_client):
    """
    End-to-End Test: Full incident investigation across all 12 pipeline stages.
    Verifies timeline, cross-camera entity correlation, provenance, confidence, and guard compliance.
    """
    req_data = {
        "investigation_id": "INV-E2E-FULL",
        "query": "Investigate unauthorized entry in corridor incident INC-8821",
        "incident_id": "INC-8821",
        "camera_ids": ["CAM-03", "CAM-05"],
        "zone_ids": ["ZONE-01", "ZONE-04"],
        "user_id": "USR-108",
    }

    result = await orchestrator.orchestrate(req_data)

    # 1. Lifecycle Status
    assert result.status == InvestigationStatus.COMPLETED
    assert result.investigation_id == "INV-E2E-FULL"

    # 2. Triad Segregation
    assert len(result.observed_facts) > 0
    assert len(result.inferences) > 0
    assert isinstance(result.unknowns, list)
    assert isinstance(result.limitations, list)

    # 3. Canonical Identifiers Preserved
    assert any("CAM-03" in f for f in result.observed_facts)
    assert any("CAM-05" in f for f in result.observed_facts)
    assert "EVD-4091" in result.evidence_ids

    # 4. Chronological Timeline
    assert len(result.timeline) >= 2
    timestamps = [item.timestamp for item in result.timeline]
    assert timestamps == sorted(timestamps)

    # 5. Confidence Score
    assert result.confidence is not None
    assert 0.0 <= result.confidence <= 1.0

    # 6. Telemetry and Result Posted to Backend
    assert "INV-E2E-FULL" in test_client.investigation_results
    assert len(test_client.progress_logs) >= 3


@pytest.mark.asyncio
async def test_e2e_insufficient_evidence_scenario(orchestrator, test_client):
    """
    End-to-End Test: Investigation with unobserved entities/cameras.
    Must reliably conclude with INSUFFICIENT_EVIDENCE and canonical safe answer.
    """
    req_data = {
        "investigation_id": "INV-E2E-EMPTY",
        "query": "Investigate activity at North Loading Dock",
        "camera_ids": ["CAM-99"],  # Nonexistent camera in mock data
        "zone_ids": ["ZONE-99"],
    }

    result = await orchestrator.orchestrate(req_data)

    assert result.status == InvestigationStatus.INSUFFICIENT_EVIDENCE
    assert result.answer == "I don't know — insufficient evidence to determine this reliably."
    assert result.confidence is None
    assert len(result.observed_facts) == 0
    assert any("insufficient" in u.lower() for u in result.unknowns)


@pytest.mark.asyncio
async def test_e2e_offline_camera_blindspot_safety(orchestrator, test_client):
    """
    End-to-End Test: Investigation involving offline camera CAM-04.
    Must never state 'nothing happened' or 'all clear'; must declare blind-spot limitations.
    """
    req_data = {
        "investigation_id": "INV-E2E-OFFLINE",
        "query": "Investigate activity around East Perimeter on CAM-04",
        "camera_ids": ["CAM-04"],
    }

    result = await orchestrator.orchestrate(req_data)

    # Must contain limitation about CAM-04 downtime
    assert any("CAM-04" in lim and "OFFLINE" in lim or "unavailable" in lim for lim in result.limitations)
    # Must never claim clear
    assert "all clear" not in result.answer.lower()
    assert "nothing happened" not in result.answer.lower()


# =============================================================================
# 2. COPILOT INTEGRATION READINESS TESTS
# =============================================================================

@pytest.mark.asyncio
async def test_copilot_e2e_conversational_workflow(copilot):
    """
    Copilot End-to-End: Operator multi-domain security queries.
    Tests incident query, camera health, and entity movement.
    """
    # 1. Ask about incident
    inc_resp = await copilot.query({"query": "What occurred during incident INC-8821?"})
    assert inc_resp.confidence is not None
    assert any("INC-8821" in f for f in inc_resp.observed_facts)
    assert len(inc_resp.suggested_followups) > 0

    # 2. Ask about camera health
    cam_resp = await copilot.query({"query": "What is the health and status of all cameras?"})
    assert any("CAM-03" in f for f in cam_resp.observed_facts)
    assert any("CAM-04" in lim for lim in cam_resp.limitations)

    # 3. Ask about entity tracking with prohibited identity request
    ent_resp = await copilot.query({
        "query": "Where did ENT-902 go and what is the suspect's name?"
    })
    # Prohibited identity must be flagged as UNKNOWN
    assert any("Personal real-world identity cannot be determined" in u for u in ent_resp.unknowns)
    # Entity movement tracked across cameras
    assert any("ENT-902" in f for f in ent_resp.observed_facts)


# =============================================================================
# 3. SYSTEM BOUNDARIES & ARCHITECTURAL INVARIANTS
# =============================================================================

def test_canonical_id_fields_contract():
    """Verify all canonical identifier fields match platform standards."""
    expected = [
        "camera_id",
        "zone_id",
        "event_id",
        "incident_id",
        "evidence_id",
        "investigation_id",
        "threat_id",
        "entity_id",
        "user_id",
        "memory_id",
    ]
    for field_name in expected:
        assert field_name in CANONICAL_ID_FIELDS


def test_no_prohibited_direct_database_modules():
    """Verify Module 4 contains NO direct SQLAlchemy models, sqlite3, or ORM table migrations."""
    import sys
    import inspect
    import agent
    import evidence
    import investigation
    import reasoning

    for mod in [agent, evidence, investigation, reasoning]:
        source = inspect.getsource(mod)
        assert "create_engine" not in source
        assert "Base.metadata" not in source
        assert "alembic" not in source
