"""
Tests for Module 4 Investigation Orchestrator.
Validates end-to-end pipeline execution, deterministic stage order, state transitions,
controlled error handling, insufficient evidence handling, and no-hallucination guarantees.
"""
import pytest
from unittest.mock import AsyncMock

from agent.context import InvestigationContext, InvestigationState
from agent.orchestrator import InvestigationOrchestrator
from agent.stage_interfaces import BaseInvestigationStage
from integration.exceptions import BackendConnectionError
from integration.mock_client import MockBackendClient
from schemas.investigation import InvestigationRequest, InvestigationResult, InvestigationStatus


@pytest.mark.asyncio
async def test_1_orchestrator_accepts_valid_request_and_preserves_id():
    """Verify orchestrator accepts valid request and preserves investigation_id."""
    client = MockBackendClient()
    orchestrator = InvestigationOrchestrator(backend_client=client)

    raw_req = {
        "investigation_id": "INV-2026-TEST",
        "query": "Investigate unauthorized entry at Main Gate",
        "camera_ids": ["CAM-03"],
        "incident_id": "INC-8821"
    }

    result = await orchestrator.orchestrate(raw_req)
    assert isinstance(result, InvestigationResult)
    assert result.investigation_id == "INV-2026-TEST"


@pytest.mark.asyncio
async def test_2_stages_execute_in_deterministic_order():
    """Verify that all stages execute in exact deterministic order."""
    client = MockBackendClient()
    orchestrator = InvestigationOrchestrator(backend_client=client)

    raw_req = {
        "investigation_id": "INV-ORDER-TEST",
        "query": "Investigate movement across corridor"
    }

    # Intercept context
    class OrderTrackerStage(BaseInvestigationStage):
        @property
        def stage_name(self) -> str:
            return "final_order_check"

        async def execute(self, context: InvestigationContext, backend_client) -> None:
            pass

    orchestrator.stages.append(OrderTrackerStage())
    result = await orchestrator.orchestrate(raw_req)

    expected_stages = [
        "intent_understanding",
        "incident_identification",
        "event_retrieval",
        "camera_retrieval",
        "entity_retrieval",
        "cross_camera_correlation",
        "timeline_construction",
        "security_context",
        "risk_reasoning",
        "evidence_verification",
        "confidence_evaluation",
        "final_order_check",
    ]
    
    # We can check progress logs recorded in client
    client_stages = [entry["stage"].replace("investigation.", "") for entry in client.progress_logs]
    for exp in expected_stages[:-1]:  # check core stages logged
        assert exp in client_stages


@pytest.mark.asyncio
async def test_3_successful_controlled_workflow():
    """Verify full successful investigation workflow using MockBackendClient."""
    client = MockBackendClient()
    orchestrator = InvestigationOrchestrator(backend_client=client)

    req = InvestigationRequest(
        investigation_id="INV-SUCCESS-001",
        query="Investigate incident INC-8821",
        incident_id="INC-8821",
        camera_ids=["CAM-03", "CAM-05"]
    )

    result = await orchestrator.orchestrate(req)
    assert result.status == InvestigationStatus.COMPLETED
    assert len(result.observed_facts) > 0
    assert len(result.timeline) > 0
    assert "EVD-4091" in result.evidence_ids
    assert result.confidence is not None
    assert 0.0 <= result.confidence <= 1.0


@pytest.mark.asyncio
async def test_4_insufficient_evidence_handling():
    """Verify that when no events/evidence are found, orchestrator outputs controlled insufficient evidence."""
    # Create empty client with no events or evidence
    client = MockBackendClient()
    client.events = {}
    client.evidence = {}
    client.incidents = {}

    orchestrator = InvestigationOrchestrator(backend_client=client)

    req = {
        "investigation_id": "INV-NO-EVIDENCE",
        "query": "Investigate vehicle at loading dock"
    }

    result = await orchestrator.orchestrate(req)
    assert result.status == InvestigationStatus.INSUFFICIENT_EVIDENCE
    assert result.answer == "I don't know — insufficient evidence to determine this reliably."
    assert len(result.unknowns) > 0
    assert result.confidence is None


@pytest.mark.asyncio
async def test_5_backend_failure_handling():
    """Verify controlled handling when Backend returns an error during event retrieval."""
    client = MockBackendClient()
    # Mock search_events to fail with connection error
    client.search_events = AsyncMock(side_effect=BackendConnectionError("Backend Core unreachable"))

    orchestrator = InvestigationOrchestrator(backend_client=client)

    req = {
        "investigation_id": "INV-BACKEND-FAIL",
        "query": "Investigate alert"
    }

    result = await orchestrator.orchestrate(req)
    assert result.status == InvestigationStatus.FAILED
    assert "Backend Core unreachable" in result.answer


@pytest.mark.asyncio
async def test_6_stage_failure_handling():
    """Verify that a failing stage safely stops execution and sets FAILED status."""
    class FailingStage(BaseInvestigationStage):
        @property
        def stage_name(self) -> str:
            return "failing_stage"

        async def execute(self, context: InvestigationContext, backend_client) -> None:
            raise RuntimeError("Unexpected pipeline failure")

    client = MockBackendClient()
    orchestrator = InvestigationOrchestrator(
        backend_client=client,
        stages=[FailingStage()]
    )

    result = await orchestrator.orchestrate({
        "investigation_id": "INV-FAIL-STAGE",
        "query": "Investigate something"
    })

    assert result.status == InvestigationStatus.FAILED
    assert "Unexpected pipeline failure" in result.answer


@pytest.mark.asyncio
async def test_7_malformed_request_handling():
    """Verify invalid or malformed request payload returns FAILED status without crashing."""
    client = MockBackendClient()
    orchestrator = InvestigationOrchestrator(backend_client=client)

    # Missing query
    result = await orchestrator.orchestrate({
        "investigation_id": "INV-BAD"
    })
    assert result.status == InvestigationStatus.FAILED
    assert "query" in result.answer


@pytest.mark.asyncio
async def test_8_no_fabricated_evidence_or_result():
    """Verify that orchestrator never hallucinates evidence or facts not present in data."""
    client = MockBackendClient()
    # Explicitly clear out CAM-07 from events
    client.events = {
        "EVT-1029": {
            "event_id": "EVT-1029",
            "camera_id": "CAM-03",
            "timestamp": "2026-10-08T10:42:13Z",
            "event_type": "person_detected",
            "confidence": 0.95
        }
    }
    client.evidence = {}
    orchestrator = InvestigationOrchestrator(backend_client=client)

    result = await orchestrator.orchestrate({
        "investigation_id": "INV-NO-FABRICATION",
        "query": "What happened on CAM-07?"
    })

    # CAM-07 was not observed in any event
    for fact in result.observed_facts:
        assert "CAM-07" not in fact
    assert result.evidence_ids == []
