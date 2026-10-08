"""
Tests for Module 4 Realtime Investigation Status and Failure Handling (Step 17).
Validates permitted canonical lifecycle stages, error isolation, telemetry failure resilience,
and graceful degradation without crashing.
"""
import pytest
from unittest.mock import AsyncMock

from agent.context import InvestigationContext
from agent.orchestrator import InvestigationOrchestrator
from agent.stage_interfaces import BaseInvestigationStage
from agent.status_reporter import (
    CanonicalInvestigationStage,
    FailureCategory,
    InvestigationStatusReporter,
)
from integration.exceptions import BackendConnectionError
from integration.mock_client import MockBackendClient
from schemas.investigation import (
    InvestigationRequest,
    InvestigationResult,
    InvestigationStatus,
)


@pytest.fixture
def mock_client():
    return MockBackendClient()


@pytest.fixture
def reporter(mock_client):
    return InvestigationStatusReporter(mock_client)


# =============================================================================
# 1. STATUS REPORTER UNIT TESTS
# =============================================================================

@pytest.mark.asyncio
async def test_reporter_emits_canonical_stages(reporter, mock_client):
    """Status reporter translates internal stages to permitted canonical stages."""
    success = await reporter.report_started("INV-STAT-001")
    assert success is True
    assert len(mock_client.progress_logs) == 1
    assert mock_client.progress_logs[0]["stage"] == "investigation.started"

    await reporter.report_stage("INV-STAT-001", "event_retrieval")
    assert len(mock_client.progress_logs) == 2
    # Canonical mapping in metadata
    assert mock_client.progress_logs[1]["metadata"]["canonical_stage"] == "investigation.searching_events"

    await reporter.report_completed("INV-STAT-001")
    assert len(mock_client.progress_logs) == 3
    assert mock_client.progress_logs[2]["stage"] == "investigation.completed"


@pytest.mark.asyncio
async def test_reporter_emits_insufficient_evidence(reporter, mock_client):
    """Reporter emits canonical investigation.insufficient_evidence terminal status."""
    await reporter.report_insufficient_evidence("INV-STAT-002")
    assert len(mock_client.progress_logs) == 1
    assert mock_client.progress_logs[0]["stage"] == "investigation.insufficient_evidence"


@pytest.mark.asyncio
async def test_reporter_emits_failed_with_categorization(reporter, mock_client):
    """Reporter emits investigation.failed with structured failure categorization."""
    await reporter.report_failed(
        "INV-STAT-003",
        error_message="Camera connection reset",
        category=FailureCategory.BACKEND_UNAVAILABLE,
    )
    assert len(mock_client.progress_logs) == 1
    entry = mock_client.progress_logs[0]
    assert entry["stage"] == "investigation.failed"
    assert entry["metadata"]["failure_category"] == "BACKEND_UNAVAILABLE"
    assert "Camera connection reset" in entry["message"]


@pytest.mark.asyncio
async def test_reporter_resilient_to_telemetry_network_failure():
    """Reporter logs error but does not raise if backend telemetry raises an exception."""
    faulty_client = AsyncMock()
    faulty_client.send_realtime_status.side_effect = BackendConnectionError("Network down")

    faulty_reporter = InvestigationStatusReporter(faulty_client)
    success = await faulty_reporter.report_started("INV-ERR-001")

    assert success is False
    assert len(faulty_reporter.history) == 1
    assert faulty_reporter.history[0].success is False
    assert "Network down" in faulty_reporter.history[0].error_detail


# =============================================================================
# 2. ORCHESTRATOR FAILURE RECOVERY & STATUS INTEGRATION
# =============================================================================

@pytest.mark.asyncio
async def test_orchestrator_handles_stage_crash_gracefully(mock_client):
    """When a stage crashes, orchestrator transitions to FAILED, reports failure, and returns valid result."""
    class CrashingStage(BaseInvestigationStage):
        @property
        def stage_name(self) -> str:
            return "crashing_stage"

        async def execute(self, context: InvestigationContext, backend_client) -> None:
            raise RuntimeError("Critical unexpected sensor anomaly")

    orchestrator = InvestigationOrchestrator(
        backend_client=mock_client,
        stages=[CrashingStage()],
    )

    req = InvestigationRequest(
        investigation_id="INV-CRASH-001",
        query="Investigate perimeter",
    )

    result = await orchestrator.orchestrate(req)

    assert isinstance(result, InvestigationResult)
    assert result.status == InvestigationStatus.FAILED
    assert "Critical unexpected sensor anomaly" in result.answer

    # Verify failure telemetry was emitted
    failure_logs = [log for log in mock_client.progress_logs if log["stage"] == "investigation.failed"]
    assert len(failure_logs) >= 1
    assert "Critical unexpected sensor anomaly" in failure_logs[0]["message"]


@pytest.mark.asyncio
async def test_orchestrator_completes_when_telemetry_fails():
    """Even if backend status endpoint completely fails, orchestrator completes investigation."""
    faulty_client = MockBackendClient()
    # Mock send_realtime_status to raise
    faulty_client.send_realtime_status = AsyncMock(side_effect=Exception("Telemetry server down"))

    orchestrator = InvestigationOrchestrator(backend_client=faulty_client)

    req = InvestigationRequest(
        investigation_id="INV-ROBUST-001",
        query="Investigate corridor movement",
        camera_ids=["CAM-03"],
    )

    result = await orchestrator.orchestrate(req)
    # Orchestration finishes successfully despite telemetry failure
    assert result.investigation_id == "INV-ROBUST-001"
    assert result.status in (InvestigationStatus.COMPLETED, InvestigationStatus.INSUFFICIENT_EVIDENCE)
