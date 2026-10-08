"""
Tests for Module 4 Event and Evidence Retrieval Layer.
Validates authoritative data fetching, filtering, empty results, error translation,
preservation of source records, zero hallucination, and compatibility with
the Evidence Sufficiency Engine and Investigation Orchestrator.
"""
import pytest
from unittest.mock import AsyncMock

from agent.orchestrator import InvestigationOrchestrator
from evidence.retrieval import EvidenceRetrievalResult, EvidenceRetrievalService
from evidence.sufficiency import EvidenceSufficiencyEngine, SufficiencyStatus
from integration.exceptions import BackendAuthError, BackendConnectionError
from integration.mock_client import MockBackendClient
from investigation.event_search import EventRetrievalResult, EventRetrievalService, RetrievalStatus
from schemas.events import Event
from schemas.evidence import Evidence
from schemas.investigation import InvestigationRequest, InvestigationStatus, TimeRange


@pytest.mark.asyncio
async def test_1_event_retrieval_success():
    """Verify event retrieval fetches and parses authoritative events."""
    client = MockBackendClient()
    service = EventRetrievalService(client)

    result = await service.get_by_event_id("EVT-1029")
    assert result.status == RetrievalStatus.DATA_FOUND
    assert result.has_data is True
    assert len(result.events) == 1
    event = result.events[0]
    assert event.event_id == "EVT-1029"
    assert event.camera_id == "CAM-03"
    assert event.event_type == "person_detected"


@pytest.mark.asyncio
async def test_2_evidence_retrieval_success():
    """Verify evidence retrieval fetches and parses authoritative evidence."""
    client = MockBackendClient()
    service = EvidenceRetrievalService(client)

    result = await service.get_by_evidence_id("EVD-4091")
    assert result.status == RetrievalStatus.DATA_FOUND
    assert result.has_data is True
    assert len(result.evidence_items) == 1
    ev = result.evidence_items[0]
    assert ev.evidence_id == "EVD-4091"
    assert ev.camera_id == "CAM-03"
    assert ev.verification_status == "VERIFIED"


@pytest.mark.asyncio
async def test_3_empty_event_result():
    """Verify querying non-existent event ID returns clean NO_DATA_FOUND."""
    client = MockBackendClient()
    service = EventRetrievalService(client)

    result = await service.get_by_event_id("EVT-NONEXISTENT")
    assert result.status == RetrievalStatus.NO_DATA_FOUND
    assert result.is_empty is True
    assert len(result.events) == 0


@pytest.mark.asyncio
async def test_4_empty_evidence_result():
    """Verify querying non-existent evidence returns NO_DATA_FOUND."""
    client = MockBackendClient()
    service = EvidenceRetrievalService(client)

    result = await service.get_by_evidence_id("EVD-NONEXISTENT")
    assert result.status == RetrievalStatus.NO_DATA_FOUND
    assert result.is_empty is True
    assert len(result.evidence_items) == 0


@pytest.mark.asyncio
async def test_5_filtering_by_time_range():
    """Verify events can be filtered using TimeRange."""
    client = MockBackendClient()
    service = EventRetrievalService(client)

    tr = TimeRange(start="2026-10-08T10:00:00Z", end="2026-10-08T11:00:00Z")
    result = await service.search(time_range=tr)
    assert result.status == RetrievalStatus.DATA_FOUND
    assert result.applied_filters.get("time_range") is not None


@pytest.mark.asyncio
async def test_6_filtering_by_camera():
    """Verify events can be filtered by camera_ids."""
    client = MockBackendClient()
    service = EventRetrievalService(client)

    result = await service.search(camera_ids=["CAM-03"])
    assert result.status == RetrievalStatus.DATA_FOUND
    for evt in result.events:
        assert evt.camera_id == "CAM-03"


@pytest.mark.asyncio
async def test_7_filtering_by_zone():
    """Verify events can be filtered by zone_ids."""
    client = MockBackendClient()
    service = EventRetrievalService(client)

    result = await service.search(zone_ids=["ZONE-04"])
    assert result.status == RetrievalStatus.DATA_FOUND
    for evt in result.events:
        assert evt.zone_id == "ZONE-04"


@pytest.mark.asyncio
async def test_8_filtering_by_incident():
    """Verify events associated with an incident are filtered."""
    client = MockBackendClient()
    service = EventRetrievalService(client)

    result = await service.search(incident_id="INC-8821")
    assert result.status == RetrievalStatus.DATA_FOUND
    assert len(result.events) >= 1
    assert any(evt.event_id == "EVT-1029" for evt in result.events)


@pytest.mark.asyncio
async def test_9_filtering_by_entity():
    """Verify events filtered by tracked entity_id token."""
    client = MockBackendClient()
    service = EventRetrievalService(client)

    result = await service.search(entity_id="ENT-902")
    assert result.status == RetrievalStatus.DATA_FOUND
    for evt in result.events:
        assert evt.entity_id == "ENT-902"


@pytest.mark.asyncio
async def test_10_backend_unavailable():
    """Verify connection failure returns BACKEND_UNAVAILABLE status."""
    client = MockBackendClient()
    client.search_events = AsyncMock(side_effect=BackendConnectionError("Core down"))
    service = EventRetrievalService(client)

    result = await service.search(camera_ids=["CAM-03"])
    assert result.status == RetrievalStatus.BACKEND_UNAVAILABLE
    assert "Backend connection error" in (result.error_message or "")


@pytest.mark.asyncio
async def test_11_backend_retrieval_failure():
    """Verify auth failure returns RETRIEVAL_FAILURE status."""
    client = MockBackendClient()
    client.search_events = AsyncMock(side_effect=BackendAuthError("Forbidden"))
    service = EventRetrievalService(client)

    result = await service.search()
    assert result.status == RetrievalStatus.RETRIEVAL_FAILURE
    assert "authorization failed" in (result.error_message or "")


@pytest.mark.asyncio
async def test_12_invalid_retrieval_request():
    """Verify blank event_id or evidence_id produces INVALID_REQUEST."""
    client = MockBackendClient()
    evt_service = EventRetrievalService(client)
    ev_service = EvidenceRetrievalService(client)

    res1 = await evt_service.get_by_event_id("   ")
    assert res1.status == RetrievalStatus.INVALID_REQUEST

    res2 = await ev_service.get_by_evidence_id("")
    assert res2.status == RetrievalStatus.INVALID_REQUEST


@pytest.mark.asyncio
async def test_13_preservation_of_authoritative_event_data():
    """Verify exact preservation of original timestamps and event metadata."""
    client = MockBackendClient()
    service = EventRetrievalService(client)

    result = await service.get_by_event_id("EVT-1029")
    evt = result.events[0]
    assert evt.timestamp == "2026-10-08T10:42:13Z"
    assert evt.confidence == 0.95
    assert evt.metadata.get("action") == "entered_gate"


@pytest.mark.asyncio
async def test_14_preservation_of_authoritative_evidence_data():
    """Verify exact preservation of evidence clip references and verification status."""
    client = MockBackendClient()
    service = EvidenceRetrievalService(client)

    result = await service.get_by_evidence_id("EVD-4091")
    ev = result.evidence_items[0]
    assert ev.timestamp_start == "2026-10-08T10:42:13Z"
    assert ev.clip_reference is None or "snapshots" in ev.clip_reference or ev.source_video is None
    assert ev.verification_status == "VERIFIED"


@pytest.mark.asyncio
async def test_15_no_fabricated_data():
    """Verify that absent events/evidence are not invented."""
    client = MockBackendClient()
    client.events = {}
    client.evidence = {}
    evt_service = EventRetrievalService(client)
    ev_service = EvidenceRetrievalService(client)

    evt_res = await evt_service.search(camera_ids=["CAM-03"])
    assert evt_res.status == RetrievalStatus.NO_DATA_FOUND
    assert evt_res.events == []

    ev_res = await ev_service.get_for_events(["EVT-999"])
    assert ev_res.status == RetrievalStatus.NO_DATA_FOUND
    assert ev_res.evidence_items == []


@pytest.mark.asyncio
async def test_16_compatibility_with_evidence_sufficiency_engine():
    """Verify retrieved events and evidence plug directly into the Evidence Sufficiency Engine."""
    client = MockBackendClient()
    evt_service = EventRetrievalService(client)
    ev_service = EvidenceRetrievalService(client)

    evt_res = await evt_service.search(camera_ids=["CAM-03"])
    ev_res = await ev_service.get_for_events([e.event_id for e in evt_res.events])

    sufficiency = EvidenceSufficiencyEngine.evaluate(
        evidence_items=ev_res.evidence_items,
        events=evt_res.events
    )
    assert sufficiency.status == SufficiencyStatus.SUFFICIENT
    assert "EVD-4091" in sufficiency.evidence_ids


@pytest.mark.asyncio
async def test_17_compatibility_with_investigation_orchestrator():
    """Verify InvestigationOrchestrator uses the retrieval services seamlessly."""
    client = MockBackendClient()
    orchestrator = InvestigationOrchestrator(backend_client=client)

    req = InvestigationRequest(
        investigation_id="INV-RETR-TEST",
        query="Investigate main gate activity",
        camera_ids=["CAM-03"]
    )
    result = await orchestrator.orchestrate(req)
    assert result.status == InvestigationStatus.COMPLETED
    assert len(result.observed_facts) > 0
    assert "EVD-4091" in result.evidence_ids
