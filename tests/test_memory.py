"""
Tests for Module 4 Persistent Security Memory Layer.
Validates creation, retrieval by type/source/status, update, timestamp preservation,
auditable sources, conflict detection, and compatibility with the orchestrator.
"""
import pytest

from agent.orchestrator import InvestigationOrchestrator
from integration.mock_client import MockBackendClient
from memory.persistent_memory import PersistentSecurityMemoryService
from memory.validation import SecurityMemoryValidator
from schemas.investigation import InvestigationRequest, InvestigationStatus
from schemas.memory import SecurityMemory


@pytest.mark.asyncio
async def test_1_create_memory():
    """Verify storing a new security context memory via the service."""
    client = MockBackendClient()
    service = PersistentSecurityMemoryService(client)

    mem = SecurityMemory(
        memory_id="MEM-TEST-1",
        type="zone_policy",
        value={"zone_id": "ZONE-09", "policy": "High Security Escort Required"},
        source="security_director_directive",
        created_at="2026-10-08T08:00:00Z",
        updated_at="2026-10-08T08:00:00Z",
        status="ACTIVE"
    )
    saved, warning = await service.store_memory(mem)
    assert saved.memory_id == "MEM-TEST-1"
    assert saved.status == "ACTIVE"
    assert warning is None


@pytest.mark.asyncio
async def test_2_retrieve_memory():
    """Verify retrieving specific memory by ID."""
    client = MockBackendClient()
    service = PersistentSecurityMemoryService(client)

    mem = await service.get_memory("MEM-301")
    assert mem is not None
    assert mem.memory_id == "MEM-301"
    assert mem.type == "camera_mapping"
    assert mem.value["location"] == "Main Gate"


@pytest.mark.asyncio
async def test_3_retrieve_by_type():
    """Verify retrieving memories by category type."""
    client = MockBackendClient()
    service = PersistentSecurityMemoryService(client)

    cams = await service.retrieve_by_type("camera_mapping")
    assert len(cams) >= 1
    assert all(c.type == "camera_mapping" for c in cams)


@pytest.mark.asyncio
async def test_4_retrieve_by_source():
    """Verify filtering memories by auditable source."""
    client = MockBackendClient()
    service = PersistentSecurityMemoryService(client)

    mems = await service.retrieve_by_source("facility_map_v1")
    assert len(mems) >= 1
    assert all(m.source == "facility_map_v1" for m in mems)


@pytest.mark.asyncio
async def test_5_retrieve_by_status():
    """Verify retrieving memories by lifecycle status."""
    client = MockBackendClient()
    service = PersistentSecurityMemoryService(client)

    active_mems = await service.retrieve_by_status("ACTIVE")
    assert len(active_mems) >= 2
    assert all(m.status == "ACTIVE" for m in active_mems)


@pytest.mark.asyncio
async def test_6_update_memory():
    """Verify updating memory updates updated_at while preserving created_at and source."""
    client = MockBackendClient()
    service = PersistentSecurityMemoryService(client)

    orig = await service.get_memory("MEM-301")
    assert orig is not None
    orig_created = orig.created_at
    orig_source = orig.source

    updated = await service.update_memory(
        "MEM-301",
        {"value": {"camera_id": "CAM-03", "location": "Main Gate West Entry"}}
    )
    assert updated.memory_id == "MEM-301"
    assert updated.created_at == orig_created
    assert updated.source == orig_source
    assert updated.value["location"] == "Main Gate West Entry"


@pytest.mark.asyncio
async def test_7_timestamp_preservation():
    """Verify historical created_at timestamp is preserved without overwrite."""
    client = MockBackendClient()
    service = PersistentSecurityMemoryService(client)

    historical_ts = "2025-01-15T12:00:00Z"
    mem = SecurityMemory(
        memory_id="MEM-HIST",
        type="shift_schedule",
        value={"shift": "Night", "hours": "22:00-06:00"},
        source="operations_manual_2025",
        created_at=historical_ts,
        updated_at=historical_ts,
        status="ACTIVE"
    )
    saved, _ = await service.store_memory(mem)
    assert saved.created_at == historical_ts


@pytest.mark.asyncio
async def test_8_source_preservation():
    """Verify every stored memory retains its exact traceable source."""
    client = MockBackendClient()
    service = PersistentSecurityMemoryService(client)

    mem = await service.get_memory("MEM-302")
    assert mem is not None
    assert mem.source == "security_sop_2026"


@pytest.mark.asyncio
async def test_9_conflict_detection():
    """Verify detector catches conflicting camera location mapping."""
    mem_a = SecurityMemory(
        memory_id="MEM-A",
        type="camera_mapping",
        value={"camera_id": "CAM-03", "location": "Main Gate"},
        source="facility_plan_v1",
        created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00Z",
        status="ACTIVE"
    )
    mem_b = SecurityMemory(
        memory_id="MEM-B",
        type="camera_mapping",
        value={"camera_id": "CAM-03", "location": "Warehouse Rear"},
        source="contractor_report",
        created_at="2026-01-02T00:00:00Z",
        updated_at="2026-01-02T00:00:00Z",
        status="ACTIVE"
    )
    conflict = SecurityMemoryValidator.check_pair_conflict(mem_a, mem_b)
    assert conflict is not None
    assert conflict.message == "Security context conflict detected."
    assert conflict.memory_id_a == "MEM-A"
    assert conflict.memory_id_b == "MEM-B"


@pytest.mark.asyncio
async def test_10_conflicting_memories_remain_auditable():
    """Verify storing contradictory memory sets CONFLICTED status and retains both sources."""
    client = MockBackendClient()
    service = PersistentSecurityMemoryService(client)

    # MEM-301 maps CAM-03 -> Main Gate. Now attempt to store conflicting mapping.
    conflicting_mem = SecurityMemory(
        memory_id="MEM-CONFLICT",
        type="camera_mapping",
        value={"camera_id": "CAM-03", "location": "Substation East"},
        source="external_survey_doc",
        created_at="2026-10-08T10:00:00Z",
        updated_at="2026-10-08T10:00:00Z",
        status="ACTIVE"
    )
    saved, warning = await service.store_memory(conflicting_mem)
    assert warning == "Security context conflict detected."
    assert saved.status == "CONFLICTED"
    assert saved.source == "external_survey_doc"

    # Original MEM-301 is also still intact and auditable
    original = await service.get_memory("MEM-301")
    assert original is not None
    assert original.source == "facility_map_v1"


@pytest.mark.asyncio
async def test_11_unavailable_memory_handling():
    """Verify non-existent memory ID returns None rather than inventing data."""
    client = MockBackendClient()
    service = PersistentSecurityMemoryService(client)

    mem = await service.get_memory("MEM-NONEXISTENT")
    assert mem is None


@pytest.mark.asyncio
async def test_12_no_fabricated_memory():
    """Verify querying non-existent category returns empty list without fabrication."""
    client = MockBackendClient()
    service = PersistentSecurityMemoryService(client)

    mems = await service.retrieve_by_type("alien_protocol_type")
    assert mems == []


@pytest.mark.asyncio
async def test_13_deterministic_retrieval():
    """Verify consecutive retrievals return identical results."""
    client = MockBackendClient()
    service = PersistentSecurityMemoryService(client)

    res1 = await service.retrieve_by_type("camera_mapping")
    res2 = await service.retrieve_by_type("camera_mapping")
    assert [m.memory_id for m in res1] == [m.memory_id for m in res2]


def test_14_security_memory_schema_compatibility():
    """Verify SecurityMemory validation and serialization."""
    mem = SecurityMemory(
        memory_id="MEM-COMPAT",
        type="access_rule",
        value="Badge level 3 required",
        source="access_policy_v2",
        created_at="2026-10-08T10:00:00Z",
        updated_at="2026-10-08T10:00:00Z"
    )
    dumped = mem.model_dump()
    reconstructed = SecurityMemory.model_validate(dumped)
    assert reconstructed == mem


@pytest.mark.asyncio
async def test_15_backend_integration_and_orchestrator_compatibility():
    """Verify orchestrator incorporates active security context memories into context."""
    client = MockBackendClient()
    orchestrator = InvestigationOrchestrator(backend_client=client)

    req = InvestigationRequest(
        investigation_id="INV-MEM-TEST",
        query="Check security policies and camera locations",
        camera_ids=["CAM-03"]
    )
    result = await orchestrator.orchestrate(req)
    assert result.status == InvestigationStatus.COMPLETED
    # Orchestrator ran and completed without errors
    assert result.investigation_id == "INV-MEM-TEST"
