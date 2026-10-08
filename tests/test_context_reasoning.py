"""
Tests for Module 4: Step 11 - Security-Context Reasoning Component.
Covers all 20 required test scenarios:
1. observed facts are preserved
2. security memory context
3. source preservation
4. memory conflict detection
5. missing context
6. temporal relevance
7. temporal mismatch
8. zone context
9. supplied policy context
10. cross-camera context
11. observed facts vs context separation
12. inference separation
13. unknown handling
14. no fabricated policy
15. no fabricated identity
16. no fabricated evidence
17. deterministic output
18. compatibility with existing schemas
19. compatibility with memory layer
20. compatibility with orchestrator
"""
import pytest

from agent.context import InvestigationContext
from agent.orchestrator import InvestigationOrchestrator
from agent.request_handler import InvestigationRequestHandler
from integration.mock_client import MockBackendClient
from investigation.entity_correlation import EntityCorrelationEngine
from investigation.timeline import TimelineEngine
from memory.persistent_memory import PersistentSecurityMemoryService
from reasoning.context_reasoning import (
    SecurityContextItem,
    SecurityContextReasoningEngine,
    SecurityContextReasoningResult,
)
from schemas.events import Event
from schemas.evidence import Evidence
from schemas.investigation import (
    InvestigationRequest,
    InvestigationStatus,
    TimelineItem,
)
from schemas.memory import SecurityMemory


@pytest.fixture
def mock_client():
    return MockBackendClient()


@pytest.fixture
def sample_event():
    return Event(
        event_id="EVT-101",
        camera_id="CAM-01",
        timestamp="2026-10-08T10:15:00Z",
        event_type="person_detection",
        zone_id="Z-01",
        entity_id="ENT-404",
        confidence=0.92,
        status="OBSERVED"
    )


@pytest.fixture
def sample_evidence():
    return Evidence(
        evidence_id="EVI-201",
        camera_id="CAM-01",
        timestamp_start="2026-10-08T10:15:00Z",
        timestamp_end="2026-10-08T10:15:10Z",
        verification_status="VERIFIED",
        metadata={"zone_id": "Z-01"}
    )


@pytest.fixture
def sample_memories():
    return [
        SecurityMemory(
            memory_id="MEM-001",
            type="camera_mapping",
            value={"camera_id": "CAM-01", "location": "North Entrance Gate"},
            source="facility_map_v1",
            created_at="2026-10-01T00:00:00Z",
            updated_at="2026-10-01T00:00:00Z",
            status="ACTIVE"
        ),
        SecurityMemory(
            memory_id="MEM-002",
            type="zone_policy",
            value={"zone_id": "Z-01", "policy": "Authorized Personnel Only"},
            source="security_sop_v2",
            created_at="2026-10-01T00:00:00Z",
            updated_at="2026-10-01T00:00:00Z",
            status="ACTIVE"
        ),
        SecurityMemory(
            memory_id="MEM-003",
            type="shift_schedule",
            value={"shift": "Day Shift", "hours": "08:00-16:00"},
            source="hr_shift_roster",
            created_at="2026-10-01T00:00:00Z",
            updated_at="2026-10-01T00:00:00Z",
            status="ACTIVE"
        ),
    ]


# 1. observed facts are preserved
def test_observed_facts_are_preserved(sample_event, sample_evidence, sample_memories):
    result = SecurityContextReasoningEngine.reason(
        events=[sample_event],
        evidence=[sample_evidence],
        memories=sample_memories
    )

    assert result.is_sufficient is True
    assert len(result.observed_facts) >= 2
    assert any("EVT-101" in fact and "CAM-01" in fact and "Z-01" in fact for fact in result.observed_facts)
    assert any("EVI-201" in fact and "CAM-01" in fact for fact in result.observed_facts)


# 2. security memory context
def test_security_memory_context(sample_event, sample_memories):
    result = SecurityContextReasoningEngine.reason(
        events=[sample_event],
        memories=sample_memories
    )

    assert len(result.security_context) == 3
    cam_item = next(c for c in result.security_context if c.category == "camera_mapping")
    assert cam_item.camera_id == "CAM-01"
    assert "North Entrance Gate" in cam_item.statement
    assert cam_item.memory_id == "MEM-001"
    assert cam_item.created_at == "2026-10-01T00:00:00Z"
    assert cam_item.updated_at == "2026-10-01T00:00:00Z"
    assert cam_item.status == "ACTIVE"


# 3. source preservation
def test_source_preservation(sample_event, sample_evidence, sample_memories):
    result = SecurityContextReasoningEngine.reason(
        events=[sample_event],
        evidence=[sample_evidence],
        memories=sample_memories
    )

    assert len(result.source_references) >= 3
    assert any("facility_map_v1" in s for s in result.source_references)
    assert any("security_sop_v2" in s for s in result.source_references)
    assert any("event:EVT-101" in s for s in result.source_references)

    for item in result.security_context:
        assert item.source in ["facility_map_v1", "security_sop_v2", "hr_shift_roster"]


# 4. memory conflict detection
def test_memory_conflict_detection(sample_event):
    conflicted_memories = [
        SecurityMemory(
            memory_id="MEM-101",
            type="camera_mapping",
            value={"camera_id": "CAM-01", "location": "North Entrance Gate"},
            source="facility_map_a",
            created_at="2026-10-01T00:00:00Z",
            updated_at="2026-10-01T00:00:00Z",
            status="ACTIVE"
        ),
        SecurityMemory(
            memory_id="MEM-102",
            type="camera_mapping",
            value={"camera_id": "CAM-01", "location": "Vault Interior"},
            source="facility_map_b",
            created_at="2026-10-02T00:00:00Z",
            updated_at="2026-10-02T00:00:00Z",
            status="ACTIVE"
        )
    ]

    result = SecurityContextReasoningEngine.reason(
        events=[sample_event],
        memories=conflicted_memories
    )

    assert result.has_conflict is True
    assert result.conflict_message == "Security context conflict detected."
    assert "Security context conflict detected." in result.limitations
    assert len(result.conflicts) >= 1
    # Does not arbitrarily pick a location
    assert not any("North Entrance Gate" in inf for inf in result.inferences)
    assert not any("Vault Interior" in inf for inf in result.inferences)


# 5. missing context
def test_missing_context(sample_event):
    result = SecurityContextReasoningEngine.reason(
        events=[sample_event],
        memories=[]
    )

    assert "Security context unavailable." in result.limitations
    assert any("Physical location mapping for camera CAM-01 is unrecorded" in u for u in result.unknowns)
    assert any("Operating policy rules for zone Z-01 are unrecorded" in u for u in result.unknowns)


# 6. temporal relevance
def test_temporal_relevance(sample_event, sample_memories):
    time_range = {"start": "2026-10-08T10:00:00Z", "end": "2026-10-08T11:00:00Z"}
    result = SecurityContextReasoningEngine.reason(
        events=[sample_event],
        memories=sample_memories,
        time_range=time_range
    )

    assert not any("Temporal context mismatch" in lim for lim in result.limitations)
    assert any("Temporal context verified within investigation window" in f for f in result.observed_facts)


# 7. temporal mismatch
def test_temporal_mismatch(sample_event, sample_memories):
    time_range = {"start": "2026-10-08T11:00:00Z", "end": "2026-10-08T12:00:00Z"}
    result = SecurityContextReasoningEngine.reason(
        events=[sample_event],  # timestamp is 10:15:00Z
        memories=sample_memories,
        time_range=time_range
    )

    assert any("Temporal context mismatch" in lim and "precedes investigation window start" in lim for lim in result.limitations)


# 8. zone context
def test_zone_context(sample_event):
    zone_memory = SecurityMemory(
        memory_id="MEM-ZONE-01",
        type="zone_policy",
        value={"zone_id": "Z-01", "policy": "Restricted Area - Badge Required"},
        source="security_director",
        created_at="2026-10-01T00:00:00Z",
        updated_at="2026-10-01T00:00:00Z",
        status="ACTIVE"
    )

    result = SecurityContextReasoningEngine.reason(
        events=[sample_event],
        memories=[zone_memory]
    )

    zone_item = next(c for c in result.security_context if c.zone_id == "Z-01")
    assert zone_item.statement == "Zone Z-01 operates under policy: 'Restricted Area - Badge Required'"
    assert any("Activity in zone Z-01 is subject to configured policy 'Restricted Area - Badge Required'" in inf for inf in result.inferences)


# 9. supplied policy context
def test_supplied_policy_context(sample_event):
    supplied_policies = [
        {
            "policy_id": "POL-DIRECTOR-9",
            "zone_id": "Z-01",
            "policy": "Emergency Lockdown Order Active",
            "source": "chief_of_security"
        }
    ]

    result = SecurityContextReasoningEngine.reason(
        events=[sample_event],
        supplied_policies=supplied_policies
    )

    pol_ctx = next(c for c in result.security_context if c.category == "supplied_policy")
    assert pol_ctx.source == "chief_of_security"
    assert "Emergency Lockdown Order Active" in pol_ctx.statement
    assert any("Activity in zone Z-01 is subject to configured policy 'Emergency Lockdown Order Active'" in inf for inf in result.inferences)


# 10. cross-camera context
def test_cross_camera_context():
    evt1 = Event(
        event_id="EVT-01",
        camera_id="CAM-01",
        timestamp="2026-10-08T10:00:00Z",
        event_type="person_detection",
        entity_id="ENT-404"
    )
    evt2 = Event(
        event_id="EVT-02",
        camera_id="CAM-02",
        timestamp="2026-10-08T10:05:00Z",
        event_type="person_detection",
        entity_id="ENT-404"
    )

    correlation_res = EntityCorrelationEngine.correlate(events=[evt1, evt2])
    assert len(correlation_res.trajectories) >= 1

    result = SecurityContextReasoningEngine.reason(
        events=[evt1, evt2],
        correlations=correlation_res.trajectories
    )

    assert any(
        "Tracked entity entity_id=ENT-404 was observed across multiple cameras: CAM-01, CAM-02." in inf
        for inf in result.inferences
    )
    # Does not fabricate personal identity
    assert not any("person" in inf.lower() and "named" in inf.lower() for inf in result.inferences)


# 11. observed facts vs context separation
def test_observed_facts_vs_context_separation(sample_event, sample_evidence, sample_memories):
    result = SecurityContextReasoningEngine.reason(
        events=[sample_event],
        evidence=[sample_evidence],
        memories=sample_memories
    )

    for fact in result.observed_facts:
        assert "Event EVT-101" in fact or "Evidence EVI-201" in fact or "Temporal context verified" in fact
        assert "operates under policy" not in fact

    for ctx in result.security_context:
        assert isinstance(ctx, SecurityContextItem)
        assert ctx.category in ["camera_mapping", "zone_policy", "shift_schedule"]


# 12. inference separation
def test_inference_separation(sample_event, sample_memories):
    result = SecurityContextReasoningEngine.reason(
        events=[sample_event],
        memories=sample_memories
    )

    for inf in result.inferences:
        assert "Observations on camera" in inf or "Activity in zone" in inf

    for fact in result.observed_facts:
        assert "subject to configured policy" not in fact


# 13. unknown handling
def test_unknown_handling(sample_event):
    result = SecurityContextReasoningEngine.reason(
        events=[sample_event],
        memories=[]
    )

    assert len(result.unknowns) >= 3
    assert any("Tracked entity ENT-404 identity cannot be verified" in u for u in result.unknowns)
    assert any("Physical location mapping for camera CAM-01 is unrecorded" in u for u in result.unknowns)
    assert any("Operating policy rules for zone Z-01 are unrecorded" in u for u in result.unknowns)


# 14. no fabricated policy
def test_no_fabricated_policy(sample_event):
    result = SecurityContextReasoningEngine.reason(
        events=[sample_event],
        memories=[]
    )

    for inf in result.inferences:
        assert "Restricted" not in inf
        assert "prohibited" not in inf.lower()
        assert "unauthorized" not in inf.lower()

    assert any("Operating policy rules for zone Z-01 are unrecorded" in u for u in result.unknowns)


# 15. no fabricated identity
def test_no_fabricated_identity(sample_event, sample_memories):
    result = SecurityContextReasoningEngine.reason(
        events=[sample_event],
        memories=sample_memories
    )

    for text in result.observed_facts + result.inferences:
        assert "John" not in text
        assert "Doe" not in text
        assert "employee" not in text.lower()
        assert "suspect" not in text.lower()

    assert any("Tracked entity ENT-404 identity cannot be verified" in u for u in result.unknowns)


# 16. no fabricated evidence
def test_no_fabricated_evidence():
    result = SecurityContextReasoningEngine.reason(
        events=[],
        evidence=[]
    )

    assert result.is_sufficient is False
    assert result.observed_facts == []
    assert result.inferences == []
    assert "I don't know — insufficient evidence." in result.limitations
    assert "Required observation evidence is unavailable." in result.unknowns


# 17. deterministic output
def test_deterministic_output(sample_event, sample_evidence, sample_memories):
    res1 = SecurityContextReasoningEngine.reason(
        events=[sample_event],
        evidence=[sample_evidence],
        memories=sample_memories
    )
    res2 = SecurityContextReasoningEngine.reason(
        events=[sample_event],
        evidence=[sample_evidence],
        memories=sample_memories
    )

    assert res1.model_dump() == res2.model_dump()


# 18. compatibility with existing schemas
def test_compatibility_with_existing_schemas(sample_event, sample_evidence, sample_memories):
    timeline_res = TimelineEngine.construct(
        events=[sample_event],
        evidence=[sample_evidence]
    )
    assert len(timeline_res.timeline) >= 1

    result = SecurityContextReasoningEngine.reason(
        events=[sample_event],
        evidence=[sample_evidence],
        memories=sample_memories,
        timeline=timeline_res.timeline
    )

    assert any("Timeline established with" in inf for inf in result.inferences)
    assert result.is_sufficient is True


# 19. compatibility with memory layer
@pytest.mark.asyncio
async def test_compatibility_with_memory_layer(mock_client, sample_event):
    service = PersistentSecurityMemoryService(mock_client)
    memory_to_store = SecurityMemory(
        memory_id="MEM-777",
        type="camera_mapping",
        value={"camera_id": "CAM-01", "location": "Perimeter East"},
        source="security_audit_2026",
        created_at="2026-10-01T00:00:00Z",
        updated_at="2026-10-01T00:00:00Z",
        status="ACTIVE"
    )
    await service.store_memory(memory_to_store)

    memories = await service.list_all(status="ACTIVE")
    context_res = SecurityContextReasoningEngine.reason(
        events=[sample_event],
        memories=memories
    )

    assert any("Perimeter East" in inf for inf in context_res.inferences)
    assert any(c.memory_id == "MEM-777" for c in context_res.security_context)


# 20. compatibility with orchestrator
@pytest.mark.asyncio
async def test_compatibility_with_orchestrator(mock_client):
    req_data = {
        "investigation_id": "INV-STEP11-ORCH",
        "query": "Investigate access at North Entrance Gate",
        "camera_ids": ["CAM-01"],
        "zone_ids": ["Z-01"]
    }
    prep_req = InvestigationRequestHandler.validate_and_prepare(req_data)

    orchestrator = InvestigationOrchestrator(mock_client)
    result = await orchestrator.orchestrate(prep_req)

    # Verify orchestrator ran pipeline through SecurityContextStage cleanly
    assert result.investigation_id == "INV-STEP11-ORCH"
    assert result.status in [
        InvestigationStatus.COMPLETED,
        InvestigationStatus.INSUFFICIENT_EVIDENCE,
        InvestigationStatus.CONFLICTED_EVIDENCE,
    ]
    assert isinstance(result.observed_facts, list)
    assert isinstance(result.unknowns, list)
