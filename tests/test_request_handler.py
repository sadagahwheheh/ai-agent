"""
Tests for Module 4 Investigation Request Handling.
Validates acceptance, normalization, no-fabrication rules, and error handling for incoming requests.
"""
import pytest

from agent.exceptions import RequestValidationError
from agent.request_handler import (
    InvestigationRequestHandler,
    PreparedInvestigationRequest,
)
from schemas.investigation import InvestigationRequest, TimeRange


def test_1_valid_investigation_request():
    raw = {
        "investigation_id": "INV-2026-001",
        "query": "Investigate unauthorized entry at Main Gate",
        "time_range": {"start": "2026-10-08T10:00:00Z", "end": "2026-10-08T11:00:00Z"},
        "camera_ids": ["CAM-03", "CAM-05"],
        "zone_ids": ["ZONE-01", "ZONE-04"],
        "incident_id": "INC-8821",
        "user_id": "USR-108"
    }
    prepared = InvestigationRequestHandler.validate_and_prepare(raw)
    assert isinstance(prepared, PreparedInvestigationRequest)
    assert prepared.investigation_id == "INV-2026-001"
    assert prepared.original_query == "Investigate unauthorized entry at Main Gate"
    assert prepared.camera_ids == ["CAM-03", "CAM-05"]
    assert prepared.zone_ids == ["ZONE-01", "ZONE-04"]
    assert prepared.incident_id == "INC-8821"
    assert prepared.user_id == "USR-108"
    assert prepared.has_time_filter is True
    assert prepared.has_camera_filter is True
    assert prepared.has_zone_filter is True
    assert prepared.has_incident_filter is True


def test_2_query_validation():
    # Missing query
    with pytest.raises(RequestValidationError) as exc:
        InvestigationRequestHandler.validate_and_prepare({"investigation_id": "INV-001"})
    assert "query" in str(exc.value)

    # Empty query
    with pytest.raises(RequestValidationError) as exc:
        InvestigationRequestHandler.validate_and_prepare({"investigation_id": "INV-001", "query": "   "})
    assert "query" in str(exc.value)


def test_3_investigation_id_validation():
    # Missing investigation_id
    with pytest.raises(RequestValidationError) as exc:
        InvestigationRequestHandler.validate_and_prepare({"query": "What happened?"})
    assert "investigation_id" in str(exc.value)

    # Empty investigation_id
    with pytest.raises(RequestValidationError) as exc:
        InvestigationRequestHandler.validate_and_prepare({"investigation_id": "  ", "query": "What happened?"})
    assert "investigation_id" in str(exc.value)


def test_4_optional_camera_ids():
    raw = {
        "investigation_id": "INV-001",
        "query": "Check system status"
    }
    prepared = InvestigationRequestHandler.validate_and_prepare(raw)
    assert prepared.camera_ids is None
    assert prepared.has_camera_filter is False

    # Invalid camera_ids item
    with pytest.raises(RequestValidationError):
        InvestigationRequestHandler.validate_and_prepare({
            "investigation_id": "INV-001",
            "query": "Check status",
            "camera_ids": ["CAM-01", ""]
        })

    # Non-list camera_ids
    with pytest.raises(RequestValidationError):
        InvestigationRequestHandler.validate_and_prepare({
            "investigation_id": "INV-001",
            "query": "Check status",
            "camera_ids": "CAM-01"
        })


def test_5_optional_zone_ids():
    raw = {
        "investigation_id": "INV-001",
        "query": "Check perimeter"
    }
    prepared = InvestigationRequestHandler.validate_and_prepare(raw)
    assert prepared.zone_ids is None
    assert prepared.has_zone_filter is False

    # Invalid zone_ids item
    with pytest.raises(RequestValidationError):
        InvestigationRequestHandler.validate_and_prepare({
            "investigation_id": "INV-001",
            "query": "Check status",
            "zone_ids": ["ZONE-01", "  "]
        })


def test_6_optional_incident_id():
    raw = {
        "investigation_id": "INV-001",
        "query": "Check perimeter"
    }
    prepared = InvestigationRequestHandler.validate_and_prepare(raw)
    assert prepared.incident_id is None
    assert prepared.has_incident_filter is False

    # Empty incident_id rejected
    with pytest.raises(RequestValidationError):
        InvestigationRequestHandler.validate_and_prepare({
            "investigation_id": "INV-001",
            "query": "Check status",
            "incident_id": "   "
        })


def test_7_valid_time_range():
    raw = {
        "investigation_id": "INV-001",
        "query": "What happened between 10:00 and 11:00?",
        "time_range": {
            "start": "2026-10-08T10:00:00Z",
            "end": "2026-10-08T11:00:00Z"
        }
    }
    prepared = InvestigationRequestHandler.validate_and_prepare(raw)
    assert prepared.time_range is not None
    assert prepared.time_range.start == "2026-10-08T10:00:00Z"
    assert prepared.time_range.end == "2026-10-08T11:00:00Z"


def test_8_invalid_time_range_ordering():
    # start after end must be rejected
    raw = {
        "investigation_id": "INV-001",
        "query": "Check time window",
        "time_range": {
            "start": "2026-10-08T12:00:00Z",
            "end": "2026-10-08T10:00:00Z"
        }
    }
    with pytest.raises(RequestValidationError) as exc:
        InvestigationRequestHandler.validate_and_prepare(raw)
    assert "cannot be after end time" in str(exc.value)


def test_9_malformed_request_rejection():
    # Non-dict and non-model input
    with pytest.raises(RequestValidationError):
        InvestigationRequestHandler.validate_and_prepare("Not a dictionary or model")  # type: ignore

    with pytest.raises(RequestValidationError):
        InvestigationRequestHandler.validate_and_prepare([1, 2, 3])  # type: ignore


def test_10_preservation_of_original_query():
    complex_query = "Who entered ZONE-04 after 22:00 without badge authorization? (Urgent)"
    raw = {
        "investigation_id": "INV-999",
        "query": complex_query
    }
    prepared = InvestigationRequestHandler.validate_and_prepare(raw)
    assert prepared.original_query == complex_query


def test_11_preservation_of_supplied_ids():
    raw = {
        "investigation_id": "INV-SPECIFIC-ID-123",
        "query": "Track entity ENT-902",
        "camera_ids": ["CAM-03", "CAM-05"],
        "zone_ids": ["ZONE-04"],
        "incident_id": "INC-8821"
    }
    prepared = InvestigationRequestHandler.validate_and_prepare(raw)
    assert prepared.investigation_id == "INV-SPECIFIC-ID-123"
    assert prepared.camera_ids == ["CAM-03", "CAM-05"]
    assert prepared.zone_ids == ["ZONE-04"]
    assert prepared.incident_id == "INC-8821"


def test_12_no_fabrication_of_missing_values():
    """Verify that absent filters remain explicitly None and are never hallucinated."""
    raw = {
        "investigation_id": "INV-002",
        "query": "General perimeter scan"
    }
    prepared = InvestigationRequestHandler.validate_and_prepare(raw)
    assert prepared.time_range is None
    assert prepared.camera_ids is None
    assert prepared.zone_ids is None
    assert prepared.incident_id is None
    assert prepared.user_id is None
