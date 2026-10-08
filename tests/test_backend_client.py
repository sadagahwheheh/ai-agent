"""
Tests for Module 4 Backend Integration Client.
Validates client behavior, configuration, error translation, and mock data provider.
"""
import pytest
import httpx

from integration.config import BackendSettings
from integration.backend_client import BackendClient
from integration.mock_client import MockBackendClient
from integration.exceptions import (
    BackendAuthError,
    BackendConnectionError,
    BackendDataNotFoundError,
    BackendIntegrationError,
    BackendTimeoutError,
)


def test_backend_settings_defaults():
    settings = BackendSettings()
    assert settings.base_url == "http://localhost:8000"
    assert settings.request_timeout_seconds == 10.0
    assert settings.endpoint_cameras == "/api/cameras"
    assert settings.endpoint_events == "/api/events"
    assert settings.endpoint_incidents == "/api/incidents"
    assert settings.endpoint_investigations == "/api/investigations"


def test_backend_client_headers():
    settings = BackendSettings(api_key="secret-key")
    client = BackendClient(settings=settings)
    
    # API Key header
    headers = client._build_headers()
    assert headers.get("X-API-Key") == "secret-key"

    # Bearer token override
    token_headers = client._build_headers(auth_token="jwt.token.here")
    assert token_headers.get("Authorization") == "Bearer jwt.token.here"

    # Token with Bearer already included
    prefixed_headers = client._build_headers(auth_token="Bearer custom.token")
    assert prefixed_headers.get("Authorization") == "Bearer custom.token"


@pytest.mark.asyncio
async def test_backend_client_mock_transport_success():
    """Verify BackendClient parsing against an httpx MockTransport."""
    def handler(request: httpx.Request):
        if request.url.path == "/api/cameras/CAM-03":
            return httpx.Response(200, json={"camera_id": "CAM-03", "status": "CONNECTED"})
        if request.url.path == "/api/cameras/CAM-99":
            return httpx.Response(404, json={"detail": "Camera not found"})
        if request.url.path == "/api/events":
            return httpx.Response(200, json=[{"event_id": "EVT-1029", "camera_id": "CAM-03"}])
        return httpx.Response(500, json={"error": "Internal Error"})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http_client:
        client = BackendClient(client=http_client)
        
        # Test 200 OK
        cam = await client.get_camera("CAM-03")
        assert cam["camera_id"] == "CAM-03"
        assert cam["status"] == "CONNECTED"

        # Test 404 Not Found
        with pytest.raises(BackendDataNotFoundError):
            await client.get_camera("CAM-99")

        # Test list events
        events = await client.search_events()
        assert len(events) == 1
        assert events[0]["event_id"] == "EVT-1029"


@pytest.mark.asyncio
async def test_backend_client_auth_error():
    """Verify BackendClient 401 raises BackendAuthError."""
    def handler(request: httpx.Request):
        return httpx.Response(401, json={"error": "Unauthorized"})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http_client:
        client = BackendClient(client=http_client)
        with pytest.raises(BackendAuthError):
            await client.get_camera("CAM-03")


@pytest.mark.asyncio
async def test_mock_backend_client_lifecycle_and_data():
    """Verify MockBackendClient contract and canonical identifiers."""
    async with MockBackendClient() as client:
        # Camera checks
        cam3 = await client.get_camera("CAM-03")
        assert cam3["camera_id"] == "CAM-03"
        assert cam3["status"] == "CONNECTED"

        cam4 = await client.get_camera("CAM-04")
        assert cam4["camera_id"] == "CAM-04"
        assert cam4["status"] == "OFFLINE"

        with pytest.raises(BackendDataNotFoundError):
            await client.get_camera("CAM-NONEXISTENT")

        # Events query
        events = await client.search_events(camera_ids=["CAM-03"])
        assert len(events) == 1
        assert events[0]["event_id"] == "EVT-1029"
        assert events[0]["entity_id"] == "ENT-902"

        # Evidence checks
        evidence = await client.get_evidence("EVD-4091")
        assert evidence["evidence_id"] == "EVD-4091"
        assert evidence["camera_id"] == "CAM-03"

        # Incident & Threat checks
        incident = await client.get_incident("INC-8821")
        assert incident["incident_id"] == "INC-8821"
        assert "EVT-1029" in incident["associated_events"]

        threat = await client.get_threat("THR-5501")
        assert threat["threat_id"] == "THR-5501"
        assert threat["severity"] == "HIGH"

        # Security context memory
        memories = await client.get_security_memory(status="ACTIVE")
        assert len(memories) >= 2
        mem_ids = [m["memory_id"] for m in memories]
        assert "MEM-301" in mem_ids

        # Investigation result submission
        res = await client.post_investigation_result("INV-001", {"status": "COMPLETED", "answer": "Test answer"})
        assert res["status"] == "SUCCESS"
        fetched = await client.get_investigation("INV-001")
        assert fetched["status"] == "COMPLETED"

        # Realtime progress update
        prog = await client.send_realtime_status(
            investigation_id="INV-001",
            stage="investigation.searching_events",
            message="Searching indexed events"
        )
        assert prog["status"] == "ACK"
        assert len(client.progress_logs) == 1
        assert client.progress_logs[0]["stage"] == "investigation.searching_events"
