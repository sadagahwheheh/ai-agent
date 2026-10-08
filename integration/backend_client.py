"""
Module 4: Backend API Integration Client.
Handles all outbound HTTP communication between AI Investigation Agent and Backend Security Core (Module 2).
Module 4 NEVER communicates directly with the database or CCTV cameras.
"""
from typing import Any, Dict, List, Optional
import httpx

from integration.config import BackendSettings
from integration.exceptions import (
    BackendAuthError,
    BackendConnectionError,
    BackendDataNotFoundError,
    BackendIntegrationError,
    BackendTimeoutError,
    BackendValidationError,
)


class BackendClient:
    """
    Asynchronous HTTP client for interacting with Backend Security Core (Module 2).
    Enforces authorization forwarding, canonical endpoint usage, and structured error mapping.
    """

    def __init__(self, settings: Optional[BackendSettings] = None, client: Optional[httpx.AsyncClient] = None):
        self.settings = settings or BackendSettings()
        self._external_client = client is not None
        self._client = client or httpx.AsyncClient(
            base_url=self.settings.base_url.rstrip("/"),
            timeout=self.settings.request_timeout_seconds,
            headers={"Content-Type": "application/json", "Accept": "application/json"}
        )

    async def __aenter__(self) -> "BackendClient":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the underlying HTTP client session if owned by this instance."""
        if not self._external_client and not self._client.is_closed:
            await self._client.aclose()

    def _build_headers(self, auth_token: Optional[str] = None) -> Dict[str, str]:
        """Construct request headers including authorization and API keys."""
        headers: Dict[str, str] = {}
        if auth_token:
            headers[self.settings.auth_header_name] = (
                f"Bearer {auth_token}" if not auth_token.lower().startswith("bearer ") else auth_token
            )
        elif self.settings.api_key:
            headers["X-API-Key"] = self.settings.api_key
        return headers

    async def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        auth_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Core internal HTTP request dispatcher with structured error handling."""
        headers = self._build_headers(auth_token)
        try:
            response = await self._client.request(
                method=method,
                url=path,
                params=params,
                json=json_data,
                headers=headers
            )
            
            if response.status_code == 401 or response.status_code == 403:
                raise BackendAuthError(
                    f"Authentication/Authorization failed for Backend endpoint: {path}",
                    status_code=response.status_code,
                    details={"response_text": response.text}
                )
            if response.status_code == 404:
                raise BackendDataNotFoundError(
                    f"Resource not found at Backend endpoint: {path}",
                    status_code=response.status_code,
                    details={"params": params, "response_text": response.text}
                )
            if response.is_error:
                raise BackendIntegrationError(
                    f"Backend error ({response.status_code}) on {path}: {response.text}",
                    status_code=response.status_code,
                    details={"response_text": response.text}
                )

            try:
                return response.json()
            except Exception as json_err:
                raise BackendValidationError(
                    f"Invalid JSON returned from Backend: {json_err}",
                    status_code=response.status_code
                ) from json_err

        except httpx.TimeoutException as exc:
            raise BackendTimeoutError(
                f"Backend request timed out after {self.settings.request_timeout_seconds}s for {path}"
            ) from exc
        except httpx.ConnectError as exc:
            raise BackendConnectionError(
                f"Failed to connect to Backend Security Core at {self.settings.base_url}"
            ) from exc
        except (BackendAuthError, BackendDataNotFoundError, BackendValidationError, BackendIntegrationError):
            raise
        except Exception as exc:
            raise BackendIntegrationError(f"Unexpected error communicating with Backend: {exc}") from exc

    # =========================================================================
    # CAMERAS (camera_id)
    # =========================================================================

    async def get_camera(self, camera_id: str, auth_token: Optional[str] = None) -> Dict[str, Any]:
        """Fetch metadata and health status for a specific camera."""
        return await self._request("GET", f"{self.settings.endpoint_cameras}/{camera_id}", auth_token=auth_token)

    async def list_cameras(self, auth_token: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all registered cameras."""
        data = await self._request("GET", self.settings.endpoint_cameras, auth_token=auth_token)
        return data if isinstance(data, list) else data.get("items", [])

    # =========================================================================
    # EVENTS (event_id, camera_id, zone_id, entity_id)
    # =========================================================================

    async def get_event(self, event_id: str, auth_token: Optional[str] = None) -> Dict[str, Any]:
        """Fetch indexed event details by event_id."""
        return await self._request("GET", f"{self.settings.endpoint_events}/{event_id}", auth_token=auth_token)

    async def search_events(
        self,
        time_range: Optional[Dict[str, str]] = None,
        camera_ids: Optional[List[str]] = None,
        zone_ids: Optional[List[str]] = None,
        entity_id: Optional[str] = None,
        event_types: Optional[List[str]] = None,
        auth_token: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Query indexed security events using filters."""
        params: Dict[str, Any] = {}
        if time_range:
            if "start" in time_range:
                params["start_time"] = time_range["start"]
            if "end" in time_range:
                params["end_time"] = time_range["end"]
        if camera_ids:
            params["camera_ids"] = ",".join(camera_ids)
        if zone_ids:
            params["zone_ids"] = ",".join(zone_ids)
        if entity_id:
            params["entity_id"] = entity_id
        if event_types:
            params["event_types"] = ",".join(event_types)

        data = await self._request("GET", self.settings.endpoint_events, params=params, auth_token=auth_token)
        return data if isinstance(data, list) else data.get("items", [])

    # =========================================================================
    # THREATS (threat_id) & INCIDENTS (incident_id)
    # =========================================================================

    async def get_incident(self, incident_id: str, auth_token: Optional[str] = None) -> Dict[str, Any]:
        """Fetch incident metadata and associated events/threats."""
        return await self._request("GET", f"{self.settings.endpoint_incidents}/{incident_id}", auth_token=auth_token)

    async def get_threat(self, threat_id: str, auth_token: Optional[str] = None) -> Dict[str, Any]:
        """Fetch threat assessment information."""
        return await self._request("GET", f"{self.settings.endpoint_threats}/{threat_id}", auth_token=auth_token)

    # =========================================================================
    # EVIDENCE (evidence_id)
    # =========================================================================

    async def get_evidence(self, evidence_id: str, auth_token: Optional[str] = None) -> Dict[str, Any]:
        """Fetch evidence metadata and verification provenance."""
        return await self._request("GET", f"{self.settings.endpoint_evidence}/{evidence_id}", auth_token=auth_token)

    async def list_evidence_for_event(self, event_id: str, auth_token: Optional[str] = None) -> List[Dict[str, Any]]:
        """Fetch evidence items tied to an event."""
        params = {"event_id": event_id}
        data = await self._request("GET", self.settings.endpoint_evidence, params=params, auth_token=auth_token)
        return data if isinstance(data, list) else data.get("items", [])

    # =========================================================================
    # SECURITY MEMORY (memory_id)
    # =========================================================================

    async def get_security_memory(
        self,
        memory_type: Optional[str] = None,
        status: Optional[str] = None,
        auth_token: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch persistent security context memory items."""
        params: Dict[str, Any] = {}
        if memory_type:
            params["type"] = memory_type
        if status:
            params["status"] = status
        data = await self._request("GET", self.settings.endpoint_security_memory, params=params, auth_token=auth_token)
        return data if isinstance(data, list) else data.get("items", [])

    async def save_security_memory(self, memory_item: Dict[str, Any], auth_token: Optional[str] = None) -> Dict[str, Any]:
        """Propose or persist an auditable security context memory entry via Backend."""
        return await self._request("POST", self.settings.endpoint_security_memory, json_data=memory_item, auth_token=auth_token)

    # =========================================================================
    # INVESTIGATION RESULTS & REALTIME STATUS (investigation_id)
    # =========================================================================

    async def get_investigation(self, investigation_id: str, auth_token: Optional[str] = None) -> Dict[str, Any]:
        """Fetch an investigation record by ID."""
        return await self._request("GET", f"{self.settings.endpoint_investigations}/{investigation_id}", auth_token=auth_token)

    async def post_investigation_result(
        self,
        investigation_id: str,
        result_payload: Dict[str, Any],
        auth_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Post finalized investigation result to Backend Security Core."""
        return await self._request(
            "POST",
            f"{self.settings.endpoint_investigations}/{investigation_id}/result",
            json_data=result_payload,
            auth_token=auth_token
        )

    async def send_realtime_status(
        self,
        investigation_id: str,
        stage: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None,
        auth_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Send investigation lifecycle status update via Backend.
        Permitted stages:
          investigation.started
          investigation.searching_events
          investigation.searching_cameras
          investigation.tracking_entity
          investigation.building_timeline
          investigation.verifying_evidence
          investigation.completed
          investigation.insufficient_evidence
        """
        payload = {
            "investigation_id": investigation_id,
            "stage": stage,
            "message": message,
            "metadata": metadata or {}
        }
        return await self._request(
            "POST",
            f"{self.settings.endpoint_investigations}/{investigation_id}/progress",
            json_data=payload,
            auth_token=auth_token
        )

    # =========================================================================
    # COPILOT (endpoint_copilot)
    # =========================================================================

    async def query_copilot(
        self,
        query_payload: Dict[str, Any],
        auth_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Send a natural-language copilot query to Backend Security Core."""
        return await self._request(
            "POST",
            self.settings.endpoint_copilot,
            json_data=query_payload,
            auth_token=auth_token,
        )

