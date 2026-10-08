"""
Module 4: Mock Backend Client for testing, simulation, and offline integration validation.
Maintains canonical structures matching Backend Security Core without connecting to a live server.
"""
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from integration.exceptions import BackendAuthError, BackendDataNotFoundError


class MockBackendClient:
    """
    In-memory simulation of Backend Security Core (Module 2) APIs.
    Provides canonical test fixtures for cameras, events, incidents, evidence, and memory.
    """

    def __init__(self):
        self.cameras: Dict[str, Dict[str, Any]] = {
            "CAM-03": {
                "camera_id": "CAM-03",
                "name": "Main Gate",
                "zone_id": "ZONE-01",
                "status": "CONNECTED",
                "coverage_area": "Main Gate North Entrance",
                "fps": 30,
            },
            "CAM-04": {
                "camera_id": "CAM-04",
                "name": "Perimeter East",
                "zone_id": "ZONE-02",
                "status": "OFFLINE",
                "coverage_area": "Perimeter Fence East",
                "fps": 0,
            },
            "CAM-05": {
                "camera_id": "CAM-05",
                "name": "Restricted Corridor",
                "zone_id": "ZONE-04",
                "status": "CONNECTED",
                "coverage_area": "Corridor leading to Server Room",
                "fps": 25,
            },
            "CAM-07": {
                "camera_id": "CAM-07",
                "name": "Warehouse Loading",
                "zone_id": "ZONE-03",
                "status": "CONNECTED",
                "coverage_area": "Loading Dock",
                "fps": 30,
            },
        }

        self.events: Dict[str, Dict[str, Any]] = {
            "EVT-1029": {
                "event_id": "EVT-1029",
                "camera_id": "CAM-03",
                "zone_id": "ZONE-01",
                "entity_id": "ENT-902",
                "event_type": "person_detected",
                "timestamp": "2026-10-08T10:42:13Z",
                "confidence": 0.95,
                "metadata": {"action": "entered_gate"}
            },
            "EVT-1030": {
                "event_id": "EVT-1030",
                "camera_id": "CAM-05",
                "zone_id": "ZONE-04",
                "entity_id": "ENT-902",
                "event_type": "restricted_zone_entry",
                "timestamp": "2026-10-08T10:43:02Z",
                "confidence": 0.92,
                "metadata": {"action": "breach_attempt"}
            }
        }

        self.evidence: Dict[str, Dict[str, Any]] = {
            "EVD-4091": {
                "evidence_id": "EVD-4091",
                "event_id": "EVT-1029",
                "camera_id": "CAM-03",
                "timestamp_start": "2026-10-08T10:42:13Z",
                "timestamp": "2026-10-08T10:42:13Z",
                "evidence_type": "video_snapshot",
                "source_ref": "storage://snapshots/CAM-03/20261008_104213.jpg",
                "verification_status": "VERIFIED",
                "quality_score": 0.96
            },
            "EVD-4092": {
                "evidence_id": "EVD-4092",
                "event_id": "EVT-1030",
                "camera_id": "CAM-05",
                "timestamp_start": "2026-10-08T10:43:02Z",
                "timestamp": "2026-10-08T10:43:02Z",
                "evidence_type": "video_clip",
                "source_ref": "storage://clips/CAM-05/20261008_104302.mp4",
                "verification_status": "VERIFIED",
                "quality_score": 0.91
            }
        }

        self.incidents: Dict[str, Dict[str, Any]] = {
            "INC-8821": {
                "incident_id": "INC-8821",
                "title": "Unauthorized Entry into Restricted Corridor",
                "status": "OPEN",
                "zone_id": "ZONE-04",
                "start_time": "2026-10-08T10:42:00Z",
                "associated_events": ["EVT-1029", "EVT-1030"],
                "associated_threat_id": "THR-5501"
            }
        }

        self.threats: Dict[str, Dict[str, Any]] = {
            "THR-5501": {
                "threat_id": "THR-5501",
                "incident_id": "INC-8821",
                "severity": "HIGH",
                "score": 0.88,
                "reason": "Policy violation in restricted zone during prohibited hours."
            }
        }

        self.memories: Dict[str, Dict[str, Any]] = {
            "MEM-301": {
                "memory_id": "MEM-301",
                "type": "camera_mapping",
                "value": {"camera_id": "CAM-03", "location": "Main Gate"},
                "source": "facility_map_v1",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
                "status": "ACTIVE"
            },
            "MEM-302": {
                "memory_id": "MEM-302",
                "type": "zone_policy",
                "value": {"zone_id": "ZONE-04", "policy": "Restricted Access 24/7"},
                "source": "security_sop_2026",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
                "status": "ACTIVE"
            }
        }

        self.investigation_results: Dict[str, Dict[str, Any]] = {}
        self.progress_logs: List[Dict[str, Any]] = []

    async def __aenter__(self) -> "MockBackendClient":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    async def close(self) -> None:
        pass

    async def get_camera(self, camera_id: str, auth_token: Optional[str] = None) -> Dict[str, Any]:
        if camera_id not in self.cameras:
            raise BackendDataNotFoundError(f"Camera {camera_id} not found", status_code=404)
        return self.cameras[camera_id]

    async def list_cameras(self, auth_token: Optional[str] = None) -> List[Dict[str, Any]]:
        return list(self.cameras.values())

    async def get_event(self, event_id: str, auth_token: Optional[str] = None) -> Dict[str, Any]:
        if event_id not in self.events:
            raise BackendDataNotFoundError(f"Event {event_id} not found", status_code=404)
        return self.events[event_id]

    async def search_events(
        self,
        time_range: Optional[Dict[str, str]] = None,
        camera_ids: Optional[List[str]] = None,
        zone_ids: Optional[List[str]] = None,
        entity_id: Optional[str] = None,
        event_types: Optional[List[str]] = None,
        auth_token: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        results = []
        for event in self.events.values():
            if camera_ids and event.get("camera_id") not in camera_ids:
                continue
            if zone_ids and event.get("zone_id") not in zone_ids:
                continue
            if entity_id and event.get("entity_id") != entity_id:
                continue
            if event_types and event.get("event_type") not in event_types:
                continue
            results.append(event)
        return results

    async def get_incident(self, incident_id: str, auth_token: Optional[str] = None) -> Dict[str, Any]:
        if incident_id not in self.incidents:
            raise BackendDataNotFoundError(f"Incident {incident_id} not found", status_code=404)
        return self.incidents[incident_id]

    async def get_threat(self, threat_id: str, auth_token: Optional[str] = None) -> Dict[str, Any]:
        if threat_id not in self.threats:
            raise BackendDataNotFoundError(f"Threat {threat_id} not found", status_code=404)
        return self.threats[threat_id]

    async def get_evidence(self, evidence_id: str, auth_token: Optional[str] = None) -> Dict[str, Any]:
        if evidence_id not in self.evidence:
            raise BackendDataNotFoundError(f"Evidence {evidence_id} not found", status_code=404)
        return self.evidence[evidence_id]

    async def list_evidence_for_event(self, event_id: str, auth_token: Optional[str] = None) -> List[Dict[str, Any]]:
        return [e for e in self.evidence.values() if e.get("event_id") == event_id]

    async def get_security_memory(
        self,
        memory_type: Optional[str] = None,
        status: Optional[str] = None,
        auth_token: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        results = []
        for m in self.memories.values():
            if memory_type and m.get("type") != memory_type:
                continue
            if status and m.get("status") != status:
                continue
            results.append(m)
        return results

    async def save_security_memory(self, memory_item: Dict[str, Any], auth_token: Optional[str] = None) -> Dict[str, Any]:
        mem_id = memory_item.get("memory_id", f"MEM-{len(self.memories) + 1:03d}")
        memory_item["memory_id"] = mem_id
        now_ts = datetime.now(timezone.utc).isoformat()
        if not memory_item.get("created_at"):
            memory_item["created_at"] = now_ts
        if not memory_item.get("updated_at"):
            memory_item["updated_at"] = now_ts
        self.memories[mem_id] = memory_item
        return memory_item

    async def get_investigation(self, investigation_id: str, auth_token: Optional[str] = None) -> Dict[str, Any]:
        if investigation_id not in self.investigation_results:
            raise BackendDataNotFoundError(f"Investigation {investigation_id} not found", status_code=404)
        return self.investigation_results[investigation_id]

    async def post_investigation_result(
        self,
        investigation_id: str,
        result_payload: Dict[str, Any],
        auth_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        self.investigation_results[investigation_id] = result_payload
        return {"status": "SUCCESS", "investigation_id": investigation_id}

    async def send_realtime_status(
        self,
        investigation_id: str,
        stage: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None,
        auth_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        log_entry = {
            "investigation_id": investigation_id,
            "stage": stage,
            "message": message,
            "metadata": metadata or {},
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        self.progress_logs.append(log_entry)
        return {"status": "ACK", "stage": stage}

    async def query_copilot(
        self,
        query_payload: Dict[str, Any],
        auth_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        from copilot.engine import SecurityCopilotEngine
        engine = SecurityCopilotEngine(backend_client=self)
        response = await engine.query(query_payload)
        return response.model_dump()

