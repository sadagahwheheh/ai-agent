"""
Module 4: Evidence Retrieval Layer.
Fetches verifiable evidence artifacts via Backend Security Core (Module 2).
Preserves authoritative timestamps, clip references, and verification status without fabrication.
"""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from integration.backend_client import BackendClient
from integration.exceptions import (
    BackendAuthError,
    BackendConnectionError,
    BackendDataNotFoundError,
    BackendIntegrationError,
    BackendTimeoutError,
)
from investigation.event_search import RetrievalStatus
from schemas.evidence import Evidence


class EvidenceRetrievalResult(BaseModel):
    """
    Structured outcome of an evidence retrieval request.
    Maintains strict provenance and status categorization.
    """
    model_config = ConfigDict(extra="ignore", frozen=True)

    status: RetrievalStatus
    evidence_items: List[Evidence] = Field(default_factory=list)
    total_count: int = 0
    error_message: Optional[str] = None
    applied_filters: Dict[str, Any] = Field(default_factory=dict)

    @property
    def is_success(self) -> bool:
        return self.status in (RetrievalStatus.DATA_FOUND, RetrievalStatus.NO_DATA_FOUND)

    @property
    def has_data(self) -> bool:
        return self.status == RetrievalStatus.DATA_FOUND and len(self.evidence_items) > 0

    @property
    def is_empty(self) -> bool:
        return self.status == RetrievalStatus.NO_DATA_FOUND or len(self.evidence_items) == 0


class EvidenceRetrievalService:
    """
    Retrieves evidence artifacts strictly mediated by Backend Security Core.
    Never invents clips, snapshots, confidence, or verification statuses.
    """

    def __init__(self, backend_client: Any):
        self.backend_client = backend_client

    async def get_by_evidence_id(self, evidence_id: str) -> EvidenceRetrievalResult:
        """Fetch a specific evidence item by canonical evidence_id."""
        if not evidence_id or not evidence_id.strip():
            return EvidenceRetrievalResult(
                status=RetrievalStatus.INVALID_REQUEST,
                error_message="evidence_id cannot be empty or whitespace.",
                applied_filters={"evidence_id": evidence_id}
            )

        cleaned_id = evidence_id.strip()
        try:
            raw_ev = await self.backend_client.get_evidence(cleaned_id)
            ev_obj = Evidence.model_validate(raw_ev)
            return EvidenceRetrievalResult(
                status=RetrievalStatus.DATA_FOUND,
                evidence_items=[ev_obj],
                total_count=1,
                applied_filters={"evidence_id": cleaned_id}
            )
        except BackendDataNotFoundError:
            return EvidenceRetrievalResult(
                status=RetrievalStatus.NO_DATA_FOUND,
                evidence_items=[],
                total_count=0,
                applied_filters={"evidence_id": cleaned_id}
            )
        except (BackendConnectionError, BackendTimeoutError) as net_err:
            return EvidenceRetrievalResult(
                status=RetrievalStatus.BACKEND_UNAVAILABLE,
                error_message=f"Backend unreachable: {net_err}",
                applied_filters={"evidence_id": cleaned_id}
            )
        except Exception as exc:
            return EvidenceRetrievalResult(
                status=RetrievalStatus.RETRIEVAL_FAILURE,
                error_message=f"Failed to retrieve evidence: {exc}",
                applied_filters={"evidence_id": cleaned_id}
            )

    async def get_by_event_id(self, event_id: str) -> EvidenceRetrievalResult:
        """Fetch all evidence items associated with an event."""
        if not event_id or not event_id.strip():
            return EvidenceRetrievalResult(
                status=RetrievalStatus.INVALID_REQUEST,
                error_message="event_id cannot be empty or whitespace.",
                applied_filters={"event_id": event_id}
            )

        cleaned_id = event_id.strip()
        return await self.get_for_events([cleaned_id])

    async def get_for_events(self, event_ids: List[str]) -> EvidenceRetrievalResult:
        """Fetch all evidence items associated with a list of event IDs."""
        if not event_ids:
            return EvidenceRetrievalResult(
                status=RetrievalStatus.NO_DATA_FOUND,
                evidence_items=[],
                total_count=0,
                applied_filters={"event_ids": []}
            )

        all_evidence: List[Evidence] = []
        seen_ids = set()

        try:
            for eid in event_ids:
                if not eid or not eid.strip():
                    continue
                raw_items = await self.backend_client.list_evidence_for_event(eid.strip())
                for raw in raw_items:
                    ev_id = raw.get("evidence_id")
                    if ev_id and ev_id not in seen_ids:
                        seen_ids.add(ev_id)
                        try:
                            all_evidence.append(Evidence.model_validate(raw))
                        except Exception:
                            pass

            if not all_evidence:
                return EvidenceRetrievalResult(
                    status=RetrievalStatus.NO_DATA_FOUND,
                    evidence_items=[],
                    total_count=0,
                    applied_filters={"event_ids": event_ids}
                )

            return EvidenceRetrievalResult(
                status=RetrievalStatus.DATA_FOUND,
                evidence_items=all_evidence,
                total_count=len(all_evidence),
                applied_filters={"event_ids": event_ids}
            )

        except (BackendConnectionError, BackendTimeoutError) as net_err:
            return EvidenceRetrievalResult(
                status=RetrievalStatus.BACKEND_UNAVAILABLE,
                error_message=f"Backend connection failed during evidence retrieval: {net_err}",
                applied_filters={"event_ids": event_ids}
            )
        except BackendAuthError as auth_err:
            return EvidenceRetrievalResult(
                status=RetrievalStatus.RETRIEVAL_FAILURE,
                error_message=f"Backend authorization failed: {auth_err}",
                applied_filters={"event_ids": event_ids}
            )
        except Exception as exc:
            return EvidenceRetrievalResult(
                status=RetrievalStatus.RETRIEVAL_FAILURE,
                error_message=f"Failed to query evidence for events: {exc}",
                applied_filters={"event_ids": event_ids}
            )

    async def get_for_incident(self, incident_id: str) -> EvidenceRetrievalResult:
        """Fetch evidence for all events correlated with an incident."""
        if not incident_id or not incident_id.strip():
            return EvidenceRetrievalResult(
                status=RetrievalStatus.INVALID_REQUEST,
                error_message="incident_id cannot be empty.",
                applied_filters={"incident_id": incident_id}
            )

        try:
            incident = await self.backend_client.get_incident(incident_id.strip())
            associated_events = incident.get("associated_events", [])
            if not associated_events:
                return EvidenceRetrievalResult(
                    status=RetrievalStatus.NO_DATA_FOUND,
                    evidence_items=[],
                    total_count=0,
                    applied_filters={"incident_id": incident_id}
                )
            result = await self.get_for_events(associated_events)
            # Annotate applied filter with incident_id
            return EvidenceRetrievalResult(
                status=result.status,
                evidence_items=result.evidence_items,
                total_count=result.total_count,
                error_message=result.error_message,
                applied_filters={"incident_id": incident_id, "associated_events": associated_events}
            )
        except BackendDataNotFoundError:
            return EvidenceRetrievalResult(
                status=RetrievalStatus.NO_DATA_FOUND,
                evidence_items=[],
                total_count=0,
                applied_filters={"incident_id": incident_id}
            )
        except (BackendConnectionError, BackendTimeoutError) as net_err:
            return EvidenceRetrievalResult(
                status=RetrievalStatus.BACKEND_UNAVAILABLE,
                error_message=f"Backend unreachable while fetching incident {incident_id}: {net_err}",
                applied_filters={"incident_id": incident_id}
            )
        except Exception as exc:
            return EvidenceRetrievalResult(
                status=RetrievalStatus.RETRIEVAL_FAILURE,
                error_message=f"Failed to fetch evidence for incident {incident_id}: {exc}",
                applied_filters={"incident_id": incident_id}
            )
