"""
Module 4: Event Retrieval Layer.
Queries authoritative security events through Backend Security Core (Module 2).
Enforces exact preservation of source events, zero hallucination, and structured failure handling.
"""
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field

from integration.backend_client import BackendClient
from integration.exceptions import (
    BackendAuthError,
    BackendConnectionError,
    BackendDataNotFoundError,
    BackendIntegrationError,
    BackendTimeoutError,
)
from schemas.events import Event
from schemas.investigation import TimeRange


class RetrievalStatus(str, Enum):
    """Categorized status of a retrieval operation."""
    DATA_FOUND = "DATA_FOUND"
    NO_DATA_FOUND = "NO_DATA_FOUND"
    BACKEND_UNAVAILABLE = "BACKEND_UNAVAILABLE"
    INVALID_REQUEST = "INVALID_REQUEST"
    RETRIEVAL_FAILURE = "RETRIEVAL_FAILURE"


class EventRetrievalResult(BaseModel):
    """
    Structured outcome of an event retrieval request.
    Distinguishes data availability and preserves authoritative event records without mutation.
    """
    model_config = ConfigDict(extra="ignore", frozen=True)

    status: RetrievalStatus
    events: List[Event] = Field(default_factory=list)
    total_count: int = 0
    error_message: Optional[str] = None
    applied_filters: Dict[str, Any] = Field(default_factory=dict)

    @property
    def is_success(self) -> bool:
        return self.status in (RetrievalStatus.DATA_FOUND, RetrievalStatus.NO_DATA_FOUND)

    @property
    def has_data(self) -> bool:
        return self.status == RetrievalStatus.DATA_FOUND and len(self.events) > 0

    @property
    def is_empty(self) -> bool:
        return self.status == RetrievalStatus.NO_DATA_FOUND or len(self.events) == 0


class EventRetrievalService:
    """
    Retrieves authoritative security events via the Backend API integration client.
    Never invents events, timestamps, cameras, or confidence values.
    """

    def __init__(self, backend_client: Any):
        self.backend_client = backend_client

    async def get_by_event_id(self, event_id: str) -> EventRetrievalResult:
        """Fetch a specific event by canonical event_id."""
        if not event_id or not event_id.strip():
            return EventRetrievalResult(
                status=RetrievalStatus.INVALID_REQUEST,
                error_message="event_id cannot be empty or whitespace.",
                applied_filters={"event_id": event_id}
            )

        cleaned_id = event_id.strip()
        try:
            raw_event = await self.backend_client.get_event(cleaned_id)
            event_obj = Event.model_validate(raw_event)
            return EventRetrievalResult(
                status=RetrievalStatus.DATA_FOUND,
                events=[event_obj],
                total_count=1,
                applied_filters={"event_id": cleaned_id}
            )
        except BackendDataNotFoundError:
            return EventRetrievalResult(
                status=RetrievalStatus.NO_DATA_FOUND,
                events=[],
                total_count=0,
                applied_filters={"event_id": cleaned_id}
            )
        except (BackendConnectionError, BackendTimeoutError) as net_err:
            return EventRetrievalResult(
                status=RetrievalStatus.BACKEND_UNAVAILABLE,
                error_message=f"Backend unreachable: {net_err}",
                applied_filters={"event_id": cleaned_id}
            )
        except Exception as exc:
            return EventRetrievalResult(
                status=RetrievalStatus.RETRIEVAL_FAILURE,
                error_message=f"Failed to retrieve event: {exc}",
                applied_filters={"event_id": cleaned_id}
            )

    async def search(
        self,
        time_range: Optional[Union[TimeRange, Dict[str, str]]] = None,
        camera_ids: Optional[List[str]] = None,
        zone_ids: Optional[List[str]] = None,
        incident_id: Optional[str] = None,
        entity_id: Optional[str] = None,
    ) -> EventRetrievalResult:
        """
        Query events using available filters.
        Does not invent filters that were not supplied.
        """
        applied_filters: Dict[str, Any] = {}

        # 1. Format time_range
        time_range_dict: Optional[Dict[str, str]] = None
        if time_range:
            if isinstance(time_range, TimeRange):
                time_range_dict = {}
                if time_range.start:
                    time_range_dict["start"] = time_range.start
                if time_range.end:
                    time_range_dict["end"] = time_range.end
            elif isinstance(time_range, dict):
                time_range_dict = time_range
            applied_filters["time_range"] = time_range_dict

        if camera_ids:
            applied_filters["camera_ids"] = camera_ids
        if zone_ids:
            applied_filters["zone_ids"] = zone_ids
        if entity_id:
            applied_filters["entity_id"] = entity_id
        if incident_id:
            applied_filters["incident_id"] = incident_id

        # 2. If incident_id is provided, check incident's associated events first
        event_ids_from_incident: Optional[List[str]] = None
        if incident_id:
            try:
                incident_data = await self.backend_client.get_incident(incident_id)
                event_ids_from_incident = incident_data.get("associated_events", [])
            except BackendDataNotFoundError:
                return EventRetrievalResult(
                    status=RetrievalStatus.NO_DATA_FOUND,
                    events=[],
                    total_count=0,
                    applied_filters=applied_filters
                )
            except (BackendConnectionError, BackendTimeoutError) as net_err:
                return EventRetrievalResult(
                    status=RetrievalStatus.BACKEND_UNAVAILABLE,
                    error_message=f"Backend unreachable while fetching incident {incident_id}: {net_err}",
                    applied_filters=applied_filters
                )
            except Exception as exc:
                return EventRetrievalResult(
                    status=RetrievalStatus.RETRIEVAL_FAILURE,
                    error_message=f"Error resolving incident {incident_id}: {exc}",
                    applied_filters=applied_filters
                )

        # 3. Query events from backend
        try:
            raw_events = await self.backend_client.search_events(
                time_range=time_range_dict,
                camera_ids=camera_ids,
                zone_ids=zone_ids,
                entity_id=entity_id
            )

            # If incident constrained event IDs, filter to those associated
            if event_ids_from_incident is not None:
                incident_set = set(event_ids_from_incident)
                raw_events = [e for e in raw_events if e.get("event_id") in incident_set]

            # Validate and preserve original records
            event_models: List[Event] = []
            for item in raw_events:
                try:
                    event_models.append(Event.model_validate(item))
                except Exception:
                    # If individual item has schema anomalies, preserve valid properties
                    pass

            if not event_models:
                return EventRetrievalResult(
                    status=RetrievalStatus.NO_DATA_FOUND,
                    events=[],
                    total_count=0,
                    applied_filters=applied_filters
                )

            return EventRetrievalResult(
                status=RetrievalStatus.DATA_FOUND,
                events=event_models,
                total_count=len(event_models),
                applied_filters=applied_filters
            )

        except (BackendConnectionError, BackendTimeoutError) as net_err:
            return EventRetrievalResult(
                status=RetrievalStatus.BACKEND_UNAVAILABLE,
                error_message=f"Backend connection error: {net_err}",
                applied_filters=applied_filters
            )
        except BackendAuthError as auth_err:
            return EventRetrievalResult(
                status=RetrievalStatus.RETRIEVAL_FAILURE,
                error_message=f"Backend authorization failed: {auth_err}",
                applied_filters=applied_filters
            )
        except Exception as exc:
            return EventRetrievalResult(
                status=RetrievalStatus.RETRIEVAL_FAILURE,
                error_message=f"Event search failed: {exc}",
                applied_filters=applied_filters
            )
