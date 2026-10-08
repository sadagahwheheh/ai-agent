"""
Module 4: Investigation Request Handler.
Safely accepts, validates, normalizes, and prepares investigation requests
for the investigation pipeline without inventing or fabricating missing data.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agent.exceptions import RequestValidationError
from schemas.investigation import InvestigationRequest, TimeRange


class PreparedInvestigationRequest(BaseModel):
    """
    Prepared internal representation of an investigation request.
    Retains all user-supplied context, preserves original query,
    and guarantees no missing fields were fabricated.
    """
    model_config = ConfigDict(extra="ignore", frozen=True)

    investigation_id: str = Field(description="Canonical investigation_id")
    original_query: str = Field(description="Exact original user query preserved without modification")
    time_range: Optional[TimeRange] = Field(default=None, description="Normalized time range filter if provided")
    camera_ids: Optional[List[str]] = Field(default=None, description="Camera scope filter if provided")
    zone_ids: Optional[List[str]] = Field(default=None, description="Zone scope filter if provided")
    incident_id: Optional[str] = Field(default=None, description="Associated incident ID if provided")
    user_id: Optional[str] = Field(default=None, description="Requesting operator user ID if provided")
    raw_request: InvestigationRequest = Field(description="Underlying validated schema object")

    @property
    def has_time_filter(self) -> bool:
        return self.time_range is not None and bool(self.time_range.start or self.time_range.end)

    @property
    def has_camera_filter(self) -> bool:
        return bool(self.camera_ids)

    @property
    def has_zone_filter(self) -> bool:
        return bool(self.zone_ids)

    @property
    def has_incident_filter(self) -> bool:
        return bool(self.incident_id)


class InvestigationRequestHandler:
    """
    Validates and prepares incoming investigation requests.
    Enforces no-fabrication rules and strict parameter validation.
    """

    @classmethod
    def validate_and_prepare(
        cls,
        data: Union[Dict[str, Any], InvestigationRequest]
    ) -> PreparedInvestigationRequest:
        """
        Validates raw request data or an InvestigationRequest model and produces
        a PreparedInvestigationRequest.
        """
        if isinstance(data, InvestigationRequest):
            req = data
        elif isinstance(data, dict):
            req = cls._parse_dict(data)
        else:
            raise RequestValidationError(
                f"Request must be a dict or InvestigationRequest instance, got {type(data).__name__}"
            )

        # Validate time_range chronological consistency if both start and end exist
        normalized_time_range = cls._validate_and_normalize_time_range(req.time_range)

        # Normalize camera_ids (deduplicate without changing order or fabricating)
        normalized_camera_ids = cls._normalize_id_list(req.camera_ids, field_name="camera_ids")

        # Normalize zone_ids (deduplicate without changing order or fabricating)
        normalized_zone_ids = cls._normalize_id_list(req.zone_ids, field_name="zone_ids")

        return PreparedInvestigationRequest(
            investigation_id=req.investigation_id,
            original_query=req.query,
            time_range=normalized_time_range,
            camera_ids=normalized_camera_ids,
            zone_ids=normalized_zone_ids,
            incident_id=req.incident_id,
            user_id=req.user_id,
            raw_request=req
        )

    @classmethod
    def _parse_dict(cls, data: Dict[str, Any]) -> InvestigationRequest:
        """Parse raw dictionary into InvestigationRequest with clear error reporting."""
        if not isinstance(data, dict):
            raise RequestValidationError("Request payload must be a JSON object / dictionary")

        if "investigation_id" not in data or data["investigation_id"] is None:
            raise RequestValidationError("Missing required field 'investigation_id'", field="investigation_id")

        if "query" not in data or data["query"] is None:
            raise RequestValidationError("Missing required field 'query'", field="query")

        # Pre-validate camera_ids if present
        if "camera_ids" in data and data["camera_ids"] is not None:
            if not isinstance(data["camera_ids"], list):
                raise RequestValidationError("'camera_ids' must be a list of camera identifiers", field="camera_ids")
            for idx, cid in enumerate(data["camera_ids"]):
                if not isinstance(cid, str) or not cid.strip():
                    raise RequestValidationError(
                        f"Item at index {idx} in camera_ids must be a non-empty string",
                        field="camera_ids"
                    )

        # Pre-validate zone_ids if present
        if "zone_ids" in data and data["zone_ids"] is not None:
            if not isinstance(data["zone_ids"], list):
                raise RequestValidationError("'zone_ids' must be a list of zone identifiers", field="zone_ids")
            for idx, zid in enumerate(data["zone_ids"]):
                if not isinstance(zid, str) or not zid.strip():
                    raise RequestValidationError(
                        f"Item at index {idx} in zone_ids must be a non-empty string",
                        field="zone_ids"
                    )

        # Pre-validate incident_id if present
        if "incident_id" in data and data["incident_id"] is not None:
            if not isinstance(data["incident_id"], str) or not data["incident_id"].strip():
                raise RequestValidationError("'incident_id' must be a non-empty string", field="incident_id")

        try:
            return InvestigationRequest.model_validate(data)
        except ValidationError as err:
            first_err = err.errors()[0]
            field_name = str(first_err.get("loc", ["unknown"])[-1])
            msg = first_err.get("msg", "Validation failed")
            raise RequestValidationError(f"{field_name}: {msg}", field=field_name, details={"errors": err.errors()}) from err

    @classmethod
    def _validate_and_normalize_time_range(cls, time_range: Optional[TimeRange]) -> Optional[TimeRange]:
        """Validate chronological coherence of start and end timestamps."""
        if time_range is None:
            return None

        start_str = time_range.start.strip() if time_range.start else None
        end_str = time_range.end.strip() if time_range.end else None

        if not start_str and not end_str:
            return None

        # If both are present, verify chronological ordering
        if start_str and end_str:
            try:
                dt_start = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
                dt_end = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
                if dt_start > dt_end:
                    raise RequestValidationError(
                        f"Start time ({start_str}) cannot be after end time ({end_str})",
                        field="time_range"
                    )
            except ValueError as val_err:
                # If error was our custom start > end check, re-raise it
                if "cannot be after end time" in str(val_err):
                    raise
                # If not standard ISO, ensure neither is blank
                pass

        return TimeRange(start=start_str, end=end_str)

    @staticmethod
    def _normalize_id_list(items: Optional[List[str]], field_name: str) -> Optional[List[str]]:
        """Deduplicate identifiers while strictly preserving original order. Returns None if None."""
        if items is None:
            return None
        seen = set()
        deduped = []
        for item in items:
            cleaned = item.strip()
            if cleaned not in seen:
                seen.add(cleaned)
                deduped.append(cleaned)
        return deduped
