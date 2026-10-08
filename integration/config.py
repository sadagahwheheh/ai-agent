"""
Module 4: Backend Integration Configuration.
Defines connection settings, timeout policies, and endpoint routes for Backend Security Core (Module 2).
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class BackendSettings(BaseSettings):
    """Configuration for Backend Security Core API gateway integration."""
    
    model_config = SettingsConfigDict(
        env_prefix="BACKEND_",
        env_file=".env",
        extra="ignore"
    )

    # Gateway URL
    base_url: str = Field(
        default="http://localhost:8000",
        description="Base URL of Backend Security Core (Module 2) API gateway"
    )
    
    # Auth & Tokens
    api_key: str | None = Field(
        default=None,
        description="Optional service API key for Backend communication"
    )
    auth_header_name: str = Field(
        default="Authorization",
        description="Header name used for passing auth tokens"
    )
    
    # Performance & Timeouts
    request_timeout_seconds: float = Field(
        default=10.0,
        description="Maximum wait time for Backend HTTP requests in seconds"
    )
    max_retries: int = Field(
        default=3,
        description="Number of retry attempts for transient connection failures"
    )

    # Canonical Endpoint Routes (Mediated strictly via Backend)
    endpoint_investigations: str = "/api/investigations"
    endpoint_cameras: str = "/api/cameras"
    endpoint_events: str = "/api/events"
    endpoint_incidents: str = "/api/incidents"
    endpoint_threats: str = "/api/threats"
    endpoint_evidence: str = "/api/evidence"
    endpoint_security_memory: str = "/api/security-memory"
    endpoint_copilot: str = "/api/copilot/query"
