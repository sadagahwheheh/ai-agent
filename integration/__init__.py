"""
Module 4: Integration
Contains Backend API client layer and communication adapters for Backend Security Core (Module 2).
"""
from integration.config import BackendSettings
from integration.backend_client import BackendClient
from integration.mock_client import MockBackendClient
from integration.exceptions import (
    BackendIntegrationError,
    BackendConnectionError,
    BackendTimeoutError,
    BackendAuthError,
    BackendDataNotFoundError,
    BackendValidationError,
)

__all__ = [
    "BackendSettings",
    "BackendClient",
    "MockBackendClient",
    "BackendIntegrationError",
    "BackendConnectionError",
    "BackendTimeoutError",
    "BackendAuthError",
    "BackendDataNotFoundError",
    "BackendValidationError",
]
