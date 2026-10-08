"""
Module 4: Backend Integration Exceptions.
Custom exceptions for handling Backend API communication failures cleanly.
"""


class BackendIntegrationError(Exception):
    """Base exception for all Backend integration errors."""
    def __init__(self, message: str, status_code: int | None = None, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}


class BackendConnectionError(BackendIntegrationError):
    """Raised when the Backend service is unreachable."""
    pass


class BackendTimeoutError(BackendIntegrationError):
    """Raised when a request to Backend times out."""
    pass


class BackendAuthError(BackendIntegrationError):
    """Raised when authentication/RBAC authorization fails at Backend."""
    pass


class BackendDataNotFoundError(BackendIntegrationError):
    """Raised when a requested resource (event, camera, incident, evidence) is not found."""
    pass


class BackendValidationError(BackendIntegrationError):
    """Raised when the Backend returns unparseable or schema-violating data."""
    pass
