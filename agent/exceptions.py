"""
Module 4: Agent Core Exceptions.
Exceptions raised during investigation request validation, preparation, and orchestration.
"""
from typing import Any, Dict, Optional


class AgentError(Exception):
    """Base exception for agent-level errors."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class RequestValidationError(AgentError):
    """Raised when an incoming investigation request fails validation."""
    def __init__(self, message: str, field: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details)
        self.field = field

    def __str__(self) -> str:
        if self.field:
            return f"Validation error on field '{self.field}': {self.message}"
        return f"Validation error: {self.message}"
