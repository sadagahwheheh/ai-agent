"""
Module 4: Copilot.
Contains natural-language query processing and structured response generation.
Adheres strictly to the Absolute No-Hallucination Triad.
"""
from copilot.engine import SecurityCopilotEngine
from copilot.intent import CopilotIntentAnalyzer
from schemas.copilot import (
    CopilotIntentType,
    CopilotQueryRequest,
    CopilotQueryResponse,
)

__all__ = [
    "SecurityCopilotEngine",
    "CopilotIntentAnalyzer",
    "CopilotIntentType",
    "CopilotQueryRequest",
    "CopilotQueryResponse",
]
