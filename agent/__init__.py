"""
Module 4: Agent Core.
Contains investigation request handling, orchestration, context tracking, and pipeline stages.
"""
from agent.context import InvestigationContext, InvestigationState
from agent.exceptions import AgentError, RequestValidationError
from agent.orchestrator import InvestigationOrchestrator
from agent.request_handler import (
    InvestigationRequestHandler,
    PreparedInvestigationRequest,
)
from agent.stage_interfaces import (
    BaseInvestigationStage,
    CameraRetrievalStage,
    ConfidenceEvaluationStage,
    CrossCameraCorrelationStage,
    EntityRetrievalStage,
    EventRetrievalStage,
    EvidenceVerificationStage,
    IncidentIdentificationStage,
    IntentUnderstandingStage,
    RiskReasoningStage,
    SecurityContextStage,
    TimelineConstructionStage,
)
from agent.status_reporter import (

    CanonicalInvestigationStage,
    FailureCategory,
    InvestigationStatusLog,
    InvestigationStatusReporter,
)

__all__ = [
    "AgentError",
    "RequestValidationError",
    "InvestigationRequestHandler",
    "PreparedInvestigationRequest",
    "InvestigationContext",
    "InvestigationState",
    "InvestigationOrchestrator",
    "BaseInvestigationStage",
    "IntentUnderstandingStage",
    "IncidentIdentificationStage",
    "EventRetrievalStage",
    "CameraRetrievalStage",
    "EntityRetrievalStage",
    "CrossCameraCorrelationStage",
    "TimelineConstructionStage",
    "SecurityContextStage",
    "RiskReasoningStage",
    "EvidenceVerificationStage",
    "ConfidenceEvaluationStage",
    "InvestigationStatusReporter",
    "CanonicalInvestigationStage",
    "FailureCategory",
    "InvestigationStatusLog",
]

