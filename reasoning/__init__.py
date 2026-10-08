"""
Module 4: Reasoning
Contains evidence grounding, security context reasoning, risk reasoning, and confidence evaluation.
"""
from reasoning.confidence_evaluation import (
    ConfidenceResult,
    ConfidenceStatus,
    InvestigationConfidenceEngine,
)
from reasoning.context_reasoning import (
    SecurityContextItem,
    SecurityContextReasoningEngine,
    SecurityContextReasoningResult,
)
from reasoning.risk_reasoning import (
    EvidenceGroundedRiskReasoningEngine,
    ReasoningStatus,
    RiskReasoningResult,
)
from reasoning.hallucination_guard import (
    HallucinationGuard,
    HallucinationGuardResult,
    HallucinationViolation,
    HallucinationViolationType,
)

__all__ = [
    "SecurityContextItem",
    "SecurityContextReasoningEngine",
    "SecurityContextReasoningResult",
    "EvidenceGroundedRiskReasoningEngine",
    "ReasoningStatus",
    "RiskReasoningResult",
    "ConfidenceStatus",
    "ConfidenceResult",
    "InvestigationConfidenceEngine",
    "HallucinationGuard",
    "HallucinationGuardResult",
    "HallucinationViolation",
    "HallucinationViolationType",
]

