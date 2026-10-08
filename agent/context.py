"""
Module 4: Investigation Execution Context.
Maintains state, collected data, and stage progression throughout the investigation pipeline.
"""
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from agent.request_handler import PreparedInvestigationRequest
from schemas.investigation import InvestigationStatus, TimelineItem


class InvestigationState(str, Enum):
    """Internal investigation lifecycle states."""
    RECEIVED = "RECEIVED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    CONFLICTED_EVIDENCE = "CONFLICTED_EVIDENCE"
    FAILED = "FAILED"

    def to_schema_status(self) -> InvestigationStatus:
        """Map internal state to external InvestigationStatus schema."""
        mapping = {
            InvestigationState.RECEIVED: InvestigationStatus.PROCESSING,
            InvestigationState.PROCESSING: InvestigationStatus.PROCESSING,
            InvestigationState.COMPLETED: InvestigationStatus.COMPLETED,
            InvestigationState.INSUFFICIENT_EVIDENCE: InvestigationStatus.INSUFFICIENT_EVIDENCE,
            InvestigationState.CONFLICTED_EVIDENCE: InvestigationStatus.CONFLICTED_EVIDENCE,
            InvestigationState.FAILED: InvestigationStatus.FAILED,
        }
        return mapping[self]


class InvestigationContext(BaseModel):
    """
    Mutable state tracker passed through the 12 pipeline stages.
    Guarantees strict auditability and no hallucination.
    """
    model_config = ConfigDict(extra="ignore", arbitrary_types_allowed=True)

    investigation_id: str
    request: PreparedInvestigationRequest
    state: InvestigationState = InvestigationState.RECEIVED
    stage_history: List[str] = Field(default_factory=list)

    # Stage Data Payloads
    intent: Optional[Dict[str, Any]] = None
    incident: Optional[Dict[str, Any]] = None
    events: List[Dict[str, Any]] = Field(default_factory=list)
    cameras: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    entities: List[str] = Field(default_factory=list)
    correlations: List[Dict[str, Any]] = Field(default_factory=list)
    timeline: List[TimelineItem] = Field(default_factory=list)
    security_memories: List[Dict[str, Any]] = Field(default_factory=list)
    security_contexts: List[Dict[str, Any]] = Field(default_factory=list)
    risk_assessment: Optional[Dict[str, Any]] = None
    verified_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    provenance: List[Dict[str, Any]] = Field(default_factory=list)
    confidence: Optional[float] = None

    # Triad Classification
    observed_facts: List[str] = Field(default_factory=list)
    inferences: List[str] = Field(default_factory=list)
    unknowns: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)

    # Narrative answer and error tracking
    answer: Optional[str] = None
    error_message: Optional[str] = None

    def record_stage(self, stage_name: str) -> None:
        """Record deterministic execution of a stage."""
        self.stage_history.append(stage_name)

    def mark_insufficient_evidence(self, reason: str) -> None:
        """Mark investigation as lacking sufficient evidence to reach a conclusion."""
        self.state = InvestigationState.INSUFFICIENT_EVIDENCE
        if reason not in self.unknowns:
            self.unknowns.append(reason)
        if not self.answer:
            self.answer = "I don't know — insufficient evidence to determine this reliably."

    def mark_conflicted_evidence(self, reason: str) -> None:
        """Mark investigation as having contradictory evidence."""
        self.state = InvestigationState.CONFLICTED_EVIDENCE
        if reason not in self.limitations:
            self.limitations.append(reason)
        if not self.answer:
            self.answer = "Conflicting evidence detected."

    def mark_failed(self, error: str) -> None:
        """Mark investigation as failed due to system/client/backend error."""
        self.state = InvestigationState.FAILED
        self.error_message = error
        if not self.answer:
            self.answer = f"Investigation could not be completed: {error}"
