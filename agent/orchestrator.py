"""
Module 4: Investigation Orchestrator.
Controls the deterministic 12-stage investigation pipeline, tracks lifecycle states,
and ensures zero hallucination while producing structured InvestigationResult objects.
"""
from typing import Any, Dict, List, Optional, Union
import logging

from agent.context import InvestigationContext, InvestigationState
from agent.exceptions import RequestValidationError
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
from integration.backend_client import BackendClient
from integration.mock_client import MockBackendClient
from schemas.investigation import (
    InvestigationRequest,
    InvestigationResult,
    InvestigationStatus,
)
from reasoning.hallucination_guard import HallucinationGuard
from agent.status_reporter import FailureCategory, InvestigationStatusReporter

logger = logging.getLogger(__name__)




class InvestigationOrchestrator:
    """
    Coordinates execution of all investigation stages in strict deterministic order.
    Enforces the Absolute No-Hallucination rule and safe state transitions.
    """

    def __init__(
        self,
        backend_client: Optional[Any] = None,
        stages: Optional[List[BaseInvestigationStage]] = None,
    ):
        self.backend_client = backend_client or MockBackendClient()
        self.reporter = InvestigationStatusReporter(self.backend_client)
        self.stages = stages or [
            IntentUnderstandingStage(),
            IncidentIdentificationStage(),
            EventRetrievalStage(),
            CameraRetrievalStage(),
            EntityRetrievalStage(),
            CrossCameraCorrelationStage(),
            TimelineConstructionStage(),
            SecurityContextStage(),
            RiskReasoningStage(),
            EvidenceVerificationStage(),
            ConfidenceEvaluationStage(),
        ]


    async def orchestrate(
        self,
        request_input: Union[Dict[str, Any], InvestigationRequest, PreparedInvestigationRequest],
    ) -> InvestigationResult:
        """
        Main entry point for autonomous security investigation.
        Validates request, initializes context, runs pipeline, and returns InvestigationResult.
        """
        # 1. Prepare & Validate Inbound Request
        if isinstance(request_input, PreparedInvestigationRequest):
            prepared_req = request_input
        else:
            try:
                prepared_req = InvestigationRequestHandler.validate_and_prepare(request_input)
            except RequestValidationError as val_err:
                # Return controlled failure result rather than crashing
                inv_id = (
                    request_input.get("investigation_id", "UNKNOWN-INV")
                    if isinstance(request_input, dict)
                    else getattr(request_input, "investigation_id", "UNKNOWN-INV")
                )
                return InvestigationResult(
                    investigation_id=str(inv_id),
                    status=InvestigationStatus.FAILED,
                    answer=f"Investigation request validation failed: {val_err}",
                    observed_facts=[],
                    inferences=[],
                    timeline=[],
                    evidence_ids=[],
                    confidence=None,
                    unknowns=["Request was invalid or malformed."],
                    limitations=[]
                )
            except Exception as exc:
                return InvestigationResult(
                    investigation_id="UNKNOWN-INV",
                    status=InvestigationStatus.FAILED,
                    answer=f"Unexpected error validating request: {exc}",
                    observed_facts=[],
                    inferences=[],
                    timeline=[],
                    evidence_ids=[],
                    confidence=None,
                    unknowns=["Request processing aborted."],
                    limitations=[]
                )

        # 2. Initialize Investigation Context
        context = InvestigationContext(
            investigation_id=prepared_req.investigation_id,
            request=prepared_req,
            state=InvestigationState.RECEIVED,
        )

        # 3. Transition to PROCESSING and notify Backend
        context.state = InvestigationState.PROCESSING
        await self.reporter.report_started(context.investigation_id)

        # 4. Execute Stages in Strict Deterministic Order
        for stage in self.stages:
            if context.state == InvestigationState.FAILED:
                break

            try:
                await self.reporter.report_stage(
                    context.investigation_id,
                    stage.stage_name,
                    message=f"Executing stage: {stage.stage_name}",
                )
                await stage.execute(context, self.backend_client)
                context.record_stage(stage.stage_name)

            except Exception as stage_err:
                logger.error("Stage %s encountered error: %s", stage.stage_name, stage_err)
                context.mark_failed(f"Error in stage '{stage.stage_name}': {stage_err}")
                await self.reporter.report_failed(
                    context.investigation_id,
                    f"Error in stage '{stage.stage_name}': {stage_err}",
                    category=FailureCategory.STAGE_FAILURE,
                )
                break

        # 5. Synthesize Final Investigation Result
        result = self._synthesize_result(context)

        # 6. Post Final Result and Status Telemetry
        if result.status == InvestigationStatus.FAILED:
            await self.reporter.report_failed(
                context.investigation_id,
                result.answer,
                category=FailureCategory.INTERNAL_ERROR,
            )
        elif result.status == InvestigationStatus.INSUFFICIENT_EVIDENCE:
            await self.reporter.report_insufficient_evidence(
                context.investigation_id,
                message=f"Investigation concluded with status {result.status.value}",
            )
        else:
            await self.reporter.report_completed(
                context.investigation_id,
                message=f"Investigation concluded with status {result.status.value}",
            )

        try:
            await self.backend_client.post_investigation_result(
                context.investigation_id,
                result.model_dump(),
            )
        except Exception:
            pass


        return result

    def _synthesize_result(self, context: InvestigationContext) -> InvestigationResult:
        """Constructs an evidence-grounded InvestigationResult strictly distinguishing triad components."""
        if context.state == InvestigationState.FAILED:
            status = InvestigationStatus.FAILED
            answer = context.answer or f"Investigation could not be completed: {context.error_message}"
        elif context.state == InvestigationState.INSUFFICIENT_EVIDENCE:
            status = InvestigationStatus.INSUFFICIENT_EVIDENCE
            answer = "I don't know — insufficient evidence to determine this reliably."
        elif context.state == InvestigationState.CONFLICTED_EVIDENCE:
            status = InvestigationStatus.CONFLICTED_EVIDENCE
            answer = context.answer or "Conflicting evidence detected."
        else:
            context.state = InvestigationState.COMPLETED
            status = InvestigationStatus.COMPLETED
            if not context.answer:
                if context.observed_facts:
                    facts_summary = "; ".join(context.observed_facts[:3])
                    answer = f"Investigation completed based on verified observation: {facts_summary}."
                else:
                    answer = "Investigation completed with verified records."
            else:
                answer = context.answer

        raw_result = InvestigationResult(
            investigation_id=context.investigation_id,
            status=status,
            answer=answer,
            observed_facts=context.observed_facts,
            inferences=context.inferences,
            timeline=context.timeline,
            evidence_ids=context.evidence_ids,
            confidence=context.confidence,
            unknowns=context.unknowns,
            limitations=context.limitations,
        )
        return HallucinationGuard.guard(raw_result, context)

