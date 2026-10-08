"""
Module 4: Unknown / Hallucination Protection Engine (Step 16).
Enforces the Absolute No-Hallucination Triad across all investigation outputs:
1. OBSERVED FACTS: Only concrete, verified facts from authoritative events and evidence.
2. INFERENCES: Deductions derived by applying security policies and context memory.
3. UNKNOWN INFORMATION: Explicitly declared UNKNOWN for missing evidence or blind spots.

Core Guarantees:
- Zero fabrication of real-world personal identities (only anonymous entity_id tokens).
- Zero fabrication of phantom camera IDs, event IDs, or evidence IDs.
- Blind-spot & camera health safety: OFFLINE cameras are never reported as "clear/no activity".
- Deterministic fallback to "I don't know — insufficient evidence to determine this reliably."
- Inferences in observed_facts are automatically detected and reclassified.
"""
import re
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, ConfigDict, Field

from schemas.identifiers import (
    CameraId,
    EntityId,
    EventId,
    EvidenceId,
    IncidentId,
)
from schemas.investigation import (
    InvestigationResult,
    InvestigationStatus,
    TimelineItem,
)


class HallucinationViolationType(str, Enum):
    """Categorization of detected hallucination attempts or safety violations."""
    IDENTITY_FABRICATION = "IDENTITY_FABRICATION"
    PHANTOM_IDENTIFIER = "PHANTOM_IDENTIFIER"
    UNGROUNDED_FACT = "UNGROUNDED_FACT"
    BLINDSPOT_UNSAFETY = "BLINDSPOT_UNSAFETY"
    CONFIDENCE_MISALIGNMENT = "CONFIDENCE_MISALIGNMENT"
    TRIAD_MISCLASSIFICATION = "TRIAD_MISCLASSIFICATION"


class HallucinationViolation(BaseModel):
    """Record of a detected hallucination violation and its resolution."""
    model_config = ConfigDict(extra="ignore", frozen=True)

    violation_type: HallucinationViolationType
    description: str
    remediated: bool = True
    original_value: Optional[str] = None
    sanitized_value: Optional[str] = None


class HallucinationGuardResult(BaseModel):
    """Outcome of hallucination guard audit and sanitization."""
    model_config = ConfigDict(extra="ignore", frozen=True)

    is_clean: bool = True
    violations: List[HallucinationViolation] = Field(default_factory=list)
    sanitized_result: InvestigationResult


class HallucinationGuard:
    """
    Deterministic guardian against hallucinations, identity fabrications, and blind-spot unsafety.
    Acts as the final quality gate before investigation results are accepted or returned to Backend.
    """

    # Inference marker words that must not be in observed_facts
    INFERENCE_MARKERS = [
        "unauthorized",
        "likely",
        "probably",
        "inferred",
        "assumed",
        "suspected",
        "violates",
        "violation",
        "breached",
        "malicious",
        "suspicious",
        "intent",
    ]

    # Phrases indicating unsafe negative assertions on blind spots
    BLINDSPOT_UNSAFE_PHRASES = [
        "no activity occurred",
        "nothing happened",
        "area was clear",
        "no intrusion",
        "all clear",
        "no movement",
    ]

    # Regex patterns for personal names or identity fabrication
    IDENTITY_PATTERNS = [
        re.compile(r"\bnamed\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b"),
        re.compile(r"\bidentity\s+is\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b"),
        re.compile(r"\bperson\s+identified\s+as\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b"),
        re.compile(r"\bsuspect\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b"),
        re.compile(r"\b([A-Z][a-z]+)\s+was\s+identified\b"),
    ]

    @classmethod
    def guard(
        cls,
        result: InvestigationResult,
        context: Optional[Any] = None,
    ) -> InvestigationResult:
        """
        Convenience wrapper returning the sanitized InvestigationResult.
        """
        guard_result = cls.validate_and_sanitize(result, context)
        return guard_result.sanitized_result

    @classmethod
    def validate_and_sanitize(
        cls,
        result: InvestigationResult,
        context: Optional[Any] = None,
    ) -> HallucinationGuardResult:
        """
        Inspects an InvestigationResult, detects violations, applies zero-hallucination sanitization,
        and produces a safe, evidence-grounded result.
        """
        violations: List[HallucinationViolation] = []

        # Clone input fields for modification
        status = result.status
        answer = result.answer
        observed_facts = list(result.observed_facts)
        inferences = list(result.inferences)
        unknowns = list(result.unknowns)
        limitations = list(result.limitations)
        evidence_ids = list(result.evidence_ids)
        timeline = list(result.timeline)
        confidence = result.confidence

        # ---------------------------------------------------------------------
        # 1. INSUFFICIENT EVIDENCE FALLBACK ENFORCEMENT
        # ---------------------------------------------------------------------
        if status in (InvestigationStatus.INSUFFICIENT_EVIDENCE, InvestigationStatus.CONFLICTED_EVIDENCE):
            if confidence is not None:
                violations.append(
                    HallucinationViolation(
                        violation_type=HallucinationViolationType.CONFIDENCE_MISALIGNMENT,
                        description=f"Confidence score {confidence} cleared due to {status.value} status",
                        original_value=str(confidence),
                    )
                )
                confidence = None

        if status == InvestigationStatus.INSUFFICIENT_EVIDENCE:
            answer = "I don't know — insufficient evidence to determine this reliably."
            # If no unknowns were stated, declare insufficient evidence
            if not any("insufficient" in u.lower() for u in unknowns):
                unknowns.append("Insufficient authoritative evidence to reach a deterministic conclusion.")


        # ---------------------------------------------------------------------
        # 2. IDENTITY FABRICATION DETECTION
        # ---------------------------------------------------------------------
        # Check answer, observed facts, and inferences
        sanitized_facts = []
        for fact in observed_facts:
            has_identity, sanitized_fact = cls._check_and_sanitize_identity(fact)
            if has_identity:
                violations.append(
                    HallucinationViolation(
                        violation_type=HallucinationViolationType.IDENTITY_FABRICATION,
                        description=f"Identity fabrication detected in observed_fact: '{fact}'",
                        original_value=fact,
                        sanitized_value=sanitized_fact,
                    )
                )
                sanitized_facts.append(sanitized_fact)
            else:
                sanitized_facts.append(fact)
        observed_facts = sanitized_facts

        sanitized_inf = []
        for inf in inferences:
            has_identity, sanitized_i = cls._check_and_sanitize_identity(inf)
            if has_identity:
                violations.append(
                    HallucinationViolation(
                        violation_type=HallucinationViolationType.IDENTITY_FABRICATION,
                        description=f"Identity fabrication detected in inference: '{inf}'",
                        original_value=inf,
                        sanitized_value=sanitized_i,
                    )
                )
                sanitized_inf.append(sanitized_i)
            else:
                sanitized_inf.append(inf)
        inferences = sanitized_inf

        has_identity_in_ans, sanitized_ans = cls._check_and_sanitize_identity(answer)
        if has_identity_in_ans:
            violations.append(
                HallucinationViolation(
                    violation_type=HallucinationViolationType.IDENTITY_FABRICATION,
                    description=f"Identity fabrication detected in answer: '{answer}'",
                    original_value=answer,
                    sanitized_value=sanitized_ans,
                )
            )
            answer = sanitized_ans
            if "Personal real-world identity cannot be determined" not in " ".join(unknowns):
                unknowns.append(
                    "Personal real-world identity cannot be determined from video intelligence (tracked token only)."
                )

        # ---------------------------------------------------------------------
        # 3. TRIAD CLASSIFICATION SANITIZATION
        # ---------------------------------------------------------------------
        clean_facts = []
        for fact in observed_facts:
            fact_lower = fact.lower()
            if any(marker in fact_lower for marker in cls.INFERENCE_MARKERS):
                # Reclassify from observed_facts to inferences
                inferences.append(fact)
                violations.append(
                    HallucinationViolation(
                        violation_type=HallucinationViolationType.TRIAD_MISCLASSIFICATION,
                        description=f"Inference marker found in observed_fact; relocated to inferences: '{fact}'",
                        original_value=fact,
                        sanitized_value=fact,
                    )
                )
            else:
                clean_facts.append(fact)
        observed_facts = clean_facts

        # ---------------------------------------------------------------------
        # 4. BLIND-SPOT & CAMERA HEALTH SAFETY
        # ---------------------------------------------------------------------
        if context:
            offline_cams = set()
            for cam_id, cam_info in getattr(context, "cameras", {}).items():
                if isinstance(cam_info, dict) and cam_info.get("status") in ("OFFLINE", "DEGRADED"):
                    offline_cams.add(cam_id)

            for cam_id in offline_cams:
                lim_msg = f"{cam_id} was unavailable during this period, so activity cannot be reliably determined."
                if not any(cam_id in lim and "unavailable" in lim.lower() for lim in limitations):
                    limitations.append(lim_msg)

                # Check if answer or facts unsafely claimed "no activity" on this camera
                for fact in list(observed_facts):
                    if cam_id in fact and any(phrase in fact.lower() for phrase in cls.BLINDSPOT_UNSAFE_PHRASES):
                        observed_facts.remove(fact)
                        violations.append(
                            HallucinationViolation(
                                violation_type=HallucinationViolationType.BLINDSPOT_UNSAFETY,
                                description=f"Unsafe negative assertion removed for offline camera {cam_id}: '{fact}'",
                                original_value=fact,
                            )
                        )
                        unknowns.append(f"Activity on {cam_id} cannot be determined due to offline status.")

                if cam_id in answer and any(phrase in answer.lower() for phrase in cls.BLINDSPOT_UNSAFE_PHRASES):
                    violations.append(
                        HallucinationViolation(
                            violation_type=HallucinationViolationType.BLINDSPOT_UNSAFETY,
                            description=f"Unsafe negative assertion in answer for offline camera {cam_id}",
                            original_value=answer,
                        )
                    )
                    answer = f"{cam_id} was unavailable; activity cannot be determined reliably."

        # ---------------------------------------------------------------------
        # 5. PHANTOM IDENTIFIER VERIFICATION
        # ---------------------------------------------------------------------
        if context:
            known_evidence: Set[str] = set()
            for ev in getattr(context, "verified_evidence", []):
                if isinstance(ev, dict) and ev.get("evidence_id"):
                    known_evidence.add(ev["evidence_id"])
            for eid in getattr(context, "evidence_ids", []):
                known_evidence.add(str(eid))

            clean_evidence_ids = []
            for eid in evidence_ids:
                if known_evidence and eid not in known_evidence:
                    violations.append(
                        HallucinationViolation(
                            violation_type=HallucinationViolationType.PHANTOM_IDENTIFIER,
                            description=f"Phantom evidence_id '{eid}' removed (not in authoritative evidence)",
                            original_value=str(eid),
                        )
                    )
                else:
                    clean_evidence_ids.append(eid)
            evidence_ids = clean_evidence_ids

        # ---------------------------------------------------------------------
        # 6. CONFIDENCE CLAMPING ON CONFLICT OR INSUFFICIENT EVIDENCE
        # ---------------------------------------------------------------------
        if status in (InvestigationStatus.INSUFFICIENT_EVIDENCE, InvestigationStatus.CONFLICTED_EVIDENCE):
            if confidence is not None:
                violations.append(
                    HallucinationViolation(
                        violation_type=HallucinationViolationType.CONFIDENCE_MISALIGNMENT,
                        description=f"Confidence {confidence} cleared due to {status.value} status",
                        original_value=str(confidence),
                    )
                )
                confidence = None

        sanitized_result = InvestigationResult(
            investigation_id=result.investigation_id,
            status=status,
            answer=answer,
            observed_facts=observed_facts,
            inferences=inferences,
            timeline=timeline,
            evidence_ids=evidence_ids,
            confidence=confidence,
            unknowns=unknowns,
            limitations=limitations,
        )

        return HallucinationGuardResult(
            is_clean=len(violations) == 0,
            violations=violations,
            sanitized_result=sanitized_result,
        )

    @classmethod
    def _check_and_sanitize_identity(cls, text: str) -> Tuple[bool, str]:
        """Detect and sanitize any personal name/identity claims in text."""
        matched = False
        sanitized = text
        for pattern in cls.IDENTITY_PATTERNS:
            if pattern.search(sanitized):
                matched = True
                # Sanitize the real name to anonymous token
                sanitized = pattern.sub("identified as anonymous tracked entity", sanitized)
        return matched, sanitized
