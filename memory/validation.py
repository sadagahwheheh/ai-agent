"""
Module 4: Security Context Memory Validation & Conflict Detection.
Validates memory items, checks auditable sources, and identifies contradictory security contexts.
"""
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field

from schemas.memory import SecurityMemory


class MemoryConflict(BaseModel):
    """Auditable representation of a detected memory contradiction."""
    model_config = ConfigDict(extra="ignore", frozen=True)

    memory_id_a: str
    source_a: str
    value_a: Any
    memory_id_b: str
    source_b: str
    value_b: Any
    memory_type: str
    reason: str
    message: str = "Security context conflict detected."


class MemoryValidationResult(BaseModel):
    """Outcome of conflict analysis across memory records."""
    model_config = ConfigDict(extra="ignore", frozen=True)

    has_conflict: bool = False
    conflicts: List[MemoryConflict] = Field(default_factory=list)
    message: Optional[str] = None


class SecurityMemoryValidator:
    """
    Evaluates consistency across security context memories.
    Never chooses between conflicting memories arbitrarily.
    Preserves both source references for auditability.
    """

    @classmethod
    def check_pair_conflict(cls, mem_a: SecurityMemory, mem_b: SecurityMemory) -> Optional[MemoryConflict]:
        """Examines two memories of the same type for semantic contradictions."""
        if mem_a.memory_id == mem_b.memory_id:
            return None
        if mem_a.type != mem_b.type:
            return None
        # Only check active or conflicted memories
        if mem_a.status not in ("ACTIVE", "CONFLICTED") or mem_b.status not in ("ACTIVE", "CONFLICTED"):
            return None

        val_a = mem_a.value
        val_b = mem_b.value

        # 1. Camera mapping conflicts: same camera_id assigned to different locations
        if mem_a.type == "camera_mapping" and isinstance(val_a, dict) and isinstance(val_b, dict):
            cam_a = val_a.get("camera_id")
            cam_b = val_b.get("camera_id")
            if cam_a and cam_b and cam_a == cam_b:
                loc_a = val_a.get("location") or val_a.get("name")
                loc_b = val_b.get("location") or val_b.get("name")
                if loc_a and loc_b and loc_a != loc_b:
                    return MemoryConflict(
                        memory_id_a=mem_a.memory_id,
                        source_a=mem_a.source,
                        value_a=val_a,
                        memory_id_b=mem_b.memory_id,
                        source_b=mem_b.source,
                        value_b=val_b,
                        memory_type=mem_a.type,
                        reason=f"Camera {cam_a} mapped to contradictory locations: '{loc_a}' vs '{loc_b}'"
                    )

        # 2. Zone policy conflicts: same zone_id with conflicting authorization rules
        if mem_a.type == "zone_policy" and isinstance(val_a, dict) and isinstance(val_b, dict):
            zone_a = val_a.get("zone_id")
            zone_b = val_b.get("zone_id")
            if zone_a and zone_b and zone_a == zone_b:
                policy_a = val_a.get("policy") or val_a.get("rule")
                policy_b = val_b.get("policy") or val_b.get("rule")
                if policy_a and policy_b and policy_a != policy_b:
                    return MemoryConflict(
                        memory_id_a=mem_a.memory_id,
                        source_a=mem_a.source,
                        value_a=val_a,
                        memory_id_b=mem_b.memory_id,
                        source_b=mem_b.source,
                        value_b=val_b,
                        memory_type=mem_a.type,
                        reason=f"Zone {zone_a} has conflicting policies: '{policy_a}' vs '{policy_b}'"
                    )

        # 3. Direct value divergence for simple string or identical dict keys
        if val_a != val_b and isinstance(val_a, str) and isinstance(val_b, str):
            return MemoryConflict(
                memory_id_a=mem_a.memory_id,
                source_a=mem_a.source,
                value_a=val_a,
                memory_id_b=mem_b.memory_id,
                source_b=mem_b.source,
                value_b=val_b,
                memory_type=mem_a.type,
                reason=f"Conflicting values for context type '{mem_a.type}': '{val_a}' vs '{val_b}'"
            )

        return None

    @classmethod
    def find_conflicts(cls, memories: List[SecurityMemory]) -> MemoryValidationResult:
        """Scan a collection of memories and detect all contradictions."""
        conflicts: List[MemoryConflict] = []
        seen_pairs = set()

        for i in range(len(memories)):
            for j in range(i + 1, len(memories)):
                mem_a = memories[i]
                mem_b = memories[j]
                pair_key = tuple(sorted([mem_a.memory_id, mem_b.memory_id]))
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                conflict = cls.check_pair_conflict(mem_a, mem_b)
                if conflict:
                    conflicts.append(conflict)

        if conflicts:
            return MemoryValidationResult(
                has_conflict=True,
                conflicts=conflicts,
                message="Security context conflict detected."
            )

        return MemoryValidationResult(has_conflict=False, conflicts=[])
