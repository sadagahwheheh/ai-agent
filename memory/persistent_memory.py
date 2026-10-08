"""
Module 4: Persistent Security Memory Service.
Coordinates storage, retrieval, status tracking, and conflict auditing of security context memory
via Backend Security Core (Module 2). Module 4 does NOT own or directly access the database.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

from integration.exceptions import (
    BackendAuthError,
    BackendConnectionError,
    BackendDataNotFoundError,
    BackendIntegrationError,
)
from memory.validation import (
    MemoryConflict,
    MemoryValidationResult,
    SecurityMemoryValidator,
)
from schemas.memory import SecurityMemory


class PersistentSecurityMemoryService:
    """
    Manages structured security context memories via Backend Security Core API gateway.
    Never fabricates memory, preserves auditable sources, and flags context conflicts.
    """

    def __init__(self, backend_client: Any):
        self.backend_client = backend_client

    async def store_memory(
        self,
        memory: Union[SecurityMemory, Dict[str, Any]],
        auto_detect_conflict: bool = True,
    ) -> Tuple[SecurityMemory, Optional[str]]:
        """
        Persists a security context memory item via Backend Security Core.
        Checks for semantic contradictions; if detected, sets CONFLICTED status and returns warning.
        """
        mem_obj = memory if isinstance(memory, SecurityMemory) else SecurityMemory.model_validate(memory)

        warning_message: Optional[str] = None

        # Check for conflicts against existing memories
        if auto_detect_conflict:
            existing = await self.retrieve_by_type(mem_obj.type)
            for ex in existing:
                conflict = SecurityMemoryValidator.check_pair_conflict(mem_obj, ex)
                if conflict:
                    warning_message = "Security context conflict detected."
                    # Mark new memory as CONFLICTED
                    mem_dict = mem_obj.model_dump()
                    mem_dict["status"] = "CONFLICTED"
                    mem_obj = SecurityMemory.model_validate(mem_dict)
                    break

        # Persist through Backend API gateway
        saved_raw = await self.backend_client.save_security_memory(mem_obj.model_dump())
        saved_obj = SecurityMemory.model_validate(saved_raw)
        return saved_obj, warning_message

    async def get_memory(self, memory_id: str) -> Optional[SecurityMemory]:
        """Fetch a specific security context memory by memory_id."""
        if not memory_id or not memory_id.strip():
            return None
        cleaned_id = memory_id.strip()
        all_mems = await self.list_all()
        for m in all_mems:
            if m.memory_id == cleaned_id:
                return m
        return None

    async def retrieve_by_type(
        self,
        memory_type: str,
        status: Optional[str] = None,
    ) -> List[SecurityMemory]:
        """Fetch memories matching a specific context category (e.g. camera_mapping, zone_policy)."""
        if not memory_type or not memory_type.strip():
            return []
        raw_items = await self.backend_client.get_security_memory(
            memory_type=memory_type.strip(),
            status=status
        )
        return [SecurityMemory.model_validate(item) for item in raw_items]

    async def retrieve_by_source(
        self,
        source: str,
        status: Optional[str] = None,
    ) -> List[SecurityMemory]:
        """Fetch memories originating from an auditable source."""
        if not source or not source.strip():
            return []
        all_items = await self.list_all(status=status)
        return [m for m in all_items if m.source == source.strip()]

    async def retrieve_by_status(self, status: str) -> List[SecurityMemory]:
        """Fetch memories by lifecycle status (ACTIVE, CONFLICTED, ARCHIVED)."""
        if not status or not status.strip():
            return []
        return await self.list_all(status=status.strip())

    async def list_all(self, status: Optional[str] = None) -> List[SecurityMemory]:
        """Fetch all stored security context memories from Backend."""
        raw_items = await self.backend_client.get_security_memory(status=status)
        return [SecurityMemory.model_validate(item) for item in raw_items]

    async def update_memory(
        self,
        memory_id: str,
        updates: Dict[str, Any],
    ) -> SecurityMemory:
        """Update an existing memory item, updating updated_at while preserving created_at and source."""
        current = await self.get_memory(memory_id)
        if not current:
            raise BackendDataNotFoundError(f"Memory item {memory_id} not found to update")

        current_dict = current.model_dump()
        for key, val in updates.items():
            if key not in ("memory_id", "created_at", "source"):  # immutable provenance fields
                current_dict[key] = val

        current_dict["updated_at"] = datetime.now(timezone.utc).isoformat()
        saved_raw = await self.backend_client.save_security_memory(current_dict)
        return SecurityMemory.model_validate(saved_raw)

    async def mark_status(self, memory_id: str, new_status: str) -> SecurityMemory:
        """Update lifecycle state of a memory item (e.g. mark CONFLICTED or ARCHIVED)."""
        return await self.update_memory(memory_id, {"status": new_status})

    async def detect_conflicts(self, memory_type: Optional[str] = None) -> MemoryValidationResult:
        """Scan active memories and report all detected security context contradictions."""
        if memory_type:
            memories = await self.retrieve_by_type(memory_type)
        else:
            memories = await self.list_all()

        return SecurityMemoryValidator.find_conflicts(memories)
