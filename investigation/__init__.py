"""
Module 4: Investigation
Contains event search, camera correlation, entity correlation, and timeline engines.
"""
from investigation.entity_correlation import (
    CorrelatedObservation,
    CorrelationStatus,
    CrossCameraCorrelationResult,
    EntityCorrelationEngine,
    EntityCorrelationTrajectory,
)
from investigation.event_search import (
    EventRetrievalResult,
    EventRetrievalService,
    RetrievalStatus,
)
from investigation.timeline import (
    TimelineConstructionResult,
    TimelineEngine,
    parse_timestamp_safe,
)

__all__ = [
    "EventRetrievalResult",
    "EventRetrievalService",
    "RetrievalStatus",
    "TimelineEngine",
    "TimelineConstructionResult",
    "parse_timestamp_safe",
    "EntityCorrelationEngine",
    "CrossCameraCorrelationResult",
    "EntityCorrelationTrajectory",
    "CorrelatedObservation",
    "CorrelationStatus",
]
