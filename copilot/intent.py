"""
Module 4: Copilot Intent Analyzer.
Analyzes natural language queries from security operators, extracting canonical identifiers,
temporal cues, intent categories, and flags queries requesting prohibited personal identity inference.
"""
import re
from typing import Any, Dict, List, Optional

from schemas.copilot import CopilotIntentType, CopilotQueryRequest
from schemas.identifiers import (
    CameraId,
    EntityId,
    EventId,
    EvidenceId,
    IncidentId,
    ThreatId,
    ZoneId,
)


class CopilotIntentAnalyzer:
    """
    Deterministic rule-based intent analyzer for security operator queries.
    Identifies canonical tokens and intent types with zero fabrication.
    """

    # Canonical identifier regex patterns
    CAM_PATTERN = re.compile(r"\bCAM-\d+\b", re.IGNORECASE)
    ZONE_PATTERN = re.compile(r"\bZONE-\d+\b", re.IGNORECASE)
    EVT_PATTERN = re.compile(r"\bEVT-\d+\b", re.IGNORECASE)
    INC_PATTERN = re.compile(r"\bINC-\d+\b", re.IGNORECASE)
    ENT_PATTERN = re.compile(r"\bENT-\d+\b", re.IGNORECASE)
    EVD_PATTERN = re.compile(r"\bEVD-\d+\b", re.IGNORECASE)
    THR_PATTERN = re.compile(r"\bTHR-\d+\b", re.IGNORECASE)

    # Personal identity query phrases that require strict no-hallucination protection
    IDENTITY_QUERY_PHRASES = [
        "who is",
        "who's",
        "identity",
        "what is the name",
        "what's the name",
        "person's name",
        "identify the person",
        "suspect name",
        "suspect's name",
        "driver name",
        "driver's name",
        "real name",
        "their name",
        "his name",
        "her name",
        "full name",
    ]


    @classmethod
    def analyze(cls, request: CopilotQueryRequest) -> Dict[str, Any]:
        """
        Analyze request query text combined with explicit request parameters.
        Returns extracted tokens, intent type, and identity inquiry flag.
        """
        query_text = request.query
        q_lower = query_text.lower()

        # Extract identifiers from query string
        extracted_cameras = [m.upper() for m in cls.CAM_PATTERN.findall(query_text)]
        extracted_zones = [m.upper() for m in cls.ZONE_PATTERN.findall(query_text)]
        extracted_events = [m.upper() for m in cls.EVT_PATTERN.findall(query_text)]
        extracted_incidents = [m.upper() for m in cls.INC_PATTERN.findall(query_text)]
        extracted_entities = [m.upper() for m in cls.ENT_PATTERN.findall(query_text)]
        extracted_evidence = [m.upper() for m in cls.EVD_PATTERN.findall(query_text)]
        extracted_threats = [m.upper() for m in cls.THR_PATTERN.findall(query_text)]

        # Merge with explicit request parameters
        all_cameras = list(dict.fromkeys((request.camera_ids or []) + extracted_cameras))
        all_zones = list(dict.fromkeys((request.zone_ids or []) + extracted_zones))
        all_incidents = list(dict.fromkeys(([request.incident_id] if request.incident_id else []) + extracted_incidents))
        all_entities = list(dict.fromkeys(([request.entity_id] if request.entity_id else []) + extracted_entities))

        # Check for personal identity queries
        asks_personal_identity = any(phrase in q_lower for phrase in cls.IDENTITY_QUERY_PHRASES)

        # Determine Intent Type
        if any(w in q_lower for w in ["policy", "policies", "polic", "rule", "restricted", "sop", "permitted", "procedure"]):
            intent_type = CopilotIntentType.SECURITY_POLICY
        elif all_incidents or any(w in q_lower for w in ["incident", "breach", "alarm", "alert"]):
            intent_type = CopilotIntentType.INCIDENT_INQUIRY
        elif all_entities or any(w in q_lower for w in ["track", "where did", "entity", "movement", "path"]):
            intent_type = CopilotIntentType.ENTITY_TRACKING
        elif any(w in q_lower for w in ["timeline", "chronology", "sequence", "order of events", "what time"]):
            intent_type = CopilotIntentType.TIMELINE_INQUIRY
        elif (all_cameras and any(w in q_lower for w in ["camera", "status", "health", "offline", "online"])) or ("camera" in q_lower and any(w in q_lower for w in ["status", "health", "offline", "online", "all"])):
            intent_type = CopilotIntentType.CAMERA_STATUS

        elif all_zones or any(w in q_lower for w in ["zone", "area", "sector", "dock", "perimeter"]):
            intent_type = CopilotIntentType.ZONE_ACTIVITY
        else:
            intent_type = CopilotIntentType.GENERAL_INVESTIGATION


        return {
            "intent_type": intent_type,
            "cameras": all_cameras,
            "zones": all_zones,
            "incidents": all_incidents,
            "entities": all_entities,
            "events": extracted_events,
            "evidence": extracted_evidence,
            "threats": extracted_threats,
            "asks_personal_identity": asks_personal_identity,
            "has_temporal": bool(request.time_range) or any(w in q_lower for w in ["at", "between", "during", "yesterday", "today", "shift"]),
        }
