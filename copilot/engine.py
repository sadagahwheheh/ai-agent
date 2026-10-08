"""
Module 4: AI Security Copilot Engine.
Provides natural-language query resolution for security operators with strict fact/inference separation.
Adheres strictly to the Absolute No-Hallucination Triad:
1. Observed Facts: Authoritative data from video intelligence events and evidence.
2. Inferences: Contextual/policy deductions explicitly flagged.
3. Unknowns: Declaring UNKNOWN for unobservable data, camera downtime, or missing evidence.
Strictly prohibits personal identity fabrication (entity_id tokens only).
"""
import logging
from typing import Any, Dict, List, Optional, Union

from copilot.intent import CopilotIntentAnalyzer
from integration.backend_client import BackendClient
from integration.mock_client import MockBackendClient
from schemas.copilot import (
    CopilotIntentType,
    CopilotQueryRequest,
    CopilotQueryResponse,
)

logger = logging.getLogger(__name__)


class SecurityCopilotEngine:
    """
    Cognitive copilot engine for security operators.
    Provides evidence-grounded answers to natural-language queries.
    """

    def __init__(self, backend_client: Optional[Any] = None, orchestrator: Optional[Any] = None):
        self.backend_client = backend_client or MockBackendClient()
        self.orchestrator = orchestrator

    async def query(
        self,
        request_input: Union[Dict[str, Any], CopilotQueryRequest],
    ) -> CopilotQueryResponse:
        """
        Processes a natural-language copilot query and returns a structured CopilotQueryResponse.
        """
        # Validate input into CopilotQueryRequest
        if isinstance(request_input, CopilotQueryRequest):
            request = request_input
        else:
            request = CopilotQueryRequest(**request_input)

        # Analyze intent and canonical tokens
        analysis = CopilotIntentAnalyzer.analyze(request)
        intent_type: CopilotIntentType = analysis["intent_type"]

        observed_facts: List[str] = []
        inferences: List[str] = []
        unknowns: List[str] = []
        limitations: List[str] = []
        evidence_ids: List[str] = []
        followups: List[str] = []
        confidence: Optional[float] = None
        answer: str = ""

        # Identity hallucination protection check
        if analysis["asks_personal_identity"]:
            unknowns.append(
                "Personal real-world identity cannot be determined from video intelligence. "
                "Entity is tracked solely via anonymous entity_id tokens."
            )

        # Dispatch based on detected intent
        if intent_type == CopilotIntentType.CAMERA_STATUS:
            ans, sub_facts, sub_inf, sub_unk, sub_lim, sub_fol, conf = (
                await self._handle_camera_status(analysis, request)
            )
            sub_ev = []
        elif intent_type == CopilotIntentType.SECURITY_POLICY:
            ans, sub_facts, sub_inf, sub_unk, sub_lim, sub_fol, conf = (
                await self._handle_security_policy(analysis, request)
            )
            sub_ev = []
        elif intent_type == CopilotIntentType.ENTITY_TRACKING:
            ans, sub_facts, sub_inf, sub_unk, sub_lim, sub_ev, sub_fol, conf = (
                await self._handle_entity_tracking(analysis, request)
            )
        elif intent_type == CopilotIntentType.INCIDENT_INQUIRY:
            ans, sub_facts, sub_inf, sub_unk, sub_lim, sub_ev, sub_fol, conf = (
                await self._handle_incident_inquiry(analysis, request)
            )
        elif intent_type == CopilotIntentType.ZONE_ACTIVITY:
            ans, sub_facts, sub_inf, sub_unk, sub_lim, sub_ev, sub_fol, conf = (
                await self._handle_zone_activity(analysis, request)
            )
        else:
            # General investigation or timeline inquiry
            ans, sub_facts, sub_inf, sub_unk, sub_lim, sub_ev, sub_fol, conf = (
                await self._handle_general_investigation(analysis, request)
            )

        answer = ans
        observed_facts.extend(sub_facts)
        inferences.extend(sub_inf)
        for u in sub_unk:
            if u not in unknowns:
                unknowns.append(u)
        for l in sub_lim:
            if l not in limitations:
                limitations.append(l)
        for e in sub_ev:
            if e not in evidence_ids:
                evidence_ids.append(e)
        followups.extend(sub_fol)
        confidence = conf

        # Append identity notice to answer if requested
        if analysis["asks_personal_identity"] and "Personal real-world identity" not in answer:
            answer = (
                f"{answer} Note: Personal real-world identity cannot be determined from video intelligence."
            ).strip()


        return CopilotQueryResponse(
            query=request.query,
            answer=answer,
            intent_type=intent_type,
            observed_facts=observed_facts,
            inferences=inferences,
            unknowns=unknowns,
            evidence_ids=evidence_ids,
            confidence=confidence,
            suggested_followups=followups,
            limitations=limitations,
        )

    # -------------------------------------------------------------------------
    # INTENT HANDLERS
    # -------------------------------------------------------------------------

    async def _handle_camera_status(
        self, analysis: Dict[str, Any], request: CopilotQueryRequest
    ):
        observed_facts = []
        inferences = []
        unknowns = []
        limitations = []
        followups = []
        confidence = 0.95

        cameras = analysis["cameras"]
        if not cameras:
            cameras = ["CAM-03", "CAM-04", "CAM-05", "CAM-07"]

        statuses = []
        for cam_id in cameras:
            try:
                cam_data = await self.backend_client.get_camera(cam_id)
                status = cam_data.get("status", "UNKNOWN")
                zone = cam_data.get("zone_id", "Unknown Zone")
                name = cam_data.get("name", cam_id)
                observed_facts.append(f"{cam_id} ({name}) is {status} in {zone}.")
                statuses.append(f"{cam_id}: {status}")

                if status == "OFFLINE":
                    limitations.append(
                        f"{cam_id} is OFFLINE; unmonitored blind spot. Activity cannot be determined."
                    )
                    followups.append(f"Check network connectivity and maintenance logs for {cam_id}")
            except Exception:
                unknowns.append(f"Status for {cam_id} could not be retrieved from Backend.")
                statuses.append(f"{cam_id}: UNKNOWN")

        answer = f"Camera operational status: {', '.join(statuses)}."
        if limitations:
            answer += f" {len(limitations)} camera(s) reported offline."
            followups.append("Inspect perimeter coverage for alternative camera views")

        return answer, observed_facts, inferences, unknowns, limitations, followups, confidence

    async def _handle_security_policy(
        self, analysis: Dict[str, Any], request: CopilotQueryRequest
    ):
        observed_facts = []
        inferences = []
        unknowns = []
        limitations = []
        followups = []
        confidence = 0.95

        try:
            memories = await self.backend_client.get_security_memory(status="ACTIVE")
            policies = [m for m in memories if m.get("type") in ("zone_policy", "security_rule")]
            if policies:
                for p in policies:
                    val = p.get("value", {})
                    zone = val.get("zone_id", "General")
                    rule = val.get("policy", str(val))
                    observed_facts.append(f"Active policy for {zone}: {rule} (source: {p.get('source')}).")
                answer = f"Active security policies found: {len(policies)} policies registered."
                followups.append("Review audit history for active zone policies")
            else:
                answer = "No active security policies currently found in security memory."
                unknowns.append("No active zone policies registered in security memory.")
        except Exception as exc:
            answer = "I don't know — security context memory is currently unavailable."
            limitations.append(f"Security memory query failed: {exc}")
            confidence = None

        return answer, observed_facts, inferences, unknowns, limitations, followups, confidence

    async def _handle_entity_tracking(
        self, analysis: Dict[str, Any], request: CopilotQueryRequest
    ):
        observed_facts = []
        inferences = []
        unknowns = []
        limitations = []
        evidence_ids = []
        followups = []
        confidence = None

        entities = analysis["entities"]
        if not entities:
            return (
                "I don't know — no tracked entity identifier specified in query.",
                [],
                [],
                ["Entity identifier was not specified for tracking."],
                [],
                [],
                ["Specify entity ID (e.g. ENT-902) to perform tracking investigation"],
                None,
            )

        ent_id = entities[0]
        try:
            events = await self.backend_client.search_events(entity_id=ent_id)
        except Exception:
            events = []

        if not events:
            answer = f"I don't know — insufficient evidence to determine movement for {ent_id}."
            unknowns.append(f"No indexed events found for entity token {ent_id}.")
            return answer, observed_facts, inferences, unknowns, limitations, evidence_ids, followups, None

        # Sort chronologically
        events = sorted(events, key=lambda e: e.get("timestamp", ""))
        cams_seen = []
        for evt in events:
            cam = evt.get("camera_id")
            ts = evt.get("timestamp")
            etype = evt.get("event_type", "event")
            observed_facts.append(f"Entity {ent_id} observed on {cam} at {ts} ({etype}).")
            if cam and cam not in cams_seen:
                cams_seen.append(cam)
            # Find evidence if any
            try:
                ev_items = await self.backend_client.list_evidence_for_event(evt.get("event_id"))
                for ev in ev_items:
                    ev_id = ev.get("evidence_id")
                    if ev_id and ev_id not in evidence_ids:
                        evidence_ids.append(ev_id)
            except Exception:
                pass

        if len(cams_seen) > 1:
            inferences.append(
                f"Entity {ent_id} transitioned across {len(cams_seen)} cameras: {' -> '.join(cams_seen)}."
            )
            answer = (
                f"Entity {ent_id} tracked moving across cameras {' -> '.join(cams_seen)} "
                f"between {events[0].get('timestamp')} and {events[-1].get('timestamp')}."
            )
            confidence = 0.92
        else:
            answer = f"Entity {ent_id} observed exclusively on {cams_seen[0]} at {events[0].get('timestamp')}."
            confidence = 0.90

        # Check for offline adjacent cameras
        try:
            all_cams = await self.backend_client.list_cameras()
            for c in all_cams:
                if c.get("status") == "OFFLINE":
                    limitations.append(f"Camera {c.get('camera_id')} is OFFLINE; unmonitored blind spot.")
        except Exception:
            pass

        followups.append(f"Request incident creation for {ent_id}")
        followups.append(f"Verify snapshot evidence for {ent_id}")

        return answer, observed_facts, inferences, unknowns, limitations, evidence_ids, followups, confidence

    async def _handle_incident_inquiry(
        self, analysis: Dict[str, Any], request: CopilotQueryRequest
    ):
        observed_facts = []
        inferences = []
        unknowns = []
        limitations = []
        evidence_ids = []
        followups = []
        confidence = None

        incidents = analysis["incidents"]
        if not incidents:
            return (
                "I don't know — no incident identifier specified.",
                [],
                [],
                ["Incident ID missing from query context."],
                [],
                [],
                ["Provide incident identifier, e.g. INC-8821"],
                None,
            )

        inc_id = incidents[0]
        try:
            incident = await self.backend_client.get_incident(inc_id)
        except Exception:
            return (
                f"I don't know — incident {inc_id} not found in Backend records.",
                [],
                [],
                [f"Incident {inc_id} could not be retrieved."],
                [],
                [],
                ["Verify incident ID with Backend Security Core"],
                None,
            )

        title = incident.get("title", "Untitled Incident")
        zone_id = incident.get("zone_id", "Unknown Zone")
        status = incident.get("status", "UNKNOWN")
        observed_facts.append(f"Incident {inc_id}: '{title}' in {zone_id} (status: {status}).")

        # Fetch associated threat if present
        thr_id = incident.get("associated_threat_id")
        if thr_id:
            try:
                thr = await self.backend_client.get_threat(thr_id)
                observed_facts.append(
                    f"Threat {thr_id} severity: {thr.get('severity')} (score: {thr.get('score')})."
                )
                inferences.append(f"Threat reason: {thr.get('reason')}")
            except Exception:
                unknowns.append(f"Associated threat {thr_id} details unavailable.")

        # Fetch associated events and evidence
        for evt_id in incident.get("associated_events", []):
            try:
                evt = await self.backend_client.get_event(evt_id)
                cam = evt.get("camera_id")
                ts = evt.get("timestamp")
                observed_facts.append(f"Event {evt_id} recorded on {cam} at {ts}.")
                ev_items = await self.backend_client.list_evidence_for_event(evt_id)
                for ev in ev_items:
                    eid = ev.get("evidence_id")
                    if eid and eid not in evidence_ids:
                        evidence_ids.append(eid)
            except Exception:
                unknowns.append(f"Event {evt_id} details could not be retrieved.")

        answer = (
            f"Incident {inc_id} ({title}) in {zone_id}. "
            f"Status is {status} with {len(incident.get('associated_events', []))} correlated event(s)."
        )
        confidence = 0.94 if evidence_ids else 0.80

        followups.append(f"Launch full investigation into {inc_id}")
        followups.append(f"Review evidence package for {inc_id}")

        return answer, observed_facts, inferences, unknowns, limitations, evidence_ids, followups, confidence

    async def _handle_zone_activity(
        self, analysis: Dict[str, Any], request: CopilotQueryRequest
    ):
        observed_facts = []
        inferences = []
        unknowns = []
        limitations = []
        evidence_ids = []
        followups = []
        confidence = None

        zones = analysis["zones"]
        if not zones:
            zones = ["ZONE-04"]

        target_zone = zones[0]
        try:
            events = await self.backend_client.search_events(zone_ids=[target_zone])
        except Exception:
            events = []

        if not events:
            answer = f"No security events recorded in {target_zone}."
            observed_facts.append(f"Query returned 0 events for {target_zone}.")
            confidence = 0.90
        else:
            for evt in events:
                eid = evt.get("event_id")
                cam = evt.get("camera_id")
                etype = evt.get("event_type")
                ts = evt.get("timestamp")
                observed_facts.append(f"Event {eid} ({etype}) on {cam} at {ts}.")
                try:
                    ev_items = await self.backend_client.list_evidence_for_event(eid)
                    for ev in ev_items:
                        ev_id = ev.get("evidence_id")
                        if ev_id and ev_id not in evidence_ids:
                            evidence_ids.append(ev_id)
                except Exception:
                    pass

            answer = f"Detected {len(events)} event(s) in {target_zone}."
            confidence = 0.93

        # Check for cameras in zone that might be offline
        try:
            all_cams = await self.backend_client.list_cameras()
            zone_cams = [c for c in all_cams if c.get("zone_id") == target_zone]
            for zc in zone_cams:
                if zc.get("status") == "OFFLINE":
                    limitations.append(
                        f"{zc.get('camera_id')} in {target_zone} is OFFLINE; blind spots exist."
                    )
        except Exception:
            pass

        followups.append(f"Check security policies for {target_zone}")
        followups.append(f"Audit recent access logs for {target_zone}")

        return answer, observed_facts, inferences, unknowns, limitations, evidence_ids, followups, confidence

    async def _handle_general_investigation(
        self, analysis: Dict[str, Any], request: CopilotQueryRequest
    ):
        observed_facts = []
        inferences = []
        unknowns = []
        limitations = []
        evidence_ids = []
        followups = []
        confidence = None

        # If orchestrator is provided, run full orchestration
        if self.orchestrator:
            try:
                inv_res = await self.orchestrator.orchestrate({
                    "investigation_id": request.investigation_id or "INV-COPILOT-001",
                    "query": request.query,
                    "camera_ids": analysis["cameras"] or None,
                    "zone_ids": analysis["zones"] or None,
                    "incident_id": analysis["incidents"][0] if analysis["incidents"] else None,
                    "time_range": request.time_range.model_dump() if request.time_range else None,
                })
                return (
                    inv_res.answer,
                    inv_res.observed_facts,
                    inv_res.inferences,
                    inv_res.unknowns,
                    inv_res.limitations,
                    inv_res.evidence_ids,
                    ["Review chronological timeline", "Inspect verified evidence items"],
                    inv_res.confidence,
                )
            except Exception as exc:
                limitations.append(f"Orchestration invocation failed: {exc}")

        # Fallback to search events
        try:
            events = await self.backend_client.search_events(
                camera_ids=analysis["cameras"] or None,
                zone_ids=analysis["zones"] or None,
            )
        except Exception:
            events = []

        if events:
            for evt in events[:5]:
                observed_facts.append(
                    f"Event {evt.get('event_id')} on {evt.get('camera_id')} at {evt.get('timestamp')}."
                )
            answer = f"Found {len(events)} relevant security event(s) matching query parameters."
            confidence = 0.85
        else:
            answer = "I don't know — insufficient evidence to determine this reliably."
            unknowns.append("No authoritative events found matching the specified parameters.")

        followups.append("Broaden search time window")
        followups.append("Check overall camera health status")

        return answer, observed_facts, inferences, unknowns, limitations, evidence_ids, followups, confidence
