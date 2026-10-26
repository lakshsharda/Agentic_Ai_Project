"""Threat Assessment & Intelligence -- process entry point (ADK, port 9102).

Serves its A2A agent card and, on an inbound task from Detection, runs:

    CANDIDATE  (mark received)
      -> Correlation agent      (enrich against threat intel)
      -> Severity agent         (assign severity + type, real reasoning)
    ASSESSED   (write severity/type/escalated)
      -> Dispatch stub          (log the would-be fan-out)
      -> reply to Detection

    python -m threat_assessment.server
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import uvicorn
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events.event_queue_v2 import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import (
    add_a2a_routes_to_fastapi,
    create_agent_card_routes,
    create_jsonrpc_routes,
)
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import Role
from fastapi import FastAPI
from google.adk.agents import LlmAgent
from google.adk.runners import InMemoryRunner
from google.genai import types as genai_types

from shared.a2a_support import (
    AGENT_CARD_PATH,
    ON_CALL_URL,
    RPC_PATH,
    THREAT_ASSESSMENT_URL,
    build_agent_card,
    from_a2a_message,
    incident_skill,
    send_incident_message,
    to_a2a_message,
)
from shared.comms_notify import notify_comms_in_background
from shared.llm import require_google_api_key, run_with_rate_limit_retry
from shared.schemas import IncidentMessage, IncidentStatus, Severity, SystemName
from shared.reasoning import record_reasoning, start_call
from shared.store import IncidentStore
from threat_assessment.agents import (
    CORRELATION_STATE_KEY,
    SEVERITY_STATE_KEY,
    VALID_SEVERITIES,
    CorrelationResult,
    SeverityAssessment,
    build_correlation_agent,
    build_severity_agent,
)
from shared.guardrail import (
    ACTION_CANDIDATE,
    ACTION_PAGE,
    ACTION_RECLASSIFY,
    ACTION_STATUS_UPDATE,
    check_authority,
    requires_human_approval,
)
from threat_assessment.dispatch import dispatch_real

_SEVERITY_RANK = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


def _rank(sev: str) -> int:
    return _SEVERITY_RANK.get(sev, 1)


def _needs_approval(sev: str) -> bool:
    return requires_human_approval(sev)


# When the model's answer is missing, incomplete or off-vocabulary, the severity we fall back to
# must never give LESS oversight than a clear answer would. "Medium" and below auto-execute
# containment (requires_human_approval is False), so an ambiguous answer defaulting there would
# silently skip the human gate. The floor is High, which requires approval; a fallback that is
# already higher (e.g. Forensics suggested Critical) is kept, never lowered.
UNCERTAIN_SEVERITY_FLOOR = "High"
assert requires_human_approval(UNCERTAIN_SEVERITY_FLOOR), "the uncertain-answer floor must require approval"


def _cautious(sev: Optional[str]) -> str:
    """``sev`` if it is at least the uncertain-answer floor, else the floor."""
    if sev in _SEVERITY_RANK and _rank(sev) >= _rank(UNCERTAIN_SEVERITY_FLOOR):
        return sev
    return UNCERTAIN_SEVERITY_FLOOR


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [threat-assessment] %(levelname)s %(message)s",
)
logging.getLogger("google_genai").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger("threat_assessment")

PORT = int(os.environ.get("THREAT_ASSESSMENT_PORT", "9102"))
SELF_SYSTEM = SystemName.THREAT_ASSESSMENT


async def _run_structured(runner: InMemoryRunner, app_name: str, prompt: str, state_key: str) -> dict:
    """Run a single-shot LlmAgent and return the structured output from state.

    Wrapped in rate-limit retry: the free Gemini tier allows few requests per
    minute, and one incident fires several model calls (noise filter, then
    correlation and severity here), so transient 429s are routine.
    """
    session = await runner.session_service.create_session(app_name=app_name, user_id="ta")

    async def _invoke():
        async for _ in runner.run_async(
            user_id="ta",
            session_id=session.id,
            new_message=genai_types.Content(role="user", parts=[genai_types.Part(text=prompt)]),
        ):
            pass

    await run_with_rate_limit_retry(_invoke, label=f"{app_name}")

    session = await runner.session_service.get_session(
        app_name=app_name, user_id="ta", session_id=session.id
    )
    return session.state.get(state_key)


def _coerce_assessment(raw: Any, *, default_severity: str, default_type: str, who: str) -> SeverityAssessment:
    """Validate the model's structured severity answer, tolerating an incomplete one.

    When Gemini is quota-exhausted the chain falls through to a weaker fallback model that can
    return a mostly-right object with a field missing (seen: no ``rationale``). A strict
    ``model_validate`` then raised and the whole task died with an InternalError -- a reclassification
    simply never happened. Only the descriptive fields are filled in here: ``severity`` must still be
    a real value from the vocabulary (otherwise the caller's default is used, as in the
    no-result case), and ``escalate`` is derived from that severity, never invented.
    """
    try:
        return SeverityAssessment.model_validate(raw)
    except Exception as exc:  # noqa: BLE001 - pydantic ValidationError or a non-dict answer
        data = raw if isinstance(raw, dict) else {}
        severity = data.get("severity") if data.get("severity") in VALID_SEVERITIES else _cautious(default_severity)
        logger.warning(
            "%s: model returned an incomplete/invalid structured answer (%s); completing the missing "
            "descriptive fields (severity=%s; an unusable severity falls to at least %s)",
            who, str(exc).splitlines()[0][:100], severity, UNCERTAIN_SEVERITY_FLOOR,
        )
        return SeverityAssessment(
            severity=severity,
            incident_type=str(data.get("incident_type") or default_type),
            escalate=bool(data["escalate"]) if isinstance(data.get("escalate"), bool)
            else requires_human_approval(severity),
            rationale=str(data.get("rationale") or "model omitted its rationale (fallback model); "
                                                   "severity and type are the model's, the text is a placeholder"),
        )


class ThreatAssessmentExecutor(AgentExecutor):
    """Runs the full assessment pipeline for each inbound A2A task."""

    def __init__(self) -> None:
        self.store = IncidentStore()
        self._correlation_runner = InMemoryRunner(
            agent=build_correlation_agent(), app_name="ta_correlation"
        )
        self._severity_runner = InMemoryRunner(
            agent=build_severity_agent(), app_name="ta_severity"
        )

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        if context.message is None:
            raise ValueError("received an A2A request with no message")

        inbound = from_a2a_message(context.message, trace_received=True)
        action = inbound.payload.get("action")

        # Containment reports back with a status_update; that is not a new
        # candidate and must not restart the assessment pipeline.
        if action == ACTION_STATUS_UPDATE:
            await self._handle_status_update(inbound, event_queue)
            return

        # Forensics feeds a re-classification back upstream. This is NOT a fresh
        # candidate -- the incident already exists; handle it separately.
        if action == ACTION_RECLASSIFY:
            await self._handle_reclassification(inbound, event_queue)
            return

        detection = inbound.payload.get("detection", {})
        evidence = detection.get("evidence", {})
        logger.info(
            "received candidate from %s: incident %s pattern=%s",
            inbound.source_system,
            inbound.incident_id,
            detection.get("pattern_type"),
        )

        # Enforce the authority matrix on the inbound candidate.
        if not check_authority(inbound.source_system, SELF_SYSTEM.value, ACTION_CANDIDATE, incident_id=inbound.incident_id):
            reply = inbound.reply(
                {"accepted": False, "reason": f"authority denied from {inbound.source_system}"},
                source_system=SELF_SYSTEM,
            )
            await event_queue.enqueue_event(to_a2a_message(reply, role=Role.ROLE_AGENT))
            return

        # CANDIDATE: we have accepted it for assessment.
        self._advance_candidate(inbound.incident_id)

        call = start_call(system=SELF_SYSTEM, agent_name="Correlation Agent", incident_id=inbound.incident_id)
        correlation = await self._correlate(evidence)
        call.resolve(
            text=(f"{correlation.intel_summary.strip()}\n\nThreat intel: {correlation.malicious_ip_count} malicious, "
                  f"{correlation.suspicious_ip_count} suspicious source IP(s).\n{correlation.enrichment_notes.strip()}"),
            narration=(f"Threat Assessment received Detection's escalation and checked the source IPs against threat intel: "
                       f"{correlation.malicious_ip_count} malicious, {correlation.suspicious_ip_count} suspicious."))
        call = start_call(system=SELF_SYSTEM, agent_name="Severity Classification Agent", incident_id=inbound.incident_id)
        assessment = await self._classify(evidence, detection, correlation)
        call.resolve(
            text=(f"Severity: {assessment.severity}  |  Type: {assessment.incident_type}  |  "
                  f"Escalate: {assessment.escalate}\n{assessment.rationale.strip()}"),
            narration=(f"Threat Assessment classified this {assessment.severity} ({assessment.incident_type}) and "
                       "dispatched to Containment, On-Call and Forensics in parallel."))

        severity = assessment.severity if assessment.severity in VALID_SEVERITIES else UNCERTAIN_SEVERITY_FLOOR
        if severity != assessment.severity:
            logger.error(
                "model returned off-vocabulary severity %r; coercing to %s (fail toward oversight)",
                assessment.severity, UNCERTAIN_SEVERITY_FLOOR,
            )

        # ASSESSED: record the classification.
        record = self.store.advance_status(
            inbound.incident_id,
            IncidentStatus.ASSESSED,
            by_system=SELF_SYSTEM.value,
            severity=Severity(severity),
            incident_type=assessment.incident_type,
            escalated=assessment.escalate,
            payload={
                "assessment": {
                    "severity": severity,
                    "incident_type": assessment.incident_type,
                    "escalate": assessment.escalate,
                    "rationale": assessment.rationale,
                    "correlation": correlation.model_dump(),
                }
            },
            note=f"severity={severity} type={assessment.incident_type}",
        )
        logger.info("assessed: %s", record.summary())

        # Build the assessment payload once; it is both the dispatch fan-out
        # body and the reply to Detection.
        assessment_payload = {
            "assessment": {
                "incident_id": inbound.incident_id,
                "severity": severity,
                "incident_type": assessment.incident_type,
                "escalate": assessment.escalate,
                "rationale": assessment.rationale,
                "correlation": correlation.model_dump(),
                "evidence": evidence,
            }
        }

        # DISPATCHED: record that we are fanning out, before the sends, so the
        # lifecycle reflects the hand-off even if a downstream call is slow.
        self.store.advance_status(
            inbound.incident_id,
            IncidentStatus.DISPATCHED,
            by_system=SELF_SYSTEM.value,
            note="fanning out to Containment and On-Call",
        )

        # Real, parallel fan-out to Containment and On-Call (Phase 2, Task 5).
        dispatch_results = await dispatch_real(inbound.incident_id, assessment_payload)

        reply = inbound.reply(
            {
                "assessment": assessment_payload["assessment"],
                "status": IncidentStatus.DISPATCHED.value,
                "dispatch": dispatch_results,
            },
            source_system=SELF_SYSTEM,
        )
        await event_queue.enqueue_event(to_a2a_message(reply, role=Role.ROLE_AGENT))

    async def _handle_status_update(self, inbound: IncidentMessage, event_queue: EventQueue) -> None:
        """Record a containment status update without re-assessing."""
        if not check_authority(inbound.source_system, SELF_SYSTEM.value, ACTION_STATUS_UPDATE, incident_id=inbound.incident_id):
            reply = inbound.reply({"accepted": False, "reason": "authority denied"}, source_system=SELF_SYSTEM)
            await event_queue.enqueue_event(to_a2a_message(reply, role=Role.ROLE_AGENT))
            return
        containment = inbound.payload.get("containment", {})
        logger.info(
            "status update from %s for %s: %s",
            inbound.source_system, inbound.incident_id, containment,
        )
        self.store.update_incident(
            inbound.incident_id,
            raw_payload={"containment_report": containment},
        )
        reply = inbound.reply({"accepted": True, "recorded": True}, source_system=SELF_SYSTEM)
        await event_queue.enqueue_event(to_a2a_message(reply, role=Role.ROLE_AGENT))

    async def _handle_reclassification(self, inbound: IncidentMessage, event_queue: EventQueue) -> None:
        """Re-assess an EXISTING incident on Forensics' new evidence (Phase 3, Task 2).

        Distinct from a fresh candidate: the incident already exists (look it up,
        never create a duplicate), the severity agent re-runs informed by the new
        findings, and the outcome is logged whether or not it actually changes.
        A revision that crosses into High/Critical re-opens the approval
        requirement and re-pages On-Call, visibly marked as re-opened.
        """
        incident_id = inbound.incident_id
        if not check_authority(inbound.source_system, SELF_SYSTEM.value, ACTION_RECLASSIFY, incident_id=inbound.incident_id):
            reply = inbound.reply({"accepted": False, "reason": "authority denied"}, source_system=SELF_SYSTEM)
            await event_queue.enqueue_event(to_a2a_message(reply, role=Role.ROLE_AGENT))
            return

        existing = self.store.get_incident(incident_id)
        if existing is None:
            logger.warning("reclassification for unknown incident %s -- refusing to create", incident_id)
            reply = inbound.reply({"accepted": False, "reason": "unknown incident"}, source_system=SELF_SYSTEM)
            await event_queue.enqueue_event(to_a2a_message(reply, role=Role.ROLE_AGENT))
            return

        old_severity = existing.severity or "Medium"
        suggested = inbound.payload.get("suggested_severity")
        forensic_reason = inbound.payload.get("reason", "")
        narrative = inbound.payload.get("root_cause_narrative", "")
        logger.warning(
            "RECLASSIFY request for existing incident %s (currently %s): Forensics suggests %s -- %s",
            incident_id, old_severity, suggested, forensic_reason,
        )

        # Re-run the severity agent, now informed by Forensics' findings.
        evidence = (existing.raw_payload or {}).get("detection", {}).get("evidence", {})
        call = start_call(system=SELF_SYSTEM, agent_name="Severity Classification Agent (re-classification)",
                          incident_id=incident_id)
        new_assessment = await self._reclassify_with_evidence(
            evidence, old_severity, suggested, forensic_reason, narrative
        )
        new_severity = new_assessment.severity if new_assessment.severity in VALID_SEVERITIES else _cautious(old_severity)
        call.resolve(
            text=(f"Re-assessed on Forensics' findings: {old_severity} -> {new_severity}  |  "
                  f"Type: {new_assessment.incident_type}\n{new_assessment.rationale.strip()}"),
            narration=("Forensics' findings prompted Threat Assessment to re-assess: severity "
                       + (f"changed {old_severity} -> {new_severity}." if new_severity != old_severity
                          else f"confirmed at {old_severity}, unchanged.")))

        changed = _rank(new_severity) != _rank(old_severity)
        crosses_approval = (not _needs_approval(old_severity)) and _needs_approval(new_severity)

        if not changed:
            # A re-classification request need not result in an actual change.
            self.store.reclassify(
                incident_id, by_system=SELF_SYSTEM.value, severity=Severity(new_severity),
                reason=f"re-assessed on Forensics evidence; confirmed {new_severity} (no change). {forensic_reason}",
                payload={"reclassification": {"changed": False, "old": old_severity, "new": new_severity,
                                              "forensic_reason": forensic_reason}},
            )
            logger.info("reclassification for %s: confirmed %s, no change", incident_id, new_severity)
            reply = inbound.reply(
                {"accepted": True, "reclassification": {"changed": False, "severity": new_severity}},
                source_system=SELF_SYSTEM)
            await event_queue.enqueue_event(to_a2a_message(reply, role=Role.ROLE_AGENT))
            return

        # Real revision -- write via the narrow exception (status does not move back).
        self.store.reclassify(
            incident_id, by_system=SELF_SYSTEM.value,
            severity=Severity(new_severity), incident_type=new_assessment.incident_type,
            escalated=True if crosses_approval else existing.escalated,
            reason=f"re-assessed on Forensics evidence: {old_severity} -> {new_severity}. "
                   f"{new_assessment.rationale}",
            payload={"reclassification": {"changed": True, "old": old_severity, "new": new_severity,
                                          "crosses_approval_threshold": crosses_approval,
                                          "forensic_reason": forensic_reason}},
        )
        logger.warning("reclassified %s: %s -> %s (crosses approval=%s)",
                       incident_id, old_severity, new_severity, crosses_approval)

        reopened = False
        if crosses_approval:
            reopened = await self._reopen_for_escalation(incident_id, new_severity, new_assessment)

        # Phase 4: an assessment that changed supersedes whatever customers were
        # (or were about to be) told, so Customer Comms drafts an updated notice.
        notify_comms_in_background(SELF_SYSTEM, incident_id, "reclassified")

        reply = inbound.reply(
            {"accepted": True, "reclassification": {
                "changed": True, "old_severity": old_severity, "new_severity": new_severity,
                "crosses_approval_threshold": crosses_approval, "reopened": reopened}},
            source_system=SELF_SYSTEM)
        await event_queue.enqueue_event(to_a2a_message(reply, role=Role.ROLE_AGENT))

    async def _reopen_for_escalation(self, incident_id, new_severity, assessment) -> bool:
        """Re-open the approval requirement and re-page On-Call for an upgraded
        incident, clearly marked as a re-open distinct from the original."""
        # Clear the prior approval so Containment's gate requires a fresh one.
        self.store.update_incident(incident_id, raw_payload={
            "approval": {"approved": False, "reopened_at": _now_iso(),
                         "reason": f"severity raised to {new_severity} on re-classification"},
            "reopened": {"at": _now_iso(), "new_severity": new_severity},
        })
        payload = {
            "action": ACTION_PAGE,
            "reopened": True,
            "assessment": {
                "incident_id": incident_id, "severity": new_severity,
                "incident_type": assessment.incident_type, "escalate": True,
                "rationale": f"RE-OPENED: severity raised to {new_severity} after Forensics re-classification. "
                             f"{assessment.rationale}",
                "evidence": (self.store.get_incident(incident_id).raw_payload or {}).get("detection", {}).get("evidence", {}),
            },
        }
        if not check_authority(SELF_SYSTEM.value, SystemName.ON_CALL.value, ACTION_PAGE, incident_id=incident_id):
            return False
        msg = IncidentMessage(
            incident_id=incident_id, source_system=SELF_SYSTEM, target_system=SystemName.ON_CALL,
            payload=payload)
        logger.warning("RE-PAGING On-Call for re-opened incident %s at %s", incident_id, new_severity)
        try:
            await send_incident_message(msg, peer_base_url=ON_CALL_URL)
            return True
        except Exception:
            logger.exception("re-page to On-Call failed for %s", incident_id)
            return False

    async def _reclassify_with_evidence(self, evidence, old_severity, suggested, forensic_reason, narrative):
        prompt = (
            "This is a RE-CLASSIFICATION of an existing incident, not a new one.\n"
            f"Current severity: {old_severity}. Forensics suggests: {suggested}.\n"
            f"Forensics reason: {forensic_reason}\n\n"
            f"Root-cause findings:\n{narrative[:1500]}\n\n"
            f"Original evidence:\n{json.dumps(evidence, indent=2, default=str)[:1200]}\n\n"
            "Re-assess severity in light of the new forensic findings. You may confirm the existing "
            "severity if the evidence does not actually warrant a change. Assign severity, incident type, "
            "and whether to escalate."
        )
        raw = await _run_structured(self._severity_runner, "ta_severity", prompt, SEVERITY_STATE_KEY)
        if raw is None:
            # Fall back to Forensics' suggestion if the model gave nothing.
            return SeverityAssessment(severity=_cautious(suggested or old_severity),
                                      incident_type="reclassified", escalate=True,
                                      rationale="model produced no structured result; used Forensics suggestion")
        return _coerce_assessment(raw, default_severity=suggested or old_severity,
                                  default_type="reclassified", who="reclassification")  # helper applies _cautious

    def _advance_candidate(self, incident_id: str) -> None:
        try:
            self.store.advance_status(
                incident_id,
                IncidentStatus.CANDIDATE,
                by_system=SELF_SYSTEM.value,
                note="accepted for assessment",
            )
        except KeyError:
            # Detection normally writes the DETECTED row before sending. If it
            # is somehow absent, create it so the pipeline still records state.
            logger.warning("no existing row for %s; creating at CANDIDATE", incident_id)
            self.store.create_incident(incident_id, status=IncidentStatus.CANDIDATE)

    async def _correlate(self, evidence: Dict[str, Any]) -> CorrelationResult:
        ips = _source_ips_from_evidence(evidence)
        prompt = (
            "Candidate incident evidence (JSON):\n"
            f"{json.dumps(evidence, indent=2, default=str)}\n\n"
            f"Source IPs to check: {ips}\n\n"
            "Enrich this against threat intelligence and summarise what it means."
        )
        raw = await _run_structured(
            self._correlation_runner, "ta_correlation", prompt, CORRELATION_STATE_KEY
        )
        if raw is None:
            logger.error("correlation produced no result; using an empty summary")
            return CorrelationResult(
                intel_summary="correlation unavailable",
                malicious_ip_count=0,
                suspicious_ip_count=0,
                enrichment_notes="model produced no structured correlation result",
            )
        return CorrelationResult.model_validate(raw)

    async def _classify(
        self, evidence: Dict[str, Any], detection: Dict[str, Any], correlation: CorrelationResult
    ) -> SeverityAssessment:
        prompt = (
            "Candidate incident evidence (JSON):\n"
            f"{json.dumps(evidence, indent=2, default=str)}\n\n"
            f"Detection's own read: pattern={detection.get('pattern_type')}, "
            f"confidence={detection.get('confidence')}, reasoning={detection.get('reasoning')}\n\n"
            "Correlation / threat-intel summary:\n"
            f"{json.dumps(correlation.model_dump(), indent=2, default=str)}\n\n"
            "Assign severity, an incident type, and whether to escalate."
        )
        raw = await _run_structured(
            self._severity_runner, "ta_severity", prompt, SEVERITY_STATE_KEY
        )
        if raw is None:
            logger.error("severity classification produced no result; defaulting to %s (fail toward oversight)",
                         UNCERTAIN_SEVERITY_FLOOR)
            return SeverityAssessment(
                severity=UNCERTAIN_SEVERITY_FLOOR,
                incident_type=detection.get("pattern_type", "unknown"),
                escalate=True,
                rationale="model produced no structured severity result; severity set to the uncertain-answer "
                          f"floor ({UNCERTAIN_SEVERITY_FLOOR}) so a human approves before any action",
            )
        return _coerce_assessment(raw, default_severity=UNCERTAIN_SEVERITY_FLOOR,
                                  default_type=detection.get("pattern_type", "unknown"), who="severity classification")

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise NotImplementedError


def _source_ips_from_evidence(evidence: Dict[str, Any]) -> list:
    """Pull the source IPs out of Detection's evidence, de-duplicated."""
    ips: list = []
    for key in ("top_failed_login_ips", "top_source_ips"):
        for entry in evidence.get(key, []):
            ip = entry[0] if isinstance(entry, (list, tuple)) and entry else entry
            if ip and ip not in ips:
                ips.append(ip)
    return ips


def build_app() -> FastAPI:
    agent_card = build_agent_card(
        name="Threat Assessment & Intelligence",
        description=(
            "Enriches candidate incidents against threat intelligence, classifies "
            "their severity and type with LLM reasoning, and fans out to response "
            "systems."
        ),
        url=THREAT_ASSESSMENT_URL,
        system=SELF_SYSTEM,
        skills=[
            incident_skill(
                skill_id="assess_incident",
                name="Assess incident",
                description="Correlate, classify severity/type, and dispatch an incident.",
            )
        ],
    )
    request_handler = DefaultRequestHandler(
        agent_executor=ThreatAssessmentExecutor(),
        task_store=InMemoryTaskStore(),
        agent_card=agent_card,
    )
    app = FastAPI(title="Threat Assessment & Intelligence — A2A")
    add_a2a_routes_to_fastapi(
        app,
        agent_card_routes=create_agent_card_routes(agent_card, card_url=AGENT_CARD_PATH),
        jsonrpc_routes=create_jsonrpc_routes(request_handler, rpc_url=RPC_PATH),
    )

    @app.get("/health", tags=["threat-assessment"])
    async def health() -> dict:
        return {"status": "ok", "system": SELF_SYSTEM.value}

    return app


if __name__ == "__main__":
    require_google_api_key()
    logger.info("agent card -> http://127.0.0.1:%s%s", PORT, AGENT_CARD_PATH)
    logger.info("a2a rpc    -> http://127.0.0.1:%s%s", PORT, RPC_PATH)
    uvicorn.run(build_app(), host="127.0.0.1", port=PORT, log_level="warning")
