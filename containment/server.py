"""Containment / Ops -- process entry point (CrewAI, port 9103).

On an inbound `request_action` from Threat Assessment:
  1. enforce the authority matrix on the sender,
  2. run the CrewAI crew to decide a mitigation (which IPs to block),
  3. gate execution behind the shared guardrail,
  4. if approval is required and absent, sit PENDING and resume when the
     approval signal appears (written by On-Call); otherwise execute now,
  5. execute against the simulated firewall, advance the incident to CONTAINED,
     and send a status update back to Threat Assessment.

    python -m containment.server
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

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

from containment.agents import MitigationPlan, build_containment_crew, interpret_plan
from containment.firewall import block_ips, blocked_ips
from containment.firewall import unblock_ips as firewall_unblock
from shared.a2a_support import (
    AGENT_CARD_PATH,
    CONTAINMENT_URL,
    RPC_PATH,
    build_agent_card,
    from_a2a_message,
    incident_skill,
    send_incident_message,
    to_a2a_message,
)
from shared.guardrail import (
    ACTION_EVIDENCE_PRESERVED,
    ACTION_RECOVERY_PLAN,
    ACTION_REQUEST_ACTION,
    ACTION_STATUS_UPDATE,
    ACTION_TIMEOUT_ESCALATION,
    check_authority,
    evaluate_action_gate,
)
from shared.comms_notify import notify_comms_in_background
from shared.llm import require_google_api_key
from shared.schemas import IncidentMessage, IncidentStatus, SystemName
from shared.store import IncidentStore
from shared.reasoning import record_reasoning, start_call
from shared.trace import record_trace

logging.basicConfig(level=logging.INFO, format="%(asctime)s [containment] %(levelname)s %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("LiteLLM").setLevel(logging.WARNING)
logger = logging.getLogger("containment")

PORT = int(os.environ.get("CONTAINMENT_PORT", "9103"))
SELF_SYSTEM = SystemName.CONTAINMENT
APPROVAL_WAIT_SECONDS = float(os.environ.get("CONTAINMENT_APPROVAL_WAIT", "180"))
APPROVAL_POLL_SECONDS = float(os.environ.get("CONTAINMENT_APPROVAL_POLL", "3"))


def _offending_ips(evidence: Dict[str, Any]) -> List[str]:
    ips: List[str] = []
    for key in ("top_failed_login_ips", "top_source_ips"):
        for entry in evidence.get(key, []):
            ip = entry[0] if isinstance(entry, (list, tuple)) and entry else entry
            # Skip loopback -- blocking the local box is never the right call.
            if ip and ip not in ips and not str(ip).startswith("127."):
                ips.append(ip)
    return ips


class ContainmentExecutor(AgentExecutor):
    def __init__(self) -> None:
        self.store = IncidentStore()
        # incident_id -> pending context, so a background waiter can execute the
        # already-decided plan once approval lands without re-running the crew.
        self._pending: Dict[str, Dict[str, Any]] = {}

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        if context.message is None:
            raise ValueError("received an A2A request with no message")
        inbound = from_a2a_message(context.message, trace_received=True)
        action = inbound.payload.get("action", ACTION_REQUEST_ACTION)
        source = inbound.source_system

        # Real inbound authority check -- the matrix, enforced in code.
        if not check_authority(source, SELF_SYSTEM.value, action, incident_id=inbound.incident_id):
            logger.warning("rejecting unauthorized %s from %s for %s", action, source, inbound.incident_id)
            reply = inbound.reply(
                {"accepted": False, "reason": f"authority denied for action {action!r} from {source}"},
                source_system=SELF_SYSTEM,
            )
            await event_queue.enqueue_event(to_a2a_message(reply, role=Role.ROLE_AGENT))
            return

        if action == ACTION_RECOVERY_PLAN:
            result = await self._on_recovery_plan(inbound)
        elif action in (ACTION_TIMEOUT_ESCALATION, ACTION_EVIDENCE_PRESERVED):
            result = await self._on_resume_signal(inbound, action)
        else:
            result = await self._on_request_action(inbound)

        reply = inbound.reply(result, source_system=SELF_SYSTEM)
        await event_queue.enqueue_event(to_a2a_message(reply, role=Role.ROLE_AGENT))

    def _gate(self, incident_id: str, from_system: str, severity: Optional[str]):
        """Evaluate the full action gate: authority + evidence + approval."""
        return evaluate_action_gate(
            self.store,
            from_system=from_system,
            to_system=SELF_SYSTEM.value,
            action_type=ACTION_REQUEST_ACTION,
            severity=severity,
            incident_id=incident_id,
            require_evidence=True,  # Phase 3: evidence must be preserved first
        )

    async def _on_request_action(self, inbound: IncidentMessage) -> Dict[str, Any]:
        incident_id = inbound.incident_id
        assessment = inbound.payload.get("assessment", {})
        severity = assessment.get("severity")
        evidence = assessment.get("evidence", {})
        offending = _offending_ips(evidence)

        logger.info(
            "containment request for %s severity=%s offending_ips=%s",
            incident_id, severity, offending,
        )

        brief = self._incident_brief(incident_id, assessment, offending)
        call = start_call(system=SELF_SYSTEM, agent_name="Containment Planning Agent", incident_id=incident_id)
        plan = await asyncio.to_thread(self._run_crew, brief, offending)
        plan_ips = plan.block_ips  # derived from evidence by interpret_plan, not model text
        call.resolve(
            text=(f"Decision: {plan.action}  |  planned blocks: {', '.join(plan_ips) if plan_ips else 'none'}\n"
                  f"{plan.rationale.strip()}"),
            narration=(f"Containment received the {severity} dispatch and planned to "
                       + (f"block {len(plan_ips)} source IP(s)" if plan_ips else f"take no blocking action ({plan.action})")
                       + "; execution waits on the evidence-preserved and approval gates."))

        # Remember the decided plan so a background waiter can execute it once
        # the gate opens, without re-running the crew.
        self._pending[incident_id] = {
            "plan_ips": plan_ips, "plan": plan, "severity": severity,
            "from_system": inbound.source_system,
        }

        gate = self._gate(incident_id, inbound.source_system, severity)
        if gate.allowed:
            self._pending.pop(incident_id, None)
            return self._execute_and_report(incident_id, plan_ips, plan, severity, gate.reason)

        # Held: evidence not preserved yet, and/or approval required and absent.
        state = "PENDING_EVIDENCE" if gate.pending_evidence else "PENDING_APPROVAL"
        self.store.update_incident(
            incident_id,
            raw_payload={"containment": {
                "state": state,
                "planned_block_ips": plan_ips,
                "rationale": plan.rationale,
                "reason": gate.reason,
                "at": datetime.now(timezone.utc).isoformat(),
            }},
        )
        logger.warning(
            "containment %s for %s: action NOT executed (%s). Planned to block %s",
            state, incident_id, gate.reason, plan_ips,
        )
        asyncio.create_task(self._await_gate(incident_id))
        return {
            "accepted": True, "state": state, "executed": False,
            "reason": gate.reason, "planned_block_ips": plan_ips,
        }

    async def _on_resume_signal(self, inbound: IncidentMessage, action: str) -> Dict[str, Any]:
        """A nudge (On-Call timeout-escalation, or Forensics evidence-preserved)
        telling us a gating signal may now be present. Re-check and resume."""
        incident_id = inbound.incident_id
        logger.info("resume nudge (%s) for %s; re-checking the gate", action, incident_id)
        done = await self._try_resume(incident_id)
        return {"accepted": True, "resumed": done}

    async def _await_gate(self, incident_id: str) -> None:
        """Poll the full gate and execute once it opens (bounded wait)."""
        waited = 0.0
        while waited < APPROVAL_WAIT_SECONDS:
            await asyncio.sleep(APPROVAL_POLL_SECONDS)
            waited += APPROVAL_POLL_SECONDS
            if incident_id not in self._pending:
                return  # already handled by a nudge
            if await self._try_resume(incident_id):
                return
        logger.warning("containment gate wait expired for %s (%.0fs)", incident_id, APPROVAL_WAIT_SECONDS)

    async def _try_resume(self, incident_id: str) -> bool:
        ctx = self._pending.get(incident_id)
        if ctx is None:
            return False
        gate = self._gate(incident_id, ctx["from_system"], ctx["severity"])
        if not gate.allowed:
            return False
        logger.info("gate opened for %s (%s); executing held action", incident_id, gate.reason)
        self._pending.pop(incident_id, None)
        self._execute_and_report(incident_id, ctx["plan_ips"], ctx["plan"], ctx["severity"], gate.reason)
        return True

    async def _on_recovery_plan(self, inbound: IncidentMessage) -> Dict[str, Any]:
        """Forensics says recovery is planned; lift the IP blocks if safe.

        Reuses the guardrail pattern: authority was already checked in execute();
        the lift only happens on an explicit safe_to_lift signal.
        """
        incident_id = inbound.incident_id
        safe = bool(inbound.payload.get("safe_to_lift"))
        record = self.store.get_incident(incident_id)
        blocked_here = []
        if record:
            blocked_here = (record.raw_payload or {}).get("containment", {}).get("blocked_ips", [])

        if not safe:
            logger.info("recovery for %s: safe_to_lift=False; keeping blocks", incident_id)
            record_trace(
                incident_id=incident_id, from_system=SELF_SYSTEM, event_type="gate_evaluated", decision="blocked",
                summary="recovery lift refused: Forensics did not signal safe_to_lift, blocks kept (no `resolved`)",
                detail={"gate": "recovery", "safe_to_lift": False, "allowed": False},
            )
            self.store.update_incident(incident_id, raw_payload={"recovery": {
                "lifted": False, "reason": "Forensics advised not safe to lift yet"}})
            return {"accepted": True, "lifted": False, "reason": "not safe to lift"}

        # Phase 4: only a containment that actually EXECUTED can be lifted and
        # resolved. A lift signal arriving while the action is still held
        # (PENDING_APPROVAL / PENDING_EVIDENCE) would otherwise mark the
        # incident RESOLVED and make the later CONTAINED advance a backward move.
        contained_state = (record.raw_payload or {}).get("containment", {}).get("state") if record else None
        if contained_state != "EXECUTED":
            logger.warning("recovery for %s: containment state is %s, not EXECUTED; nothing to lift yet",
                           incident_id, contained_state)
            record_trace(
                incident_id=incident_id, from_system=SELF_SYSTEM, event_type="gate_evaluated", decision="blocked",
                summary=f"recovery lift refused: containment has not executed yet (state={contained_state})",
                detail={"gate": "recovery", "safe_to_lift": True, "allowed": False, "state": contained_state},
            )
            return {"accepted": True, "lifted": False,
                    "reason": f"containment not executed yet (state={contained_state})"}

        record_trace(
            incident_id=incident_id, from_system=SELF_SYSTEM, event_type="gate_evaluated", decision="auto",
            summary="recovery lift allowed: Forensics signalled safe_to_lift and containment was executed",
            detail={"gate": "recovery", "safe_to_lift": True, "allowed": True},
        )
        fw = firewall_unblock(blocked_here, incident_id=incident_id, reason="recovery: safe to lift")
        record_trace(
            incident_id=incident_id, from_system=SELF_SYSTEM, event_type="action_executed", decision="auto",
            summary=f"lifted {len(fw.get('unblocked', []))} block(s) in the simulated firewall (recovery, safe_to_lift)",
            detail={"action": "lift_containment", "count": len(fw.get("unblocked", [])), "simulated": True},
        )
        self.store.update_incident(incident_id, raw_payload={"recovery": {
            "lifted": True, "unblocked": fw.get("unblocked", []), "firewall": fw,
            "at": datetime.now(timezone.utc).isoformat()}})
        # Phase 4: nothing advanced an incident to RESOLVED before. The lift
        # completing is the natural end of the lifecycle, so Containment (which
        # performed it) records RESOLVED, forward-only like every other move.
        self.store.advance_status(
            incident_id, IncidentStatus.RESOLVED, by_system=SELF_SYSTEM.value,
            note=f"recovery lift complete: unblocked {fw.get('unblocked', [])}",
        )
        logger.info("recovery for %s: lifted blocks %s; incident RESOLVED", incident_id, fw.get("unblocked"))
        return {"accepted": True, "lifted": True, "unblocked": fw.get("unblocked", [])}

    def _execute_and_report(
        self, incident_id: str, plan_ips: List[str], plan: MitigationPlan,
        severity: Optional[str], reason: str,
    ) -> Dict[str, Any]:
        """The physically-gated side effect + status reporting."""
        if not plan_ips:
            logger.info("no IPs to block for %s; marking contained with no action", incident_id)
            fw_result = {"newly_blocked": [], "note": "no offending IPs to block"}
            record_trace(
                incident_id=incident_id, from_system=SELF_SYSTEM, event_type="action_executed", decision="auto",
                summary="no containment action taken: nothing to block (marked contained with no firewall change)",
                detail={"action": plan.action, "count": 0, "simulated": True, "approval_reason": reason},
            )
        else:
            fw_result = block_ips(plan_ips, incident_id=incident_id, reason=plan.rationale)
            record_trace(
                incident_id=incident_id, from_system=SELF_SYSTEM, event_type="action_executed",
                decision="auto", summary=f"blocked {len(plan_ips)} source address(es) in the simulated firewall",
                detail={"action": plan.action, "count": len(plan_ips), "simulated": True, "approval_reason": reason},
            )

        self.store.advance_status(
            incident_id, IncidentStatus.CONTAINED, by_system=SELF_SYSTEM.value,
            payload={"containment": {
                "state": "EXECUTED", "action": plan.action, "blocked_ips": plan_ips,
                "rationale": plan.rationale, "firewall": fw_result,
                "approval_reason": reason, "simulated": True,
                "at": datetime.now(timezone.utc).isoformat(),
            }},
            note=f"contained: blocked {plan_ips} ({reason})",
        )
        logger.info("CONTAINED %s: blocked=%s (%s)", incident_id, plan_ips, reason)

        asyncio.create_task(self._report_status(incident_id, plan_ips, plan, fw_result))
        if plan_ips:
            # Phase 4: tell Customer Comms protective action is in place. Only
            # when something was really blocked -- "we took protective action"
            # would be untrue after a no_action decision.
            notify_comms_in_background(SELF_SYSTEM, incident_id, "contained")
        return {
            "accepted": True, "executed": True, "state": "CONTAINED",
            "blocked_ips": plan_ips, "simulated": True, "reason": reason,
        }

    async def _report_status(self, incident_id, plan_ips, plan: MitigationPlan, fw_result) -> None:
        """Status Reporting: send a real A2A status update back to Threat Assessment."""
        if not check_authority(SELF_SYSTEM.value, SystemName.THREAT_ASSESSMENT.value, ACTION_STATUS_UPDATE, incident_id=incident_id):
            return
        msg = IncidentMessage(
            incident_id=incident_id,
            source_system=SELF_SYSTEM,
            target_system=SystemName.THREAT_ASSESSMENT,
            payload={"action": ACTION_STATUS_UPDATE, "status": IncidentStatus.CONTAINED.value,
                     "containment": {"blocked_ips": plan_ips, "action": plan.action,
                                     "rationale": plan.rationale, "firewall": fw_result, "simulated": True}},
        )
        try:
            from shared.a2a_support import THREAT_ASSESSMENT_URL
            await send_incident_message(msg, peer_base_url=THREAT_ASSESSMENT_URL)
            logger.info("status update sent to Threat Assessment for %s", incident_id)
        except Exception:
            logger.exception("failed to send status update for %s", incident_id)

    def _incident_brief(self, incident_id, assessment, offending) -> str:
        return (
            f"Incident {incident_id}\n"
            f"Severity: {assessment.get('severity')}\n"
            f"Type: {assessment.get('incident_type')}\n"
            f"Assessment rationale: {assessment.get('rationale')}\n"
            f"Offending source IPs (block candidates): {offending}\n"
            f"Currently blocked IPs: {blocked_ips()}\n"
            f"Evidence: {json.dumps(assessment.get('evidence', {}), default=str)[:1200]}"
        )

    def _run_crew(self, brief: str, offending: List[str]) -> MitigationPlan:
        try:
            crew = build_containment_crew(brief)
            result = crew.kickoff()
            return interpret_plan(str(result), offending)
        except Exception as exc:  # noqa: BLE001 - a model failure must not strand containment
            logger.warning("containment crew failed (%s); failing safe to blocking offending IPs", exc)
            return MitigationPlan(block_ips=list(offending), action="block_ips",
                                  rationale=f"crew unavailable ({str(exc)[:120]}); blocked offending IPs")

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise NotImplementedError


def build_app() -> FastAPI:
    agent_card = build_agent_card(
        name="Containment / Ops",
        description="Executes gated mitigation actions (IP blocking) against the environment "
        "in response to Threat Assessment, and reports status back.",
        url=CONTAINMENT_URL,
        system=SELF_SYSTEM,
        skills=[incident_skill(
            skill_id="contain_incident",
            name="Contain incident",
            description="Block offending IPs for an assessed incident, subject to approval.",
        )],
    )
    request_handler = DefaultRequestHandler(
        agent_executor=ContainmentExecutor(),
        task_store=InMemoryTaskStore(),
        agent_card=agent_card,
    )
    app = FastAPI(title="Containment / Ops — A2A")
    add_a2a_routes_to_fastapi(
        app,
        agent_card_routes=create_agent_card_routes(agent_card, card_url=AGENT_CARD_PATH),
        jsonrpc_routes=create_jsonrpc_routes(request_handler, rpc_url=RPC_PATH),
    )

    @app.get("/health", tags=["containment"])
    async def health() -> dict:
        return {"status": "ok", "system": SELF_SYSTEM.value, "blocked_ips": blocked_ips()}

    return app


if __name__ == "__main__":
    require_google_api_key()
    logger.info("agent card -> http://127.0.0.1:%s%s", PORT, AGENT_CARD_PATH)
    uvicorn.run(build_app(), host="127.0.0.1", port=PORT, log_level="warning")
