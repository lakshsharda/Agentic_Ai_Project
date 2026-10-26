"""On-Call / Escalation -- process entry point (CrewAI, port 9104).

On an inbound `page` from Threat Assessment:
  1. enforce authority, look up the on-call contact (static schedule),
  2. compose the page (CrewAI, template fallback) and send it for real
     (Slack webhook, else honest local file sink),
  3. start an escalation timer, and reply immediately.

Approval signal (what Containment's guardrail reads):
  * human ack before timeout  -> POST /ack?incident_id=...  -> approval,
    provenance=human
  * timer expires             -> approval, provenance=timeout_escalation, and a
    timeout-escalation A2A nudge to Containment

    python -m on_call.server
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, Set

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

from on_call.agents import compose_page_text
from on_call.ops import lookup_oncall, send_notification
from shared.a2a_support import (
    AGENT_CARD_PATH,
    CONTAINMENT_URL,
    ON_CALL_URL,
    RPC_PATH,
    build_agent_card,
    from_a2a_message,
    incident_skill,
    send_incident_message,
    to_a2a_message,
)
from shared.guardrail import (
    ACTION_PAGE,
    ACTION_TIMEOUT_ESCALATION,
    APPROVAL_HUMAN,
    APPROVAL_TIMEOUT,
    check_authority,
    record_approval,
)
from shared.llm import require_google_api_key
from shared.schemas import IncidentMessage, SystemName
from shared.store import IncidentStore
from shared.reasoning import record_reasoning, start_call
from shared.trace import record_trace

logging.basicConfig(level=logging.INFO, format="%(asctime)s [on-call] %(levelname)s %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("LiteLLM").setLevel(logging.WARNING)
logger = logging.getLogger("on_call")

PORT = int(os.environ.get("ONCALL_PORT", "9104"))
SELF_SYSTEM = SystemName.ON_CALL
# Short + demo-friendly default, not a realistic production value.
ACK_TIMEOUT_SECONDS = float(os.environ.get("ONCALL_ACK_TIMEOUT_SECONDS", "120"))


class OnCallExecutor(AgentExecutor):
    def __init__(self) -> None:
        self.store = IncidentStore()
        self._timers: Dict[str, asyncio.Task] = {}
        self._acked: Set[str] = set()

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        if context.message is None:
            raise ValueError("received an A2A request with no message")
        inbound = from_a2a_message(context.message, trace_received=True)
        action = inbound.payload.get("action", ACTION_PAGE)

        if not check_authority(inbound.source_system, SELF_SYSTEM.value, action, incident_id=inbound.incident_id):
            reply = inbound.reply(
                {"accepted": False, "reason": f"authority denied for {action!r} from {inbound.source_system}"},
                source_system=SELF_SYSTEM,
            )
            await event_queue.enqueue_event(to_a2a_message(reply, role=Role.ROLE_AGENT))
            return

        result = await self._on_page(inbound)
        reply = inbound.reply(result, source_system=SELF_SYSTEM)
        await event_queue.enqueue_event(to_a2a_message(reply, role=Role.ROLE_AGENT))

    async def _on_page(self, inbound: IncidentMessage) -> Dict[str, Any]:
        incident_id = inbound.incident_id
        assessment = inbound.payload.get("assessment", {})
        severity = assessment.get("severity")
        contact = lookup_oncall(severity)

        brief = (
            f"Incident {incident_id}\nSeverity: {severity}\n"
            f"Type: {assessment.get('incident_type')}\n"
            f"Rationale: {assessment.get('rationale')}\n"
            f"On-call: {contact['name']} ({contact['handle']})"
        )
        call = start_call(system=SELF_SYSTEM, agent_name="On-Call Paging Agent", incident_id=incident_id)
        text = await asyncio.to_thread(self._compose, brief, incident_id, severity, contact)
        call.resolve(text=f"Paging {contact.get('name')} ({contact.get('channel')}):\n{text}",
                     narration=(f"On-Call received the {severity} dispatch and paged {contact.get('name')} via "
                                    f"{contact.get('channel')}; a human acknowledgement (or the escalation timeout) "
                                    "clears the approval gate."))
        notice = await asyncio.to_thread(
            send_notification, text, incident_id=incident_id, contact=contact
        )

        record_trace(
            incident_id=incident_id, from_system=SELF_SYSTEM, event_type="action_executed", decision="auto",
            summary=f"paged on-call ({contact.get('channel')}) via {notice.get('transport')}"
                    + (" [RE-OPENED escalation]" if inbound.payload.get("reopened") else ""),
            detail={"action": "page", "transport": notice.get("transport"), "sent": notice.get("sent"),
                    "reopened": bool(inbound.payload.get("reopened"))},
        )
        self.store.update_incident(
            incident_id,
            raw_payload={"on_call": {
                "paged": True, "contact": contact, "notification": notice,
                "ack_timeout_seconds": ACK_TIMEOUT_SECONDS,
            }},
        )

        # Start the escalation timer for this incident.
        if incident_id in self._timers and not self._timers[incident_id].done():
            self._timers[incident_id].cancel()
        self._acked.discard(incident_id)
        self._timers[incident_id] = asyncio.create_task(self._escalation_timer(incident_id, severity))

        logger.info("paged %s for %s; escalation timer %.0fs started",
                    contact["name"], incident_id, ACK_TIMEOUT_SECONDS)
        return {
            "accepted": True, "paged": True, "contact": contact,
            "notification_transport": notice.get("transport"),
            "notification_sent": notice.get("sent"),
            "ack_timeout_seconds": ACK_TIMEOUT_SECONDS,
        }

    def _compose(self, brief, incident_id, severity, contact) -> str:
        try:
            return compose_page_text(brief)
        except Exception as exc:  # noqa: BLE001 - a page must still go out
            logger.warning("page composition via LLM failed (%s); using template", exc)
            return (f":rotating_light: Incident {incident_id} severity={severity}. "
                    f"Containment awaiting approval. On-call: {contact['handle']}. "
                    f"Ack: POST /ack?incident_id={incident_id}")

    async def _escalation_timer(self, incident_id: str, severity: str) -> None:
        try:
            await asyncio.sleep(ACK_TIMEOUT_SECONDS)
        except asyncio.CancelledError:
            return  # acked in time
        if incident_id in self._acked:
            return
        logger.warning("ESCALATION TIMEOUT for %s after %.0fs -- auto-approving",
                       incident_id, ACK_TIMEOUT_SECONDS)
        record_approval(
            self.store, incident_id,
            approved_by=APPROVAL_TIMEOUT, provenance=APPROVAL_TIMEOUT,
            note=f"no human ack within {ACK_TIMEOUT_SECONDS:.0f}s",
        )
        await self._nudge_containment(incident_id)

    async def acknowledge(self, incident_id: str, who: str) -> Dict[str, Any]:
        """Human ack path (called by the /ack endpoint)."""
        timer = self._timers.get(incident_id)
        if timer and not timer.done():
            timer.cancel()
        self._acked.add(incident_id)
        record_approval(
            self.store, incident_id, approved_by=who, provenance=APPROVAL_HUMAN,
            note="acknowledged by human before timeout",
        )
        logger.info("ACK received for %s by %s; approval recorded (human)", incident_id, who)
        await self._nudge_containment(incident_id)
        return {"acknowledged": True, "incident_id": incident_id, "by": who, "provenance": APPROVAL_HUMAN}

    async def _nudge_containment(self, incident_id: str) -> None:
        """Signal Containment to re-check approval (authorized timeout_escalation)."""
        if not check_authority(SELF_SYSTEM.value, SystemName.CONTAINMENT.value, ACTION_TIMEOUT_ESCALATION, incident_id=incident_id):
            return
        msg = IncidentMessage(
            incident_id=incident_id,
            source_system=SELF_SYSTEM,
            target_system=SystemName.CONTAINMENT,
            payload={"action": ACTION_TIMEOUT_ESCALATION, "note": "approval signal available"},
        )
        try:
            await send_incident_message(msg, peer_base_url=CONTAINMENT_URL)
            logger.info("nudged Containment to resume for %s", incident_id)
        except Exception:
            logger.exception("failed to nudge Containment for %s", incident_id)

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise NotImplementedError


def build_app() -> FastAPI:
    executor = OnCallExecutor()
    agent_card = build_agent_card(
        name="On-Call / Escalation",
        description="Pages the on-call responder for an assessed incident, runs an escalation "
        "timer, and emits a provenance-tagged approval signal on ack or timeout.",
        url=ON_CALL_URL,
        system=SELF_SYSTEM,
        skills=[incident_skill(
            skill_id="page_oncall",
            name="Page on-call",
            description="Notify the on-call contact and manage the approval/escalation timer.",
        )],
    )
    request_handler = DefaultRequestHandler(
        agent_executor=executor,
        task_store=InMemoryTaskStore(),
        agent_card=agent_card,
    )
    app = FastAPI(title="On-Call / Escalation — A2A")
    add_a2a_routes_to_fastapi(
        app,
        agent_card_routes=create_agent_card_routes(agent_card, card_url=AGENT_CARD_PATH),
        jsonrpc_routes=create_jsonrpc_routes(request_handler, rpc_url=RPC_PATH),
    )
    app.state.executor = executor

    @app.post("/ack", tags=["on-call"])
    async def ack(incident_id: str, who: str = "operator") -> dict:
        """Human acknowledgment callback. Stops the timer, records human approval."""
        return await executor.acknowledge(incident_id, who)

    @app.get("/health", tags=["on-call"])
    async def health() -> dict:
        return {"status": "ok", "system": SELF_SYSTEM.value,
                "ack_timeout_seconds": ACK_TIMEOUT_SECONDS,
                "active_timers": list(executor._timers.keys())}

    return app


if __name__ == "__main__":
    require_google_api_key()
    logger.info("agent card -> http://127.0.0.1:%s%s", PORT, AGENT_CARD_PATH)
    logger.info("ack endpoint -> POST http://127.0.0.1:%s/ack?incident_id=...", PORT)
    uvicorn.run(build_app(), host="127.0.0.1", port=PORT, log_level="warning")
