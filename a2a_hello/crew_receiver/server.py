"""Phase 0 hello-world CrewAI agent, exposed over A2A.

Runs as its own process on port 9002. It serves an A2A agent card, accepts a
`message/send` task carrying an `IncidentMessage`, hands it to a real CrewAI
Crew, and replies with an `IncidentMessage` addressed back at the sender.

Scope note: the crew here does nothing resembling incident response. It
acknowledges receipt. Phase 0 is proving transport, not reasoning.

    python -m a2a_hello.crew_receiver.server
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

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

from shared.a2a_support import (
    AGENT_CARD_PATH,
    CREW_RECEIVER_URL,
    RPC_PATH,
    build_agent_card,
    from_a2a_message,
    incident_skill,
    to_a2a_message,
)
from shared.schemas import IncidentMessage, SystemName
from shared.store import IncidentStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [crew-receiver] %(levelname)s %(message)s",
)
logger = logging.getLogger("crew_receiver")

PORT = int(os.environ.get("CREW_RECEIVER_PORT", "9002"))
SELF_SYSTEM = SystemName.SCAFFOLD_CREW


# --------------------------------------------------------------------------
# The CrewAI side
# --------------------------------------------------------------------------


def build_crew(incident_id: str):
    """Construct a real CrewAI Agent/Task/Crew.

    Built fresh per request because the task description embeds the incident
    id. Returns the Crew without kicking it off -- see `run_crew`.
    """
    from crewai import Agent, Crew, Task

    acknowledger = Agent(
        role="A2A Acknowledger",
        goal=f"Confirm that incident {incident_id} was received over A2A.",
        backstory=(
            "A Phase 0 scaffolding agent. Its only job is to prove a CrewAI "
            "process can be reached over the A2A protocol."
        ),
        verbose=False,
        allow_delegation=False,
    )

    ack_task = Task(
        description=(
            f"Acknowledge receipt of incident {incident_id}. "
            "Reply with the single word ACKNOWLEDGED."
        ),
        expected_output="The single word ACKNOWLEDGED.",
        agent=acknowledger,
    )

    return Crew(agents=[acknowledger], tasks=[ack_task], verbose=False)


def crew_llm_available() -> bool:
    """Whether a kickoff can actually reach a model.

    CrewAI delegates to LiteLLM, so any one of these provider keys is enough.
    Without one, `kickoff()` fails on an auth error -- which says nothing
    about whether A2A works, so we skip it and say so.
    """
    return any(
        os.environ.get(key)
        for key in (
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "GEMINI_API_KEY",
            "GOOGLE_API_KEY",
        )
    )


def run_crew(incident_id: str) -> Dict[str, Any]:
    """Build the crew, and kick it off only if a model is reachable."""
    crew = build_crew(incident_id)
    constructed = {
        "crew_constructed": True,
        "agents": [a.role for a in crew.agents],
        "tasks": [t.description for t in crew.tasks],
    }

    if not crew_llm_available():
        logger.info("no LLM provider key set -- crew built but not kicked off")
        return {
            **constructed,
            "crew_kickoff": "skipped",
            "crew_kickoff_reason": "no LLM provider API key in environment",
            "ack": "ACKNOWLEDGED",
        }

    try:
        result = crew.kickoff()
        return {**constructed, "crew_kickoff": "ok", "ack": str(result).strip()}
    except Exception as exc:  # noqa: BLE001 - a model failure must not break A2A
        logger.warning("crew kickoff failed: %s", exc)
        return {
            **constructed,
            "crew_kickoff": "failed",
            "crew_kickoff_reason": str(exc)[:300],
            "ack": "ACKNOWLEDGED",
        }


# --------------------------------------------------------------------------
# A2A executor
# --------------------------------------------------------------------------


class CrewAckExecutor(AgentExecutor):
    """Unpacks the envelope, runs the crew, enqueues a single reply Message."""

    def __init__(self) -> None:
        self.store = IncidentStore()

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        if context.message is None:
            raise ValueError("received an A2A request with no message")

        inbound = from_a2a_message(context.message)
        logger.info(
            "received A2A task: incident_id=%s from=%s to=%s payload_keys=%s",
            inbound.incident_id,
            inbound.source_system,
            inbound.target_system,
            sorted(inbound.payload),
        )

        if inbound.target_system != SELF_SYSTEM.value:
            logger.warning(
                "message addressed to %s but this process is %s -- handling anyway "
                "(Phase 0 has no router)",
                inbound.target_system,
                SELF_SYSTEM.value,
            )

        crew_result = run_crew(inbound.incident_id)
        store_result = self._touch_store(inbound.incident_id)

        reply = inbound.reply(
            {
                "received": True,
                "received_at": datetime.now(timezone.utc).isoformat(),
                "echoed_payload": inbound.payload,
                "incident_store": store_result,
                **crew_result,
            },
            source_system=SELF_SYSTEM,
        )

        logger.info("replying to %s for incident %s", reply.target_system, reply.incident_id)
        await event_queue.enqueue_event(to_a2a_message(reply, role=Role.ROLE_AGENT))

    def _touch_store(self, incident_id: str) -> Dict[str, Any]:
        """Mark the incident as acknowledged. Best-effort.

        The store being down is a store problem; it must not make the A2A
        exchange look broken.
        """
        try:
            record = self.store.update_incident(
                incident_id,
                status="ack_received",
                raw_payload={"acked_by": SELF_SYSTEM.value},
            )
            if record is None:
                return {"ok": False, "reason": "no such incident row"}
            return {"ok": True, "status": record.status}
        except Exception as exc:  # noqa: BLE001
            logger.warning("incident store update failed: %s", exc)
            return {"ok": False, "reason": str(exc)[:200]}

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise NotImplementedError("the Phase 0 scaffold agent has nothing cancellable")


# --------------------------------------------------------------------------
# Wiring
# --------------------------------------------------------------------------


def build_app() -> FastAPI:
    agent_card = build_agent_card(
        name="Containment Scaffold (CrewAI)",
        description=(
            "Phase 0 hello-world CrewAI agent. Accepts an IncidentMessage over "
            "A2A and acknowledges it. No containment logic."
        ),
        url=CREW_RECEIVER_URL,
        system=SELF_SYSTEM,
        skills=[
            incident_skill(
                skill_id="ack_incident",
                name="Acknowledge incident",
                description="Confirm receipt of an IncidentMessage and echo its payload back.",
            )
        ],
    )

    request_handler = DefaultRequestHandler(
        agent_executor=CrewAckExecutor(),
        task_store=InMemoryTaskStore(),
        agent_card=agent_card,
    )

    app = FastAPI(
        title="Containment Scaffold (CrewAI) — A2A",
        description="Phase 0 scaffolding. Serves an A2A agent card and one skill.",
    )
    add_a2a_routes_to_fastapi(
        app,
        agent_card_routes=create_agent_card_routes(agent_card, card_url=AGENT_CARD_PATH),
        jsonrpc_routes=create_jsonrpc_routes(request_handler, rpc_url=RPC_PATH),
    )
    return app


if __name__ == "__main__":
    logger.info("agent card -> http://127.0.0.1:%s%s", PORT, AGENT_CARD_PATH)
    logger.info("a2a rpc    -> http://127.0.0.1:%s%s", PORT, RPC_PATH)
    uvicorn.run(build_app(), host="127.0.0.1", port=PORT, log_level="info")
