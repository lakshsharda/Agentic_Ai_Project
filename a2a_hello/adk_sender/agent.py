"""The ADK side of the Phase 0 hello-world exchange.

Defines a real ADK `LlmAgent` whose single tool performs an outbound A2A call
to the CrewAI process. The tool function is also callable directly, which is
how the exchange is driven when no Google model credential is present -- the
network call is identical either way, only the thing deciding to make it
differs.

Scope note: the agent has no detection logic. It sends a canned payload.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool

from shared.a2a_support import CREW_RECEIVER_URL, send_incident_message
from shared.schemas import IncidentMessage, SystemName, new_incident_id
from shared.store import IncidentStore

logger = logging.getLogger("adk_sender.agent")

SELF_SYSTEM = SystemName.SCAFFOLD_ADK
TARGET_SYSTEM = SystemName.SCAFFOLD_CREW

# Model is only consulted when a Google credential exists; see server.py.
DEFAULT_MODEL = "gemini-2.0-flash"


def _record_incident(message: IncidentMessage) -> Dict[str, Any]:
    """Create the incident row before sending. Best-effort.

    The row is created here so the receiver has something to update, which is
    what ties the A2A exchange and the shared store together.
    """
    try:
        store = IncidentStore()
        record = store.create_incident(
            message.incident_id,
            status="detected",
            raw_payload={"origin": SELF_SYSTEM.value, **message.payload},
        )
        return {"ok": True, "status": record.status}
    except Exception as exc:  # noqa: BLE001 - store trouble must not block A2A
        logger.warning("could not create incident row: %s", exc)
        return {"ok": False, "reason": str(exc)[:200]}


async def send_scaffold_incident(note: str = "phase-0 hello world") -> Dict[str, Any]:
    """Send a scaffolding IncidentMessage to the CrewAI agent over A2A.

    Args:
        note: Free-text note carried in the message payload.

    Returns:
        A dict describing the round trip: what was sent, and the reply.
    """
    message = IncidentMessage(
        incident_id=new_incident_id(),
        source_system=SELF_SYSTEM,
        target_system=TARGET_SYSTEM,
        payload={
            "note": note,
            "sent_at": datetime.now(timezone.utc).isoformat(),
            "scaffold": True,
        },
    )

    store_result = _record_incident(message)
    logger.info("sending incident %s to %s", message.incident_id, CREW_RECEIVER_URL)

    reply = await send_incident_message(message, peer_base_url=CREW_RECEIVER_URL)

    logger.info("got reply from %s for %s", reply.source_system, reply.incident_id)
    return {
        "sent": message.model_dump(mode="json"),
        "incident_store_create": store_result,
        "reply": reply.model_dump(mode="json"),
    }


send_incident_tool = FunctionTool(func=send_scaffold_incident)


def build_adk_agent(model: Optional[str] = None) -> LlmAgent:
    """The ADK agent. Constructing it requires no credential; running it does."""
    return LlmAgent(
        name="detection_scaffold",
        model=model or DEFAULT_MODEL,
        description=(
            "Phase 0 hello-world ADK agent. Sends an IncidentMessage to the "
            "CrewAI scaffold agent over A2A."
        ),
        instruction=(
            "You are a Phase 0 scaffolding agent. When asked to send a test "
            "incident, call the send_scaffold_incident tool exactly once and "
            "report the reply you receive verbatim. Do not invent incidents."
        ),
        tools=[send_incident_tool],
    )
