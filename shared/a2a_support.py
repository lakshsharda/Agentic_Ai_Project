"""Shared A2A plumbing: agent cards, envelope <-> wire conversion, client send.

Both the ADK side and the CrewAI side import this so the two independently
running processes cannot drift on how an ``IncidentMessage`` is packed into an
A2A message. It contains transport mechanics only -- no agent reasoning.

Pinned against a2a-sdk 1.2.x, where the protocol types are protobuf messages
and an ``IncidentMessage`` rides as JSON text in a single message Part.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any, Dict, List, Optional

from a2a.client import ClientConfig, create_client
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentSkill,
    Message,
    Part,
    Role,
    SendMessageRequest,
)
from a2a.utils.constants import (
    AGENT_CARD_WELL_KNOWN_PATH,
    DEFAULT_RPC_URL,
    PROTOCOL_VERSION_1_0,
    TransportProtocol,
)

from shared.schemas import IncidentMessage, SystemName
from shared.trace import record_trace

logger = logging.getLogger(__name__)

# Phase 0 scaffolding endpoints, kept so the hello-world exchange still runs.
ADK_SENDER_URL = "http://127.0.0.1:9001"
CREW_RECEIVER_URL = "http://127.0.0.1:9002"

# Real system endpoints. Static for now; a later phase will almost certainly
# replace this with service discovery once more than two systems are live.
DETECTION_URL = "http://127.0.0.1:9101"
THREAT_ASSESSMENT_URL = "http://127.0.0.1:9102"
CONTAINMENT_URL = "http://127.0.0.1:9103"
ON_CALL_URL = "http://127.0.0.1:9104"
FORENSICS_URL = "http://127.0.0.1:9105"
COMMS_URL = "http://127.0.0.1:9106"

# Where each system can be reached, keyed by SystemName value. Lets a sender
# resolve a peer's base URL from the target_system on an envelope.
SYSTEM_URLS = {
    SystemName.DETECTION.value: DETECTION_URL,
    SystemName.THREAT_ASSESSMENT.value: THREAT_ASSESSMENT_URL,
    SystemName.CONTAINMENT.value: CONTAINMENT_URL,
    SystemName.ON_CALL.value: ON_CALL_URL,
    SystemName.FORENSICS.value: FORENSICS_URL,
    SystemName.CUSTOMER_COMMS.value: COMMS_URL,
}


def url_for_system(system: "SystemName | str") -> str:
    """Base URL for a system, or raise if it has no endpoint yet.

    A KeyError here means a message is addressed at a system that is not stood
    up in this phase -- better a loud failure than a silent misroute.
    """
    key = system.value if isinstance(system, SystemName) else system
    try:
        return SYSTEM_URLS[key]
    except KeyError as exc:
        raise KeyError(
            f"no A2A endpoint registered for system {key!r}; "
            f"known systems: {sorted(SYSTEM_URLS)}"
        ) from exc

AGENT_CARD_PATH = AGENT_CARD_WELL_KNOWN_PATH
RPC_PATH = DEFAULT_RPC_URL


# --------------------------------------------------------------------------
# Agent cards
# --------------------------------------------------------------------------


def build_agent_card(
    *,
    name: str,
    description: str,
    url: str,
    system: SystemName,
    skills: Optional[List[AgentSkill]] = None,
    version: str = "0.1.0",
) -> AgentCard:
    """Build the public agent card this process serves at AGENT_CARD_PATH.

    Streaming is advertised as False: Phase 0 only needs a single
    request/response round trip, and non-streaming keeps the exchange easy to
    read in logs and in a raw curl.
    """
    card = AgentCard(
        name=name,
        description=description,
        version=version,
        capabilities=AgentCapabilities(streaming=False, push_notifications=False),
        default_input_modes=["application/json", "text/plain"],
        default_output_modes=["application/json", "text/plain"],
    )
    card.supported_interfaces.append(
        AgentInterface(
            url=url.rstrip("/") + RPC_PATH,
            protocol_binding=TransportProtocol.JSONRPC.value,
            protocol_version=PROTOCOL_VERSION_1_0,
        )
    )
    for skill in skills or []:
        card.skills.append(skill)
    # Carry the system identity on the card so a peer can check it is talking
    # to the system it meant to address.
    card.documentation_url = f"urn:crisis-coordination:system:{SystemName(system).value}"
    return card


def incident_skill(
    *, skill_id: str, name: str, description: str, tags: Optional[List[str]] = None
) -> AgentSkill:
    skill = AgentSkill(id=skill_id, name=name, description=description)
    skill.tags.append("crisis-coordination")
    for tag in tags or []:
        skill.tags.append(tag)
    skill.input_modes.append("application/json")
    skill.output_modes.append("application/json")
    return skill


# --------------------------------------------------------------------------
# Envelope <-> A2A message
# --------------------------------------------------------------------------


def to_a2a_message(msg: IncidentMessage, *, role: int = Role.ROLE_USER) -> Message:
    """Pack an IncidentMessage into an A2A Message as a single JSON text part."""
    a2a_msg = Message(message_id=uuid.uuid4().hex, role=role)
    a2a_msg.parts.append(Part(text=msg.to_wire(), media_type="application/json"))
    # context_id groups every message about one incident into one A2A context.
    a2a_msg.context_id = msg.incident_id
    return a2a_msg


_TRACE_PAYLOAD_KEYS = ("action", "event", "safe_to_lift", "reopened")


def _envelope_summary(action: Optional[str], payload: Dict[str, Any]) -> str:
    # On-Call reuses the wire action `timeout_escalation` as a generic "an approval signal is now
    # on the incident" nudge to Containment, including after a HUMAN ack. Say so, so the timeline
    # does not read as a timeout; who actually approved is the approval_recorded row.
    if action == "timeout_escalation":
        return "approval-signal nudge to Containment (wire action: timeout_escalation)"
    return f"{action or 'message'}" + (f" / {payload['event']}" if payload.get("event") else "")


def _trace_envelope(kind: str, msg: IncidentMessage) -> None:
    """Phase 5: record that an envelope crossed the wire. Observation only; the
    payload contributes just its action/event names, never its content."""
    payload = msg.payload or {}
    action = payload.get("action")
    reclassify = action == "reclassify"
    record_trace(
        incident_id=msg.incident_id, from_system=msg.source_system, to_system=msg.target_system,
        event_type=(f"reclassify_{kind}" if reclassify else f"a2a_{kind}"),
        summary=_envelope_summary(action, payload),
        detail={k: payload[k] for k in _TRACE_PAYLOAD_KEYS if k in payload},
    )


def from_a2a_message(a2a_msg: Message, *, trace_received: bool = False) -> IncidentMessage:
    """Extract and validate the IncidentMessage carried by an A2A Message.

    Raises ValueError if no part holds a parsable envelope -- better a loud
    failure at the boundary than a half-understood message reaching an agent.

    ``trace_received`` is set by each system's inbound handler (not by the
    sender parsing a reply) so the receipt shows up in the Phase 5 trace.
    """
    errors: List[str] = []
    for part in a2a_msg.parts:
        if not part.text:
            continue
        try:
            envelope = IncidentMessage.from_wire(part.text)
            if trace_received:
                _trace_envelope("received", envelope)
            return envelope
        except Exception as exc:  # noqa: BLE001 - we aggregate and re-raise below
            errors.append(str(exc))
    raise ValueError(
        f"no part of message {a2a_msg.message_id!r} contained a valid IncidentMessage; "
        f"attempts: {errors or ['no text parts present']}"
    )


def describe_stream_response(response: Any) -> Dict[str, Any]:
    """Summarise what came back, for logging and for the hello-world output."""
    which = response.WhichOneof("payload") if hasattr(response, "WhichOneof") else None
    if response.HasField("message"):
        return {"kind": "message", "message_id": response.message.message_id}
    if response.HasField("task"):
        return {
            "kind": "task",
            "task_id": response.task.id,
            "state": response.task.status.state,
        }
    return {"kind": which or "unknown"}


# --------------------------------------------------------------------------
# Outbound call
# --------------------------------------------------------------------------


async def send_incident_message(
    msg: IncidentMessage,
    *,
    peer_base_url: str,
    timeout: float = 30.0,
) -> IncidentMessage:
    """Send the envelope to a peer and return its reply, tracing the send (Phase 5).

    The trace is observation only; any failure of the send itself propagates
    exactly as before.
    """
    _trace_envelope("sent", msg)
    try:
        return await _send_incident_message(msg, peer_base_url=peer_base_url, timeout=timeout)
    except Exception as exc:
        record_trace(
            incident_id=msg.incident_id, from_system=msg.source_system, to_system=msg.target_system,
            event_type="a2a_failed", summary=f"send failed: {type(exc).__name__}",
            detail={"action": (msg.payload or {}).get("action")},
        )
        raise


async def _send_incident_message(
    msg: IncidentMessage,
    *,
    peer_base_url: str,
    timeout: float = 30.0,
) -> IncidentMessage:
    """Resolve the peer's agent card, send the envelope, return its reply.

    This is a real HTTP round trip: the card is fetched over the network, then
    the task goes out over A2A JSON-RPC to the URL the card advertises.
    """
    import httpx

    async with httpx.AsyncClient(timeout=timeout) as http_client:
        client = await create_client(
            peer_base_url,
            client_config=ClientConfig(streaming=False, httpx_client=http_client),
            relative_card_path=AGENT_CARD_PATH,
        )
        request = SendMessageRequest(message=to_a2a_message(msg))

        async for response in client.send_message(request):
            logger.info("a2a response: %s", describe_stream_response(response))
            if response.HasField("message"):
                return from_a2a_message(response.message)
            if response.HasField("task"):
                # The receiver returned a Task instead of an immediate Message.
                # Phase 0's receiver replies with a Message, so this is a
                # protocol surprise worth surfacing rather than silently
                # polling for completion.
                raise RuntimeError(
                    "peer returned a Task; Phase 0 expects an immediate Message reply. "
                    f"task_id={response.task.id} state={response.task.status.state}"
                )

    raise RuntimeError(f"peer at {peer_base_url} closed the stream without replying")


def pretty(obj: Any) -> str:
    """JSON dump for human-readable console output."""
    if hasattr(obj, "model_dump"):
        obj = json.loads(obj.to_wire()) if hasattr(obj, "to_wire") else obj.model_dump()
    return json.dumps(obj, indent=2, default=str)
