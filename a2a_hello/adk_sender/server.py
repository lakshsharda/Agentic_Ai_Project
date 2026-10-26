"""Phase 0 hello-world ADK agent, exposed over A2A.

Runs as its own process on port 9001. Two jobs:

  1. Serve an A2A agent card, so the ADK side is discoverable as a peer the
     same way the CrewAI side is (it echoes anything sent to it).
  2. Offer `POST /trigger`, which makes the ADK agent send a real A2A task to
     the CrewAI process on 9002 and returns the round trip.

    python -m a2a_hello.adk_sender.server
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

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
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from a2a_hello.adk_sender.agent import (
    SELF_SYSTEM,
    build_adk_agent,
    send_scaffold_incident,
)
from shared.a2a_support import (
    ADK_SENDER_URL,
    AGENT_CARD_PATH,
    RPC_PATH,
    build_agent_card,
    from_a2a_message,
    incident_skill,
    to_a2a_message,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [adk-sender] %(levelname)s %(message)s",
)
logger = logging.getLogger("adk_sender")

PORT = int(os.environ.get("ADK_SENDER_PORT", "9001"))


def google_model_available() -> bool:
    """Whether ADK can actually call a Gemini model.

    Without this the agent object still exists and its tool still works; only
    the LLM-decides-to-call-the-tool path is unavailable.
    """
    return bool(
        os.environ.get("GOOGLE_API_KEY")
        or os.environ.get("GEMINI_API_KEY")
        or os.environ.get("GOOGLE_GENAI_USE_VERTEXAI")
    )


# --------------------------------------------------------------------------
# A2A inbound side (so this process is a real peer, not just a client)
# --------------------------------------------------------------------------


class EchoExecutor(AgentExecutor):
    """Echoes any IncidentMessage back. Phase 0 scaffolding only."""

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        if context.message is None:
            raise ValueError("received an A2A request with no message")

        inbound = from_a2a_message(context.message)
        logger.info("inbound A2A task for incident %s", inbound.incident_id)

        reply = inbound.reply(
            {
                "received": True,
                "received_at": datetime.now(timezone.utc).isoformat(),
                "echoed_payload": inbound.payload,
                "note": "adk scaffold echo",
            },
            source_system=SELF_SYSTEM,
        )
        await event_queue.enqueue_event(to_a2a_message(reply, role=Role.ROLE_AGENT))

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise NotImplementedError("the Phase 0 scaffold agent has nothing cancellable")


# --------------------------------------------------------------------------
# Trigger endpoint
# --------------------------------------------------------------------------


class TriggerRequest(BaseModel):
    note: str = "phase-0 hello world"
    use_llm: Optional[bool] = None
    """None = use the LLM only if a credential exists. False = always call the
    tool directly. True = require the LLM path and fail loudly without it."""


async def _run_via_llm(note: str) -> Dict[str, Any]:
    """Drive the exchange by letting the ADK agent decide to call its tool."""
    from google.adk.runners import InMemoryRunner
    from google.genai import types as genai_types

    runner = InMemoryRunner(agent=build_adk_agent(), app_name="adk_scaffold")
    session = await runner.session_service.create_session(
        app_name="adk_scaffold", user_id="phase0"
    )

    prompt = f"Send a test incident over A2A with the note: {note}"
    transcript = []
    async for event in runner.run_async(
        user_id="phase0",
        session_id=session.id,
        new_message=genai_types.Content(
            role="user", parts=[genai_types.Part(text=prompt)]
        ),
    ):
        if event.content and event.content.parts:
            for part in event.content.parts:
                if part.text:
                    transcript.append({"author": event.author, "text": part.text})
                if part.function_response is not None:
                    transcript.append(
                        {
                            "author": event.author,
                            "tool_response": part.function_response.response,
                        }
                    )

    return {"driver": "adk_llm_runner", "transcript": transcript}


def build_app() -> FastAPI:
    agent_card = build_agent_card(
        name="Detection Scaffold (ADK)",
        description=(
            "Phase 0 hello-world ADK agent. Sends an IncidentMessage to the "
            "CrewAI scaffold over A2A, and echoes anything sent to it. No "
            "detection logic."
        ),
        url=ADK_SENDER_URL,
        system=SELF_SYSTEM,
        skills=[
            incident_skill(
                skill_id="echo_incident",
                name="Echo incident",
                description="Echo an IncidentMessage back to its sender.",
            )
        ],
    )

    request_handler = DefaultRequestHandler(
        agent_executor=EchoExecutor(),
        task_store=InMemoryTaskStore(),
        agent_card=agent_card,
    )

    app = FastAPI(
        title="Detection Scaffold (ADK) — A2A",
        description="Phase 0 scaffolding. Serves an A2A agent card and a /trigger endpoint.",
    )
    add_a2a_routes_to_fastapi(
        app,
        agent_card_routes=create_agent_card_routes(agent_card, card_url=AGENT_CARD_PATH),
        jsonrpc_routes=create_jsonrpc_routes(request_handler, rpc_url=RPC_PATH),
    )

    @app.post("/trigger", tags=["Phase 0 scaffolding"])
    async def trigger(body: TriggerRequest | None = None) -> Dict[str, Any]:
        """Make this ADK process send a real A2A task to the CrewAI process."""
        body = body or TriggerRequest()
        want_llm = google_model_available() if body.use_llm is None else body.use_llm

        if want_llm and not google_model_available():
            raise HTTPException(
                status_code=400,
                detail=(
                    "use_llm=true but no GOOGLE_API_KEY / GEMINI_API_KEY is set. "
                    "Omit use_llm to call the A2A tool directly."
                ),
            )

        try:
            if want_llm:
                llm_run = await _run_via_llm(body.note)
                # The tool already performed the real A2A call inside the run.
                return {"ok": True, **llm_run}

            result = await send_scaffold_incident(note=body.note)
            return {
                "ok": True,
                "driver": "direct_tool_call",
                "llm_skipped_reason": (
                    None
                    if body.use_llm is False
                    else "no Google model credential in environment"
                ),
                **result,
            }
        except Exception as exc:  # noqa: BLE001 - surface the failure to the caller
            logger.exception("A2A exchange failed")
            raise HTTPException(status_code=502, detail=f"{type(exc).__name__}: {exc}") from exc

    @app.get("/health", tags=["Phase 0 scaffolding"])
    async def health() -> Dict[str, Any]:
        return {
            "status": "ok",
            "system": SELF_SYSTEM.value,
            "google_model_available": google_model_available(),
        }

    return app


if __name__ == "__main__":
    logger.info("agent card -> http://127.0.0.1:%s%s", PORT, AGENT_CARD_PATH)
    logger.info("a2a rpc    -> http://127.0.0.1:%s%s", PORT, RPC_PATH)
    logger.info("trigger    -> POST http://127.0.0.1:%s/trigger", PORT)
    logger.info("google model credential present: %s", google_model_available())
    uvicorn.run(build_app(), host="127.0.0.1", port=PORT, log_level="info")
