"""Customer Communications -- process entry point (CrewAI, port 9106).

The sixth and last system. It only RECEIVES: inbound A2A ``notify_status`` from
Containment (``contained``), Threat Assessment (``reclassified``) and Forensics
(``resolved``). It makes no outbound A2A calls; it records its state (drafts,
sign-offs, publishes) in the incident store.

For each event it drafts a customer message (Impact Assessment -> Message
Drafting -> deterministic validator) and parks it PENDING_SIGNOFF. Nothing is
ever published without a recorded human sign-off, every time: there is no
severity threshold, no bypass and no timeout auto-approval here.

Human interface:
    GET  /drafts            pending drafts (``?status=all`` for everything)
    POST /signoff           {incident_id, draft_id, decision, approver, edited_text?}

    python -m customer_comms.server
"""

from __future__ import annotations

import asyncio
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
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from customer_comms.agents import assess_impact, draft_message
from customer_comms.pipeline import EVENTS, SENDER_FOR_EVENT, build_draft
from customer_comms.publisher import publish_draft
from shared.a2a_support import (
    AGENT_CARD_PATH,
    COMMS_URL,
    RPC_PATH,
    build_agent_card,
    from_a2a_message,
    incident_skill,
    to_a2a_message,
)
from shared.comms_validation import validate_customer_text
from shared.guardrail import ACTION_NOTIFY_STATUS, check_authority, is_human_identity
from shared.llm import require_google_api_key
from shared.schemas import SystemName
from shared.store import DraftStore, IncidentStore
from shared.trace import record_trace
from shared.store.drafts import (
    STATUS_APPROVED,
    STATUS_PENDING,
    STATUS_PUBLISHED,
    STATUS_REJECTED,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [customer-comms] %(levelname)s %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("LiteLLM").setLevel(logging.WARNING)
logger = logging.getLogger("customer_comms")

PORT = int(os.environ.get("COMMS_PORT", "9106"))
SELF_SYSTEM = SystemName.CUSTOMER_COMMS

# Events that are announced once per incident; `reclassified` may repeat.
_ONCE_PER_INCIDENT = {"contained", "resolved"}


class CommsExecutor(AgentExecutor):
    def __init__(self, store: IncidentStore, drafts: DraftStore) -> None:
        self.store = store
        self.drafts = drafts
        # One lock per incident so drafts are created (and supersede each other)
        # in arrival order even though generation runs in the background.
        self._locks: Dict[str, asyncio.Lock] = {}
        self._background: set = set()

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        if context.message is None:
            raise ValueError("received an A2A request with no message")
        inbound = from_a2a_message(context.message, trace_received=True)
        action = inbound.payload.get("action", ACTION_NOTIFY_STATUS)
        event = inbound.payload.get("event")

        def refuse(reason: str) -> Dict[str, Any]:
            logger.warning("refusing %s/%s from %s for %s: %s", action, event, inbound.source_system,
                           inbound.incident_id, reason)
            return {"accepted": False, "reason": reason}

        if not check_authority(inbound.source_system, SELF_SYSTEM.value, action, incident_id=inbound.incident_id):
            result = refuse(f"authority denied for action {action!r} from {inbound.source_system}")
        elif event not in EVENTS:
            result = refuse(f"unknown event {event!r}")
        elif SENDER_FOR_EVENT[event] != str(inbound.source_system):
            result = refuse(f"{inbound.source_system} may not report event {event!r}")
        elif self.store.get_incident(inbound.incident_id) is None:
            result = refuse("unknown incident")
        else:
            task = asyncio.create_task(self._process(inbound.incident_id, event))
            self._background.add(task)
            task.add_done_callback(self._background.discard)
            result = {"accepted": True, "queued": True, "event": event}

        reply = inbound.reply(result, source_system=SELF_SYSTEM)
        await event_queue.enqueue_event(to_a2a_message(reply, role=Role.ROLE_AGENT))

    async def _process(self, incident_id: str, event: str) -> None:
        lock = self._locks.setdefault(incident_id, asyncio.Lock())
        async with lock:
            if event in _ONCE_PER_INCIDENT:
                live = [d for d in self.drafts.list(incident_id=incident_id, status=None)
                        if d.event_type == event and d.status in (STATUS_PENDING, STATUS_APPROVED, STATUS_PUBLISHED)]
                if live:
                    logger.info("event %s already drafted for %s (%s); ignoring duplicate", event,
                                incident_id, live[-1].draft_id)
                    return
            try:
                await asyncio.to_thread(
                    build_draft, self.store, self.drafts, incident_id, event,
                    assessor=assess_impact, drafter=draft_message,
                )
            except Exception:
                logger.exception("draft creation failed for %s event=%s", incident_id, event)

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise NotImplementedError


class SignoffRequest(BaseModel):
    incident_id: str
    draft_id: str
    decision: str            # "approve" | "reject"
    approver: str
    edited_text: Optional[str] = None
    reason: Optional[str] = None


def build_app() -> FastAPI:
    store = IncidentStore()
    drafts = DraftStore()
    executor = CommsExecutor(store, drafts)

    agent_card = build_agent_card(
        name="Customer Communications",
        description="Drafts customer-facing status updates for incident events and publishes them "
        "only after a recorded human sign-off. Receive-only: it sends no A2A calls.",
        url=COMMS_URL,
        system=SELF_SYSTEM,
        skills=[incident_skill(
            skill_id="customer_comms",
            name="Customer communications",
            description="Draft, validate, and (after human sign-off) publish customer status updates.",
        )],
    )
    request_handler = DefaultRequestHandler(
        agent_executor=executor, task_store=InMemoryTaskStore(), agent_card=agent_card,
    )
    app = FastAPI(title="Customer Communications — A2A")
    add_a2a_routes_to_fastapi(
        app,
        agent_card_routes=create_agent_card_routes(agent_card, card_url=AGENT_CARD_PATH),
        jsonrpc_routes=create_jsonrpc_routes(request_handler, rpc_url=RPC_PATH),
    )

    @app.get("/health", tags=["customer-comms"])
    async def health() -> dict:
        pending = drafts.list(status=STATUS_PENDING)
        return {"status": "ok", "system": SELF_SYSTEM.value, "pending_drafts": len(pending),
                "slack_configured": bool(os.environ.get("COMMS_SLACK_WEBHOOK_URL"))}

    @app.get("/drafts", tags=["customer-comms"])
    async def list_drafts(incident_id: Optional[str] = None, status: Optional[str] = None) -> dict:
        """Pending sign-off queue by default; ``status=all`` for every draft."""
        wanted = None if status == "all" else (status or STATUS_PENDING)
        items = await asyncio.to_thread(drafts.list, incident_id=incident_id, status=wanted)
        return {"count": len(items), "drafts": [d.to_dict() for d in items]}

    @app.post("/signoff", tags=["customer-comms"])
    async def signoff(req: SignoffRequest) -> JSONResponse:
        return await asyncio.to_thread(_signoff, store, drafts, req)

    return app


def _signoff(store: IncidentStore, drafts: DraftStore, req: SignoffRequest) -> JSONResponse:
    def out(code: int, **body) -> JSONResponse:
        return JSONResponse(status_code=code, content=body)

    decision = req.decision.strip().lower()
    if decision not in ("approve", "reject"):
        return out(400, ok=False, reason="decision must be 'approve' or 'reject'")

    draft = drafts.get(req.draft_id)
    if draft is None or draft.incident_id != req.incident_id:
        return out(404, ok=False, reason="no such draft for that incident")
    if draft.status != STATUS_PENDING:
        return out(409, ok=False, reason=f"draft is {draft.status}, not PENDING_SIGNOFF",
                   draft=draft.to_dict())

    # Sign-off is a person's act. A system value (timeout_escalation, ...) is
    # refused here and, independently, by the publish gate.
    if not is_human_identity(req.approver):
        logger.warning("sign-off for %s refused: approver %r is not a human identity", req.draft_id, req.approver)
        record_trace(
            incident_id=req.incident_id, from_system=SELF_SYSTEM, event_type="signoff_refused", decision="blocked",
            summary=f"sign-off refused: approver {req.approver!r} is not a human identity",
            detail={"draft_id": req.draft_id, "attempted_decision": decision},
        )
        return out(403, ok=False, reason=f"approver {req.approver!r} is not a human identity",
                   draft=draft.to_dict())

    if decision == "reject":
        updated = drafts.decide(req.draft_id, status=STATUS_REJECTED, approved_by=None,
                                rejection_reason=f"rejected by {req.approver}: {req.reason or 'no reason given'}")
        if updated is None:
            return out(409, ok=False, reason="draft changed before the decision was recorded")
        store.append_history(req.incident_id, {
            "event": "comms_signoff", "by": req.approver, "draft_id": req.draft_id, "decision": "reject"})
        logger.info("draft %s REJECTED by %s", req.draft_id, req.approver)
        record_trace(
            incident_id=req.incident_id, from_system=SELF_SYSTEM, event_type="signoff_recorded", decision="human",
            summary=f"draft {req.draft_id} rejected by {req.approver.strip()}",
            detail={"draft_id": req.draft_id, "decision": "reject"},
        )
        return out(200, ok=True, decision="reject", draft=updated.to_dict(), published=False)

    # approve, optionally with an edit that must pass the same validator.
    incident = store.get_incident(req.incident_id)
    payload = incident.raw_payload if incident else {}
    final_text = req.edited_text if req.edited_text is not None else draft.draft_text
    check = validate_customer_text(final_text, payload)
    if not check.ok:
        which = "edit" if req.edited_text is not None else "draft"
        logger.warning("sign-off for %s refused: %s failed validation: %s", req.draft_id, which, check.reason)
        record_trace(
            incident_id=req.incident_id, from_system=SELF_SYSTEM, event_type="signoff_refused", decision="blocked",
            summary=f"sign-off refused: the {which} failed customer-text validation ({len(check.violations)} violation(s))",
            detail={"draft_id": req.draft_id, "edited": req.edited_text is not None},
        )
        return out(422, ok=False, reason=f"{which} failed validation: {check.reason}",
                   violations=check.violations, draft=draft.to_dict())

    updated = drafts.decide(req.draft_id, status=STATUS_APPROVED, approved_by=req.approver.strip(),
                            edited_text=req.edited_text)
    if updated is None:
        return out(409, ok=False, reason="draft changed (e.g. superseded) before approval was recorded")
    store.append_history(req.incident_id, {
        "event": "comms_signoff", "by": req.approver.strip(), "draft_id": req.draft_id,
        "decision": "approve", "edited": req.edited_text is not None})
    logger.info("draft %s APPROVED by %s (edited=%s)", req.draft_id, req.approver, req.edited_text is not None)
    record_trace(
        incident_id=req.incident_id, from_system=SELF_SYSTEM, event_type="signoff_recorded", decision="human",
        summary=f"draft {req.draft_id} approved by {req.approver.strip()}"
                + (" (with a human edit)" if req.edited_text is not None else ""),
        detail={"draft_id": req.draft_id, "decision": "approve", "edited": req.edited_text is not None},
    )

    result = publish_draft(req.draft_id, drafts=drafts, store=store)
    final = drafts.get(req.draft_id)
    return out(200, ok=True, decision="approve", published=result["published"],
               publish=result, draft=final.to_dict() if final else None)


if __name__ == "__main__":
    require_google_api_key()
    logger.info("agent card -> http://127.0.0.1:%s%s", PORT, AGENT_CARD_PATH)
    logger.info("sign-off   -> GET /drafts , POST /signoff on :%s", PORT)
    uvicorn.run(build_app(), host="127.0.0.1", port=PORT, log_level="warning")
