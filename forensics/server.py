"""Forensics & Recovery -- process entry point (CrewAI, port 9105).

On an inbound `collect_evidence` from Threat Assessment:
  1. snapshot the evidence and write the `evidence_preserved` signal (the gate
     Containment waits on), then nudge Containment over A2A,
  2. reply immediately, and continue the heavy work in the background:
  3. run long-form Root Cause Analysis (continuation-aware LLM path),
  4. if the analysis warrants it, send a `reclassify` A2A task BACK upstream to
     Threat Assessment,
  5. produce a recovery plan and send the lift-containment signal to Containment.

    python -m forensics.server
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

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

from forensics.evidence import collect
from forensics.rca import analyze
from forensics.recovery import plan_recovery
from shared.a2a_support import (
    AGENT_CARD_PATH,
    CONTAINMENT_URL,
    FORENSICS_URL,
    RPC_PATH,
    THREAT_ASSESSMENT_URL,
    build_agent_card,
    from_a2a_message,
    incident_skill,
    send_incident_message,
    to_a2a_message,
)
from shared.guardrail import (
    ACTION_COLLECT_EVIDENCE,
    ACTION_EVIDENCE_PRESERVED,
    ACTION_RECLASSIFY,
    ACTION_RECOVERY_PLAN,
    check_authority,
    record_evidence_preserved,
)
from shared.comms_notify import notify_comms
from shared.llm import require_google_api_key
from shared.schemas import IncidentMessage, SystemName
from shared.reasoning import record_reasoning, start_call
from shared.store import IncidentStore

logging.basicConfig(level=logging.INFO, format="%(asctime)s [forensics] %(levelname)s %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("LiteLLM").setLevel(logging.WARNING)
logger = logging.getLogger("forensics")

PORT = int(os.environ.get("FORENSICS_PORT", "9105"))
SELF_SYSTEM = SystemName.FORENSICS
LIFT_RETRIES = int(os.environ.get("FORENSICS_LIFT_RETRIES", "12"))
LIFT_RETRY_SECONDS = float(os.environ.get("FORENSICS_LIFT_RETRY_SECONDS", "10"))


class ForensicsExecutor(AgentExecutor):
    def __init__(self) -> None:
        self.store = IncidentStore()

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        if context.message is None:
            raise ValueError("received an A2A request with no message")
        inbound = from_a2a_message(context.message, trace_received=True)
        action = inbound.payload.get("action", ACTION_COLLECT_EVIDENCE)

        if not check_authority(inbound.source_system, SELF_SYSTEM.value, action, incident_id=inbound.incident_id):
            reply = inbound.reply(
                {"accepted": False, "reason": f"authority denied for {action!r} from {inbound.source_system}"},
                source_system=SELF_SYSTEM,
            )
            await event_queue.enqueue_event(to_a2a_message(reply, role=Role.ROLE_AGENT))
            return

        result = await self._on_collect_evidence(inbound)
        reply = inbound.reply(result, source_system=SELF_SYSTEM)
        await event_queue.enqueue_event(to_a2a_message(reply, role=Role.ROLE_AGENT))

    async def _on_collect_evidence(self, inbound: IncidentMessage) -> Dict[str, Any]:
        incident_id = inbound.incident_id
        record = self.store.get_incident(incident_id)
        if record is None:
            logger.warning("collect_evidence for unknown incident %s", incident_id)
            return {"accepted": False, "reason": "unknown incident"}

        # 1. Evidence Collection (fast, synchronous) + the evidence_preserved signal.
        snapshot = collect(record)
        record_evidence_preserved(
            self.store, incident_id, by=SELF_SYSTEM.value,
            preserve_worthy=snapshot["preserve_worthy"], snapshot_ref=snapshot.get("snapshot_path"),
        )
        # Nudge Containment so its evidence gate re-checks without waiting for a poll.
        await self._nudge_containment_evidence(incident_id)

        # 2. Heavy work (RCA, reclassify, recovery) runs in the background so the
        #    dispatch fan-out does not block on it.
        asyncio.create_task(self._analyze_and_recover(incident_id))

        return {
            "accepted": True,
            "evidence_preserved": True,
            "preserve_worthy": snapshot["preserve_worthy"],
            "snapshot": snapshot.get("snapshot_path"),
        }

    async def _nudge_containment_evidence(self, incident_id: str) -> None:
        if not check_authority(SELF_SYSTEM.value, SystemName.CONTAINMENT.value, ACTION_EVIDENCE_PRESERVED, incident_id=incident_id):
            return
        msg = IncidentMessage(
            incident_id=incident_id, source_system=SELF_SYSTEM, target_system=SystemName.CONTAINMENT,
            payload={"action": ACTION_EVIDENCE_PRESERVED, "note": "evidence snapshot captured"},
        )
        try:
            await send_incident_message(msg, peer_base_url=CONTAINMENT_URL)
        except Exception:
            logger.exception("evidence-preserved nudge to Containment failed for %s", incident_id)

    async def _analyze_and_recover(self, incident_id: str) -> None:
        from forensics.evidence import load_snapshot

        record = self.store.get_incident(incident_id)
        snapshot = load_snapshot(incident_id)
        if record is None or not snapshot:
            logger.warning("cannot analyze %s: missing record/snapshot", incident_id)
            return

        # 3. Root Cause Analysis (long-form, continuation-aware).
        call = start_call(system=SELF_SYSTEM, agent_name="Root Cause Analysis Agent", incident_id=incident_id)
        rca = await asyncio.to_thread(analyze, record, snapshot)
        self.store.update_incident(incident_id, raw_payload={"forensics": {
            "root_cause_narrative": rca.narrative,
            "generation": rca.generation,
            "reclassification_suggested": rca.should_reclassify,
            "at": datetime.now(timezone.utc).isoformat(),
        }})
        logger.info("RCA stored for %s (continued=%s, rounds=%s)",
                    incident_id, rca.generation.get("continued"), rca.generation.get("rounds"))
        call.resolve(
            text=(rca.narrative.strip() + (
                f"\n\nRe-classification suggested: {rca.suggested_severity} - {rca.reclassify_reason}"
                if rca.should_reclassify else "\n\nRe-classification: not suggested.")),
            narration=("Forensics received the dispatch, preserved the evidence and wrote the root-cause analysis; "
                       + (f"it suggests re-classifying to {rca.suggested_severity}." if rca.should_reclassify
                          else "it does not suggest changing the severity.")))

        # 4. Feedback loop: re-classify upstream if warranted.
        if rca.should_reclassify:
            await self._send_reclassification(incident_id, rca)

        # 5. Recovery planning + lift signal (after any reclassification resolved).
        await self._recover(incident_id, rca)

    async def _send_reclassification(self, incident_id: str, rca) -> None:
        if not check_authority(SELF_SYSTEM.value, SystemName.THREAT_ASSESSMENT.value, ACTION_RECLASSIFY, incident_id=incident_id):
            return
        msg = IncidentMessage(
            incident_id=incident_id, source_system=SELF_SYSTEM, target_system=SystemName.THREAT_ASSESSMENT,
            payload={
                "action": ACTION_RECLASSIFY,
                "suggested_severity": rca.suggested_severity,
                "suggested_type": rca.suggested_type,
                "reason": rca.reclassify_reason,
                "root_cause_narrative": rca.narrative,
            },
        )
        logger.warning("RECLASSIFY -> Threat Assessment for %s: suggest %s (%s)",
                       incident_id, rca.suggested_severity, rca.reclassify_reason)
        try:
            reply = await send_incident_message(msg, peer_base_url=THREAT_ASSESSMENT_URL)
            logger.info("reclassification handled for %s: %s", incident_id, reply.payload.get("reclassification"))
        except Exception:
            logger.exception("reclassification send failed for %s", incident_id)

    async def _recover(self, incident_id: str, rca) -> None:
        record = self.store.get_incident(incident_id)
        brief = (
            f"Incident {incident_id}\nFinal severity: {record.severity if record else '?'}\n"
            f"Root-cause findings:\n{rca.narrative[:1500]}\n"
        )
        call = start_call(system=SELF_SYSTEM, agent_name="Recovery Planning Agent", incident_id=incident_id)
        plan = await asyncio.to_thread(plan_recovery, brief)
        call.resolve(text=plan.plan_text,
                     narration="Forensics drafted a recovery plan from its root-cause findings"
                                   + (" and judged it safe to lift containment." if plan.safe_to_lift
                                      else "; containment stays in place for now."))
        self.store.update_incident(incident_id, raw_payload={"recovery_plan": {
            "plan": plan.plan_text, "safe_to_lift": plan.safe_to_lift,
            "at": datetime.now(timezone.utc).isoformat(),
        }})
        if not check_authority(SELF_SYSTEM.value, SystemName.CONTAINMENT.value, ACTION_RECOVERY_PLAN, incident_id=incident_id):
            return
        msg = IncidentMessage(
            incident_id=incident_id, source_system=SELF_SYSTEM, target_system=SystemName.CONTAINMENT,
            payload={"action": ACTION_RECOVERY_PLAN, "safe_to_lift": plan.safe_to_lift,
                     "plan": plan.plan_text},
        )
        logger.info("recovery -> Containment for %s: safe_to_lift=%s", incident_id, plan.safe_to_lift)
        # Containment refuses to lift something it has not executed yet (it is
        # still held on approval/evidence). Retry that specific answer for a
        # bounded time instead of silently never resolving the incident.
        reply = None
        for attempt in range(1 + LIFT_RETRIES):
            try:
                reply = await send_incident_message(msg, peer_base_url=CONTAINMENT_URL)
            except Exception:
                logger.exception("recovery-plan send to Containment failed for %s", incident_id)
                return
            not_yet = "not executed" in str(reply.payload.get("reason", ""))
            if reply.payload.get("lifted") or not plan.safe_to_lift or not not_yet:
                break
            logger.info("recovery for %s: containment not executed yet; retrying lift in %.0fs (%d/%d)",
                        incident_id, LIFT_RETRY_SECONDS, attempt + 1, LIFT_RETRIES)
            await asyncio.sleep(LIFT_RETRY_SECONDS)

        # Phase 4: when LIFT: YES and Containment confirms the blocks are
        # actually lifted, tell Customer Comms the incident is resolved.
        if plan.safe_to_lift and reply.payload.get("lifted"):
            await notify_comms(SELF_SYSTEM, incident_id, "resolved")

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise NotImplementedError


def build_app() -> FastAPI:
    agent_card = build_agent_card(
        name="Forensics & Recovery",
        description="Preserves incident evidence, performs root-cause analysis, feeds "
        "re-classifications back to Threat Assessment, and plans recovery.",
        url=FORENSICS_URL,
        system=SELF_SYSTEM,
        skills=[incident_skill(
            skill_id="forensic_analysis",
            name="Forensic analysis & recovery",
            description="Snapshot evidence, analyze root cause, re-classify, and plan recovery.",
        )],
    )
    request_handler = DefaultRequestHandler(
        agent_executor=ForensicsExecutor(),
        task_store=InMemoryTaskStore(),
        agent_card=agent_card,
    )
    app = FastAPI(title="Forensics & Recovery — A2A")
    add_a2a_routes_to_fastapi(
        app,
        agent_card_routes=create_agent_card_routes(agent_card, card_url=AGENT_CARD_PATH),
        jsonrpc_routes=create_jsonrpc_routes(request_handler, rpc_url=RPC_PATH),
    )

    @app.get("/health", tags=["forensics"])
    async def health() -> dict:
        return {"status": "ok", "system": SELF_SYSTEM.value}

    return app


if __name__ == "__main__":
    require_google_api_key()
    logger.info("agent card -> http://127.0.0.1:%s%s", PORT, AGENT_CARD_PATH)
    uvicorn.run(build_app(), host="127.0.0.1", port=PORT, log_level="warning")
