"""Detection & Monitoring -- process entry point (ADK, port 9101).

Three responsibilities:

  1. Serve Detection's own A2A agent card, so later systems (e.g. Forensics'
     feedback loop) can address it. Nothing calls it inbound in this phase; the
     card is still real and complete.
  2. Run the ingestion -> window -> noise-filter -> handoff pipeline on a poll
     loop against the access log.
  3. On an escalated verdict, create the DETECTED incident and send it to
     Threat Assessment over A2A.

    python -m detection.server
    python -m detection.server --once      # assess one window and exit (tests)
    python -m detection.server --replay     # read the whole log, not just new lines
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import uuid
from pathlib import Path
from typing import Optional

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
from google.adk.runners import InMemoryRunner
from google.genai import types as genai_types

from detection.agents import (
    VERDICT_STATE_KEY,
    WINDOW_STATS_STATE_KEY,
    NoiseVerdict,
    build_noise_filter_agent,
    hand_off,
)
from detection.log_reader import AccessLogReader
from detection.windowing import SignalWindow
from shared.a2a_support import (
    AGENT_CARD_PATH,
    DETECTION_URL,
    RPC_PATH,
    build_agent_card,
    from_a2a_message,
    incident_skill,
    to_a2a_message,
)
from shared.llm import require_google_api_key, run_with_rate_limit_retry
from shared.schemas import SystemName
from shared.store import IncidentStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [detection] %(levelname)s %(message)s",
)
logging.getLogger("google_genai").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger("detection")

PORT = int(os.environ.get("DETECTION_PORT", "9101"))
SELF_SYSTEM = SystemName.DETECTION

LOG_PATH = Path(
    os.environ.get(
        "TARGET_APP_LOG_DIR",
        Path(__file__).resolve().parents[1] / "target_app" / "logs",
    )
) / "access.log"

POLL_INTERVAL_S = float(os.environ.get("DETECTION_POLL_INTERVAL", "2.0"))
WINDOW_SECONDS = float(os.environ.get("DETECTION_WINDOW_SECONDS", "30.0"))
# After escalating, wait this long before escalating again, so one ongoing
# attack becomes one incident rather than one per poll.
ESCALATION_COOLDOWN_S = float(os.environ.get("DETECTION_COOLDOWN", "20.0"))


# --------------------------------------------------------------------------
# The reasoning pipeline
# --------------------------------------------------------------------------


class DetectionPipeline:
    """Drives Ingestion -> Window -> Noise Filter -> Handoff."""

    def __init__(self, *, from_end: bool = True) -> None:
        self.reader = AccessLogReader(LOG_PATH, from_end=from_end)
        self.window = SignalWindow(window_seconds=WINDOW_SECONDS)
        self.store = IncidentStore()
        self.noise_filter = build_noise_filter_agent()
        self._runner = InMemoryRunner(agent=self.noise_filter, app_name="detection")
        self._last_escalation_at = 0.0

    async def assess_once(self, *, force: bool = False) -> Optional[NoiseVerdict]:
        """Ingest any new lines and run the noise filter over the window.

        Returns the verdict, or None when there is nothing worth an LLM call.

        The noise filter runs only when new signals actually arrived this cycle
        (or force=True). The Gemini free tier allows very few requests per
        minute, so re-reasoning over an unchanged window every poll would both
        waste quota and tell us nothing new. A quiet poll costs zero LLM calls.
        """
        import time

        new_signals = self.reader.read_new()
        if new_signals:
            self.window.add_all(new_signals)
            logger.info(
                "ingested %d new signal(s); window now holds %d",
                len(new_signals),
                len(self.window),
            )

        if len(self.window) == 0:
            return None

        if not new_signals and not force:
            # Nothing changed -- don't spend an LLM call.
            return None

        # Still inside the post-escalation cooldown: an attack we already
        # handed off is ongoing. Skip the LLM entirely until it expires.
        since = time.time() - self._last_escalation_at
        if self._last_escalation_at and since < ESCALATION_COOLDOWN_S and not force:
            logger.debug("in escalation cooldown (%.0fs/%.0fs); skipping filter", since, ESCALATION_COOLDOWN_S)
            return None

        stats = self.window.aggregate()
        verdict = await self._run_noise_filter(stats)
        logger.info(
            "noise filter verdict: escalate=%s pattern=%s confidence=%.2f -- %s",
            verdict.escalate,
            verdict.pattern_type,
            verdict.confidence,
            verdict.reasoning,
        )

        if verdict.escalate:
            await self._maybe_hand_off(verdict, stats)
        return verdict

    async def _run_noise_filter(self, stats: dict) -> NoiseVerdict:
        session = await self._runner.session_service.create_session(
            app_name="detection",
            user_id="detection",
            state={WINDOW_STATS_STATE_KEY: stats},
        )

        async def _invoke():
            async for _ in self._runner.run_async(
                user_id="detection",
                session_id=session.id,
                new_message=genai_types.Content(
                    role="user",
                    parts=[genai_types.Part(text="Assess the current traffic window.")],
                ),
            ):
                pass

        await run_with_rate_limit_retry(_invoke, label="noise filter")

        session = await self._runner.session_service.get_session(
            app_name="detection", user_id="detection", session_id=session.id
        )
        raw = session.state.get(VERDICT_STATE_KEY)
        if raw is None:
            # The model returned nothing parseable. Treat as "do not escalate"
            # rather than crashing the loop -- but say so loudly.
            logger.error("noise filter produced no verdict; defaulting to no-escalate")
            return NoiseVerdict(
                escalate=False,
                pattern_type="unknown",
                confidence=0.0,
                reasoning="model produced no structured verdict",
            )
        return NoiseVerdict.model_validate(raw)

    async def _maybe_hand_off(self, verdict: NoiseVerdict, stats: dict) -> None:
        import time

        now = time.time()
        since = now - self._last_escalation_at
        if since < ESCALATION_COOLDOWN_S:
            logger.info(
                "suppressing re-escalation (%.1fs < %.1fs cooldown); "
                "ongoing attack already handed off",
                since,
                ESCALATION_COOLDOWN_S,
            )
            return

        self._last_escalation_at = now
        sample = self.window.current()[-10:]
        try:
            await hand_off(verdict, stats, store=self.store, sample_signals=sample)
        except Exception:
            logger.exception("handoff to Threat Assessment failed")
            # Allow another attempt on the next escalation rather than being
            # stuck in cooldown after a failed send.
            self._last_escalation_at = 0.0

    async def run_forever(self) -> None:
        logger.info(
            "watching %s (poll=%.1fs, window=%.0fs, cooldown=%.0fs)",
            LOG_PATH,
            POLL_INTERVAL_S,
            WINDOW_SECONDS,
            ESCALATION_COOLDOWN_S,
        )
        while True:
            try:
                await self.assess_once()
            except Exception:
                logger.exception("assessment cycle failed; continuing")
            await asyncio.sleep(POLL_INTERVAL_S)


# --------------------------------------------------------------------------
# A2A inbound side (card + a minimal executor so Detection is a real peer)
# --------------------------------------------------------------------------


class DetectionInboundExecutor(AgentExecutor):
    """Accepts inbound A2A messages. No system sends to Detection in Phase 1;
    this exists so the card is backed by a real endpoint for later phases."""

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        if context.message is None:
            raise ValueError("received an A2A request with no message")
        inbound = from_a2a_message(context.message, trace_received=True)
        logger.info("inbound A2A message for incident %s (no handler in Phase 1)", inbound.incident_id)
        reply = inbound.reply(
            {"received": True, "note": "Detection has no inbound handler in Phase 1"},
            source_system=SELF_SYSTEM,
        )
        await event_queue.enqueue_event(to_a2a_message(reply, role=Role.ROLE_AGENT))

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise NotImplementedError


def build_agent_card_for_detection():
    return build_agent_card(
        name="Detection & Monitoring",
        description=(
            "Watches the target application's access log, reasons over windows "
            "of traffic to separate attacks from noise, and raises classified "
            "incidents to Threat Assessment."
        ),
        url=DETECTION_URL,
        system=SELF_SYSTEM,
        skills=[
            incident_skill(
                skill_id="monitor_access_log",
                name="Monitor access log",
                description="Ingest access-log traffic and escalate attack patterns as incidents.",
            )
        ],
    )


def build_app() -> FastAPI:
    agent_card = build_agent_card_for_detection()
    request_handler = DefaultRequestHandler(
        agent_executor=DetectionInboundExecutor(),
        task_store=InMemoryTaskStore(),
        agent_card=agent_card,
    )
    app = FastAPI(title="Detection & Monitoring — A2A")
    add_a2a_routes_to_fastapi(
        app,
        agent_card_routes=create_agent_card_routes(agent_card, card_url=AGENT_CARD_PATH),
        jsonrpc_routes=create_jsonrpc_routes(request_handler, rpc_url=RPC_PATH),
    )

    pipeline = DetectionPipeline(from_end=not _REPLAY)

    @app.on_event("startup")
    async def _start_loop() -> None:
        app.state.pipeline = pipeline
        app.state.loop_task = asyncio.create_task(pipeline.run_forever())

    @app.on_event("shutdown")
    async def _stop_loop() -> None:
        task = getattr(app.state, "loop_task", None)
        if task:
            task.cancel()

    @app.get("/health", tags=["detection"])
    async def health() -> dict:
        return {
            "status": "ok",
            "system": SELF_SYSTEM.value,
            "watching": str(LOG_PATH),
            "window_size": len(pipeline.window),
        }

    return app


_REPLAY = False


async def _run_once(replay: bool) -> int:
    require_google_api_key()
    pipeline = DetectionPipeline(from_end=not replay)
    verdict = await pipeline.assess_once(force=True)
    if verdict is None:
        logger.info("nothing in the window to assess")
        return 0
    print(f"\nVERDICT: escalate={verdict.escalate} pattern={verdict.pattern_type} "
          f"confidence={verdict.confidence:.2f}\n{verdict.reasoning}")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="assess one window and exit")
    parser.add_argument("--replay", action="store_true", help="read the whole log, not just new lines")
    args = parser.parse_args()

    require_google_api_key()
    _REPLAY = args.replay

    if args.once:
        raise SystemExit(asyncio.run(_run_once(args.replay)))

    logger.info("agent card -> http://127.0.0.1:%s%s", PORT, AGENT_CARD_PATH)
    logger.info("a2a rpc    -> http://127.0.0.1:%s%s", PORT, RPC_PATH)
    uvicorn.run(build_app(), host="127.0.0.1", port=PORT, log_level="warning")
