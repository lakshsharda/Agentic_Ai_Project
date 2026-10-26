"""Detection's reasoning agents.

Two things live here:

  * noise_filter_agent -- an LlmAgent that reasons over a window of aggregated
    traffic stats and decides whether the pattern is noise or an attack worth
    escalating. The decision is the model's; the stats are supplied by a
    FunctionTool, not a hardcoded threshold.

  * the Handoff step -- packages an escalated verdict into the shared envelope,
    writes the initial DETECTED row, and sends it to Threat Assessment over
    A2A. This is plumbing, not reasoning, so it is a plain function.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool, ToolContext
from pydantic import BaseModel, Field

from shared.a2a_support import THREAT_ASSESSMENT_URL, send_incident_message
from shared.llm import ROLE_MECHANICAL, adk_model
from shared.schemas import IncidentMessage, IncidentStatus, SystemName, new_incident_id
from shared.store import IncidentStore
from shared.reasoning import record_reasoning
from shared.trace import record_trace

logger = logging.getLogger("detection.agents")

WINDOW_STATS_STATE_KEY = "window_stats"
VERDICT_STATE_KEY = "noise_verdict"


# --------------------------------------------------------------------------
# Noise Filtering agent
# --------------------------------------------------------------------------


class NoiseVerdict(BaseModel):
    """The structured decision the Noise Filtering agent must produce."""

    escalate: bool = Field(
        description="True if this window shows a pattern worth raising as an incident; "
        "False if it is noise or normal traffic."
    )
    pattern_type: str = Field(
        description="Short label for what was observed, e.g. 'brute_force', "
        "'credential_stuffing', 'traffic_spike', 'normal', 'isolated_failure'."
    )
    confidence: float = Field(
        description="Confidence in this verdict, 0.0 to 1.0.", ge=0.0, le=1.0
    )
    reasoning: str = Field(
        description="Two or three sentences explaining the decision by referring to the "
        "actual numbers in the window (counts, distinct IPs, rate, time span)."
    )


def get_window_stats(tool_context: ToolContext) -> Dict[str, Any]:
    """Return aggregated statistics for the current window of traffic.

    Includes totals, distinct source IPs, failed vs successful logins, how many
    distinct IPs and usernames the failed logins span, request rate, and
    breakdowns by endpoint and status code. Reason over these to decide whether
    the window is an attack or normal noise.
    """
    stats = tool_context.state.get(WINDOW_STATS_STATE_KEY, {})
    logger.debug("noise filter requested window stats: %s", stats)
    return stats


NOISE_FILTER_INSTRUCTION = """\
You are the Noise Filtering agent inside a security Detection system. You decide \
whether a window of recent web traffic against a monitored application represents \
an attack worth escalating, or is just noise and normal activity.

First call get_window_stats to retrieve the aggregated statistics for the current \
window. Then reason over them. Judge the pattern in context -- do not apply a fixed \
numeric threshold. Consider, for example:

- Many failed logins from many distinct IPs in a short span, or many usernames \
  tried, points to brute force or credential stuffing.
- A single failed login, or a couple from one known user's IP, is almost always a \
  mistyped password -- not an incident.
- A high request rate concentrated on one endpoint with few distinct IPs may be a \
  traffic spike worth noting; spread across normal endpoints at a normal rate is \
  routine.
- Mostly successful logins and status checks from a few IPs is normal baseline use.

Escalate only patterns that genuinely warrant a human or downstream system looking. \
When unsure and the signal is weak, prefer not to escalate -- a later, stronger \
window will catch a real attack. Explain your decision by citing the actual numbers.

Respond using the NoiseVerdict structure.
"""


def build_noise_filter_agent() -> LlmAgent:
    return LlmAgent(
        name="noise_filter",
        # Noise filtering is a short, mechanical verdict -> mechanical chain
        # (local Ollama first if available, else Gemini lite). Routes through
        # LiteLLM so a provider rate-limit falls back instead of stalling.
        model=adk_model(ROLE_MECHANICAL, agent_name="noise_filter"),
        description="Reasons over a window of traffic stats to separate attacks from noise.",
        instruction=NOISE_FILTER_INSTRUCTION,
        tools=[FunctionTool(func=get_window_stats)],
        output_schema=NoiseVerdict,
        output_key=VERDICT_STATE_KEY,
    )


# --------------------------------------------------------------------------
# Handoff
# --------------------------------------------------------------------------


def _clean_signal(signal: Dict[str, Any]) -> Dict[str, Any]:
    """Drop the reader/window-derived fields that are not JSON-serializable.

    `ts` (a datetime) and `_ingested_at` are internal to Detection; the raw log
    line already carries a string `timestamp`, which is what downstream needs.
    """
    return {k: v for k, v in signal.items() if k not in ("ts", "_ingested_at")}


def _evidence_from_stats(stats: Dict[str, Any]) -> Dict[str, Any]:
    """Pull the fields worth carrying into the incident, so downstream systems
    and a human reading the row see the shape of what triggered it."""
    keep = [
        "total_requests",
        "window_seconds",
        "observed_span_seconds",
        "request_rate_per_sec",
        "distinct_source_ips",
        "login_attempts",
        "failed_logins",
        "successful_logins",
        "distinct_ips_with_failed_logins",
        "distinct_usernames_targeted",
        "top_failed_login_ips",
        "top_targeted_usernames",
        "requests_by_endpoint",
        "requests_by_status",
    ]
    return {k: stats[k] for k in keep if k in stats}


def _reasoning_text(verdict: NoiseVerdict, evidence: Dict[str, Any]) -> str:
    """The verdict as the Noise Filtering agent gave it, plus the real window numbers it reasoned over.
    Unsanitized on purpose (Phase 6 reasoning feed): real IPs and usernames show the reasoning is grounded."""
    lines = [f"Verdict: ESCALATE as {verdict.pattern_type} (confidence {verdict.confidence:.2f}).", verdict.reasoning.strip()]
    facts = []
    for key in ("total_requests", "failed_logins", "successful_logins",
                "distinct_ips_with_failed_logins", "distinct_usernames_targeted"):
        if key in evidence:
            facts.append(f"{key}={evidence[key]}")
    if facts:
        lines.append("Window: " + ", ".join(facts))
    ips = ", ".join(f"{ip} x{n}" for ip, n in (evidence.get("top_failed_login_ips") or [])[:5])
    users = ", ".join(f"{u} x{n}" for u, n in (evidence.get("top_targeted_usernames") or [])[:5])
    if ips:
        lines.append("Top failing source IPs: " + ips)
    if users:
        lines.append("Usernames targeted: " + users)
    return "\n".join(lines)


async def hand_off(
    verdict: NoiseVerdict,
    stats: Dict[str, Any],
    *,
    store: IncidentStore,
    sample_signals: Optional[List[Dict[str, Any]]] = None,
) -> IncidentMessage:
    """Create the DETECTED row and send it to Threat Assessment over A2A.

    Returns the reply envelope from Threat Assessment. Raises on transport
    failure -- a handoff that silently drops an escalated attack is worse than
    a loud crash the operator can see.
    """
    incident_id = new_incident_id()
    evidence = _evidence_from_stats(stats)

    payload = {
        "detection": {
            "pattern_type": verdict.pattern_type,
            "confidence": verdict.confidence,
            "reasoning": verdict.reasoning,
            "evidence": evidence,
            "sample_signals": [_clean_signal(s) for s in (sample_signals or [])[:10]],
        }
    }

    # Write the initial row first, so the incident exists in the store the
    # moment it is real -- even if the A2A send then fails.
    record = store.create_incident(
        incident_id,
        status=IncidentStatus.DETECTED,
        incident_type=verdict.pattern_type,
        raw_payload={
            "origin": SystemName.DETECTION.value,
            "status_history": [
                {
                    "from": None,
                    "to": IncidentStatus.DETECTED.value,
                    "by": SystemName.DETECTION.value,
                    "at": record_now(),
                }
            ],
            **payload,
        },
    )
    logger.info("created incident row: %s", record.summary())
    record_trace(
        incident_id=incident_id, from_system=SystemName.DETECTION, event_type="status_advanced",
        decision="auto", summary=f"None -> {IncidentStatus.DETECTED.value}",
        detail={"from": None, "to": IncidentStatus.DETECTED.value, "pattern_type": verdict.pattern_type,
                "confidence": round(float(verdict.confidence), 2)},
    )
    top_ips = evidence.get("top_failed_login_ips") or []
    record_reasoning(
        system=SystemName.DETECTION, agent_name="Noise Filtering Agent", incident_id=incident_id,
        text=_reasoning_text(verdict, evidence),
        narration=(f"Detection analyzed {evidence.get('total_requests', 'a window of')} requests"
                   + (f" ({evidence.get('failed_logins')} failed logins)" if 'failed_logins' in evidence else "")
                   + (f" from {top_ips[0][0]} and {len(top_ips) - 1} other source(s)" if len(top_ips) > 1
                      else f" from {top_ips[0][0]}" if top_ips else "")
                   + f", judged it a {verdict.pattern_type} (confidence {verdict.confidence:.2f}) and escalated "
                   "to Threat Assessment."))

    message = IncidentMessage(
        incident_id=incident_id,
        source_system=SystemName.DETECTION,
        target_system=SystemName.THREAT_ASSESSMENT,
        payload=payload,
    )

    logger.info(
        "A2A handoff -> Threat Assessment (%s): incident %s pattern=%s confidence=%.2f",
        THREAT_ASSESSMENT_URL,
        incident_id,
        verdict.pattern_type,
        verdict.confidence,
    )
    reply = await send_incident_message(message, peer_base_url=THREAT_ASSESSMENT_URL)
    logger.info(
        "Threat Assessment acknowledged %s: %s",
        reply.incident_id,
        reply.payload.get("assessment", reply.payload),
    )
    return reply


def record_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()
