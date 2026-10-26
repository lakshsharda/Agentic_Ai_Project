"""Root Cause Analysis -- the long-form reasoning agent (Phase 3).

Produces a genuine narrative explanation of what happened and why, using the
continuation-aware generation path in shared/llm.py (the one place the
partial-generation-cutoff handling is wired in). Separately decides whether the
analysis warrants a re-classification back to Threat Assessment.

Design note: the *narrative* is open-ended LLM reasoning. The *reclassification
trigger* is grounded in concrete evidence (a successful login during the
attack, or a campaign-scale spread) rather than relying on the model to
reliably emit a signal -- more defensible and more deterministic, while the
narrative still carries the real reasoning. Documented in the Phase 3 report.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

from shared.llm import ROLE_REASONING, generate_with_continuation
from shared.schemas import Severity

logger = logging.getLogger("forensics.rca")

_SEVERITY_RANK = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}

RCA_SYSTEM_PROMPT = (
    "You are the Root Cause Analysis agent in a security incident-response system. "
    "You write a clear, specific narrative explaining what most likely happened in an "
    "incident and why, reasoning over the concrete evidence you are given -- counts, "
    "source IPs, usernames, timings, the firewall state, and the prior assessment. "
    "Be concrete and incident-specific; do not produce boilerplate. Cover: what the "
    "attacker appears to have done, how far they likely got (blast radius), what the "
    "evidence does and does not support, and what the biggest remaining risk is."
)


@dataclass
class RcaResult:
    narrative: str
    should_reclassify: bool
    suggested_severity: Optional[str]
    suggested_type: Optional[str]
    reclassify_reason: str
    generation: Dict[str, Any]  # {rounds, providers, continued, mode, ...}


def _reclassification_judgment(record, snapshot) -> Dict[str, Any]:
    """Evidence-grounded decision on whether to escalate the assessment."""
    ev = (snapshot.get("detection_signals", {}) or {}).get("evidence", {}) or {}
    current = record.severity or "Medium"
    cur_rank = _SEVERITY_RANK.get(current, 1)

    successful = int(ev.get("successful_logins", 0) or 0)
    distinct_users = int(ev.get("distinct_usernames_targeted", 0) or 0)
    distinct_ips = int(ev.get("distinct_ips_with_failed_logins", 0) or 0)

    # A successful login during the attack = likely real compromise -> Critical.
    if successful > 0 and cur_rank < _SEVERITY_RANK["Critical"]:
        return {
            "should_reclassify": True, "suggested_severity": "Critical",
            "reason": f"evidence shows {successful} successful login(s) during the attack -- "
                      f"likely account compromise, wider blast radius than the {current} assessment",
        }
    # Campaign-scale distributed credential attack under-rated as Low/Medium -> High.
    if cur_rank <= _SEVERITY_RANK["Medium"] and (distinct_users >= 5 or distinct_ips >= 10):
        return {
            "should_reclassify": True, "suggested_severity": "High",
            "reason": f"distributed/credential-stuffing scale ({distinct_ips} IPs, {distinct_users} usernames) "
                      f"exceeds a {current} assessment",
        }
    return {"should_reclassify": False, "suggested_severity": None, "reason": "assessment consistent with evidence"}


def analyze(record, snapshot: Dict[str, Any], *, max_tokens_per_round: int = 900) -> RcaResult:
    """Run the narrative RCA and the reclassification judgment for an incident."""
    ev = (snapshot.get("detection_signals", {}) or {}).get("evidence", {})
    user_prompt = (
        f"Incident {record.incident_id}\n"
        f"Current assessment: severity={record.severity}, type={record.incident_type}, "
        f"escalated={record.escalated}\n\n"
        f"Detection pattern: {snapshot.get('detection_signals', {}).get('pattern_type')}\n"
        f"Detection reasoning: {snapshot.get('detection_signals', {}).get('reasoning')}\n\n"
        f"Evidence (aggregated signals):\n{_fmt(ev)}\n\n"
        f"Firewall state at capture: {snapshot.get('firewall_state_at_capture', {})}\n"
        f"Status history: {snapshot.get('status_history', [])}\n\n"
        "Write the root-cause narrative."
    )

    gen = generate_with_continuation(
        ROLE_REASONING,
        system_prompt=RCA_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        agent_name="root_cause_analysis",
        max_tokens_per_round=max_tokens_per_round,
    )
    narrative = gen["text"] or "(root-cause analysis produced no text)"

    judgment = _reclassification_judgment(record, snapshot)
    logger.info(
        "RCA for %s: %d words, continued=%s; reclassify=%s -> %s",
        record.incident_id, len(narrative.split()), gen.get("continued"),
        judgment["should_reclassify"], judgment.get("suggested_severity"),
    )
    return RcaResult(
        narrative=narrative,
        should_reclassify=judgment["should_reclassify"],
        suggested_severity=judgment["suggested_severity"],
        suggested_type=record.incident_type,
        reclassify_reason=judgment["reason"],
        generation=gen,
    )


def _fmt(ev: Dict[str, Any]) -> str:
    keys = ["total_requests", "failed_logins", "successful_logins", "distinct_source_ips",
            "distinct_ips_with_failed_logins", "distinct_usernames_targeted",
            "top_failed_login_ips", "top_targeted_usernames", "requests_by_endpoint"]
    return "\n".join(f"  {k}: {ev[k]}" for k in keys if k in ev)
