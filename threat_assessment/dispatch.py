"""Dispatch -- real fan-out to Containment, On-Call and Forensics.

Phase 1 logged well-formed envelopes without sending them. Phase 2 sends them
for real, in parallel, each call gated by the shared authority matrix. Phase 3
adds Forensics to the same concurrent fan-out, so evidence collection starts at
the same moment Containment begins deciding and On-Call pages.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Tuple

from shared.a2a_support import (
    CONTAINMENT_URL,
    FORENSICS_URL,
    ON_CALL_URL,
    send_incident_message,
)
from shared.guardrail import (
    ACTION_COLLECT_EVIDENCE,
    ACTION_PAGE,
    ACTION_REQUEST_ACTION,
    check_authority,
)
from shared.schemas import IncidentMessage, SystemName

logger = logging.getLogger("threat_assessment.dispatch")

# (target system, its URL, the action type it is being asked to perform)
_FAN_OUT: List[Tuple[SystemName, str, str]] = [
    (SystemName.CONTAINMENT, CONTAINMENT_URL, ACTION_REQUEST_ACTION),
    (SystemName.ON_CALL, ON_CALL_URL, ACTION_PAGE),
    (SystemName.FORENSICS, FORENSICS_URL, ACTION_COLLECT_EVIDENCE),
]


def _message_for(incident_id: str, assessment_payload: Dict[str, Any], target: SystemName, action: str) -> IncidentMessage:
    return IncidentMessage(
        incident_id=incident_id,
        source_system=SystemName.THREAT_ASSESSMENT,
        target_system=target,
        payload={"action": action, **assessment_payload},
    )


async def dispatch_real(incident_id: str, assessment_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Fan out to Containment and On-Call in parallel. Returns per-target results.

    Each send is authority-checked before it leaves; a denied pair is skipped
    and reported rather than sent. The two sends are launched together and
    awaited as a group, so neither blocks the other.
    """
    async def _one(target: SystemName, url: str, action: str) -> Tuple[str, Dict[str, Any]]:
        if not check_authority(SystemName.THREAT_ASSESSMENT.value, target.value, action, incident_id=incident_id):
            return target.value, {"sent": False, "reason": "authority denied"}
        msg = _message_for(incident_id, assessment_payload, target, action)
        try:
            reply = await send_incident_message(msg, peer_base_url=url)
            logger.info("dispatched %s to %s for %s", action, target.value, incident_id)
            return target.value, {"sent": True, "action": action, "reply": reply.payload}
        except Exception as exc:  # noqa: BLE001 - report, don't abort the other leg
            logger.exception("dispatch to %s failed for %s", target.value, incident_id)
            return target.value, {"sent": False, "error": str(exc)[:200]}

    logger.info("=== DISPATCH: fanning out %s to Containment + On-Call + Forensics in parallel ===", incident_id)
    results = await asyncio.gather(*[_one(t, u, a) for (t, u, a) in _FAN_OUT])
    return dict(results)
