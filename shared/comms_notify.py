"""The one place a system tells Customer Comms something happened.

Containment, Forensics and Threat Assessment each call ``notify_comms`` with an
event name. It passes the authority matrix first (``notify_status`` is the only
action those three may send to Comms), then sends a real A2A task. The payload
carries only the event name -- Comms reads incident state from the store, so a
sender cannot put words (or an attacker IP) into a customer message.

Comms never sends anything back out; this module is one-directional.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional, Set

from shared.a2a_support import COMMS_URL, send_incident_message
from shared.guardrail import ACTION_NOTIFY_STATUS, check_authority
from shared.schemas import IncidentMessage, SystemName

logger = logging.getLogger("comms_notify")

_background: Set[asyncio.Task] = set()


async def notify_comms(from_system: SystemName, incident_id: str, event: str) -> Optional[dict]:
    """Send ``notify_status`` to Comms. Returns Comms' reply payload, or None."""
    if not check_authority(from_system, SystemName.CUSTOMER_COMMS, ACTION_NOTIFY_STATUS, incident_id=incident_id):
        return None
    msg = IncidentMessage(
        incident_id=incident_id, source_system=from_system, target_system=SystemName.CUSTOMER_COMMS,
        payload={"action": ACTION_NOTIFY_STATUS, "event": event},
    )
    try:
        reply = await send_incident_message(msg, peer_base_url=COMMS_URL)
        logger.info("notify_status(%s) -> Customer Comms for %s: %s", event, incident_id, reply.payload)
        return reply.payload
    except Exception:
        logger.exception("notify_status(%s) to Customer Comms failed for %s", event, incident_id)
        return None


def notify_comms_in_background(from_system: SystemName, incident_id: str, event: str) -> None:
    """Fire-and-forget from inside a running event loop, holding a reference so
    the task is not garbage-collected mid-flight."""
    task = asyncio.create_task(notify_comms(from_system, incident_id, event))
    _background.add(task)
    task.add_done_callback(_background.discard)
