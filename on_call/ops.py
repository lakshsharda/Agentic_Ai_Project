"""On-Call non-LLM operations: who to page, and how to notify them.

Kept out of the agents module because none of this is reasoning -- it is a
static schedule lookup and a notification transport.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger("on_call.ops")

# --- static on-call schedule (Phase 2: hardcoded is fine) -----------------
# severity -> contact. Real rotation logic is out of scope this phase.
_SCHEDULE = {
    "Critical": {"name": "Priya (SecLead)", "handle": "@priya", "channel": "sec-critical"},
    "High": {"name": "Priya (SecLead)", "handle": "@priya", "channel": "sec-oncall"},
    "Medium": {"name": "Sam (SOC)", "handle": "@sam", "channel": "sec-oncall"},
    "Low": {"name": "SOC queue", "handle": "@soc", "channel": "sec-triage"},
}
_DEFAULT_CONTACT = {"name": "SOC queue", "handle": "@soc", "channel": "sec-triage"}


def lookup_oncall(severity: str | None) -> Dict[str, str]:
    """Return the on-call contact for a severity (static schedule)."""
    contact = _SCHEDULE.get(severity or "", _DEFAULT_CONTACT)
    logger.info("on-call lookup: severity=%s -> %s", severity, contact["name"])
    return contact


# --- notification transport ----------------------------------------------

NOTIFICATIONS_FILE = Path(
    os.environ.get(
        "ONCALL_NOTIFICATIONS_FILE",
        Path(__file__).resolve().parents[1] / "on_call" / "notifications.log",
    )
)


def _slack_webhook() -> str | None:
    return os.environ.get("ONCALL_SLACK_WEBHOOK_URL") or None


def send_notification(text: str, *, incident_id: str, contact: Dict[str, str]) -> Dict[str, Any]:
    """Send the page for real via Slack webhook, or fall back to a file sink.

    The file sink is NOT a real send -- it writes the notification to a local
    log so the flow is testable without a webhook. Which path ran is in the
    return value and the Phase 2 report, so the gap is visible, not hidden.
    """
    record = {
        "at": datetime.now(timezone.utc).isoformat(),
        "incident_id": incident_id,
        "contact": contact,
        "text": text,
    }
    webhook = _slack_webhook()

    if webhook:
        try:
            import httpx

            payload = {"text": text, "channel": contact.get("channel")}
            resp = httpx.post(webhook, json=payload, timeout=10)
            resp.raise_for_status()
            logger.info("Slack notification sent for %s (status %s)", incident_id, resp.status_code)
            record.update({"transport": "slack", "sent": True, "status_code": resp.status_code})
            _append(record)
            return record
        except Exception as exc:  # noqa: BLE001 - fall back to file sink, report it
            logger.warning("Slack send failed (%s); falling back to file sink", exc)
            record.update({"transport": "slack", "sent": False, "error": str(exc)[:200]})

    # File sink (honest local fallback: logged, not actually delivered).
    record.setdefault("transport", "file_sink")
    record.setdefault("sent", False)
    _append(record)
    logger.warning(
        "[NOTIFICATION -- FILE SINK, not actually delivered] incident=%s to=%s\n%s",
        incident_id, contact.get("handle"), text,
    )
    return record


def _append(record: Dict[str, Any]) -> None:
    NOTIFICATIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with NOTIFICATIONS_FILE.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")
