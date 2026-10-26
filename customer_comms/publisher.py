"""The Publishing tool -- NOT an LLM decision.

``publish_draft`` is the only function in the system that talks to customers,
and the only place it is reachable from is the sign-off handler in server.py,
after a human decision has been written to the draft row. Inside it, the actual
post sits physically behind ``if gate.allowed``: the gate
(``shared.guardrail.evaluate_publish_gate``) reads the stored draft, and with no
recorded human approval it returns deny and nothing below the ``if`` runs.

Channel: a Slack incoming webhook (``COMMS_SLACK_WEBHOOK_URL``) pointing at the
status-updates channel -- deliberately NOT the On-Call webhook, which has a
different audience. If it is missing, or the post fails, the message goes to an
honest local file sink with ``sent=False``: logged, not delivered.

No crewai imports here, so tests can exercise the gate without any model stack.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from shared.comms_validation import validate_customer_text
from shared.guardrail import evaluate_publish_gate
from shared.store import Draft, DraftStore, IncidentStore
from shared.trace import record_trace

logger = logging.getLogger("customer_comms.publisher")

CHANNEL_SLACK = "slack:status-updates"
CHANNEL_FILE = "file_sink"

STATUS_FILE = Path(
    os.environ.get(
        "COMMS_STATUS_FILE",
        Path(__file__).resolve().parents[1] / "customer_comms" / "status_updates.log",
    )
)


def _webhook() -> str | None:
    return os.environ.get("COMMS_SLACK_WEBHOOK_URL") or None


def _append(record: Dict[str, Any]) -> None:
    STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with STATUS_FILE.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")


def _post(draft: Draft) -> Dict[str, Any]:
    """Transport only: Slack if configured and healthy, else the file sink."""
    record: Dict[str, Any] = {
        "at": datetime.now(timezone.utc).isoformat(),
        "incident_id": draft.incident_id,
        "draft_id": draft.draft_id,
        "event_type": draft.event_type,
        "approved_by": draft.approved_by,
        "text": draft.draft_text,
    }
    webhook = _webhook()
    if webhook:
        try:
            import httpx

            resp = httpx.post(webhook, json={"text": f"*Service status update*\n{draft.draft_text}"}, timeout=10)
            resp.raise_for_status()
            record.update({"transport": "slack", "sent": True, "channel": CHANNEL_SLACK})
            _append(record)
            return record
        except Exception as exc:  # noqa: BLE001 - fall back to the file sink and say so
            logger.warning("Slack status post failed (%s); falling back to file sink", exc)
            record["error"] = str(exc)[:200]

    record.update({"transport": "file_sink", "sent": False, "channel": CHANNEL_FILE})
    _append(record)
    logger.warning("[STATUS UPDATE -- FILE SINK, not actually delivered] %s: %s",
                   draft.incident_id, draft.draft_text)
    return record


def publish_draft(draft_id: str, *, drafts: DraftStore, store: IncidentStore) -> Dict[str, Any]:
    """Publish one draft if, and only if, the gate allows it.

    Returns ``{"published": bool, "reason": str, ...}``. A refusal changes
    nothing about the draft or the sink; it is only logged and audited on the
    incident.
    """
    draft = drafts.get(draft_id)                      # the stored row, not a caller's claim
    gate = evaluate_publish_gate(draft)

    if gate.allowed:                                  # <-- the physical gate
        incident = store.get_incident(draft.incident_id)
        recheck = validate_customer_text(draft.draft_text, (incident.raw_payload if incident else {}))
        if not recheck.ok:                            # last line of defence on the final text
            reason = f"final text failed validation: {recheck.reason}"
            logger.error("PUBLISH REFUSED for %s: %s", draft_id, reason)
            record_trace(
                incident_id=draft.incident_id, from_system="customer_comms", event_type="publish_refused",
                decision="blocked", summary="publish refused: final text failed validation",
                detail={"draft_id": draft_id},
            )
            return {"published": False, "reason": reason, "draft_id": draft_id}
        posted = _post(draft)
        updated = drafts.mark_published(draft_id, channel=posted["channel"], sent=bool(posted["sent"]))
        if updated is None:
            return {"published": False, "reason": "draft was not APPROVED when marking published",
                    "draft_id": draft_id}
        store.append_history(draft.incident_id, {
            "event": "comms_published", "by": "customer_comms", "draft_id": draft_id,
            "comms_event": draft.event_type, "approved_by": draft.approved_by,
            "channel": posted["channel"], "sent": bool(posted["sent"]),
        })
        record_trace(
            incident_id=draft.incident_id, from_system="customer_comms", event_type="published", decision="human",
            summary=f"{draft.event_type} message published via {posted['channel']} (sent={bool(posted['sent'])}), "
                    f"approved by {draft.approved_by}",
            detail={"draft_id": draft_id, "event": draft.event_type, "channel": posted["channel"],
                    "sent": bool(posted["sent"])},
        )
        logger.info("PUBLISHED %s for %s via %s sent=%s approved_by=%s", draft_id, draft.incident_id,
                    posted["channel"], posted["sent"], draft.approved_by)
        return {"published": True, "reason": gate.reason, "draft_id": draft_id,
                "channel": posted["channel"], "sent": bool(posted["sent"])}

    logger.warning("PUBLISH GATE DENIED %s: %s", draft_id, gate.reason)
    if draft is not None:
        store.append_history(draft.incident_id, {
            "event": "comms_publish_refused", "by": "customer_comms", "draft_id": draft_id,
            "reason": gate.reason,
        })
    return {"published": False, "reason": gate.reason, "draft_id": draft_id}
