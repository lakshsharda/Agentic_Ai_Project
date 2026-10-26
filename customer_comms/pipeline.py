"""Draft creation pipeline for Customer Communications (no LLM imports here).

    incident state --(Impact Assessment)--> impact label + summary
                   --(Message Drafting)---> draft text
                   --(validator, in code)-> PENDING_SIGNOFF row, or REJECTED + retry

The two model-backed steps are passed in as callables (``assessor`` and
``drafter``), so this module -- the validate / retry / supersede / audit logic
-- is testable without CrewAI or any model, and a model outage degrades to a
deterministic template instead of leaving customers with no draft at all.

Nothing here publishes. A draft leaves this module PENDING_SIGNOFF at best.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Dict, Optional

from shared.comms_validation import validate_customer_text
from shared.reasoning import record_reasoning, start_call
from shared.store import Draft, DraftStore, IncidentRecord, IncidentStore
from shared.store.drafts import STATUS_PENDING, STATUS_PUBLISHED, STATUS_REJECTED

logger = logging.getLogger("customer_comms.pipeline")

EVENT_CONTAINED = "contained"
EVENT_RECLASSIFIED = "reclassified"
EVENT_RESOLVED = "resolved"
EVENTS = (EVENT_CONTAINED, EVENT_RECLASSIFIED, EVENT_RESOLVED)

# Which system is allowed to report which event. The authority matrix already
# limits each sender to `notify_status`; this stops (say) Forensics from
# announcing that something was *contained*.
SENDER_FOR_EVENT = {
    EVENT_CONTAINED: "containment",
    EVENT_RECLASSIFIED: "threat_assessment",
    EVENT_RESOLVED: "forensics",
}

IMPACT_LABELS = ("DEGRADED", "AT_RISK", "MITIGATED", "RESTORED")


@dataclass
class Impact:
    label: str
    summary: str


# An assessor takes (snapshot, event) -> Impact; a drafter takes
# (snapshot, event, impact, feedback) -> text. Either may raise.
Assessor = Callable[[Dict, str], Impact]
Drafter = Callable[[Dict, str, Impact, Optional[str]], str]


def snapshot_of(record: IncidentRecord, drafts: DraftStore) -> Dict:
    """What Comms is allowed to know, read from the store (never from the sender)."""
    payload = record.raw_payload or {}
    containment = payload.get("containment", {}) or {}
    recovery = payload.get("recovery", {}) or {}
    published = [d for d in drafts.list(incident_id=record.incident_id) if d.status == STATUS_PUBLISHED]
    return {
        "severity": record.severity or "Medium",
        "incident_type": record.incident_type,
        "status": record.status,
        "containment_done": containment.get("state") == "EXECUTED",
        "recovery_done": bool(recovery.get("lifted")),
        "previous_published_text": published[-1].draft_text if published else None,
    }


def fallback_impact(snapshot: Dict, event: str) -> Impact:
    """Deterministic impact label, used when the assessor model is unavailable
    or returns something outside the vocabulary."""
    if event == EVENT_RESOLVED or snapshot.get("recovery_done"):
        return Impact("RESTORED", "Service has been restored and protective measures are no longer needed.")
    if snapshot.get("containment_done"):
        return Impact("MITIGATED", "Protective action is in place; the service is operating normally.")
    if snapshot.get("severity") in ("High", "Critical"):
        return Impact("DEGRADED", "Service may be disrupted while the issue is handled.")
    return Impact("AT_RISK", "The service is at risk and is being monitored closely.")


def template_draft(snapshot: Dict, event: str) -> str:
    """The deterministic, always-valid message. Used when the model is down or
    has failed validation twice. Differs by event and by severity band."""
    high = snapshot.get("severity") in ("High", "Critical")
    if event == EVENT_CONTAINED:
        text = ("We detected unusual activity affecting our service and have taken protective action. "
                "Our team is monitoring the situation closely.")
        text += (" As a precaution, please reset your password if you see any sign-ins you do not recognize."
                 if high else " No action is needed from you at this time.")
        return text + " We will post another update when the issue is resolved."
    if event == EVENT_RECLASSIFIED:
        text = ("Update to our earlier notice: after further review we have revised our assessment of "
                "the recent service issue. This update replaces our previous message.")
        text += (" Please reset your password if you see any sign-ins you do not recognize, and contact "
                 "support if anything looks wrong on your account." if high else
                 " No action is needed from you at this time.")
        return text + " We will keep you informed."
    return ("The service issue we reported earlier has been resolved and the service is operating normally. "
            "Thank you for your patience."
            + (" If you noticed any unfamiliar account activity, please reset your password and contact support."
               if high else ""))


def build_draft(
    store: IncidentStore,
    drafts: DraftStore,
    incident_id: str,
    event: str,
    *,
    assessor: Optional[Assessor] = None,
    drafter: Optional[Drafter] = None,
) -> Optional[Draft]:
    """Create the draft for one event. Returns the PENDING_SIGNOFF draft.

    Validation outcomes are recorded, not hidden: a draft that fails is stored
    as REJECTED with the violations; one regeneration is attempted with those
    violations fed back; if that fails too the deterministic template is used
    (generation = template_fallback) and the double failure is logged loudly.
    """
    record = store.get_incident(incident_id)
    if record is None:
        logger.warning("notify_status for unknown incident %s; no draft created", incident_id)
        return None
    payload = record.raw_payload or {}
    snap = snapshot_of(record, drafts)

    # 1. Impact Assessment.
    impact = None
    if assessor is not None:
        call = start_call(system="customer_comms", agent_name="Impact Assessment Agent", incident_id=incident_id)
        try:
            impact = assessor(snap, event)
        except Exception as exc:  # noqa: BLE001 - model outage must not strand customers
            logger.warning("impact assessor failed for %s (%s); using deterministic impact", incident_id, exc)
            call.fail(reason=str(exc)[:160] or type(exc).__name__)
        else:
            if impact is not None and impact.label in IMPACT_LABELS:
                call.resolve(text=f"Event: {event}  |  customer impact: {impact.label}\n{impact.summary}",
                            narration=f"Customer Comms was notified of the '{event}' event and rated the "
                                      f"customer impact {impact.label}.")
            else:
                call.fail(reason="model returned an off-vocabulary impact label")
    if impact is None or impact.label not in IMPACT_LABELS:
        impact = fallback_impact(snap, event)
        record_reasoning(system="customer_comms", agent_name="Impact Assessment Agent", incident_id=incident_id,
                         text=f"Event: {event}  |  customer impact: {impact.label}\n{impact.summary}",
                         narration=f"Customer Comms was notified of the '{event}' event and rated the customer "
                                   f"impact {impact.label} (deterministic fallback, no model assessor available).")

    # 2. Message Drafting, with validate -> reject -> regenerate once.
    final_text: Optional[str] = None
    generation = "llm"
    feedback: Optional[str] = None
    if drafter is not None:
        for attempt in (1, 2):
            gen = "llm" if attempt == 1 else "llm_retry"
            agent_label = "Customer Message Drafting Agent" if attempt == 1 else "Customer Message Drafting Agent (retry)"
            call = start_call(system="customer_comms", agent_name=agent_label, incident_id=incident_id)
            try:
                text = drafter(snap, event, impact, feedback)
            except Exception as exc:  # noqa: BLE001
                logger.warning("drafter failed for %s attempt %d (%s)", incident_id, attempt, exc)
                call.fail(reason=str(exc)[:160] or type(exc).__name__)
                break
            result = validate_customer_text(text, payload)
            if result.ok:
                final_text, generation = text.strip(), gen
                call.resolve(text=text, narration=f"Draft attempt {attempt} passed validation; finalizing.")
                break
            logger.warning("draft for %s FAILED validation (attempt %d): %s", incident_id, attempt, result.reason)
            call.resolve(text=f"Draft attempt {attempt} REJECTED by the validator ({result.reason}):\n{text}",
                        narration=f"The customer-message validator rejected draft attempt {attempt} ({result.reason}); regenerating.")
            drafts.create(
                incident_id, event_type=event, draft_text=text or "", severity_at_draft=snap["severity"],
                status=STATUS_REJECTED, rejection_reason=f"validator: {result.reason}",
                generation=gen, impact=impact.label,
            )
            store.append_history(incident_id, {
                "event": "comms_draft_rejected", "by": "customer_comms", "comms_event": event,
                "attempt": attempt, "reason": result.reason,
            })
            feedback = (f"Your previous draft was rejected because it {result.reason}. "
                        "Rewrite it with none of those; never mention addresses, accounts, hosts, ports or technical causes.")
        else:
            logger.error("draft for %s failed validation TWICE; falling back to the deterministic template",
                         incident_id)

    if final_text is None:
        final_text, generation = template_draft(snap, event), "template_fallback"
        check = validate_customer_text(final_text, payload)
        if not check.ok:  # a template that fails its own validator is a code bug
            raise RuntimeError(f"template draft failed validation: {check.reason}")

    record_reasoning(system="customer_comms", agent_name="Customer Message Drafting Agent", incident_id=incident_id,
                     text=f"[{generation}] draft for the '{event}' notice, awaiting human sign-off:\n{final_text}",
                     narration=f"Customer Comms drafted the '{event}' customer notice; it cannot be published until a human signs it off.")
    # 3. Store as PENDING_SIGNOFF and supersede older unpublished drafts.
    draft = drafts.create(
        incident_id, event_type=event, draft_text=final_text, severity_at_draft=snap["severity"],
        status=STATUS_PENDING, generation=generation, impact=impact.label,
    )
    superseded = drafts.supersede_unpublished(incident_id, superseded_by=draft.draft_id)
    store.append_history(incident_id, {
        "event": "comms_draft_created", "by": "customer_comms", "comms_event": event,
        "draft_id": draft.draft_id, "status": STATUS_PENDING, "generation": generation,
        "impact": impact.label,
    })
    for old in superseded:
        store.append_history(incident_id, {
            "event": "comms_draft_superseded", "by": "customer_comms",
            "draft_id": old, "superseded_by": draft.draft_id,
        })
    logger.info("draft %s for %s event=%s severity=%s generation=%s -> PENDING_SIGNOFF (superseded %s)",
                draft.draft_id, incident_id, event, snap["severity"], generation, superseded or "none")
    return draft
