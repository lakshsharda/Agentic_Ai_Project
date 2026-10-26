"""Guardrail middleware v1 -- the shared policy gate (Phase 2, Task 2).

A real, code-level gate, not a prompt instruction. Every system imports this
and calls it before any side-effecting action or outbound A2A call, so the
authority matrix lives in exactly one place as more systems are added.

Two independent checks, as the brief specifies:

  * ``check_authority(from_system, to_system, action_type)`` -- is this caller
    even allowed to ask this of that target?
  * ``requires_human_approval(severity)`` -- does an action at this severity
    need a human (or a timeout escalation) to sign off before it runs?

Plus the Phase 2 approval-signal mechanism: a flag on the incident row that
On-Call writes and Containment reads, keyed on ``incident_id``. A full pub/sub
event bus is Phase 3 scope; this is the simplest thing that is correct.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional, Set, Tuple

from shared.schemas import Severity, SystemName
from shared.store import IncidentStore
from shared.trace import record_trace

logger = logging.getLogger("guardrail")

# Action-type vocabulary used across A2A calls this phase.
ACTION_CANDIDATE = "candidate"               # Detection -> Threat Assessment
ACTION_REQUEST_ACTION = "request_action"     # Threat Assessment -> Containment
ACTION_PAGE = "page"                         # Threat Assessment -> On-Call
ACTION_TIMEOUT_ESCALATION = "timeout_escalation"  # On-Call -> Containment
ACTION_STATUS_UPDATE = "status_update"       # Containment -> Threat Assessment (reporting)
# Phase 3
ACTION_COLLECT_EVIDENCE = "collect_evidence"  # Threat Assessment -> Forensics (on dispatch)
ACTION_RECLASSIFY = "reclassify"             # Forensics -> Threat Assessment (feedback loop)
ACTION_EVIDENCE_PRESERVED = "evidence_preserved"  # Forensics -> Containment (gate signal)
ACTION_RECOVERY_PLAN = "recovery_plan"       # Forensics -> Containment (lift-containment signal)
# Phase 4
ACTION_NOTIFY_STATUS = "notify_status"       # Containment / Forensics / Threat Assessment -> Customer Comms

# --------------------------------------------------------------------------
# Authority matrix -- who may ask what of whom. One static table, not scattered
# across agents. (from_system, to_system) -> allowed action types.
# --------------------------------------------------------------------------

_S = SystemName
AUTHORITY_MATRIX: Dict[Tuple[str, str], Set[str]] = {
    (_S.DETECTION.value, _S.THREAT_ASSESSMENT.value): {ACTION_CANDIDATE},
    (_S.THREAT_ASSESSMENT.value, _S.CONTAINMENT.value): {ACTION_REQUEST_ACTION},
    (_S.THREAT_ASSESSMENT.value, _S.ON_CALL.value): {ACTION_PAGE},
    # On-Call may reach Containment ONLY for the timeout-escalation signal.
    (_S.ON_CALL.value, _S.CONTAINMENT.value): {ACTION_TIMEOUT_ESCALATION},
    # Containment reports status back to Threat Assessment; it may NOT issue
    # commands to other systems in this phase.
    (_S.CONTAINMENT.value, _S.THREAT_ASSESSMENT.value): {ACTION_STATUS_UPDATE},
    # Phase 3: Forensics.
    (_S.THREAT_ASSESSMENT.value, _S.FORENSICS.value): {ACTION_COLLECT_EVIDENCE},
    # Forensics' feedback loop back upstream to Threat Assessment.
    (_S.FORENSICS.value, _S.THREAT_ASSESSMENT.value): {ACTION_RECLASSIFY},
    # Forensics -> Containment: evidence-preservation handshake and the
    # recovery/lift-containment signal, nothing else.
    (_S.FORENSICS.value, _S.CONTAINMENT.value): {ACTION_EVIDENCE_PRESERVED, ACTION_RECOVERY_PLAN},
    # Phase 4: Customer Comms only RECEIVES. Three inbound edges, one action
    # each; Comms has no outbound edge at all, and nothing else may reach it.
    (_S.CONTAINMENT.value, _S.CUSTOMER_COMMS.value): {ACTION_NOTIFY_STATUS},
    (_S.FORENSICS.value, _S.CUSTOMER_COMMS.value): {ACTION_NOTIFY_STATUS},
    (_S.THREAT_ASSESSMENT.value, _S.CUSTOMER_COMMS.value): {ACTION_NOTIFY_STATUS},
}

# Severities that may not auto-execute a side-effecting action.
_APPROVAL_REQUIRED_SEVERITIES = {Severity.HIGH.value, Severity.CRITICAL.value}


def _as_value(system) -> str:
    return system.value if isinstance(system, SystemName) else str(system)


def check_authority(from_system, to_system, action_type: str, incident_id: Optional[str] = None) -> bool:
    """Whether ``from_system`` may send ``action_type`` to ``to_system``.

    Deny by default: an unlisted pair or action is refused. This is the real
    gate on outbound A2A -- a caller that is not in the matrix cannot route a
    task to a peer just because it knows the URL.

    ``incident_id`` is only for the trace (Phase 5): every check, allowed or
    denied, is recorded so a denial shows up in the timeline. The decision does
    not depend on it and a failed trace write cannot change the answer.
    """
    key = (_as_value(from_system), _as_value(to_system))
    allowed = AUTHORITY_MATRIX.get(key, set())
    ok = action_type in allowed
    if not ok:
        logger.warning(
            "AUTHORITY DENIED: %s -> %s action=%s (allowed for this pair: %s)",
            key[0], key[1], action_type, sorted(allowed) or "none",
        )
    record_trace(
        incident_id=incident_id, from_system=key[0], to_system=key[1],
        event_type="authority_checked" if ok else "authority_denied",
        decision="auto" if ok else "blocked",
        summary=f"{action_type}: {'allowed' if ok else 'DENIED (not in the authority matrix)'}",
        detail={"action": action_type, "allowed": ok},
    )
    return ok


def requires_human_approval(severity: Optional[str]) -> bool:
    """Whether an action on an incident of this severity needs sign-off first.

    True for High and Critical. Unknown/missing severity is treated as needing
    approval -- fail safe, not fail open.
    """
    if severity is None:
        return True
    return _as_value(severity) in _APPROVAL_REQUIRED_SEVERITIES


# --------------------------------------------------------------------------
# Approval signal -- a flag on the incident row, keyed on incident_id.
# On-Call writes it (human ack or timeout auto-approval); Containment reads it.
# --------------------------------------------------------------------------

APPROVAL_HUMAN = "human"
APPROVAL_TIMEOUT = "timeout_escalation"

_APPROVAL_KEY = "approval"


@dataclass
class Approval:
    approved: bool
    approved_by: str          # a human identity, or "timeout_escalation"
    provenance: str           # APPROVAL_HUMAN | APPROVAL_TIMEOUT
    at: str
    note: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "approved": self.approved,
            "approved_by": self.approved_by,
            "provenance": self.provenance,
            "at": self.at,
            "note": self.note,
        }


def record_approval(
    store: IncidentStore,
    incident_id: str,
    *,
    approved_by: str,
    provenance: str,
    note: Optional[str] = None,
) -> Approval:
    """Write the approval signal onto the incident row.

    ``provenance`` makes the signal's origin auditable -- a human acknowledgment
    versus a timeout auto-approval -- which is the whole point of tagging it
    rather than storing a bare boolean.
    """
    approval = Approval(
        approved=True,
        approved_by=approved_by,
        provenance=provenance,
        at=datetime.now(timezone.utc).isoformat(),
        note=note,
    )
    store.update_incident(incident_id, raw_payload={_APPROVAL_KEY: approval.to_dict()})
    logger.info(
        "APPROVAL recorded for %s by=%s provenance=%s", incident_id, approved_by, provenance
    )
    record_trace(
        incident_id=incident_id, from_system=SystemName.ON_CALL.value, to_system=SystemName.CONTAINMENT.value,
        event_type="approval_recorded",
        decision="human" if provenance == APPROVAL_HUMAN else (
            "timeout_escalation" if provenance == APPROVAL_TIMEOUT else "n/a"),
        summary=f"containment approval recorded by {approved_by} ({provenance})",
        detail={"provenance": provenance},
    )
    return approval


def get_approval(store: IncidentStore, incident_id: str) -> Optional[Approval]:
    """Read the approval signal for an incident, or None if not yet approved."""
    record = store.get_incident(incident_id)
    if record is None:
        return None
    raw = (record.raw_payload or {}).get(_APPROVAL_KEY)
    if not raw or not raw.get("approved"):
        return None
    return Approval(
        approved=raw.get("approved", False),
        approved_by=raw.get("approved_by", "unknown"),
        provenance=raw.get("provenance", "unknown"),
        at=raw.get("at", ""),
        note=raw.get("note"),
    )


# --------------------------------------------------------------------------
# Evidence-preservation signal (Phase 3) -- the second gate Containment waits
# on, written by Forensics once it has snapshotted preserve-worthy state.
# Same store-flag mechanism as approval, keyed on incident_id.
# --------------------------------------------------------------------------

_EVIDENCE_KEY = "evidence"


@dataclass
class EvidenceSignal:
    preserved: bool
    preserve_worthy: bool      # did the incident actually warrant preservation?
    by: str
    at: str
    snapshot_ref: Optional[str] = None
    note: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "preserved": self.preserved, "preserve_worthy": self.preserve_worthy,
            "by": self.by, "at": self.at, "snapshot_ref": self.snapshot_ref, "note": self.note,
        }


def record_evidence_preserved(
    store: IncidentStore,
    incident_id: str,
    *,
    by: str,
    preserve_worthy: bool,
    snapshot_ref: Optional[str] = None,
    note: Optional[str] = None,
) -> EvidenceSignal:
    """Mark that evidence for an incident has been preserved (or found not
    preserve-worthy). Containment's evidence gate reads this."""
    sig = EvidenceSignal(
        preserved=True, preserve_worthy=preserve_worthy, by=by,
        at=datetime.now(timezone.utc).isoformat(), snapshot_ref=snapshot_ref, note=note,
    )
    store.update_incident(incident_id, raw_payload={_EVIDENCE_KEY: sig.to_dict()})
    logger.info("EVIDENCE preserved for %s by=%s preserve_worthy=%s", incident_id, by, preserve_worthy)
    record_trace(
        incident_id=incident_id, from_system=by, to_system=SystemName.CONTAINMENT.value,
        event_type="evidence_preserved", decision="auto",
        summary=f"evidence preserved (preserve_worthy={preserve_worthy})",
        detail={"preserve_worthy": preserve_worthy},
    )
    return sig


def get_evidence_signal(store: IncidentStore, incident_id: str) -> Optional[EvidenceSignal]:
    record = store.get_incident(incident_id)
    if record is None:
        return None
    raw = (record.raw_payload or {}).get(_EVIDENCE_KEY)
    if not raw or not raw.get("preserved"):
        return None
    return EvidenceSignal(
        preserved=raw.get("preserved", False), preserve_worthy=raw.get("preserve_worthy", False),
        by=raw.get("by", "unknown"), at=raw.get("at", ""),
        snapshot_ref=raw.get("snapshot_ref"), note=raw.get("note"),
    )


# --------------------------------------------------------------------------
# Combined gate for a side-effecting action.
# --------------------------------------------------------------------------


@dataclass
class GateDecision:
    allowed: bool
    reason: str
    pending_approval: bool = False
    pending_evidence: bool = False
    approval: Optional[Approval] = None


def evaluate_action_gate(
    store: IncidentStore,
    *,
    from_system,
    to_system,
    action_type: str,
    severity: Optional[str],
    incident_id: str,
    require_evidence: bool = False,
) -> GateDecision:
    """Evaluate the action gate and trace the decision (Phase 5).

    The trace is observation only: the returned decision is exactly what
    ``_evaluate_action_gate`` computed, whatever happens to the trace write.
    """
    decision = _evaluate_action_gate(
        store, from_system=from_system, to_system=to_system, action_type=action_type,
        severity=severity, incident_id=incident_id, require_evidence=require_evidence,
    )
    if decision.allowed:
        who = decision.approval.provenance if decision.approval else None
        outcome = APPROVAL_HUMAN if who == APPROVAL_HUMAN else (APPROVAL_TIMEOUT if who == APPROVAL_TIMEOUT else "auto")
    else:
        outcome = "blocked"
    record_trace(
        incident_id=incident_id, from_system=to_system, to_system=None,
        event_type="gate_evaluated", decision=outcome,
        summary=f"{action_type} gate: {'ALLOWED' if decision.allowed else 'BLOCKED'} - {decision.reason}",
        detail={"gate": "action", "action": action_type, "requested_by": _as_value(from_system),
                "severity": _as_value(severity) if severity else None, "allowed": decision.allowed,
                "pending_approval": decision.pending_approval, "pending_evidence": decision.pending_evidence},
    )
    return decision


def _evaluate_action_gate(
    store: IncidentStore,
    *,
    from_system,
    to_system,
    action_type: str,
    severity: Optional[str],
    incident_id: str,
    require_evidence: bool = False,
) -> GateDecision:
    """The single call Containment makes before executing a real action.

    Returns a decision; the caller must physically branch on ``allowed`` and
    not execute when it is False. Order: authority first (may this even be
    requested?), then -- when ``require_evidence`` -- the evidence-preservation
    gate (Phase 3), then approval (if required, is the signal present yet?).

    The evidence gate comes before approval because preserving evidence must
    happen before any state change, regardless of who approves the action.
    """
    if not check_authority(from_system, to_system, action_type, incident_id=incident_id):
        return GateDecision(
            allowed=False,
            reason=f"authority denied: {_as_value(from_system)} -> {_as_value(to_system)} / {action_type}",
        )

    if require_evidence:
        evidence = get_evidence_signal(store, incident_id)
        if evidence is None:
            return GateDecision(
                allowed=False, pending_evidence=True,
                reason="evidence preservation required and no evidence_preserved signal yet",
            )

    if not requires_human_approval(severity):
        return GateDecision(allowed=True, reason=f"no approval required at severity={severity}")

    approval = get_approval(store, incident_id)
    if approval is None:
        return GateDecision(
            allowed=False,
            pending_approval=True,
            reason=f"approval required (severity={severity}) and none recorded yet",
        )
    return GateDecision(
        allowed=True,
        reason=f"approved by {approval.approved_by} ({approval.provenance})",
        approval=approval,
    )


# --------------------------------------------------------------------------
# Publish gate (Phase 4) -- the code-level gate in front of the one function
# that talks to customers. Same deny-by-default shape as the action gate, but
# with NO severity threshold and NO timeout path: a human signs off every time.
# --------------------------------------------------------------------------

# Identities that are a mechanism, not a person. A draft "approved" by one of
# these is refused. ``timeout_escalation`` is On-Call's auto-approval for
# Containment actions and must never count as sign-off to publish.
_NON_HUMAN_APPROVERS = {
    APPROVAL_TIMEOUT, "timeout", "system", "auto", "automatic", "automation", "bot", "agent",
    "llm", "model", "none", "null", "unknown", "anonymous", "n/a", "na",
}


def is_human_identity(approver: Optional[str]) -> bool:
    """Whether ``approver`` looks like a person rather than a system value."""
    if approver is None:
        return False
    name = str(approver).strip().lower()
    if not name:
        return False
    if name in _NON_HUMAN_APPROVERS:
        return False
    if name in {s.value for s in SystemName}:
        return False
    return True


@dataclass
class PublishDecision:
    allowed: bool
    reason: str


def evaluate_publish_gate(draft) -> PublishDecision:
    """Evaluate the publish gate and trace the decision (Phase 5); the decision
    itself is computed by ``_evaluate_publish_gate`` and is unaffected by tracing."""
    decision = _evaluate_publish_gate(draft)
    if draft is not None:
        status = getattr(draft, "status", None)
        approver = getattr(draft, "approved_by", None)
        record_trace(
            incident_id=getattr(draft, "incident_id", None), from_system=SystemName.CUSTOMER_COMMS.value,
            event_type="gate_evaluated", decision="human" if decision.allowed else "blocked",
            summary=f"publish gate: {'ALLOWED' if decision.allowed else 'BLOCKED'} - {decision.reason}",
            detail={"gate": "publish", "draft_id": getattr(draft, "draft_id", None),
                    "event": getattr(draft, "event_type", None), "allowed": decision.allowed,
                    "draft_status": status, "pending_signoff": status == "PENDING_SIGNOFF",
                    "approver_is_human": bool(approver) and is_human_identity(approver)},
        )
    return decision


def _evaluate_publish_gate(draft) -> PublishDecision:
    """May this draft be published? Deny by default.

    Allowed only when the draft's recorded status is ``APPROVED`` and its
    ``approved_by`` is a non-empty human identity (not ``timeout_escalation`` or
    any other system value). The decision is made from the stored row the
    caller loaded, never from anything an LLM or a request body says.
    The publish tool must branch on ``allowed`` and do nothing when it is False.
    """
    if draft is None:
        return PublishDecision(False, "no such draft")
    status = getattr(draft, "status", None)
    if status != "APPROVED":
        return PublishDecision(False, f"draft status is {status!r}; only APPROVED drafts may be published")
    approver = getattr(draft, "approved_by", None)
    if not approver or not str(approver).strip():
        return PublishDecision(False, "no approver recorded")
    if not is_human_identity(approver):
        return PublishDecision(
            False, f"approver {approver!r} is a system value, not a human sign-off"
        )
    return PublishDecision(True, f"approved by {approver}")
