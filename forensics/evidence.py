"""Evidence Collection -- the non-LLM front of Forensics.

Snapshots the state relevant to an incident to a durable JSON file (one per
incident_id) and decides whether the incident is "preserve-worthy". The
snapshot pairs the current simulated-firewall rule set with the raw signals
that produced the incident (already stored by Detection on the incident row).
No reasoning here -- that is the Root Cause Analysis agent's job.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from containment.firewall import blocked_ips  # read-only query of the simulated firewall
from shared.store import IncidentRecord

logger = logging.getLogger("forensics.evidence")

EVIDENCE_DIR = Path(
    os.environ.get(
        "FORENSICS_EVIDENCE_DIR",
        Path(__file__).resolve().parents[1] / "forensics" / "evidence_store",
    )
)

# Severities that always warrant preserving evidence before any state change.
_PRESERVE_WORTHY_SEVERITIES = {"High", "Critical"}


def is_preserve_worthy(record: IncidentRecord) -> bool:
    """Whether this incident's state must be preserved before containment acts.

    High/Critical always qualify. So does any incident where the evidence shows
    a successful login during the attack -- a possible real compromise is always
    worth a snapshot, regardless of the headline severity.
    """
    if record.severity in _PRESERVE_WORTHY_SEVERITIES:
        return True
    evidence = (record.raw_payload or {}).get("detection", {}).get("evidence", {})
    return bool(evidence.get("successful_logins", 0))


def collect(record: IncidentRecord) -> Dict[str, Any]:
    """Build and persist the evidence snapshot for an incident."""
    incident_id = record.incident_id
    detection = (record.raw_payload or {}).get("detection", {})
    assessment = (record.raw_payload or {}).get("assessment", {})

    snapshot = {
        "incident_id": incident_id,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "preserve_worthy": is_preserve_worthy(record),
        "incident": {
            "status": record.status,
            "severity": record.severity,
            "incident_type": record.incident_type,
            "escalated": record.escalated,
        },
        "firewall_state_at_capture": {
            "simulated": True,
            "blocked_ips": blocked_ips(),
        },
        "detection_signals": {
            "pattern_type": detection.get("pattern_type"),
            "confidence": detection.get("confidence"),
            "reasoning": detection.get("reasoning"),
            "evidence": detection.get("evidence", {}),
            "sample_signals": detection.get("sample_signals", []),
        },
        "assessment_at_capture": assessment,
        "status_history": (record.raw_payload or {}).get("status_history", []),
    }

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    path = EVIDENCE_DIR / f"{incident_id}.json"
    path.write_text(json.dumps(snapshot, indent=2, default=str), encoding="utf-8")
    logger.info(
        "evidence snapshot for %s -> %s (preserve_worthy=%s, %d sample signals)",
        incident_id, path, snapshot["preserve_worthy"], len(snapshot["detection_signals"]["sample_signals"]),
    )
    snapshot["snapshot_path"] = str(path)
    return snapshot


def load_snapshot(incident_id: str) -> Dict[str, Any]:
    path = EVIDENCE_DIR / f"{incident_id}.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))
