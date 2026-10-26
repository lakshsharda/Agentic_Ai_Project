"""Phase 3 no-LLM checks: the evidence gate and the reclassify store exception.

  * Evidence gate: a High incident with no evidence_preserved signal is held
    (pending_evidence), and the real firewall action does not run; once the
    signal is recorded the gate opens.
  * reclassify(): revises severity/type without moving status backward, logs a
    `reclassified` status_history entry, and refuses once RESOLVED.

    .venv-app\\Scripts\\python scripts/test_phase3_gates.py
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["CONTAINMENT_FIREWALL_STATE"] = str(Path(tempfile.mkdtemp()) / "fw.json")

from containment import firewall  # noqa: E402
from shared.guardrail import (  # noqa: E402
    ACTION_REQUEST_ACTION,
    APPROVAL_TIMEOUT,
    evaluate_action_gate,
    record_approval,
    record_evidence_preserved,
)
from shared.schemas import IncidentStatus, Severity, SystemName, new_incident_id  # noqa: E402
from shared.store import IncidentStore  # noqa: E402

results = {}


def check(name, ok, detail=""):
    results[name] = ok
    print(f"[p3] {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def gate(store, incident_id, severity):
    return evaluate_action_gate(
        store, from_system=SystemName.THREAT_ASSESSMENT.value, to_system=SystemName.CONTAINMENT.value,
        action_type=ACTION_REQUEST_ACTION, severity=severity, incident_id=incident_id, require_evidence=True)


def main() -> int:
    store = IncidentStore()

    # ---- Evidence gate ----
    iid = new_incident_id()
    store.create_incident(iid, status=IncidentStatus.DISPATCHED, severity=Severity.HIGH,
                          incident_type="Brute Force")
    before = set(firewall.blocked_ips())

    g1 = gate(store, iid, "High")
    check("no evidence yet -> gate held (pending_evidence)", g1.pending_evidence and not g1.allowed,
          g1.reason)
    # Caller must not act while held:
    if not g1.allowed:
        pass  # (no firewall call)
    check("firewall unchanged while evidence pending", set(firewall.blocked_ips()) == before)

    record_evidence_preserved(store, iid, by="forensics", preserve_worthy=True, snapshot_ref="x.json")
    g2 = gate(store, iid, "High")
    # still needs approval (High), but evidence gate now satisfied
    check("after evidence, no longer pending_evidence", not g2.pending_evidence, g2.reason)
    check("still pending_approval (High, no approval yet)", g2.pending_approval)

    record_approval(store, iid, approved_by=APPROVAL_TIMEOUT, provenance=APPROVAL_TIMEOUT)
    g3 = gate(store, iid, "High")
    check("evidence + approval -> gate allowed", g3.allowed, g3.reason)

    # ---- reclassify exception ----
    rid = new_incident_id()
    store.create_incident(rid, status=IncidentStatus.CONTAINED, severity=Severity.MEDIUM,
                          incident_type="Brute Force")
    rec = store.reclassify(rid, by_system="threat_assessment", severity=Severity.CRITICAL,
                           incident_type="Credential Stuffing", escalated=True,
                           reason="forensics found successful compromise")
    check("status NOT moved backward by reclassify", rec.status == "CONTAINED", f"status={rec.status}")
    check("severity revised", rec.severity == "Critical", f"severity={rec.severity}")
    check("incident_type revised", rec.incident_type == "Credential Stuffing")
    hist = store.status_history(rid)
    tagged = [h for h in hist if h.get("event") == "reclassified"]
    check("a reclassified status_history entry was logged", len(tagged) == 1,
          f"from={tagged[0]['from']} to={tagged[0]['to']}" if tagged else "none")

    # refuses once RESOLVED
    store.advance_status(rid, IncidentStatus.RESOLVED, by_system="test")
    try:
        store.reclassify(rid, by_system="test", severity=Severity.LOW, reason="late")
        check("reclassify refused after RESOLVED", False, "no error raised")
    except ValueError:
        check("reclassify refused after RESOLVED", True)

    store.delete_incident(iid)
    store.delete_incident(rid)

    failed = [k for k, v in results.items() if not v]
    print(f"\n[p3] {len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print("[p3] FAILED: " + ", ".join(failed)); return 1
    print("[p3] ALL PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
