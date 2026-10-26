"""Phase 2, Task 2 exit check: the guardrail physically blocks an un-approved action.

Drives the exact gate-then-execute sequence Containment uses, for a
High-severity incident with no approval signal, and confirms the real side
effect (firewall block) does NOT happen -- it is held pending, not skipped and
not silently allowed. Then records a timeout approval and confirms the gate
now permits execution.

    .venv-app\\Scripts\\python scripts/test_guardrail_block.py

No LLM, no servers; uses a throwaway firewall-state file and a temp incident.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Point the firewall at a throwaway file BEFORE importing it.
_tmp = Path(tempfile.mkdtemp()) / "fw_state.json"
os.environ["CONTAINMENT_FIREWALL_STATE"] = str(_tmp)

from containment import firewall  # noqa: E402
from shared.guardrail import (  # noqa: E402
    ACTION_REQUEST_ACTION,
    APPROVAL_TIMEOUT,
    evaluate_action_gate,
    record_approval,
)
from shared.schemas import IncidentStatus, Severity, SystemName, new_incident_id  # noqa: E402
from shared.store import IncidentStore  # noqa: E402

results = {}


def check(name, ok, detail=""):
    results[name] = ok
    print(f"[guardrail] {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def contain_once(store, incident_id, severity, offending):
    """The real gated sequence: gate, then only block if allowed."""
    gate = evaluate_action_gate(
        store,
        from_system=SystemName.THREAT_ASSESSMENT.value,
        to_system=SystemName.CONTAINMENT.value,
        action_type=ACTION_REQUEST_ACTION,
        severity=severity,
        incident_id=incident_id,
    )
    if gate.allowed:
        firewall.block_ips(offending, incident_id=incident_id, reason="test")
        return "EXECUTED"
    return "PENDING" if gate.pending_approval else "BLOCKED"


def main() -> int:
    store = IncidentStore()
    incident_id = new_incident_id()
    offending = ["203.0.113.50", "203.0.113.51"]

    store.create_incident(
        incident_id, status=IncidentStatus.ASSESSED, severity=Severity.HIGH,
        incident_type="Brute Force", raw_payload={"origin": "guardrail-test"},
    )
    print(f"[guardrail] test incident {incident_id} at High severity, no approval\n")

    before = set(firewall.blocked_ips())

    # 1. High severity, no approval -> must NOT execute.
    outcome = contain_once(store, incident_id, "High", offending)
    after = set(firewall.blocked_ips())
    check("un-approved High action is held pending, not executed", outcome == "PENDING", f"outcome={outcome}")
    check("the real firewall action did NOT run", before == after,
          f"blocked set unchanged: {sorted(after)}")
    check("no offending IP got blocked", not (set(offending) & after))

    # 2. Record a timeout approval -> gate now permits, action executes.
    record_approval(store, incident_id, approved_by=APPROVAL_TIMEOUT, provenance=APPROVAL_TIMEOUT,
                    note="test auto-approval")
    outcome2 = contain_once(store, incident_id, "High", offending)
    after2 = set(firewall.blocked_ips())
    check("after approval the action executes", outcome2 == "EXECUTED", f"outcome={outcome2}")
    check("offending IPs are now blocked", set(offending).issubset(after2), f"blocked={sorted(after2)}")

    # 3. A Low-severity incident needs no approval -> executes immediately.
    low_id = new_incident_id()
    store.create_incident(low_id, status=IncidentStatus.ASSESSED, severity=Severity.LOW)
    outcome3 = contain_once(store, low_id, "Low", ["203.0.113.90"])
    check("Low severity executes without approval", outcome3 == "EXECUTED", f"outcome={outcome3}")

    store.delete_incident(incident_id)
    store.delete_incident(low_id)

    failed = [k for k, v in results.items() if not v]
    print(f"\n[guardrail] {len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print("[guardrail] FAILED: " + ", ".join(failed))
        return 1
    print("[guardrail] ALL PASSED -- the gate physically blocks un-approved actions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
