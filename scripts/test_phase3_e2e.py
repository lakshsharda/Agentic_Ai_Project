"""Phase 3 end-to-end, driven through the live processes.

Requires the full stack running (target app + Detection + Threat Assessment +
Containment + On-Call + Forensics + Postgres).

PART A -- natural flow with a partial compromise:
    attack(with successes) -> Detection -> Threat Assessment -> parallel dispatch
    (Containment + On-Call + Forensics) -> Forensics preserves evidence, runs
    RCA, and -- because the evidence shows a successful login -- sends a real
    re-classification back to Threat Assessment, which revises the severity.
    Covers exit criteria 1, 2, 3, 4, 6, 7.

PART B -- re-classification that crosses the approval threshold (exit 5):
    a Medium incident already CONTAINED (no approval was needed at Medium) is
    re-examined by the REAL Forensics process; RCA finds a compromise and sends
    a real Forensics->Threat-Assessment re-classification; Threat Assessment
    raises it to Critical, which crosses the approval threshold and re-pages
    On-Call, visible in the audit trail as a re-open.

    The Medium incident in PART B is seeded by the test, because the reasoning
    agents correctly rate real escalated attacks as High+ -- a naturally Medium
    escalated incident does not occur. The re-classification A2A itself is fully
    real: Forensics process -> Threat Assessment process. Documented in the report.

    .venv-app\\Scripts\\python scripts/test_phase3_e2e.py
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shared.a2a_support import FORENSICS_URL, send_incident_message  # noqa: E402
from shared.guardrail import ACTION_COLLECT_EVIDENCE  # noqa: E402
from shared.schemas import (  # noqa: E402
    IncidentMessage,
    IncidentStatus,
    Severity,
    SystemName,
    new_incident_id,
)
from shared.store import IncidentStore  # noqa: E402

PY_APP = Path(__file__).resolve().parents[1] / ".venv-app" / "Scripts" / "python.exe"
SIM = Path(__file__).resolve().parents[1] / "scripts" / "attack_simulate.py"
ONCALL = "http://127.0.0.1:9104"

results = {}


def check(name, ok, detail=""):
    results[name] = ok
    print(f"[p3e2e] {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))
    return ok


def cards_up() -> bool:
    for port, name in [(9101, "Detection"), (9102, "Threat Assessment"), (9103, "Containment"),
                       (9104, "On-Call"), (9105, "Forensics")]:
        try:
            requests.get(f"http://127.0.0.1:{port}/.well-known/agent-card.json", timeout=5).raise_for_status()
        except Exception as exc:  # noqa: BLE001
            return check(f"{name} card reachable", False, str(exc))
    return check("all five agent cards reachable (Forensics is independent)", True)


def newest_id(store) -> Optional[str]:
    r = store.list_incidents(limit=1)
    return r[0].incident_id if r else None


def wait_until(fn, timeout=600, interval=3):
    deadline = time.time() + timeout
    while time.time() < deadline:
        v = fn()
        if v:
            return v
        time.sleep(interval)
    return None


def part_a(store) -> str:
    print("\n" + "=" * 70 + "\nPART A: natural compromise -> reclassification\n" + "=" * 70)
    before = newest_id(store)
    subprocess.run([str(PY_APP), str(SIM), "--pattern", "brute-force", "--intensity", "20",
                    "--successes", "3", "--single-source", "--delay", "0.02"],
                   check=True, capture_output=True)

    inc = wait_until(lambda: (lambda n: n if n and n != before else None)(newest_id(store)), timeout=300)
    if not check("attack produced a new incident", inc is not None, inc or "none"):
        return ""
    print(f"[p3e2e] incident {inc}")

    # Forensics preserved evidence (snapshot file + signal).
    rec = wait_until(lambda: store.get_incident(inc) if (store.get_incident(inc).raw_payload or {}).get("evidence") else None,
                     timeout=600)
    ev_sig = (store.get_incident(inc).raw_payload or {}).get("evidence", {})
    check("Forensics preserved evidence (evidence_preserved signal present)",
          bool(ev_sig.get("preserved")), f"by={ev_sig.get('by')} preserve_worthy={ev_sig.get('preserve_worthy')}")
    snap = Path(__file__).resolve().parents[1] / "forensics" / "evidence_store" / f"{inc}.json"
    check("evidence snapshot written to durable store", snap.exists(), str(snap.name))

    # Reached CONTAINED (approval via ack or timeout).
    check("incident reached CONTAINED", wait_until(lambda: store.get_incident(inc).status == "CONTAINED", timeout=600),
          f"status={store.get_incident(inc).status}")

    # RCA narrative.
    rca = wait_until(lambda: (store.get_incident(inc).raw_payload or {}).get("forensics"), timeout=600)
    narrative = (rca or {}).get("root_cause_narrative", "")
    check("Root Cause Analysis produced a substantial narrative", len(narrative.split()) >= 40,
          f"{len(narrative.split())} words")
    gen = (rca or {}).get("generation", {})
    check("RCA used the continuation-aware generation path", gen.get("mode") in ("single", "continuation", "retry"),
          f"mode={gen.get('mode')} rounds={gen.get('rounds')} continued={gen.get('continued')}")

    # Forensics evaluated re-classification. Whether it actually changes the
    # severity depends on the initial assessment (if TA already rated it
    # Critical there is nothing to raise) -- the brief says a request need not
    # result in a change. Part B demonstrates a guaranteed actual revision.
    forensics_block = wait_until(
        lambda: (store.get_incident(inc).raw_payload or {}).get("forensics"), timeout=600)
    check("Forensics evaluated re-classification (suggestion recorded)",
          forensics_block is not None and "reclassification_suggested" in forensics_block,
          f"suggested={forensics_block.get('reclassification_suggested') if forensics_block else None}")
    recl = (store.get_incident(inc).raw_payload or {}).get("reclassification")
    if recl is not None:
        tagged = [h for h in store.status_history(inc) if h.get("event") == "reclassified"]
        check("when revised, a reclassified entry is logged and status stays forward",
              bool(tagged) and store.get_incident(inc).status == "CONTAINED",
              f"entry={tagged[-1]['from']}->{tagged[-1]['to']}" if tagged else "none")

    # Recovery plan produced.
    plan = wait_until(lambda: (store.get_incident(inc).raw_payload or {}).get("recovery_plan"), timeout=600)
    check("Recovery Planning produced a plan + lift signal", plan is not None,
          f"safe_to_lift={plan.get('safe_to_lift') if plan else None}")

    print(f"\n[p3e2e] --- RCA narrative (PART A, {len(narrative.split())} words) ---\n{narrative[:600]}...\n")
    return narrative


def part_b(store, narrative_a: str) -> None:
    print("\n" + "=" * 70 + "\nPART B: reclassification crossing the approval threshold (re-page)\n" + "=" * 70)
    # Seed a Medium incident already CONTAINED (Medium needed no approval).
    mid = new_incident_id()
    store.create_incident(
        mid, status=IncidentStatus.DETECTED, severity=Severity.MEDIUM, incident_type="Brute Force",
        raw_payload={
            "origin": "phase3-test-seed",
            "detection": {"pattern_type": "brute_force", "confidence": 0.6,
                          "reasoning": "limited single-source attempts",
                          "evidence": {"total_requests": 14, "failed_logins": 11, "successful_logins": 2,
                                       "distinct_ips_with_failed_logins": 1, "distinct_usernames_targeted": 3,
                                       "top_failed_login_ips": [["198.51.100.77", 11]],
                                       "top_targeted_usernames": [["admin", 5]]}},
        })
    # Walk it to CONTAINED the honest way (no approval needed at Medium).
    store.advance_status(mid, IncidentStatus.CANDIDATE, by_system="threat_assessment")
    store.advance_status(mid, IncidentStatus.ASSESSED, by_system="threat_assessment", severity=Severity.MEDIUM)
    store.advance_status(mid, IncidentStatus.DISPATCHED, by_system="threat_assessment")
    store.advance_status(mid, IncidentStatus.CONTAINED, by_system="containment",
                         payload={"containment": {"blocked_ips": ["198.51.100.77"], "state": "EXECUTED"}})
    print(f"[p3e2e] seeded Medium incident {mid} at CONTAINED (no approval was required at Medium)")

    # Kick the REAL Forensics process to examine it (sent as Threat Assessment,
    # the authorized dispatcher). Everything downstream is real inter-process A2A.
    import asyncio

    async def _kick():
        msg = IncidentMessage(incident_id=mid, source_system=SystemName.THREAT_ASSESSMENT,
                              target_system=SystemName.FORENSICS,
                              payload={"action": ACTION_COLLECT_EVIDENCE})
        return await send_incident_message(msg, peer_base_url=FORENSICS_URL)

    asyncio.run(_kick())
    print("[p3e2e] Forensics kicked; awaiting real Forensics->Threat-Assessment reclassification ...")

    # Wait for TA to raise severity and re-open.
    raised = wait_until(lambda: store.get_incident(mid).severity in ("High", "Critical"), timeout=600)
    rec = store.get_incident(mid)
    check("severity raised across the approval threshold", rec.severity in ("High", "Critical"),
          f"Medium -> {rec.severity}")
    tagged = [h for h in store.status_history(mid) if h.get("event") == "reclassified"]
    check("reclassified entry logged, status stayed CONTAINED",
          bool(tagged) and rec.status == "CONTAINED", f"status={rec.status}")
    reopened = (rec.raw_payload or {}).get("reopened")
    check("approval was re-opened (distinct from original)", reopened is not None, str(reopened))
    appr = (rec.raw_payload or {}).get("approval", {})
    check("prior approval invalidated (re-page requires fresh approval)", appr.get("approved") is False,
          f"approved={appr.get('approved')}")

    # On-Call should have been re-paged. Threat Assessment writes the new severity first and
    # re-pages afterwards (the page includes an LLM-composed message; measured ~13s later), so wait
    # for the page to land before asserting.
    wait_until(lambda: ((store.get_incident(mid).raw_payload or {}).get("on_call") or {}).get("paged"),
               timeout=120)
    rec = store.get_incident(mid)
    oncall = (rec.raw_payload or {}).get("on_call", {})
    check("On-Call was re-paged for the escalation", bool(oncall.get("paged")), str(oncall.get("contact")))

    narrative_b = (rec.raw_payload or {}).get("forensics", {}).get("root_cause_narrative", "")
    if narrative_a and narrative_b:
        check("RCA narratives differ across incidents (not boilerplate)",
              narrative_a.strip() != narrative_b.strip(),
              f"A={len(narrative_a.split())}w B={len(narrative_b.split())}w")

    store.delete_incident(mid)


def main() -> int:
    store = IncidentStore()
    if not cards_up():
        print("\n[p3e2e] start the full stack first (scripts/start_all.ps1)")
        return 1
    narrative_a = part_a(store)
    part_b(store, narrative_a)

    failed = [k for k, v in results.items() if not v]
    print(f"\n[p3e2e] {len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print("[p3e2e] FAILED: " + ", ".join(failed)); return 1
    print("[p3e2e] ALL PASSED -- Forensics, evidence gate, RCA, feedback loop, re-page, recovery")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
