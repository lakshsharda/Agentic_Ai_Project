"""Phase 1 end-to-end test, driven entirely through the live processes.

Assumes the full stack is already running in separate processes:

    .venv-app\\Scripts\\python  target_app/app.py                  # :8080
    .venv-adk\\Scripts\\python  -m threat_assessment.server        # :9102
    .venv-adk\\Scripts\\python  -m detection.server                # :9101

Then:

    .venv-app\\Scripts\\python scripts/test_phase1_e2e.py

It fires the attack simulator at the target app and waits for the incident to
appear in the store and progress to ASSESSED -- so a pass depends on the whole
chain working (log -> Detection poll loop -> noise filter -> A2A -> Threat
Assessment -> store), with nothing in this script touching agent code directly.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shared.store import IncidentStore  # noqa: E402

DETECTION = "http://127.0.0.1:9101"
THREAT = "http://127.0.0.1:9102"
CARD = "/.well-known/agent-card.json"
PY_APP = Path(__file__).resolve().parents[1] / ".venv-app" / "Scripts" / "python.exe"
SIM = Path(__file__).resolve().parents[1] / "scripts" / "attack_simulate.py"

results = {}


def check(name, ok, detail=""):
    results[name] = ok
    print(f"[e2e] {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))
    return ok


def newest_incident_id(store: IncidentStore) -> Optional[str]:
    rows = store.list_incidents(limit=1)
    return rows[0].incident_id if rows else None


def main() -> int:
    store = IncidentStore()

    # --- cards up and distinct ------------------------------------------
    try:
        dcard = requests.get(DETECTION + CARD, timeout=10).json()
        tcard = requests.get(THREAT + CARD, timeout=10).json()
    except Exception as exc:  # noqa: BLE001
        check("both agent cards reachable", False, str(exc))
        print("\n[e2e] start the stack first (see this file's docstring)")
        return 1
    check("both agent cards reachable", True, f"{dcard['name']} / {tcard['name']}")
    check("cards are distinct real systems",
          dcard["name"] != tcard["name"]
          and "scaffold" not in dcard["documentationUrl"]
          and "scaffold" not in tcard["documentationUrl"])

    # --- baseline first: should NOT create an incident ------------------
    before_id = newest_incident_id(store)
    print("\n[e2e] firing BASELINE traffic (expect no new incident) ...")
    subprocess.run([str(PY_APP), str(SIM), "--pattern", "baseline", "--intensity", "16",
                    "--delay", "0.01"], check=True, capture_output=True)
    # give Detection a few poll cycles to see and judge it
    time.sleep(12)
    after_baseline = newest_incident_id(store)
    check("baseline produced no new incident", after_baseline == before_id,
          f"newest still {after_baseline}")

    # --- attack: SHOULD create an incident that reaches ASSESSED --------
    print("\n[e2e] firing BRUTE-FORCE traffic (expect a new ASSESSED incident) ...")
    subprocess.run([str(PY_APP), str(SIM), "--pattern", "brute-force", "--intensity", "40",
                    "--delay", "0.01"], check=True, capture_output=True)

    # Generous: on the Gemini free tier a 429 triggers a ~60s backoff, and one
    # incident fires several model calls, so an assessment can legitimately
    # take a couple of minutes under quota pressure.
    print("[e2e] waiting for the incident to appear and reach ASSESSED (up to 240s) ...")
    deadline = time.time() + 240
    incident_id = None
    record = None
    while time.time() < deadline:
        newest = newest_incident_id(store)
        if newest and newest != before_id:
            incident_id = newest
            record = store.get_incident(incident_id)
            if record and record.status == "ASSESSED":
                break
        time.sleep(3)

    if not check("a new incident was created by the attack", incident_id is not None,
                 incident_id or "none appeared"):
        return 1

    record = store.get_incident(incident_id)
    check("incident reached ASSESSED", record.status == "ASSESSED", f"status={record.status}")
    check("severity populated by the classifier", bool(record.severity),
          f"severity={record.severity}")
    check("severity is from the allowed set",
          record.severity in {"Low", "Medium", "High", "Critical"})
    check("incident_type populated", bool(record.incident_type), f"type={record.incident_type}")

    history = store.status_history(incident_id)
    seq = [h["to"] for h in history if "event" not in h]
    check("status progression is DETECTED -> CANDIDATE -> ASSESSED",
          seq == ["DETECTED", "CANDIDATE", "ASSESSED"], f"progression={seq}")
    check("Detection created it, Threat Assessment advanced it",
          history and history[0]["by"] == "detection"
          and any(h["by"] == "threat_assessment" for h in history))

    assessment = (record.raw_payload or {}).get("assessment", {})
    check("assessment carries a non-empty rationale", bool(assessment.get("rationale")),
          (assessment.get("rationale") or "")[:80])
    check("correlation ran against threat intel",
          "correlation" in assessment and "intel_summary" in assessment.get("correlation", {}))

    print("\n[e2e] incident summary:")
    print(f"      {record.summary()}")
    print(f"      rationale: {assessment.get('rationale', '')[:160]}")

    failed = [k for k, v in results.items() if not v]
    print(f"\n[e2e] {len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print("[e2e] FAILED: " + ", ".join(failed))
        return 1
    print(f"[e2e] ALL PASSED -- incident {incident_id} traced from attack to ASSESSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
