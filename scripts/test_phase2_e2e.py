"""Phase 2 full-chain end-to-end test, driven through the live processes.

Requires the whole stack running (target app + Detection + Threat Assessment +
Containment + On-Call + Postgres). Fires the attack simulator and follows one
incident all the way:

    attack -> Detection -> Threat Assessment -> parallel dispatch
           -> On-Call pages -> (human ack | timeout) -> Containment acts
           -> status reported back -> CONTAINED, all in the store.

Runs two incidents: one resolved by human acknowledgment, one by escalation
timeout -- so both approval provenances are demonstrated.

    .venv-app\\Scripts\\python scripts/test_phase2_e2e.py
    .venv-app\\Scripts\\python scripts/test_phase2_e2e.py --path ack
    .venv-app\\Scripts\\python scripts/test_phase2_e2e.py --path timeout
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

ONCALL = "http://127.0.0.1:9104"
PY_APP = Path(__file__).resolve().parents[1] / ".venv-app" / "Scripts" / "python.exe"
SIM = Path(__file__).resolve().parents[1] / "scripts" / "attack_simulate.py"

results = {}


def check(name, ok, detail=""):
    results[name] = ok
    print(f"[e2e] {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))
    return ok


def cards_up() -> bool:
    for port, name in [(9101, "Detection"), (9102, "Threat Assessment"),
                       (9103, "Containment"), (9104, "On-Call")]:
        try:
            requests.get(f"http://127.0.0.1:{port}/.well-known/agent-card.json", timeout=5).raise_for_status()
        except Exception as exc:  # noqa: BLE001
            check(f"{name} card reachable", False, str(exc))
            return False
    check("all four agent cards reachable", True)
    return True


def newest_id(store) -> Optional[str]:
    rows = store.list_incidents(limit=1)
    return rows[0].incident_id if rows else None


def fire_attack(intensity=40):
    subprocess.run([str(PY_APP), str(SIM), "--pattern", "brute-force",
                    "--intensity", str(intensity), "--delay", "0.01"],
                   check=True, capture_output=True)


def wait_for_new_incident(store, before, timeout=300) -> Optional[str]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        nid = newest_id(store)
        if nid and nid != before:
            return nid
        time.sleep(2)
    return None


def wait_for_paged(store, incident_id, timeout=400) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        rec = store.get_incident(incident_id)
        if rec and (rec.raw_payload or {}).get("on_call", {}).get("paged"):
            return True
        time.sleep(1.5)
    return False


def wait_for_status(store, incident_id, status, timeout=600) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        rec = store.get_incident(incident_id)
        if rec and rec.status == status:
            return True
        time.sleep(2)
    return False


def run_ack_path(store) -> None:
    print("\n" + "=" * 70 + "\nPATH A: human acknowledgment before timeout\n" + "=" * 70)
    before = newest_id(store)
    fire_attack()
    incident_id = wait_for_new_incident(store, before)
    if not check("attack produced a new incident", incident_id is not None, incident_id or "none"):
        return
    print(f"[e2e] incident {incident_id}")

    check("incident reached DISPATCHED (parallel fan-out)",
          wait_for_status(store, incident_id, "DISPATCHED", timeout=600)
          or (store.get_incident(incident_id).status in ("CONTAINED",)),
          f"status={store.get_incident(incident_id).status}")

    paged = wait_for_paged(store, incident_id)
    check("On-Call paged the responder", paged)

    # Ack immediately (well within the escalation window).
    try:
        r = requests.post(f"{ONCALL}/ack", params={"incident_id": incident_id, "who": "alice@soc"}, timeout=10)
        acked = r.status_code == 200 and r.json().get("acknowledged")
    except Exception as exc:  # noqa: BLE001
        acked = False
        print(f"   ack error: {exc}")
    check("human ack accepted by On-Call", acked)

    check("incident reached CONTAINED after ack",
          wait_for_status(store, incident_id, "CONTAINED", timeout=400),
          f"status={store.get_incident(incident_id).status}")

    rec = store.get_incident(incident_id)
    approval = (rec.raw_payload or {}).get("approval", {})
    check("approval provenance is human", approval.get("provenance") == "human",
          f"provenance={approval.get('provenance')} by={approval.get('approved_by')}")
    containment = (rec.raw_payload or {}).get("containment", {})
    check("Containment executed a (simulated) block", containment.get("state") == "EXECUTED",
          f"blocked={containment.get('blocked_ips')}")

    seq = [h["to"] for h in store.status_history(incident_id) if "event" not in h]
    check("full lifecycle recorded",
          seq == ["DETECTED", "CANDIDATE", "ASSESSED", "DISPATCHED", "CONTAINED"], f"{seq}")
    print(f"[e2e] {rec.summary()}")


def run_timeout_path(store) -> None:
    print("\n" + "=" * 70 + "\nPATH B: no ack -> escalation timeout auto-approval\n" + "=" * 70)
    before = newest_id(store)
    fire_attack()
    incident_id = wait_for_new_incident(store, before)
    if not check("second attack produced a new incident", incident_id is not None, incident_id or "none"):
        return
    print(f"[e2e] incident {incident_id} -- NOT acking; waiting for timeout")

    check("On-Call paged (timeout path)", wait_for_paged(store, incident_id))

    # Do nothing; the escalation timer should auto-approve and Containment resume.
    check("incident reached CONTAINED via timeout",
          wait_for_status(store, incident_id, "CONTAINED", timeout=400),
          f"status={store.get_incident(incident_id).status}")

    rec = store.get_incident(incident_id)
    approval = (rec.raw_payload or {}).get("approval", {})
    check("approval provenance is timeout_escalation",
          approval.get("provenance") == "timeout_escalation",
          f"provenance={approval.get('provenance')} by={approval.get('approved_by')}")
    print(f"[e2e] {rec.summary()}")


def main() -> int:
    which = "both"
    if "--path" in sys.argv:
        which = sys.argv[sys.argv.index("--path") + 1]

    store = IncidentStore()
    if not cards_up():
        print("\n[e2e] start the full stack first (scripts/start_all.ps1)")
        return 1

    if which in ("ack", "both"):
        run_ack_path(store)
    if which in ("timeout", "both"):
        run_timeout_path(store)

    failed = [k for k, v in results.items() if not v]
    print(f"\n[e2e] {len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print("[e2e] FAILED: " + ", ".join(failed))
        return 1
    print("[e2e] ALL PASSED -- full Phase 2 chain works end to end")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
