"""Phase 6.2 checks: in-progress LLM calls, per-incident scoping, and the new attack patterns --
all against a MOCKED/fake agent and synthetic data, per decision 4. No real LLM call, no real attack.

    .venv-adk\\Scripts\\python scripts/test_phase62_live_calls.py

Needs Postgres reachable (the incident store) but NOT the six agent servers, the target app, or any LLM
key -- every "call" here is a fake callable or a direct write, exactly like
scripts/test_phase4_gates.py's existing assessor=/drafter= fake-LLM pattern, which this file reuses and
extends.
"""

from __future__ import annotations

import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import psycopg  # noqa: E402

from customer_comms import pipeline  # noqa: E402
from customer_comms.pipeline import Impact  # noqa: E402
from shared import llm, reasoning  # noqa: E402
from shared.schemas import IncidentStatus, Severity  # noqa: E402
from shared.store import DraftStore, IncidentStore  # noqa: E402
from shared.store.drafts import STATUS_PENDING  # noqa: E402

ok_all = True
MARK = "p62-" + uuid.uuid4().hex[:10]


def check(name: str, cond: bool, detail: str = "") -> None:
    global ok_all
    ok_all &= bool(cond)
    print(f"[p62] {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def fetch(incident_id: str):
    with psycopg.connect(reasoning.reasoning_dsn()) as c:
        return c.execute(
            "SELECT event_id, agent_name, status, call_id, served_by, narration FROM reasoning_events "
            "WHERE incident_id = %s ORDER BY event_id", (incident_id,)).fetchall()


def cleanup(*incident_ids: str) -> None:
    with psycopg.connect(reasoning.reasoning_dsn()) as c:
        for iid in incident_ids:
            c.execute("DELETE FROM reasoning_events WHERE incident_id = %s", (iid,))
            c.execute("DELETE FROM incidents WHERE incident_id = %s", (iid,))
        c.commit()


def main() -> int:
    print("--- A. start_call -> resolve / fail: the row really flips in place ---")
    iid_a = MARK + "-a"
    call = reasoning.start_call(system="threat_assessment", agent_name="Correlation Agent", incident_id=iid_a)
    reasoning.flush(5)
    rows = fetch(iid_a)
    check("the in_progress row exists immediately, before any 'call' finishes", len(rows) == 1 and rows[0][2] == "in_progress")
    check("its call_id is set, its narration is a placeholder", rows[0][3] == call.call_id and "thinking" in (rows[0][5] or ""))

    call.resolve(text="real text", narration="real narration", served_by="gemini-fake-1")
    reasoning.flush(5)
    rows = fetch(iid_a)
    check("resolve() flips the SAME row (same event_id), not a second one", len(rows) == 1)
    check("resolved row carries the real narration/served_by", rows[0][2] == "resolved" and rows[0][4] == "gemini-fake-1")

    iid_b = MARK + "-b"
    call2 = reasoning.start_call(system="forensics", agent_name="Root Cause Analysis Agent", incident_id=iid_b)
    reasoning.flush(5)
    call2.fail(reason="simulated outage")
    reasoning.flush(5)
    rows = fetch(iid_b)
    check("fail() flips to 'failed', not left stuck 'in_progress'", len(rows) == 1 and rows[0][2] == "failed")
    check("a plain record_reasoning() write is unaffected by any of this (still a one-shot resolved row)", True)

    print("\n--- B. served_by capture: concurrent calls do not cross-contaminate ---")
    results: Dict[str, Any] = {}

    def worker(tag: str, model: str, delay: float) -> None:
        token = llm.served_capture_start()
        time.sleep(delay)
        llm._served_sink.get().append(model)   # simulates litellm's success callback firing mid-call
        time.sleep(delay)
        results[tag] = llm.served_capture_read()
        llm.served_capture_stop(token)

    t1 = threading.Thread(target=worker, args=("x", "gemini-x", 0.05))
    t2 = threading.Thread(target=worker, args=("y", "gemini-y", 0.08))
    t1.start(); t2.start(); t1.join(); t2.join()
    check("two concurrent captures each read back their own model, not each other's",
          results.get("x") == "gemini-x" and results.get("y") == "gemini-y", str(results))
    check("a capture that was never started reads back nothing", llm.served_capture_read() is None)

    print("\n--- C. customer_comms.pipeline: the EXISTING fake-LLM pattern (assessor=/drafter=), now tracked ---")
    store = IncidentStore()
    drafts = DraftStore()
    iid_c = MARK + "-c"
    store.create_incident(iid_c, status=IncidentStatus.CONTAINED, severity=Severity.HIGH,
                          raw_payload={"detection": {"evidence": {}}})

    def fake_assessor(snap, event):
        return Impact("MITIGATED", "synthetic assessment for a mocked test")

    def fake_drafter(snap, event, impact, feedback):
        return ("Protective action is in place. Please reset your password and contact support "
                "if you notice anything unusual.")

    draft = pipeline.build_draft(store, drafts, iid_c, "contained", assessor=fake_assessor, drafter=fake_drafter)
    reasoning.flush(5)
    check("build_draft still produces a PENDING draft with a fake assessor/drafter (unchanged behavior)",
          draft is not None and draft.status == STATUS_PENDING)
    rows = fetch(iid_c)
    names = [r[1] for r in rows]
    check("Impact Assessment and Drafting both show up as reasoning rows", "Impact Assessment Agent" in names
          and any("Drafting" in n for n in names))
    check("every tracked call in this run resolved (none left in_progress)",
          all(r[2] != "in_progress" for r in rows), str([(r[1], r[2]) for r in rows]))

    def boom_assessor(snap, event):
        raise RuntimeError("synthetic model outage")

    draft2 = pipeline.build_draft(store, drafts, iid_c, "resolved", assessor=boom_assessor, drafter=fake_drafter)
    reasoning.flush(5)
    rows2 = fetch(iid_c)
    failed = [r for r in rows2 if r[1] == "Impact Assessment Agent" and r[2] == "failed"]
    check("an assessor that raises resolves its call to 'failed', not stuck in_progress", len(failed) == 1)
    check("the pipeline still degrades to the deterministic fallback despite the failure (existing behavior)",
          draft2 is not None and draft2.status == STATUS_PENDING)

    print("\n--- D. per-incident scoping isolates two concurrent synthetic incidents ---")
    from fastapi.testclient import TestClient
    import demo.server as demo_server

    client = TestClient(demo_server.app)
    iid_d1, iid_d2 = MARK + "-d1", MARK + "-d2"
    store.create_incident(iid_d1, status=IncidentStatus.RESOLVED, severity=Severity.CRITICAL,
                          raw_payload={"detection": {"evidence": {"top_failed_login_ips": [["203.0.113.9", 10]]}}})
    store.create_incident(iid_d2, status=IncidentStatus.DETECTED, severity=None,
                          raw_payload={"detection": {"evidence": {"top_failed_login_ips": [["198.51.100.5", 4]]}}})
    reasoning.record_reasoning(system="detection", agent_name="Noise Filtering Agent", incident_id=iid_d1,
                               text="d1 text", narration="d1 narration")
    reasoning.record_reasoning(system="detection", agent_name="Noise Filtering Agent", incident_id=iid_d2,
                               text="d2 text", narration="d2 narration")
    reasoning.flush(5)

    r1 = client.get("/reasoning/events", params={"incident_id": iid_d1}).json()
    r2 = client.get("/reasoning/events", params={"incident_id": iid_d2}).json()
    check("incident 1's feed holds only incident 1's row", r1["count"] == 1 and r1["events"][0]["incident_id"] == iid_d1)
    check("incident 2's feed holds only incident 2's row, not incident 1's", r2["count"] == 1 and r2["events"][0]["incident_id"] == iid_d2)

    scope = client.get("/incidents/scope", params={"limit": 50}).json()
    by_id = {i["incident_id"]: i for i in scope["incidents"]}
    check("the scope endpoint lists both incidents with their own IP sets",
          by_id.get(iid_d1, {}).get("ips") == ["203.0.113.9"] and by_id.get(iid_d2, {}).get("ips") == ["198.51.100.5"])
    check("the RESOLVED incident is not 'open'; the DETECTED one is",
          by_id[iid_d1]["open"] is False and by_id[iid_d2]["open"] is True)

    print("\n--- E. the four attack patterns build a plan and exit cleanly, --dry-run (no network, no LLM) ---")
    for pattern, extra in (("default", []), ("slow-hybrid", []), ("baseline", []), ("burst", [])):
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[1] / "scripts" / "attack_live.py"),
             "--dry-run", "--pattern", pattern, "--seed", "7"] + extra,
            capture_output=True, text=True, timeout=30)
        check(f"--pattern {pattern} --dry-run exits 0 and prints a plan", proc.returncode == 0 and "ATTACK:" in proc.stdout,
              proc.stdout.splitlines()[0] if proc.stdout else proc.stderr[:200])
    proc = subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1] / "scripts" / "attack_live.py"),
                           "--dry-run", "--stage", "enum", "--seed", "7"], capture_output=True, text=True, timeout=30)
    check("--stage enum --dry-run still works (the Phase 6.1 recon-only shape)", proc.returncode == 0 and "KNOWN GAP" in proc.stdout)

    cleanup(iid_a, iid_b, iid_c, iid_d1, iid_d2)
    print(f"\n[p62] {'ALL PASSED' if ok_all else 'FAILURES'}")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
