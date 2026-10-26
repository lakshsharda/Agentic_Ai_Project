"""Phase 5 proof: the unified trace table, the denied-call trace, and the read-only dashboard.

Needs the full stack (scripts/start_all.ps1, which now also starts the dashboard on :8090).

    .venv-adk\\Scripts\\python scripts/test_phase5_dashboard.py [--skip-timeout] [--skip-reclassify]

What it does, in order:
  A. degrade-to-warning: point the trace writer at a dead connection string and show that
     record_trace never raises or blocks, that check_authority / advance_status still do exactly
     the right thing, that one warning is logged, and that tracing recovers afterwards.
  B. scrubbing: an IP / internal host / username-keyed field handed to record_trace is not stored.
  C. LIVE incident 1 (human ack): a real attack through all six systems, a human /ack, a human
     /signoff -> every system's rows are in trace_events, in a sensible order, queried directly.
  D. LIVE incident 2 (no ack): the timeout-escalation path is traced as `timeout_escalation`.
  E. Denied calls over the wire and in-process -> `authority_denied` rows, decision `blocked`.
  F. Feedback loop: Forensics -> Threat Assessment shows up as reclassify_sent / reclassify_received.
  G. Dashboard backend vs the table: /incidents, /incidents/<id>/timeline, /live, store-down -> 503.
  H. No attacker IP, username or internal host anywhere in the trace table or the API output.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import psycopg
import requests
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from shared.a2a_support import COMMS_URL, FORENSICS_URL, send_incident_message  # noqa: E402
from shared.comms_validation import _INTERNAL_HOST, _IPV4, _IPV6, sensitive_terms  # noqa: E402
from shared.guardrail import (  # noqa: E402
    ACTION_COLLECT_EVIDENCE, ACTION_NOTIFY_STATUS, ACTION_PAGE, check_authority,
)
from shared.schemas import IncidentMessage, IncidentStatus, Severity, SystemName, new_incident_id  # noqa: E402
from shared.store import DraftStore, IncidentStore, store_dsn  # noqa: E402
from shared import trace  # noqa: E402

PY_APP = ROOT / ".venv-app" / "Scripts" / "python.exe"
SIM = ROOT / "scripts" / "attack_simulate.py"
ONCALL = "http://127.0.0.1:9104"
COMMS = "http://127.0.0.1:9106"
DASH = "http://127.0.0.1:8090"

store = IncidentStore()
drafts = DraftStore()
results: Dict[str, bool] = {}


def check(name: str, ok: bool, detail: str = "") -> bool:
    results[name] = bool(ok)
    print(f"[p5] {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)
    return bool(ok)


def wait_until(fn, timeout=300, interval=3):
    deadline = time.time() + timeout
    while time.time() < deadline:
        v = fn()
        if v:
            return v
        time.sleep(interval)
    return None


def q(sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
    with psycopg.connect(store_dsn(), row_factory=dict_row) as conn:
        return conn.execute(sql, params).fetchall()


def rows_for(iid: str) -> List[Dict[str, Any]]:
    return q('SELECT * FROM trace_events WHERE incident_id = %s ORDER BY "timestamp", event_id', (iid,))


def newest_id() -> Optional[str]:
    rs = store.list_incidents(limit=1)
    return rs[0].incident_id if rs else None


def one_line(rows, types=None) -> str:
    return "; ".join(f"{r['from_system']}:{r['event_type']}/{r['decision']}" for r in rows
                     if not types or r["event_type"] in types)


# --------------------------------------------------------------------------
# A. degrade to a warning
# --------------------------------------------------------------------------

class _Capture(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.WARNING)
        self.records: List[logging.LogRecord] = []

    def emit(self, record):
        self.records.append(record)


def part_a_degrade():
    print("\n--- A. a failing trace writer must never block or alter a real action ---")
    marker = f"p5-degrade-{new_incident_id()[-8:]}"
    cap = _Capture()
    tlog = logging.getLogger("shared.trace")
    tlog.addHandler(cap)
    old_level = tlog.level
    tlog.setLevel(logging.WARNING)
    trace._last_warn = 0.0
    os.environ["TRACE_STORE_DSN"] = "postgresql://crisis:wrong@127.0.0.1:1/none?connect_timeout=1"
    iid = new_incident_id()
    store.create_incident(iid, status=IncidentStatus.DETECTED, severity=Severity.HIGH, incident_type="x")
    try:
        t0 = time.perf_counter()
        trace.record_trace(from_system="detection", event_type="degrade_probe", incident_id=marker,
                           summary="written while the trace store is unreachable")
        dt = time.perf_counter() - t0
        check("record_trace returns immediately with an unreachable trace store", dt < 0.2, f"{dt * 1000:.1f} ms")

        # The real decisions, with the broken writer in the background.
        allowed = check_authority("containment", "customer_comms", ACTION_NOTIFY_STATUS, incident_id=iid)
        denied = check_authority("on_call", "customer_comms", ACTION_NOTIFY_STATUS, incident_id=iid)
        check("check_authority still answers correctly (allowed pair True, denied pair False)",
              allowed is True and denied is False, f"allowed={allowed} denied={denied}")
        rec = store.advance_status(iid, IncidentStatus.CANDIDATE, by_system="threat_assessment")
        check("advance_status still moves the incident while tracing is broken",
              rec.status == IncidentStatus.CANDIDATE.value and store.get_incident(iid).status == "CANDIDATE",
              f"status={store.get_incident(iid).status}")
        for weird in ({"decision": "not-a-decision"}, {"detail": {"x": object()}}, {"summary": None}):
            trace.record_trace(from_system="detection", event_type="degrade_probe", incident_id=marker, **weird)
        check("malformed trace arguments are swallowed, not raised", True)

        trace.flush(15)
        warned = [r for r in cap.records if "trace write failed" in r.getMessage()]
        check("the failure degrades to a logged warning (and the writer drained)", bool(warned) and trace.pending() == 0,
              (warned[0].getMessage()[:110] if warned else "no warning captured"))
        check("nothing was written to the trace table while the writer was broken",
              not q("SELECT 1 FROM trace_events WHERE incident_id = %s", (marker,)))
    finally:
        os.environ.pop("TRACE_STORE_DSN", None)
        tlog.removeHandler(cap)
        tlog.setLevel(old_level)
        store.delete_incident(iid)

    time.sleep(trace._COOLDOWN_SECONDS + 1)   # the writer pauses briefly after a failure
    trace.record_trace(from_system="detection", event_type="degrade_probe", incident_id=marker,
                       summary="written after the trace store came back")
    trace.flush(10)
    check("tracing recovers on its own once the store is reachable again",
          bool(q("SELECT 1 FROM trace_events WHERE incident_id = %s", (marker,))))
    q("DELETE FROM trace_events WHERE incident_id = %s RETURNING 1", (marker,))


# --------------------------------------------------------------------------
# B. scrubbing
# --------------------------------------------------------------------------

def part_b_scrub():
    print("\n--- B. the writer scrubs attacker detail itself ---")
    marker = f"p5-scrub-{new_incident_id()[-8:]}"
    trace.record_trace(
        from_system="containment", event_type="scrub_probe", incident_id=marker,
        summary="blocked 203.0.113.99 and fe80::1 after contact with db-01 and app.corp.internal",
        detail={"blocked_ips": ["203.0.113.99"], "usernames": ["admin"], "note": "from 198.51.100.7",
                "count": 2, "nested": {"host": "bastion-02", "ok": True}},
    )
    trace.flush(10)
    rows = q("SELECT * FROM trace_events WHERE incident_id = %s", (marker,))
    blob = json.dumps([(r["summary"], r["detail"]) for r in rows])
    check("IPs and internal hosts in summary/detail are replaced, sensitive keys dropped",
          bool(rows) and not _IPV4.search(blob) and not _IPV6.search(blob) and not _INTERNAL_HOST.search(blob)
          and "blocked_ips" not in blob and '"usernames"' not in blob and "admin" not in blob,
          rows[0]["summary"] if rows else "no row")
    q("DELETE FROM trace_events WHERE incident_id = %s RETURNING 1", (marker,))


# --------------------------------------------------------------------------
# C / D. live incidents
# --------------------------------------------------------------------------

def fire_attack() -> Optional[str]:
    before = newest_id()
    subprocess.run([str(PY_APP), str(SIM), "--pattern", "brute-force", "--intensity", "40", "--delay", "0.01"],
                   check=True, capture_output=True)
    return wait_until(lambda: (lambda n: n if n and n != before else None)(newest_id()), timeout=240)


def signoff_pending(iid: str, approver="priya") -> Optional[dict]:
    pend = wait_until(lambda: drafts.list(incident_id=iid, status="PENDING_SIGNOFF"), timeout=360)
    if not pend:
        return None
    d = pend[-1]
    r = requests.post(f"{COMMS}/signoff", json={"incident_id": iid, "draft_id": d.draft_id,
                                                "decision": "approve", "approver": approver}, timeout=60)
    return {"draft_id": d.draft_id, "code": r.status_code, "body": r.json()}


def part_c_live_human() -> Optional[str]:
    print("\n" + "=" * 72 + "\nC. LIVE incident 1: real attack, human ack, human sign-off\n" + "=" * 72)
    iid = fire_attack()
    if not check("attack produced an incident", iid is not None, iid or "none"):
        return None
    print(f"[p5] >>> incident {iid}")
    paged = wait_until(lambda: (store.get_incident(iid).raw_payload or {}).get("on_call", {}).get("paged"), timeout=360)
    check("On-Call paged", bool(paged))
    ack = requests.post(f"{ONCALL}/ack", params={"incident_id": iid, "who": "priya"}, timeout=30).json()
    check("human ack recorded", ack.get("provenance") == "human", f"by={ack.get('by')}")
    contained = wait_until(lambda: store.get_incident(iid).status in ("CONTAINED", "RESOLVED"), timeout=360)
    check("incident reached CONTAINED", bool(contained), store.get_incident(iid).status)
    so = signoff_pending(iid)
    check("a draft reached sign-off and was approved/published by a human",
          bool(so) and so["code"] == 200 and so["body"].get("published") is True,
          f"{so['draft_id']} published={so['body'].get('published')}" if so else "no draft")
    time.sleep(8)           # let the other processes' writers drain
    trace.flush(10)

    rows = rows_for(iid)
    print(f"[p5] {len(rows)} trace rows for {iid}")
    systems = {r["from_system"] for r in rows}
    wanted = {"detection", "threat_assessment", "containment", "on_call", "forensics", "customer_comms"}
    check("trace has rows written by every one of the six systems the incident touched",
          wanted <= systems, f"missing={sorted(wanted - systems)} present={sorted(systems)}")

    def first(pred):
        for r in rows:
            if pred(r):
                return r
        return None

    def adv(to):
        return first(lambda r: r["event_type"] == "status_advanced" and r["summary"].endswith(f"-> {to}"))

    marks = [
        ("detection creates the incident", adv("DETECTED")),
        ("-> CANDIDATE", adv("CANDIDATE")), ("-> ASSESSED", adv("ASSESSED")),
        ("-> DISPATCHED", adv("DISPATCHED")), ("-> CONTAINED", adv("CONTAINED")),
        ("draft_created", first(lambda r: r["event_type"] == "draft_created")),
        ("signoff_recorded", first(lambda r: r["event_type"] == "signoff_recorded")),
        ("published", first(lambda r: r["event_type"] == "published")),
    ]
    check("every lifecycle milestone is present in the trace", all(m[1] for m in marks),
          "missing: " + ", ".join(n for n, r in marks if not r))
    key = lambda r: (r["timestamp"], r["event_id"])  # noqa: E731
    present = [r for _, r in marks if r]
    check("the milestones occur in lifecycle order (DETECTED < ... < CONTAINED < draft < sign-off < published)",
          [key(r) for r in present] == sorted(key(r) for r in present),
          " | ".join(f"{n}@{r['timestamp'].strftime('%H:%M:%S.%f')[:-3]}" for n, r in marks if r))
    check("the whole trace is returned in non-decreasing time order",
          [r["timestamp"] for r in rows] == sorted(r["timestamp"] for r in rows))

    gates = [r for r in rows if r["event_type"] == "gate_evaluated" and (r["detail"] or {}).get("gate") == "action"]
    first_block = next((r for r in gates if r["decision"] == "blocked"), None)
    cleared = next((r for r in gates if r["decision"] in ("human", "timeout_escalation", "auto")), None)
    appr = first(lambda r: r["event_type"] == "approval_recorded")
    check("the action gate is traced: blocked while pending, then cleared by the human approval",
          bool(cleared) and cleared["decision"] == "human" and bool(appr) and appr["decision"] == "human",
          f"first_block={'yes' if first_block else 'no'} cleared_by={cleared['decision'] if cleared else None}")
    if first_block and cleared:
        check("blocked gate precedes the approval, which precedes the clearing gate",
              key(first_block) < key(appr) <= key(cleared), "")
    pg = first(lambda r: r["event_type"] == "gate_evaluated" and (r["detail"] or {}).get("gate") == "publish")
    check("the publish gate is traced and cleared by the human sign-off",
          bool(pg) and pg["decision"] == "human", pg["summary"] if pg else "none")
    check("evidence preservation and the containment action are traced",
          bool(first(lambda r: r["event_type"] == "evidence_preserved"))
          and bool(first(lambda r: r["event_type"] == "action_executed" and r["from_system"] == "containment")))
    check("A2A traffic is traced on both ends (sent and received)",
          bool(first(lambda r: r["event_type"] == "a2a_sent")) and bool(first(lambda r: r["event_type"] == "a2a_received")))
    print("[p5] timeline (routine authority checks hidden):")
    for r in rows:
        if r["event_type"] == "authority_checked":
            continue
        print(f"[p5]   {r['timestamp'].strftime('%H:%M:%S.%f')[:-3]}  {r['from_system']:17s}"
              f"{('-> ' + r['to_system']) if r['to_system'] else '':20s}{r['event_type']:20s}{r['decision']:19s}{r['summary'][:70]}")
    return iid


def part_d_live_timeout() -> Optional[str]:
    print("\n" + "=" * 72 + "\nD. LIVE incident 2: no ack -> timeout escalation clears the gate\n" + "=" * 72)
    iid = fire_attack()
    if not check("second attack produced an incident", iid is not None, iid or "none"):
        return None
    print(f"[p5] >>> incident {iid} (NOT acking)")
    contained = wait_until(lambda: store.get_incident(iid).status in ("CONTAINED", "RESOLVED"), timeout=600)
    check("incident reached CONTAINED via the timeout path", bool(contained), store.get_incident(iid).status)
    time.sleep(8)
    rows = rows_for(iid)
    appr = next((r for r in rows if r["event_type"] == "approval_recorded"), None)
    check("approval is traced as `timeout_escalation`, not as a human decision",
          bool(appr) and appr["decision"] == "timeout_escalation", appr["summary"] if appr else "no approval row")
    gate = next((r for r in rows if r["event_type"] == "gate_evaluated"
                 and (r["detail"] or {}).get("gate") == "action" and r["decision"] == "timeout_escalation"), None)
    check("the action gate is traced as cleared by timeout_escalation", bool(gate),
          gate["summary"][:90] if gate else one_line(rows, {"gate_evaluated"}))
    return iid


# --------------------------------------------------------------------------
# E. denied calls
# --------------------------------------------------------------------------

def part_e_denied():
    print("\n--- E. denied authority-matrix calls are traced, not dropped ---")
    iid = new_incident_id()
    store.create_incident(iid, status=IncidentStatus.CONTAINED, severity=Severity.HIGH, incident_type="x")
    try:
        async def _send(src, action, event=None):
            payload = {"action": action}
            if event:
                payload["event"] = event
            return await send_incident_message(
                IncidentMessage(incident_id=iid, source_system=src, target_system=SystemName.CUSTOMER_COMMS,
                                payload=payload), peer_base_url=COMMS_URL)

        r1 = asyncio.run(_send(SystemName.ON_CALL, ACTION_NOTIFY_STATUS, "contained")).payload
        r2 = asyncio.run(_send(SystemName.CONTAINMENT, ACTION_PAGE)).payload
        check("live Comms refused both calls", r1.get("accepted") is False and r2.get("accepted") is False,
              f"{r1.get('reason', '')[:60]} | {r2.get('reason', '')[:60]}")
        out = check_authority("customer_comms", "containment", ACTION_PAGE, incident_id=iid)   # Comms outbound
        check("Comms attempting an outbound call to Containment is denied", out is False)
        trace.flush(10)

        def have():
            rs = [r for r in rows_for(iid) if r["event_type"] == "authority_denied"]
            return rs if len(rs) >= 3 else None
        denied = wait_until(have, timeout=30, interval=1) or [r for r in rows_for(iid) if r["event_type"] == "authority_denied"]
        pairs = {(r["from_system"], r["to_system"]) for r in denied}
        check("authority_denied rows exist for each denied call, decision=blocked",
              {("on_call", "customer_comms"), ("containment", "customer_comms"),
               ("customer_comms", "containment")} <= pairs and all(r["decision"] == "blocked" for r in denied),
              f"{sorted(pairs)}")
        check("the over-the-wire denials were written by the Comms process, not just this test",
              len([r for r in denied if r["to_system"] == "customer_comms"]) == 2)
        none_inc = new_incident_id()
        check_authority("on_call", "forensics", ACTION_COLLECT_EVIDENCE)     # no incident id at all
        trace.flush(10)
        check("a denial with no incident id is still traced (incident_id NULL)",
              bool(q("SELECT 1 FROM trace_events WHERE event_type = 'authority_denied' AND incident_id IS NULL "
                     "AND from_system = 'on_call' AND to_system = 'forensics' AND \"timestamp\" > now() - interval '2 minutes'")))
        del none_inc
    finally:
        store.delete_incident(iid)


# --------------------------------------------------------------------------
# F. feedback loop
# --------------------------------------------------------------------------

def part_f_reclassify():
    print("\n--- F. the feedback loop is traced distinctly (reclassify_sent / reclassify_received) ---")
    mid = new_incident_id()
    store.create_incident(
        mid, status=IncidentStatus.DETECTED, severity=Severity.MEDIUM, incident_type="Brute Force",
        raw_payload={"origin": "phase5-test-seed", "detection": {
            "pattern_type": "brute_force", "confidence": 0.6, "reasoning": "limited single-source attempts",
            "evidence": {"total_requests": 14, "failed_logins": 11, "successful_logins": 2,
                         "distinct_ips_with_failed_logins": 1, "distinct_usernames_targeted": 3,
                         "top_failed_login_ips": [["198.51.100.77", 11]],
                         "top_targeted_usernames": [["admin", 5]]}}})
    for st, by in ((IncidentStatus.CANDIDATE, "threat_assessment"), (IncidentStatus.ASSESSED, "threat_assessment"),
                   (IncidentStatus.DISPATCHED, "threat_assessment")):
        store.advance_status(mid, st, by_system=by, **({"severity": Severity.MEDIUM} if st == IncidentStatus.ASSESSED else {}))
    store.advance_status(mid, IncidentStatus.CONTAINED, by_system="containment",
                         payload={"containment": {"blocked_ips": ["198.51.100.77"], "state": "EXECUTED"}})

    async def _kick():
        return await send_incident_message(
            IncidentMessage(incident_id=mid, source_system=SystemName.THREAT_ASSESSMENT,
                            target_system=SystemName.FORENSICS, payload={"action": ACTION_COLLECT_EVIDENCE}),
            peer_base_url=FORENSICS_URL)
    asyncio.run(_kick())
    got = wait_until(lambda: [r for r in rows_for(mid) if r["event_type"] == "reclassify_received"], timeout=600, interval=4)
    time.sleep(5)
    rows = rows_for(mid)
    sent = [r for r in rows if r["event_type"] == "reclassify_sent"]
    recv = [r for r in rows if r["event_type"] == "reclassify_received"]
    check("reclassify_sent (forensics -> threat_assessment) is traced",
          bool(sent) and sent[0]["from_system"] == "forensics" and sent[0]["to_system"] == "threat_assessment",
          one_line(sent))
    check("reclassify_received is traced by Threat Assessment's own process", bool(got) and bool(recv),
          one_line(recv))
    check("the back-and-forth is ordered: sent before received",
          bool(sent and recv) and (sent[0]["timestamp"], sent[0]["event_id"]) <= (recv[0]["timestamp"], recv[0]["event_id"]))
    store.delete_incident(mid)


# --------------------------------------------------------------------------
# G. dashboard backend
# --------------------------------------------------------------------------

def part_g_backend(iid: str, iid2: Optional[str]):
    print("\n--- G. dashboard backend returns real data for the live incidents ---")
    h = requests.get(f"{DASH}/health", timeout=10).json()
    check("dashboard is up, read-only, and sees the store", h.get("store") == "up" and h.get("read_only") is True, str(h))
    lst = requests.get(f"{DASH}/incidents", timeout=15).json()
    byid = {i["incident_id"]: i for i in lst["incidents"]}
    rec = store.get_incident(iid)
    check("/incidents lists the live incident with its real status and severity",
          iid in byid and byid[iid]["status"] == rec.status and byid[iid]["severity"] == rec.severity,
          f"api={byid.get(iid, {}).get('status')}/{byid.get(iid, {}).get('severity')} store={rec.status}/{rec.severity}")
    check("/incidents carries created/updated times and the pending-sign-off count",
          all(k in byid[iid] for k in ("created_at", "updated_at", "pending_signoff")))
    tl = requests.get(f"{DASH}/incidents/{iid}/timeline", timeout=15).json()
    table = rows_for(iid)
    api_trace = [e for e in tl["events"] if e["source"] == "trace"]
    check("/timeline returns exactly the trace rows in the table, in the same order",
          [e["event_id"] for e in api_trace] == [r["event_id"] for r in table],
          f"api={len(api_trace)} table={len(table)}")
    from datetime import datetime
    stamps = [datetime.fromisoformat(e["ts"]) for e in tl["events"]]
    check("/timeline is ordered by real time (offset-aware, UTC) across trace rows and status_history",
          stamps == sorted(stamps) and all(e["ts"].endswith("+00:00") for e in tl["events"]),
          f"first={tl['events'][0]['ts']} last={tl['events'][-1]['ts']}")
    dup = [e for e in tl["events"] if e["source"] == "status_history" and e["event_type"] == "history"
           and e["summary"] in ("comms_draft_created", "comms_signoff", "comms_published")]
    check("Comms moments appear once (trace row), not twice (trace row + status_history copy)", not dup,
          str([e["summary"] for e in dup]))
    check("/timeline merges status_history and comms_drafts",
          len(tl["drafts"]) == len(drafts.list(incident_id=iid, status=None))
          and tl["incident"]["status"] == rec.status,
          f"events={len(tl['events'])} (trace={len(api_trace)}) drafts={len(tl['drafts'])}")
    check("/timeline never returns draft text", all("draft_text" not in d for d in tl["drafts"]))
    if iid2:
        tl2 = requests.get(f"{DASH}/incidents/{iid2}/timeline", timeout=15).json()
        check("the timeout-path incident's timeline carries a timeout_escalation decision",
              any(e["decision"] == "timeout_escalation" for e in tl2["events"]))
    live = requests.get(f"{DASH}/live?limit=25", timeout=15).json()
    # Other processes keep writing, so compare against the table as it stood at the newest id /live saw.
    newest_seen = max(e["event_id"] for e in live["events"])
    expect = [r["event_id"] for r in q(
        'SELECT event_id FROM trace_events WHERE event_id <= %s ORDER BY "timestamp" DESC, event_id DESC LIMIT 25',
        (newest_seen,))]
    check("/live returns exactly the newest trace events across incidents",
          live["count"] == 25 and [e["event_id"] for e in live["events"]] == expect,
          f"api_top={live['events'][0]['event_id']} table_top_at_snapshot={expect[0]}")

    # A pending draft is visible (and points at the existing sign-off paths) but cannot be approved here.
    pid = new_incident_id()
    store.create_incident(pid, status=IncidentStatus.CONTAINED, severity=Severity.HIGH, incident_type="Brute Force")
    d = drafts.create(pid, event_type="contained", draft_text="We have taken protective action.",
                      severity_at_draft="High")
    try:
        ptl = requests.get(f"{DASH}/incidents/{pid}/timeline", timeout=15).json()
        check("a draft awaiting sign-off is shown with the existing sign-off route, not an approve action",
              [p["draft_id"] for p in ptl["pending_signoff"]] == [d.draft_id] and "comms_signoff.py" in (ptl["signoff_hint"] or ""))
        post = requests.post(f"{DASH}/incidents/{pid}/timeline", json={}, timeout=10)
        approve = requests.post(f"{DASH}/signoff", json={}, timeout=10)
        check("the dashboard exposes no write or approval endpoint", post.status_code == 405 and approve.status_code == 404)
    finally:
        store.delete_incident(pid)

    # Store down -> a clear error, not a stack trace.
    from fastapi.testclient import TestClient
    import dashboard.server as dsrv
    real = os.environ.get("INCIDENT_STORE_DSN")
    os.environ["INCIDENT_STORE_DSN"] = "postgresql://crisis:x@127.0.0.1:1/none?connect_timeout=1"
    try:
        c = TestClient(dsrv.app, raise_server_exceptions=False)
        r1, r2, r3 = c.get("/incidents"), c.get(f"/incidents/{iid}/timeline"), c.get("/live")
        check("with the store unreachable every data endpoint answers 503 with a clear JSON error",
              all(r.status_code == 503 and r.json().get("ok") is False and "unreachable" in r.json().get("error", "")
                  and "Traceback" not in r.text for r in (r1, r2, r3)), f"{r1.status_code}/{r2.status_code}/{r3.status_code}")
        check("/health still answers (store: down) instead of crashing", c.get("/health").json().get("store") == "down")
    finally:
        if real is None:
            os.environ.pop("INCIDENT_STORE_DSN", None)
        else:
            os.environ["INCIDENT_STORE_DSN"] = real
    page = requests.get(f"{DASH}/", timeout=10).text
    check("the frontend page is served and polls the three endpoints",
          "/incidents" in page and "/live" in page and "setInterval(refresh" in page and "timeout_escalation" in page)


# --------------------------------------------------------------------------
# H. no leaks
# --------------------------------------------------------------------------

def part_h_leaks(iids: List[str]):
    print("\n--- H. no attacker IP, username or internal host in the trace table or the dashboard ---")
    allrows = q("SELECT incident_id, summary, detail FROM trace_events")
    text = [json.dumps([r["summary"], r["detail"]]) for r in allrows]
    ip_hits = [t[:100] for t in text if _IPV4.search(t) or _IPV6.search(t)]
    host_hits = [t[:100] for t in text if _INTERNAL_HOST.search(t)]
    check(f"no IPv4/IPv6 address in any of the {len(allrows)} trace rows", not ip_hits, "; ".join(ip_hits[:2]))
    check("no internal hostname in any trace row", not host_hits, "; ".join(host_hits[:2]))

    users = set()
    for iid in iids:
        rec = store.get_incident(iid)
        if rec:
            users |= sensitive_terms(rec.raw_payload or {})["usernames"]
    users = {u for u in users if len(u) > 2}
    pat = re.compile(r"\b(?:" + "|".join(re.escape(u) for u in sorted(users)) + r")\b", re.IGNORECASE) if users else None
    api = [json.dumps(requests.get(f"{DASH}/incidents", timeout=15).json()),
           json.dumps(requests.get(f"{DASH}/live?limit=200", timeout=15).json())]
    for iid in iids:
        api.append(json.dumps(requests.get(f"{DASH}/incidents/{iid}/timeline", timeout=15).json()))
    own = [t for r, t in zip(allrows, text) if r["incident_id"] in iids]
    leaks = [pat.search(t).group(0) for t in own + api if pat and pat.search(t)]
    check("no targeted username (taken from the incidents' own evidence) in their trace rows or in the API output",
          not leaks, f"checked usernames={sorted(users)}; hits={leaks[:3]}")
    api_ip = [a[:100] for a in api if _IPV4.search(a) or _IPV6.search(a) or _INTERNAL_HOST.search(a)]
    check("no IP or internal host in /incidents, /live or any /timeline response", not api_ip, "; ".join(api_ip[:2]))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-timeout", action="store_true")
    ap.add_argument("--skip-reclassify", action="store_true")
    args = ap.parse_args()

    for port, name in [(9101, "Detection"), (9102, "Threat Assessment"), (9103, "Containment"),
                       (9104, "On-Call"), (9105, "Forensics"), (9106, "Customer Comms")]:
        try:
            requests.get(f"http://127.0.0.1:{port}/.well-known/agent-card.json", timeout=5).raise_for_status()
        except Exception as exc:  # noqa: BLE001
            print(f"[p5] {name} not reachable ({exc}); start the stack first (scripts/start_all.ps1)")
            return 1
    try:
        requests.get(f"{DASH}/health", timeout=5).raise_for_status()
    except Exception as exc:  # noqa: BLE001
        print(f"[p5] dashboard not reachable on :8090 ({exc}); start the stack first")
        return 1

    part_a_degrade()
    part_b_scrub()
    iid = part_c_live_human()
    iid2 = None if args.skip_timeout else part_d_live_timeout()
    part_e_denied()
    if not args.skip_reclassify:
        part_f_reclassify()
    if iid:
        part_g_backend(iid, iid2)
        part_h_leaks([i for i in (iid, iid2) if i])

    failed = [k for k, v in results.items() if not v]
    print(f"\n[p5] {len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print("[p5] FAILED: " + ", ".join(failed))
        return 1
    print("[p5] ALL PASSED -- trace table, denied-call trace, degrade-to-warning, dashboard backend, no leaks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
