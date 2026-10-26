"""Phase 4 end-to-end: one real attack through all six systems, with the human
sign-off done through Customer Comms' /signoff API.

Requires the full stack (scripts/start_all.ps1): target app, Detection, Threat
Assessment, Containment, On-Call, Forensics, Customer Comms, Postgres.

Traces ONE incident_id:
    attack -> Detection -> Threat Assessment -> parallel dispatch -> On-Call page
    + human approval -> evidence preserved -> Containment (simulated firewall)
    -> `contained` draft -> NEGATIVE: no sign-off => nothing published
    -> NEGATIVE: timeout_escalation / bad edit refused -> human sign-off ->
    publish -> root cause + live recovery plan (the model's LIFT decision is reported; NO is valid).
    The `resolved` path is then proved on SEEDED CONTAINED incidents through Forensics' real
    _recover() (only the LLM lift decision is stubbed): safe_to_lift=False => no lift, no RESOLVED,
    no `resolved` draft; safe_to_lift=True => lift, RESOLVED, `resolved` draft, CLI sign-off, publish.

Seeded pieces (documented in the report): the two CONTAINED incidents for the resolved path,
the Medium incident used to show a
second severity band, and the forged APPROVED-by-timeout_escalation row used to
hit the publish gate directly. Everything on the traced incident is real.

    .venv-adk\\Scripts\\python scripts/test_phase4_e2e.py
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from containment.firewall import block_ips, blocked_ips  # noqa: E402
from customer_comms.publisher import STATUS_FILE, publish_draft  # noqa: E402
from shared.a2a_support import COMMS_URL, send_incident_message  # noqa: E402
from shared.comms_validation import validate_customer_text  # noqa: E402
from shared.guardrail import ACTION_NOTIFY_STATUS, ACTION_PAGE  # noqa: E402
from shared.schemas import (  # noqa: E402
    IncidentMessage,
    IncidentStatus,
    Severity,
    SystemName,
    new_incident_id,
)
from shared.store import DraftStore, IncidentStore  # noqa: E402
from types import SimpleNamespace  # noqa: E402

PY_APP = ROOT / ".venv-app" / "Scripts" / "python.exe"
SIM = ROOT / "scripts" / "attack_simulate.py"
CLI = ROOT / "scripts" / "comms_signoff.py"
ONCALL = "http://127.0.0.1:9104"
COMMS = "http://127.0.0.1:9106"

results = {}
store = IncidentStore()
drafts = DraftStore()


def check(name, ok, detail=""):
    results[name] = bool(ok)
    print(f"[p4e2e] {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))
    return bool(ok)


def wait_until(fn, timeout=240, interval=3):
    deadline = time.time() + timeout
    while time.time() < deadline:
        v = fn()
        if v:
            return v
        time.sleep(interval)
    return None


def payload(iid):
    return store.get_incident(iid).raw_payload or {}


def sink_text() -> str:
    return STATUS_FILE.read_text(encoding="utf-8") if STATUS_FILE.exists() else ""


def pending_for(iid):
    return drafts.list(incident_id=iid, status="PENDING_SIGNOFF")


def signoff(iid, draft_id, decision, approver, **extra):
    r = requests.post(f"{COMMS}/signoff", json={"incident_id": iid, "draft_id": draft_id,
                      "decision": decision, "approver": approver, **extra}, timeout=60)
    return r.status_code, r.json()


async def _notify(iid, source, event):
    msg = IncidentMessage(incident_id=iid, source_system=source, target_system=SystemName.CUSTOMER_COMMS,
                          payload={"action": ACTION_NOTIFY_STATUS, "event": event})
    return await send_incident_message(msg, peer_base_url=COMMS_URL)


def six_cards_up() -> bool:
    for port, name in [(9101, "Detection"), (9102, "Threat Assessment"), (9103, "Containment"),
                       (9104, "On-Call"), (9105, "Forensics"), (9106, "Customer Comms")]:
        try:
            card = requests.get(f"http://127.0.0.1:{port}/.well-known/agent-card.json", timeout=5)
            card.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            return check(f"{name} card reachable", False, str(exc))
    comms = requests.get("http://127.0.0.1:9106/.well-known/agent-card.json", timeout=5).json()
    return check("all six agent cards reachable; Comms is its own process on :9106", True,
                 f"comms card name={comms.get('name')!r} slack_configured="
                 f"{requests.get(COMMS + '/health', timeout=5).json().get('slack_configured')}")


def authority_over_the_wire():
    print("\n--- inbound authority on the live Comms process ---")
    iid = new_incident_id()
    store.create_incident(iid, status=IncidentStatus.CONTAINED, severity=Severity.HIGH, incident_type="x")
    try:
        denied = asyncio.run(_notify(iid, SystemName.ON_CALL, "contained")).payload
        check("On-Call -> Comms notify_status denied by the live process", denied.get("accepted") is False,
              denied.get("reason", ""))
        wrong = asyncio.run(_notify(iid, SystemName.FORENSICS, "contained")).payload
        check("Forensics may not announce `contained` (event/sender binding)", wrong.get("accepted") is False,
              wrong.get("reason", ""))
        async def _page():
            msg = IncidentMessage(incident_id=iid, source_system=SystemName.CONTAINMENT,
                                  target_system=SystemName.CUSTOMER_COMMS, payload={"action": ACTION_PAGE})
            return await send_incident_message(msg, peer_base_url=COMMS_URL)
        other = asyncio.run(_page()).payload
        check("Containment -> Comms with a non-notify_status action denied", other.get("accepted") is False,
              other.get("reason", ""))
        time.sleep(2)
        check("denied requests created no drafts", not drafts.list(incident_id=iid))
    finally:
        store.delete_incident(iid)


def traced_incident() -> Optional[str]:
    print("\n" + "=" * 72 + "\nTHE TRACED INCIDENT (real attack, all six systems)\n" + "=" * 72)
    before = (store.list_incidents(limit=1) or [None])[0]
    before = before.incident_id if before else None
    r = subprocess.run([str(PY_APP), str(SIM), "--pattern", "brute-force", "--intensity", "40"],
                       capture_output=True, text=True)
    print(f"[p4e2e] attack script exit={r.returncode}")
    iid = wait_until(lambda: (lambda n: n if n and n != before else None)(
        (store.list_incidents(limit=1) or [None])[0].incident_id if store.list_incidents(limit=1) else None),
        timeout=180)
    if not check("1. attack produced an incident (Detection)", iid is not None, iid or "none"):
        return None
    print(f"[p4e2e] >>> tracing incident_id = {iid}")

    hist = store.status_history(iid)
    check("   Detection created the row", hist and hist[0]["by"] == "detection")

    # Severity is written after the type (CANDIDATE -> ASSESSED) and the LLM call can be slow under
    # quota retries, so wait for severity AND a post-assessment status, not just the first write.
    def _assessed():
        r = store.get_incident(iid)
        st = str(getattr(r.status, "value", r.status))
        return r.severity if r.severity and st not in ("DETECTED", "CANDIDATE") else None
    assessed = wait_until(_assessed, timeout=600)
    rec = store.get_incident(iid)
    check("2. Threat Assessment assessed it", bool(assessed), f"severity={rec.severity} type={rec.incident_type}")

    wait_until(lambda: "DISPATCHED" in [h.get("to") for h in store.status_history(iid)], timeout=120)
    check("3. dispatched (parallel fan-out)", "DISPATCHED" in [h.get("to") for h in store.status_history(iid)])

    paged = wait_until(lambda: payload(iid).get("on_call", {}).get("paged"), timeout=120)
    check("4. On-Call paged", bool(paged), str(payload(iid).get("on_call", {}).get("contact")))
    ack = requests.post(f"{ONCALL}/ack", params={"incident_id": iid, "who": "priya"}, timeout=30).json()
    check("   human approval recorded via On-Call /ack", ack.get("provenance") == "human", f"by={ack.get('by')}")

    ev = wait_until(lambda: payload(iid).get("evidence", {}).get("preserved"), timeout=120)
    check("5. Forensics preserved evidence (gate signal)", bool(ev), f"by={payload(iid).get('evidence', {}).get('by')}")

    contained = wait_until(lambda: store.get_incident(iid).status in ("CONTAINED", "RESOLVED"), timeout=180)
    c = payload(iid).get("containment", {})
    check("6. Containment executed (simulated firewall)", bool(contained) and c.get("state") == "EXECUTED",
          f"blocked={c.get('blocked_ips')}")
    attacker_ips = list(c.get("blocked_ips") or [])
    return iid, attacker_ips


def negative_and_signoff(iid, attacker_ips):
    print("\n--- first customer draft: negatives, then human sign-off ---")
    first = wait_until(lambda: pending_for(iid), timeout=120)
    if not check("7. a draft reached PENDING_SIGNOFF", bool(first),
                 f"{[(d.event_type, d.status) for d in drafts.list(incident_id=iid)]}"):
        return None
    d = pending_for(iid)[-1]
    print(f"[p4e2e]     draft {d.draft_id} event={d.event_type} severity={d.severity_at_draft} "
          f"generation={d.generation}\n[p4e2e]     TEXT: {d.draft_text}")

    # NEGATIVE 1: no sign-off => nothing published, state unchanged.
    before_row, before_sink = drafts.get(d.draft_id).to_dict(), sink_text()
    print("[p4e2e]     (waiting 15s with NO sign-off recorded ...)")
    time.sleep(15)
    cur = drafts.get(d.draft_id)
    if cur.status == "SUPERSEDED":     # a newer draft legitimately replaced it; follow it
        d = pending_for(iid)[-1]
        before_row, before_sink = drafts.get(d.draft_id).to_dict(), sink_text()
        print(f"[p4e2e]     superseded by {d.draft_id} ({d.event_type}); checking that one instead")
        time.sleep(5)
        cur = drafts.get(d.draft_id)
    check("NEG-1 no sign-off: draft still PENDING_SIGNOFF, row unchanged",
          cur.to_dict() == before_row and cur.status == "PENDING_SIGNOFF" and cur.published_at is None)
    check("NEG-1 no sign-off: nothing published (sink unchanged, no published history)",
          sink_text() == before_sink and d.draft_id not in sink_text()
          and not [h for h in store.status_history(iid) if h.get("event") == "comms_published"])

    # NEGATIVE 2: timeout_escalation as approver.
    code, body = signoff(iid, d.draft_id, "approve", "timeout_escalation")
    check("NEG-2 /signoff with approver=timeout_escalation refused", code == 403, body.get("reason", ""))
    check("NEG-2 draft state unchanged after that attempt",
          drafts.get(d.draft_id).to_dict() == before_row)
    # ... and the publish gate itself refuses a forged APPROVED-by-timeout row.
    seed = new_incident_id()
    store.create_incident(seed, status=IncidentStatus.CONTAINED, severity=Severity.HIGH, incident_type="seed")
    forged = drafts.create(seed, event_type="contained", draft_text="We took protective action.",
                           severity_at_draft="High", status="APPROVED", approved_by="timeout_escalation")
    sink_before = sink_text()
    res = publish_draft(forged.draft_id, drafts=drafts, store=store)
    check("NEG-2 publish gate refuses a timeout_escalation approval (forged APPROVED row)",
          res["published"] is False and sink_text() == sink_before
          and drafts.get(forged.draft_id).status == "APPROVED" and drafts.get(forged.draft_id).published_at is None,
          res["reason"])
    store.delete_incident(seed)

    # NEGATIVE 3: bad human edit (contains an attacker IP) is refused.
    bad_ip = attacker_ips[0] if attacker_ips else "198.51.100.77"
    code, body = signoff(iid, d.draft_id, "approve", "priya",
                         edited_text=f"We blocked traffic from {bad_ip} to protect you.")
    check("NEG-3 human edit containing an IP is refused (422)", code == 422, body.get("reason", ""))
    check("NEG-3 draft still PENDING_SIGNOFF after the bad edit",
          drafts.get(d.draft_id).status == "PENDING_SIGNOFF" and drafts.get(d.draft_id).draft_text == d.draft_text)

    # Real sign-off.
    code, body = signoff(iid, d.draft_id, "approve", "priya")
    row = drafts.get(d.draft_id)
    check("8. human sign-off accepted and published", code == 200 and body.get("published") is True
          and row.status == "PUBLISHED", f"channel={row.publish_channel} sent={row.sent}")
    check("   record shows who approved and when",
          row.approved_by == "priya" and row.decided_at is not None and row.published_at is not None,
          f"approved_by={row.approved_by} decided_at={row.decided_at} published_at={row.published_at}")
    check("   message is in the status sink", d.draft_id in sink_text())
    return d


def resolve_phase(iid, attacker_ips):
    """Live part: RCA + the model's recovery plan. The lift decision is the model's judgment, so
    LIFT: NO is a valid outcome here (reported, never failed). The `resolved` path itself is proved
    deterministically in resolved_path_seeded()."""
    print("\n--- live: root cause + recovery plan (the lift decision is the model's; NO is valid) ---")
    rca = wait_until(lambda: payload(iid).get("forensics", {}).get("root_cause_narrative"), timeout=240)
    check("9. root-cause narrative produced", bool(rca), f"{len((rca or '').split())} words")
    plan = wait_until(lambda: payload(iid).get("recovery_plan"), timeout=240)
    check("10. recovery plan produced", bool(plan), f"safe_to_lift={(plan or {}).get('safe_to_lift')}")
    if not (plan and plan.get("safe_to_lift")):
        print("[p4e2e]     live Forensics answered LIFT: NO -> containment stays, no `resolved` event "
              "(a valid outcome, not a failure)")
        time.sleep(5)
        check("    live LIFT: NO leaves the incident CONTAINED, blocks in place, no `resolved` draft",
              str(getattr(store.get_incident(iid).status, "value", store.get_incident(iid).status)) == "CONTAINED"
              and all(ip in blocked_ips() for ip in attacker_ips)
              and not [d for d in drafts.list(incident_id=iid) if d.event_type == "resolved"])
        return
    # The model said YES: verify the real chain end to end as a bonus.
    lifted = wait_until(lambda: payload(iid).get("recovery", {}).get("lifted"), timeout=240)
    check("    live LIFT: YES -> lift completed by Containment", bool(lifted))
    check("    live LIFT: YES -> incident RESOLVED",
          wait_until(lambda: str(getattr(store.get_incident(iid).status, "value",
                                         store.get_incident(iid).status)) == "RESOLVED", 60))


def _status(iid):
    r = store.get_incident(iid)
    return str(getattr(r.status, "value", r.status))


def _seed_contained(label, ips):
    iid = new_incident_id()
    store.create_incident(
        iid, status=IncidentStatus.CONTAINED, severity=Severity.HIGH, incident_type="Brute Force",
        raw_payload={"containment": {"blocked_ips": ips, "state": "EXECUTED"},
                     "detection": {"evidence": {"top_targeted_usernames": [["alice", 4]],
                                                "top_failed_login_ips": [[ips[0], 9]]}}})
    block_ips(ips, incident_id=iid, reason=f"p4e2e {label} seed")
    return iid


def _drive_recovery(iid, safe_to_lift):
    """Run Forensics' REAL _recover() in-process: real A2A to the live Containment and Comms
    processes. Only the LLM's lift decision (plan_recovery) is replaced."""
    import forensics.server as fsrv
    from forensics.recovery import RecoveryPlan
    original = fsrv.plan_recovery
    fsrv.plan_recovery = lambda brief: RecoveryPlan(
        plan_text=f"seeded plan\nLIFT: {'YES' if safe_to_lift else 'NO'}", safe_to_lift=safe_to_lift)
    try:
        rca = SimpleNamespace(narrative="seeded root-cause narrative")
        asyncio.run(fsrv.ForensicsExecutor()._recover(iid, rca))
    finally:
        fsrv.plan_recovery = original


def resolved_path_seeded():
    print("\n--- resolved path, deterministic: seeded CONTAINED incidents, real _recover() ---")
    n = int(new_incident_id()[-4:], 16)
    ips_no = [f"203.0.113.{100 + n % 20}"]
    ips_yes = [f"203.0.113.{130 + n % 20}"]

    # NEGATIVE (the safety property): safe_to_lift=False => no lift, no RESOLVED, no `resolved` draft.
    no_id = _seed_contained("neg", ips_no)
    try:
        _drive_recovery(no_id, False)
        check("NEG-4 safe_to_lift=False: blocks stay in the firewall", all(ip in blocked_ips() for ip in ips_no))
        check("NEG-4 safe_to_lift=False: incident stays CONTAINED", _status(no_id) == "CONTAINED", _status(no_id))
        check("NEG-4 safe_to_lift=False: no `recovery.lifted` recorded",
              not payload(no_id).get("recovery", {}).get("lifted"))
        # The positive case below proves a `resolved` draft appears when it should; wait long enough
        # here that its absence means something.
        print("[p4e2e]     (waiting 45s to confirm NO `resolved` draft ever appears ...)")
        time.sleep(45)
        check("NEG-4 safe_to_lift=False: no `resolved` draft produced",
              not [d for d in drafts.list(incident_id=no_id) if d.event_type == "resolved"],
              str([(d.event_type, d.status) for d in drafts.list(incident_id=no_id)]))
    finally:
        store.delete_incident(no_id)

    # POSITIVE: safe_to_lift=True => real lift, RESOLVED, `resolved` draft, sign-off, publish.
    yes_id = _seed_contained("pos", ips_yes)
    check("    seeded block present before recovery", all(ip in blocked_ips() for ip in ips_yes), str(ips_yes))
    _drive_recovery(yes_id, True)
    lifted = wait_until(lambda: payload(yes_id).get("recovery", {}).get("lifted"), timeout=60)
    check("11. safe_to_lift=True: Containment lifted (recorded on the incident)", bool(lifted))
    check("    firewall: this incident's IPs are no longer blocked",
          all(ip not in blocked_ips() for ip in ips_yes), f"was {ips_yes}")
    check("12. incident advanced to RESOLVED",
          wait_until(lambda: _status(yes_id) == "RESOLVED", 60), f"status={_status(yes_id)}")
    res = wait_until(lambda: [d for d in drafts.list(incident_id=yes_id)
                              if d.event_type == "resolved" and d.status == "PENDING_SIGNOFF"], timeout=150)
    if not check("13. a `resolved` draft reached PENDING_SIGNOFF", bool(res),
                 f"{[(d.event_type, d.status) for d in drafts.list(incident_id=yes_id)]}"):
        return None, yes_id
    d = res[-1]
    print(f"[p4e2e]     draft {d.draft_id} severity={d.severity_at_draft} generation={d.generation}\n"
          f"[p4e2e]     TEXT: {d.draft_text}")
    check("    nothing published before sign-off", d.draft_id not in sink_text() and d.published_at is None)
    r = subprocess.run([sys.executable, str(CLI), "approve", d.draft_id, "--as", "priya"],
                       capture_output=True, text=True)
    row = drafts.get(d.draft_id)
    check("14. sign-off via scripts/comms_signoff.py CLI, then published",
          r.returncode == 0 and row.status == "PUBLISHED", f"exit={r.returncode} sent={row.sent}")
    check("    resolved message is in the status sink", d.draft_id in sink_text())
    check("15. seeded incident ends RESOLVED with a published `resolved` message",
          _status(yes_id) == "RESOLVED"
          and any(x.event_type == "resolved" and x.status == "PUBLISHED" for x in drafts.list(incident_id=yes_id)))
    return drafts.get(d.draft_id), yes_id


def variation_and_content(iid, attacker_ips, first, last):
    print("\n--- drafts differ by event and severity; none leaks attacker detail ---")
    mid = new_incident_id()
    store.create_incident(
        mid, status=IncidentStatus.CONTAINED, severity=Severity.MEDIUM, incident_type="Brute Force",
        raw_payload={"containment": {"state": "EXECUTED", "blocked_ips": ["198.51.100.88"]},
                     "detection": {"evidence": {"top_targeted_usernames": [["alice", 4]],
                                                "top_failed_login_ips": [["198.51.100.88", 9]]}}})
    try:
        asyncio.run(_notify(mid, SystemName.CONTAINMENT, "contained"))
        med = wait_until(lambda: pending_for(mid), timeout=120)
        texts = {"HIGH/contained(live)": first, "HIGH/resolved(live)": last,
                 "MEDIUM/contained(seeded)": (med or [None])[-1]}
        for k, d in texts.items():
            print(f"[p4e2e]     {k}: {d.draft_text if d else '<none>'}")
        check("Medium draft produced", bool(med))
        if med and first and last:
            uniq = {first.draft_text, last.draft_text, med[-1].draft_text}
            check("three drafts differ (by event and severity)", len(uniq) == 3)
    finally:
        store.delete_incident(mid)

    usernames = [u for u, _ in (payload(iid).get("detection", {}).get("evidence", {}).get("top_targeted_usernames", []))]
    leaks = []
    for d in drafts.list(incident_id=iid):
        t = d.draft_text
        if any(ip in t for ip in attacker_ips) or any(u.lower() in t.lower() for u in usernames if len(u) > 2):
            leaks.append(d.draft_id)
        if not validate_customer_text(t, payload(iid)).ok:
            leaks.append(d.draft_id)
    check("no draft for the traced incident contains an IP, username or internal host", not leaks,
          f"checked {len(drafts.list(incident_id=iid))} drafts; usernames={usernames}")


def final_trace(iid):
    print("\n" + "=" * 72 + f"\nTRACE for {iid}\n" + "=" * 72)
    for h in store.status_history(iid):
        label = h.get("event") or f"{h.get('from')} -> {h.get('to')}"
        extra = {k: v for k, v in h.items() if k in ("draft_id", "comms_event", "decision", "approved_by",
                                                       "channel", "sent", "reason") and v is not None}
        print(f"  {h.get('at', '')[11:19]}  {h.get('by', ''):18s} {label}  {extra if extra else ''}")
    print("\n  drafts:")
    for d in drafts.list(incident_id=iid, status="all" if False else None):
        print(f"    {d.draft_id} {d.event_type:12s} {d.status:15s} approved_by={d.approved_by} "
              f"published_at={str(d.published_at)[:19]} channel={d.publish_channel} sent={d.sent} gen={d.generation}")
    print("\n  status sink (customer_comms/status_updates.log) lines for this incident:")
    for line in sink_text().splitlines():
        if iid in line:
            rec = json.loads(line)
            print(f"    {rec['at'][11:19]} {rec['event_type']} sent={rec['sent']} approved_by={rec['approved_by']}")
    rec = store.get_incident(iid)
    print(f"\n  final: {rec.summary()}")


def main() -> int:
    if not six_cards_up():
        print("\n[p4e2e] start the full stack first (scripts/start_all.ps1)")
        return 1
    authority_over_the_wire()
    out = traced_incident()
    if not out:
        return 1
    iid, attacker_ips = out
    first = negative_and_signoff(iid, attacker_ips)
    resolve_phase(iid, attacker_ips)
    last, yes_id = resolved_path_seeded()
    variation_and_content(iid, attacker_ips, first, last)
    final_trace(iid)
    check("16. the traced live incident has a published message and a lifecycle consistent with the "
          "model's lift decision",
          len([d for d in drafts.list(incident_id=iid) if d.status == "PUBLISHED"]) >= 1
          and _status(iid) in ("CONTAINED", "RESOLVED"))
    try:
        store.delete_incident(yes_id)
    except Exception:  # noqa: BLE001
        pass

    failed = [k for k, v in results.items() if not v]
    print(f"\n[p4e2e] {len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print("[p4e2e] FAILED: " + ", ".join(failed))
        return 1
    print("[p4e2e] ALL PASSED -- six systems, one incident, human sign-off, published")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
