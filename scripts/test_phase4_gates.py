"""Phase 4 no-LLM checks: validator, authority edges, publish gate, draft pipeline.

Needs only Postgres (no model, no A2A processes):

  * the deterministic validator rejects IPs, signal usernames, internal hosts,
    ports, root-cause jargon and empty text -- and passes clean copy,
  * the authority matrix has exactly the three new inbound edges to Comms and
    denies every other Comms edge (including anything Comms might send),
  * evaluate_publish_gate is deny-by-default, and the publishing tool does
    nothing (draft row and sink unchanged) unless a human approval is recorded,
  * the draft pipeline stores a failing draft as REJECTED with the reason,
    regenerates once, falls back to a template after a second failure, and
    supersedes older unpublished drafts without touching published ones.

    .venv-app\\Scripts\\python scripts/test_phase4_gates.py
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
_TMP = Path(tempfile.mkdtemp())
os.environ["COMMS_STATUS_FILE"] = str(_TMP / "status_updates.log")
os.environ.pop("COMMS_SLACK_WEBHOOK_URL", None)  # exercise the honest file sink

from customer_comms import pipeline  # noqa: E402
from customer_comms.publisher import STATUS_FILE, publish_draft  # noqa: E402
from shared import guardrail  # noqa: E402
from shared.comms_validation import validate_customer_text  # noqa: E402
from shared.schemas import IncidentStatus, Severity, SystemName, new_incident_id  # noqa: E402
from shared.store import DraftStore, IncidentStore  # noqa: E402

results = {}


def check(name, ok, detail=""):
    results[name] = ok
    print(f"[p4] {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


PAYLOAD = {"detection": {
    "evidence": {"top_failed_login_ips": [["198.51.100.77", 40]],
                 "top_targeted_usernames": [["admin", 12], ["jdoe", 3]]},
    "sample_signals": [{"ip": "198.51.100.77", "username": "svc-backup", "path": "/login"}]}}


def sink_lines() -> int:
    return len(STATUS_FILE.read_text(encoding="utf-8").splitlines()) if STATUS_FILE.exists() else 0


def seed(store, severity=Severity.HIGH, status=IncidentStatus.CONTAINED):
    iid = new_incident_id()
    store.create_incident(iid, status=status, severity=severity, incident_type="Brute Force",
                          raw_payload=PAYLOAD)
    return iid


def test_validator():
    clean = "We detected unusual activity and have taken protective action. No action is needed."
    check("validator passes clean copy", validate_customer_text(clean, PAYLOAD).ok)
    bad = {
        "IPv4 address": "Traffic from 198.51.100.77 was blocked.",
        "username from signals": "The account jdoe was targeted.",
        "username (nested sample signal)": "Someone tried svc-backup repeatedly.",
        "internal hostname": "The db-01 server is affected; see app.corp.internal.",
        "port number": "Service on port 5432 was reachable.",
        "host:port": "We shut off localhost:8080.",
        "root-cause detail": "A brute force attack caused this.",
        "empty text": "   ",
    }
    for label, text in bad.items():
        r = validate_customer_text(text, PAYLOAD)
        check(f"validator rejects {label}", not r.ok, r.reason)


def test_matrix():
    S = SystemName
    A = guardrail.ACTION_NOTIFY_STATUS
    for src in (S.CONTAINMENT, S.FORENSICS, S.THREAT_ASSESSMENT):
        check(f"edge allowed: {src.value} -> customer_comms / notify_status",
              guardrail.check_authority(src, S.CUSTOMER_COMMS, A))
    real = [S.DETECTION, S.THREAT_ASSESSMENT, S.CONTAINMENT, S.FORENSICS, S.CUSTOMER_COMMS, S.ON_CALL]
    actions = [v for k, v in vars(guardrail).items() if k.startswith("ACTION_") and isinstance(v, str)]
    allowed_to_comms, denied_ok = [], True
    for src in real:
        for act in actions:
            if guardrail.check_authority(src, S.CUSTOMER_COMMS, act):
                allowed_to_comms.append((src.value, act))
            # Comms sends nothing: no outbound edge at all.
            if src is not S.CUSTOMER_COMMS and guardrail.check_authority(S.CUSTOMER_COMMS, src, act):
                denied_ok = False
            if guardrail.check_authority(S.CUSTOMER_COMMS, src, act):
                denied_ok = False
    check("exactly three inbound edges to Comms, all notify_status",
          sorted(allowed_to_comms) == sorted([("containment", A), ("forensics", A), ("threat_assessment", A)]),
          str(allowed_to_comms))
    check("Comms has no outbound edge to any system for any action", denied_ok)
    check("On-Call -> Comms denied", not guardrail.check_authority(S.ON_CALL, S.CUSTOMER_COMMS, A))
    check("Detection -> Comms denied", not guardrail.check_authority(S.DETECTION, S.CUSTOMER_COMMS, A))
    check("Containment -> Comms with another action denied",
          not guardrail.check_authority(S.CONTAINMENT, S.CUSTOMER_COMMS, guardrail.ACTION_PAGE))


class _D:  # a draft-shaped object for the pure gate function
    def __init__(self, status, approved_by):
        self.status, self.approved_by = status, approved_by


def test_gate_function():
    check("gate denies a missing draft", not guardrail.evaluate_publish_gate(None).allowed)
    for st in ("PENDING_SIGNOFF", "REJECTED", "SUPERSEDED", "PUBLISHED"):
        check(f"gate denies status {st} even with a human name",
              not guardrail.evaluate_publish_gate(_D(st, "priya")).allowed)
    for who in (None, "", "   ", "timeout_escalation", "system", "auto", "containment", "on_call", "unknown"):
        check(f"gate denies APPROVED by {who!r}", not guardrail.evaluate_publish_gate(_D("APPROVED", who)).allowed)
    check("gate allows APPROVED by a named human", guardrail.evaluate_publish_gate(_D("APPROVED", "priya")).allowed)


def test_publisher(store, drafts):
    iid = seed(store)
    text = "We detected unusual activity and took protective action."
    pending = drafts.create(iid, event_type="contained", draft_text=text, severity_at_draft="High")

    before, lines = drafts.get(pending.draft_id).to_dict(), sink_lines()
    r = publish_draft(pending.draft_id, drafts=drafts, store=store)
    after = drafts.get(pending.draft_id).to_dict()
    check("no sign-off: publish refused, nothing sent", r["published"] is False and sink_lines() == lines, r["reason"])
    check("no sign-off: draft row unchanged and still PENDING_SIGNOFF",
          before == after and after["status"] == "PENDING_SIGNOFF" and after["published_at"] is None)

    # A forged/buggy row: APPROVED, but by the On-Call timeout mechanism.
    forged = drafts.create(iid, event_type="resolved", draft_text=text, severity_at_draft="High",
                           status="APPROVED", approved_by="timeout_escalation")
    before, lines = drafts.get(forged.draft_id).to_dict(), sink_lines()
    r = publish_draft(forged.draft_id, drafts=drafts, store=store)
    check("timeout_escalation approver: gate refuses, nothing sent",
          r["published"] is False and sink_lines() == lines, r["reason"])
    check("timeout_escalation approver: draft row unchanged (still APPROVED, unpublished)",
          drafts.get(forged.draft_id).to_dict() == before and before["published_at"] is None)

    human = drafts.create(iid, event_type="contained", draft_text=text, severity_at_draft="High",
                          status="APPROVED", approved_by="priya")
    lines = sink_lines()
    r = publish_draft(human.draft_id, drafts=drafts, store=store)
    row = drafts.get(human.draft_id)
    check("human sign-off: published to the status channel sink",
          r["published"] and sink_lines() == lines + 1 and row.status == "PUBLISHED",
          f"channel={row.publish_channel} sent={row.sent}")
    check("published row records approver, time, channel and sent flag",
          row.approved_by == "priya" and row.published_at is not None
          and row.publish_channel == "file_sink" and row.sent is False)
    again = publish_draft(human.draft_id, drafts=drafts, store=store)
    check("a published draft cannot be published twice", again["published"] is False and sink_lines() == lines + 1)

    # An approved draft whose text no longer validates is still not sent.
    sneaky = drafts.create(iid, event_type="contained", draft_text="Blocked 198.51.100.77.",
                           severity_at_draft="High", status="APPROVED", approved_by="priya")
    lines = sink_lines()
    r = publish_draft(sneaky.draft_id, drafts=drafts, store=store)
    check("approved text that fails validation is not sent", r["published"] is False and sink_lines() == lines,
          r["reason"])
    store.delete_incident(iid)


def test_pipeline(store, drafts):
    def good(snap, event, impact, fb):
        return f"Notice about {event} at {snap['severity']}. Please contact support if you need help."

    # Differs by event and severity (deterministic template path, no model).
    texts = {}
    for sev in ("Medium", "Critical"):
        for ev in pipeline.EVENTS:
            texts[(sev, ev)] = pipeline.template_draft({"severity": sev}, ev)
    check("template drafts all differ by event and severity band", len(set(texts.values())) == len(texts))
    check("every template draft passes the validator",
          all(validate_customer_text(t, PAYLOAD).ok for t in texts.values()))

    # (a) first draft has an IP, retry is clean.
    iid = seed(store)
    calls = []

    def ip_then_clean(snap, event, impact, fb):
        calls.append(fb)
        return "Blocked 198.51.100.77 for you." if len(calls) == 1 else "We took protective action."

    d = pipeline.build_draft(store, drafts, iid, "contained", drafter=ip_then_clean)
    rows = drafts.list(incident_id=iid)
    rejected = [r for r in rows if r.status == "REJECTED"]
    check("bad draft (IP) stored REJECTED with the validator reason",
          len(rejected) == 1 and "IPv4" in (rejected[0].rejection_reason or ""), rejected[0].rejection_reason if rejected else "")
    check("regenerated once, with the violation fed back",
          len(calls) == 2 and calls[0] is None and "IPv4" in (calls[1] or ""))
    check("the corrected draft is PENDING_SIGNOFF (generation=llm_retry)",
          d.status == "PENDING_SIGNOFF" and d.generation == "llm_retry")
    store.delete_incident(iid)

    # (b) fails twice -> template fallback, reported.
    iid = seed(store)
    d = pipeline.build_draft(store, drafts, iid, "contained",
                             drafter=lambda *a: "Attacker 198.51.100.77 was blocked by the db-01 host.")
    rows = drafts.list(incident_id=iid)
    check("two failures -> two REJECTED rows then a template_fallback PENDING draft",
          sum(r.status == "REJECTED" for r in rows) == 2 and d.generation == "template_fallback"
          and d.status == "PENDING_SIGNOFF", f"{[r.status for r in rows]}")
    store.delete_incident(iid)

    # (c) model down -> template, still a draft.
    iid = seed(store)

    def boom(*a):
        raise RuntimeError("model unavailable")

    d = pipeline.build_draft(store, drafts, iid, "contained", assessor=boom, drafter=boom)
    check("model outage still yields a PENDING_SIGNOFF template draft",
          d.status == "PENDING_SIGNOFF" and d.generation == "template_fallback")
    store.delete_incident(iid)

    # (d) supersession: pending is replaced, published is kept.
    iid = seed(store)
    first = pipeline.build_draft(store, drafts, iid, "contained", drafter=good)
    second = pipeline.build_draft(store, drafts, iid, "reclassified", drafter=good)
    check("a newer draft supersedes the unpublished one",
          drafts.get(first.draft_id).status == "SUPERSEDED"
          and drafts.get(first.draft_id).superseded_by == second.draft_id
          and drafts.get(second.draft_id).status == "PENDING_SIGNOFF")
    drafts.decide(second.draft_id, status="APPROVED", approved_by="priya")
    publish_draft(second.draft_id, drafts=drafts, store=store)
    third = pipeline.build_draft(store, drafts, iid, "resolved", drafter=good)
    check("a published draft is never superseded",
          drafts.get(second.draft_id).status == "PUBLISHED"
          and drafts.get(third.draft_id).status == "PENDING_SIGNOFF")
    hist = [h.get("event") for h in store.status_history(iid) if h.get("event")]
    check("draft lifecycle is in the incident's status_history",
          {"comms_draft_created", "comms_draft_superseded", "comms_published"} <= set(hist), str(hist))
    check("status never moved (audit entries are not lifecycle moves)",
          store.get_incident(iid).status == "CONTAINED")
    store.delete_incident(iid)


def main() -> int:
    store, drafts = IncidentStore(), DraftStore()
    test_validator()
    test_matrix()
    test_gate_function()
    test_publisher(store, drafts)
    test_pipeline(store, drafts)
    failed = [k for k, v in results.items() if not v]
    print(f"\n[p4] {len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print("[p4] FAILED: " + ", ".join(failed))
        return 1
    print("[p4] ALL PASSED -- validator, authority edges, publish gate, draft pipeline")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
