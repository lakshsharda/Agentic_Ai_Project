# Phase 4 — completion report

Verified 2026-10-21, Python 3.11.9, Windows 11. All results below come from a
stack that was **fully restarted on the rotated OpenRouter key and the new
model chain** (`nvidia/nemotron-3-ultra-550b-a55b:free`); nothing run against the
old server processes is counted.

**All nine exit criteria MET.** Customer Communications runs as a sixth
independent system (:9106). It drafts customer-facing text per event and
severity, a validator keeps attacker detail out of it, and **nothing is
published without a named human's sign-off** — enforced in the publish gate in
`shared/guardrail.py`, not by convention. One incident was traced live through
all six systems to a published `resolved` message.

---

## 1. What was built, task by task

### Task 1 — Customer Comms system (`customer_comms/`, :9106) — **done**
Own process, own A2A card ("Customer Communications"), registered in
`SYSTEM_URLS`. Receives `notify_status` events from other systems, drafts a
customer-safe message per event (`contained`, `reclassified`, `resolved`) and
severity band, and stores it as a `PENDING_SIGNOFF` draft. It makes no outbound
A2A calls. If the model fails twice it falls back to a template draft, so a
model outage still yields a draft awaiting sign-off.

### Task 2 — Draft validator (`shared/comms_validation.py`) — **done**
Rejects any draft or human edit containing an IPv4 address, a targeted
username, or an internal hostname. A bad model draft is stored `REJECTED` with
the reason, regenerated once with the violation fed back, then falls back to a
template. A bad human edit is refused (422) and the draft is left untouched.

### Task 3 — Human sign-off + publish gate — **done**
`comms_drafts` table (migration 002), `/signoff` API and
`scripts/comms_signoff.py` CLI. The publish gate refuses unless the draft is
`APPROVED` by a named human: `timeout_escalation` (a system value) is refused,
a published draft cannot be published twice, and the approved text is
re-validated at publish time. Publishing goes to Slack if
`COMMS_SLACK_WEBHOOK_URL` is set, otherwise to an honest file sink with
`sent=False`. The record keeps approver, decision time, publish time, channel
and `sent`.

### Task 4 — Authority edges and upstream hooks — **done**
Three new edges: Containment, Forensics and Threat Assessment → Customer Comms,
each limited to `notify_status`; every other Comms edge is denied. Event/sender
binding is enforced too (Forensics may announce `resolved`, not `contained`).
Hooks: Containment announces `contained` and now advances the incident to
`RESOLVED` when a recovery lift is carried out (nothing did before);
Forensics announces `resolved` only after Containment confirms the lift; Threat
Assessment announces `reclassified`.

---

## 2. Files created or modified

Created: `customer_comms/{__init__,agents,pipeline,publisher,server}.py`,
`shared/comms_validation.py`, `shared/comms_notify.py`,
`shared/store/drafts.py`, `infra/migrations/002_phase4_comms_drafts.sql`,
`scripts/comms_signoff.py`, `scripts/test_phase4_gates.py`,
`scripts/test_phase4_e2e.py`, `docs/PHASE4_REPORT.md`.

Modified: `shared/guardrail.py` (three edges, publish gate),
`shared/store/__init__.py`, `containment/server.py`, `forensics/server.py`,
`threat_assessment/server.py` (notify hooks; RESOLVED advance),
`scripts/start_all.ps1` (Comms process; `SKIP_DOCKER_STORE`),
`scripts/test_phase2_e2e.py` and `scripts/test_phase3_e2e.py` (waits only, see
section 4), `.env` (model id and rotated key).

---

## 3. Exit criteria check

**1. Comms is an independent process (:9106) with a real card, reachable — MET.**
`test_phase4_e2e.py`: "all six agent cards reachable; Comms is its own process
on :9106", card name `Customer Communications`, `slack_configured=False`.

**2. Drafts differ by event and severity; none leaks IP, username or host — MET.**
Actual texts from the verified run:

- *HIGH, `resolved` (live):* "RESTORED -- All services are now operating
  normally following the earlier disruption. We have fully resolved the issue
  and restored normal operations. If you notice any unfamiliar sign-in activity
  on your account, please reset your password immediately. …"
- *MEDIUM, `contained` (seeded):* "Protective measures are successfully in
  place to safeguard the platform, and our team is actively monitoring system
  performance. You may continue to experience temporary service interruptions
  while this monitoring continues. No action is needed on your part unless you
  observe unusual activity."
- *HIGH, `contained` (live; from the earlier pre-restart run, kept for the
  contrast):* "We detected an issue and have taken protective action. … we
  strongly recommend resetting your password immediately …"

The e2e asserts the three differ and that no draft for the traced incident
contains an attacker IP, a targeted username or an internal host (checked
against the incident's real evidence; usernames `admin, alice, guest,
administrator, root`). `test_phase4_gates.py` also shows every template draft
differs by event and severity band and passes the validator.

**3. Validator rejects a bad draft and a bad human edit — MET.**
Bad draft: stored `REJECTED` with "contains an IPv4 address (198.51.100.77)"
(and, in another case, "contains an internal hostname (db-01)"), regenerated
once, then `PENDING_SIGNOFF`; two failures → two `REJECTED` rows then a
`template_fallback` draft. Bad human edit: `/signoff` with an edit containing
the incident's real blocked IP → 422, draft still `PENDING_SIGNOFF`, text
unchanged (NEG-3).

**4. No sign-off ⇒ nothing published, state unchanged — MET.**
NEG-1: after 15 s with no sign-off the draft row is byte-for-byte equal to the
snapshot taken before (still `PENDING_SIGNOFF`, `published_at` empty), the sink
is unchanged and no `comms_published` history entry exists.

**5. `timeout_escalation` approver refused by the publish gate — MET.**
NEG-2, two ways: `/signoff` with `approver=timeout_escalation` → 403 with the
draft unchanged; and a forged `APPROVED`-by-`timeout_escalation` row handed
straight to `publish_draft` → refused, sink unchanged, row still unpublished
("approver 'timeout_escalation' is a system value, not a human sign-off").

**6. Human sign-off publishes to the status channel; record shows who and when — MET.**
Webhook is unset, so the honest file sink is used: `channel=file_sink
sent=False`. The row records `approved_by=priya`, `decided_at` and
`published_at`; the message is in `customer_comms/status_updates.log`. The
`resolved` message was signed off through the CLI
(`scripts/comms_signoff.py approve … --as priya`). **Slack delivery itself was
not exercised** (no webhook configured).

**7. Full 6-system chain live for one incident, traceable — MET.**
Final run, `inc-f748c386be9f`: `detection → DETECTED`, `threat_assessment →
CANDIDATE → ASSESSED → DISPATCHED`, On-Call paged and acked, Forensics
preserved evidence, `containment → CONTAINED → RESOLVED`, `customer_comms
draft_created (resolved)`, `priya comms_signoff`, `comms_published`. The
incident's `status_history` and the sink line carry the same `incident_id`.
In this run the live Forensics answered `LIFT: YES`; in earlier runs it answered
`LIFT: NO`, and the test accepts either (section 4).
Note: because the lift came six seconds after containment, the first draft was
already a `resolved` one — the pipeline writes recovery-aware text whenever
recovery is done — so this particular run shows no separate `contained` draft.
The `resolved`-path negative and positive cases below cover that path
deterministically.

**8. Three new authority edges work; every other Comms edge is denied — MET.**
`test_phase4_gates.py` checks the edge matrix. Live over the wire: On-Call →
Comms `notify_status` denied; Forensics announcing `contained` denied (event
binding); Containment → Comms with `page` denied; the denied requests created no
drafts.

**9. Phase 3 tests still pass — MET** (all on the restarted stack):
`test_phase3_gates.py` 10/10, `test_phase3_e2e.py` 15/15,
`test_rca_continuation.py` pass, `test_recovery_revert.py` 5/5,
`test_guardrail_block.py` 6/6, plus `test_phase2_e2e.py` 13/13.
Phase 4 totals: `test_phase4_gates.py` 51/51, `test_phase4_e2e.py` 45/45.

---

## 4. Deviations, and why

1. **Postgres is native, not Docker.** Docker Desktop will not start on this
   host ("Virtualization support not detected"). I installed PostgreSQL 16
   natively on :5433 (role `crisis`, db `incidents`, schema loaded, migrations
   001 and 002 applied) and added `SKIP_DOCKER_STORE=1` to `start_all.ps1`. A
   separate Postgres 18 was already on the machine and was left alone. The
   Docker route still works wherever virtualization does.

2. **The `resolved` path is proved on seeded incidents; the live lift is
   reported, not required.** Forensics' `LIFT` decision is the model's
   judgment, and `LIFT: NO` is a defensible answer for a Critical successful
   credential-stuffing incident. The first e2e versions failed twice on that
   alone. I did **not** touch the recovery prompt. Instead: checks 1–10 stay on
   the live attack and accept `LIFT: NO` as valid; checks 11–15 and a new
   negative NEG-4 run on seeded CONTAINED incidents through Forensics' **real**
   `_recover()` in-process (only the model's `plan_recovery` is stubbed), with
   real A2A to the live Containment and Comms processes. `safe_to_lift=False` ⇒
   blocks stay, status stays `CONTAINED`, no `resolved` draft after a 45 s
   wait; `safe_to_lift=True` ⇒ lift, `RESOLVED`, `resolved` draft, CLI
   sign-off, publish. This differs slightly from `test_recovery_revert.py`'s
   direct send, because the `resolved` announcement comes from Forensics, not
   Containment. NEG-4 is the property worth proving: no lift, no `resolved`
   message.

3. **Waits lengthened to match live latency (timeouts only).** Threat
   Assessment sometimes takes minutes under free-tier retries (one run: 5 min
   46 s CANDIDATE → ASSESSED). `test_phase4_e2e.py` check 2 now waits for
   severity *and* a post-assessment status (up to 600 s); the Phase 2 and Phase 3
   e2e waits were raised to 300–600 s. No assertion's expected behavior was
   changed.

4. **A real race in the Phase 3 re-page check, diagnosed and fixed.**
   `test_phase3_e2e.py` failed "On-Call was re-paged" even with generous waits.
   Instead of just stretching a timeout, I measured it with a standalone
   diagnostic that repeats the scenario and timestamps each step: severity is
   raised at +24.3 s and the `reopened` marker is set at the same instant, but
   On-Call's `paged` lands at +37.2 s, **12.9 s later**. Threat Assessment
   writes the new severity first and then re-pages On-Call, whose page includes
   an LLM-composed message. The test read `on_call.paged` the instant severity
   changed. So the re-page was happening (Priya, `sec-critical`); the test was
   early. The fix is a bounded wait (≤120 s) for `on_call.paged` before the
   unchanged assertion. The check then passed, 15/15. This is one measured
   diagnostic plus one passing re-run, not a stress test of the timing.

5. **Dead OpenRouter fallback replaced.** `nvidia/nemotron-3-super-120b-a12b:free`
   is still listed in OpenRouter's catalog but returns an upstream 404 on every
   call. I replaced it in both chains with `nvidia/nemotron-3-ultra-550b-a55b:free`
   after confirming it answers. With the Gemini models rate-limited, the RCA
   continuation test now continues onto the next round and passes.

6. **Key hygiene.** While looking up the model I printed the old
   OpenRouter key into the session output; it was rotated afterward and the
   whole stack restarted on the new one.

---

## 5. What is needed from the user before Phase 5

1. **Slack webhook — `COMMS_SLACK_WEBHOOK_URL`** (optional). Until it is set,
   publishing uses the file sink and `sent=False`; real Slack delivery is
   untested.
2. **Docker / virtualization** (optional). Enable virtualization in the BIOS and
   the Windows features if you want the Docker route back; the native Postgres
   works meanwhile.
3. **Gemini quota** remains the main pressure point. Assessment latency swings
   between under a minute and several minutes, and the tests now allow for it.
4. **Free-model churn.** Free OpenRouter models can disappear or 404 without
   leaving the catalog; keep an eye on the fallback entry.

**Carried over:** cloud deploy of the target app is still deferred, so the
firewall remains simulated.
