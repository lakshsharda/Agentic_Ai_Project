# Phase 5 — completion report (Observability Dashboard)

Verified 2026-10-21, Python 3.11.9, Windows 11, native Postgres 16 on :5433.

**Seven of eight exit criteria MET; one PARTIAL (criterion 8, the regression suite).** The unified trace table,
the denied-call trace, the read-only dashboard and its live walkthrough all work and are proven. The one
open item is an *intermittent* failure in `test_phase2_e2e.py` that is independent of this phase's code (shown
below with tracing switched off) but is not root-caused. It is reported rather than hidden.

---

## 1. What was built, task by task

### Task 1 — Unified trace table — **done**
- `infra/migrations/003_phase5_trace_log.sql`, folded into `infra/schema.sql` (a fresh install loads cleanly; checked
  against a scratch database). `trace_events`: `event_id, incident_id` (nullable, no foreign key so a denial for
  a non-existent incident still lands), `timestamp, from_system, to_system, event_type, decision` (CHECKed to
  `auto | human | timeout_escalation | blocked | n/a`)`, summary, detail JSONB`.
- `shared/trace.py` — `record_trace()`. Never raises, never blocks: it timestamps the event and queues it; one
  daemon thread writes. After a failed write the writer pauses 3 s and drops what arrives meanwhile, so a dead
  store cannot build a backlog. Summaries and details are **scrubbed** on the way in (IPv4/IPv6 and internal
  hostnames replaced, free-text and attacker-derived keys dropped), using the Phase 4 validator's patterns.
- Wired at the shared chokepoints so all six systems write rows: every `check_authority()` call (allowed
  *and* denied, now carrying the incident id), both gates (`gate_evaluated`, with `decision` = `blocked` /
  `auto` / `human` / `timeout_escalation`), approvals, evidence preservation, every `advance_status()`, A2A
  send/receive on both ends, reclassify messages tagged `reclassify_sent` / `reclassify_received`, Containment and
  On-Call actions (including "no action taken" and refused/allowed recovery lifts), and Comms draft creation,
  sign-off and publish. Identical routine gate/authority rows within 20 s are collapsed so Containment's gate polling
  does not read as a heartbeat. `TRACE_DISABLED=1` is a kill switch (used for the experiment below).

### Task 2 — Dashboard backend — **done**
`dashboard/server.py`, FastAPI on :8090 (already installed in `.venv-crew`; the six systems use it too, so no new
dependency and no new venv). `GET /incidents`, `GET /incidents/{id}/timeline` (trace rows merged with
`status_history` and `comms_drafts`, UTC-normalised and time-sorted, Comms moments de-duplicated),
`GET /live`, `GET /health`. Read-only; no write or approval route; **never returns draft text**; every string is
scrubbed on the way out; with the store down it answers 503 with a JSON error, not a stack trace.

### Task 3 — Dashboard frontend — **done**
`dashboard/static/index.html`, plain HTML/JS, polls every 3 s. Rows are colour-coded: grey A2A/event, green
auto-passed, blue cleared by a human, amber cleared by timeout escalation, red blocked, and a pulsing red row for
a gate that is blocked *right now*. A banner shows drafts awaiting sign-off with the existing route
(`scripts/comms_signoff.py` / `/signoff`) — there is no approve button. "Follow newest" auto-scroll keeps the
latest event in view during a live demo.

### Task 4 — Prove it live — **done**
`scripts/test_phase5_dashboard.py` — **52/52** (twice, clean). It covers the degrade-to-warning test, scrubbing, two
live incidents (human-acked and timeout-cleared), denied calls over the wire and in-process, the reclassification
trace, the backend against the table, and the leak scan. Manual walkthroughs with screenshots are in criterion 6.

---

## 2. Files created or modified

Created: `infra/migrations/003_phase5_trace_log.sql`, `shared/trace.py`, `dashboard/__init__.py`,
`dashboard/server.py`, `dashboard/static/index.html`, `scripts/test_phase5_dashboard.py`, `docs/PHASE5_REPORT.md`.

Modified: `infra/schema.sql`, `shared/guardrail.py`, `shared/a2a_support.py`, `shared/comms_notify.py`,
`shared/store/incidents.py`, `shared/store/drafts.py`, `detection/agents.py`, `detection/server.py`,
`threat_assessment/server.py`, `threat_assessment/dispatch.py`, `containment/server.py`, `on_call/server.py`,
`forensics/server.py`, `customer_comms/server.py`, `customer_comms/publisher.py`, `scripts/start_all.ps1`,
`scripts/test_phase2_e2e.py` and `scripts/test_phase3_e2e.py` (waits only; plus one bounded wait before the
re-page assertion), `.env` (OpenRouter fallback model id; key rotated by the user).

---

## 3. Exit criteria check

**1. `trace_events` written by all six systems; never blocks or alters an action — MET.**
The live trace carries rows from `detection, threat_assessment, containment, on_call, forensics, customer_comms`.
Degrade test: with the writer pointed at a dead connection string `record_trace` returned in under a millisecond,
`check_authority` still answered correctly (allowed pair True, denied pair False), `advance_status` still moved
the incident, malformed arguments were swallowed, one warning was logged
(`trace write failed (ConnectionTimeout…); the action it describes is unaffected`), nothing was written meanwhile,
and tracing recovered by itself once the store was back.

**2. Complete, correctly ordered trace for one `incident_id` — MET.** Queried directly: `None -> DETECTED`,
`CANDIDATE`, `ASSESSED`, `DISPATCHED`, `CONTAINED`, `draft_created`, `signoff_recorded`, `published`, in lifecycle
order; the whole trace is in non-decreasing time order; the action gate shows blocked-while-pending, then the
approval, then the clearing gate, in that order.

**3. A denied authority-matrix call traced as `authority_denied` — MET.** On-Call→Comms `notify_status` and
Containment→Comms `page` (denied by the live Comms process) and Comms→Containment (in-process), all
`decision=blocked`; a denial with no incident id at all is stored with `incident_id NULL`.

**4. Backend endpoints return correct, real data — MET.** `/incidents` matches the store's status/severity;
`/timeline` returns exactly the table's trace rows in the same order, merged with history and drafts; `/live`
returns exactly the newest rows; store-down answers 503 with a clear error.

**5. Frontend renders the timeline and distinguishes auto / human / timeout / blocked — MET.** Screenshots
(headless Edge) show green AUTO, red BLOCKED, amber TIMEOUT rows and the pulsing red PENDING row on one incident
(`…\scratchpad\shots\7b_timeout_full.png`, `6_gate_blocked_pending.png`).

**6. Auto-refresh, used to watch an incident live, end to end — MET.** Two walkthroughs with the dashboard open:
(a) human path — stage 1 gate pending → human ack → `approval_recorded … human`, `gate_evaluated … ALLOWED`,
blocks executed, `CONTAINED`, a draft pending (orange banner), sign-off, `published`; (b) no-ack path — red
`PENDING` gate row (`BLOCKED - approval required (severity=High) and none recorded yet`), then amber
`approval recorded by timeout_escalation` and `gate ... ALLOWED - approved by timeout_escalation`, then `CONTAINED`.
The walkthroughs also found and fixed real bugs (below).

**7. No attacker IPs, usernames or internal hosts in the trace table or dashboard — MET.** Scanned all
rows in the table after the regression traffic (thousands of rows, including seeded test data containing IPs and
usernames): zero IPv4/IPv6, zero internal hostnames; zero of the live incidents' targeted usernames in their trace
rows or any API response. One scan flagged the loopback address inside the dashboard's own sign-off hint; that
was reworded rather than the check loosened.

**8. Phase 4's regression suite still passes — PARTIAL.**
Latest clean run on the final code: `test_phase4_gates` 51/51, `test_phase3_gates` 10/10, `test_phase3_e2e` 15/15,
`test_phase4_e2e` 45/45, `test_phase2_e2e` 13/13, `test_recovery_revert` 5/5, `test_guardrail_block` 6/6,
`test_target_app` 16/16, `test_phase5_dashboard` 52/52. Not clean:
- **`test_phase2_e2e.py` is intermittent (~50%).** Failures: "attack produced a new incident: none" (Detection did
  not open an incident, on the first or the second attack). Evidence it is not the tracing: with tracing
  **fully disabled** (`TRACE_DISABLED=1` in every server and the test) one run failed this way and one passed
  13/13; with tracing on, a sample of three passed 13/13, failed on the second attack, passed 13/13. The cause
  is not isolated (Detection's model-dependent noise filter, its 30 s window and 20 s cooldown are the suspects).
- **A stale assertion in the same file:** "full lifecycle recorded" requires the status history to end exactly at
  `CONTAINED`, but Phase 4 deliberately adds `RESOLVED` when a recovery lift is carried out; the test fails
  whenever the live Forensics answers `LIFT: YES`. Left unchanged pending your decision.
- **`test_rca_continuation.py` depends on provider availability.** It needs two chain models to answer so it can
  prove truncation handling; when `gemini-flash-latest` returns 503 and `gemini-2.5-flash` and OpenRouter return
  429 it sees one round and fails. It passed earlier the same day with more models reachable.

---

## 4. Deviations from these instructions, and why

1. **Criterion 8 is PARTIAL, not MET** — see above; reported honestly instead of re-running until green.
2. **Uncertain-answer severity floor (a fix, made at your request).** A weak fallback model (Gemini over quota
   → OpenRouter) could return an incomplete severity answer; Threat Assessment's strict validation then raised and
   the task died with an `InternalError`, so a reclassification never happened and live incidents stalled at
   `CANDIDATE`. `_coerce_assessment()` now fills only descriptive fields. Separately, every *uncertain* path
   used to fall back to **Medium**, and `requires_human_approval("Medium")` is **False** — an ambiguous answer got
   less oversight than a clear High/Critical. All four paths (no result, incomplete answer, off-vocabulary severity,
   reclassification fallback) now resolve to at least **High** (`UNCERTAIN_SEVERITY_FLOOR`, asserted at import time
   to require approval); a fallback already higher (e.g. Forensics suggested Critical) is kept, never lowered; a
   clear answer, including a clear Low, is respected; `escalate` is derived from the severity, never invented.
3. **A race in the Phase 3 re-page check, diagnosed and fixed.** Threat Assessment raises severity first and
   re-pages On-Call ~13 s later (the page includes an LLM-composed message); the test read `on_call.paged` the
   instant severity changed. Measured with a standalone diagnostic, fixed with a bounded wait before the
   unchanged assertion. Also: Phase 2/3 e2e waits were lengthened to match live model latency.
4. **Bugs the walkthrough found and fixed:** trace rows (local zone) and `status_history` (UTC) were sorted as
   strings, mis-ordering the timeline; Comms moments appeared twice; On-Call's reuse of the wire action
   `timeout_escalation` as a generic "approval available" nudge made a human ack read like a timeout (summary now
   says so; the `approval_recorded` row shows who approved); refused recovery lifts and the no-action containment
   outcome left no trace; the "ordered by time" test passed trivially (now compares parsed UTC times).
5. **Writer cooldown drops events** during a store outage (a few seconds of trace rows), by design, to avoid a
   backlog; the actions are unaffected.
6. **Postgres is native** (carried forward), and `docs/PHASE5_REPORT.md` was written late, after the Phase 6
   file asked for it.

Known limitation (as agreed): the dashboard has no authentication — a local demo tool.

---

## 5. What is needed from the user before Phase 6 / Phase 7

1. **Decision — the Phase 2 lifecycle assertion.** Update it to accept `RESOLVED` as a valid terminal state
   (Phase 4 made that a real, intended transition), or leave it. I have not edited it.
2. **Decision — the intermittent Detection failure** behind the Phase 2 e2e flake. Root-causing it touches
   Detection's window/cooldown/noise-filter behaviour, which is outside Phases 5–6; it sits naturally with the
   Phase 7 concurrency/race work if you want it fixed rather than tolerated.
3. **Gemini quota / billing.** Free-tier caps and 503 spikes are the main source of run-to-run variation (including
   `test_rca_continuation`). Not blocking.
4. `COMMS_SLACK_WEBHOOK_URL` — still unset; Comms publishes to the file sink (`sent=False`). Optional.
