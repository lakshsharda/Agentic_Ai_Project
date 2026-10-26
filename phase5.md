# Phase 5 — Observability Dashboard

## Context Carried Over From Phase 4

Phase 4 is complete, all 9 exit criteria MET (`docs/PHASE4_REPORT.md`). What exists and is proven working:

- **Six independent systems**, each its own process and A2A agent card, registered in `shared/a2a_support.SYSTEM_URLS`: Detection (ADK, :9101), Threat Assessment (ADK, :9102), Containment/Ops (CrewAI, :9103), On-Call/Escalation (CrewAI, :9104), Forensics & Recovery (CrewAI, :9105), Customer Communications (CrewAI, :9106)
- The full chain runs live: attack → detection → assessment → parallel dispatch (Containment, On-Call, Forensics) → evidence gate + approval gate → containment → `contained` notify → draft → sign-off → publish, root cause → recovery lift decision → `resolved` notify (or no draft, if `safe_to_lift=False`) → draft → sign-off → publish
- The feedback loop is real: Forensics can send `reclassify` back to Threat Assessment mid-incident, which revises severity, re-opens approval, and re-pages On-Call (confirmed with a diagnosed and fixed timing race — see `docs/PHASE4_REPORT.md` deviation 4)
- `shared/guardrail.py`: `AUTHORITY_MATRIX`, `check_authority()` (deny-by-default), `requires_human_approval()`, `evaluate_action_gate()`, `evaluate_publish_gate()` — every gate decision is a real code branch, not a prompt instruction
- Incident store (native Postgres 16, port 5433 — see deviation below): CHECK-constrained status vocabulary `DETECTED → CANDIDATE → ASSESSED → DISPATCHED → CONTAINED → RESOLVED`, `advance_status()` refuses backward moves, `status_history` audit trail (including `reclassified` and Comms `event`-tagged entries), `comms_drafts` table with full sign-off provenance
- `shared/llm.py`: LiteLLM routing, per-role chains, cross-provider fallback (Gemini + OpenRouter) proven live including a dead-model swap and mid-generation continuation (`test_rca_continuation.py`)
- `ONCALL_SLACK_WEBHOOK_URL` is set and real; `COMMS_SLACK_WEBHOOK_URL` is **not** set — Comms publishing still uses the honest file sink with `sent=False`
- Full regression suite green on the current stack: `test_phase4_gates.py` 51/51, `test_phase4_e2e.py` 45/45, `test_phase3_gates.py` 10/10, `test_phase3_e2e.py` 15/15, `test_phase2_e2e.py` 13/13, `test_recovery_revert.py` 5/5, `test_guardrail_block.py` 6/6, `test_rca_continuation.py` passing

**Infrastructure deviation from the original Phase 0 plan, carried forward:** Postgres runs as a native Windows service on port 5433 (via winget), not the Dockerized instance Phase 0 originally set up. `scripts/start_all.ps1` has a `SKIP_DOCKER_STORE=1` switch for this. Phase 5's dashboard must read from **whichever store is actually running** — don't assume Docker, and don't silently switch this back. If this matters for how you'll demo the project (e.g. needing Docker running for some other reason), say so now.

**Open items, not blocking this phase:** `COMMS_SLACK_WEBHOOK_URL`, `CEREBRAS_API_KEY`, Ollama, cloud deploy of the target app (still deferred; the firewall stays simulated).

---

## Decisions Settled Before This Phase Starts

1. **No new A2A systems.** Phase 5 adds observability, not a seventh agent system. The dashboard is a passive reader of what already exists.
2. **Trace log lives in the incident store**, as a new table, not a separate log file or external service. Everything needed to reconstruct a timeline is already partly present across `status_history`, `comms_drafts`, and the servers' own stdout logs — Phase 5 unifies this into one queryable, timestamped table that every system writes to as it acts, rather than scraping logs after the fact.
3. **The dashboard is a local web UI the demo runs on a laptop**, not a hosted artifact. A single lightweight backend (Flask or FastAPI, your choice, but say which and why) serves a read-only view over the trace table, with a simple auto-refreshing or polling frontend. No new framework sprawl — reuse `.venv-app` or a thin new `.venv-dashboard` if the dependencies don't belong in either existing venv; justify whichever you pick.
4. **Writing traces must not become a seventh approval gate.** Trace writes are logging, not control flow: if a trace write fails, the real action it's describing must still have happened and still be correct — a dashboard outage must never block or alter an incident. Wrap every trace write in a guarded call that degrades to a warning, same pattern already used for the scaffold agents' incident-store writes back in Phase 0.
5. **Scope is read and display, not edit.** The dashboard does not add new sign-off or approval actions — `scripts/comms_signoff.py` and the existing `/signoff` endpoint remain how approvals happen. The dashboard may link to or embed the pending-drafts list for visibility, but does not duplicate the approval logic.

---

## Task 1 — Unified Trace Table

- Add migration `infra/migrations/003_phase5_trace_log.sql` (apply via `scripts/migrate_store.py`, fold into `infra/schema.sql` for fresh volumes/installs, same pattern as before).
- A `trace_events` table: `event_id`, `incident_id` (nullable — some events, like a rejected A2A call due to an authority-matrix denial, may not have a valid incident yet), `timestamp`, `from_system`, `to_system` (nullable for internal events), `event_type` (free text but documented: e.g. `a2a_sent`, `a2a_received`, `authority_denied`, `gate_evaluated`, `action_executed`, `status_advanced`, `draft_created`, `signoff_recorded`, `published`), `decision` (one of `auto`, `human`, `timeout_escalation`, `blocked`, `n/a`), `summary` (short human-readable text), `detail` (JSON blob for anything structured worth keeping, e.g. the gate's reasoning or the A2A payload's event name — never raw draft text with PII/IP content, since the Phase 4 validator rules apply here too: no attacker IPs or usernames in `summary` or `detail`).
- Write a single shared helper, `shared/trace.py` with `record_trace(...)`, used by all six systems. Every system that already calls `check_authority()`, `evaluate_action_gate()`, `evaluate_publish_gate()`, `advance_status()`, or sends/receives an A2A task should call `record_trace()` alongside it. This is mostly wiring, not new logic — find every existing call site for those functions and add a trace write next to each one.
- Specifically make sure these are captured, since they are the moments that make the project's guardrail story demonstrable:
  - Every `check_authority()` call, including denials (so a denied cross-system request shows up, not just allowed ones)
  - Every gate evaluation (`evaluate_action_gate`, `evaluate_publish_gate`), with `decision` reflecting whether it was `blocked`, or who/what cleared it (`human`, `timeout_escalation`)
  - The re-classification / feedback-loop messages specifically, tagged distinctly (e.g. `event_type=reclassify_sent` / `reclassify_received`) so the timeline can visibly show the back-and-forth, not just a forward chain
  - Comms draft creation, sign-off and publish events

---

## Task 2 — Dashboard Backend

- A small read-only service (new file, e.g. `dashboard/server.py`) exposing:
  - `GET /incidents` — list of incidents with id, current status, severity, created/updated times
  - `GET /incidents/<incident_id>/timeline` — the full ordered `trace_events` rows for that incident, merged with its `status_history` and `comms_drafts` so one call gives everything needed to render one incident's story top to bottom
  - `GET /live` — the most recent N trace events across all incidents (for a "what's happening right now" view during a live demo)
- Keep this stateless and read-only. It should tolerate the incident store being temporarily unreachable without crashing — return a clear error the frontend can show, not a stack trace.

---

## Task 3 — Dashboard Frontend

- A single page (plain HTML/JS is fine — this does not need a frontend framework for a university project) that:
  - Lists active/recent incidents, clickable into a timeline view
  - Renders one incident's timeline as a vertical, timestamped sequence, visually distinguishing: a plain A2A message, a gate that auto-passed, a gate that waited for a human, a gate that was satisfied by timeout escalation, and a gate currently blocked/pending
  - Auto-refreshes (simple polling every few seconds is sufficient; no need for websockets) so it's usable as a live "watch it happen" view during a demo
  - Shows, for the currently selected incident, its current `status`, `severity`, and whether a Comms draft is pending sign-off right now (with a visible link/reference to use `comms_signoff.py` or the `/signoff` endpoint — not a working approve button, per Decision 5)
- Visual design should be simple and legible over flashy — this is a lab/demo tool, not a product. A clear timeline with color-coded decision types (e.g. auto vs human vs timeout vs blocked) is the single most important thing to get right, since it's what directly demonstrates the guardrail/authority-boundary story to a viewer.

---

## Task 4 — Prove It Live

- Write `scripts/test_phase5_dashboard.py` that: runs a real attack through the stack (reuse `scripts/attack_simulate.py`), confirms the trace table is populated for that `incident_id` with entries from every system the incident actually touched, confirms at least one `authority_denied` entry exists somewhere in the system by deliberately attempting a denied call (e.g. Comms attempting an outbound A2A call, or Containment attempting to call Comms directly) and checking it's traced, and confirms the backend's two incident endpoints return data consistent with what's in the table.
- Manually (not scriptable, but report on it) run one full live incident end to end with the dashboard open, and describe in the report what the timeline showed at each stage — this is effectively your own first dry run of the demo.

---

## Exit Criteria (all must be true before moving to Phase 6)

- [ ] `trace_events` table exists, is written by all six systems, and never blocks or alters a real action if a trace write fails (demonstrate this degrade-to-warning behavior with a quick test, e.g. by pointing the trace writer at a bad connection string briefly)
- [ ] A live attack run produces a complete, correctly ordered trace for one `incident_id`, provable by querying the table directly
- [ ] At least one denied authority-matrix call is visibly traced as `authority_denied`, not silently dropped
- [ ] The dashboard backend's `/incidents` and `/incidents/<id>/timeline` endpoints return correct, real data for a live incident
- [ ] The frontend renders one incident's full timeline and visually distinguishes auto / human / timeout_escalation / blocked decisions
- [ ] The frontend auto-refreshes and was used to watch at least one incident happen live, end to end, reported with what was observed at each stage
- [ ] No attacker IPs, usernames, or internal hosts appear anywhere in the trace table or the dashboard (the Phase 4 validator's rule applies here too — confirm this explicitly, don't assume it carries over for free)
- [ ] Phase 4's full regression suite still passes on the current stack

---

## Explicitly Out of Scope for This Phase

- Any new approval or sign-off actions in the dashboard UI (Decision 5)
- The timeout-vs-approval race hardening and multi-incident concurrency work (Phase 6)
- Cloud deployment of anything
- Real Slack delivery for Comms (optional, unrelated to this phase)
- Any Legal/Compliance system (removed from the project)
- Authentication/access control on the dashboard (it's a local demo tool; note this as a known limitation in the report rather than building it)

If something above feels necessary to finish a Phase 5 task, stop and flag it rather than building it. Do not start any Phase 6 work.

---

## Instructions for Claude Code

Before building, relaunch everything with `scripts\start_all.ps1` (with `SKIP_DOCKER_STORE=1` if that's still the working setup) and confirm Phase 4's full regression suite still passes, so you have a known-good baseline. Then build this phase's deliverables directly in the repository, following the decisions above exactly.

**At the end of the session, report back in plain text, in this exact structure** (same shape as the Phase 0 to 4 reports):

1. **What was built, task by task**, against the 4 tasks above
2. **Files created or modified**, full list of paths
3. **Exit criteria check**: MET / PARTIAL / NOT MET for each of the 8 criteria, with evidence (log snippets, test output, query results, and ideally a screenshot or described walkthrough of the dashboard mid-incident)
4. **Deviations from these instructions**, and the reason for each
5. **What is needed from the user before Phase 6 can begin**, itemized. For each key, account, or decision: what it's for, and whether it's currently missing. Do not work around a missing credential or decision in a way that changes the architecture; report it as a blocker.