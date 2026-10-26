# Phase 2 — Containment/Ops + On-Call/Escalation + Guardrail Gate v1 + Multi-Provider LLM Routing

## Context Carried Over From Phase 1

Phase 1 is complete and verified. What exists and is proven working:

- Attack simulation script (`scripts/attack_simulate.py`) — brute-force, burst, and baseline patterns against the local target app
- Detection & Monitoring (ADK, port 9101) — real log tailing, LLM-reasoned noise filtering, writes `DETECTED` row, sends real A2A task to Threat Assessment
- Threat Assessment & Intelligence (ADK, port 9102) — real threat-intel correlation, LLM-reasoned severity/type classification, writes `ASSESSED` row with `status_history` audit trail, **dispatch is currently a stub** that logs well-formed envelopes for Containment and On-Call without sending them
- Incident store with CHECK-constrained status vocabulary, `advance_status()` that refuses backward moves, `escalated` and `incident_type` columns
- `shared/a2a_support.SYSTEM_URLS` — registry of known agent endpoints, currently only has Detection and Threat Assessment

**The binding constraint going into this phase:** Gemini's free tier was exhausted during Phase 1 testing alone, by 2 systems. Phase 2 adds 2 more systems (Containment, On-Call) and more calls per incident. This phase **must** solve LLM reliability before building more agents on top of a shaky foundation — so that work comes first, not last.

---

## Decisions Settled Before This Phase Starts

1. **Multi-provider LLM routing (Option C), not paid Gemini.** Build a routing/fallback layer so no single provider's free-tier limit blocks the project. This is university-project scope — don't over-engineer it (see Task 1 for exactly what's in and out of scope).
2. **Containment and On-Call are CrewAI**, per the original architecture. Confirmed — proceed.
3. **Guardrail middleware lives in the shared layer** (`shared/guardrail.py` or similar), not duplicated per-system — every system imports and calls the same policy-check function before any real side-effecting action or outbound A2A call. This keeps the authority matrix in one place as more systems get added in later phases.
4. **Dispatch goes real this phase** — Threat Assessment's stub is replaced with real A2A calls to Containment and On-Call.

---

## Task 1 — Multi-Provider LLM Routing Layer (build this first)

**Goal:** No single provider's rate limit should be able to stall the pipeline, the way Gemini's free tier did in Phase 1.

**Scope, kept deliberately tight for a university project — do not go beyond this:**

- Use **LiteLLM** as the routing abstraction. Every agent calls one LiteLLM-wrapped interface instead of calling a specific provider's SDK directly.
- Configure a **fallback chain per agent role**, not one global chain — reasoning-heavy agents (severity classification, threat correlation, future root-cause analysis) get a different priority order than simple/mechanical agents (noise filtering verdicts, status lookups):
  - **Reasoning-heavy chain:** Gemini (`gemini-2.5-flash` or current non-retired equivalent) → Cerebras → OpenRouter free tier
  - **Mechanical/simple chain:** local Ollama model (e.g., `llama3.1:8b` or `qwen2.5:7b`, whichever the dev machine runs comfortably) → Gemini as fallback only if local is unavailable
- **Failure handling — two cases, handled differently:**
  - **Upfront rejection** (429 / quota exhausted / auth error before any generation starts): retry the **original prompt**, unchanged, on the next provider in the chain. This is the common case — it's what actually happened in Phase 1 — and LiteLLM handles it natively via its fallback config; do not build custom logic for this case.
  - **Mid-generation cutoff** (partial output returned before a failure): **only implement this for agents doing long-form, open-ended reasoning** (in this phase, that's none yet — Containment and On-Call's agents are short, bounded decisions, not long essays). Build the partial-continuation handling as a small reusable helper (`shared/llm.py`, likely already has a hook from Phase 1) but do not spend significant time on it this phase — it becomes relevant in Phase 3 for Forensics' Root Cause Analysis Agent, not before. If it's more than a half-day of work to get working cleanly, stop and defer it to Phase 3 with a note, rather than polishing it now.
- Log which provider actually served each call (for the audit trail, and so quota issues are visible rather than silent)
- `.env`-configurable: provider priority order and model names should not be hardcoded, so switching providers later is a config change

**Explicitly out of scope for this task:** cost-based routing, latency-based routing, custom retry/backoff tuning beyond what LiteLLM provides by default, a provider health-check dashboard. This is a reliability patch, not a product.

**Exit check for this task:** simulate a provider failure (e.g., temporarily point the primary model name at something invalid, or exhaust a key deliberately) and confirm the call still succeeds via fallback, with a log line showing which provider actually answered.

---

## Task 2 — Guardrail Middleware v1

**Goal:** A real, code-level gate — not a prompt instruction — that blocks a side-effecting action until conditions are met.

- Build `shared/guardrail.py` with a policy-check function, e.g. `check_authority(from_system, to_system, action_type) -> bool` and a separate `requires_human_approval(severity) -> bool`
- Define the **authority matrix for the systems that exist after this phase** (Detection, Threat Assessment, Containment, On-Call) as a simple static structure (dict/table) in this file — not scattered across agents:
  - Detection → Threat Assessment: allowed (send candidate)
  - Threat Assessment → Containment: allowed (request action)
  - Threat Assessment → On-Call: allowed (trigger paging)
  - Containment → anything: **not allowed to call other systems directly** in this phase
  - On-Call → Containment: allowed only for the specific "timeout escalation" signal (used in Phase 2's human-approval flow — see Task 4)
- **Approval gate:** `requires_human_approval(severity)` returns true for High/Critical. Containment's action-execution step must call this and, if true, must not proceed until an approval signal exists (see Task 4 for how that signal arrives).
- This must be enforced as a real function call inside the tool-execution path — i.e., the actual cloud API call (or its local-sandbox equivalent — see Task 3) is physically gated behind this check in code, not just described in the agent's prompt/instructions.

**Exit check:** write a small test that calls Containment's mitigation path with a High-severity incident and no approval — confirm the real action does NOT execute, and is logged as blocked/pending, not silently skipped or silently allowed.

---

## Task 3 — Containment/Ops System (CrewAI)

Build as its own process, own venv (`.venv-crew`, already exists from Phase 0), own A2A agent card, registered in `shared/a2a_support.SYSTEM_URLS`.

- **Situation Review Agent** — for this phase, "real cloud API" means whatever is actually available: if no cloud account exists yet (cloud deploy is still deferred per Phase 0/1), simulate the equivalent locally — e.g., a mock "firewall rule" state file or in-memory structure representing which IPs are currently blocked, which the target app could plausibly check. Do not block this phase on a real cloud account; note clearly in the report whether this is real-cloud or local-simulated, so it's an honest, visible gap, not a silent one.
- **Immediate Action Agent** — decides on a mitigation action (block IP, in this phase's scope — keep the action set small: blocking the offending IP(s) identified by Threat Assessment is sufficient, don't build isolate-server/revoke-token/rollback-deployment unless time allows). Before executing: calls the guardrail's `requires_human_approval()` check. If required and not yet approved, the task must sit in a pending state, not fail and not silently proceed.
- **Status Reporting Agent** — once executed (or once approval clears and it executes), sends a real A2A status update back toward Threat Assessment, and updates the incident row's status.

---

## Task 4 — On-Call/Escalation System (CrewAI)

Build as its own process, own A2A agent card, registered in `SYSTEM_URLS`.

- **On-Call Lookup Agent** — a simple static schedule is fine for this phase (hardcoded or a small config file mapping severity/time → a contact). Real rotation logic is out of scope.
- **Notification Agent** — sends a **real** notification. Simplest real option: a Slack webhook (free, quick to set up) or email via a free transactional email API. Avoid building a custom SMS integration unless you already have a provider in mind — scope creep risk is high here.
- **Escalation Timer Agent** — starts a timer when paged. For this phase, keep it simple: a short, demo-friendly window (e.g., configurable, default 2 minutes so it's demoable live, not a realistic 15-minute production value). On acknowledgment (a simple callback endpoint or a manual "ack" trigger for now — a full Slack interactive-button flow is a nice-to-have, not required), the timer stops and an approval signal is written that Containment's guardrail check can see. **On timeout**, this agent writes an auto-approval signal with `approved_by=timeout_escalation` instead of a human identity, so Containment can proceed — this makes the approval signal's provenance visible in the audit trail (human vs. timeout) without building full multi-tier escalation yet (next tier paging is Phase 3+ scope, not required here).

**Note:** this phase builds the approval **signal mechanism** (how Containment learns "approved" happened) at the simplest level that works — a row/flag in the incident store that both On-Call and Containment read/write, keyed on `incident_id`. A full pub/sub event bus is Phase 3+ scope (that's where the genuine timeout-vs-approval race condition gets built properly); this phase just needs the signal to exist and be correct.

---

## Task 5 — Wire Real Dispatch

- Replace Threat Assessment's Phase 1 dispatch stub with real A2A calls to Containment and On-Call, using the now-registered `SYSTEM_URLS` entries
- Confirm the fan-out is genuinely parallel (both calls fired without waiting for one to finish before starting the other), not accidentally sequential

---

## Exit Criteria (must all be true before moving to Phase 3)

- [ ] LLM routing layer demonstrably survives a simulated provider failure via fallback, with the serving provider logged
- [ ] Guardrail middleware demonstrably blocks a real action when approval is required and absent (not just logs a warning — the action genuinely does not execute)
- [ ] Containment executes a real (or honestly-labeled local-simulated) mitigation action once approval clears
- [ ] On-Call sends a real notification and correctly handles both paths: human acknowledgment before timeout, and timeout with auto-approval — both producing a traceable, provenance-tagged approval signal
- [ ] Threat Assessment's dispatch is real (not a stub) and demonstrably parallel to both Containment and On-Call
- [ ] Full chain runs live: attack script → Detection → Threat Assessment → parallel dispatch → On-Call pages → (approval or timeout) → Containment acts → status reported back, all traceable in the incident store for one incident_id

---

## Explicitly Out of Scope for This Phase

- Forensics & Recovery system (Phase 3)
- The evidence-preservation handshake and feedback/re-classification loop (Phase 3)
- Customer Communications system (Phase 4)
- Real pub/sub-based race condition between timer and approval (Phase 3+ — this phase's version is store-flag based, intentionally simpler)
- Multi-tier escalation beyond one timeout step (Phase 3+)
- Cloud deployment of anything (still deferred)

If something above feels necessary to finish a Phase 2 task, stop and flag it rather than building it.

---

## Instructions for Claude Code

Build this phase's deliverables directly in the project repository, following the decisions above exactly. If a decision turns out to be unworkable in practice (e.g., local Ollama is too slow on the dev machine, or a free Slack webhook has an unexpected limitation), flag it clearly rather than silently substituting something else.

**At the end of the session, report back in plain text, in this exact structure** (same shape as the Phase 0 and Phase 1 reports):

1. **What was built, task by task** — against the 5 tasks above
2. **Files created or modified** — full list of paths
3. **Exit criteria check** — MET / PARTIAL / NOT MET for each of the 6 criteria above, with evidence (log snippet, test output, query result) wherever possible
4. **Deviations from these instructions**, and the reason for each
5. **What is needed from the user before Phase 3 can begin** — be explicit and itemized about any API keys, accounts, or webhooks required. For each one needed, state: which provider, what it's for, and that it is currently missing/blocking. Do not proceed past a missing key by silently working around it in a way that changes the architecture — report it as a blocker instead, the same way the Gemini key requirement was reported after Phase 0.

Do not begin any Phase 3 task (Forensics, evidence handshake, feedback loop) under this phase.