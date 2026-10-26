# Phase 6 — Live Demo Experience (Branded Site, Live Logs, Live Agent Reasoning)

**Note on renumbering:** this phase is inserted ahead of the originally-planned "timeout race condition + edge cases" work. That work is now **Phase 7**. Final polish and demo rehearsal is now **Phase 8**. Nothing about Phases 0–5 changes; this phase builds on top of the finished Phase 5 dashboard.

## Context Carried Over From Phase 5

Phase 5 is complete (confirm its final regression re-run and `docs/PHASE5_REPORT.md` are both green before starting this phase — if they are not, finish closing Phase 5 first). What exists and is proven working:

- Six independent systems, each its own process and A2A agent card: Detection (ADK, :9101), Threat Assessment (ADK, :9102), Containment/Ops (CrewAI, :9103), On-Call/Escalation (CrewAI, :9104), Forensics & Recovery (CrewAI, :9105), Customer Communications (CrewAI, :9106)
- The full feedback loop (reclassification), the evidence and approval gates, and the mandatory Comms sign-off all work live, including under a hardened severity-floor fallback (`UNCERTAIN_SEVERITY_FLOOR`, asserted at import time to require approval)
- `shared/trace.py` and the `trace_events` table: every gate, authority check, A2A message, and status move is recorded, non-blocking, scrubbed of IPs/usernames/hostnames — this scrubbing is correct and must **not** be loosened; see Decision 2
- A read-only FastAPI dashboard backend on :8090 and a polling frontend showing one incident's timeline, color-coded (pending / human / timeout / blocked), with a sign-off banner linking to `scripts/comms_signoff.py`
- `scripts/attack_simulate.py`: configurable brute-force / burst / baseline patterns against the local target app, writing real `access.log` entries
- Target app (`target_app/app.py`): a minimal Flask app — login, status, profile — deliberately insecure, currently with no visual branding
- Native Postgres 16 on port 5433, `scripts/start_all.ps1` with `SKIP_DOCKER_STORE=1`

---

## Decisions Settled Before This Phase Starts

1. **The target app becomes a small, believably-branded company site**, not a redesign of its security behavior. Give it a name (pick something generic and clearly fictional, e.g. "Northwind Cloud" or similar — not a real company), a simple landing page, and a slightly nicer login/dashboard shell around the **existing** endpoints and logging. Do not change `/login`, `/status`, `/profile`'s behavior, status codes, or log format — Detection depends on that format exactly as it is. This is a skin, not a rewrite.
2. **Two different live views, with two different rules — do not merge them:**
   - The **Phase 5 trace dashboard** stays exactly as it is: scrubbed, audit-grade, the thing you'd show as evidence the guardrails work.
   - A **new live reasoning feed**, built this phase, is explicitly internal-only and unscrubbed — it shows real attacker IPs, usernames, and full LLM reasoning text, because the whole point is proving the reasoning is grounded in real data. Label it clearly in the UI (e.g. a banner: "Internal demo view — not sanitized") so it's never confused with the audit trail or mistaken for something that could be shown to a customer.
3. **Capturing reasoning text is additive, not a rework of any agent.** Every system's reasoning agents already produce real text (Detection's verdict, Threat Assessment's rationale, Forensics' root-cause narrative, Comms' draft reasoning, etc.) — this phase captures and surfaces that text, it does not change what any agent decides or how it decides it.
4. **One command starts the whole demo.** A single script (e.g. `scripts/run_demo.ps1`) should: confirm all six systems and the dashboard backend are up (start them if not, via the existing `start_all.ps1`), open the two browser tabs (or print the two URLs if it can't open a browser), and then accept a pattern argument and kick off `attack_simulate.py`. The person running the demo should not need to remember multiple commands or manually arrange windows.
5. **Live log tab is a simple real-time tail**, not a new logging system. Reuse `access.log` exactly as it already exists; stream new lines to a browser tab as they're written (a small SSE or websocket endpoint on a lightweight backend is enough — reuse the dashboard backend process if that's simplest, or a second small one, your call, but say which and why).

---

## Task 1 — Brand the Target Site

- Add a simple landing page and light visual shell (a name, a logo-as-text or simple SVG, consistent colors) around the existing login/status/profile pages. Keep it to plain HTML/CSS — no new frontend framework, no new build step.
- Do not touch `target_app/app.py`'s routes, status codes, or `access.log` format. If a change there seems necessary to make the branding work, stop and flag it — Detection's parser depends on this format being exact.

## Task 2 — Live Log Tab

- A browser tab that tails `target_app/logs/access.log` in real time as the attack runs, showing raw JSON lines as they're written (pretty-printed is fine, raw JSON is also fine — readability matters more than formatting polish).
- This should need no polling delay noticeable to a viewer — a line appearing in the log should appear on screen within roughly a second.

## Task 3 — Live Agent Reasoning Feed

- A new table, e.g. `reasoning_events` (separate from `trace_events` — do not add unscrubbed fields to the existing scrubbed table), written by every system alongside its existing trace writes, capturing: `incident_id`, `timestamp`, `system`, `agent_name` (e.g. "Noise Filtering Agent", "Severity Classification Agent", "Root Cause Analysis Agent"), and the actual reasoning/output text the agent produced.
- Use the same non-blocking, never-raises write pattern as `shared/trace.py` (reuse or closely mirror it) — a reasoning-feed write failure must never affect a real action, same principle as Decision 4 in Phase 5.
- A browser tab that shows this feed live, grouped or clearly labeled by which system and agent produced each entry, in time order, auto-scrolling, so a viewer watching it can see Detection reasoning, then Threat Assessment reasoning, then Containment's decision reasoning, and so on, as the incident actually unfolds.
- Clearly mark this tab as the internal/unsanitized view (Decision 2).

## Task 4 — One-Command Demo Launcher

- `scripts/run_demo.ps1` (or equivalent): starts/confirms all services, opens or prints the three views (branded site, live log tab, live reasoning feed — plus the existing Phase 5 trace dashboard makes four total views available, but the launcher's job is just to make them reachable, not to force all four open at once if that's visually overwhelming; use your judgment and explain your choice), then runs `attack_simulate.py` with a chosen pattern.
- Confirm it works from a cold start (no servers running) and from a warm start (servers already up).

---

## Exit Criteria (all must be true before moving to Phase 7)

- [ ] The target site has a believable company identity and its existing routes/logging are provably unchanged (re-run `scripts/test_target_app.py` or equivalent from Phase 0 and confirm it still passes)
- [ ] The live log tab shows new `access.log` lines appearing within about a second of being written, during a real attack run
- [ ] The live reasoning feed shows real reasoning text from at least Detection, Threat Assessment, and one of Containment/Forensics/Comms, correctly time-ordered, for one real incident
- [ ] The reasoning feed is visibly and explicitly marked as the unsanitized internal view, and is a genuinely separate table/pathway from `trace_events` — confirm the Phase 5 scrubbed trace table still contains zero raw IPs/usernames after a run that populates the reasoning feed (the two must not leak into each other)
- [ ] One command starts the full demo from a cold stack and a real incident is watchable end to end across the log tab, the reasoning feed, and the existing Phase 5 trace dashboard
- [ ] Phase 5's full regression suite still passes on the current stack

---

## Explicitly Out of Scope for This Phase

- Any change to agent decision logic, severity handling, or gate behavior (that's Phase 7)
- The timeout-vs-approval race hardening and multi-incident concurrency (Phase 7)
- Cloud deployment of anything
- Authentication or access control on any of the demo views (still a local-only demo tool)
- A unified single-page view combining all four tabs into one UI (nice-to-have only if time allows; separate tabs/windows is a perfectly good demo)

If something above feels necessary to finish a Phase 6 task, stop and flag it rather than building it. Do not start any Phase 7 work.

---

## Instructions for Claude Code

Before building, confirm Phase 5's final regression results and report are actually green (ask the user if unclear). Relaunch everything with `scripts\start_all.ps1` and confirm the Phase 5 dashboard still works as a baseline. Then build this phase's deliverables directly in the repository, following the decisions above exactly — especially Decision 2: the scrubbed audit trail and the unscrubbed internal reasoning feed must stay two genuinely separate pathways.

**At the end of the session, report back in plain text, in this exact structure** (same shape as the Phase 0 to 5 reports):

1. **What was built, task by task**, against the 4 tasks above
2. **Files created or modified**, full list of paths
3. **Exit criteria check**: MET / PARTIAL / NOT MET for each of the 6 criteria, with evidence (log snippets, test output, screenshots or a described walkthrough of all four live views during one real incident)
4. **Deviations from these instructions**, and the reason for each
5. **What is needed from the user before Phase 7 can begin**, itemized. Do not work around a missing decision or credential in a way that changes the architecture; report it as a blocker.