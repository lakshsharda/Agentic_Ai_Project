# Phase 6.1 — Demo-Ready Login Flow + Guided Live Walkthrough

**This is a focused add-on to Phase 6, not a new architecture phase.** Phase 6 is built and its six exit criteria are met (`docs/PHASE6_REPORT.md`). This phase exists for one reason: the person demoing this to a professor needs to **stand in front of the real site, log in, trigger a real attack, and watch the whole multi-agent chain narrate itself** without having to explain raw JSON or a flat event feed. Nothing here touches agent decision logic, severity handling, or gate behavior — that stays exactly as Phase 4–6 left it.

## Context Carried Over From Phase 6

What exists and is proven working (see `docs/PHASE6_REPORT.md` for full detail):

- Branded site "Northwind Cloud" on :8081, a skin over the unchanged `target_app/app.py` routes — `/login`, `/status`, `/profile` behavior and `access.log` format are untouched and must stay that way
- Live log tab streaming `access.log` in near real time
- `reasoning_events` table + a live reasoning feed page showing real agent output from all six systems, grouped by system, in time order, clearly banner-marked as the unsanitized internal view
- `scripts\run_demo.ps1 -Pattern <pattern>` — one command from cold start to all services up and an attack running
- The scrubbed `trace_events` table stays a provably separate pathway from the unscrubbed reasoning feed (confirmed zero PII leakage)

**Known open items carried in, not blocking this phase:** the `test_phase2_e2e` intermittent Detection flake is still being characterized separately and is not this phase's concern. Postgres must be up and stable before any of this phase's work is demoed (see prior report's Postgres note).

---

## The Problem This Phase Solves

Phase 6 built the right *infrastructure* — a log tab and a reasoning tab both exist and both work. What's still missing for an actual demo in front of a professor:

1. The branded site has no real, usable login-to-dashboard experience yet — a "Sign in" button that doesn't lead anywhere credible undercuts the demo before it starts.
2. There's no single place that tells the demoer exactly what commands to run, in what order, to go from nothing to a live attack.
3. The reasoning feed currently reads as a flat list of agent outputs. For a technical audience that's fine; for a professor who is not reading A2A payloads in real time, it needs to visibly **narrate the handoff** — this log window triggered Detection, Detection's verdict triggered Threat Assessment, Threat Assessment's severity triggered parallel dispatch, etc. — so someone watching it live can follow the causal chain without the demoer narrating every line themselves.

---

## Decisions Settled Before This Phase Starts

1. **Login must be real, not cosmetic.** Use the target app's *existing* `/login` behavior and session handling exactly as it already works (proven 16/16 in the Phase 0 target-app tests, unchanged through Phase 6). Do not add new auth logic, new routes, or anything that changes `access.log`'s format or line count. If the current `/login` doesn't actually establish a session today, say so and propose the smallest possible addition that doesn't touch logging — don't guess and build silently.
2. **A dashboard page is shown after a successful login**, styled consistently with the rest of the Northwind Cloud site, showing believable account-ish content (e.g. account status, a couple of mock usage stats, a "recent sign-ins" widget). This is presentation only — it must not write anything to `access.log` beyond what a normal page load already writes (if `/profile` or `/status` already represents this, reuse it rather than inventing a new authenticated page).
3. **One printed, copy-pasteable command sequence** is the deliverable for running the demo — not just a working script, but the exact lines a nervous presenter can read off a card. This goes in a new file, e.g. `docs/DEMO_SCRIPT.md`, and is also printed by `run_demo.ps1` itself when it finishes starting up (what to type next, in what tab, to do what).
4. **The reasoning feed gets a narration layer, additive only.** Do not change what any agent decides or how. Add a short, plain-English one-line summary attached to each reasoning entry (e.g. "Detection analyzed 23 requests in 0.94s from 198.51.100.77 and escalated." / "Threat Assessment classified this CRITICAL and dispatched to Containment, On-Call, and Forensics in parallel."). Where one entry is a direct causal consequence of a previous one (verdict → dispatch → gate → action), visually connect them — an arrow, indentation, or grouped block — so the sequence reads top to bottom as a story, not a timestamp-sorted list a viewer has to mentally reassemble.
5. **No change to agent decision logic, severity handling, gate behavior, or the authority matrix.** This phase is UI, command documentation, and presentation of data that already exists. If anything here seems to require touching decision logic, stop and flag it rather than building it.

---

## Task 1 — Real Login → Dashboard on the Branded Site

- Wire the existing "Sign in" button to the target app's real `/login` form behavior, using one of the credentials already used by `attack_simulate.py` / the existing test fixtures (document which one).
- On successful login, show a dashboard page in the Northwind Cloud visual shell: account name, a status widget, a couple of plausible usage numbers. Keep it static/mock data — this is not a real product, it's a believable skin.
- On failed login, show a normal invalid-credentials message (this is also what the attack script will trigger in bulk — that's the point, don't suppress or change this behavior).
- Confirm `access.log` line count and format are unchanged by running the Phase 0 target-app test suite again and pasting the result.

## Task 2 — The Demo Command Script

- Write `docs/DEMO_SCRIPT.md`: numbered, copy-pasteable PowerShell commands covering, in order: cold-start launch, opening the branded site and logging in, which tab to switch to for the live log, running `attack_simulate.py` with a specific recommended pattern for demo purposes (pick one that produces a clean CRITICAL path through all six systems reliably, and say why you picked it), switching to the reasoning feed, and — if time allows — the Phase 5 trace dashboard as the "this is the audited, customer-safe version" closing beat.
- `run_demo.ps1` should print this same short "what to do next" sequence to the terminal once services are up, so the demoer isn't juggling two documents.

## Task 3 — Narrated Reasoning Feed

- Add a one-line plain-English summary to each `reasoning_events` entry as it's written (generate it alongside the existing capture, not as a separate LLM call — derive it from data already available, e.g. the verdict/severity/decision fields already being captured, so this stays cheap and doesn't add latency to the live demo).
- Visually group or connect causally-linked entries (Detection's escalate → Threat Assessment receiving it → the parallel dispatch fan-out → each downstream system's action) so a viewer can trace the chain without needing the raw A2A payload.
- This is additive to the existing feed — the full raw reasoning text stays visible underneath or alongside the summary line, it is not replaced.

## Task 4 — One Dry Run, Timed

- Run the full sequence from `docs/DEMO_SCRIPT.md` exactly as written, cold start to finished incident, with a stopwatch. Report total time, and flag any step that's slow enough to be awkward live (e.g. waiting on an approval gate — note where a presenter would need to either pre-stage an approval or narrate through the wait).

---

## Exit Criteria (all must be true before calling this demo-ready)

- [ ] Logging in on the branded site with real credentials works end to end and lands on a dashboard page, with zero change to `access.log` format (Phase 0 target-app tests still pass)
- [ ] `docs/DEMO_SCRIPT.md` exists and was followed verbatim in a real dry run, cold start to finished incident, with no undocumented manual steps
- [ ] The reasoning feed shows a plain-English narration line on every entry, and causally-linked entries are visually traceable as a sequence
- [ ] The dry run is timed and any slow/awkward step is called out with a recommended way to handle it live (pre-staging, talking through the wait, etc.)
- [ ] Phase 6's existing six exit criteria still hold (nothing here regressed the log tab, reasoning feed separation, or the scrubbed trace table's PII guarantee)

---

## Explicitly Out of Scope

- Any change to `/login`, `/status`, `/profile` behavior, status codes, or `access.log` format
- Any change to agent decision logic, severity thresholds, or gate behavior (Phase 7)
- Real authentication/security on the dashboard (still a local demo tool)
- The Phase 2 Detection flakiness investigation (tracked separately, not this phase's job)

If something here seems to require any of the above, stop and flag it rather than building around it.

---

## Instructions for Claude Code

Before building, confirm Phase 6's exit criteria still hold on the current stack (relaunch via `run_demo.ps1` or `start_all.ps1` as appropriate). Then build this phase's four tasks directly in the repository.

**At the end of the session, report back in plain text, in this exact structure:**

1. **What was built, task by task**, against the 4 tasks above
2. **Files created or modified**, full list of paths
3. **Exit criteria check**: MET / PARTIAL / NOT MET for each of the 5 criteria, with evidence (the timed dry-run walkthrough, screenshots of login → dashboard, a sample narrated reasoning sequence, test output)
4. **Deviations from these instructions**, and the reason for each
5. **The actual contents of `docs/DEMO_SCRIPT.md`**, pasted in full, so it can be reviewed without opening the repo