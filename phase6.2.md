# Phase 6.2 — Multiple Attack Shapes, Per-Incident Scoped Views, Visible Live LLM Calls

**This is a focused add-on to Phase 6.1, not a new architecture phase.** The hybrid attack from 6.1 proved the full six-system chain runs live, correctly, with a real finding along the way (Containment correctly refused to lift on a Critical incident — that's documented behavior, not a bug). This phase exists to make the demo richer and the live views legible when more than one attack has run: more attack shapes to show, each live vi# Phase 6.2 — Multiple Attack Shapes, Per-Incident Scoped Views, Visible Live LLM Calls

**This is a focused add-on to Phase 6.1, not a new architecture phase.** The hybrid attack from 6.1 proved the full six-system chain runs live, correctly, with a real finding along the way (Containment correctly refused to lift on a Critical incident — that's documented behavior, not a bug). This phase exists to make the demo richer and the live views legible when more than one attack has run: more attack shapes to show, each live view scoped to the incident actually being watched, and the reasoning feed showing an LLM call *while it's in flight*, not only after it resolves — so what a viewer sees is visibly a live call, not a replay.

## Context Carried Over From Phase 6.1

- `scripts/attack_live.py` runs a hybrid attack (recon via `/profile?username=`, then credential-stuffing against confirmed accounts) by default, with `--stage enum` preserving the old recon-only shape that Detection correctly does not escalate (no login activity, no signal — this is a documented Detection scope boundary, tracked in `docs/BACKLOG.md` under Phase 7, not something this phase touches)
- Full six-system live run proven: Detection → Threat Assessment → parallel dispatch (Containment, On-Call, Forensics) → evidence + approval gates → containment → sign-off → publish, with `--auto-ack` acknowledging the page automatically
- Live log tab streams `access.log` in near real time; live reasoning feed shows narrated, causally-linked agent output grouped by system, with an incident filter dropdown already present on the reasoning feed (seen as "incident: all (live)" in the existing UI)
- Scrubbed trace table confirmed to still contain zero attacker IPs/usernames after the hybrid run
- Real login → dashboard flow exists on the branded site (Phase 6.1 Task 1), using the target app's existing `/login` session behavior unchanged

---

## Decisions Settled Before This Phase Starts

1. **Two to three new attack patterns, added to `attack_live.py` alongside the existing hybrid and `--stage enum`.** At minimum include: (a) a slower/quieter variant of the hybrid attack (same recon-then-credential-stuffing shape, spread over a longer window with randomized delay, to show Detection still catching a less obviously bursty pattern), and (b) a **negative-control baseline run** — realistic normal traffic only (a handful of legitimate-looking logins and profile views, no attack shape at all) that Detection should correctly **not** escalate. The baseline run is deliberately valuable for the demo: it proves the system doesn't cry wolf on ordinary traffic, which is a stronger credibility point than another attack that fires. A third pattern (e.g. a pure high-volume credential-stuffing burst with no recon stage) is welcome if time allows, but the slow-hybrid and the baseline are the two that matter most.
2. **Both live views get per-incident scoping, not just the reasoning feed.** The log tab needs the same kind of incident selector the reasoning feed already has, so that once an incident exists, the log tab can be narrowed to just that incident's traffic (by source IP and time window tied to the incident's own record — not by changing what gets logged). Default behavior: when no incident is selected, show everything live as today; once an attack produces an incident, auto-select that incident in both views so a demo doesn't require the presenter to manually filter mid-run. An explicit "all" option stays available in both.
3. **The reasoning feed shows a call in progress, not just a finished one.** When a system starts an LLM call, write (or update) a `reasoning_events` row showing which agent, which system, and that it has started, before the model responds — then resolve that same entry to the full reasoning text plus the `served_by` model tag once the call completes. A viewer watching live should be able to see "Threat Assessment is thinking..." appear and then resolve into real text, which is the clearest possible proof that this is a live call and not a pre-recorded log replay.
4. **Build and validate without spending real LLM calls or running a real attack in this session.** Every piece above — the new attack pattern code paths, the per-incident scoping in both views, and the in-progress-call UI state — must be proven correct using a mocked/fake agent response (the same `FakeLlm`-style approach already used elsewhere in this project for structural verification), exercised against a synthetic or replayed incident, not a live attack against the real model chain. **Do not run `attack_live.py` against the live stack with real LLMs as part of this build session.** The user will trigger the first real live run themselves, specifically so they can personally watch the log tab and reasoning feed confirm the system end to end rather than being told it was already verified.
5. **No change to agent decision logic, Detection's input data, severity handling, or gate behavior.** Same standing rule as every prior phase. If the slow-hybrid or baseline pattern reveals another gap like the enumeration one in 6.1, document it the same way (plain-English, added to `docs/BACKLOG.md` under Phase 7) rather than fixing it here.
6. **Demo login credentials get written down explicitly**, in `docs/DEMO_SCRIPT.md` and in the end-of-session report — the exact username/email and password to use when logging into the branded site during the demo, not just "use existing test credentials."
7. **All three surfaces — the branded site, the live log tab, and the live reasoning feed — get a visual polish pass**, not just new functionality bolted onto the existing look. The goal is that someone unfamiliar with the project can glance at any of the three and immediately understand what they're looking at and how it fits the overall flow, without the presenter narrating every element. This is presentation work only: it must not touch routes, `access.log` format, agent logic, or any data the UI reads — layout, typography, color, spacing, state indicators, and in-page framing only. Concretely:
   - **Branded site:** keep it consistent with the existing Northwind Cloud identity already built in Phase 6/6.1 — the login → dashboard flow should feel like a finished product page, not a placeholder.
   - **Live log tab:** make it visually obvious which lines belong to the active attack vs. background noise, and pair the incident selector (Task 2) with a clear "currently viewing: incident X / all traffic" header so nobody watching has to ask.
   - **Live reasoning feed:** this is the one that's telling the actual story, so it matters most — keep the per-system color coding and causal grouping already built in Phase 6.1, but make the sequence read as a visible pipeline (e.g. a slim flow header or breadcrumb showing Detection → Threat Assessment → Containment/On-Call/Forensics → Comms, with the currently-active stage highlighted as entries arrive) so a non-technical viewer can follow the chain at a glance, not just by reading narration text top to bottom.
   - Keep it plain HTML/CSS/vanilla JS, consistent with every other phase's "no new framework" rule — this is about layout and clarity, not rebuilding the frontend stack.

---

## Task 1 — New Attack Patterns

- Add the slow-hybrid and baseline-negative-control patterns to `attack_live.py` (e.g. `--pattern slow-hybrid`, `--pattern baseline`), alongside the existing default hybrid and `--stage enum`. Add the burst-only pattern too if time allows.
- Document each pattern's shape and expected Detection outcome (escalates / doesn't escalate, and why) in a short table in `docs/DEMO_SCRIPT.md`.

## Task 2 — Per-Incident Scoping on Both Live Views

- Add an incident selector to the log tab matching the reasoning feed's existing one, with the same auto-select-latest-open-incident behavior.
- Confirm both views stay correctly scoped when more than one incident exists in the store at once (e.g. run two patterns back to back against mocked data and confirm each view can isolate either one).

## Task 3 — Visible In-Progress LLM Calls

- Add the "call started" → "call resolved" two-step write to the reasoning-event capture path, for every system's agent calls.
- The feed UI should visibly distinguish an in-progress entry from a resolved one (e.g. a pulsing/dimmed state vs. full text), and the `served_by` model tag should only appear once resolved.

## Task 4 — Mocked-LLM Structural Validation

- Using a fake/mocked agent (reuse the project's existing fake-LLM pattern), drive a synthetic incident through the new code paths and confirm: each new attack pattern's code runs without error and produces the expected log/trace shape, the per-incident scoping correctly isolates data across at least two concurrent mock incidents, and the in-progress → resolved transition renders correctly in both views.
- This is the only validation step for this session. Do not additionally run a real attack against the live LLM chain to "double-check" — that's the user's step, deliberately.

## Task 5 — Document Demo Credentials

- Add the exact login email/username and password to use for the demo to `docs/DEMO_SCRIPT.md`, clearly labeled, and repeat them in the final report.

## Task 6 — Visual Polish on All Three Live Surfaces

- Apply the polish described in Decision 7 to the branded site, the live log tab, and the live reasoning feed.
- Prioritize the reasoning feed's pipeline framing (Detection → Threat Assessment → parallel dispatch → Comms, currently-active stage highlighted) — that's the single highest-value visual change for explaining the system to someone watching for the first time.
- Take a screenshot of each of the three surfaces after the polish pass and include them in the final report so the change can be reviewed without opening the repo.

---

## Exit Criteria (all must be true before this is demo-ready)

- [ ] At least two new attack patterns exist beyond the Phase 6.1 hybrid, including one negative-control baseline that Detection correctly does not escalate, each documented with its expected outcome
- [ ] The log tab supports per-incident scoping with the same selector pattern as the reasoning feed, auto-selecting the latest open incident
- [ ] The reasoning feed visibly shows an LLM call in progress before it resolves, with `served_by` appearing only on resolution
- [ ] All of the above is verified via mocked/fake-LLM structural testing only — no real attack was run against the live stack in this session
- [ ] `docs/DEMO_SCRIPT.md` contains the exact demo login credentials and the new pattern table
- [ ] No change to agent decision logic or Detection's input data; Phase 6 and 6.1's existing exit criteria still hold
- [ ] The branded site, live log tab, and live reasoning feed have all had a visual polish pass per Decision 7, with the reasoning feed's pipeline framing in place, and screenshots of all three are included in the report

---

## Explicitly Out of Scope

- Running a real attack against the live LLM chain in this session (the user does this personally, after the code is delivered)
- Any change to agent decision logic, severity thresholds, gate behavior, or Detection's window-summary fields (still Phase 7, including the enumeration-detection gap already in `docs/BACKLOG.md`)
- A unified single-page UI merging the log tab and reasoning feed (still a nice-to-have only, per Phase 6)
- Fixing the Phase 2 Detection flakiness (tracked separately)

If something here seems to require any of the above, stop and flag it rather than building around it.

---

## Instructions for Claude Code

Build all five tasks directly in the repository. Validate everything with a mocked/fake agent as described in Task 4. **Do not run `attack_live.py` against the live stack with real LLMs at any point in this session** — the user will run the first real live attack themselves once this is delivered, specifically to watch the log tab and reasoning feed confirm correct behavior with their own eyes.

**At the end of the session, report back in plain text, in this exact structure:**

1. **What was built, task by task**, against the 6 tasks above
2. **Files created or modified**, full list of paths
3. **Exit criteria check**: MET / PARTIAL / NOT MET for each of the 7 criteria, with evidence from the mocked-LLM structural tests (not a live run), plus the three screenshots from Task 6
4. **Deviations from these instructions**, and the reason for each
5. **Exact demo login credentials**, plus a one-line note on what command the user should run themselves to trigger the first real live attack and watch it end to endew scoped to the incident actually being watched, and the reasoning feed showing an LLM call *while it's in flight*, not only after it resolves — so what a viewer sees is visibly a live call, not a replay.

## Context Carried Over From Phase 6.1

- `scripts/attack_live.py` runs a hybrid attack (recon via `/profile?username=`, then credential-stuffing against confirmed accounts) by default, with `--stage enum` preserving the old recon-only shape that Detection correctly does not escalate (no login activity, no signal — this is a documented Detection scope boundary, tracked in `docs/BACKLOG.md` under Phase 7, not something this phase touches)
- Full six-system live run proven: Detection → Threat Assessment → parallel dispatch (Containment, On-Call, Forensics) → evidence + approval gates → containment → sign-off → publish, with `--auto-ack` acknowledging the page automatically
- Live log tab streams `access.log` in near real time; live reasoning feed shows narrated, causally-linked agent output grouped by system, with an incident filter dropdown already present on the reasoning feed (seen as "incident: all (live)" in the existing UI)
- Scrubbed trace table confirmed to still contain zero attacker IPs/usernames after the hybrid run
- Real login → dashboard flow exists on the branded site (Phase 6.1 Task 1), using the target app's existing `/login` session behavior unchanged

---

## Decisions Settled Before This Phase Starts

1. **Two to three new attack patterns, added to `attack_live.py` alongside the existing hybrid and `--stage enum`.** At minimum include: (a) a slower/quieter variant of the hybrid attack (same recon-then-credential-stuffing shape, spread over a longer window with randomized delay, to show Detection still catching a less obviously bursty pattern), and (b) a **negative-control baseline run** — realistic normal traffic only (a handful of legitimate-looking logins and profile views, no attack shape at all) that Detection should correctly **not** escalate. The baseline run is deliberately valuable for the demo: it proves the system doesn't cry wolf on ordinary traffic, which is a stronger credibility point than another attack that fires. A third pattern (e.g. a pure high-volume credential-stuffing burst with no recon stage) is welcome if time allows, but the slow-hybrid and the baseline are the two that matter most.
2. **Both live views get per-incident scoping, not just the reasoning feed.** The log tab needs the same kind of incident selector the reasoning feed already has, so that once an incident exists, the log tab can be narrowed to just that incident's traffic (by source IP and time window tied to the incident's own record — not by changing what gets logged). Default behavior: when no incident is selected, show everything live as today; once an attack produces an incident, auto-select that incident in both views so a demo doesn't require the presenter to manually filter mid-run. An explicit "all" option stays available in both.
3. **The reasoning feed shows a call in progress, not just a finished one.** When a system starts an LLM call, write (or update) a `reasoning_events` row showing which agent, which system, and that it has started, before the model responds — then resolve that same entry to the full reasoning text plus the `served_by` model tag once the call completes. A viewer watching live should be able to see "Threat Assessment is thinking..." appear and then resolve into real text, which is the clearest possible proof that this is a live call and not a pre-recorded log replay.
4. **Build and validate without spending real LLM calls or running a real attack in this session.** Every piece above — the new attack pattern code paths, the per-incident scoping in both views, and the in-progress-call UI state — must be proven correct using a mocked/fake agent response (the same `FakeLlm`-style approach already used elsewhere in this project for structural verification), exercised against a synthetic or replayed incident, not a live attack against the real model chain. **Do not run `attack_live.py` against the live stack with real LLMs as part of this build session.** The user will trigger the first real live run themselves, specifically so they can personally watch the log tab and reasoning feed confirm the system end to end rather than being told it was already verified.
5. **No change to agent decision logic, Detection's input data, severity handling, or gate behavior.** Same standing rule as every prior phase. If the slow-hybrid or baseline pattern reveals another gap like the enumeration one in 6.1, document it the same way (plain-English, added to `docs/BACKLOG.md` under Phase 7) rather than fixing it here.
6. **Demo login credentials get written down explicitly**, in `docs/DEMO_SCRIPT.md` and in the end-of-session report — the exact username/email and password to use when logging into the branded site during the demo, not just "use existing test credentials."

---

## Task 1 — New Attack Patterns

- Add the slow-hybrid and baseline-negative-control patterns to `attack_live.py` (e.g. `--pattern slow-hybrid`, `--pattern baseline`), alongside the existing default hybrid and `--stage enum`. Add the burst-only pattern too if time allows.
- Document each pattern's shape and expected Detection outcome (escalates / doesn't escalate, and why) in a short table in `docs/DEMO_SCRIPT.md`.

## Task 2 — Per-Incident Scoping on Both Live Views

- Add an incident selector to the log tab matching the reasoning feed's existing one, with the same auto-select-latest-open-incident behavior.
- Confirm both views stay correctly scoped when more than one incident exists in the store at once (e.g. run two patterns back to back against mocked data and confirm each view can isolate either one).

## Task 3 — Visible In-Progress LLM Calls

- Add the "call started" → "call resolved" two-step write to the reasoning-event capture path, for every system's agent calls.
- The feed UI should visibly distinguish an in-progress entry from a resolved one (e.g. a pulsing/dimmed state vs. full text), and the `served_by` model tag should only appear once resolved.

## Task 4 — Mocked-LLM Structural Validation

- Using a fake/mocked agent (reuse the project's existing fake-LLM pattern), drive a synthetic incident through the new code paths and confirm: each new attack pattern's code runs without error and produces the expected log/trace shape, the per-incident scoping correctly isolates data across at least two concurrent mock incidents, and the in-progress → resolved transition renders correctly in both views.
- This is the only validation step for this session. Do not additionally run a real attack against the live LLM chain to "double-check" — that's the user's step, deliberately.

## Task 5 — Document Demo Credentials

- Add the exact login email/username and password to use for the demo to `docs/DEMO_SCRIPT.md`, clearly labeled, and repeat them in the final report.

---

## Exit Criteria (all must be true before this is demo-ready)

- [ ] At least two new attack patterns exist beyond the Phase 6.1 hybrid, including one negative-control baseline that Detection correctly does not escalate, each documented with its expected outcome
- [ ] The log tab supports per-incident scoping with the same selector pattern as the reasoning feed, auto-selecting the latest open incident
- [ ] The reasoning feed visibly shows an LLM call in progress before it resolves, with `served_by` appearing only on resolution
- [ ] All of the above is verified via mocked/fake-LLM structural testing only — no real attack was run against the live stack in this session
- [ ] `docs/DEMO_SCRIPT.md` contains the exact demo login credentials and the new pattern table
- [ ] No change to agent decision logic or Detection's input data; Phase 6 and 6.1's existing exit criteria still hold

---

## Explicitly Out of Scope

- Running a real attack against the live LLM chain in this session (the user does this personally, after the code is delivered)
- Any change to agent decision logic, severity thresholds, gate behavior, or Detection's window-summary fields (still Phase 7, including the enumeration-detection gap already in `docs/BACKLOG.md`)
- A unified single-page UI merging the log tab and reasoning feed (still a nice-to-have only, per Phase 6)
- Fixing the Phase 2 Detection flakiness (tracked separately)

If something here seems to require any of the above, stop and flag it rather than building around it.

---

## Instructions for Claude Code

Build all five tasks directly in the repository. Validate everything with a mocked/fake agent as described in Task 4. **Do not run `attack_live.py` against the live stack with real LLMs at any point in this session** — the user will run the first real live attack themselves once this is delivered, specifically to watch the log tab and reasoning feed confirm correct behavior with their own eyes.

**At the end of the session, report back in plain text, in this exact structure:**

1. **What was built, task by task**, against the 5 tasks above
2. **Files created or modified**, full list of paths
3. **Exit criteria check**: MET / PARTIAL / NOT MET for each of the 6 criteria, with evidence from the mocked-LLM structural tests (not a live run)
4. **Deviations from these instructions**, and the reason for each
5. **Exact demo login credentials**, plus a one-line note on what command the user should run themselves to trigger the first real live attack and watch it end to end