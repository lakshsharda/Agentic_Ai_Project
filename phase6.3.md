# Phase 6.3 — 20-Case Live Validation Matrix

**This is a validation pass, not a build phase.** Phase 6.2 delivered multiple attack patterns, per-incident scoping, visible in-progress LLM calls, and a visual polish pass — but it was deliberately validated only with a mocked LLM, so the user could personally run the first real live attack. That's now done (or about to be). This phase asks for the opposite of 6.2's restriction: **design 20 distinct test cases that exercise the system's real behavior space, and run every one of them live, for real, against the actual LLM chain.** The point is confidence before a demo or submission — a single happy-path run proves the chain *can* work; 20 varied cases are what prove it *reliably* works across the range of things it claims to handle.

## Context Carried Over From Phase 6.2

What should exist going into this phase (confirm before starting, don't assume):

- `scripts/attack_live.py` supports multiple patterns: the default hybrid (recon + credential-stuffing), `--stage enum` (recon-only, a known non-escalating case), a slow-hybrid variant, a baseline negative-control pattern, and possibly a burst-only pattern
- Both the live log tab and live reasoning feed support per-incident scoping with auto-select-latest-open-incident
- The reasoning feed shows an LLM call in progress before it resolves, with `served_by` on resolution
- All three live surfaces (branded site, log tab, reasoning feed) have had a visual polish pass, including the reasoning feed's pipeline framing
- `docs/DEMO_SCRIPT.md` has the demo login credentials and the pattern table
- `docs/BACKLOG.md` documents the known Detection enumeration-only blind spot as Phase 7 scope

If any of the above isn't actually in place, say so before starting rather than building test cases against a system that isn't there yet.

---

## Decisions Settled Before This Phase Starts

1. **Claude Code designs the 20 cases first, as a table, before running anything.** The table goes in `docs/VALIDATION_MATRIX.md`: case number, short name, what it's testing, the attack pattern or action used, and the expected outcome. This lets the full scope be sanity-checked (by inspection) before burning real LLM calls and wall-clock time on all 20.
2. **Every case runs live, for real** — real attack traffic (or a real scripted action, for cases that aren't attack-driven, like an authority-matrix denial or a draft-validator rejection), real LLM calls, real gate evaluations. No mocking in this phase; that was Phase 6.2's job and is done.
3. **Coverage must span the system's actual behavior space, not 20 variations on one theme.** At minimum, the 20 cases should include: multiple severities (Low/Medium/High/Critical) actually produced by real traffic, not asserted; all four gate decision types (auto-pass, human-approved, timeout-escalated, blocked/denied) occurring for real; at least one authority-matrix denial, visibly traced; the reclassification/feedback loop firing at least once; both a recovery lift (`safe_to_lift=True`) and a recovery refusal (`safe_to_lift=False`, same as the Phase 6.1 finding) occurring for real; at least one Comms draft validator rejection (a deliberately bad draft or edit); the `timeout_escalation` approver being refused by the publish gate; the known-non-escalating enumeration-only case (confirming it still correctly does not escalate); the baseline negative-control case (confirming normal traffic still does not escalate); and at least one case with two incidents open concurrently, to confirm per-incident scoping in the log tab and reasoning feed actually isolates them. Fill remaining slots with variations on attack timing/volume/pattern that are likely to surface new edge cases, including anything that stresses the cross-provider LLM fallback.
4. **Every run captures real evidence, not just pass/fail.** For each case: the resulting `incident_id` (where applicable), the actual severity/decision/outcome observed, the relevant trace/reasoning-event rows or a short excerpt, and timing. A case that produces an unexpected result is not silently retried until it passes — it's recorded as-is, and investigated only if it looks like a real bug rather than legitimate system behavior (e.g. a borderline severity call differing from your guess is not a bug; an incident that should have escalated and silently didn't is).
5. **No change to agent decision logic, Detection's input data, severity thresholds, or gate behavior as a result of this phase.** This phase finds out how the system actually behaves across 20 real cases; it does not change that behavior. If a case surfaces a genuine bug (not a known, already-documented boundary like the enumeration gap), stop, report it clearly with evidence, and ask before fixing it — don't silently patch and re-run.
6. **Budget check before running all 20.** Before executing, give a rough estimate of total wall-clock time and real LLM call volume for the full matrix (based on the per-stage timings already observed in the Phase 6.1 dry run), so there's a chance to trim the list if it's going to take an unreasonable amount of time or spend. Then proceed once that's acknowledged — this doesn't need to block on a back-and-forth, just state the estimate plainly in the same message as the finished table before running.

---

## Task 1 — Design and Document the 20 Cases

- Build `docs/VALIDATION_MATRIX.md`: a table of exactly 20 cases per Decision 1 and 3 above.
- State the time/spend estimate for running all 20, per Decision 6.

## Task 2 — Run All 20 Cases Live

- Execute each case for real, in a reasonable order (e.g. grouping cases that can safely share a stack state, separating ones that need a clean incident count for scoping checks).
- Capture evidence for each as described in Decision 4, written into `docs/VALIDATION_MATRIX.md` alongside each case's row (a results column, or a linked section per case — your call, say which).

## Task 3 — Summarize Results

- A short results summary: how many of the 20 behaved exactly as expected, how many diverged and why (legitimate behavior vs. real bug), and whether anything found belongs in `docs/BACKLOG.md` as a new, clearly worded Phase 7 item.
- Re-confirm the scrubbed trace table still has zero PII after all 20 cases have run (a higher-volume version of the same check done after the Phase 6.1 hybrid run).

---

## Exit Criteria (all must be true before this phase is done)

- [ ] `docs/VALIDATION_MATRIX.md` exists with exactly 20 well-specified cases, each with a clear expected outcome, built before any case was run
- [ ] All 20 cases were run live against the real LLM chain, not mocked
- [ ] Every case has recorded evidence (incident id where applicable, observed outcome, relevant trace/reasoning excerpt, timing) — not just a pass/fail mark
- [ ] The coverage requirements in Decision 3 are each satisfied by at least one real case (severities, all four gate decision types, an authority denial, a reclassification, both a lift and a refusal, a validator rejection, a refused timeout-escalation publish attempt, the enumeration non-escalation, the baseline non-escalation, and a concurrent-incident scoping check)
- [ ] Any genuine bug found (as opposed to already-documented or legitimate behavior) is reported clearly with evidence, not silently fixed
- [ ] The scrubbed trace table has zero attacker IPs/usernames after all 20 runs
- [ ] No agent decision logic, Detection input data, or gate behavior was changed as a result of this phase

---

## Explicitly Out of Scope

- Fixing anything found, beyond what Decision 5 allows (report and ask first)
- Any change to agent decision logic, severity thresholds, gate behavior, or Detection's window-summary fields
- Building new attack patterns beyond what's needed to hit the coverage list in Decision 3 (reuse what Phase 6.2 built wherever it already covers a case)
- A unified single-page UI (still out of scope per Phase 6)

If something here seems to require any of the above, stop and flag it rather than building around it.

---

## Instructions for Claude Code

Build `docs/VALIDATION_MATRIX.md`'s 20-case table and time/spend estimate first (Task 1), present it, and then proceed straight into running all 20 live (Task 2) and summarizing (Task 3) in the same session — this phase does not need a separate approval step between the table and the run, per Decision 6.

**At the end of the session, report back in plain text, in this exact structure:**

1. **The 20-case table**, summarized (full detail lives in `docs/VALIDATION_MATRIX.md`, but list all 20 case names and outcomes here too so it can be read without opening the repo)
2. **Files created or modified**, full list of paths
3. **Exit criteria check**: MET / PARTIAL / NOT MET for each of the 7 criteria, with evidence
4. **Any genuine bugs found**, with evidence, kept separate from legitimate/expected behavior variations
5. **What is needed from the user before Phase 7 can begin**, itemized, including any new backlog items this run surfaced