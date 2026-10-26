# Backlog

Items noticed during a phase but explicitly out of that phase's scope. Each is a candidate for the phase
named, not yet scheduled.

## Phase 7

- **Detection's window summary has no signal for enumeration-only reconnaissance** (repeated 404s with no
  login attempts), so pure username-harvesting traffic currently produces `escalate=False` even at high
  volume. Needs new summary fields (e.g. distinct-path-per-source, 404 ratio) before Detection can see this
  attack shape. Found in Phase 6.1 while building `scripts/attack_live.py --stage enum` (confirmed:
  `detection/windowing.py`'s `aggregate()` only counts login failures and targeted usernames against
  `/login`; a `/profile` scrape of 90 requests with 84 404s was read as "normal application polling").
  Reproduce on demand with `attack_live.py --stage enum`; do not fix inside Phase 6.1 (confirmed out of
  scope -- no change to Detection's input data or window-summary logic this phase).

  **Phase 6.3 correction (2026-10-25):** this is NOT a hard structural gap. Re-run live, in isolation,
  during the Phase 6.3 validation matrix, the identical traffic shape (`attack_live.py --stage enum`, 90
  `/profile` requests, 84 404s, 0 login attempts) was correctly classified `endpoint_enumeration`
  (confidence 0.9) and escalated -- see `inc-02f2f14d9cc9`, reasoning: *"This rapid volume of 404 errors
  on a single endpoint indicates automated profile enumeration or probing activity."* The aggregate window
  fields (`total_requests`, `requests_by_endpoint`, `requests_by_status`, `distinct_source_ips`) the model
  received were the same shape every prior time it said "normal application polling." **The real gap is
  non-determinism in the noise-filter LLM's judgment on this traffic shape, not a missing summary field**
  -- it sometimes reasons correctly about it and sometimes doesn't, on materially the same input. Revise
  the Phase 7 item accordingly: investigate whether new summary fields would make the *correct* read more
  consistent (lower the odds of the "normal polling" misread), or whether this calls for a different fix
  (e.g. a stricter/lower-temperature prompt for this one judgment, or a deterministic pre-filter ahead of
  the LLM call) -- not necessarily new fields alone, since the fields already present were sufficient for
  a correct call at least once. Do not assume `--stage enum` reliably reproduces non-escalation in a demo
  any more; it may escalate.

  **Phase 6.5 investigation (2026-10-25), 5 isolated runs -- this replaces the single-run note above as
  the evidence-backed conclusion.** Ran `attack_live.py --stage enum` five times, each in isolation (no
  other traffic in flight), logging Detection's raw verdict line and `served_by` for every evaluation
  cycle from `.run/logs/detection.log.err` directly (not just the `reasoning_events` row, since a
  non-escalating run writes no such row at all -- `detection/agents.py`'s `hand_off()`, where
  `record_reasoning` is called, only runs when `verdict.escalate` is `True`).

  | Run | Final verdict | Pattern | Confidence | `served_by` | Requests (final window) | Span | Req/sec | Incident |
  |---|---|---|---|---|---|---|---|---|
  | 1 | **escalate=True** | `traffic_spike` | 0.95 | `gemini-3.5-flash-lite` | 85 | 8.5s | 9.96 | `inc-d786f2fbb989` (Medium) |
  | 2 | escalate=False | `normal` | 0.95 | `gemini-3.5-flash-lite` | 91 | 9.39s | ~9.7 | none |
  | 3 | **escalate=True** | `traffic_spike` | 0.95 | `gemini-3.5-flash-lite` | 91 | 9.6s | ~9.5 | `inc-4a630319028a` (Medium) |
  | 4 | **escalate=True** | `traffic_spike` | 0.95 | `gemini-3.5-flash-lite` | 57 | 6.5s | ~8.8 | `inc-d0f05f5ebfb7` (**Low** -- first Low severity seen in this project) |
  | 5 | escalate=False | `normal` | 0.90 | `gemini-3.5-flash-lite` | 125 | 42s | 2.73 | none |

  **Result: 3 of 5 escalated (runs 1, 3, 4); 2 of 5 did not (runs 2, 5).** Every single evaluation across
  all 5 runs -- roughly 15 noise-filter calls total, counting the earlier, smaller windows each run also
  evaluated before its decisive one -- was served by the exact same model, `gemini-3.5-flash-lite`,
  ruling out "a different/weaker model answered" as an explanation. **Runs 1, 2 and 3 are the cleanest
  comparison: 85-91 requests, 6.5-9.6 second spans, ~9-10 req/sec, identical shape (nearly all 404s on
  `/profile`, zero login attempts), same model -- yet the verdict alternates escalate / do-not-escalate /
  escalate on materially the same input.** That is the definition of judgment variance, not a
  data-dependent boundary: there is no volume or rate threshold consistent with escalating at 85 but not
  at 91, then escalating again at 91. Run 5 (125 requests, but spread over 42s at a much lower 2.73
  req/sec) is the one run with a genuinely different shape and a lower confidence (0.90) -- a plausible
  borderline case on its own, but it does not change the conclusion from runs 1-3, and if anything argues
  against a simple volume threshold (more total requests, same non-escalating read).

  **Conclusion, replacing the Phase 6.3 one-line note: this is confirmed genuine LLM judgment
  non-determinism on this traffic shape, not a missing data field and not a timing/volume-dependent
  boundary.** The Phase 7 fix should target the judgment step itself -- a lower-temperature or
  more-constrained prompt for this one classification, a deterministic pre-filter ahead of the LLM call
  for the specific "many 404s, one endpoint, no logins" shape, or accepting the variance and compensating
  with a second-opinion/retry-on-disagreement pattern -- rather than assuming new window-summary fields
  alone will fix it (the fields already present were sufficient for a correct "probing" read in 3 of 5
  identical-shape runs). `--stage enum` should be described to a demo audience as "usually, but not always
  reliably, triggers an incident" -- neither "never escalates" nor "reliably escalates" is accurate.

- **`scripts/attack_live.py`'s `run_baseline()` doc/code mismatch (minor, tooling only, found in Phase
  6.3).** The docstring says "one honest mistake"; the code actually rolls a ~15% chance of the wrong-
  password branch on every one of up to 90 iterations (not once), so a baseline run can send several
  failed logins, not one. Observed in the Phase 6.3 matrix as repeated small failed-login counts from
  `LEGIT_IPS` showing up in a concurrently-running real incident's evidence when baseline was run
  alongside other attacks. Not a product bug (Detection correctly didn't escalate baseline run alone);
  just means baseline should be run without other attack traffic in flight if its non-escalation is being
  verified in isolation, and the docstring should say "a handful of" rather than "one."

- **Real structural blind spot: a genuinely low-and-slow credential attack is invisible to Detection
  (found in Phase 6.3.5, the real-tool attack sweep).** 12 failed logins against one account from one IP,
  spread over 145 seconds (~1 request every 12s, ≈0.08 req/sec, via a real curl script substituting for
  `slowhttptest`), produced **zero** incidents, zero trace rows, nothing -- confirmed in a clean, isolated
  re-run after a first contaminated attempt (merged with concurrent `nuclei` traffic) wrongly looked like
  it escalated. Unlike the enumeration finding above, this is NOT LLM judgment variance: Detection's
  `window_seconds=30.0` rolling window (`detection/windowing.py`) never held more than 2-3 of the slow
  attack's requests at any single evaluation cycle, so the noise-filter LLM never even saw a count worth
  reasoning about -- each cycle's aggregate genuinely looked like isolated, unremarkable traffic. This is a
  structural gap in the windowing/aggregation layer itself, not a prompt or model problem, and is the
  single strongest, most reproducible finding to come out of either the Phase 6.3 matrix or the Phase 6.3.5
  tool sweep. Needs either a much longer rolling window, a persistent per-account/per-IP failed-login
  counter that survives across windows (not reset each cycle), or an explicit rate-independent trigger
  (e.g. "N failed logins against the same account within H hours" regardless of pacing) before Detection
  can see this attack shape. Reproduce with the two-request-per-12s pattern in
  `docs/VALIDATION_MATRIX.md`'s Phase 6.3.5 section, tool #10 (not yet promoted to a named
  `attack_live.py` pattern). Do not fix inside Phase 6.3.5 or 6.4's prerequisite step (confirmed out of
  scope -- no change to Detection's window-summary logic or `window_seconds` outside of Phase 7).
