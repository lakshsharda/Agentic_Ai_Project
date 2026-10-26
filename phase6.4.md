# Phase 6.3.5 — Real-World Tool Attack Sweep

**Run this before Phase 6.4.** You already ran `ffuf` live against the target app for credential stuffing and password spraying, with real findings (`wonderland`, `builder123`, `admin`/`admin`). This phase extends that with 9 more real, well-established open-source security tools, each run against your own local target app (never anything outside it), chosen so the 10 tools together stress genuinely different signals rather than repeating the same shape. This produces stronger validation evidence than another synthetic script, and gives Phase 6.4's master documentation real external-tool data to cite alongside the project's own simulator.

All of this targets `localhost`/the local target app only, which you own and are authorized to test — the same scope `ffuf` already ran in.

---

## The 10 Tools and What Each One Tests

| # | Tool | Technique | What it stresses in Detection |
|---|------|-----------|-------------------------------|
| 1 | `ffuf` | credential stuffing / password spray | already run — baseline, no action needed unless repeating for comparison |
| 2 | `hydra` (THC-Hydra) | `http-post-form` brute force against `/login` | a second, independently-built brute-force client — confirms Detection's signal isn't an artifact of your own script's request shape |
| 3 | `medusa` | parallel multi-threaded login brute force against `/login` | high concurrency / thread count — a different burst shape than ffuf or hydra |
| 4 | `patator` | `http_fuzz` module brute force against `/login` | another independent brute-force implementation, different default headers/timing |
| 5 | `nikto` | general web server / misconfiguration scan | broad, noisy recon traffic across many paths with no login attempts at all — should land near the enumeration-only boundary case, useful alongside that investigation |
| 6 | `gobuster` (or `dirb`) | directory/endpoint brute-force discovery | hidden-path enumeration (`/admin`, `/backup`, `/.git`, etc.) against a 3-route app — expect mostly 404s, a cleaner enumeration-only case than the existing `/profile?username=` scraper since it never touches a real parameter |
| 7 | `wfuzz` | parameter fuzzing against `/profile?username=` | fuzzer-driven IDOR-style enumeration, a second tool hitting the same known blind spot for cross-validation |
| 8 | `sqlmap` | automated SQL injection probing at `/login` | real tool-generated SQLi payloads, not the project's own synthetic fuzzing — tests whether Detection's failed-login signal holds up against a very different request pattern (many requests, unusual payload content, same endpoint) |
| 9 | `nuclei` | template-based scan including default-credential and exposed-panel templates | realistic reconnaissance scanner traffic, broad template sweep |
| 10 | `slowhttptest` (or a Slowloris-style script) | low-and-slow connection/request pacing | the opposite extreme from a burst — tests whether a trickled-out attack still gets caught, or whether Detection's window-based approach has a blind spot at low request rates over a long duration |

If any tool isn't installable in this environment (no network access to its package source, Windows incompatibility, etc.), substitute the closest equivalent and say so — don't skip the technique it represents.

---

## Decisions Settled Before Running

1. **Every run is against the local target app only**, using the same demo credentials/account set already established (`alice`, `bob`, `admin`, etc.) — no tool points anywhere else.
2. **Capture the same evidence discipline as the Phase 6.3 matrix**: for each tool run, record the resulting `incident_id` (if one opened), Detection's verdict and severity, relevant trace/reasoning excerpts, and — critically — whether it escalated or not and why, in Detection's own words where available.
3. **No code or agent-logic changes as a result of this phase.** If a tool's traffic reveals another gap (like the existing enumeration-only one), document it in `docs/BACKLOG.md` with the same evidence standard already established (raw output, not a guess) — don't patch Detection to handle it.
4. **Record exact tool invocations used**, not just results — the specific command line for each of the 10 tools, so the run is reproducible and so the master doc in Phase 6.4 can cite real commands.
5. **This is additive to, not a replacement for, the existing `ffuf` results and the Phase 6.3 matrix.** All ten (including `ffuf`'s existing results) belong together in one place.

---

## Task 1 — Run All 10 Tools

- Execute each tool (or its substitute) against the target app, one at a time, capturing evidence per Decision 2 and the exact command per Decision 4.
- Where a tool found a real credential or vulnerability (as `ffuf` did), record it explicitly — that's strong demo material.

## Task 2 — Record Results

- Add all 10 (the 9 new runs plus a cross-reference to the existing `ffuf` results) to `docs/VALIDATION_MATRIX.md` as a clearly labeled "Real-World Tool Sweep" section, separate from the synthetic-pattern cases already there, with the same table shape: tool, technique, command used, result, severity, and whether/why it escalated.
- Any new findings (bugs, blind spots, surprising non-escalations) go in `docs/BACKLOG.md` with evidence, same standard as before.

## Task 3 — Summarize

- A short summary: how many of the 10 escalated vs. didn't, which severities were reached, and whether the enumeration-style tools (`nikto`, `gobuster`, `wfuzz`) landed on the same non-escalation boundary as the existing `/profile` scraper or behaved differently — this is directly relevant to the enumeration investigation already queued for Phase 6.4's prerequisite step, so flag anything here that bears on it.

---

## Exit Criteria

- [ ] All 10 tools (or documented substitutes) were run live against the local target app, each with recorded evidence and exact command used
- [ ] Results are in `docs/VALIDATION_MATRIX.md`'s new "Real-World Tool Sweep" section, alongside the existing `ffuf` data
- [ ] Any new findings are in `docs/BACKLOG.md` with evidence, not assumption
- [ ] A short summary states escalation rate, severities reached, and anything relevant to the enumeration-only investigation
- [ ] No agent logic, Detection inputs, or gate behavior were changed

---

## Explicitly Out of Scope

- Running any tool against anything other than the local target app
- Fixing any gap or bug found (report it, don't patch it)
- The enumeration re-investigation itself (that's Phase 6.4's prerequisite step — this phase only flags anything relevant to it)

---

## Instructions for Claude Code

Run all 10 tools (installing whichever aren't already available, substituting where necessary) against the local target app only, in the order listed, capturing evidence as described.

**At the end of the session, report back in plain text, in this exact structure:**

1. **Results table**: all 10 tools, technique, command used, outcome, severity, escalated y/n
2. **Files created or modified**, full list of paths
3. **Exit criteria check**: MET / PARTIAL / NOT MET for each of the 5 criteria
4. **Any new findings**, with evidence, added to the backlog
5. **Anything relevant to the enumeration-only investigation**, flagged separately, to carry into Phase 6.4