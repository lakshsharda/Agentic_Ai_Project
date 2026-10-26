# Phase 6.5 — Master System Documentation

**This is a documentation phase, not a build phase.** Everything described here already exists and has been tested (Phases 0–6.3, the 20-case validation matrix, and today's live ffuf runs). The goal is a single, complete, well-organized document that someone who has never seen this project — including a professor evaluating it — can read start to finish and come away understanding what was built, how it's built, how it behaves, and what's been proven about it. Nothing in this phase changes code, agent logic, or behavior.

---

## Prerequisite — Close Out Open Data Before Writing the Doc

1. **Add today's three `ffuf` runs** (two credential-stuffing runs against `alice` and `bob`, one password-spray against 91 usernames with a single weak password) to `docs/VALIDATION_MATRIX.md` and/or `docs/BACKLOG.md` as a short, clearly dated addendum — tool used, technique, result, and the specific weak credentials found (`wonderland`, `builder123`, `admin`/`admin`). These are strong demo evidence (real external tool, not the project's own simulator) and must be in the record before the master doc cites them.
2. **Investigate the enumeration-only escalation reversal properly before writing it up as settled.** The current claim — "enumeration-only can escalate; LLM judgment variance, not a missing data field" — is asserted from what sounds like a single re-run. That's not enough to rule out a data/timing explanation, the same standard already applied to the Phase 2 Detection flake. Before this goes in the master doc:
   - Run the enumeration-only pattern 5 times in isolation, logging each run's full raw Detection output and `served_by` model.
   - If the verdict varies across identical-shape runs with the same model answering, that supports genuine LLM judgment variance — report it as a real, if undesirable, characteristic of an LLM-judged detector, not a bug.
   - If a specific run's window-summary input differs in some way (volume, timing, a field value) between an escalating and non-escalating run, that's not "judgment variance," that's a data-dependent boundary and should be described as such instead.
   - Either way, state plainly in `docs/BACKLOG.md` what was actually found, replacing the current short note with the evidence-backed version.

Do not proceed to building the master document until both of the above are done — the master doc should reflect the corrected, evidenced record, not the current summary as given.

---

## Decisions Settled Before Writing the Document

1. **One file, `docs/SYSTEM_OVERVIEW.md`**, is the deliverable — not scattered across the existing per-phase reports. It should stand alone: a reader should not need to also open `PHASE4_REPORT.md` or `VALIDATION_MATRIX.md` to follow it, though it can reference them for deeper detail.
2. **Two audiences, clearly separated within the one file.** Open with a short, plain-language section (no jargon, no code, no table of ports) that explains what the system does and why it's interesting, suitable for a professor or anyone non-technical to read first. Follow it with the full technical depth. Do not make the technical reader wade through restated basics, and do not make the non-technical reader wade through agent/tool tables to find the point.
3. **Every system, agent, and subagent gets cataloged**, not just named. For each of the six systems (Detection, Threat Assessment, Containment/Ops, On-Call/Escalation, Forensics & Recovery, Customer Communications): its framework (ADK or CrewAI), its port, and a table of its agents — name, role/responsibility, which LLM chain or model role it uses, and what tools or data it touches. This is the section that proves there's real multi-agent architecture here, not one prompt wearing six hats.
4. **The guardrail/authority architecture gets its own clearly explained section**, since it's the project's actual thesis: the authority matrix (deny-by-default), the four gate decision types with a real example of each from the validation data, the evidence-preservation gate, the mandatory human sign-off for Comms with no timeout bypass, and the two genuinely separate observability pathways (scrubbed `trace_events` vs. unscrubbed `reasoning_events`) and why that separation exists.
5. **Results are reported with real numbers, not vague claims** — pull from the validation matrix, the backlog, and the addendum added above: total incidents, the 10 distinct attack/test types, severities actually reached, all four gate types confirmed, the reclassification event, the two genuine findings (the customer-notice template crash, and the corrected/evidenced enumeration finding), and the PII-separation confirmation across the full trace row count. Numbers that aren't yet confirmed (e.g. Low severity never being cleanly isolated) are stated as such, not smoothed over.
6. **One end-to-end flow narrative plus one diagram.** Walk through a single real incident from first attack packet to published customer notice, naming every system and gate it passes through in order, cross-referenced to a real incident id from the data where possible. Pair it with a simple diagram (a plain Markdown/ASCII flow or a Mermaid diagram block — pick whichever renders cleanest in a plain Markdown viewer, state which and why) showing the six systems, the gates, and the direction of A2A calls, including the one feedback-loop (reclassify) edge.
7. **Tech stack is stated explicitly and completely**: Python version(s)/venvs in use and why there's more than one, ADK vs. CrewAI and why each was chosen where it was, LiteLLM and the cross-provider fallback chain, Postgres (native service, not Docker, and why), FastAPI for the dashboard/reasoning backends, Flask for the target app, plain HTML/CSS/vanilla JS for every frontend surface, and the A2A agent-card protocol tying the six systems together.
8. **Known limitations and Phase 7 backlog get an honest closing section**, pulled directly from the corrected `docs/BACKLOG.md` — don't omit or soften anything that's already been found and documented, including the enumeration finding as corrected above.

---

## Task 1 — Prerequisite Data Work

- Complete both items under "Prerequisite" above before starting Task 2.

## Task 2 — Write `docs/SYSTEM_OVERVIEW.md`

- Structure, in order: (1) plain-language overview, (2) architecture and tech stack, (3) full agent/subagent catalog per system, (4) guardrail/authority/gate architecture, (5) one real end-to-end incident walkthrough with diagram, (6) results to date with real numbers, (7) known limitations / Phase 7 backlog, (8) where to find deeper detail (links to `DEMO_SCRIPT.md`, `VALIDATION_MATRIX.md`, `BACKLOG.md`, the per-phase reports).
- Keep it in plain Markdown, no build step, readable directly on GitHub or any Markdown viewer.

## Task 3 — Sanity Pass

- Read the finished document once as if you'd never seen the project, and fix anything that assumes context it hasn't yet introduced, or that a professor would have to ask you to explain out loud.

---

## Exit Criteria

- [ ] Today's three `ffuf` runs are recorded in the matrix/backlog with real findings (the three discovered credentials and the techniques used)
- [ ] The enumeration-escalation claim is re-investigated with 5 isolated runs and raw evidence, and `docs/BACKLOG.md` reflects the evidenced conclusion, not the original one-line assertion
- [ ] `docs/SYSTEM_OVERVIEW.md` exists, is self-contained, and is clearly split into a plain-language section followed by full technical depth
- [ ] Every one of the six systems' agents/subagents is cataloged with framework, role, model chain, and tools
- [ ] The guardrail/gate architecture is explained with one real example of each of the four gate decision types
- [ ] Real result numbers are present throughout (incident counts, attack types, severities, PII-scrub confirmation), with anything not yet confirmed stated honestly as such
- [ ] One full incident walkthrough with a diagram is included
- [ ] Tech stack and the reasoning behind each major choice (ADK vs CrewAI, native Postgres, LiteLLM fallback) is stated explicitly

---

## Explicitly Out of Scope

- Any change to code, agent logic, gate behavior, or Detection's inputs
- Fixing the customer-notice template crash bug (stays in the backlog for Phase 7)
- Any new attack patterns or live runs beyond the 5 isolated enumeration re-runs needed for the investigation above

---

## Instructions for Claude Code

Complete the prerequisite data work first, then write `docs/SYSTEM_OVERVIEW.md` per the decisions above.

**At the end of the session, report back in plain text, in this exact structure:**

1. **What the enumeration re-investigation found**, with the raw evidence summarized (verdict-per-run and `served_by`-per-run at minimum)
2. **Files created or modified**, full list of paths
3. **Exit criteria check**: MET / PARTIAL / NOT MET for each of the 8 criteria
4. **The full contents of `docs/SYSTEM_OVERVIEW.md`**, pasted in full so it can be reviewed without opening the repo
5. **Anything still needed from the user**, itemized