# Phase 3 — Forensics & Recovery + Evidence-Preservation Handshake + Feedback/Re-classification Loop

## Context Carried Over From Phase 2

Phase 2 is complete, all exit criteria MET. What exists and is proven working:

- Attack simulation script, Detection (ADK, :9101), Threat Assessment (ADK, :9102) — unchanged from Phase 1, dispatch is now real (not a stub)
- Containment/Ops (CrewAI, :9103) — Situation Review + Immediate Action crew, gated by the guardrail, executes against a **locally-simulated firewall** (cloud deploy still deferred), reports status back
- On-Call/Escalation (CrewAI, :9104) — real Slack paging (once `ONCALL_SLACK_WEBHOOK_URL` is set) or honest file-sink fallback, escalation timer with two provenance-tagged approval paths: `human` and `timeout_escalation`
- `shared/llm.py` — multi-provider routing via LiteLLM, per-role fallback chains (`LLM_CHAIN_REASONING`, `LLM_CHAIN_MECHANICAL`), pruned by available credentials, logs `served_by=<model>` per call. **A minimal mid-generation-cutoff hook already exists, deliberately left unfinished — this phase is where it gets completed, for Forensics' long-form reasoning agent specifically.**
- `shared/guardrail.py` — `AUTHORITY_MATRIX`, `check_authority()`, `requires_human_approval()`, `evaluate_action_gate()` — deny-by-default, real code-level gate
- Incident store — status vocabulary enforced via CHECK constraint, `advance_status()` refuses backward moves, `status_history` audit trail, `escalated` and `incident_type` columns
- Full chain proven live for both approval paths (human ack, timeout escalation), traced end-to-end through `CONTAINED`

**Open items from Phase 2, not blocking this phase but still outstanding:** `CEREBRAS_API_KEY`/`OPENROUTER_API_KEY` for true cross-provider fallback (currently Gemini-only across model buckets); Ollama install (optional). Proceed without these — note again at the end of this phase if they're still missing, since Forensics' longer reasoning chain is exactly where a real cross-provider fallback starts to matter most.

---

## Decisions Settled Before This Phase Starts

1. **`advance_status()` currently refuses backward moves — this phase requires a deliberate, narrow exception.** A re-classification is not "the incident went backward," it's "the incident's assessment was revised while containment work continues in parallel." Do not loosen the backward-move guard generally. Instead, add a specific, explicit path: an incident at `CONTAINED` (or `DISPATCHED`) can receive an updated `severity`/`incident_type`/`escalated` value and a new `status_history` entry tagged `reclassified`, **without reverting `status` itself backward.** Status keeps moving forward through the pipeline; severity/type/escalated are mutable fields that can be revised with a logged reason at any point before `RESOLVED`. This is the cleanest way to get real feedback-loop behavior without contradicting Phase 2's hard-won backward-move guard.
2. **The evidence-preservation handshake is a direct Forensics ↔ Containment exchange**, not mediated by a Legal system (Legal was removed from this project's scope, per the finalized 6-system architecture). Containment's Immediate Action Agent gains a second real gate, alongside the existing approval gate: it must also hold for an `evidence_preserved` signal from Forensics before executing anything that would alter the simulated firewall/system state, when Forensics reports the incident involves a "preserve-worthy" system (see Task 1).
3. **The partial-generation-cutoff LLM handling, deferred from Phase 2, is built this phase** — scoped specifically to the Root Cause Analysis Agent (Task 2), which is this project's first genuinely long-form, open-ended reasoning agent. Do not retrofit it onto Detection/Threat Assessment/Containment's short, bounded-decision agents — they don't need it and it adds complexity without benefit there.
4. **Recovery is advisory in this phase, not literally reversing the Containment action.** Recovery Planning Agent produces a plan and a go/no-go signal; actually un-blocking the simulated firewall IPs is a one-line action gated behind the same guardrail pattern, not new mechanism — reuse `evaluate_action_gate()`.

---

## Task 1 — Forensics & Recovery System (CrewAI)

Build as its own process, own A2A agent card, registered in `SYSTEM_URLS`. This is your fourth independently deployed system.

- **Evidence Collection Agent** — triggered as soon as Threat Assessment dispatches to Containment (listen for the same dispatch event Containment receives, or have Containment itself notify Forensics on receipt — either is acceptable, document which). Takes a snapshot of the current simulated system state relevant to the incident (for this phase: a snapshot of the simulated firewall's current rule set plus the raw signals/log lines that led to the incident, already available from Detection's data). Writes this snapshot to a durable location (a table or a JSON file per `incident_id` is sufficient — this is a student project, not a real forensics tool). Once the snapshot is captured, sends the `evidence_preserved` signal for that `incident_id`, which Containment's second gate (per Decision 2 above) is waiting on.
- **Root Cause Analysis Agent** — this is the agent where you build real open-ended reasoning, and where the partial-generation-cutoff LLM handling applies. Takes the evidence snapshot plus the full incident history (`status_history`, Threat Assessment's rationale, Detection's original signal data) and produces a genuine narrative root-cause explanation — not a label, a few sentences of real reasoning about what likely happened and why. **If, during this reasoning, the agent's own analysis surfaces something that contradicts or exceeds the originally assessed severity** (e.g., evidence suggests a wider blast radius than Threat Assessment initially saw), it must emit a re-classification signal.
- **Recovery Planning Agent** — once root cause analysis is done and no re-classification was triggered (or once a re-classification has itself been resolved — see Task 2), produces a short recovery plan and a boolean "safe to lift containment" signal, sent back to Containment.

---

## Task 2 — The Feedback/Re-classification Loop

This is the piece that makes the pipeline genuinely non-linear, not just a longer sequential chain.

- When Root Cause Analysis flags a re-classification, Forensics sends a real A2A task **back upstream to Threat Assessment**, carrying the existing `incident_id`, the new evidence/reasoning, and a suggested severity/type.
- Threat Assessment needs a new handler for this case — **it is not the same code path as a brand-new candidate incident.** It must:
  - Recognize the incoming `incident_id` already exists in the store (look it up, don't create a duplicate row)
  - Re-run its Severity Classification Agent reasoning, now informed by Forensics' new evidence, and decide whether to actually revise the severity (the agent might conclude the original assessment was already correct — a re-classification *request* doesn't have to result in an *actual* change; log the outcome either way)
  - If severity is revised upward and crosses the High/Critical threshold where it previously didn't, this must **re-trigger `requires_human_approval()`** downstream — meaning if Containment already executed an action under the old, lower severity, this is a real scenario to handle: On-Call should be re-paged for the escalation, and this should be clearly visible in the audit trail as "re-opened" rather than silently merged into the original decision
  - Write the revised fields via the narrow exception described in Decision 1 (status_history entry tagged `reclassified`, status itself does not move backward)

**This is the single most important thing to get right in this phase.** A fake version of this (e.g., Forensics just calls a function that updates the DB directly) does not count — it must be a real A2A task sent between two independently running processes, and Threat Assessment must demonstrably treat it differently from a fresh incident.

---

## Task 3 — Partial-Generation-Cutoff LLM Handling (completing the Phase 2 hook)

- Complete `shared/llm.py`'s existing minimal hook: if a provider returns a partial response before failing mid-generation (not an upfront rejection — that case is already handled by the Phase 2 fallback chain), capture the partial text and pass it to the next provider in the chain with an explicit continuation instruction (e.g., "the following reasoning was cut off, continue it naturally from where it stopped: [partial text]").
- Apply this **only** to the Root Cause Analysis Agent's LLM calls. Do not wire it into Detection, Threat Assessment, Containment, or On-Call's agents.
- If this proves to add meaningful complexity or instability (different model families producing an awkward seam, as flagged as a risk back when this was first discussed), it is acceptable to implement a simpler fallback: on mid-generation cutoff, discard the partial output and retry the full original prompt on the next provider, same as the upfront-rejection case — but only after genuinely attempting the continuation approach first, and note in the report which approach was kept and why.

---

## Exit Criteria (must all be true before moving to Phase 4)

- [ ] Forensics runs as its own independent process with a real agent card, registered and reachable
- [ ] Evidence Collection genuinely gates Containment — demonstrate Containment's action-execution held in a pending/waiting state until the `evidence_preserved` signal arrives, the same way Phase 2 proved the human-approval gate (a test showing state unchanged before, changed after)
- [ ] Root Cause Analysis produces a real, non-templated narrative explanation for at least two different incidents with different attack patterns (brute-force vs. burst), showing the content genuinely differs based on the evidence, not boilerplate
- [ ] A real re-classification scenario is demonstrated end-to-end: an incident that was under-assessed initially gets a real A2A message sent from Forensics back to Threat Assessment, Threat Assessment revises the severity, and this is visible in `status_history` as a `reclassified` entry — traceable to a specific incident_id, not simulated/mocked
- [ ] The re-classification crossing the approval threshold correctly re-triggers On-Call paging / re-opens the approval requirement, visible in the audit trail as distinct from the original approval
- [ ] Recovery Planning produces a plan and a lift-containment signal, and the simulated firewall rule is genuinely reverted once that signal clears the guardrail gate
- [ ] The partial-generation-cutoff handling is implemented for the Root Cause Analysis Agent specifically (or explicitly reported as simplified to retry-only, with reasoning, if continuation proved unstable)

---

## Explicitly Out of Scope for This Phase

- Customer Communications system (Phase 4)
- Legal/Compliance — out of scope for the entire project (removed from the architecture)
- Multi-incident concurrency / two incidents competing for the same on-call engineer (stretch, Phase 6+ if time allows)
- Real pub/sub event bus (the store-flag-based signal approach from Phase 2 continues to be sufficient here)
- Cloud deployment of anything (still deferred)
- The observability dashboard (Phase 5)

If something above feels necessary to finish a Phase 3 task, stop and flag it rather than building it.

---

## Instructions for Claude Code

Build this phase's deliverables directly in the project repository, following the decisions above exactly — particularly Decision 1 (the narrow backward-move exception) and Decision 2 (direct Forensics↔Containment handshake, no Legal system). If something turns out to be unworkable in practice, flag it clearly rather than silently substituting a different design.

**At the end of the session, report back in plain text, in this exact structure** (same shape as the Phase 0/1/2 reports):

1. **What was built, task by task** — against the 3 tasks above
2. **Files created or modified** — full list of paths
3. **Exit criteria check** — MET / PARTIAL / NOT MET for each of the 7 criteria above, with evidence (log snippet, test output, query result, and ideally the actual root-cause narrative text produced) wherever possible
4. **Deviations from these instructions**, and the reason for each
5. **What is needed from the user before Phase 4 can begin** — itemized, same format as before (which provider/account, what it's for, currently missing or not)

Do not begin any Phase 4 task (Customer Communications, mandatory comms sign-off, real publish integration) under this phase.