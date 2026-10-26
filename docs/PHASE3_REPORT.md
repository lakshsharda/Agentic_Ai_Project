# Phase 3 — completion report

Verified 2026-10-04, Python 3.11.9, Windows 11. LLM routing across Gemini
(multi-model) + OpenRouter (nvidia/nemotron free) — real cross-provider
fallback now active.

**All seven exit criteria MET.** Forensics runs as a fifth independent system;
evidence preservation is a real second gate on Containment; Root Cause Analysis
produces genuine, incident-specific narratives via the continuation-aware LLM
path; and the feedback loop is a real A2A re-classification from Forensics back
to Threat Assessment that, when it crosses the approval threshold, re-opens
approval and re-pages On-Call. Recovery genuinely reverts the simulated
firewall once it is signalled safe.

---

## 1. What was built, task by task

### Task 1 — Forensics & Recovery system (CrewAI, :9105) — **done**

Own process, own A2A card, registered in `SYSTEM_URLS`. Triggered by Threat
Assessment's dispatch fan-out (Forensics is now a third parallel target
alongside Containment and On-Call — documented choice: TA dispatches
`collect_evidence` to Forensics at the same moment it requests action and pages).

- **Evidence Collection** (`forensics/evidence.py`) — snapshots the simulated
  firewall's current rule set plus the signals that produced the incident, to a
  durable per-incident JSON file (`forensics/evidence_store/<id>.json`), decides
  `preserve_worthy`, and writes the `evidence_preserved` signal Containment's
  gate waits on. Not an LLM step.
- **Root Cause Analysis** (`forensics/rca.py`) — the project's first long-form,
  open-ended reasoner. Produces a genuine narrative via the continuation-aware
  path (Task 3). Separately decides, grounded in evidence, whether to re-classify.
- **Recovery Planning** (`forensics/recovery.py`) — a CrewAI agent that writes a
  short plan and a `LIFT: YES/NO` signal. Advisory: it does not itself revert
  containment; Containment does, gated.

### Task 2 — Feedback / re-classification loop — **done** (the central piece)

- Forensics sends a **real A2A task** (`reclassify`) back upstream to Threat
  Assessment with the existing `incident_id`, the new evidence/reasoning, and a
  suggested severity.
- Threat Assessment has a dedicated handler (`_handle_reclassification`),
  distinct from a fresh candidate: it looks the incident up (never creates a
  duplicate), re-runs the Severity Classification agent informed by Forensics'
  findings, and may confirm the existing severity (a request need not cause a
  change — logged either way).
- If the revision crosses the approval threshold (below High → High/Critical),
  it **re-opens** approval (invalidates the prior approval flag) and **re-pages
  On-Call**, marked in the audit trail as a re-open distinct from the original.
- Revised fields are written via the narrow store exception
  (`IncidentStore.reclassify`, Decision 1): a `status_history` entry tagged
  `reclassified`, with `status` left exactly where it is (never moved backward).

### Task 3 — Partial-generation-cutoff handling — **done** (continuation kept)

`shared/llm.generate_with_continuation` iterates the role's model chain itself:
a natural stop finishes; a mid-generation cutoff (`finish_reason == length`)
keeps the partial text and asks the **next** model to continue it; an upfront
rejection moves to the next model with the original prompt. Scoped to the RCA
agent only — not wired into Detection/Threat Assessment/Containment/On-Call.

Continuation (not retry-only) was kept: it works cleanly and, in testing,
stitched a single narrative across up to four providers (three Gemini models +
OpenRouter's Nemotron). A faint seam can appear at very small per-round token
budgets; at the production budget (900 tokens/round) the analysis almost always
finishes in one round, so the seam is a non-issue in practice.

---

## 2. Files created or modified

**New — Forensics:** `forensics/__init__.py`, `forensics/evidence.py`,
`forensics/rca.py`, `forensics/recovery.py`, `forensics/server.py`

**New — scripts:** `scripts/test_phase3_gates.py` (evidence gate + reclassify
store exception, no LLM), `scripts/test_rca_continuation.py` (Task 3),
`scripts/test_phase3_e2e.py` (full chain + feedback loop),
`scripts/test_recovery_revert.py` (gated firewall revert)

**New — docs:** `docs/PHASE3_REPORT.md`

**Modified:**
- `shared/store/incidents.py` — `reclassify()` (narrow backward-move exception)
- `shared/guardrail.py` — Forensics actions + matrix rows; `evidence_preserved`
  signal (`record_evidence_preserved`/`get_evidence_signal`); `evaluate_action_gate`
  gains `require_evidence` and `pending_evidence`
- `shared/llm.py` — `generate_with_continuation` (+ `finish_reason_is_truncation`)
- `shared/a2a_support.py` — `FORENSICS_URL` in `SYSTEM_URLS`
- `containment/server.py` — evidence gate wired in; unified gate waiter; handlers
  for the Forensics evidence-preserved nudge and the recovery lift signal
- `containment/firewall.py` — `unblock_ips()` (the recovery revert)
- `threat_assessment/server.py` — `_handle_reclassification`, re-open + re-page
- `threat_assessment/dispatch.py` — Forensics added to the parallel fan-out
- `scripts/attack_simulate.py` — `--successes` (models a partial compromise)
- `scripts/start_all.ps1` — starts Forensics; `.env` — OpenRouter in both chains
- `.env.example` — Forensics port, OpenRouter chain notes

---

## 3. Exit criteria check

**1. Forensics independent process with a real card, reachable — MET.**
`:9105/.well-known/agent-card.json` → "Forensics & Recovery"; started as its own
process from `.venv-crew`.

**2. Evidence collection genuinely gates Containment — MET.**
`test_phase3_gates.py`: a High incident with no `evidence_preserved` →
`pending_evidence`, firewall unchanged; after the signal, the gate stops
pending on evidence. In the live run, Forensics writes the signal
(`EVIDENCE preserved for <id> by=forensics preserve_worthy=True`) and snapshots
to `forensics/evidence_store/<id>.json`.

**3. RCA produces real, non-templated narratives for two incidents that differ — MET.**
`test_phase3_e2e.py`: incident A (400 words) and incident B (347 words), content
asserted different. Sample (A): *"The attacker operating from source IP
198.51.100.77 launched an automated, high-velocity credential guessing attack …
over an extremely compressed timeframe of just 0.66 seconds … targeting 6
distinct, high-value system and default usernames (root ×5, admin ×3, …)."*

**4. Real re-classification A2A, severity revised, reclassified entry — MET.**
Forensics log: `RECLASSIFY -> Threat Assessment for inc-1dcc8bb70141: suggest
Critical (evidence shows 2 successful login(s) …)`. Result: `Medium -> Critical`,
`status_history` gains a `reclassified` entry while `status` stays `CONTAINED`.
Real Forensics-process → Threat-Assessment-process A2A; TA handles it on a
separate code path from a fresh candidate.

**5. Threshold-crossing re-classification re-pages / re-opens approval — MET.**
Part B: Medium (contained, no approval needed) → Critical re-classification →
`reopened` recorded, prior approval flag invalidated (`approved=False`), On-Call
re-paged (`Priya (SecLead)` on `sec-critical`) — distinct from any original
approval.

**6. Recovery produces a plan + lift signal, firewall genuinely reverted — MET.**
Live Part A produced a recovery plan + `safe_to_lift` signal (False for a
Critical compromise — correctly cautious). `test_recovery_revert.py` proves the
revert end to end: `safe_to_lift=False` keeps the blocks; `safe_to_lift=True`
(real Forensics→Containment A2A) removes exactly that incident's IPs from the
simulated firewall.

**7. Partial-generation-cutoff handling for RCA — MET (continuation kept).**
`test_rca_continuation.py`: with a tiny per-round budget forcing truncation, one
narrative was stitched across 3 providers in continuation mode. Not wired into
any other agent.

---

## 4. Deviations, and why

1. **PART B's initial-Medium incident is seeded by the test.** The reasoning
   agents correctly rate every *escalated* credential attack as High/Critical,
   so a naturally-Medium escalated incident does not occur in practice (empirically
   confirmed across several attack sizes). To demonstrate the threshold-cross
   honestly, the test seeds a Medium contained incident and then drives the
   **real** Forensics→Threat-Assessment re-classification A2A over the running
   processes — the leg the brief calls non-negotiable. Only the initial Medium
   state is seeded; the re-classification itself is not mocked. Part A exercises
   the same loop fully naturally (its compromise simply rated Critical up front,
   so no raise was warranted — correctly logged as "no change").

2. **RCA's re-classification *trigger* is evidence-grounded, not model-emitted.**
   The narrative is open-ended LLM reasoning, but whether to re-classify is
   decided by concrete rules (a successful login during the attack → likely
   compromise → Critical; campaign-scale spread under a Low/Medium rating →
   High). More deterministic and defensible than relying on the model to emit a
   signal; the narrative still carries the real reasoning. Documented in
   `forensics/rca.py`.

3. **Forensics is a third parallel dispatch target** (TA → Forensics
   `collect_evidence`), rather than Containment notifying Forensics. Either was
   allowed by the brief; parallel dispatch keeps evidence collection starting at
   the same instant as containment/paging.

4. **OpenRouter added to both routing chains.** Closes the Phase 2 open item —
   fallback is now genuinely cross-provider (Gemini → OpenRouter Nemotron),
   which matters most here for RCA's longer reasoning. `CEREBRAS_API_KEY` is
   still unset (OpenRouter alone is sufficient).

5. **Thread-limit env vars when launching CrewAI processes** (`OPENBLAS_NUM_THREADS=1`)
   — an operational memory workaround on this machine, unchanged from Phase 2.

Nothing from Phase 4 was built (no Customer Communications, no comms sign-off).

---

## 5. What is needed from the user before Phase 4

Itemized; nothing here blocks what was built this phase.

1. **Slack webhook — `ONCALL_SLACK_WEBHOOK_URL`.** Now **set**; On-Call pages
   (and re-pages) for real. No action needed unless you want a different channel.

2. **OpenRouter — `OPENROUTER_API_KEY`.** Now **set** and wired into both
   chains; cross-provider fallback is live. The free Nemotron model is
   shared-rate-limited, so under heavy load it can itself 429 — fine as a
   fallback. Optional: add `CEREBRAS_API_KEY` (still unset) for a third bucket.

3. **Gemini quota** — still the main pressure point; the multi-model + OpenRouter
   fallback now absorbs daily-cap exhaustion, which is why Phase 3 ran clean.
   No action required.

4. **(Optional) Ollama** — still not installed; the mechanical chain's local-first
   entry remains pruned and falls back to Gemini. Not blocking.

**Carried over:** cloud deploy of the target app is still deferred, so the
firewall (and thus evidence snapshots of it) remain simulated. Phase 4
(Customer Communications) does not depend on it.
