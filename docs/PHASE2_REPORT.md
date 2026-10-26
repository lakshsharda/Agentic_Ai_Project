# Phase 2 — completion report

Verified 2026-10-04, Python 3.11.9, Windows 11, Gemini free tier (multi-model
routing) + CrewAI 1.15.23 + LiteLLM 1.103.2.

**All six exit criteria MET.** The full crisis-response chain runs live: a
simulated attack becomes a classified incident, Threat Assessment fans out in
parallel to Containment and On-Call, On-Call pages a responder, and Containment
executes a guardrail-gated mitigation only after approval arrives — by human
acknowledgment or by escalation timeout — all traceable in the store for one
`incident_id`. The LLM routing layer demonstrably survived provider failure
both in a targeted test and live in the real pipeline.

---

## 1. What was built, task by task

### Task 1 — Multi-provider LLM routing layer — **done**

`shared/llm.py` gained a routing layer on top of the Phase 1 config/retry
helpers. Every agent now asks for a model via `adk_model(role, ...)` (ADK) or
`crew_llm(role, ...)` (CrewAI) instead of naming a provider.

- **LiteLLM is the abstraction.** Both ADK's `LiteLlm` wrapper and CrewAI's
  `LLM` forward a `fallbacks=[...]` kwarg to litellm, which natively retries
  the *original prompt* on the next model on an upfront 429/quota/auth
  rejection — exactly the Phase 1 failure mode. No custom retry logic for that
  case (the Phase 1 `run_with_rate_limit_retry` remains as a backstop).
- **Per-role chains, not one global chain.** `LLM_CHAIN_REASONING` (severity,
  correlation, containment) and `LLM_CHAIN_MECHANICAL` (noise filter, page
  drafting), both `.env`-configurable. Providers with no credentials — and
  Ollama with no local server — are pruned from a chain automatically, so
  listing more than you have keys for is safe.
- **Provider-served logging.** A litellm `CustomLogger` logs `agent=<name>
  served_by=<model>` for every call, across both frameworks, so fallback is
  visible in the audit trail.
- **Mid-generation cutoff:** a minimal `finish_reason_is_truncation` hook only.
  As the brief says, no Phase 2 agent does long-form reasoning, so continuation
  is not implemented — deferred to Phase 3 (Forensics RCA), noted in code.

**Exit check (`scripts/test_llm_routing.py`):** force the primary to an invalid
model, confirm the call still succeeds via fallback with the serving provider
logged. ADK path and CrewAI path both PASS. Live confirmation too — see §3.

### Task 2 — Guardrail middleware v1 — **done**

`shared/guardrail.py`, imported by every system:

- `check_authority(from, to, action_type)` — a static `AUTHORITY_MATRIX`
  (Detection→TA candidate; TA→Containment request; TA→On-Call page;
  On-Call→Containment timeout-escalation only; Containment→TA status only;
  Containment→anything-else denied). Deny by default.
- `requires_human_approval(severity)` — True for High/Critical; unknown/missing
  severity fails safe to True.
- `evaluate_action_gate(...)` — the single call Containment makes before a real
  action: authority first, then approval. Returns allowed / pending / blocked.
- Approval signal: a provenance-tagged flag on the incident row
  (`record_approval` / `get_approval`), written by On-Call, read by Containment.

The gate is a real code branch in the tool-execution path — the firewall call
is physically behind `if gate.allowed`, not a prompt instruction.

### Task 3 — Containment / Ops (CrewAI, :9103) — **done**

- **Situation Review + Immediate Action** agents in a sequential CrewAI crew
  decide whether to block and emit a `DECISION: BLOCK|NO_ACTION` sentinel. The
  IPs blocked are derived from the incident evidence, never model text, so a
  block cannot target a hallucinated address.
- Execution is gated by `evaluate_action_gate`. On a required-but-absent
  approval the task goes **PENDING** (recorded in the store, action NOT run) and
  a bounded background waiter resumes it when the approval flag appears.
- **Status Reporting** advances the incident to `CONTAINED` and sends a real
  A2A status update back to Threat Assessment.
- The firewall is **locally simulated** (`containment/firewall.py`, a JSON state
  file) — honestly labeled, because cloud deploy is still deferred. See §4/§5.

### Task 4 — On-Call / Escalation (CrewAI, :9104) — **done**

- **Lookup** — static severity→contact schedule (`on_call/ops.py`).
- **Notification** — real Slack webhook when `ONCALL_SLACK_WEBHOOK_URL` is set;
  otherwise an honest local **file sink** (`on_call/notifications.log`,
  `sent=False`). Page text drafted by a CrewAI agent, template fallback.
- **Escalation Timer** — starts on page (default 20s, demo-friendly). Human ack
  via `POST /ack?incident_id=...` stops it and records approval
  `provenance=human`; timeout records approval `provenance=timeout_escalation`
  and nudges Containment. The signal is the store flag, keyed on `incident_id`,
  as the brief specifies (pub/sub deferred to Phase 3).

### Task 5 — Real dispatch — **done**

Threat Assessment's Phase 1 stub is replaced by `dispatch_real` — concurrent
`asyncio.gather` fan-out to Containment and On-Call, each leg authority-checked
before it leaves, incident advanced `ASSESSED → DISPATCHED` before the sends.
TA also now distinguishes an inbound Containment `status_update` from a new
candidate, so a status report does not restart assessment.

---

## 2. Files created or modified

**New:**
- `containment/__init__.py`, `containment/firewall.py`, `containment/agents.py`, `containment/server.py`
- `on_call/__init__.py`, `on_call/ops.py`, `on_call/agents.py`, `on_call/server.py`
- `shared/guardrail.py`
- `scripts/test_llm_routing.py`, `scripts/test_guardrail_block.py`, `scripts/test_phase2_e2e.py`
- `docs/PHASE2_REPORT.md`

**Modified:**
- `shared/llm.py` — routing layer (`llm_chain`, `adk_model`, `crew_llm`, provider logging, truncation hook)
- `shared/a2a_support.py` — Containment/On-Call URLs in `SYSTEM_URLS`
- `detection/agents.py` — noise filter via `adk_model(ROLE_MECHANICAL)`
- `threat_assessment/agents.py` — correlation/severity via `adk_model(ROLE_REASONING)`
- `threat_assessment/server.py` — real parallel dispatch, status-update handling, inbound authority check
- `threat_assessment/dispatch.py` — rewritten from stub to real parallel fan-out
- `.env`, `.env.example` — routing chains, extra provider keys, On-Call settings, ports
- `requirements/adk.txt`+lock, `requirements/crewai.txt`+lock — `google-adk[extensions]`, `litellm`, `python-dotenv`
- `scripts/start_all.ps1` — launches the 5-process Phase 2 stack

---

## 3. Exit criteria check

**1. LLM routing survives a simulated provider failure, serving provider logged — MET.**
`test_llm_routing.py` (ADK): invalid primary → `served_by=gemini-3.5-flash-lite`, call returns `ROUTED`.
Live, in the real pipeline (TA log), the reasoning chain fell through two
quota-capped Gemini models to a third, transparently:
```
[threat-assessment] [llm] agent=correlation served_by=gemini-3.5-flash-lite
[threat-assessment] [llm] agent=severity_classifier served_by=gemini-3.5-flash-lite
```
(primary `gemini-flash-latest` and `gemini-2.5-flash` were daily-capped; the
chain reached the third entry with no code change.)

**2. Guardrail blocks a real action when approval is required and absent — MET.**
`test_guardrail_block.py` (no LLM): High severity, no approval →
```
PASS  un-approved High action is held pending, not executed  -- outcome=PENDING
PASS  the real firewall action did NOT run  -- blocked set unchanged: []
PASS  after approval the action executes  -- outcome=EXECUTED
```
Live (Containment log): `containment PENDING ... action NOT executed. Planned to block [...]`.

**3. Containment executes a real (local-simulated) mitigation once approval clears — MET.**
```
[containment] [SIMULATED FIREWALL] blocked 5 new IP(s) ['203.0.113.15', ...] for incident inc-0e6935d336bf
[containment] CONTAINED inc-0e6935d336bf: blocked=[...] (approved by alice@soc (human))
```

**4. On-Call sends a notification and handles both ack and timeout, with provenance-tagged signal — MET (notification = honest file-sink; see §5).**
- Human path: `POST /ack` → `approval=human/alice@soc` → Containment resumes → CONTAINED.
- Timeout path: no ack → `ESCALATION TIMEOUT ... auto-approving` → `approval=timeout_escalation` → Containment resumes → CONTAINED.
Final rows:
```
inc-0e6935d336bf: DETECTED -> CANDIDATE -> ASSESSED -> DISPATCHED -> CONTAINED   approval=human/alice@soc
inc-a699847f56af: DETECTED -> CANDIDATE -> ASSESSED -> DISPATCHED -> CONTAINED   approval=timeout_escalation
```
The notification itself used the **file-sink fallback** (`sent=False`) because
no Slack webhook is configured — the one honest gap on this criterion (§5).

**5. Dispatch is real and parallel — MET.**
`dispatch_real` uses `asyncio.gather`; both legs are launched together and
authority-checked. TA log:
```
=== DISPATCH (Phase 2): fanning out inc-a699847f56af to Containment + On-Call in parallel ===
dispatched page to on_call for inc-a699847f56af
dispatched request_action to containment for inc-a699847f56af
```
On-Call's page returns quickly while Containment is still running its crew, so
the two are genuinely in flight at once (the per-leg "dispatched" lines log on
completion, not on start).

**6. Full chain runs live, traceable for one incident_id — MET.**
`test_phase2_e2e.py`: **ack path 9/9**, **timeout path 5/5**. Both incidents
traced end to end in the store (see §3.4).

---

## 4. Deviations, and why

1. **Firewall is locally simulated, not a real cloud API.** The brief permits
   this (cloud deploy still deferred) and asks it be labeled: `firewall.py`
   writes a JSON state file and logs `[SIMULATED FIREWALL]`. When a cloud
   account exists, only that module changes.
2. **CrewAI forced onto its LiteLLM route via a `litellm/` model prefix.**
   CrewAI 1.x routes a bare `gemini/...` model to a *native* google-genai
   provider that bypasses LiteLLM (killing our fallback) and isn't installed.
   The prefix forces the LiteLLM route. It also meant dropping CrewAI's
   `output_pydantic` (its instructor path re-sends the prefixed string and
   litellm rejects it) in favour of parsing a `DECISION:` sentinel — more
   robust anyway, and IP selection comes from evidence, not model text.
3. **Model ids differ from the brief's literal `gemini-2.5-flash`.** That
   model's free-tier *daily* quota (20/day) was exhausted during development,
   so the chains list fresher buckets first. Provider decision (Gemini via
   routing) unchanged; the whole point of the routing layer is that this is a
   config change. Flagged per instructions.
4. **Thread-limit env vars (`OPENBLAS_NUM_THREADS=1`) when launching CrewAI
   processes** to avoid an OpenBLAS memory-allocation error under concurrent
   imports on this machine. Operational workaround, no behaviour change.

No Phase 3 work was done: no Forensics, no evidence handshake, no
feedback/re-classification, no pub/sub race, no multi-tier escalation.

---

## 5. What is needed from the user before Phase 3

**Itemized, each currently missing/blocking:**

1. **Slack webhook — `ONCALL_SLACK_WEBHOOK_URL` (provider: Slack incoming
   webhook).** For On-Call to send a *real* notification. **Currently missing**
   → On-Call falls back to a local file sink (`on_call/notifications.log`,
   `sent=False`): the flow is fully exercised but nothing is actually
   delivered. This is the one honest gap in exit criterion 4. A free Slack
   incoming webhook (or any webhook URL) flips it to real with no code change.
   Set it in `.env` and restart On-Call.

2. **A second real LLM provider key — `CEREBRAS_API_KEY` and/or
   `OPENROUTER_API_KEY` (providers: Cerebras, OpenRouter).** **Currently
   missing** → every routing chain is Gemini-only, so "multi-provider" fallback
   is really multi-*model* fallback within one provider. That still works (and
   saved the pipeline live when Gemini buckets capped), but a single provider
   outage would stall everything. One non-Gemini key makes the fallback truly
   cross-provider. Add to `.env`; the chains already list these providers
   (commented) and prune them until a key exists.

3. **(Optional) Ollama — local model server (provider: Ollama).** **Currently
   not installed** → the mechanical chain's local-first entry is pruned and
   falls back to Gemini. Installing Ollama + pulling a small model (e.g.
   `llama3.1:8b`) would give the mechanical agents quota-free local inference —
   valuable given the Gemini free-tier daily caps. Not blocking; the chain
   degrades gracefully. Needs ~6–8 GB RAM; flag if the dev machine can't spare
   it.

**Standing constraint (unchanged):** the Gemini free tier's per-model daily cap
(~20/day) remains the pressure point. Phase 2's routing spreads load across
model buckets and survived live by falling back, but Phase 3 adds Forensics and
more calls per incident. Items 2 and 3 above are the durable fix; otherwise
expect to rotate model ids in the chains as buckets exhaust, or move to a paid
tier.

**Carried over:** cloud deploy of the target app is still deferred, so the
firewall stays simulated until there is a real environment to act on.
