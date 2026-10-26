# Phase 1 — completion report

Verified 2026-10-03/04, Python 3.11.9, Windows 11, Gemini free tier.

**All six exit criteria MET.** The front half of the pipeline runs end to end:
a simulated attack against the live target app becomes a real, LLM-classified
incident in the store, with no manual data entry anywhere in the chain. The
one thing to know up front is a hard external constraint — the **Gemini free
tier's per-model daily request cap** (gemini-2.5-flash is ~20/day) — which
shaped the model choices and is the main thing to plan around for Phase 2. See
§5.

---

## 1. What was built, task by task

### Task 1 — Attack Simulation Script — **done**

`scripts/attack_simulate.py`, configurable (`--target-url`, `--pattern`,
`--intensity`, `--delay`, `--endpoint`, `--single-source`). Three patterns:

- `brute-force` — many `POST /login` failures across usernames and simulated
  source IPs (a botnet by default via `X-Forwarded-For`, or one host with
  `--single-source`).
- `burst` — a GET spike against `/status` or `/profile`.
- `baseline` — quiet, mostly-legitimate traffic: the control case Detection
  must **not** escalate.

The attacker source IPs are RFC-5737 documentation ranges that the threat-intel
mock also knows as "bad", so a simulated brute force lights up correlation.
Confirmed it produces real, varied `access.log` entries (brute force → 401s,
baseline → 200s).

### Task 2 — Detection & Monitoring (ADK, port 9101) — **done**

Own process, own agent card, replaces the Phase 0 `adk_sender` scaffold.

- **Alert Ingestion** (`detection/log_reader.py`) — polls `access.log`
  incrementally (byte-offset tail, handles rotation/truncation and a not-yet-
  existing file), parses each JSON line into a raw signal. No judgement here.
- **Noise Filtering** (`detection/agents.py`) — an ADK `LlmAgent` with a
  `FunctionTool` (`get_window_stats`) that serves aggregated window stats
  (counts, distinct IPs, distinct usernames, rate, endpoint/status
  breakdowns). The agent reasons over the window and emits a structured
  `NoiseVerdict` (escalate / pattern_type / confidence / reasoning). The
  decision is the model's — no threshold in code.
- **Handoff** (`detection/agents.py::hand_off`) — packages a survivor into the
  shared envelope, writes the `DETECTED` row, and sends a real A2A task to
  Threat Assessment.
- Detection serves its own complete agent card and backs it with a real
  inbound executor (no-op in Phase 1), so Forensics' feedback loop can reach
  it later.

Windowing (`detection/windowing.py`) is a time-bounded buffer reduced to the
descriptive stats the agent reasons over — arithmetic only, no verdict.

### Task 3 — Threat Assessment & Intelligence (ADK, port 9102) — **done**

Own process, replaces the Phase 0 `crew_receiver` role. **ADK, not CrewAI** —
the Phase 0 receiver was CrewAI only to prove cross-framework transport.

- **Correlation** (`threat_assessment/agents.py`) — an `LlmAgent` with a
  threat-intel `FunctionTool` (`threat_assessment/threat_intel.py`, a mock over
  RFC-5737 "known bad" ranges). It calls the tool and *reasons* over the result
  into a structured `CorrelationResult`; the lookup supplies facts, the agent
  draws the conclusion.
- **Severity Classification** — an `LlmAgent` that takes the evidence plus the
  correlation summary and emits `SeverityAssessment` (severity ∈
  Low/Medium/High/Critical, incident_type, escalate, rationale). Updates the
  row to `ASSESSED` with severity/type/escalated. Off-vocabulary severities are
  coerced to Medium with a loud log rather than written raw.
- **Dispatch** (`threat_assessment/dispatch.py`) — **stubbed, by design.**
  Builds the correctly-formed envelopes for Containment and On-Call and logs
  each in full, bracketed by `=== DISPATCH STUB (Phase 1): NOT sending ===`, so
  the skip is unambiguous. Switching to real sends later is one line per
  target.

### Task 4 — Incident Store Integration — **done**

Phase 0 left `status` free text; Phase 1 settled the vocabulary and migrated
the store (`infra/migrations/001_phase1_status_vocabulary.sql`, applied by
`scripts/migrate_store.py`; folded into `infra/schema.sql` for fresh volumes):

- `status` CHECK-constrained to `DETECTED → CANDIDATE → ASSESSED → DISPATCHED →
  CONTAINED → RESOLVED`.
- `severity` CHECK-constrained to the four labels, still nullable.
- new `escalated` boolean (independent of status) and `incident_type` columns.

The store client (`shared/store/incidents.py`) gained `advance_status()`, which
refuses backwards transitions (safe under concurrent writers with no
orchestrator) and appends every transition to `raw_payload.status_history` with
which system made it and when — this is the audit trail. Full write path
confirmed: Detection inserts `DETECTED`, Threat Assessment advances
`CANDIDATE → ASSESSED` with severity populated, all keyed on one
`incident_id`. No manual writes — every row traces to an attack-script run.

---

## 2. Files created or modified

**New — Detection**
- `detection/__init__.py`
- `detection/log_reader.py`
- `detection/windowing.py`
- `detection/agents.py`
- `detection/server.py`

**New — Threat Assessment**
- `threat_assessment/__init__.py`
- `threat_assessment/threat_intel.py`
- `threat_assessment/agents.py`
- `threat_assessment/dispatch.py`
- `threat_assessment/server.py`

**New — shared / infra**
- `shared/llm.py` — model selection, `.env` loading, rate-limit retry
- `infra/migrations/001_phase1_status_vocabulary.sql`
- `scripts/migrate_store.py`

**New — scripts**
- `scripts/attack_simulate.py`
- `scripts/test_detection_filter.py` — attack-vs-baseline discrimination
- `scripts/test_phase1_e2e.py` — full live pipeline

**Modified**
- `shared/schemas/incident_message.py` — added `IncidentStatus`, `Severity` enums
- `shared/schemas/__init__.py` — export them
- `shared/schemas/incident_message.schema.json` — regenerated
- `shared/store/incidents.py` — new columns, `advance_status`, `status_history`, enum handling
- `shared/a2a_support.py` — real system URLs + `url_for_system`; `incident_skill` tags param
- `scripts/test_incident_store.py` — updated to the settled vocabulary
- `scripts/start_all.ps1` — launches the Phase 1 stack
- `requirements/adk.txt`, `requirements/adk.lock.txt`, `requirements/target_app.txt`, `requirements/target_app.lock.txt` — `python-dotenv`
- `.env` — model selection block (and the existing `GOOGLE_API_KEY`)

---

## 3. Exit criteria check

**1. Attack script produces real log entries — MET.**
```
[sim] brute-force: 15 failed logins, source=many IPs
[sim] done: 15 requests in 0.6s, status breakdown={401: 15}, transport errors=0
```
Log grew by exactly the requests sent; baseline run produced 200s.

**2. Noise filter distinguishes attack from baseline — MET.**
`scripts/test_detection_filter.py`, both from real generated traffic:
```
NEGATIVE (baseline):  escalate=False pattern=isolated_failure confidence=0.90
  "...only 2 failed login attempts... both targeting the same single username
   'alice'... isolated user errors rather than a sustained attack."
POSITIVE (brute-force): escalate=True pattern=credential_stuffing confidence=0.90
  "...34 failed logins from 24 distinct source IPs targeting 8 distinct
   usernames within 0.94 seconds... characteristic of a credential stuffing attack."
2/2 cases passed
```

**3. Real A2A task Detection → Threat Assessment between two processes — MET.**
Detection's log, live run:
```
A2A handoff -> Threat Assessment (http://127.0.0.1:9102): incident inc-3ad6c1fc00b9 pattern=credential_stuffing confidence=0.90
Successfully fetched agent card data from http://127.0.0.1:9102/.well-known/agent-card.json
a2a response: {'kind': 'message', 'message_id': ...}
Threat Assessment acknowledged inc-3ad6c1fc00b9
```

**4. Severity Classification produces real LLM-reasoned severity and type — MET.**
```
inc-3ad6c1fc00b9 ASSESSED severity=Critical type=Credential Stuffing ESCALATED
rationale: "...coordinated botnet-driven credential-stuffing attack involving 34
 distinct source IPs, 41 failed logins, and confirmed malicious-reputation..."
```
Different attacks yield different reasoning; not a hardcoded default.

**5. Store shows DETECTED → CANDIDATE → ASSESSED with severity, traceable — MET.**
`status_history` for a traced incident:
```
DETECTED   by detection          (from null)
CANDIDATE  by threat_assessment  "accepted for assessment"
ASSESSED   by threat_assessment  "severity=Critical type=Credential Stuffing"
```
Final row: `status=ASSESSED, severity=Critical, incident_type=Credential Stuffing, escalated=t`.

**6. Dispatch stub shows exact Containment/On-Call payloads, well-formed — MET.**
```
=== DISPATCH STUB (Phase 1): NOT sending -- Containment and On-Call do not exist yet ===
[STUB] WOULD send A2A task -> containment for incident inc-3ad6c1fc00b9: { ...full IncidentMessage... }
[STUB] WOULD send A2A task -> on_call   for incident inc-3ad6c1fc00b9: { ...full IncidentMessage... }
=== END DISPATCH STUB ===
```

`scripts/test_phase1_e2e.py` asserts criteria 2–6 against the live processes:
**12/12 checks passed**, incident `inc-3ad6c1fc00b9` traced from attack to ASSESSED.

---

## 4. Deviations from the instructions, and why

1. **Noise filter and correlation run on different Gemini models from the
   severity classifier.** The free tier meters per model, so splitting the
   pipeline across models multiplies the available quota (see §5). No decision
   from the brief's "settled decisions" was changed — the LLM provider is still
   Gemini via `GOOGLE_API_KEY`. Models are `.env`-configurable
   (`GEMINI_MODEL`, `GEMINI_REASONING_MODEL`, `GEMINI_FILTER_MODEL`).

2. **Model is `gemini-2.5-flash` / `gemini-3.5-flash-lite`, not
   `gemini-2.0-flash`.** The Phase 0 scaffold referenced `gemini-2.0-flash`,
   which Google has since retired (404). This is the "flag it if a settled
   decision turns out unworkable" case: the *provider* decision stands, only
   the specific retired model id changed.

3. **Added a rate-limit retry/backoff layer** (`shared/llm.py`) and **gated
   Detection's LLM calls to fire only on new activity** (no new signals → no
   model call; post-escalation cooldown → no model call). Not asked for, but
   without it the poll loop burns the tiny free-tier quota in seconds and the
   pipeline cannot complete. This is infrastructure, not Phase 2 logic.

4. **Status-vocabulary migration + backwards-transition guard.** The brief
   settled the vocabulary; enforcing it (CHECK constraint) and refusing
   backward moves is implied by "correct, complete row progression" once six
   systems will write concurrently with no orchestrator.

5. **Detection serves a real inbound A2A executor** (no-op in Phase 1). The
   brief says keep Detection's card "real and complete"; a card with no backing
   endpoint would 404 when later phases probe it.

Nothing from Phase 2 was built: no Containment/On-Call/Forensics/Comms logic,
no real mitigation, no guardrail/approval middleware, no feedback/re-classification.

---

## 5. What is needed from the user before Phase 2

**Blocking / most important — Gemini quota.**
The free tier's **per-model, per-day** cap (gemini-2.5-flash ≈ 20 requests/day)
was exhausted during development; the pipeline then stalls at `CANDIDATE` with
a 429 whose retry delay is hours. Phase 1 works today only because the agents
are split across flash-lite model buckets. Phase 2 adds four more systems and
more model calls per incident, so this will not scale on free tier. **Decision
needed:** enable billing on the Gemini key (paid tier lifts the per-minute and
per-day caps dramatically), or accept a deliberately slow, low-volume demo
cadence and I will tune cooldowns/intervals accordingly. Either is fine — but
it should be a conscious choice before Phase 2, not a surprise mid-build.

**Carried over from Phase 0 (still open, not blocking Phase 1 or 2 logic):**
- Cloud deploy of the target app is still deferred (the brief confirmed this).
  Detection reads the local `access.log` as decided.

**Decisions worth taking now because Phase 2 forces them:**
- **Dispatch becomes real in Phase 2.** The stub already emits correctly-formed
  Containment and On-Call envelopes; those two systems need agent cards at
  known URLs (I have reserved none yet beyond Detection/Threat Assessment in
  `shared/a2a_support.py`). Confirm CrewAI for those systems per the
  architecture, and that `shared/a2a_support.SYSTEM_URLS` is where their
  endpoints should be registered.
- **Guardrail/approval middleware starts in Phase 2** per the brief — worth
  deciding whether it sits in the shared layer (so every system inherits it) or
  per-system.

**Housekeeping:** a few incidents are parked at `CANDIDATE` in the store from
runs that hit the daily quota mid-assessment (e.g. `inc-42ae9eee0c02`,
`inc-a3af1273a9e4`). They are real, attack-traceable rows, left as honest
evidence of the quota stall; delete them with
`store.delete_incident(...)` if you want a clean table.
