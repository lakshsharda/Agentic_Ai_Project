# Phase 1 — Detection & Monitoring + Threat Assessment & Intelligence

## Context Carried Over From Phase 0

Phase 0 is complete except the cloud deploy (deferred — see decision below). What exists and is verified working:

- Target app running locally (`target_app/app.py`), deliberately insecure, logging one JSON object per line to both stdout and `target_app/logs/access.log` with: `timestamp, request_id, source_ip, method, endpoint, status_code, success, auth_outcome, username, user_agent, duration_ms`
- Postgres incident store (`infra/docker-compose.yml`, `infra/schema.sql`) on host port 5433, `incidents` table with `incident_id, created_at, updated_at, status, severity, raw_payload`
- Shared A2A message envelope: `shared/schemas/incident_message.py` (Pydantic + generated JSON Schema), with `schema_version`, `correlation_id`, and `SystemName` enum already added beyond the original five required fields
- A working, bidirectional A2A hello-world exchange between an ADK process and a CrewAI process, each serving its own agent card, proven over real HTTP with a third-process trigger
- Three separate virtualenvs: `.venv-adk`, `.venv-crew`, `.venv-app`

**Decisions settled before this phase starts (do not re-litigate these unless something concrete forces a change — flag it if so):**

1. **LLM:** `GOOGLE_API_KEY` (Gemini) is the model backing both ADK and CrewAI (via LiteLLM) for this phase. Assume it is present in `.env` — if it is missing, stop and report that as a blocker rather than building around its absence.
2. **Log source:** Detection reads from the local file `target_app/logs/access.log`, not stdout and not a cloud log sink. Cloud deploy is deferred to a later phase.
3. **Status vocabulary (fixed enum for `incidents.status`):** `DETECTED → CANDIDATE → ASSESSED → DISPATCHED → CONTAINED → RESOLVED`, plus a separate boolean/flag `escalated` that Threat Assessment can set independently of status. This phase only ever writes `DETECTED`, `CANDIDATE`, and `ASSESSED`.
4. **Incident store location:** stays local Docker Postgres, unchanged from Phase 0.

---

## Goal of This Phase

Build the first two real agent systems — **Detection & Monitoring** and **Threat Assessment & Intelligence**, both on Google ADK — and prove the "front half" of the pipeline end to end: a real attack against the real target app results in a real, classified incident recorded in the incident store, with no manual data entry anywhere in the chain.

This phase replaces the Phase 0 hello-world scaffold agents with real reasoning agents. The hello-world agents' code can be referenced/reused for transport plumbing but their actual logic (echo/acknowledge) should not carry forward.

---

## Tasks

### 1. Attack Simulation Script
- Write a script (`scripts/attack_simulate.py`) that generates realistic malicious-looking traffic against the local target app:
  - A brute-force pattern: repeated `POST /login` attempts with varying usernames/wrong passwords in a short time window
  - Optionally, a second pattern: a request burst against `GET /status` or `GET /profile` to simulate a traffic spike
- The script should be configurable (target URL, intensity, pattern type) since it will be reused in every later phase as the trigger/test mechanism
- Confirm running it produces real, varied entries in `access.log`

### 2. Detection & Monitoring System (Google ADK)
Build as its own process (own venv, own A2A agent card), replacing the Phase 0 `adk_sender` scaffold.

- **Alert Ingestion Agent** — tails/reads `access.log` in near-real-time (polling is fine for this phase; no need for inotify/streaming infra yet). Converts each log line into a raw signal object.
- **Noise Filtering Agent** — an ADK `LlmAgent` that reasons over a window of recent signals (not single lines in isolation — context matters, e.g., "5 failed logins from 5 different IPs in 10 seconds" vs. "1 failed login from a known IP") and decides whether the pattern is noise or worth escalating. This must be a real reasoning step, not a hardcoded threshold — a `FunctionTool` can supply aggregated stats (count, distinct IPs, time window) for the LLM to reason over.
- **Handoff Agent** — packages anything that survives filtering into the shared incident envelope (new `incident_id`, `status=DETECTED`), writes the initial row to the incident store, and sends it as a real A2A task to Threat Assessment's agent card.
- Expose Detection's own agent card (even though nothing calls Detection directly yet, in later phases Forensics' feedback loop will need to reach it conceptually — keep the card real and complete).

### 3. Threat Assessment & Intelligence System (Google ADK)
Build as its own process, replacing the Phase 0 `crew_receiver` scaffold's role (this system is ADK, not CrewAI — the original Phase 0 scaffold used CrewAI for the receiver to prove cross-framework transport; that was a hello-world convenience, not a statement that Threat Assessment is CrewAI. Threat Assessment is ADK per the project architecture).

- **Correlation Agent** — enriches the incoming candidate incident. For this phase, a real threat-intel call is not required — a `FunctionTool` with a small local mock dataset (a short list of "known bad" IP ranges / patterns) is sufficient, but the agent's *reasoning* over that data must be real (not a lookup table decision).
- **Severity Classification Agent** — an `LlmAgent` that takes the enriched incident and assigns `severity` (Low/Medium/High/Critical) and an incident `type` label. Updates the incident row: `status=ASSESSED`, `severity=<value>`.
- **Dispatch Agent** — for this phase, **stub the fan-out**: log what it *would* send to Containment and On-Call (full payload, correctly formed per the shared envelope) rather than actually sending it, since those systems don't exist yet. Make the stub obvious in logs/output so it's unambiguous this is intentional, not a missing feature.

### 4. Incident Store Integration
- Confirm the full write path: Detection inserts the row at `DETECTED`, Threat Assessment updates it through `CANDIDATE` → `ASSESSED` with severity populated, all keyed on the same `incident_id`
- No manual writes — every row in the table during a test run should trace back to the attack script

---

## Exit Criteria (must all be true before moving to Phase 2)

- [ ] Running `scripts/attack_simulate.py` against the live local target app produces real log entries
- [ ] Detection's Noise Filtering Agent demonstrably distinguishes a real attack pattern from a quiet/normal baseline (show both: a run where nothing escalates, and a run where something does)
- [ ] A detected pattern results in a real A2A task sent from Detection to Threat Assessment, over an actual network call between two independently running processes
- [ ] Threat Assessment's Severity Classification Agent produces a real, LLM-reasoned severity and type (not a hardcoded default) and this is visible in its output/logs
- [ ] The incident store shows a correct, complete row progression (`DETECTED → CANDIDATE → ASSESSED` with severity populated) for an incident_id traceable to a specific attack script run
- [ ] The Dispatch Agent's stubbed fan-out output clearly shows the exact payload that would go to Containment and On-Call, correctly formed per the shared schema

---

## Explicitly Out of Scope for This Phase

- No real Containment, Forensics, Comms, or On-Call systems or logic
- No real cloud deploy of the target app
- No guardrail/approval middleware yet (that starts in Phase 2)
- No feedback loop / re-classification logic yet (that starts in Phase 3)

If building something above feels necessary to finish a Phase 1 task, stop and flag it rather than building it.

---

## Instructions for Claude Code

Build this phase's deliverables directly in the project repository, following the carried-over decisions above exactly — do not re-decide the log source, status vocabulary, LLM provider, or store location; flag it if one of them turns out to be unworkable rather than silently changing it.

**At the end of the session, report back in plain text, in this exact structure:**

1. **What was built, task by task** — against the 4 tasks above, same level of detail as the Phase 0 report (what's done, what's partial, what's skipped and why)
2. **Files created or modified** — full list of paths
3. **Exit criteria check** — go through the 6 criteria above one by one, state MET / PARTIAL / NOT MET for each, with evidence (a log snippet, a query result, a test output) wherever possible, the same way the Phase 0 report showed the actual receiver log output
4. **Deviations from these instructions**, and the reason for each
5. **What is needed from the user** before Phase 2 can begin (credentials, decisions, anything blocking)

Do not begin any Phase 2 task (Containment, On-Call, real mitigation actions, or the first guardrail middleware) under this phase.