# Phase 0 — Foundations & Environment Setup

## Project Context (for reference)

This is **Crisis Coordination Agents** — an AI-coordinated incident response system made of 6 independently built agent systems that detect, assess, and respond to real security incidents against a live, self-hosted target application. The systems communicate exclusively over Google's **A2A (Agent-to-Agent) protocol** — no shared codebase, no shared database, no central orchestrator.

**The 6 systems (built across later phases):**
1. Detection & Monitoring (Google ADK)
2. Threat Assessment & Intelligence (Google ADK)
3. Containment/Ops (CrewAI)
4. Forensics & Recovery (CrewAI)
5. Customer Communications (CrewAI)
6. On-Call/Escalation (CrewAI)

**This phase (Phase 0) builds none of the above yet.** It only builds the shared plumbing every later phase depends on: working dev environments, a live target app to eventually attack, a shared incident-state store, and a proven, working A2A handshake between one ADK agent and one CrewAI agent.

---

## Goal of This Phase

Prove that every piece of infrastructure the project needs is actually working, in isolation, before any real agent logic is built on top of it. Nothing here should involve incident detection, severity classification, or any "real" agent reasoning — this phase is scaffolding only.

---

## Tasks

### 1. Environment Setup
- Set up a Python environment (venv or poetry) for the project
- Install and verify **Google ADK** — run ADK's own sample/quickstart agent locally and confirm it responds
- Install and verify **CrewAI** — run CrewAI's own sample crew locally and confirm it responds
- Document exact versions installed (ADK version, CrewAI version, Python version) in a `requirements.txt` / `pyproject.toml`

### 2. Cloud Sandbox Setup
- Set up a free-tier cloud sandbox account (AWS or GCP — pick one and note which)
- Confirm basic CLI/SDK access works (e.g., `aws sts get-caller-identity` or GCP equivalent)
- Note: do not provision the target app yet — just confirm sandbox access works

### 3. Target Application (the future "victim" site)
- Build a minimal Flask or Node app with:
  - A basic login endpoint (`POST /login`) that accepts username/password and returns success/failure
  - At least one other simple endpoint (e.g., `GET /status` or `GET /profile`)
  - Basic request logging to a file or stdout (timestamp, endpoint, source IP, status code, success/failure) — this log is what Detection will read from in Phase 1, so the log format matters; keep it simple and consistent
- Deploy this app to the cloud sandbox so it's reachable over a real URL
- Confirm you can hit it manually (e.g., via `curl`) and see log entries appear

### 4. Shared Incident-State Store
- Stand up a Postgres or Redis instance (local Docker container is fine for now — doesn't need to be in the cloud yet)
- Define and create the basic schema/structure for an "incident" record. Minimum fields:
  - `incident_id` (unique identifier)
  - `created_at` / `updated_at` timestamps
  - `status` (free text for now, e.g., "detected")
  - `severity` (nullable for now)
  - `raw_payload` (JSON blob, flexible)
- Write a trivial test script that inserts a dummy incident record and reads it back

### 5. Define the Shared A2A Message Schema
- Define the baseline JSON shape every A2A task will carry across all future systems. At minimum:
  - `incident_id`
  - `timestamp`
  - `source_system`
  - `target_system`
  - `payload` (flexible object, shape will grow per system in later phases)
- Save this as a shared schema file (e.g., `shared/schemas/incident_message.py` or `.json`) that every future system will import/reference — this avoids each phase reinventing the message shape

### 6. "Hello World" A2A Exchange
- Build two minimal dummy agents:
  - One trivial ADK agent exposing an A2A agent card
  - One trivial CrewAI agent exposing an A2A agent card
- Have the ADK agent send a real A2A task request (using the shared schema above) to the CrewAI agent
- Confirm the CrewAI agent receives it, and sends a real task response back
- This must be a **real network call between two independently running processes** — not an in-memory function call pretending to be A2A

---

## Exit Criteria (must all be true before moving to Phase 1)

- [ ] ADK and CrewAI both run sample agents successfully in this environment
- [ ] The target app is live on the cloud sandbox and reachable via a real URL
- [ ] Hitting the target app's endpoints manually produces log entries in a consistent, readable format
- [ ] The incident-state store is running and a test record can be written and read back
- [ ] The shared A2A message schema is defined in a shared, reusable location
- [ ] A real A2A task request/response exchange has been completed between one ADK process and one CrewAI process, each running independently (separate terminals/processes, not one script calling functions directly)

---

## Instructions for Claude Code

Claude Code must build this phase's deliverables directly in the project repository. Once the tasks above are complete:

**Claude Code must report back, in plain text at the end of the session, exactly:**
1. What was built or configured, listed task-by-task against the task list above
2. The exact file paths created or modified
3. Any exit criteria above that could NOT be fully verified, and why (e.g., "cloud sandbox step skipped — no AWS credentials provided — target app deployed locally only instead")
4. Any deviations made from these instructions, and the reason for the deviation
5. What is needed from the user (credentials, decisions, approvals) before Phase 1 can begin

Do not proceed to any Phase 1 task (Detection, Threat Assessment, or any real agent reasoning logic) under this phase. If something in Phase 1's scope seems necessary to complete a Phase 0 task, stop and flag it rather than building it.