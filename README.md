# Crisis Coordination Agents

Six independently built agent systems that detect, assess and respond to real
security incidents against a live, self-hosted target application. The systems
share no codebase, no database client library and no orchestrator — they
coordinate only over Google's **A2A (Agent-to-Agent) protocol**.

| # | System | Framework | Status |
| --- | --- | --- | --- |
| 1 | Detection & Monitoring | Google ADK | **built (Phase 1)** |
| 2 | Threat Assessment & Intelligence | Google ADK | **built (Phase 1)** |
| 3 | Containment / Ops | CrewAI | **built (Phase 2)** |
| 4 | Forensics & Recovery | CrewAI | **built (Phase 3)** |
| 5 | Customer Communications | CrewAI | later |
| 6 | On-Call / Escalation | CrewAI | **built (Phase 2)** |

**Current phase: 3 complete.** Phase 0 built the shared plumbing; Phase 1 the
detection→assessment front half; Phase 2 added Containment, On-Call, the shared
guardrail gate, and multi-provider LLM routing; Phase 3 added Forensics &
Recovery, the evidence-preservation gate, and a real feedback/re-classification
loop that makes the pipeline non-linear
([docs/PHASE3_REPORT.md](docs/PHASE3_REPORT.md)).

```
attack_simulate.py ─▶ target app ─▶ access.log
                                       │ (poll)
                                Detection (ADK :9101)   ingest ▸ window ▸ noise-filter(LLM) ▸ handoff
                                       │ A2A  DETECTED
                                Threat Assessment (ADK :9102)  correlate(LLM) ▸ severity(LLM)
                                       │ CANDIDATE ▸ ASSESSED ▸ DISPATCHED
              parallel fan-out (asyncio.gather, authority-gated)
       ┌───────────────────────┬────────────────────────┬─────────────────────────┐
  On-Call (:9104)       Containment (:9103)        Forensics (:9105)               │
  page ▸ esc. timer     decide ▸ GUARDRAIL gate    preserve evidence ▸ RCA(LLM)    │
       │ ack | timeout        │ (evidence + approval)      │        │               │
       └─▶ approval signal ───┤                    evidence_preserved │ reclassify? │
          (store flag)        ▼                      signal ──────────┘  (A2A back   │
                       execute (sim firewall) ▸ CONTAINED                 upstream)  │
                              ▲                                              │       │
                       recovery lift ◀── Forensics recovery plan   Threat Assessment ◀┘
                              │                                    re-assess ▸ reclassified
                       incident store (Postgres :5433)             (re-page if crosses threshold)
```

Every agent reaches its model through `shared/llm.py`'s routing layer
(LiteLLM, per-role fallback chains). All side-effecting actions pass
`shared/guardrail.py` first.

> **Gemini free-tier quota matters here.** The free tier caps requests per
> model per day; the routing layer falls back across model/providers to cope.
> See [docs/PHASE2_REPORT.md](docs/PHASE2_REPORT.md) §5.

## Layout

```
shared/                     imported by every system; no agent logic
  schemas/incident_message.py       the A2A envelope contract + status/severity vocab
  schemas/incident_message.schema.json  generated JSON Schema, for non-Python consumers
  store/incidents.py                incident-store client (lifecycle-aware, audit trail)
  a2a_support.py                    agent cards, envelope <-> wire, outbound send, system URLs
  llm.py                            LLM routing (LiteLLM per-role fallback chains), .env, retry
  guardrail.py                      authority matrix + approval gate (Phase 2)
detection/                  System 1 — Detection & Monitoring (ADK, :9101)
  log_reader.py                     Alert Ingestion: tails access.log -> signals
  windowing.py                      rolling window + aggregated stats
  agents.py                         Noise Filtering LlmAgent + handoff
  server.py                         A2A card + poll loop
threat_assessment/          System 2 — Threat Assessment & Intelligence (ADK, :9102)
  threat_intel.py                   mock intel FunctionTool (known-bad ranges)
  agents.py                         Correlation + Severity Classification LlmAgents
  dispatch.py                       real parallel fan-out to Containment + On-Call
  server.py                         A2A card + assessment executor
containment/                System 3 — Containment / Ops (CrewAI, :9103)
  firewall.py                       locally-simulated firewall state (not real cloud)
  agents.py                         Situation Review + Immediate Action crew
  server.py                         A2A receiver; guardrail-gated execution
on_call/                    System 6 — On-Call / Escalation (CrewAI, :9104)
  ops.py                            static schedule + notification (Slack / file sink)
  agents.py                         page-drafting crew
  server.py                         A2A receiver; escalation timer + /ack endpoint
forensics/                  System 4 — Forensics & Recovery (CrewAI, :9105)
  evidence.py                       evidence snapshot + evidence_preserved signal
  rca.py                            long-form Root Cause Analysis (continuation-aware)
  recovery.py                       recovery plan + lift signal (CrewAI)
  server.py                         A2A receiver; evidence -> RCA -> reclassify -> recovery
target_app/                 the deliberately insecure "victim" site
  app.py                            Flask app; access-log format is Detection's input
  Dockerfile                        deployable image
infra/
  docker-compose.yml                Postgres incident store (host port 5433)
  schema.sql                        full current schema, applied on a fresh volume
  migrations/                       numbered migrations for existing volumes
  deploy_target_app_gcp.sh          Cloud Run deploy — written, NOT yet run
a2a_hello/                  Phase 0 throwaway agents; superseded, not started by default
scripts/                    attack simulator + verification; each runnable on its own
requirements/               one dependency set per virtualenv, plus exact locks
```

### Why three virtualenvs

ADK and CrewAI pull large, overlapping dependency trees. Forcing them into one
resolved set buys nothing — the architecture says the systems share no
codebase, so they need not share a dependency resolution either. The target
app gets its own because it is the thing being attacked, not part of the
response system.

| venv | For | Key versions |
| --- | --- | --- |
| `.venv-adk` | Systems 1–2 | `google-adk` 2.11.0, `a2a-sdk` 1.2.1 |
| `.venv-crew` | Systems 3–6 | `crewai` 1.15.23, `a2a-sdk` 1.2.1 |
| `.venv-app` | Target app, test scripts | `Flask` 3.1.3, `psycopg` 3.3.6 |

Verified on Python 3.11.9, Windows 11.

## Setup from scratch

```powershell
# one venv per system
py -3.11 -m venv .venv-adk ; .\.venv-adk\Scripts\python -m pip install -r requirements\adk.txt
py -3.11 -m venv .venv-crew; .\.venv-crew\Scripts\python -m pip install -r requirements\crewai.txt
py -3.11 -m venv .venv-app ; .\.venv-app\Scripts\python -m pip install -r requirements\target_app.txt

Copy-Item .env.example .env   # then fill in GOOGLE_API_KEY (required for Phase 1)
```

Use `requirements/*.lock.txt` instead for the exact transitive set that was
verified. Phase 1 needs the store on the Phase 1 schema — if your Postgres
volume predates it, run `.\.venv-app\Scripts\python scripts\migrate_store.py`.

## Running

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1
```

That starts Postgres and opens three windows: the target app on `:8080`, Threat
Assessment on `:9102`, Detection on `:9101`. Or by hand (Threat Assessment
before Detection — Detection hands off to it):

```powershell
docker compose -f infra\docker-compose.yml up -d
.\.venv-app\Scripts\python  target_app\app.py               # :8080
.\.venv-adk\Scripts\python  -m threat_assessment.server     # :9102
.\.venv-adk\Scripts\python  -m detection.server             # :9101
```

Then drive an attack and watch an incident appear:

```powershell
.\.venv-app\Scripts\python scripts\attack_simulate.py --pattern brute-force --intensity 40
docker exec crisis-incident-store psql -U crisis -d incidents -c `
  "SELECT incident_id,status,severity,incident_type,escalated FROM incidents ORDER BY created_at DESC LIMIT 5;"
```

## Verification

Each script is independent and prints PASS/FAIL per check.

```powershell
# Phase 1 — needs the stack running and GOOGLE_API_KEY set
.\.venv-adk\Scripts\python scripts\test_detection_filter.py   # attack vs baseline (no stack needed beyond target app)
.\.venv-app\Scripts\python scripts\test_phase1_e2e.py         # full pipeline, live processes

# Phase 0 — still pass
.\.venv-adk\Scripts\python  scripts\verify_frameworks.py      # run in both ADK and crew venvs
.\.venv-crew\Scripts\python scripts\verify_frameworks.py
.\.venv-app\Scripts\python  scripts\test_incident_store.py
.\.venv-app\Scripts\python  scripts\test_target_app.py
```

`verify_frameworks.py` reports SKIPPED rather than FAILED for the live-model
checks when no API key is set. The Phase 1 scripts need a working
`GOOGLE_API_KEY`; on the free tier, mind the per-model daily quota
([docs/PHASE1_REPORT.md](docs/PHASE1_REPORT.md) §5).

## The Phase 0 A2A hello-world (superseded)

The original cross-framework handshake still exists under `a2a_hello/` and can
be run by hand on ports 9001/9002; it is not part of the Phase 1 stack. The
real Detection → Threat Assessment A2A flow is diagrammed at the top of this
file.

## The access-log contract

`target_app` writes one JSON object per line to stdout **and** to
`target_app/logs/access.log`. Phase 1's Detection system reads these fields by
name — renaming one breaks Detection.

```json
{"timestamp":"2026-10-02T10:39:19.627422+00:00","request_id":"45014c0c4a93",
 "source_ip":"127.0.0.1","method":"POST","endpoint":"/login","status_code":401,
 "success":false,"auth_outcome":"invalid_credentials","username":"alice",
 "user_agent":"python-requests/2.34.2","duration_ms":0.11}
```

`auth_outcome` is `success`, `invalid_credentials`, `missing_credentials`, or
`null` on endpoints where authentication does not apply. The log file is
ephemeral in a container — read stdout when the app runs in the cloud.

## The A2A envelope

Every task between systems carries an `IncidentMessage`
([shared/schemas/incident_message.py](shared/schemas/incident_message.py)).
The envelope fields are fixed for the project's life; `payload` is free-form
and each phase documents its own shape.

```python
IncidentMessage(
    incident_id="inc-4bcd85655259",     # join key into the incident store
    timestamp=...,                      # UTC, set by the sender
    source_system=SystemName.DETECTION,
    target_system=SystemName.CONTAINMENT,
    payload={...},                      # grows per system
    correlation_id=None,                # set on replies
)
```

`SystemName` is an enum, so a mistyped target fails at the sender instead of
routing nowhere. Regenerate the JSON Schema after editing the model:

```bash
python shared/schemas/incident_message.py > shared/schemas/incident_message.schema.json
```

## Security posture

The target app is **intentionally insecure** — plaintext credentials, no rate
limiting, no lockout, an unauthenticated `/profile`. That is what makes it a
usable target. Deploy it only to a throwaway cloud project, never alongside
anything real.
