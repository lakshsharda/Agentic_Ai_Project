# Phase 0 — completion report

Verified on 2026-10-02, Python 3.11.9, Windows 11 (10.0.26200), Docker 29.1.3.

**Five of six exit criteria met. One is blocked: the target app is not
deployed to a cloud sandbox, because no cloud account, credential or CLI
exists in this environment.** Details in [CLOUD_SANDBOX.md](CLOUD_SANDBOX.md).

---

## 1. What was built, task by task

### Task 1 — Environment setup — **done, with one gap**

Three virtualenvs, one per concern, rather than one shared environment. ADK and
CrewAI pull large overlapping dependency trees (`opentelemetry`, `protobuf`,
`pydantic`, `google-genai` vs `litellm`); the project's own architecture says
the systems share no codebase, so forcing one resolved dependency set buys
nothing and risks a conflict blocking both.

| venv | Purpose | Verified versions |
| --- | --- | --- |
| `.venv-adk` | Systems 1–2 | `google-adk` 2.11.0, `google-genai` 2.27.0, `a2a-sdk` 1.2.1 |
| `.venv-crew` | Systems 3–6 | `crewai` 1.15.23, `a2a-sdk` 1.2.1 |
| `.venv-app` | Target app, test scripts | `Flask` 3.1.3, `psycopg` 3.3.6 |

Both frameworks verified installed and able to construct and wire up a real
agent — `scripts/verify_frameworks.py`, run in each venv:

- ADK: built an `LlmAgent` with a `FunctionTool`. **PASS**
- CrewAI: built an `Agent` + `Task` + `Crew`. **PASS**
- a2a-sdk: agent-card construction and envelope round trip. **PASS**

**The gap:** neither framework's sample agent was driven through a live model
call, because that needs an API key and none was provided. Both report
`SKIPPED` with the missing variable named, rather than `FAILED`. The install is
proven; the model response is not. See *Outstanding* below.

### Task 2 — Cloud sandbox — **BLOCKED**

No `gcloud` and no `aws` on this machine, and no credentials. I did not create
a billable cloud account on your behalf. Nothing was provisioned.

### Task 3 — Target application — **built and verified locally; not deployed**

`target_app/app.py`, a Flask app, deliberately insecure (plaintext credential
comparison, no rate limiting, no lockout, unauthenticated `/profile`) because
it is the thing later phases attack.

- `POST /login` — JSON or form body; 200 success / 401 invalid / 400 missing
- `GET /status` — liveness, uptime
- `GET /profile?username=` — returns a profile with no auth (an IDOR to find later)
- `GET /` — endpoint index

Access log: one JSON object per line, to **both** stdout and
`target_app/logs/access.log`. Fields — `timestamp`, `request_id`, `source_ip`,
`method`, `endpoint`, `status_code`, `success`, `auth_outcome`, `username`,
`user_agent`, `duration_ms`. `source_ip` prefers the first `X-Forwarded-For`
entry so it stays correct behind a load balancer.

`auth_outcome` is deliberately separate from `status_code`: Phase 1 needs to
distinguish a failed login from any other 4xx without pattern-matching paths.

Verified by `scripts/test_target_app.py` — **16/16** as a host process,
**9/9** against the container (log assertions skipped there by design; the
container's log was checked separately via `docker logs`, 10 entries).

Deployment artifacts built and verified locally:

- `target_app/Dockerfile` — image `crisis-target-app:phase0` builds, runs, and
  serves all endpoints on `127.0.0.1:8081`, streaming the JSON access log to
  stdout.
- `infra/deploy_target_app_gcp.sh` — Cloud Run deploy. Written and
  syntax-checked, **never executed**.

### Task 4 — Shared incident-state store — **done**

Postgres 16-alpine via `infra/docker-compose.yml`, host port **5433** (chosen
to avoid clashing with any locally installed Postgres). `infra/schema.sql` is
mounted into `docker-entrypoint-initdb.d`, so the schema applies automatically
on a fresh volume — verified by destroying the volume (`down -v`) and bringing
it back: table, both indexes and the trigger were all present.

`incidents` table: `incident_id` (PK), `created_at`, `updated_at`, `status`
(default `'detected'`), `severity` (nullable), `raw_payload` (JSONB). `status`
and `severity` are left free text / nullable as the task specifies. An
`updated_at` trigger means no system has to remember to set it.

`shared/store/incidents.py` is the single place the SQL lives, so the six
systems cannot drift on column names. `update_incident` **merges** into
`raw_payload` (`||`) rather than replacing it — several systems write into the
same incident and must not clobber each other's keys.

`scripts/test_incident_store.py` — **all checks pass**: insert, read back,
every field round-tripped, payload merge, `updated_at` trigger fired, cleanup.

### Task 5 — Shared A2A message schema — **done**

`shared/schemas/incident_message.py` — a pydantic model, the source of truth,
plus `incident_message.schema.json` generated from it for non-Python consumers.

Required fields are all present: `incident_id`, `timestamp`, `source_system`,
`target_system`, `payload`. Three additions that cost nothing now and save
rework later:

- `schema_version` (`0.1.0`) — so a receiver can reject a shape it does not know.
- `correlation_id` — request/response pairing.
- `SystemName` as an **enum** covering all six systems — a mistyped target
  system fails at the sender instead of silently routing nowhere.

`extra="forbid"`: an unexpected field is an error, not silently dropped.
Helpers: `to_wire()`, `from_wire()`, `reply()`.

### Task 6 — "Hello World" A2A exchange — **done**

Two agents, each its own OS process, each serving its own A2A agent card:

| | ADK side | CrewAI side |
| --- | --- | --- |
| File | `a2a_hello/adk_sender/` | `a2a_hello/crew_receiver/server.py` |
| venv | `.venv-adk` | `.venv-crew` |
| Port | 9001 | 9002 |
| Card | `Detection Scaffold (ADK)` | `Containment Scaffold (CrewAI)` |
| Skill | `echo_incident` | `ack_incident` |

The exchange, all over real HTTP:

1. The ADK process fetches the CrewAI card from
   `http://127.0.0.1:9002/.well-known/agent-card.json`.
2. It sends a `message/send` JSON-RPC task to the URL that card advertises,
   carrying an `IncidentMessage` as a JSON text part.
3. The CrewAI process parses and validates the envelope, builds a real CrewAI
   `Crew`, updates the incident row, and enqueues a reply `IncidentMessage`
   with the roles reversed.
4. The ADK process validates the reply.

Confirmed in the receiver's own process log:

```
[crew-receiver] INFO received A2A task: incident_id=inc-4bcd85655259 from=scaffold_adk to=scaffold_crew payload_keys=['note', 'scaffold', 'sent_at']
[crew-receiver] INFO replying to scaffold_adk for incident inc-4bcd85655259
INFO:     127.0.0.1:55298 - "POST / HTTP/1.1" 200 OK
```

And the shared store ties the two sides together — the sender created the row,
the receiver updated it, in one round trip:

```
incident_id | inc-4bcd85655259
status      | ack_received
raw_payload | {"note": "...", "origin": "scaffold_adk", "acked_by": "scaffold_crew", ...}
```

`scripts/test_a2a_hello.py` — **14/14**. It drives the exchange from a third
process over HTTP, so a pass cannot be explained by the test calling agent
code directly.

---

## 2. Files created

Everything below is new; nothing pre-existing was modified (`Phase0.md` is
untouched).

**Shared contracts**
- `shared/__init__.py`
- `shared/schemas/__init__.py`
- `shared/schemas/incident_message.py` — the A2A envelope, source of truth
- `shared/schemas/incident_message.schema.json` — generated JSON Schema
- `shared/store/__init__.py`
- `shared/store/incidents.py` — incident-store client
- `shared/a2a_support.py` — agent cards, envelope↔wire, outbound send

**Target app**
- `target_app/app.py`
- `target_app/Dockerfile`
- `target_app/logs/access.log` *(runtime output; gitignored)*

**Infrastructure**
- `infra/docker-compose.yml`
- `infra/schema.sql`
- `infra/deploy_target_app_gcp.sh` — written, not executed

**Phase 0 hello-world agents**
- `a2a_hello/__init__.py`
- `a2a_hello/adk_sender/__init__.py`
- `a2a_hello/adk_sender/agent.py`
- `a2a_hello/adk_sender/server.py`
- `a2a_hello/crew_receiver/__init__.py`
- `a2a_hello/crew_receiver/server.py`

**Scripts**
- `scripts/verify_frameworks.py`
- `scripts/test_incident_store.py`
- `scripts/test_target_app.py`
- `scripts/test_a2a_hello.py`
- `scripts/start_all.ps1`

**Dependencies and config**
- `pyproject.toml`
- `requirements/adk.txt`, `requirements/adk.lock.txt`
- `requirements/crewai.txt`, `requirements/crewai.lock.txt`
- `requirements/target_app.txt`, `requirements/target_app.lock.txt`
- `.gitignore`, `.dockerignore`, `.env.example`

**Docs**
- `README.md`
- `docs/PHASE0_REPORT.md` *(this file)*
- `docs/CLOUD_SANDBOX.md`

---

## 3. Exit criteria

| Criterion | Status |
| --- | --- |
| ADK and CrewAI both run sample agents successfully | **PARTIAL** — both install, construct and wire up agents (verified). Neither was driven through a live model call: no API key. |
| Target app live on a cloud sandbox, real URL | **NOT MET** — runs locally and as a container; no cloud account exists. |
| Hitting endpoints produces consistent, readable log entries | **MET** — 16/16 checks; format locked and documented. |
| Incident store running, record written and read back | **MET** — all checks pass, including from a destroyed-and-rebuilt volume. |
| Shared A2A schema in a shared, reusable location | **MET** — `shared/schemas/`, imported by both agent processes. |
| Real A2A request/response between independent ADK and CrewAI processes | **MET** — 14/14, separate venvs, separate ports, real HTTP, confirmed in the receiver's own log. |

### Why the two unmet criteria could not be verified

**Cloud sandbox.** No credentials, and neither CLI is installed:

```
$ gcloud --version
bash: gcloud: command not found
$ aws --version
bash: aws: command not found
```

Creating a billable cloud account is your decision, not something to do on
your behalf. Everything up to the deploy is done: the image builds and runs,
and the deploy script is written.

**Live framework responses.** ADK needs `GOOGLE_API_KEY` or `GEMINI_API_KEY`;
CrewAI's `kickoff()` needs one of `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` /
`GEMINI_API_KEY` / `GOOGLE_API_KEY`. Without one, a sample agent fails on an
auth error, which says nothing about whether the install works. So the scripts
verify construction unconditionally and mark the live call `SKIPPED`, naming
the missing variable. Add a key and re-run `verify_frameworks.py` — the live
paths are already written.

---

## 4. Deviations from the Phase 0 instructions

1. **Three virtualenvs, not one.** The task says "a Python environment". ADK
   and CrewAI have large overlapping dependency trees and the project's
   architecture already says the systems share no codebase, so one resolved
   dependency set is a liability rather than a simplification. Each venv has
   its own pinned requirements and lock file.

2. **Postgres on host port 5433, not 5432.** Avoids colliding with a locally
   installed Postgres. Override with `INCIDENT_STORE_DSN`.

3. **Envelope has three fields beyond the required five.** `schema_version`,
   `correlation_id`, and `SystemName` as an enum rather than free text. All
   three are cheap now and expensive to retrofit once six systems depend on
   the shape. The five required fields are unchanged.

4. **The hello-world agents each expose a card and each can receive.** The
   task asks for the ADK agent to send and the CrewAI agent to receive. Making
   both full peers was no extra work and is what later phases need, since
   messages will flow in both directions.

5. **`/trigger` on the ADK process, instead of a one-shot send script.** The
   exchange has to be driven from outside both processes for the test to mean
   anything. An HTTP endpoint makes that reproducible with `curl` and keeps the
   ADK agent a long-running service rather than a script.

6. **The ADK tool is invoked directly when no model credential exists.** The
   ADK agent is a real `LlmAgent` owning a real `FunctionTool`, and
   `{"use_llm": true}` drives it through ADK's `Runner`. Without a credential
   the process calls the tool's function directly. The outbound network call
   is byte-for-byte identical either way — only the thing deciding to make it
   differs. Phase 0 is proving transport, and this keeps that provable with no
   API key.

7. **The CrewAI receiver builds a real Crew but skips `kickoff()` without a
   key.** Same reasoning. The reply says which happened
   (`crew_kickoff: "skipped"` and the reason) so a passing test never hides a
   missing credential.

8. **The hello-world agents touch the incident store.** Not asked for in task
   6. It is a few lines, it proves the store and the message bus actually join
   up on `incident_id`, and it is best-effort — a store outage degrades to a
   logged warning rather than making the A2A exchange look broken.

Nothing from Phase 1 was built: no detection logic, no severity
classification, no threat assessment, no real agent reasoning. The scaffold
agents acknowledge and echo, nothing more.

---

## 5. Outstanding — needed before Phase 1

**Blocking**

1. **An LLM API key.** `GOOGLE_API_KEY` covers both frameworks (CrewAI reaches
   Gemini through LiteLLM). Phase 1 is detection reasoning, which cannot be
   built or tested without a model. Put it in `.env` (gitignored; see
   `.env.example`).

**Blocking for the cloud exit criterion, not for Phase 1 logic**

2. **A cloud sandbox decision and account.** Recommendation: **GCP + Cloud
   Run** — it takes the existing image unchanged, has a usable free tier,
   gives a real HTTPS URL, and sends stdout to Cloud Logging, which is where
   Detection should read the access log from in the cloud. Needs: a billing-
   enabled account, a **throwaway** project (this app is deliberately
   insecure and will be attacked), and `gcloud` installed. Then
   `bash infra/deploy_target_app_gcp.sh`. Say so if you would rather use AWS
   and I will write the App Runner equivalent.

**Decisions worth making now, because they shape Phase 1**

3. **Where Detection reads the log from.** Three options: tail the local file,
   read the container's stdout, or query Cloud Logging. The app already writes
   both file and stdout, so all three stay open — but Phase 1 has to pick one,
   and the answer depends on whether the cloud deploy happens first.

4. **The `status` vocabulary.** Phase 0 leaves it free text as instructed.
   Phase 1 introduces real statuses; settling the allowed set then (and
   constraining the column) avoids six systems inventing their own spellings.

5. **Whether the incident store should move to the cloud with the app.** It is
   local Docker now, which the task permits. Once agents run anywhere but this
   machine they will all need to reach it.
