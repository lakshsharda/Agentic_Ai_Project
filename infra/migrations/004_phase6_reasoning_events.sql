-- Phase 6: the live agent-reasoning feed.
--
-- One row per piece of reasoning text an agent produced (Detection's verdict, Threat
-- Assessment's rationale, Containment's plan, Forensics' root-cause narrative, ...).
--
-- This is deliberately a SEPARATE table from trace_events (Phase 5). trace_events is the
-- scrubbed, audit-grade record and must never contain an attacker IP, username or internal
-- host. reasoning_events is the opposite: INTERNAL DEMO USE ONLY, UNSANITIZED -- it holds the
-- real text the models wrote, including real IPs and usernames, because its whole purpose is
-- to show the reasoning is grounded in real data. Nothing writes one table's content into the
-- other, and the two have separate writers (shared/trace.py, shared/reasoning.py).
--
-- Like trace_events it is logging, never control flow: nothing reads it to decide anything and a
-- failed write never blocks or alters the action it describes. incident_id is not a foreign key,
-- so a row survives its incident being deleted.
--
-- Safe to re-run. Applied by scripts/migrate_store.py; a fresh install gets the same end state
-- from schema.sql.

BEGIN;

CREATE TABLE IF NOT EXISTS reasoning_events (
    event_id        BIGSERIAL   PRIMARY KEY,
    incident_id     TEXT,
    "timestamp"     TIMESTAMPTZ NOT NULL DEFAULT now(),
    system          TEXT        NOT NULL,
    agent_name      TEXT        NOT NULL,
    reasoning_text  TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS reasoning_events_incident_idx ON reasoning_events (incident_id, "timestamp", event_id);
CREATE INDEX IF NOT EXISTS reasoning_events_time_idx     ON reasoning_events ("timestamp" DESC, event_id DESC);

INSERT INTO schema_migrations (filename) VALUES ('004_phase6_reasoning_events.sql')
ON CONFLICT (filename) DO NOTHING;

COMMIT;
