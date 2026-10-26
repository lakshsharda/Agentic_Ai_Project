-- Phase 5: unified, timestamped trace of what every system did and decided.
--
-- One row per observable moment: an A2A message sent/received, an authority
-- check (allowed or denied), a gate evaluation, a status move, a draft, a
-- sign-off, a publish. Written by shared/trace.py from all six systems; read by
-- the dashboard. This is LOGGING, not control flow: nothing reads it to decide
-- anything, and a failed write never blocks or alters the action it describes.
--
-- incident_id is deliberately NOT a foreign key: a denied call may name an
-- incident that does not exist (or no incident at all), and a trace row must
-- survive an incident being deleted.
--
-- event_type is free text; the vocabulary in use is documented in shared/trace.py.
-- summary and detail never carry attacker IPs, usernames or internal hosts
-- (shared/trace.py scrubs them on the way in, the same rule as the Phase 4
-- customer-text validator).
--
-- Safe to re-run. Applied to an existing database by scripts/migrate_store.py;
-- a fresh install gets the same end state from schema.sql.

BEGIN;

CREATE TABLE IF NOT EXISTS trace_events (
    event_id     BIGSERIAL   PRIMARY KEY,
    incident_id  TEXT,
    "timestamp"  TIMESTAMPTZ NOT NULL DEFAULT now(),
    from_system  TEXT        NOT NULL,
    to_system    TEXT,
    event_type   TEXT        NOT NULL,
    decision     TEXT        NOT NULL DEFAULT 'n/a'
                 CHECK (decision IN ('auto', 'human', 'timeout_escalation', 'blocked', 'n/a')),
    summary      TEXT        NOT NULL DEFAULT '',
    detail       JSONB       NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS trace_events_incident_idx ON trace_events (incident_id, "timestamp", event_id);
CREATE INDEX IF NOT EXISTS trace_events_time_idx     ON trace_events ("timestamp" DESC, event_id DESC);

INSERT INTO schema_migrations (filename) VALUES ('003_phase5_trace_log.sql')
ON CONFLICT (filename) DO NOTHING;

COMMIT;
