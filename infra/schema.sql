-- Shared incident-state store schema.
--
-- One row per incident. Every one of the six agent systems reads and writes
-- this table over the network; none of them share application code.
--
-- This file is the full, current schema and runs only on a FRESH volume (via
-- docker-entrypoint-initdb.d). Changes to an existing volume go through
-- infra/migrations/ as well -- keep the two in step, or a developer who
-- rebuilds their volume ends up with a different schema from one who migrates.

CREATE TABLE IF NOT EXISTS incidents (
    incident_id   TEXT PRIMARY KEY,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Fixed lifecycle vocabulary, settled before Phase 1. Mirrors
    -- shared.schemas.IncidentStatus; the constraint stops six independent
    -- systems inventing their own spellings.
    status        TEXT        NOT NULL DEFAULT 'DETECTED'
                  CHECK (status IN ('DETECTED', 'CANDIDATE', 'ASSESSED',
                                    'DISPATCHED', 'CONTAINED', 'RESOLVED')),

    -- Null until Threat Assessment classifies the incident.
    severity      TEXT        CHECK (severity IS NULL OR severity IN
                                    ('Low', 'Medium', 'High', 'Critical')),

    -- Deliberately independent of `status`: Threat Assessment can escalate at
    -- any point in the lifecycle without moving the incident forwards or back.
    escalated     BOOLEAN     NOT NULL DEFAULT FALSE,

    -- The type label the classification agent proposes ("credential stuffing",
    -- "brute force", ...). Free text on purpose -- constraining it would force
    -- a schema change every time a new attack shape appears.
    incident_type TEXT,

    raw_payload   JSONB       NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS incidents_status_idx     ON incidents (status);
CREATE INDEX IF NOT EXISTS incidents_created_at_idx ON incidents (created_at DESC);
CREATE INDEX IF NOT EXISTS incidents_severity_idx   ON incidents (severity);
CREATE INDEX IF NOT EXISTS incidents_escalated_idx  ON incidents (escalated) WHERE escalated;

-- Keep updated_at honest without every system having to remember to set it.
CREATE OR REPLACE FUNCTION incidents_touch_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS incidents_touch_updated_at ON incidents;
CREATE TRIGGER incidents_touch_updated_at
    BEFORE UPDATE ON incidents
    FOR EACH ROW EXECUTE FUNCTION incidents_touch_updated_at();

-- Phase 4: customer-communications drafts (folded in from
-- migrations/002_phase4_comms_drafts.sql so a fresh volume matches a migrated one).
CREATE TABLE IF NOT EXISTS comms_drafts (
    draft_id          TEXT        PRIMARY KEY,
    incident_id       TEXT        NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    event_type        TEXT        NOT NULL
                      CHECK (event_type IN ('contained', 'reclassified', 'resolved')),
    severity_at_draft TEXT,
    draft_text        TEXT        NOT NULL DEFAULT '',
    status            TEXT        NOT NULL DEFAULT 'PENDING_SIGNOFF'
                      CHECK (status IN ('PENDING_SIGNOFF', 'APPROVED', 'REJECTED', 'PUBLISHED', 'SUPERSEDED')),
    approved_by       TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at        TIMESTAMPTZ,
    published_at      TIMESTAMPTZ,
    publish_channel   TEXT,
    sent              BOOLEAN,

    -- Why a draft was REJECTED (validator violations, or a human's reason).
    rejection_reason  TEXT,
    -- How the text was produced: llm | llm_retry | template_fallback.
    generation        TEXT,
    -- The text before a human edit, when one happened.
    original_text     TEXT,
    edited_by_human   BOOLEAN     NOT NULL DEFAULT FALSE,
    -- The impact label the Impact Assessment agent produced for this draft.
    impact            TEXT,
    superseded_by     TEXT
);

CREATE INDEX IF NOT EXISTS comms_drafts_incident_idx ON comms_drafts (incident_id, created_at);
CREATE INDEX IF NOT EXISTS comms_drafts_pending_idx  ON comms_drafts (status) WHERE status = 'PENDING_SIGNOFF';

-- Phase 5: unified trace log (see infra/migrations/003_phase5_trace_log.sql).
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

-- Phase 6: live agent-reasoning feed. INTERNAL DEMO USE ONLY, UNSANITIZED -- a separate table from the
-- scrubbed trace_events on purpose (see infra/migrations/004_phase6_reasoning_events.sql).
CREATE TABLE IF NOT EXISTS reasoning_events (
    event_id        BIGSERIAL   PRIMARY KEY,
    incident_id     TEXT,
    "timestamp"     TIMESTAMPTZ NOT NULL DEFAULT now(),
    system          TEXT        NOT NULL,
    agent_name      TEXT        NOT NULL,
    reasoning_text  TEXT        NOT NULL DEFAULT '',
    -- Phase 6.1 narration layer (infra/migrations/005_phase61_reasoning_narration.sql)
    narration       TEXT,
    caused_by       TEXT,
    depth           INTEGER     NOT NULL DEFAULT 0,
    -- Phase 6.2 in-progress calls (infra/migrations/006_phase62_live_calls.sql)
    call_id         TEXT,
    status          TEXT        NOT NULL DEFAULT 'resolved'
                    CHECK (status IN ('in_progress', 'resolved', 'failed')),
    served_by       TEXT,
    resolved_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS reasoning_events_incident_idx ON reasoning_events (incident_id, "timestamp", event_id);
CREATE INDEX IF NOT EXISTS reasoning_events_time_idx     ON reasoning_events ("timestamp" DESC, event_id DESC);
CREATE INDEX IF NOT EXISTS reasoning_events_call_id_idx  ON reasoning_events (call_id) WHERE call_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS reasoning_events_inflight_idx ON reasoning_events (status) WHERE status = 'in_progress';

-- Migration bookkeeping, so scripts/migrate_store.py sees a fresh volume as
-- already carrying every migration folded into this file.
CREATE TABLE IF NOT EXISTS schema_migrations (
    filename    TEXT PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO schema_migrations (filename) VALUES
    ('001_phase1_status_vocabulary.sql'),
    ('002_phase4_comms_drafts.sql'),
    ('003_phase5_trace_log.sql'),
    ('004_phase6_reasoning_events.sql'),
    ('005_phase61_reasoning_narration.sql'),
    ('006_phase62_live_calls.sql')
ON CONFLICT (filename) DO NOTHING;
