-- Phase 4: customer-communications drafts and their human sign-off trail.
--
-- One row per drafted customer message. A draft is created PENDING_SIGNOFF and
-- can only reach PUBLISHED through a recorded human approval (the publish gate
-- in shared/guardrail.py reads approved_by from this row). SUPERSEDED marks an
-- unpublished draft that a newer one for the same incident replaced.
--
-- Safe to re-run. Applied to an existing volume by scripts/migrate_store.py;
-- a fresh volume gets the same end state directly from schema.sql.

BEGIN;

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

COMMIT;
