-- Phase 6.2: visible in-progress LLM calls. Additive only: four nullable-or-defaulted columns on
-- reasoning_events (INTERNAL DEMO USE ONLY, unsanitized -- unchanged by this migration).
--   call_id      links a call's "started" row to its later "resolved"/"failed" update (NULL for the
--                older one-shot writes that never go through the two-step path)
--   status       'in_progress' | 'resolved' | 'failed' -- a live viewer sees 'in_progress' the moment
--                the call starts, before the model has answered
--   served_by    the model tag that actually answered (e.g. "gemini-flash-latest"), set only on resolve
--   resolved_at  when the call finished; NULL while in_progress
-- Existing rows (and any write that still uses the plain one-shot record_reasoning path) default to
-- status='resolved' with resolved_at = their own timestamp, so every pre-6.2 row reads the same as a
-- call that was "instantly" resolved -- no backfill needed, no row looks broken.

BEGIN;

ALTER TABLE reasoning_events ADD COLUMN IF NOT EXISTS call_id     TEXT;
ALTER TABLE reasoning_events ADD COLUMN IF NOT EXISTS status      TEXT NOT NULL DEFAULT 'resolved'
    CHECK (status IN ('in_progress', 'resolved', 'failed'));
ALTER TABLE reasoning_events ADD COLUMN IF NOT EXISTS served_by   TEXT;
ALTER TABLE reasoning_events ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ;

UPDATE reasoning_events SET resolved_at = "timestamp" WHERE resolved_at IS NULL AND status = 'resolved';

CREATE INDEX IF NOT EXISTS reasoning_events_call_id_idx ON reasoning_events (call_id) WHERE call_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS reasoning_events_inflight_idx ON reasoning_events (status) WHERE status = 'in_progress';

INSERT INTO schema_migrations (filename) VALUES ('006_phase62_live_calls.sql')
ON CONFLICT (filename) DO NOTHING;

COMMIT;
