-- Phase 6.1: narration layer for the live reasoning feed. Additive only: three nullable-or-defaulted
-- columns on reasoning_events (INTERNAL DEMO USE ONLY, unsanitized -- unchanged by this migration).
--   narration  one plain-English line derived from data the writer already had (no extra LLM call)
--   caused_by  agent_name of the entry that directly caused this one (NULL for the chain's root)
--   depth      0 for the root; +1 per causal hop, so the viewer can indent the story
-- Rows written before this migration keep NULL narration; the viewer falls back to a generic line.

BEGIN;

ALTER TABLE reasoning_events ADD COLUMN IF NOT EXISTS narration TEXT;
ALTER TABLE reasoning_events ADD COLUMN IF NOT EXISTS caused_by TEXT;
ALTER TABLE reasoning_events ADD COLUMN IF NOT EXISTS depth     INTEGER NOT NULL DEFAULT 0;

INSERT INTO schema_migrations (filename) VALUES ('005_phase61_reasoning_narration.sql')
ON CONFLICT (filename) DO NOTHING;

COMMIT;
