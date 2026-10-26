-- Phase 1: pin down the incident lifecycle vocabulary.
--
-- Phase 0 left `status` as free text with a lowercase 'detected' default,
-- which was correct for Phase 0 (the vocabulary was not settled yet). Phase 1
-- settles it, so the column gets a CHECK constraint and the two fields the
-- classification step needs.
--
-- Safe to re-run. Applied to an existing volume by scripts/migrate_store.py;
-- a fresh volume gets the same end state directly from schema.sql.

BEGIN;

-- 1. Normalise any Phase 0 rows before the constraint goes on, or the ALTER
--    fails on the old lowercase values.
UPDATE incidents SET status = upper(status);

-- Phase 0 scaffolding wrote statuses that are not in the Phase 1 vocabulary.
-- Map the one it used; anything else unrecognised becomes DETECTED, which is
-- the safest floor (it says "we know about this and nothing has assessed it").
UPDATE incidents SET status = 'CANDIDATE' WHERE status = 'ACK_RECEIVED';
UPDATE incidents
   SET status = 'DETECTED'
 WHERE status NOT IN ('DETECTED', 'CANDIDATE', 'ASSESSED', 'DISPATCHED', 'CONTAINED', 'RESOLVED');

-- 2. The fixed vocabulary.
ALTER TABLE incidents DROP CONSTRAINT IF EXISTS incidents_status_check;
ALTER TABLE incidents
  ADD CONSTRAINT incidents_status_check
  CHECK (status IN ('DETECTED', 'CANDIDATE', 'ASSESSED', 'DISPATCHED', 'CONTAINED', 'RESOLVED'));

ALTER TABLE incidents ALTER COLUMN status SET DEFAULT 'DETECTED';

-- 3. Severity shares the same treatment: nullable until Threat Assessment
--    sets it, but constrained to the four allowed labels once present.
ALTER TABLE incidents DROP CONSTRAINT IF EXISTS incidents_severity_check;
ALTER TABLE incidents
  ADD CONSTRAINT incidents_severity_check
  CHECK (severity IS NULL OR severity IN ('Low', 'Medium', 'High', 'Critical'));

-- 4. `escalated` is deliberately independent of `status`: Threat Assessment
--    can escalate at any point in the lifecycle without moving the incident
--    forwards or backwards.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS escalated BOOLEAN NOT NULL DEFAULT FALSE;

-- 5. The incident type label from the Severity Classification agent. Free
--    text on purpose -- the label set is the LLM's to propose in Phase 1, and
--    constraining it now would force a schema change every time a new attack
--    shape shows up.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS incident_type TEXT;

CREATE INDEX IF NOT EXISTS incidents_escalated_idx ON incidents (escalated) WHERE escalated;
CREATE INDEX IF NOT EXISTS incidents_severity_idx  ON incidents (severity);

COMMIT;
