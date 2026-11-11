-- BUG-1884: record the reverted culprit's change_id on `bisect_reverts` so
-- S20 and S21 guard against revert-of-revert and repeated-revert loops.
-- Idempotent (IF NOT EXISTS).
ALTER TABLE bisect_reverts ADD COLUMN IF NOT EXISTS culprit_change_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS bisect_reverts_change_id
    ON bisect_reverts (project_id, culprit_change_id)
    WHERE state = 'reverted';
CREATE INDEX IF NOT EXISTS bisect_reverts_revert_snapshot
    ON bisect_reverts (project_id, branch, revert_snapshot)
    WHERE revert_snapshot IS NOT NULL;
