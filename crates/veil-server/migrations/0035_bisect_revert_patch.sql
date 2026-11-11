-- BUG-1921: record what the reverted culprit's edits were (their identity
-- whatever change id carries them) on `bisect_reverts`, so "reverted twice"
-- counts the same edits made again as a new change.
-- Idempotent (IF NOT EXISTS). Rows from before have '' and count by change
-- id only.
ALTER TABLE bisect_reverts ADD COLUMN IF NOT EXISTS culprit_patch TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS bisect_reverts_patch
    ON bisect_reverts (project_id, culprit_patch)
    WHERE state = 'reverted';
