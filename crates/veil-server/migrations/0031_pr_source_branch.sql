-- BUG-1885: the branch a PR's head was named by (its source branch), so that
-- landing the PR deletes the branch it merged. NULL: the head was named by a
-- snapshot or a change, and nothing is deleted.
ALTER TABLE prs ADD COLUMN IF NOT EXISTS source_branch TEXT;
