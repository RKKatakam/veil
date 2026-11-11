-- BUG-1885: the branch a PR's head was named by (its source branch), so that
-- landing the PR deletes the branch it merged. NULL: the head was named by a
-- snapshot or a change, and nothing is deleted. (28 is S23's, on another line
-- of work: migrations need not be consecutive.)
ALTER TABLE prs ADD COLUMN IF NOT EXISTS source_branch TEXT;
