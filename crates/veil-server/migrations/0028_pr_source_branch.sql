-- BUG-1885: remember the source branch a PR was opened or updated from so
-- landing the PR can clean up the merged branch automatically.
ALTER TABLE prs ADD COLUMN IF NOT EXISTS source_branch TEXT;
