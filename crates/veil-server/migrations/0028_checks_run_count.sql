-- Count consecutive counted outcomes on each (project, snapshot, check) row so
-- `bisect` recounts confirmation runs from `checks.run_count` whenever it
-- advances (`docs/HUB.md` §13.36, BUG-1862).
ALTER TABLE checks ADD COLUMN IF NOT EXISTS run_count BIGINT NOT NULL DEFAULT 0;
UPDATE checks SET run_count = 1 WHERE run_count = 0 AND state IN ('pass', 'fail');
