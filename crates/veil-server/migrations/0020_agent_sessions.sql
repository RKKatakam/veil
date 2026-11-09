-- Agent sessions (docs/HUB.md §13.27; phase 2 §5.6): a session made from a
-- person's own session (`parent_hash`), for one project, maybe narrowed to
-- some paths (`agent_only`, a JSON array), carrying the attribution the
-- server stamps on its commits through the API (`agent`, JSON). Ordinary
-- sessions leave all four NULL. Idempotent, as every migration.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS agent TEXT;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS agent_project BIGINT;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS agent_only TEXT;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS parent_hash TEXT;
