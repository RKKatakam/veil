-- Limits on the landing service (docs/HUB.md §13.32;
-- docs/design/server/phase-4-agent-scale.md §4.11): the session that
-- submitted a queue entry (its stored hash for an agent session, empty for a
-- person's own session), so that each agent session is bounded at 100
-- outstanding landings, each person at 1,000, and each batch takes a fair
-- share across people and across each person's sessions.
ALTER TABLE landing_queue ADD COLUMN IF NOT EXISTS session TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS landing_queue_queued_who
    ON landing_queue (project_id, person_id, session)
    WHERE state = 'queued';
