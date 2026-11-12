-- BUG-1940: a person's and an agent session's bounds on queued landings
-- (docs/HUB.md §13.32) without a lock that makes one person's submits wait
-- for one another. Each waiting landing holds one of its person's slots
-- (0 to the person's bound) and, from an agent session, one of the
-- session's (0 to the session's bound). The unique indexes are the bound: a
-- submit takes a free slot of each, and two submits that take the same one
-- are decided by the index, across every server on the database. A row
-- leaves both indexes when it is no longer waiting, which frees its slots.
-- NULL (rows from before, and the server's own reverts) takes no slot.
-- Idempotent (IF NOT EXISTS).
ALTER TABLE landing_queue ADD COLUMN IF NOT EXISTS person_slot INT;
ALTER TABLE landing_queue ADD COLUMN IF NOT EXISTS session_slot INT;
CREATE UNIQUE INDEX IF NOT EXISTS landing_queue_person_slot
    ON landing_queue (project_id, person_id, person_slot)
    WHERE state IN ('queued', 'merging');
CREATE UNIQUE INDEX IF NOT EXISTS landing_queue_session_slot
    ON landing_queue (project_id, person_id, session, session_slot)
    WHERE state IN ('queued', 'merging');
-- What the count of a person's waiting landings read: the two above have
-- the same leading columns.
DROP INDEX IF EXISTS landing_queue_queued_who;
