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

-- BUG-1941: the index a landing service chooses its batch through: a
-- branch's queued rows in the queue's order (reverts first, then by age). A
-- batch reads its first rows and stops (`limits::landing::pick_batch`).
--
-- Its first column is an expression (the project, of a queued row only), and
-- the batch's statement asks by that expression and names neither
-- `project_id` nor `state`. So no other index of the table answers the
-- statement, and the database reads the queue in its order through this one
-- whatever its statistics say. With plain columns (`landing_queue_ready`,
-- dropped here) it chose by its estimate of the queue's length: while its
-- statistics were behind a queue that had grown in seconds, it read every
-- waiting row through a smaller index and sorted them, for each batch. What
-- else read `landing_queue_ready` (a branch's `merging` rows) has
-- `landing_queue_state`.
CREATE INDEX IF NOT EXISTS landing_queue_pick
    ON landing_queue ((CASE WHEN state = 'queued' THEN project_id END), branch, priority DESC, created_at, seq);
DROP INDEX IF EXISTS landing_queue_ready;
