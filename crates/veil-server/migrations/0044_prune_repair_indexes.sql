-- Prune unused/redundant indexes and repair global hot-spot indexes on
-- landed_changes, projections, and landing_queue
-- (docs/design/server/yugabyte-scaling.md P4).
--
-- All index changes run in the online section (outside the transaction,
-- db::ONLINE_INDEXES) so rolling upgrades never block writers on PostgreSQL
-- or miss concurrent writes on YugabyteDB. New indexes are created before
-- the old ones they replace are dropped.

-- veil: online indexes (outside the transaction, `db::ONLINE_INDEXES`: on a table servers already write)

-- 1. landed_changes: drop unused secondary index (all lookups use the PK
--    (project_id, branch, lineage, change_id, author)).
DROP INDEX CONCURRENTLY IF EXISTS landed_changes_by_author;

-- 2. projections (4 -> 2 secondary indexes):
--    - projections_by_projected is a redundant prefix of projections_by_projected_at.
--    - projections_by_view_v2 covers both projections_by_view and projections_own
--      (and includes real_id for index-only scans ordered by real_id).
CREATE INDEX CONCURRENTLY IF NOT EXISTS projections_by_view_v2
    ON projections (project_id, view_key, projected_id, collapsed, real_id);
DROP INDEX CONCURRENTLY IF EXISTS projections_by_projected;
DROP INDEX CONCURRENTLY IF EXISTS projections_by_view;
DROP INDEX CONCURRENTLY IF EXISTS projections_own;

-- 3. landing_queue (8 -> 5 secondary indexes):
--    - landing_queue_queued replaces both landing_queue_pick (which wrote NULL
--      for every finished row, creating a global hot tablet on YB) and
--      landing_queue_ready.
--    - landing_queue_active_state replaces landing_queue_state (which hashed
--      every finished 'landed' row onto one tablet on YB).
--    - landing_queue_finished replaces both landing_queue_done and
--      landing_queue_old; enqueue (done_at IS NULL) writes 0 entries to it.
--    - landing_queue_project_ticket replaces globally hashed landing_queue_ticket
--      so ticket lookups and inserts stay project-sharded.
CREATE INDEX CONCURRENTLY IF NOT EXISTS landing_queue_queued
    ON landing_queue ((CASE WHEN state = 'queued' THEN project_id END), branch, priority DESC, created_at, seq)
    WHERE state = 'queued';
CREATE INDEX CONCURRENTLY IF NOT EXISTS landing_queue_active_state
    ON landing_queue (state, project_id, branch)
    WHERE state IN ('queued', 'merging');
CREATE INDEX CONCURRENTLY IF NOT EXISTS landing_queue_finished
    ON landing_queue (project_id, done_at, branch)
    WHERE done_at IS NOT NULL;
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS landing_queue_project_ticket
    ON landing_queue (project_id, ticket);

DROP INDEX CONCURRENTLY IF EXISTS landing_queue_pick;
DROP INDEX CONCURRENTLY IF EXISTS landing_queue_ready;
DROP INDEX CONCURRENTLY IF EXISTS landing_queue_state;
DROP INDEX CONCURRENTLY IF EXISTS landing_queue_done;
DROP INDEX CONCURRENTLY IF EXISTS landing_queue_old;
DROP INDEX CONCURRENTLY IF EXISTS landing_queue_ticket;
