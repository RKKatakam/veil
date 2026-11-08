-- The viewer graph (milestone S13; crates/veil-server/src/query/graph.rs):
-- the commit graph of each viewer's projected history, one row per
-- (project, view key, projected snapshot). A cache, a function of the
-- projected snapshots alone: rows are written parents first, and written
-- again identically after a crash (no foreign keys). Idempotent
-- (IF NOT EXISTS): YugabyteDB may apply DDL statement by statement. Keyed
-- by project first, so it shards by project.
--
-- `parents` and `skip` are JSON lists of snapshot ids (the jump table:
-- the first parent, then the first-parent ancestors at the multiples of
-- 16, 256 and 4096 just below); `down_id` is the nearest snapshot below on
-- the first-parent line without exactly one parent; `real_id` a real
-- snapshot it projects. Nothing here names a path or holds content.
CREATE TABLE IF NOT EXISTS view_graph (
    project_id BIGINT NOT NULL,
    view_key TEXT NOT NULL,
    snapshot TEXT NOT NULL,
    generation BIGINT NOT NULL,
    depth BIGINT NOT NULL,
    parents TEXT NOT NULL,
    flags INT NOT NULL,
    skip TEXT NOT NULL,
    down_id TEXT NOT NULL,
    real_id TEXT NOT NULL,
    PRIMARY KEY (project_id, view_key, snapshot)
);
-- Who fills a view key's graph now (BUG-1073): a lease, taken with one
-- statement and given back with another, so that no database connection is
-- held while a fill runs. A lease past `expires_at` (milliseconds since the
-- epoch; renewed while its fill runs) may be taken over.
CREATE TABLE IF NOT EXISTS view_fills (
    project_id BIGINT NOT NULL,
    view_key TEXT NOT NULL,
    holder TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (project_id, view_key)
);
-- Log cursors wider than a request may carry (BUG-1076): what is left of
-- a log to walk, kept under the hash of what it names and the viewer's
-- key (the same frontier is one row). Bounded: a row lives an hour from
-- its last writing (`created_at`, milliseconds since the epoch), and each
-- write drops the project's expired rows and its oldest past a byte cap.
CREATE TABLE IF NOT EXISTS log_cursors (
    project_id BIGINT NOT NULL,
    view_key TEXT NOT NULL,
    id TEXT NOT NULL,
    frontier TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (project_id, view_key, id)
);
