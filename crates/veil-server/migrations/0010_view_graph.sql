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
