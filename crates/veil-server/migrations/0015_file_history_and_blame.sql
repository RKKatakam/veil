-- File history and blame per viewer (milestone S14;
-- crates/veil-server/src/query/files.rs). Caches, functions of each
-- viewer's projected history alone; no foreign keys; idempotent (IF NOT
-- EXISTS: YugabyteDB may apply DDL statement by statement). Keyed by
-- project first, so they shard by project.
--
-- One row per path a snapshot of a viewer's graph changed against its
-- first parent, as their projected trees show it (`path_key`: a hash of
-- the path). `change` is JSON: the old and new entries, and per parent the
-- depth and id of the snapshot that last changed the path along that
-- parent's first parents. Written by the fill of the viewer's graph,
-- before the graph rows.
CREATE TABLE IF NOT EXISTS view_file_history (
    project_id BIGINT NOT NULL,
    view_key TEXT NOT NULL,
    path_key TEXT NOT NULL,
    depth BIGINT NOT NULL,
    snapshot TEXT NOT NULL,
    change TEXT NOT NULL,
    PRIMARY KEY (project_id, view_key, path_key, depth, snapshot)
);
-- Kept blames: the object (`veil-derived blame 1`, addressed by its hash)
-- holding the blame of the version a snapshot of a viewer's graph
-- introduced at a path, with or without following renames.
CREATE TABLE IF NOT EXISTS blame_memo (
    project_id BIGINT NOT NULL,
    view_key TEXT NOT NULL,
    path_key TEXT NOT NULL,
    follow BOOLEAN NOT NULL,
    snapshot TEXT NOT NULL,
    object TEXT NOT NULL,
    PRIMARY KEY (project_id, view_key, path_key, follow, snapshot)
);
-- Viewer graphs filled before this migration have no file history: drop
-- them (a cache), so the next landing or query fills them again with it.
DELETE FROM view_graph;
