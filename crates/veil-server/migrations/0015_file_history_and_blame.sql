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
-- Walks down to the versions a blame starts from that stopped before
-- they got there (BUG-1212, BUG-1215): from a version (snapshot and path),
-- the versions it had not expanded yet (`frontier`, JSON) and those it had,
-- with what blaming them needs (`expanded`, JSON). Requests go on below
-- them, and blame the expanded versions from this record once the
-- frontier is done; no walk from a recorded version is made again.
CREATE TABLE IF NOT EXISTS blame_walks (
    project_id BIGINT NOT NULL,
    view_key TEXT NOT NULL,
    path_key TEXT NOT NULL,
    follow BOOLEAN NOT NULL,
    snapshot TEXT NOT NULL,
    frontier TEXT NOT NULL,
    expanded TEXT NOT NULL,
    PRIMARY KEY (project_id, view_key, path_key, follow, snapshot)
);
-- Which viewer-graph rows have their file history (S14 writes it before
-- the row, and sets `files`; an S13 server, which may still run beside S14
-- servers in a rolling restart, writes graph rows only and never sets it).
-- A row without it is not read as present: S14 fills it again and marks
-- it (BUG-1210). Adding a nullable column rewrites no rows (BUG-1211).
ALTER TABLE view_graph ADD COLUMN IF NOT EXISTS files BOOLEAN;
