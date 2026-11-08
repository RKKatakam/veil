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
-- Kept blames (S14 cycle 3): the encoded blame (`veil-derived blame 2`,
-- at most 64 + 128 bytes a line of its version and 768 a change its lines
-- name: what an answer shows of each) of the version a snapshot
-- of a viewer's graph introduced at a path, with or without following
-- renames; `bytes` its size, `created_at` when written (milliseconds):
-- a project keeps at most 256 MiB of them, its oldest dropped first.
CREATE TABLE IF NOT EXISTS blame_memo (
    project_id BIGINT NOT NULL,
    view_key TEXT NOT NULL,
    path_key TEXT NOT NULL,
    follow BOOLEAN NOT NULL,
    snapshot TEXT NOT NULL,
    body BYTEA NOT NULL,
    bytes BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    path_keys TEXT NOT NULL,
    PRIMARY KEY (project_id, view_key, path_key, follow, snapshot)
);
-- The paths kept blames name, once per project, by key (`path_keys` above:
-- the keys a kept blame names, comma-separated, read with it).
CREATE TABLE IF NOT EXISTS blame_paths (
    project_id BIGINT NOT NULL,
    path_key TEXT NOT NULL,
    path TEXT NOT NULL,
    PRIMARY KEY (project_id, path_key)
);
-- Who runs the blame job of a version now (one server at a time): a
-- lease, taken, renewed and given back by single statements, as
-- `view_fills`; past `expires_at` (milliseconds) it may be taken over.
CREATE TABLE IF NOT EXISTS blame_jobs (
    project_id BIGINT NOT NULL,
    view_key TEXT NOT NULL,
    path_key TEXT NOT NULL,
    follow BOOLEAN NOT NULL,
    snapshot TEXT NOT NULL,
    holder TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (project_id, view_key, path_key, follow, snapshot)
);
-- Blames found too wide (BUG-1309): the job passed a memory bound of
-- `held` bytes, so a request under a bound no larger answers `too_wide`
-- from this row instead of walking again. A version's history below it
-- never changes, and a change of access is a new view key. At most
-- 4,096 rows a view key (its oldest dropped).
CREATE TABLE IF NOT EXISTS blame_ends (
    project_id BIGINT NOT NULL,
    view_key TEXT NOT NULL,
    path_key TEXT NOT NULL,
    follow BOOLEAN NOT NULL,
    snapshot TEXT NOT NULL,
    held BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (project_id, view_key, path_key, follow, snapshot)
);
-- Which viewer-graph rows have their file history (S14 writes it before
-- the row, and sets `files`; an S13 server, which may still run beside S14
-- servers in a rolling restart, writes graph rows only and never sets it).
-- A row without it is not read as present: S14 fills it again and marks
-- it (BUG-1210). Adding a nullable column rewrites no rows (BUG-1211).
ALTER TABLE view_graph ADD COLUMN IF NOT EXISTS files BOOLEAN;
