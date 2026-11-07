-- Derived history data (docs/design/server/phase-3-server-history.md §3.1,
-- §4.2; milestone S12). A cache: every row is a function of immutable
-- snapshots and the accepted policy, recomputed identically after a crash
-- (no foreign keys: inserts stay one write each on YugabyteDB).
-- Idempotent (IF NOT EXISTS): YugabyteDB may apply DDL statement by
-- statement. Keyed by project first, so it shards by project.
--
-- The commit graph: one row per derived snapshot. `skip` holds the
-- first-parent jump table (JSON: the first parent, then the first-parent
-- ancestors at the depths just below the multiples of 16, 256 and 4096
-- under this one's). `changed` is written last: the changed-paths object's
-- id, or 'many' / 'none'; NULL while the snapshot's other values are not
-- derived yet.
CREATE TABLE IF NOT EXISTS graph (
    project_id BIGINT NOT NULL,
    snapshot TEXT NOT NULL,
    generation BIGINT NOT NULL,
    depth BIGINT NOT NULL,
    parents TEXT NOT NULL,
    change_id TEXT NOT NULL,
    flags INT NOT NULL,
    skip TEXT NOT NULL,
    changed TEXT,
    PRIMARY KEY (project_id, snapshot)
);
CREATE INDEX IF NOT EXISTS graph_by_change ON graph (project_id, change_id);
-- Per-path file history: every snapshot that changed a path against its
-- first parent, by first-parent depth. `path_key` is a hash of the path;
-- '*' rows are the snapshots that changed too many paths to list.
CREATE TABLE IF NOT EXISTS file_history (
    project_id BIGINT NOT NULL,
    path_key TEXT NOT NULL,
    depth BIGINT NOT NULL,
    snapshot TEXT NOT NULL,
    PRIMARY KEY (project_id, path_key, depth, snapshot)
);
-- Per-rule history lists (§3.4): for each access line, the snapshots that
-- changed a path it decides. `line_key` names the set of paths a line
-- decides (its path and the rule paths below it), so a line whose paths a
-- new policy leaves alone keeps its list.
CREATE TABLE IF NOT EXISTS rule_history (
    project_id BIGINT NOT NULL,
    line_key TEXT NOT NULL,
    generation BIGINT NOT NULL,
    snapshot TEXT NOT NULL,
    PRIMARY KEY (project_id, line_key, generation, snapshot)
);
-- The lists kept for the current accepted policy; `ready` once every
-- derived snapshot is on them (a new policy's lists are built first).
CREATE TABLE IF NOT EXISTS rule_lines (
    project_id BIGINT NOT NULL,
    line_key TEXT NOT NULL,
    ready BOOLEAN NOT NULL,
    PRIMARY KEY (project_id, line_key)
);
-- How far each index is derived on each branch.
CREATE TABLE IF NOT EXISTS derive_progress (
    project_id BIGINT NOT NULL,
    index_name TEXT NOT NULL,
    index_version INT NOT NULL,
    branch TEXT NOT NULL,
    through_snapshot TEXT NOT NULL,
    PRIMARY KEY (project_id, index_name, index_version, branch)
);
