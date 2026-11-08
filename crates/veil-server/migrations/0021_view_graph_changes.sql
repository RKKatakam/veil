-- The viewer graph's change ids (S3, BUG-1317; crates/veil-server/src/query/graph.rs):
-- one row per (project, view key, change id, projected snapshot) of every
-- viewer graph row, with its flags, so that `q/resolve` answers a change id
-- prefix from the caller's own rows, in a bounded range of the key, and
-- never reads the real `graph` (hidden changes, old versions). A cache,
-- written with `view_graph` (first) by the same fills. A table of its own,
-- not an index on `view_graph`: on YugabyteDB an index built on an existing
-- table is an online schema change, which under the load of other
-- databases' work outlasts the statement timeout. Idempotent (IF NOT
-- EXISTS): YugabyteDB may apply DDL statement by statement.
--
-- Rows of `view_graph` written before this migration have no change ids.
-- The viewer graph is a cache (0010_view_graph.sql): it is emptied, and
-- filled again the first time a query needs it (`q/generations` and page
-- starts fill what they are asked about, BUG-1384). `TRUNCATE`, whose time
-- does not grow with the table, so the step finishes under the statement
-- timeout however large the graph (BUG-1383). (Migrations run under their
-- lock before servers start, so no row of this release is lost.)
CREATE TABLE IF NOT EXISTS view_changes (
    project_id BIGINT NOT NULL,
    view_key TEXT NOT NULL,
    change_id TEXT NOT NULL,
    snapshot TEXT NOT NULL,
    flags INT NOT NULL,
    PRIMARY KEY (project_id, view_key, change_id, snapshot)
);
TRUNCATE view_graph;
