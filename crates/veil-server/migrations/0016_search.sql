-- The search index (milestone S15; crates/veil-server/src/search/index.rs).
-- A cache, a function of the branches' trees, the history and the accepted
-- policy: dropped, it is built again. Idempotent (IF NOT EXISTS): YugabyteDB
-- may apply DDL statement by statement. Keyed by project first, so it
-- shards by project. No foreign keys (one write per row on YugabyteDB).
--
-- A head says what an index covers: `code` per branch (the tip indexed),
-- `names` once per project (branch ''), `walk` per branch (the tip whose
-- history the names index holds). `lines` is the identity of the accepted
-- policy's lines it was built under; `version` is bumped by every write, so
-- that a write compares and swaps it, in the same transaction as its shards.
CREATE TABLE IF NOT EXISTS search_heads (
    project_id BIGINT NOT NULL,
    kind TEXT NOT NULL,
    branch TEXT NOT NULL,
    snapshot TEXT NOT NULL,
    lines TEXT NOT NULL,
    version BIGINT NOT NULL,
    PRIMARY KEY (project_id, kind, branch)
);
-- One row per shard: an index's documents decided by one access line
-- (`line_key`, S12's keys). `segments` is a JSON list of the segment
-- objects ([{id, bytes}], oldest first) in the project's object space;
-- the counts are of live documents (`text_docs`, `text_bytes`: plain files
-- of at most 1 MiB), and `dead` the documents replaced or deleted that a
-- segment still holds. Nothing here holds content; paths are inside the
-- segments only.
CREATE TABLE IF NOT EXISTS search_shards (
    project_id BIGINT NOT NULL,
    kind TEXT NOT NULL,
    branch TEXT NOT NULL,
    line_key TEXT NOT NULL,
    segments TEXT NOT NULL,
    docs BIGINT NOT NULL,
    text_docs BIGINT NOT NULL,
    text_bytes BIGINT NOT NULL,
    dead BIGINT NOT NULL,
    PRIMARY KEY (project_id, kind, branch, line_key)
);
