-- Automatic bisect and revert (milestone S20; docs/HUB.md §13.36;
-- docs/design/server/phase-4-agent-scale.md §4.7, §4.10, §5.2):
--
-- * `landing_queue.priority`: `0` for normal landings, `1` for automatic
--   reverts so a confirmed culprit's revert lands in the priority lane ahead
--   of ordinary submissions.
-- * `bisect_leases`: one row per (project, branch), fencing bisect across
--   multiple servers and restarts (`epoch` bumped at takeover).
-- * `bisects`: at most one active bisect per (project, branch) (plus finished
--   history rows), tracking the known-good base (`good`), the failing upper
--   bound (`bad`), the required check (`check_name`) and its runner visibility
--   footprint (`session_paths`, `admin_only`), the narrowed candidate list
--   (`candidates` JSON), the current search/confirmation state (`phase`, `lo`,
--   `hi`, `probes` JSON, `culprit`, `culprit_fails`, `parent_passes`), and
--   the revert ticket (`revert_ticket`) so a revert lands at most once.
-- Idempotent (IF NOT EXISTS).
ALTER TABLE landing_queue ADD COLUMN IF NOT EXISTS priority INT NOT NULL DEFAULT 0;
DROP INDEX IF EXISTS landing_queue_ready;
CREATE INDEX IF NOT EXISTS landing_queue_ready ON landing_queue (project_id, branch, state, priority DESC, created_at, seq);

CREATE TABLE IF NOT EXISTS bisect_leases (
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    branch TEXT NOT NULL,
    holder TEXT NOT NULL,
    epoch BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (project_id, branch)
);

CREATE TABLE IF NOT EXISTS bisects (
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    branch TEXT NOT NULL,
    lineage BIGINT NOT NULL,
    check_name TEXT NOT NULL,
    good TEXT NOT NULL,
    bad TEXT NOT NULL,
    candidates TEXT NOT NULL,
    lo INT NOT NULL,
    hi INT NOT NULL,
    -- searching | confirming | reverted | conflict | flaky | unconfirmed
    phase TEXT NOT NULL,
    -- JSON array of probe snapshots currently awaiting check results
    probes TEXT NOT NULL DEFAULT '[]',
    culprit TEXT,
    culprit_parent TEXT,
    culprit_fails INT NOT NULL DEFAULT 0,
    parent_passes INT NOT NULL DEFAULT 0,
    -- Timestamp (ms) of the last confirmation check request, so only a fresh
    -- check report counts toward confirmation.
    confirm_requested_at BIGINT NOT NULL DEFAULT 0,
    session_paths TEXT NOT NULL DEFAULT '[]',
    admin_only BOOLEAN NOT NULL DEFAULT FALSE,
    revert_ticket TEXT,
    revert_snapshot TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (project_id, branch)
);

CREATE TABLE IF NOT EXISTS bisect_reverts (
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    branch TEXT NOT NULL,
    lineage BIGINT NOT NULL,
    culprit TEXT NOT NULL,
    check_name TEXT NOT NULL,
    ticket TEXT NOT NULL,
    revert_snapshot TEXT,
    state TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (project_id, branch, lineage, culprit)
);
