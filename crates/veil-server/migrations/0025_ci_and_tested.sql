-- CI through the API and `main@tested` (docs/HUB.md §13.35;
-- docs/design/server/phase-4-agent-scale.md §4.6, §4.7, §5.2):
--
-- * `sessions.agent_runner`: a CI runner session reads only what its grant
--   allows and writes only check results (never pushes, creates changes or
--   lands).
-- * `checks`: one row per (project, real snapshot, check name), carrying the
--   paths the runner's session could read (`session_paths`, JSON array;
--   `admin_only` when an unnarrowed admin posted it) so a result is shown
--   only to readers who can see every path the job could read. Bounded per
--   tip and per runner.
-- * `tested`: one row per (project, branch), recording the newest snapshot on
--   the branch (within its `lineage`, ordered by first-parent `depth` from
--   the root) whose required checks all passed. Moves only forward.
-- Idempotent (IF NOT EXISTS).
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS agent_runner BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS checks (
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    snapshot TEXT NOT NULL,
    name TEXT NOT NULL,
    state TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    url TEXT,
    log TEXT,
    runner_id BIGINT NOT NULL REFERENCES people(id),
    runner_name TEXT NOT NULL,
    session_paths TEXT NOT NULL DEFAULT '[]',
    admin_only BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (project_id, snapshot, name)
);
CREATE INDEX IF NOT EXISTS checks_by_runner ON checks (project_id, runner_id, updated_at, snapshot, name);

CREATE TABLE IF NOT EXISTS tested (
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    branch TEXT NOT NULL,
    lineage BIGINT NOT NULL,
    snapshot TEXT NOT NULL,
    depth BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (project_id, branch)
);
