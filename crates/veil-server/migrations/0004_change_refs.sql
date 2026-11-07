-- Commits through the API (docs/HUB.md §13.13): each change made through
-- `POST /v1/projects/{p}/changes` is kept on a change ref, its newest
-- revision's (real) snapshot, whether or not a branch moved to it. Only
-- its creator makes new revisions of it.
-- Idempotent (IF NOT EXISTS): YugabyteDB may apply DDL statement by
-- statement.
CREATE TABLE IF NOT EXISTS change_refs (
    project_id BIGINT NOT NULL REFERENCES projects(id),
    change_id TEXT NOT NULL,
    snapshot TEXT NOT NULL,
    created_by BIGINT NOT NULL REFERENCES people(id),
    created_at BIGINT NOT NULL,
    PRIMARY KEY (project_id, change_id)
);
