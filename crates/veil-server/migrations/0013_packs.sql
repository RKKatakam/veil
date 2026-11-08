-- Packs (S28, docs/HUB.md §13.20): the storage objects that hold many
-- objects of a project. One row per pack, written before its storage
-- object (an upload's) or in the transaction that lists it (a push's own),
-- so the database names every pack in storage:
--   state 0 staged: an upload's pack, its uploader in person_id; read by
--     nobody but that person's push or API commit that names it;
--   state 1 listed: its objects are the project's;
--   state 2 discarded: refused, its storage object deleted after the row.
-- A staged row turns listed or discarded once (the row is locked by the
-- update that changes it). Idempotent (IF NOT EXISTS): YugabyteDB may apply
-- DDL statement by statement. Queries are by project: the primary key's
-- prefix serves them.
CREATE TABLE IF NOT EXISTS packs (
    project_id BIGINT NOT NULL REFERENCES projects(id),
    name TEXT NOT NULL,
    state SMALLINT NOT NULL,
    person_id BIGINT REFERENCES people(id),
    size BIGINT NOT NULL,
    objects BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (project_id, name)
);
