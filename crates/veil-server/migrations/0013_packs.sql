-- Packs (S28, docs/HUB.md §13.20): the storage objects that hold many
-- objects of a project. One row per pack a transaction listed (`listed`:
-- its objects are the project's) or discarded (not `listed`: a refused
-- push's upload, deleted from storage after this row). The primary key
-- decides between the two: whichever row is written first stays. A pack an
-- upload wrote has no row until then (staged: read by nobody but the push
-- that names it). Idempotent (IF NOT EXISTS): YugabyteDB may apply DDL
-- statement by statement. Queries are by project: the primary key's prefix
-- serves them.
CREATE TABLE IF NOT EXISTS packs (
    project_id BIGINT NOT NULL REFERENCES projects(id),
    name TEXT NOT NULL,
    size BIGINT NOT NULL,
    objects BIGINT NOT NULL,
    listed BOOLEAN NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (project_id, name)
);
