-- Person-to-person secret shares (docs/HUB.md §13.14). One row per (path,
-- sharer, recipient): the latest signed version (ciphertext only: the
-- server cannot open it) and, in plain text for the admins' audit, who
-- shared which path with whom and when. A share the sharer ends keeps its
-- row (the audit) without its body. Idempotent (IF NOT EXISTS): YugabyteDB
-- may apply DDL statement by statement. Every query is by project: the
-- primary key's prefix serves them, so there is no other index (each one is
-- a tablet more per database on YugabyteDB).
CREATE TABLE IF NOT EXISTS secret_shares (
    project_id BIGINT NOT NULL REFERENCES projects(id),
    path TEXT NOT NULL,
    sharer_id BIGINT NOT NULL REFERENCES people(id),
    recipient_id BIGINT NOT NULL REFERENCES people(id),
    version BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    unshared_at BIGINT,
    body TEXT,
    PRIMARY KEY (project_id, path, sharer_id, recipient_id)
);
-- How many shares each person has made in a project (at most
-- secret_share::MAX_SHARES_PER_SHARER): a new share reserves one in the
-- same transaction as its insert, so requests sent together never pass the
-- limit (BUG-1061).
CREATE TABLE IF NOT EXISTS secret_share_quota (
    project_id BIGINT NOT NULL REFERENCES projects(id),
    sharer_id BIGINT NOT NULL REFERENCES people(id),
    used BIGINT NOT NULL,
    PRIMARY KEY (project_id, sharer_id)
);
