-- Person-to-person secret shares (docs/HUB.md §13.13). One row per (path,
-- sharer, recipient): the latest signed version (ciphertext only: the
-- server cannot open it) and, in plain text for the admins' audit, who
-- shared which path with whom and when. A share the sharer ends keeps its
-- row (the audit) without its body. Idempotent (IF NOT EXISTS): YugabyteDB
-- may apply DDL statement by statement.
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
CREATE INDEX IF NOT EXISTS secret_shares_by_recipient ON secret_shares (project_id, recipient_id);
CREATE INDEX IF NOT EXISTS secret_shares_by_sharer ON secret_shares (project_id, sharer_id);
