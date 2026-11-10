-- S22: embargoes through the server, hidden embargo lines, and scheduled release.
--
-- Embargoes are server-enforced visibility boundaries that lift at a deadline.
-- Nothing is encrypted; the server holds the real history on a hidden branch
-- `embargo/<id>` (`hidden_for_embargo = <id>`) visible only to members of the
-- embargo's groups (and project admins), and lands it onto `target_branch`
-- through the landing service once `until_ms` arrives (or when released early).

ALTER TABLE branches
    ADD COLUMN hidden_for_embargo TEXT;

CREATE INDEX branches_hidden_embargo
    ON branches (project_id, hidden_for_embargo)
    WHERE hidden_for_embargo IS NOT NULL;

CREATE TABLE embargo_lines (
    project_id      BIGINT  NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    embargo_id      TEXT    NOT NULL,
    group_names     TEXT[]  NOT NULL,
    target_branch   TEXT    NOT NULL,
    embargo_branch  TEXT    NOT NULL,
    until_ms        BIGINT,
    released_at     BIGINT,
    record_json     TEXT    NOT NULL,
    created_by      TEXT    NOT NULL,
    created_at      BIGINT  NOT NULL,
    PRIMARY KEY (project_id, embargo_id)
);

CREATE INDEX embargo_lines_due
    ON embargo_lines (until_ms)
    WHERE released_at IS NULL AND until_ms IS NOT NULL;

CREATE TABLE embargo_snapshots (
    project_id  BIGINT  NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    snapshot    TEXT    NOT NULL,
    embargo_id  TEXT    NOT NULL,
    PRIMARY KEY (project_id, snapshot)
);

CREATE INDEX embargo_snapshots_by_embargo
    ON embargo_snapshots (project_id, embargo_id);
