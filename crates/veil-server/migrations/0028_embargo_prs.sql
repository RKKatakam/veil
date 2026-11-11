-- S23: embargoed PRs (docs/HUB.md §13.38; phase-4 design §4.9, decision 8).
-- Embargoed PRs are server-enforced permission classes (`pr_classes.embargo`)
-- that become ordinary PRs (or land via S17) at release; nothing is encrypted.
-- Idempotent for YugabyteDB statement-by-statement execution.

ALTER TABLE prs
    ADD COLUMN IF NOT EXISTS embargo TEXT NOT NULL DEFAULT '';

ALTER TABLE prs
    ADD COLUMN IF NOT EXISTS land_at_release BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS prs_by_embargo
    ON prs (project_id, embargo)
    WHERE embargo <> '';

ALTER TABLE embargo_lines
    ADD COLUMN IF NOT EXISTS has_pr BOOLEAN NOT NULL DEFAULT FALSE;

-- Requests for changes on an unreleased embargoed PR hold PRs in that same
-- embargo without touching public `pr_holds`, so outsiders' public PRs never
-- observe an embargoed hold before release; promoted into `pr_holds` when the
-- embargo releases onto an open PR.
CREATE TABLE IF NOT EXISTS pr_embargo_holds (
    project_id BIGINT NOT NULL,
    embargo TEXT NOT NULL,
    person BIGINT NOT NULL,
    path TEXT NOT NULL,
    pr TEXT NOT NULL,
    at BIGINT NOT NULL,
    PRIMARY KEY (project_id, embargo, person, path)
);

CREATE INDEX IF NOT EXISTS pr_embargo_holds_by_path
    ON pr_embargo_holds (project_id, embargo, path);
