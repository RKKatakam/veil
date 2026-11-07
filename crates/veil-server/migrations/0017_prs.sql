-- PRs and review (S21, docs/HUB.md §13.24; phase-4 design §4.9, §5.2).
-- Everything here is plain text behind the server's checks: titles,
-- bodies, threads and reviews are never encrypted (docs/VISIBILITY.md).
-- Idempotent, like every migration (YugabyteDB applies DDL statement by
-- statement).

-- A visibility class: the access lines deciding the paths a PR touches
-- (sorted JSON list of their paths; "" for a path no line decides, which
-- only admins read), under one set of access lines (`policy_key`, a hash
-- of the lines' paths in order), plus an embargo (S23; '' for none).
CREATE TABLE IF NOT EXISTS pr_classes (
    project_id BIGINT NOT NULL,
    class_id TEXT NOT NULL,
    policy_key TEXT NOT NULL,
    lines TEXT NOT NULL,
    embargo TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (project_id, class_id)
);
CREATE INDEX IF NOT EXISTS pr_classes_by_policy ON pr_classes (project_id, policy_key);

CREATE TABLE IF NOT EXISTS prs (
    project_id BIGINT NOT NULL,
    id TEXT NOT NULL,                      -- short random id: pr-xxxxxxxx
    class_id TEXT NOT NULL,
    policy_key TEXT NOT NULL,              -- the access lines class_id was computed under
    target TEXT NOT NULL,
    author BIGINT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    state TEXT NOT NULL,                   -- open | closed | landed
    revision INT NOT NULL,                 -- the current revision
    risk TEXT NOT NULL,                    -- the current revision's
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (project_id, id)
);
-- Lists are newest first by creation, which nothing hidden can change.
CREATE INDEX IF NOT EXISTS prs_by_class ON prs (project_id, class_id, state, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS prs_by_policy ON prs (project_id, policy_key);

-- Every path any revision of a PR touched (files, and folders that differ
-- with nothing differing below them): its visibility class is computed from
-- these, again whenever the access lines change.
CREATE TABLE IF NOT EXISTS pr_paths (
    project_id BIGINT NOT NULL,
    pr TEXT NOT NULL,
    path TEXT NOT NULL,
    PRIMARY KEY (project_id, pr, path)
);

CREATE TABLE IF NOT EXISTS pr_revisions (
    project_id BIGINT NOT NULL,
    pr TEXT NOT NULL,
    n INT NOT NULL,
    base TEXT NOT NULL,                    -- real snapshot ids
    head TEXT NOT NULL,
    changes TEXT NOT NULL,                 -- JSON [{change, snapshot, parent}], bottom first
    patch TEXT NOT NULL,                   -- hash of every file change of the stack
    risk TEXT NOT NULL,
    reasons TEXT NOT NULL,                 -- JSON list: why the risk
    files INT NOT NULL,
    pushed_by BIGINT NOT NULL,
    at BIGINT NOT NULL,
    PRIMARY KEY (project_id, pr, n)
);

CREATE TABLE IF NOT EXISTS pr_threads (
    project_id BIGINT NOT NULL,
    pr TEXT NOT NULL,
    id TEXT NOT NULL,
    anchor TEXT,                           -- JSON, as written; NULL: on the PR as a whole
    now_at TEXT,                           -- JSON {revision, start, end} on the current revision; NULL: outdated
    state TEXT NOT NULL,                   -- open | resolved
    author BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (project_id, pr, id)
);

CREATE TABLE IF NOT EXISTS pr_comments (
    project_id BIGINT NOT NULL,
    pr TEXT NOT NULL,
    thread TEXT NOT NULL,
    id TEXT NOT NULL,
    author BIGINT NOT NULL,
    body TEXT NOT NULL,
    at BIGINT NOT NULL,
    PRIMARY KEY (project_id, pr, thread, id)
);

-- A person's verdict on one revision (the latest they gave), bound to its
-- patch, with the device signature (over project, PR, patch, verdict).
CREATE TABLE IF NOT EXISTS pr_reviews (
    project_id BIGINT NOT NULL,
    pr TEXT NOT NULL,
    revision INT NOT NULL,                 -- the (real) revision it was given on
    person BIGINT NOT NULL,
    verdict TEXT NOT NULL,                 -- approve | request-changes
    patch TEXT NOT NULL,
    agent BOOLEAN NOT NULL,                -- given by an agent session (S11; none yet)
    device TEXT NOT NULL,
    signature TEXT NOT NULL,
    body TEXT NOT NULL,
    at BIGINT NOT NULL,
    PRIMARY KEY (project_id, pr, revision, person)
);
