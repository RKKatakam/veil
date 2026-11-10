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
    files TEXT NOT NULL,                   -- JSON list of the file changes risk reads (path, secret, executable, regular)
    -- The risk and its reasons are a cache (BUG-1424): `files` rated under
    -- the rules whose risk key (`Review::risk_key`) is `rules_key`; a view
    -- under other rules rates `files` again and replaces them.
    risk TEXT NOT NULL,
    reasons TEXT NOT NULL,                 -- JSON list: why the risk
    rules_key TEXT NOT NULL,
    files_count INT NOT NULL,
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
-- Pages of a thread's comments, oldest first, read by size before their
-- bodies (BUG-1258).
CREATE INDEX IF NOT EXISTS pr_comments_by_time ON pr_comments (project_id, pr, thread, at, id);

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

-- Each reviewer's latest verdict, read without its body (cycle 3).
CREATE INDEX IF NOT EXISTS pr_reviews_by_person ON pr_reviews (project_id, pr, person, at);

-- A request for changes (BUG-1278, BUG-1323, BUG-1326), attached to the
-- paths the PR had touched when it was given, whoever opened the PR: it
-- holds every PR touching one of them, until that reviewer approves that
-- same PR (its current patch, after the hold) or an admin dismisses it.
CREATE TABLE IF NOT EXISTS pr_holds (
    project_id BIGINT NOT NULL,
    person BIGINT NOT NULL,                -- the reviewer
    path TEXT NOT NULL,
    pr TEXT NOT NULL,                      -- the PR it was last given on
    at BIGINT NOT NULL,
    PRIMARY KEY (project_id, person, path)
);
CREATE INDEX IF NOT EXISTS pr_holds_by_path ON pr_holds (project_id, path);

-- The `[review]` rules in force on each project's default branch
-- (BUG-1279): a state recorded at each landing, in the landing's
-- transaction (`prs::record_landing`), for the tip it landed. `state` is
-- JSON: {"kind": "file", "text": …} | {"kind": "absent"} | {"kind": "strict"}.
CREATE TABLE IF NOT EXISTS pr_review_rules (
    project_id BIGINT PRIMARY KEY,
    checked TEXT NOT NULL,
    state TEXT NOT NULL
);
