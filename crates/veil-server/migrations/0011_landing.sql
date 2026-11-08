-- The landing service (docs/HUB.md §13.15; docs/design/server/phase-4-agent-scale.md
-- §4.1, §4.2, §5.2): the queue of submitted landings, and the lease that lets
-- one landing service at a time move a branch.
--
-- A queue row is one submitted stack of changes (oldest first), already
-- checked as a push is: its real snapshots are committed history from the
-- submit on (`snapshots` rows), so they resolve and project like any other.
-- The edits of each change are not stored: they are its diff against its
-- base, read from the objects (objects are authority), on the submitter's
-- projected trees when something they cannot see lies between.
-- Idempotent (IF NOT EXISTS): YugabyteDB may apply DDL statement by
-- statement.
CREATE TABLE IF NOT EXISTS landing_queue (
    project_id BIGINT NOT NULL REFERENCES projects(id),
    branch TEXT NOT NULL,
    seq BIGSERIAL,
    -- Random, shown only to the submitter.
    ticket TEXT NOT NULL,
    person_id BIGINT NOT NULL REFERENCES people(id),
    -- Who submitted, as the request was signed in: a later re-check of their
    -- access opens the project as them.
    person_name TEXT NOT NULL,
    device_key TEXT NOT NULL,
    -- JSON list of the stack's changes, oldest first: [snapshot, base] (real
    -- ids), or [snapshot, base, projected tree, projected base tree,
    -- "whole" | "part"] when the submitter's edits are those of their view
    -- (`landing::Entry`).
    stack TEXT NOT NULL,
    -- The branch's lineage the stack was judged under: it lands only under
    -- that one (BUG-1300).
    lineage BIGINT NOT NULL,
    -- The access epochs the submit's checks ran under (person, project):
    -- while both are unchanged, those checks still hold.
    person_epoch BIGINT NOT NULL,
    project_epoch BIGINT NOT NULL,
    -- queued | landed | conflict | rejected
    state TEXT NOT NULL,
    -- JSON: the outcome, with the real snapshots it landed (each answer is
    -- projected for its asker). Finished rows are deleted after an hour.
    result TEXT,
    -- Microseconds, on the database's clock: the queue's order (`seq` is
    -- not in commit order across connections on YugabyteDB, whose
    -- sequences are cached per connection).
    created_at BIGINT NOT NULL,
    done_at BIGINT,
    PRIMARY KEY (project_id, branch, seq)
);
CREATE UNIQUE INDEX IF NOT EXISTS landing_queue_ticket ON landing_queue (ticket);
CREATE INDEX IF NOT EXISTS landing_queue_ready ON landing_queue (project_id, branch, state, created_at, seq);
-- What a branch's poller reads (`landing::poll`: the rows finished since it
-- last looked).
CREATE INDEX IF NOT EXISTS landing_queue_done ON landing_queue (project_id, branch, done_at);
-- What a starting server resumes (`landing::resume`: every queued row).
CREATE INDEX IF NOT EXISTS landing_queue_state ON landing_queue (state, project_id, branch);

-- One row per branch some landing service has moved. `epoch` is the fencing
-- token: bumped at every takeover, and checked in the transaction that moves
-- the branch, so a holder that lost its lease can never move it.
CREATE TABLE IF NOT EXISTS landing_leases (
    project_id BIGINT NOT NULL REFERENCES projects(id),
    branch TEXT NOT NULL,
    holder TEXT NOT NULL,
    epoch BIGINT NOT NULL,
    -- Milliseconds, on the database's clock (servers' clocks never decide).
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (project_id, branch)
);

-- A branch's lineage (BUG-1300): a new value at every creation (the
-- default), forced update and deletion (a branch made again starts a new
-- one); fast-forward moves keep it. What the landing service records about
-- a branch counts only within its current lineage.
CREATE SEQUENCE IF NOT EXISTS branch_lineages;
ALTER TABLE branches ADD COLUMN IF NOT EXISTS lineage BIGINT NOT NULL DEFAULT 0;
ALTER TABLE branches ALTER COLUMN lineage SET DEFAULT nextval('branch_lineages');

-- Where each change of a landed stack is on the branch (the snapshot it was
-- made again as on the tip), and each tip a batch moved from (as itself),
-- within the branch's lineage then. A later stack on a submitted snapshot
-- does not land its change twice (BUG-1103, BUG-1270), and a submit finds
-- its base here in one lookup (BUG-1275). `whole`: all of the change's own
-- edits landed; else only what `view_key`'s view showed of it. Deleted
-- after an hour, in bounded chunks also while the branch is busy
-- (BUG-1303).
CREATE TABLE IF NOT EXISTS landings (
    project_id BIGINT NOT NULL REFERENCES projects(id),
    branch TEXT NOT NULL,
    lineage BIGINT NOT NULL,
    submitted TEXT NOT NULL,
    landed TEXT NOT NULL,
    whole BOOLEAN NOT NULL,
    view_key TEXT NOT NULL,
    at BIGINT NOT NULL,
    PRIMARY KEY (project_id, branch, lineage, submitted)
);
CREATE INDEX IF NOT EXISTS landings_at ON landings (project_id, at);
-- Is a snapshot one the service landed on a branch?
CREATE INDEX IF NOT EXISTS landings_landed ON landings (project_id, branch, lineage, landed);
