-- The landing service (docs/HUB.md §13.15; docs/design/server/phase-4-agent-scale.md
-- §4.1, §4.2, §5.2): the queue of submitted landings, and the lease that lets
-- one landing service at a time move a branch.
--
-- A queue row is one submitted stack of changes (oldest first), already
-- checked as a push is: its real snapshots are committed history from the
-- submit on (`snapshots` rows), so they resolve and project like any other.
-- The edit set of each change is not stored: it is the diff of its snapshot
-- against its first parent, read from the objects (objects are authority).
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
    -- JSON list of the real submitted snapshots, oldest first.
    stack TEXT NOT NULL,
    -- The access epochs the submit's checks ran under (person, project):
    -- while both are unchanged, those checks still hold.
    person_epoch BIGINT NOT NULL,
    project_epoch BIGINT NOT NULL,
    -- queued | landed | conflict | rejected
    state TEXT NOT NULL,
    -- JSON: the outcome, with the real snapshots it landed (each answer is
    -- projected for its asker). Finished rows are deleted after a day.
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

-- Where each submitted snapshot of a landed stack is on the branch: itself
-- (landed as it was), or the snapshot it was made again as on a newer tip.
-- A later stack on a submitted snapshot does not land its change twice
-- (BUG-1103, BUG-1270). Kept as long as finished queue rows (a day): a push
-- on a submitted snapshot older than that is answered `conflict` for the
-- change it repeats, never landed over.
CREATE TABLE IF NOT EXISTS landings (
    project_id BIGINT NOT NULL REFERENCES projects(id),
    submitted TEXT NOT NULL,
    landed TEXT NOT NULL,
    at BIGINT NOT NULL,
    PRIMARY KEY (project_id, submitted)
);
CREATE INDEX IF NOT EXISTS landings_at ON landings (project_id, at);
