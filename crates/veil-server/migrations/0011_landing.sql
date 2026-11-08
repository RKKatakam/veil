-- The landing service (docs/HUB.md §13.15; docs/design/server/phase-4-agent-scale.md
-- §4.1, §4.2, §5.2): the queue of submitted landings, and the lease that lets
-- one landing service at a time move a branch.
--
-- A queue row is one submitted stack of changes (oldest first), already
-- checked as a push is: its real snapshots are committed history from the
-- submit on (`snapshots` rows), so they resolve and project like any other.
-- The edits of each change are not stored: they are its diff against its
-- first parent, read from the objects (objects are authority).
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
    -- ids; `landing::Entry`).
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
-- What retention reads (`Service::clean`: the project's rows finished an
-- hour ago), so a pass with nothing to delete reads nothing.
CREATE INDEX IF NOT EXISTS landing_queue_old ON landing_queue (project_id, done_at);
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

-- What landed on a branch, within its lineage then: each change of a landed
-- stack (`submitted`: its edits are on the branch, for every viewer) with
-- the snapshot it landed as (`landed`: on the branch), and each tip a batch
-- moved from (as itself). A later stack skips a change landed already and
-- reads on below it (BUG-1103, BUG-1270, BUG-1311), and a submit finds its
-- base here in one lookup (BUG-1275). Deleted after an hour, in bounded
-- chunks also while the branch is busy (BUG-1303).
CREATE TABLE IF NOT EXISTS landings (
    project_id BIGINT NOT NULL REFERENCES projects(id),
    branch TEXT NOT NULL,
    lineage BIGINT NOT NULL,
    submitted TEXT NOT NULL,
    landed TEXT NOT NULL,
    at BIGINT NOT NULL,
    PRIMARY KEY (project_id, branch, lineage, submitted)
);
CREATE INDEX IF NOT EXISTS landings_at ON landings (project_id, at);
-- Is a snapshot one the service landed on a branch?
CREATE INDEX IF NOT EXISTS landings_landed ON landings (project_id, branch, lineage, landed);

-- The real snapshots of one view's projected id (`landing::Ancestry::
-- below_hidden`: a run of changes hidden from a submitter stepped over in
-- one statement; `sync::resolve_newest`: a branch tip, or the newest, among
-- them), by one index range.
CREATE INDEX IF NOT EXISTS projections_by_view ON projections (project_id, view_key, projected_id);

-- What each landing was made from (BUG-1465, BUG-1466): one row for each
-- snapshot the landing service landed (as `snapshots`, never deleted), the
-- submitted snapshot it was made from as `source`. "Already landed" asks
-- whether one of a change's rows names a snapshot on the branch, in one
-- statement whose condition is the change itself, nothing cut before it.
CREATE TABLE IF NOT EXISTS landed_from (
    project_id BIGINT NOT NULL REFERENCES projects(id),
    source TEXT NOT NULL,
    landed TEXT NOT NULL,
    PRIMARY KEY (project_id, source, landed)
);
-- A memo of a change hidden from its view (BUG-1468): it collapsed into its
-- parent's projection. Of one view's real snapshots with one projected id,
-- the one not collapsed is the change of that view's history they all
-- stand for: a run of hidden changes is stepped over by reading that one
-- row (`projections_own`), however long the run. Rows written before this
-- column count as collapsed (the step then reads the run itself, bounded).
ALTER TABLE projections ADD COLUMN IF NOT EXISTS collapsed BOOLEAN NOT NULL DEFAULT TRUE;
CREATE INDEX IF NOT EXISTS projections_own ON projections (project_id, view_key, projected_id) WHERE NOT collapsed;
