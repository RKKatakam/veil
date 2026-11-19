-- Shard person-wide access epochs by `person_id` instead of storing every
-- person under `access_epochs (project_id = 0, person_id)`, which concentrates
-- 100% of person-epoch reads onto the single `hash(0)` tablet on YugabyteDB.
--
-- Rolling-upgrade safe across PostgreSQL and YugabyteDB (BUG-2922):
--   Step 1 (committed transaction):
--     1. Create `person_epochs` (hash-sharded by `person_id` on YugabyteDB).
--     2. Install `AFTER INSERT OR UPDATE ON access_epochs` trigger
--        `veil_access_epochs_mirror_person` for `project_id = 0 AND person_id > 0`
--        that upserts `(person_id, epoch, changed_at)` into `person_epochs`.
--        Because `CREATE TRIGGER` takes `SHARE ROW EXCLUSIVE` on `access_epochs`
--        on PostgreSQL (and bumps+waits the cluster catalog version on
--        YugabyteDB), every pre-0045 revocation that already wrote
--        `access_epochs` commits before Step 1 commits, and every revocation
--        that writes `access_epochs` after Step 1 commits fires the mirror
--        trigger and updates `person_epochs` in the same lock order
--        (`access_epochs` -> `person_epochs`).
--   Step 2 (separate committed transaction, after Step 1 commits):
--     3. Backfill `person_epochs` from `access_epochs (0, person_id)` with
--        `ON CONFLICT (person_id) DO NOTHING`. Because Step 2's snapshot starts
--        after Step 1 commits, it observes every pre-Step-1 revocation; any
--        revocation committing after Step 1 either writes `person_epochs` first
--        (preserved by `ON CONFLICT DO NOTHING`) or waits on Step 2's row lock
--        and overwrites the backfilled value via `ON CONFLICT DO UPDATE`.
--
-- Idempotent (IF NOT EXISTS, OR REPLACE, DROP TRIGGER IF EXISTS, ON CONFLICT).

CREATE TABLE IF NOT EXISTS person_epochs (
    person_id  BIGINT PRIMARY KEY,
    epoch      BIGINT NOT NULL DEFAULT 0,
    changed_at BIGINT NOT NULL DEFAULT 0
);

CREATE OR REPLACE FUNCTION veil_mirror_person_epoch() RETURNS trigger AS $$
BEGIN
    INSERT INTO person_epochs (person_id, epoch, changed_at)
    VALUES (NEW.person_id, NEW.epoch, NEW.changed_at)
    ON CONFLICT (person_id) DO UPDATE
        SET epoch = EXCLUDED.epoch,
            changed_at = EXCLUDED.changed_at;
    RETURN NULL;
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS veil_access_epochs_mirror_person ON access_epochs;
CREATE TRIGGER veil_access_epochs_mirror_person
    AFTER INSERT OR UPDATE ON access_epochs
    FOR EACH ROW
    WHEN (NEW.project_id = 0 AND NEW.person_id > 0)
    EXECUTE FUNCTION veil_mirror_person_epoch();

-- veil: step

INSERT INTO person_epochs (person_id, epoch, changed_at)
SELECT person_id, epoch, changed_at
FROM access_epochs
WHERE project_id = 0 AND person_id > 0
ON CONFLICT (person_id) DO NOTHING;
