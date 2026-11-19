-- Shard person-wide access epochs by `person_id` instead of storing every
-- person under `access_epochs (project_id = 0, person_id)`, which concentrates
-- 100% of person-epoch reads onto the single `hash(0)` tablet on YugabyteDB.
--
-- Rolling-upgrade safe:
--   1. Create `person_epochs` (hash-sharded by `person_id` on YugabyteDB).
--   2. Update `veil_bump_epoch(p, q)` so `p = 0` writes `person_epochs` and
--      dual-writes `access_epochs (0, q)` with the same new epoch so servers
--      from before this migration still observe every person-epoch bump.
--   3. Backfill `person_epochs` from existing `access_epochs (0, person_id)`
--      rows with `ON CONFLICT DO NOTHING` so bumps written after step 2 win.
--
-- Idempotent (IF NOT EXISTS, OR REPLACE, ON CONFLICT DO NOTHING).

CREATE TABLE IF NOT EXISTS person_epochs (
    person_id  BIGINT PRIMARY KEY,
    epoch      BIGINT NOT NULL DEFAULT 0,
    changed_at BIGINT NOT NULL DEFAULT 0
);

CREATE OR REPLACE FUNCTION veil_bump_epoch(p BIGINT, q BIGINT) RETURNS VOID AS $$
DECLARE
    -- The first 64 bits of a random UUID: 60 random bits (4 name its version).
    e BIGINT := ('x' || substr(replace(gen_random_uuid()::text, '-', ''), 1, 16))::bit(64)::bigint;
    now_ms BIGINT := (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
BEGIN
    IF e = 0 THEN
        e := 1;
    END IF;
    IF p = 0 THEN
        INSERT INTO person_epochs (person_id, epoch, changed_at)
        VALUES (q, e, now_ms)
        ON CONFLICT (person_id) DO UPDATE
            -- Drawing the previous value again (one chance in 2^60) must still
            -- change it, and never to 0.
            SET epoch = CASE WHEN person_epochs.epoch = EXCLUDED.epoch THEN (CASE WHEN EXCLUDED.epoch = 1 THEN 2 ELSE 1 END)
                             ELSE EXCLUDED.epoch END,
                changed_at = EXCLUDED.changed_at
        RETURNING epoch INTO e;
        -- Rolling-upgrade dual-write: keep `access_epochs (0, q)` in sync for
        -- older servers still reading it until rollout completes.
        INSERT INTO access_epochs (project_id, person_id, epoch, changed_at)
        VALUES (0, q, e, now_ms)
        ON CONFLICT (project_id, person_id) DO UPDATE
            SET epoch = EXCLUDED.epoch,
                changed_at = EXCLUDED.changed_at;
    ELSE
        INSERT INTO access_epochs (project_id, person_id, epoch, changed_at)
        VALUES (p, q, e, now_ms)
        ON CONFLICT (project_id, person_id) DO UPDATE
            SET epoch = CASE WHEN access_epochs.epoch = EXCLUDED.epoch THEN (CASE WHEN EXCLUDED.epoch = 1 THEN 2 ELSE 1 END)
                             ELSE EXCLUDED.epoch END,
                changed_at = EXCLUDED.changed_at;
    END IF;
END
$$ LANGUAGE plpgsql;

INSERT INTO person_epochs (person_id, epoch, changed_at)
SELECT person_id, epoch, changed_at
FROM access_epochs
WHERE project_id = 0 AND person_id > 0
ON CONFLICT (person_id) DO NOTHING;
