-- veil: yugabyte-only
-- Single-repository scaling (Q4): rebuild the hottest per-branch and
-- per-change tables with composite hash primary keys (and matching hash-keyed
-- secondary indexes) on YugabyteDB so concurrent pushes, landings, and pulls
-- on different branches of the SAME repository spread across all nodes instead
-- of hashing by project_id alone onto one tablet.
--
-- PostgreSQL skips this migration via the `-- veil: yugabyte-only` runner
-- marker (`db::YUGABYTE_ONLY`) and records it as applied.
--
-- Rebuilt tables (11):
--   1. branches       PRIMARY KEY ((project_id, name) HASH)
--                     + branches_by_project (project_id HASH, name ASC)
--                       (keeps per-project scans like GET /tips bounded;
--                        skipped on steady-state UPDATE target)
--                     + branches_hidden_embargo (project_id HASH, hidden_for_embargo ASC)
--   2. snapshots      PRIMARY KEY ((project_id, id) HASH)
--   3. origins        PRIMARY KEY ((project_id, real_id) HASH)
--   4. projections    PRIMARY KEY ((project_id, view_key, real_id) HASH)
--                     + projections_by_view_v2 ((project_id, view_key, projected_id) HASH, ...)
--                     + projections_by_projected_at ((project_id, projected_id) HASH, created_at DESC)
--   5. landed_changes PRIMARY KEY ((project_id, branch) HASH, lineage ASC, change_id ASC, author ASC)
--   6. landing_queue  PRIMARY KEY ((project_id, branch) HASH, seq ASC)
--                     + landing_queue_ticket UNIQUE (ticket HASH)
--                     + landing_queue_queued (((CASE ...), branch) HASH, priority DESC, created_at ASC, seq ASC)
--                     + landing_queue_person_slot UNIQUE ((project_id, person_id) HASH, person_slot ASC)
--                     + landing_queue_session_slot UNIQUE ((project_id, person_id, session) HASH, session_slot ASC)
--                     + landing_queue_active_state ((project_id, branch) HASH, state ASC)
--                     + landing_queue_finished (project_id HASH, done_at ASC, branch ASC) INCLUDE (seq, state) WHERE done_at IS NOT NULL
--   7. landings       PRIMARY KEY ((project_id, branch) HASH, lineage ASC, submitted ASC)
--                     + landings_at (project_id HASH, at ASC) INCLUDE (branch, lineage, submitted)
--                     + landings_landed ((project_id, branch) HASH, lineage ASC, landed ASC)
--   8. landing_leases PRIMARY KEY ((project_id, branch) HASH)
--   9. packs          PRIMARY KEY ((project_id, name) HASH)
--                     + packs_listed (project_id HASH, created_at ASC, name ASC) INCLUDE (size, objects)
--                     + packs_unlisted (project_id HASH) INCLUDE (name, state, person_id, created_at, discarded_at) WHERE state <> 1
--  10. change_refs    PRIMARY KEY ((project_id, change_id) HASH)
--  11. access_epochs  PRIMARY KEY ((project_id, person_id) HASH)
--                     (spreads `(0, person_id)` global person epoch rows across
--                      all tablets without a dual-written `person_epochs` table;
--                      every query is an exact `(project_id, person_id)` point lookup, BUG-2930)
--
-- audit_log keeps PRIMARY KEY (id) (id HASH on YB, synchronous in-tx per P9)
-- so audit writes already spread across all nodes for both multi-project and
-- single-repo workloads; hot sequence caches are raised to 1000.
--
-- Each table rebuild uses 3 separate `-- veil: step` blocks so DDL and DML
-- never share a YugabyteDB transaction (where DDL commits immediately while
-- DML aborts/rolls back on catalog conflict), and is gated offline on any
-- existing hash-sharded YugabyteDB database (any database that already had
-- migrations recorded before this migrate run took the lock; fresh databases
-- created from scratch run it automatically; BUG-2920, BUG-2931):
--   1. If `<t>` exists and lacks the new PK, `DROP TABLE IF EXISTS <t>_q4`
--      (wiping any stale staging table left by an interrupted prior attempt)
--      and create a fresh empty `<t>_q4` with its indexes.
--   2. Copy all rows from `<t>` into fresh `<t>_q4` (standalone DML tx —
--      committed durably before any DROP).
--   3. Verify `count(<t>_q4) = count(<t>)`, detach any owned sequence, DROP
--      `<t>`, rename `<t>_q4` -> `<t>` and its indexes, re-attach sequence.
-- After all steps finish, `db::migrate_once` verifies every secondary index on
-- the rebuilt tables is live, ready, valid, and passes `yb_index_check`.

-- 1. branches
DO $q4$
BEGIN
  IF to_regclass('branches') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM pg_index i
    WHERE i.indrelid = to_regclass('branches') AND i.indisprimary
      AND pg_get_indexdef(i.indexrelid) LIKE '%(project_id, name) HASH%'
  ) THEN
    DROP TABLE IF EXISTS branches_q4;
    CREATE TABLE IF NOT EXISTS branches_q4 (
      project_id         BIGINT  NOT NULL,
      name               TEXT    NOT NULL,
      target             TEXT    NOT NULL,
      lineage            BIGINT  NOT NULL DEFAULT nextval('branch_lineages'),
      hidden_for_embargo TEXT,
      changes_recorded   BOOLEAN NOT NULL DEFAULT FALSE,
      PRIMARY KEY ((project_id, name) HASH)
    );
    CREATE INDEX IF NOT EXISTS branches_q4_hidden_embargo
      ON branches_q4 (project_id HASH, hidden_for_embargo ASC) WHERE hidden_for_embargo IS NOT NULL;
    CREATE INDEX IF NOT EXISTS branches_q4_by_project
      ON branches_q4 (project_id HASH, name ASC);
  END IF;
END
$q4$;

-- veil: step

DO $q4$
BEGIN
  IF to_regclass('branches') IS NOT NULL AND to_regclass('branches_q4') IS NOT NULL THEN
    EXECUTE 'INSERT INTO branches_q4 (project_id, name, target, lineage, hidden_for_embargo, changes_recorded) '
         || 'SELECT project_id, name, target, lineage, hidden_for_embargo, changes_recorded FROM branches';
  END IF;
END
$q4$;

-- veil: step

DO $q4$
DECLARE
  c_old BIGINT;
  c_new BIGINT;
BEGIN
  IF to_regclass('branches') IS NOT NULL AND to_regclass('branches_q4') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM pg_index i
    WHERE i.indrelid = to_regclass('branches') AND i.indisprimary
      AND pg_get_indexdef(i.indexrelid) LIKE '%(project_id, name) HASH%'
  ) THEN
    EXECUTE 'SELECT count(*) FROM branches' INTO c_old;
    EXECUTE 'SELECT count(*) FROM branches_q4' INTO c_new;
    IF c_new <> c_old THEN
      RAISE EXCEPTION 'branches_q4 has % rows, expected % rows from branches', c_new, c_old;
    END IF;
    DROP TABLE IF EXISTS branches;
  END IF;
  IF to_regclass('branches') IS NULL AND to_regclass('branches_q4') IS NOT NULL THEN
    ALTER TABLE branches_q4 RENAME TO branches;
  END IF;
  ALTER INDEX IF EXISTS branches_q4_pkey RENAME TO branches_pkey;
  ALTER INDEX IF EXISTS branches_q4_hidden_embargo RENAME TO branches_hidden_embargo;
  ALTER INDEX IF EXISTS branches_q4_by_project RENAME TO branches_by_project;
END
$q4$;

-- veil: step

-- 2. snapshots
DO $q4$
BEGIN
  IF to_regclass('snapshots') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM pg_index i
    WHERE i.indrelid = to_regclass('snapshots') AND i.indisprimary
      AND pg_get_indexdef(i.indexrelid) LIKE '%(project_id, id) HASH%'
  ) THEN
    DROP TABLE IF EXISTS snapshots_q4;
    CREATE TABLE IF NOT EXISTS snapshots_q4 (
      project_id BIGINT NOT NULL,
      id         TEXT   NOT NULL,
      author     BIGINT NOT NULL DEFAULT 0,
      PRIMARY KEY ((project_id, id) HASH)
    );
  END IF;
END
$q4$;

-- veil: step

DO $q4$
BEGIN
  IF to_regclass('snapshots') IS NOT NULL AND to_regclass('snapshots_q4') IS NOT NULL THEN
    EXECUTE 'INSERT INTO snapshots_q4 (project_id, id, author) '
         || 'SELECT project_id, id, author FROM snapshots';
  END IF;
END
$q4$;

-- veil: step

DO $q4$
DECLARE
  c_old BIGINT;
  c_new BIGINT;
BEGIN
  IF to_regclass('snapshots') IS NOT NULL AND to_regclass('snapshots_q4') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM pg_index i
    WHERE i.indrelid = to_regclass('snapshots') AND i.indisprimary
      AND pg_get_indexdef(i.indexrelid) LIKE '%(project_id, id) HASH%'
  ) THEN
    EXECUTE 'SELECT count(*) FROM snapshots' INTO c_old;
    EXECUTE 'SELECT count(*) FROM snapshots_q4' INTO c_new;
    IF c_new <> c_old THEN
      RAISE EXCEPTION 'snapshots_q4 has % rows, expected % rows from snapshots', c_new, c_old;
    END IF;
    DROP TABLE IF EXISTS snapshots;
  END IF;
  IF to_regclass('snapshots') IS NULL AND to_regclass('snapshots_q4') IS NOT NULL THEN
    ALTER TABLE snapshots_q4 RENAME TO snapshots;
  END IF;
  ALTER INDEX IF EXISTS snapshots_q4_pkey RENAME TO snapshots_pkey;
END
$q4$;

-- veil: step

-- 3. origins
DO $q4$
BEGIN
  IF to_regclass('origins') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM pg_index i
    WHERE i.indrelid = to_regclass('origins') AND i.indisprimary
      AND pg_get_indexdef(i.indexrelid) LIKE '%(project_id, real_id) HASH%'
  ) THEN
    DROP TABLE IF EXISTS origins_q4;
    CREATE TABLE IF NOT EXISTS origins_q4 (
      project_id BIGINT NOT NULL,
      real_id    TEXT   NOT NULL,
      origin_id  TEXT   NOT NULL,
      PRIMARY KEY ((project_id, real_id) HASH)
    );
  END IF;
END
$q4$;

-- veil: step

DO $q4$
BEGIN
  IF to_regclass('origins') IS NOT NULL AND to_regclass('origins_q4') IS NOT NULL THEN
    EXECUTE 'INSERT INTO origins_q4 (project_id, real_id, origin_id) '
         || 'SELECT project_id, real_id, origin_id FROM origins';
  END IF;
END
$q4$;

-- veil: step

DO $q4$
DECLARE
  c_old BIGINT;
  c_new BIGINT;
BEGIN
  IF to_regclass('origins') IS NOT NULL AND to_regclass('origins_q4') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM pg_index i
    WHERE i.indrelid = to_regclass('origins') AND i.indisprimary
      AND pg_get_indexdef(i.indexrelid) LIKE '%(project_id, real_id) HASH%'
  ) THEN
    EXECUTE 'SELECT count(*) FROM origins' INTO c_old;
    EXECUTE 'SELECT count(*) FROM origins_q4' INTO c_new;
    IF c_new <> c_old THEN
      RAISE EXCEPTION 'origins_q4 has % rows, expected % rows from origins', c_new, c_old;
    END IF;
    DROP TABLE IF EXISTS origins;
  END IF;
  IF to_regclass('origins') IS NULL AND to_regclass('origins_q4') IS NOT NULL THEN
    ALTER TABLE origins_q4 RENAME TO origins;
  END IF;
  ALTER INDEX IF EXISTS origins_q4_pkey RENAME TO origins_pkey;
END
$q4$;

-- veil: step

-- 4. projections
DO $q4$
BEGIN
  IF to_regclass('projections') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM pg_index i
    WHERE i.indrelid = to_regclass('projections') AND i.indisprimary
      AND pg_get_indexdef(i.indexrelid) LIKE '%(project_id, view_key, real_id) HASH%'
  ) THEN
    DROP TABLE IF EXISTS projections_q4;
    CREATE TABLE IF NOT EXISTS projections_q4 (
      project_id   BIGINT  NOT NULL,
      view_key     TEXT    NOT NULL,
      real_id      TEXT    NOT NULL,
      projected_id TEXT    NOT NULL,
      created_at   BIGINT  NOT NULL,
      collapsed    BOOLEAN NOT NULL DEFAULT TRUE,
      PRIMARY KEY ((project_id, view_key, real_id) HASH)
    );
    CREATE INDEX IF NOT EXISTS projections_q4_by_view_v2
      ON projections_q4 ((project_id, view_key, projected_id) HASH, collapsed ASC, real_id ASC);
    CREATE INDEX IF NOT EXISTS projections_q4_by_projected_at
      ON projections_q4 ((project_id, projected_id) HASH, created_at DESC);
  END IF;
END
$q4$;

-- veil: step

DO $q4$
BEGIN
  IF to_regclass('projections') IS NOT NULL AND to_regclass('projections_q4') IS NOT NULL THEN
    EXECUTE 'INSERT INTO projections_q4 (project_id, view_key, real_id, projected_id, created_at, collapsed) '
         || 'SELECT project_id, view_key, real_id, projected_id, created_at, collapsed FROM projections';
  END IF;
END
$q4$;

-- veil: step

DO $q4$
DECLARE
  c_old BIGINT;
  c_new BIGINT;
BEGIN
  IF to_regclass('projections') IS NOT NULL AND to_regclass('projections_q4') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM pg_index i
    WHERE i.indrelid = to_regclass('projections') AND i.indisprimary
      AND pg_get_indexdef(i.indexrelid) LIKE '%(project_id, view_key, real_id) HASH%'
  ) THEN
    EXECUTE 'SELECT count(*) FROM projections' INTO c_old;
    EXECUTE 'SELECT count(*) FROM projections_q4' INTO c_new;
    IF c_new <> c_old THEN
      RAISE EXCEPTION 'projections_q4 has % rows, expected % rows from projections', c_new, c_old;
    END IF;
    DROP TABLE IF EXISTS projections;
  END IF;
  IF to_regclass('projections') IS NULL AND to_regclass('projections_q4') IS NOT NULL THEN
    ALTER TABLE projections_q4 RENAME TO projections;
  END IF;
  ALTER INDEX IF EXISTS projections_q4_pkey RENAME TO projections_pkey;
  ALTER INDEX IF EXISTS projections_q4_by_view_v2 RENAME TO projections_by_view_v2;
  ALTER INDEX IF EXISTS projections_q4_by_projected_at RENAME TO projections_by_projected_at;
END
$q4$;

-- veil: step

-- 5. landed_changes
DO $q4$
BEGIN
  IF to_regclass('landed_changes') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM pg_index i
    WHERE i.indrelid = to_regclass('landed_changes') AND i.indisprimary
      AND pg_get_indexdef(i.indexrelid) LIKE '%(project_id, branch) HASH%'
  ) THEN
    DROP TABLE IF EXISTS landed_changes_q4;
    CREATE TABLE IF NOT EXISTS landed_changes_q4 (
      project_id BIGINT NOT NULL,
      branch     TEXT   NOT NULL,
      lineage    BIGINT NOT NULL,
      change_id  TEXT   NOT NULL,
      author     BIGINT NOT NULL DEFAULT 0,
      landed     TEXT   NOT NULL,
      PRIMARY KEY ((project_id, branch) HASH, lineage ASC, change_id ASC, author ASC)
    );
  END IF;
END
$q4$;

-- veil: step

DO $q4$
BEGIN
  IF to_regclass('landed_changes') IS NOT NULL AND to_regclass('landed_changes_q4') IS NOT NULL THEN
    EXECUTE 'INSERT INTO landed_changes_q4 (project_id, branch, lineage, change_id, author, landed) '
         || 'SELECT project_id, branch, lineage, change_id, author, landed FROM landed_changes';
  END IF;
END
$q4$;

-- veil: step

DO $q4$
DECLARE
  c_old BIGINT;
  c_new BIGINT;
BEGIN
  IF to_regclass('landed_changes') IS NOT NULL AND to_regclass('landed_changes_q4') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM pg_index i
    WHERE i.indrelid = to_regclass('landed_changes') AND i.indisprimary
      AND pg_get_indexdef(i.indexrelid) LIKE '%(project_id, branch) HASH%'
  ) THEN
    EXECUTE 'SELECT count(*) FROM landed_changes' INTO c_old;
    EXECUTE 'SELECT count(*) FROM landed_changes_q4' INTO c_new;
    IF c_new <> c_old THEN
      RAISE EXCEPTION 'landed_changes_q4 has % rows, expected % rows from landed_changes', c_new, c_old;
    END IF;
    DROP TABLE IF EXISTS landed_changes;
  END IF;
  IF to_regclass('landed_changes') IS NULL AND to_regclass('landed_changes_q4') IS NOT NULL THEN
    ALTER TABLE landed_changes_q4 RENAME TO landed_changes;
  END IF;
  ALTER INDEX IF EXISTS landed_changes_q4_pkey RENAME TO landed_changes_pkey;
END
$q4$;

-- veil: step

-- 6. landing_queue
DO $q4$
BEGIN
  IF to_regclass('landing_queue') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM pg_index i
    WHERE i.indrelid = to_regclass('landing_queue') AND i.indisprimary
      AND pg_get_indexdef(i.indexrelid) LIKE '%(project_id, branch) HASH%'
  ) THEN
    DROP TABLE IF EXISTS landing_queue_q4;
    CREATE TABLE IF NOT EXISTS landing_queue_q4 (
      project_id    BIGINT  NOT NULL,
      branch        TEXT    NOT NULL,
      seq           BIGINT  NOT NULL DEFAULT nextval('landing_queue_seq_seq'),
      ticket        TEXT    NOT NULL,
      person_id     BIGINT  NOT NULL,
      person_name   TEXT    NOT NULL,
      device_key    TEXT    NOT NULL,
      stack         TEXT    NOT NULL,
      lineage       BIGINT  NOT NULL,
      person_epoch  BIGINT  NOT NULL,
      project_epoch BIGINT  NOT NULL,
      state         TEXT    NOT NULL,
      result        TEXT,
      created_at    BIGINT  NOT NULL,
      done_at       BIGINT,
      merges        BIGINT  NOT NULL DEFAULT 0,
      agent_session TEXT,
      session       TEXT    NOT NULL DEFAULT '',
      priority      INTEGER NOT NULL DEFAULT 0,
      person_slot   INTEGER,
      session_slot  INTEGER,
      PRIMARY KEY ((project_id, branch) HASH, seq ASC)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS landing_queue_q4_ticket
      ON landing_queue_q4 (ticket HASH);
    CREATE INDEX IF NOT EXISTS landing_queue_q4_queued
      ON landing_queue_q4 (
        ((CASE WHEN state = 'queued' THEN project_id ELSE NULL END), branch) HASH,
        priority DESC, created_at ASC, seq ASC
      )
      WHERE state = 'queued';
    CREATE UNIQUE INDEX IF NOT EXISTS landing_queue_q4_person_slot
      ON landing_queue_q4 ((project_id, person_id) HASH, person_slot ASC)
      WHERE state IN ('queued', 'merging');
    CREATE UNIQUE INDEX IF NOT EXISTS landing_queue_q4_session_slot
      ON landing_queue_q4 ((project_id, person_id, session) HASH, session_slot ASC)
      WHERE state IN ('queued', 'merging');
    CREATE INDEX IF NOT EXISTS landing_queue_q4_active_state
      ON landing_queue_q4 ((project_id, branch) HASH, state ASC)
      WHERE state IN ('queued', 'merging');
    CREATE INDEX IF NOT EXISTS landing_queue_q4_finished
      ON landing_queue_q4 (project_id HASH, done_at ASC, branch ASC)
      INCLUDE (seq, state)
      WHERE done_at IS NOT NULL;
  END IF;
END
$q4$;

-- veil: step

DO $q4$
BEGIN
  IF to_regclass('landing_queue') IS NOT NULL AND to_regclass('landing_queue_q4') IS NOT NULL THEN
    EXECUTE 'INSERT INTO landing_queue_q4 ('
         || 'project_id, branch, seq, ticket, person_id, person_name, device_key, '
         || 'stack, lineage, person_epoch, project_epoch, state, result, created_at, '
         || 'done_at, merges, agent_session, session, priority, person_slot, session_slot) '
         || 'SELECT project_id, branch, seq, ticket, person_id, person_name, device_key, '
         || 'stack, lineage, person_epoch, project_epoch, state, result, created_at, '
         || 'done_at, merges, agent_session, session, priority, person_slot, session_slot '
         || 'FROM landing_queue';
  END IF;
END
$q4$;

-- veil: step

DO $q4$
DECLARE
  c_old BIGINT;
  c_new BIGINT;
BEGIN
  IF to_regclass('landing_queue') IS NOT NULL AND to_regclass('landing_queue_q4') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM pg_index i
    WHERE i.indrelid = to_regclass('landing_queue') AND i.indisprimary
      AND pg_get_indexdef(i.indexrelid) LIKE '%(project_id, branch) HASH%'
  ) THEN
    EXECUTE 'SELECT count(*) FROM landing_queue' INTO c_old;
    EXECUTE 'SELECT count(*) FROM landing_queue_q4' INTO c_new;
    IF c_new <> c_old THEN
      RAISE EXCEPTION 'landing_queue_q4 has % rows, expected % rows from landing_queue', c_new, c_old;
    END IF;
    ALTER SEQUENCE landing_queue_seq_seq OWNED BY NONE;
    DROP TABLE IF EXISTS landing_queue;
  END IF;
  IF to_regclass('landing_queue') IS NULL AND to_regclass('landing_queue_q4') IS NOT NULL THEN
    ALTER TABLE landing_queue_q4 RENAME TO landing_queue;
  END IF;
  ALTER SEQUENCE landing_queue_seq_seq OWNED BY landing_queue.seq;
  ALTER INDEX IF EXISTS landing_queue_q4_pkey RENAME TO landing_queue_pkey;
  ALTER INDEX IF EXISTS landing_queue_q4_ticket RENAME TO landing_queue_ticket;
  ALTER INDEX IF EXISTS landing_queue_q4_queued RENAME TO landing_queue_queued;
  ALTER INDEX IF EXISTS landing_queue_q4_person_slot RENAME TO landing_queue_person_slot;
  ALTER INDEX IF EXISTS landing_queue_q4_session_slot RENAME TO landing_queue_session_slot;
  ALTER INDEX IF EXISTS landing_queue_q4_active_state RENAME TO landing_queue_active_state;
  ALTER INDEX IF EXISTS landing_queue_q4_finished RENAME TO landing_queue_finished;
END
$q4$;

-- veil: step

-- 7. landings
DO $q4$
BEGIN
  IF to_regclass('landings') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM pg_index i
    WHERE i.indrelid = to_regclass('landings') AND i.indisprimary
      AND pg_get_indexdef(i.indexrelid) LIKE '%(project_id, branch) HASH%'
  ) THEN
    DROP TABLE IF EXISTS landings_q4;
    CREATE TABLE IF NOT EXISTS landings_q4 (
      project_id BIGINT NOT NULL,
      branch     TEXT   NOT NULL,
      lineage    BIGINT NOT NULL,
      submitted  TEXT   NOT NULL,
      landed     TEXT   NOT NULL,
      at         BIGINT NOT NULL,
      PRIMARY KEY ((project_id, branch) HASH, lineage ASC, submitted ASC)
    );
    CREATE INDEX IF NOT EXISTS landings_q4_at
      ON landings_q4 (project_id HASH, at ASC)
      INCLUDE (branch, lineage, submitted);
    CREATE INDEX IF NOT EXISTS landings_q4_landed
      ON landings_q4 ((project_id, branch) HASH, lineage ASC, landed ASC);
  END IF;
END
$q4$;

-- veil: step

DO $q4$
BEGIN
  IF to_regclass('landings') IS NOT NULL AND to_regclass('landings_q4') IS NOT NULL THEN
    EXECUTE 'INSERT INTO landings_q4 (project_id, branch, lineage, submitted, landed, at) '
         || 'SELECT project_id, branch, lineage, submitted, landed, at FROM landings';
  END IF;
END
$q4$;

-- veil: step

DO $q4$
DECLARE
  c_old BIGINT;
  c_new BIGINT;
BEGIN
  IF to_regclass('landings') IS NOT NULL AND to_regclass('landings_q4') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM pg_index i
    WHERE i.indrelid = to_regclass('landings') AND i.indisprimary
      AND pg_get_indexdef(i.indexrelid) LIKE '%(project_id, branch) HASH%'
  ) THEN
    EXECUTE 'SELECT count(*) FROM landings' INTO c_old;
    EXECUTE 'SELECT count(*) FROM landings_q4' INTO c_new;
    IF c_new <> c_old THEN
      RAISE EXCEPTION 'landings_q4 has % rows, expected % rows from landings', c_new, c_old;
    END IF;
    DROP TABLE IF EXISTS landings;
  END IF;
  IF to_regclass('landings') IS NULL AND to_regclass('landings_q4') IS NOT NULL THEN
    ALTER TABLE landings_q4 RENAME TO landings;
  END IF;
  ALTER INDEX IF EXISTS landings_q4_pkey RENAME TO landings_pkey;
  ALTER INDEX IF EXISTS landings_q4_at RENAME TO landings_at;
  ALTER INDEX IF EXISTS landings_q4_landed RENAME TO landings_landed;
END
$q4$;

-- veil: step

-- 8. landing_leases
DO $q4$
BEGIN
  IF to_regclass('landing_leases') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM pg_index i
    WHERE i.indrelid = to_regclass('landing_leases') AND i.indisprimary
      AND pg_get_indexdef(i.indexrelid) LIKE '%(project_id, branch) HASH%'
  ) THEN
    DROP TABLE IF EXISTS landing_leases_q4;
    CREATE TABLE IF NOT EXISTS landing_leases_q4 (
      project_id BIGINT NOT NULL,
      branch     TEXT   NOT NULL,
      holder     TEXT   NOT NULL,
      epoch      BIGINT NOT NULL,
      expires_at BIGINT NOT NULL,
      served     BIGINT NOT NULL DEFAULT 0,
      lock_epoch BIGINT,
      PRIMARY KEY ((project_id, branch) HASH)
    );
  END IF;
END
$q4$;

-- veil: step

DO $q4$
BEGIN
  IF to_regclass('landing_leases') IS NOT NULL AND to_regclass('landing_leases_q4') IS NOT NULL THEN
    EXECUTE 'INSERT INTO landing_leases_q4 (project_id, branch, holder, epoch, expires_at, served, lock_epoch) '
         || 'SELECT project_id, branch, holder, epoch, expires_at, served, lock_epoch FROM landing_leases';
  END IF;
END
$q4$;

-- veil: step

DO $q4$
DECLARE
  c_old BIGINT;
  c_new BIGINT;
BEGIN
  IF to_regclass('landing_leases') IS NOT NULL AND to_regclass('landing_leases_q4') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM pg_index i
    WHERE i.indrelid = to_regclass('landing_leases') AND i.indisprimary
      AND pg_get_indexdef(i.indexrelid) LIKE '%(project_id, branch) HASH%'
  ) THEN
    EXECUTE 'SELECT count(*) FROM landing_leases' INTO c_old;
    EXECUTE 'SELECT count(*) FROM landing_leases_q4' INTO c_new;
    IF c_new <> c_old THEN
      RAISE EXCEPTION 'landing_leases_q4 has % rows, expected % rows from landing_leases', c_new, c_old;
    END IF;
    DROP TABLE IF EXISTS landing_leases;
  END IF;
  IF to_regclass('landing_leases') IS NULL AND to_regclass('landing_leases_q4') IS NOT NULL THEN
    ALTER TABLE landing_leases_q4 RENAME TO landing_leases;
  END IF;
  ALTER INDEX IF EXISTS landing_leases_q4_pkey RENAME TO landing_leases_pkey;
END
$q4$;

-- veil: step

-- 9. packs
DO $q4$
BEGIN
  IF to_regclass('packs') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM pg_index i
    WHERE i.indrelid = to_regclass('packs') AND i.indisprimary
      AND pg_get_indexdef(i.indexrelid) LIKE '%(project_id, name) HASH%'
  ) THEN
    DROP TABLE IF EXISTS packs_q4;
    CREATE TABLE IF NOT EXISTS packs_q4 (
      project_id   BIGINT   NOT NULL,
      name         TEXT     NOT NULL,
      state        SMALLINT NOT NULL,
      person_id    BIGINT,
      size         BIGINT   NOT NULL,
      objects      BIGINT   NOT NULL,
      created_at   BIGINT   NOT NULL,
      discarded_at BIGINT,
      PRIMARY KEY ((project_id, name) HASH)
    );
    CREATE INDEX IF NOT EXISTS packs_q4_listed
      ON packs_q4 (project_id HASH, created_at ASC, name ASC) INCLUDE (size, objects) WHERE state = 1;
    CREATE INDEX IF NOT EXISTS packs_q4_unlisted
      ON packs_q4 (project_id HASH)
      INCLUDE (name, state, person_id, created_at, discarded_at)
      WHERE state <> 1;
  END IF;
END
$q4$;

-- veil: step

DO $q4$
BEGIN
  IF to_regclass('packs') IS NOT NULL AND to_regclass('packs_q4') IS NOT NULL THEN
    EXECUTE 'INSERT INTO packs_q4 (project_id, name, state, person_id, size, objects, created_at, discarded_at) '
         || 'SELECT project_id, name, state, person_id, size, objects, created_at, discarded_at FROM packs';
  END IF;
END
$q4$;

-- veil: step

DO $q4$
DECLARE
  c_old BIGINT;
  c_new BIGINT;
BEGIN
  IF to_regclass('packs') IS NOT NULL AND to_regclass('packs_q4') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM pg_index i
    WHERE i.indrelid = to_regclass('packs') AND i.indisprimary
      AND pg_get_indexdef(i.indexrelid) LIKE '%(project_id, name) HASH%'
  ) THEN
    EXECUTE 'SELECT count(*) FROM packs' INTO c_old;
    EXECUTE 'SELECT count(*) FROM packs_q4' INTO c_new;
    IF c_new <> c_old THEN
      RAISE EXCEPTION 'packs_q4 has % rows, expected % rows from packs', c_new, c_old;
    END IF;
    DROP TABLE IF EXISTS packs;
  END IF;
  IF to_regclass('packs') IS NULL AND to_regclass('packs_q4') IS NOT NULL THEN
    ALTER TABLE packs_q4 RENAME TO packs;
  END IF;
  ALTER INDEX IF EXISTS packs_q4_pkey RENAME TO packs_pkey;
  ALTER INDEX IF EXISTS packs_q4_listed RENAME TO packs_listed;
  ALTER INDEX IF EXISTS packs_q4_unlisted RENAME TO packs_unlisted;
END
$q4$;

-- veil: step

-- 10. change_refs
DO $q4$
BEGIN
  IF to_regclass('change_refs') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM pg_index i
    WHERE i.indrelid = to_regclass('change_refs') AND i.indisprimary
      AND pg_get_indexdef(i.indexrelid) LIKE '%(project_id, change_id) HASH%'
  ) THEN
    DROP TABLE IF EXISTS change_refs_q4;
    CREATE TABLE IF NOT EXISTS change_refs_q4 (
      project_id BIGINT NOT NULL,
      change_id  TEXT   NOT NULL,
      snapshot   TEXT   NOT NULL,
      created_by BIGINT NOT NULL,
      created_at BIGINT NOT NULL,
      PRIMARY KEY ((project_id, change_id) HASH)
    );
  END IF;
END
$q4$;

-- veil: step

DO $q4$
BEGIN
  IF to_regclass('change_refs') IS NOT NULL AND to_regclass('change_refs_q4') IS NOT NULL THEN
    EXECUTE 'INSERT INTO change_refs_q4 (project_id, change_id, snapshot, created_by, created_at) '
         || 'SELECT project_id, change_id, snapshot, created_by, created_at FROM change_refs';
  END IF;
END
$q4$;

-- veil: step

DO $q4$
DECLARE
  c_old BIGINT;
  c_new BIGINT;
BEGIN
  IF to_regclass('change_refs') IS NOT NULL AND to_regclass('change_refs_q4') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM pg_index i
    WHERE i.indrelid = to_regclass('change_refs') AND i.indisprimary
      AND pg_get_indexdef(i.indexrelid) LIKE '%(project_id, change_id) HASH%'
  ) THEN
    EXECUTE 'SELECT count(*) FROM change_refs' INTO c_old;
    EXECUTE 'SELECT count(*) FROM change_refs_q4' INTO c_new;
    IF c_new <> c_old THEN
      RAISE EXCEPTION 'change_refs_q4 has % rows, expected % rows from change_refs', c_new, c_old;
    END IF;
    DROP TABLE IF EXISTS change_refs;
  END IF;
  IF to_regclass('change_refs') IS NULL AND to_regclass('change_refs_q4') IS NOT NULL THEN
    ALTER TABLE change_refs_q4 RENAME TO change_refs;
  END IF;
  ALTER INDEX IF EXISTS change_refs_q4_pkey RENAME TO change_refs_pkey;
END
$q4$;

-- veil: step

-- 11. access_epochs
DO $q4$
BEGIN
  IF to_regclass('access_epochs') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM pg_index i
    WHERE i.indrelid = to_regclass('access_epochs') AND i.indisprimary
      AND pg_get_indexdef(i.indexrelid) LIKE '%(project_id, person_id) HASH%'
  ) THEN
    DROP TABLE IF EXISTS access_epochs_q4;
    CREATE TABLE IF NOT EXISTS access_epochs_q4 (
      project_id BIGINT NOT NULL,
      person_id  BIGINT NOT NULL,
      epoch      BIGINT NOT NULL,
      changed_at BIGINT NOT NULL,
      PRIMARY KEY ((project_id, person_id) HASH)
    );
  END IF;
END
$q4$;

-- veil: step

DO $q4$
BEGIN
  IF to_regclass('access_epochs') IS NOT NULL AND to_regclass('access_epochs_q4') IS NOT NULL THEN
    EXECUTE 'INSERT INTO access_epochs_q4 (project_id, person_id, epoch, changed_at) '
         || 'SELECT project_id, person_id, epoch, changed_at FROM access_epochs';
  END IF;
END
$q4$;

-- veil: step

DO $q4$
DECLARE
  c_old BIGINT;
  c_new BIGINT;
BEGIN
  IF to_regclass('access_epochs') IS NOT NULL AND to_regclass('access_epochs_q4') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM pg_index i
    WHERE i.indrelid = to_regclass('access_epochs') AND i.indisprimary
      AND pg_get_indexdef(i.indexrelid) LIKE '%(project_id, person_id) HASH%'
  ) THEN
    EXECUTE 'SELECT count(*) FROM access_epochs' INTO c_old;
    EXECUTE 'SELECT count(*) FROM access_epochs_q4' INTO c_new;
    IF c_new <> c_old THEN
      RAISE EXCEPTION 'access_epochs_q4 has % rows, expected % rows from access_epochs', c_new, c_old;
    END IF;
    DROP TABLE IF EXISTS access_epochs;
  END IF;
  IF to_regclass('access_epochs') IS NULL AND to_regclass('access_epochs_q4') IS NOT NULL THEN
    ALTER TABLE access_epochs_q4 RENAME TO access_epochs;
  END IF;
  ALTER INDEX IF EXISTS access_epochs_q4_pkey RENAME TO access_epochs_pkey;
END
$q4$;

-- veil: step

ALTER SEQUENCE audit_log_id_seq CACHE 1000;

-- veil: step

ALTER SEQUENCE landing_queue_seq_seq CACHE 1000;

-- veil: step

ALTER SEQUENCE branch_lineages CACHE 1000;
