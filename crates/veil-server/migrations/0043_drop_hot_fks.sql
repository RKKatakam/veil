-- Drop foreign keys referencing projects(id) and people(id) from the 11 hot
-- write tables (docs/design/server/yugabyte-scaling.md P3).
--
-- Neither projects nor people rows are ever deleted by the server, and every
-- hot write already runs inside an authenticated request or lease that verified
-- the project and person. On YugabyteDB each FK adds a cross-tablet KEY SHARE
-- lock RPC to the single projects/people tablet on every INSERT (and on
-- PostgreSQL it adds per-row FK trigger checks). Dropping them matches the
-- existing derived, view_graph, file_history, and search tables.
--
-- Idempotent (IF EXISTS): YugabyteDB may apply DDL statement by statement.

ALTER TABLE packs          DROP CONSTRAINT IF EXISTS packs_project_id_fkey;
ALTER TABLE packs          DROP CONSTRAINT IF EXISTS packs_person_id_fkey;
ALTER TABLE landing_queue  DROP CONSTRAINT IF EXISTS landing_queue_project_id_fkey;
ALTER TABLE landing_queue  DROP CONSTRAINT IF EXISTS landing_queue_person_id_fkey;
ALTER TABLE branches       DROP CONSTRAINT IF EXISTS branches_project_id_fkey;
ALTER TABLE snapshots      DROP CONSTRAINT IF EXISTS snapshots_project_id_fkey;
ALTER TABLE origins        DROP CONSTRAINT IF EXISTS origins_project_id_fkey;
ALTER TABLE projections    DROP CONSTRAINT IF EXISTS projections_project_id_fkey;
ALTER TABLE landed_changes DROP CONSTRAINT IF EXISTS landed_changes_project_id_fkey;
ALTER TABLE landings       DROP CONSTRAINT IF EXISTS landings_project_id_fkey;
ALTER TABLE landed_from    DROP CONSTRAINT IF EXISTS landed_from_project_id_fkey;
ALTER TABLE landing_leases DROP CONSTRAINT IF EXISTS landing_leases_project_id_fkey;
ALTER TABLE change_refs    DROP CONSTRAINT IF EXISTS change_refs_project_id_fkey;
ALTER TABLE change_refs    DROP CONSTRAINT IF EXISTS change_refs_created_by_fkey;
