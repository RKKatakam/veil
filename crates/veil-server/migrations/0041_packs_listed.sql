-- BUG-2462: a project's listed packs are read in order (each server's
-- listing, `pack::Packs::refresh_in`; each background merge pass, its
-- count of small packs and its listing, `pack_gc`) and, by the primary
-- key alone, each read also walked the rows of the packs merges replaced,
-- kept a grace period before they are swept: at 3,000 packs listed a
-- second, about 180,000 rows, read by every pass. Only listed rows are
-- indexed here, in the order they are read. Idempotent (IF NOT EXISTS).
--
-- PostgreSQL only. The listing reads this index alone once it exists, so
-- it must hold every listed row. PostgreSQL builds it in the migration's
-- transaction holding the table's lock, so no write is missed (writes wait
-- for the build). YugabyteDB builds an index made in a transaction block
-- without that lock, and rows listed by other servers during the build may
-- be missing from it, with no error: a missing row is a pack every server
-- leaves out of its listing, whose objects then read as missing (BUG-2462
-- review). On YugabyteDB the listings keep reading the primary key.
DO $$
BEGIN
    IF version() NOT LIKE '%-YB-%' THEN
        CREATE INDEX IF NOT EXISTS packs_listed ON packs (project_id, created_at, name) INCLUDE (size, objects) WHERE state = 1;
    END IF;
END
$$;
