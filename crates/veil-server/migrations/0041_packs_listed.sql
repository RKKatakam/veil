-- BUG-2462: a project's listed packs are read in order (each server's
-- listing, `pack::Packs::refresh_in`; each background merge pass, its
-- count of small packs and its listing, `pack_gc`) and, by the primary
-- key alone, each read also walked the rows of the packs merges replaced,
-- kept a grace period before they are swept: at 3,000 packs listed a
-- second, about 180,000 rows, read by every pass. Only listed rows are
-- indexed here, in the order they are read. Idempotent (IF NOT EXISTS).
CREATE INDEX IF NOT EXISTS packs_listed ON packs (project_id, created_at, name) INCLUDE (size, objects) WHERE state = 1;
