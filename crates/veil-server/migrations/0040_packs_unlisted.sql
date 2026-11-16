-- BUG-2280: every server looks, at start-up and every few minutes, for the
-- projects with packs to sweep (`pack_gc::sweep_scan`): discarded packs and
-- staged ones. Only those rows are indexed, so the look reads none of the
-- listed packs. Idempotent (IF NOT EXISTS).
-- veil: online indexes (outside the transaction, `db::ONLINE_INDEXES`: on a table servers already write)
CREATE INDEX CONCURRENTLY IF NOT EXISTS packs_unlisted ON packs (project_id) WHERE state <> 1;
