-- BUG-1955: the count of queue entries a branch's landing service has
-- served (landed, refused, handed to a merge), kept in its lease row by the
-- batch's own transaction. What a submit reads to know how fast the service
-- is landing now (`limits::pressure`): a submit that would wait longer than
-- the service's rate allows is told to come back, before any work is done
-- for it. Idempotent (IF NOT EXISTS).
ALTER TABLE landing_leases ADD COLUMN IF NOT EXISTS served BIGINT NOT NULL DEFAULT 0;
