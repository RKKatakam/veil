-- BUG-1970 (cause 2): the epoch of a landing lease whose session advisory
-- lock its holder took before taking the lease (`landing/lease_lock.rs`).
-- Only a lease whose `lock_epoch` is its `epoch` is taken over before it
-- expires, once that lock is found free (its holder is gone); any other (a
-- server of an earlier release, no lock session, a row written otherwise)
-- only on expiry, as before. Idempotent (IF NOT EXISTS).
ALTER TABLE landing_leases ADD COLUMN IF NOT EXISTS lock_epoch BIGINT;
