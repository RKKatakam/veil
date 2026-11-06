-- Confirmed devices (docs/HUB.md §13.11, BUG-827). A device that signs in
-- under an existing person's name is pending: no session, its signatures
-- not accepted, until one of that person's devices vouches for it.
-- Idempotent (IF NOT EXISTS): YugabyteDB may apply DDL statement by
-- statement.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS pending BOOLEAN NOT NULL DEFAULT FALSE;
-- A vouch: the device with `voucher_key` signed (context `hub-device`)
-- that `device_id` is its person's too. Admins' `vl` verify it; the
-- server's record of it is never what wraps a key.
CREATE TABLE IF NOT EXISTS device_vouches (
    device_id BIGINT NOT NULL REFERENCES devices(id),
    voucher_key TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (device_id, voucher_key)
);
