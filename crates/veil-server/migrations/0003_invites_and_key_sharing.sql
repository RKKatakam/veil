-- S2 secrets (docs/HUB.md §13.12): invites, background key sharing,
-- device removal, pending devices found by fingerprint. Idempotent (IF NOT
-- EXISTS): YugabyteDB may apply DDL statement by statement.
--
-- A pending device's fingerprint (hub::wire::device_fingerprint): its
-- person's `vl identity confirm` looks it up by it, so no number of other
-- pending devices under the name can hide it.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS fingerprint TEXT;
CREATE INDEX IF NOT EXISTS devices_by_fingerprint ON devices (person_id, fingerprint);
-- An invite: the public key of a secret only the invite link holds. The
-- join is the joining device's signature under it; key rings hold the
-- admin-signed record of the same key, and are the authority for keys.
CREATE TABLE IF NOT EXISTS invites (
    project_id BIGINT NOT NULL REFERENCES projects(id),
    invite_key TEXT NOT NULL,
    person TEXT NOT NULL,
    group_id BIGINT NOT NULL REFERENCES groups(id),
    expires_at BIGINT NOT NULL,
    created_by BIGINT NOT NULL REFERENCES people(id),
    created_at BIGINT NOT NULL,
    used_at BIGINT,
    device_id BIGINT REFERENCES devices(id),
    signature TEXT,
    PRIMARY KEY (project_id, invite_key)
);
-- "Someone's devices may need keys in this project": a hint for the
-- devices that share keys in the background, never what grants one.
CREATE TABLE IF NOT EXISTS key_requests (
    project_id BIGINT NOT NULL REFERENCES projects(id),
    person_id BIGINT NOT NULL REFERENCES people(id),
    created_at BIGINT NOT NULL,
    PRIMARY KEY (project_id, person_id)
);
-- A device an admin removed from one project (BUG-843): it may no longer
-- use that project; only its person removes it everywhere
-- (`devices.removed_at`).
CREATE TABLE IF NOT EXISTS device_bars (
    project_id BIGINT NOT NULL REFERENCES projects(id),
    device_id BIGINT NOT NULL REFERENCES devices(id),
    created_at BIGINT NOT NULL,
    PRIMARY KEY (project_id, device_id)
);
-- A fingerprint a person's `vl identity confirm` looked for and did not
-- find: a pending device with it is never pushed out by the bound on
-- pending devices per person, whoever else signs in under the name.
CREATE TABLE IF NOT EXISTS device_expected (
    person_id BIGINT NOT NULL REFERENCES people(id),
    fingerprint TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (person_id, fingerprint)
);
