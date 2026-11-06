-- Veil server schema, version 1 (docs/HUB.md §5.1). Portable SQL for
-- PostgreSQL and YugabyteDB; idempotent (IF NOT EXISTS), because DDL in a
-- transaction is not atomic on every YugabyteDB release.
CREATE TABLE IF NOT EXISTS people (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
    id BIGSERIAL PRIMARY KEY,
    person_id BIGINT NOT NULL REFERENCES people(id),
    signing_key TEXT NOT NULL UNIQUE,
    -- The device's full public identity (veil1<x25519><ed25519><binding>):
    -- what an admin's device wraps secret keys to. The binding proves the
    -- signing key chose the X25519 key.
    public_identity TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    removed_at BIGINT
);
CREATE TABLE IF NOT EXISTS challenges (
    challenge TEXT PRIMARY KEY,
    signing_key TEXT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    device_id BIGINT NOT NULL REFERENCES devices(id),
    person_id BIGINT NOT NULL REFERENCES people(id),
    expires_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS projects (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_by BIGINT NOT NULL REFERENCES people(id),
    created_at BIGINT NOT NULL,
    default_branch TEXT NOT NULL,
    -- The accepted .veilpolicy (its text) and how its names were bound
    -- (JSON: name -> {"group": id} | {"person": id}).
    policy_text TEXT NOT NULL,
    policy_bindings TEXT NOT NULL,
    policy_version BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS project_admins (
    project_id BIGINT NOT NULL REFERENCES projects(id),
    person_id BIGINT NOT NULL REFERENCES people(id),
    PRIMARY KEY (project_id, person_id)
);
CREATE TABLE IF NOT EXISTS groups (
    id BIGSERIAL PRIMARY KEY,
    project_id BIGINT NOT NULL REFERENCES projects(id),
    name TEXT NOT NULL,
    UNIQUE (project_id, name)
);
CREATE TABLE IF NOT EXISTS group_members (
    group_id BIGINT NOT NULL REFERENCES groups(id),
    person_id BIGINT NOT NULL REFERENCES people(id),
    PRIMARY KEY (group_id, person_id)
);
CREATE TABLE IF NOT EXISTS group_managers (
    group_id BIGINT NOT NULL REFERENCES groups(id),
    person_id BIGINT NOT NULL REFERENCES people(id),
    PRIMARY KEY (group_id, person_id)
);
-- A branch move is one compare-and-swap on one row.
CREATE TABLE IF NOT EXISTS branches (
    project_id BIGINT NOT NULL REFERENCES projects(id),
    name TEXT NOT NULL,
    target TEXT NOT NULL,
    PRIMARY KEY (project_id, name)
);
-- Every snapshot a branch has reached: the committed history.
CREATE TABLE IF NOT EXISTS snapshots (
    project_id BIGINT NOT NULL REFERENCES projects(id),
    id TEXT NOT NULL,
    PRIMARY KEY (project_id, id)
);
-- A snapshot the server completed from a pusher's projection, and the
-- pusher's own signed snapshot.
CREATE TABLE IF NOT EXISTS origins (
    project_id BIGINT NOT NULL REFERENCES projects(id),
    real_id TEXT NOT NULL,
    origin_id TEXT NOT NULL,
    PRIMARY KEY (project_id, real_id)
);
-- Per-viewer projections of snapshots, by view key.
CREATE TABLE IF NOT EXISTS projections (
    project_id BIGINT NOT NULL REFERENCES projects(id),
    view_key TEXT NOT NULL,
    real_id TEXT NOT NULL,
    projected_id TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (project_id, view_key, real_id)
);
CREATE INDEX IF NOT EXISTS projections_by_projected ON projections (project_id, projected_id);
-- Key rings of secret scopes (signed logs; the server cannot open them).
CREATE TABLE IF NOT EXISTS rings (
    project_id BIGINT NOT NULL REFERENCES projects(id),
    scope TEXT NOT NULL,
    body TEXT NOT NULL,
    PRIMARY KEY (project_id, scope)
);
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    project_id BIGINT,
    at BIGINT NOT NULL,
    actor BIGINT,
    action TEXT NOT NULL,
    details TEXT NOT NULL
);
