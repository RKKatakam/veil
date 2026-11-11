-- Secrets in the browser and passkey sign-in (S26, docs/HUB.md §13.40):
--   * projects.web_secrets: admin opt-in setting (default FALSE);
--   * devices.browser / devices.prf_supported: browser device identity flags;
--   * web_enrollments: short-lived single-use enrollment codes minted by `vl web`;
--   * webauthn_challenges: single-use WebAuthn registration/assertion challenges;
--   * webauthn_credentials: passkeys bound to browser devices;
--   * browser_device_rings: wrapped key-ring copies indexed per confirmed browser device.

ALTER TABLE projects ADD COLUMN IF NOT EXISTS web_secrets BOOLEAN NOT NULL DEFAULT FALSE;

DROP TRIGGER IF EXISTS veil_epoch ON projects;
CREATE TRIGGER veil_epoch AFTER UPDATE OF name, default_branch, policy_text, policy_bindings, web_secrets OR DELETE ON projects
    FOR EACH ROW EXECUTE FUNCTION veil_epoch_project_row();

ALTER TABLE devices ADD COLUMN IF NOT EXISTS browser BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS prf_supported BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS web_enrollments (
    code_hash TEXT PRIMARY KEY,
    person_id BIGINT NOT NULL REFERENCES people(id) ON DELETE CASCADE,
    label TEXT,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    used_at BIGINT
);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
    challenge TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    person_id BIGINT,
    code_hash TEXT,
    prf_salt TEXT,
    origin TEXT NOT NULL,
    rp_id TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    -- The address that asked (the anonymous rate's key, `limits::Address`):
    -- an address holds a bounded number of pending sign-ins (BUG-1902).
    address TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS webauthn_challenges_by_address ON webauthn_challenges (address);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    credential_id TEXT PRIMARY KEY,
    person_id BIGINT NOT NULL REFERENCES people(id) ON DELETE CASCADE,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    alg INT NOT NULL,
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    prf_salt TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    -- `vl web --label`: what the person called this browser (BUG-1901).
    label TEXT
);

CREATE INDEX IF NOT EXISTS webauthn_credentials_by_person ON webauthn_credentials (person_id);
CREATE INDEX IF NOT EXISTS webauthn_credentials_by_device ON webauthn_credentials (device_id);

CREATE TABLE IF NOT EXISTS browser_device_rings (
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    body TEXT NOT NULL,
    PRIMARY KEY (device_id, project_id, scope)
);
