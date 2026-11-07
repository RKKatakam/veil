-- Access epochs (docs/HUB.md §13.14; docs/design/server/phase-2-thin-clients.md
-- §4.4, §5.2): the one record of access changes, for every server's caches
-- (S4) and for read grants (S5). Every server caches sessions and
-- permissions in memory and checks them, on every request, against these
-- epochs: a change that could make a cached decision wrong gives its key a
-- new epoch in the same transaction, so the next request to any server sees
-- it. Rows are never deleted.
--
--   (0, person)    the person's sessions, devices, admin rights, groups, bars
--   (project, 0)   the project's accepted policy, its bindings, its groups
--
-- An epoch is a random value, new at each change, never a count: a grant
-- that carries it shows its holder neither how many changes happened nor
-- when (BUG-1081). Equality is all a cache or a grant compares. The value
-- comes from gen_random_uuid() (the strong random source; random() is a
-- seeded generator whose outputs predict one another), is never 0 (a key
-- that never changed reads as 0) and never the key's previous value. A bump
-- writes only its own key's row, which stays locked until the change
-- commits: there is no server-wide row, and bumps of different keys never
-- wait for one another.
--
-- The bumps are triggers, not code in each route: any write to these
-- tables, granting as well as taking away, by any route written later or by
-- an operator, gives a new epoch.
-- Idempotent (IF NOT EXISTS, OR REPLACE, DROP … IF EXISTS): YugabyteDB may
-- apply DDL statement by statement.
CREATE TABLE IF NOT EXISTS access_epochs (
    project_id BIGINT NOT NULL,          -- 0 for a person-wide change
    person_id BIGINT NOT NULL,           -- 0 for a project-wide change
    epoch BIGINT NOT NULL,
    changed_at BIGINT NOT NULL,
    PRIMARY KEY (project_id, person_id)
);

CREATE OR REPLACE FUNCTION veil_bump_epoch(p BIGINT, q BIGINT) RETURNS VOID AS $$
DECLARE
    -- The first 64 bits of a random UUID: 60 random bits (4 name its
    -- version).
    e BIGINT := ('x' || substr(replace(gen_random_uuid()::text, '-', ''), 1, 16))::bit(64)::bigint;
BEGIN
    IF e = 0 THEN
        e := 1;
    END IF;
    INSERT INTO access_epochs (project_id, person_id, epoch, changed_at)
    VALUES (p, q, e, (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT)
    ON CONFLICT (project_id, person_id) DO UPDATE
        -- Drawing the previous value again (one chance in 2^60) must still
        -- change it, and never to 0.
        SET epoch = CASE WHEN access_epochs.epoch = EXCLUDED.epoch THEN (CASE WHEN EXCLUDED.epoch = 1 THEN 2 ELSE 1 END)
                         ELSE EXCLUDED.epoch END,
            changed_at = EXCLUDED.changed_at;
END
$$ LANGUAGE plpgsql;

-- Rows naming a person: group members, project admins, sessions (deleted or
-- changed; a new session invalidates nothing), people (a new name).
CREATE OR REPLACE FUNCTION veil_epoch_person_row() RETURNS trigger AS $$
BEGIN
    IF TG_OP IN ('UPDATE', 'DELETE') THEN
        PERFORM veil_bump_epoch(0, OLD.person_id);
    END IF;
    IF TG_OP IN ('INSERT', 'UPDATE') THEN
        PERFORM veil_bump_epoch(0, NEW.person_id);
    END IF;
    RETURN NULL;
END
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION veil_epoch_people_row() RETURNS trigger AS $$
BEGIN
    PERFORM veil_bump_epoch(0, OLD.id);
    RETURN NULL;
END
$$ LANGUAGE plpgsql;

-- Devices: removed, confirmed, moved. A pending device has no session, so
-- deleting one (the bound on pending devices) invalidates nothing.
CREATE OR REPLACE FUNCTION veil_epoch_device_row() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF NOT OLD.pending THEN
            PERFORM veil_bump_epoch(0, OLD.person_id);
        END IF;
        RETURN NULL;
    END IF;
    PERFORM veil_bump_epoch(0, OLD.person_id);
    PERFORM veil_bump_epoch(0, NEW.person_id);
    RETURN NULL;
END
$$ LANGUAGE plpgsql;

-- A device barred from (or let back into) one project: its person's epoch.
CREATE OR REPLACE FUNCTION veil_epoch_bar_row() RETURNS trigger AS $$
DECLARE
    d BIGINT;
BEGIN
    IF TG_OP = 'DELETE' THEN d := OLD.device_id; ELSE d := NEW.device_id; END IF;
    PERFORM veil_bump_epoch(0, (SELECT person_id FROM devices WHERE id = d));
    IF TG_OP = 'UPDATE' THEN
        PERFORM veil_bump_epoch(0, (SELECT person_id FROM devices WHERE id = OLD.device_id));
    END IF;
    RETURN NULL;
END
$$ LANGUAGE plpgsql;

-- A project's accepted policy, its bindings, its default branch; a group
-- deleted or renamed.
CREATE OR REPLACE FUNCTION veil_epoch_project_row() RETURNS trigger AS $$
BEGIN
    PERFORM veil_bump_epoch(OLD.id, 0);
    RETURN NULL;
END
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION veil_epoch_group_row() RETURNS trigger AS $$
BEGIN
    PERFORM veil_bump_epoch(OLD.project_id, 0);
    IF TG_OP = 'UPDATE' THEN
        PERFORM veil_bump_epoch(NEW.project_id, 0);
    END IF;
    RETURN NULL;
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS veil_epoch ON group_members;
CREATE TRIGGER veil_epoch AFTER INSERT OR UPDATE OR DELETE ON group_members
    FOR EACH ROW EXECUTE FUNCTION veil_epoch_person_row();
DROP TRIGGER IF EXISTS veil_epoch ON project_admins;
CREATE TRIGGER veil_epoch AFTER INSERT OR UPDATE OR DELETE ON project_admins
    FOR EACH ROW EXECUTE FUNCTION veil_epoch_person_row();
DROP TRIGGER IF EXISTS veil_epoch ON sessions;
CREATE TRIGGER veil_epoch AFTER UPDATE OR DELETE ON sessions
    FOR EACH ROW EXECUTE FUNCTION veil_epoch_person_row();
DROP TRIGGER IF EXISTS veil_epoch ON people;
CREATE TRIGGER veil_epoch AFTER UPDATE OR DELETE ON people
    FOR EACH ROW EXECUTE FUNCTION veil_epoch_people_row();
DROP TRIGGER IF EXISTS veil_epoch ON devices;
CREATE TRIGGER veil_epoch AFTER UPDATE OF removed_at, pending, signing_key, person_id OR DELETE ON devices
    FOR EACH ROW EXECUTE FUNCTION veil_epoch_device_row();
DROP TRIGGER IF EXISTS veil_epoch ON device_bars;
CREATE TRIGGER veil_epoch AFTER INSERT OR UPDATE OR DELETE ON device_bars
    FOR EACH ROW EXECUTE FUNCTION veil_epoch_bar_row();
DROP TRIGGER IF EXISTS veil_epoch ON projects;
CREATE TRIGGER veil_epoch AFTER UPDATE OF name, default_branch, policy_text, policy_bindings OR DELETE ON projects
    FOR EACH ROW EXECUTE FUNCTION veil_epoch_project_row();
DROP TRIGGER IF EXISTS veil_epoch ON groups;
CREATE TRIGGER veil_epoch AFTER UPDATE OR DELETE ON groups
    FOR EACH ROW EXECUTE FUNCTION veil_epoch_group_row();
