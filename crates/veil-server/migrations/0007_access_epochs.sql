-- Access epochs (docs/HUB.md §13.13; phase-2 design §4.4, §5.2): every
-- change that can take access away gives its project or person a new
-- epoch, in the same transaction as the change, and a read grant made
-- with another epoch than the current one is void. Idempotent: YugabyteDB
-- may apply DDL statement by statement.
--
-- One row per project (person_id 0: its accepted policy) and per person
-- (project_id 0: their groups, admin rights or devices). An epoch is a
-- random value, new at each change, never a count: a grant shows its
-- holder neither how many changes happened nor when (BUG-1081). A bump
-- writes only its own key's row, which stays locked until the change
-- commits, so a grant that read the epoch before the change is void after
-- it, and bumps of different keys never wait for one another.
CREATE TABLE IF NOT EXISTS access_epochs (
    project_id BIGINT NOT NULL,
    person_id BIGINT NOT NULL,
    epoch BIGINT NOT NULL,
    changed_at BIGINT NOT NULL,
    PRIMARY KEY (project_id, person_id)
);

CREATE OR REPLACE FUNCTION veil_bump_epoch(p BIGINT, q BIGINT) RETURNS VOID AS $$
DECLARE
    e BIGINT := floor(random() * 9.0e18)::BIGINT + 1;
BEGIN
    INSERT INTO access_epochs (project_id, person_id, epoch, changed_at)
    VALUES (p, q, e, (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT)
    ON CONFLICT (project_id, person_id) DO UPDATE
        SET epoch = CASE WHEN access_epochs.epoch = EXCLUDED.epoch THEN EXCLUDED.epoch + 1 ELSE EXCLUDED.epoch END,
            changed_at = EXCLUDED.changed_at;
END
$$ LANGUAGE plpgsql;

-- Triggers, so that no route that takes access away can forget the bump.
-- A person leaves a group (removed, or the group deleted).
CREATE OR REPLACE FUNCTION veil_epoch_member() RETURNS TRIGGER AS $$
BEGIN
    PERFORM veil_bump_epoch(0, OLD.person_id);
    RETURN OLD;
END
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS veil_epoch_member ON group_members;
CREATE TRIGGER veil_epoch_member AFTER DELETE ON group_members FOR EACH ROW EXECUTE PROCEDURE veil_epoch_member();
-- An admin stops being one.
DROP TRIGGER IF EXISTS veil_epoch_admin ON project_admins;
CREATE TRIGGER veil_epoch_admin AFTER DELETE ON project_admins FOR EACH ROW EXECUTE PROCEDURE veil_epoch_member();
-- A project's accepted policy or its bindings change (a push accepted by
-- an admin, a group created under a name a line names).
CREATE OR REPLACE FUNCTION veil_epoch_policy() RETURNS TRIGGER AS $$
BEGIN
    PERFORM veil_bump_epoch(NEW.id, 0);
    RETURN NEW;
END
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS veil_epoch_policy ON projects;
CREATE TRIGGER veil_epoch_policy AFTER UPDATE ON projects FOR EACH ROW
    WHEN (OLD.policy_text IS DISTINCT FROM NEW.policy_text OR OLD.policy_bindings IS DISTINCT FROM NEW.policy_bindings)
    EXECUTE PROCEDURE veil_epoch_policy();
-- A device removed by its person (everywhere).
CREATE OR REPLACE FUNCTION veil_epoch_device() RETURNS TRIGGER AS $$
BEGIN
    PERFORM veil_bump_epoch(0, NEW.person_id);
    RETURN NEW;
END
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS veil_epoch_device ON devices;
CREATE TRIGGER veil_epoch_device AFTER UPDATE ON devices FOR EACH ROW
    WHEN (OLD.removed_at IS NULL AND NEW.removed_at IS NOT NULL)
    EXECUTE PROCEDURE veil_epoch_device();
-- A device removed from one project by an admin (BUG-843).
CREATE OR REPLACE FUNCTION veil_epoch_bar() RETURNS TRIGGER AS $$
BEGIN
    PERFORM veil_bump_epoch(0, (SELECT person_id FROM devices WHERE id = NEW.device_id));
    RETURN NEW;
END
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS veil_epoch_bar ON device_bars;
CREATE TRIGGER veil_epoch_bar AFTER INSERT ON device_bars FOR EACH ROW EXECUTE PROCEDURE veil_epoch_bar();
