-- The review gate's writers (BUG-2110, `prs::gate`): a write that takes a
-- project's review gate exclusively first announces itself here, in a row
-- committed on its own, and a landing batch takes the gate shared only
-- when no writer of its project is announced; one that finds one waits
-- for it outside its transaction. A row goes when its writer's transaction
-- ends (or, the writer gone, once stale and its advisory lock free).
-- Idempotent (IF NOT EXISTS): YugabyteDB may apply DDL statement by
-- statement.
CREATE TABLE IF NOT EXISTS review_writers (
    id BIGSERIAL PRIMARY KEY,
    project_id BIGINT NOT NULL,
    since_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS review_writers_project ON review_writers (project_id);
