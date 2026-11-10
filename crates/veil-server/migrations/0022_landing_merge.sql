-- Content merges and re-queue for the landing service (milestone S18;
-- docs/HUB.md §13.30; docs/design/server/phase-4-agent-scale.md §5).
--
-- `merges` counts how many times a merge worker cleanly merged and re-queued
-- a queue row (at most `MAX_MERGES` = 3; past that it is answered `conflict`).
-- `agent_session` records the submitting agent session's `token_hash` (S11)
-- so merge workers and the landing service preserve its narrowing and verify
-- it has not expired or been revoked before merging or landing.
ALTER TABLE landing_queue ADD COLUMN IF NOT EXISTS merges BIGINT NOT NULL DEFAULT 0;
ALTER TABLE landing_queue ADD COLUMN IF NOT EXISTS agent_session TEXT;

