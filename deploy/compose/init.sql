-- Run once by the PostgreSQL image on first start: the statement counter
-- veil-bench's cost gates read (docs/design/server/storage-and-cost.md §9).
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
