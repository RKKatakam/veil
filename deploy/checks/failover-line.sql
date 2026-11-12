-- `main`'s first-parent line in the failover run's project, one row per
-- snapshot from the tip down: `n|snapshot|change_id|tickets`, where n is
-- the distance from the tip, change_id the snapshot's change (from the
-- derived graph; empty if it is not derived) and tickets the landing
-- tickets whose change became this snapshot (comma-separated; empty for a
-- set-up snapshot). failover-verdict.py compares it with the benchmark's
-- per-change log (failover.landings.jsonl): every change an agent was told
-- landed must be on this line exactly once, as the snapshot it was told.
-- :T0 is the run's start on the database's clock (µs); the run has one project.
WITH RECURSIVE
p AS (SELECT DISTINCT project_id FROM landing_queue WHERE created_at >= :T0),
q AS (SELECT * FROM landing_queue WHERE project_id IN (SELECT project_id FROM p) AND branch = 'main'),
sub AS (SELECT q.project_id, q.ticket, json_array_elements(q.stack::json)->>0 AS submitted FROM q WHERE q.state = 'landed'),
lc AS (SELECT * FROM landings WHERE project_id IN (SELECT project_id FROM p) AND branch = 'main' AND submitted <> landed),
chain(project_id, snapshot, n) AS (
    SELECT b.project_id, b.target, 0 FROM branches b WHERE b.name = 'main' AND b.project_id IN (SELECT project_id FROM p)
    UNION ALL
    SELECT c.project_id, g.parents::json->>0, c.n + 1
    FROM chain c JOIN graph g ON g.project_id = c.project_id AND g.snapshot = c.snapshot
    WHERE json_array_length(g.parents::json) > 0
)
SELECT c.n::TEXT || '|' || c.snapshot || '|' || coalesce(g.change_id, '') || '|' ||
       coalesce((SELECT string_agg(sub.ticket, ',' ORDER BY sub.ticket)
                 FROM lc JOIN sub ON sub.project_id = lc.project_id AND sub.submitted = lc.submitted
                 WHERE lc.project_id = c.project_id AND lc.landed = c.snapshot), '')
FROM chain c LEFT JOIN graph g ON g.project_id = c.project_id AND g.snapshot = c.snapshot
ORDER BY c.project_id, c.n;
