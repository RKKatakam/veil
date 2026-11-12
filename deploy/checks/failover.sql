-- The failover gate's checks (deploy/gates.sh `gate_failover`), one
-- `name|value` row each, judged by failover-verdict.py. :T0 is the run's
-- start and :STOP the moment the lease holder was stopped, both in µs on
-- the database's clock; `done_at` is in ms on the landing server's clock.
--
-- The run's project is new: every ticket of it is the run's, and `main`
-- holds only the project's set-up snapshots and what the tickets landed.
--   lost:   tickets still queued after settling (`unfinished`); landed
--           tickets whose change has no landing record (`landed_without_record`);
--           recorded landings that are not on `main`'s first-parent line
--           (`recorded_not_on_main`).
--   twice:  a change id twice on `main`'s line (`change_twice_on_main`); one
--           landed snapshot recorded for two changes (`landed_twice`); a snapshot
--           on `main`, after its first landing, that no ticket landed
--           (`main_without_ticket`; `setup_snapshots` are the ones before it).
-- `main`'s line is walked in the derived graph (`graph.parents`, first
-- parent first), from the branch's tip to the root.
--
-- `landings` holds two kinds of rows: a change's (submitted -> the snapshot
-- it became) and, for each landed snapshot, one of itself (landed ->
-- landed), which the server reads to tell that a change already landed.
-- The checks of "which change made this snapshot" use the first kind only.
WITH RECURSIVE
p AS (SELECT DISTINCT project_id FROM landing_queue WHERE created_at >= :T0),
q AS (SELECT * FROM landing_queue WHERE project_id IN (SELECT project_id FROM p) AND branch = 'main'),
sub AS (SELECT q.project_id, q.ticket, json_array_elements(q.stack::json)->>0 AS submitted FROM q WHERE q.state = 'landed'),
l AS (SELECT * FROM landings WHERE project_id IN (SELECT project_id FROM p) AND branch = 'main'),
lc AS (SELECT * FROM l WHERE submitted <> landed),
chain(project_id, snapshot, n) AS (
    SELECT b.project_id, b.target, 0 FROM branches b WHERE b.name = 'main' AND b.project_id IN (SELECT project_id FROM p)
    UNION ALL
    SELECT c.project_id, g.parents::json->>0, c.n + 1
    FROM chain c JOIN graph g ON g.project_id = c.project_id AND g.snapshot = c.snapshot
    WHERE json_array_length(g.parents::json) > 0
),
line AS (SELECT c.project_id, c.snapshot, c.n, g.change_id,
                EXISTS (SELECT 1 FROM lc WHERE lc.project_id = c.project_id AND lc.landed = c.snapshot) AS ticketed
         FROM chain c LEFT JOIN graph g ON g.project_id = c.project_id AND g.snapshot = c.snapshot),
oldest AS (SELECT project_id, max(n) AS n FROM line WHERE ticketed GROUP BY project_id),
root AS (SELECT project_id, max(n) AS n FROM chain GROUP BY project_id),
done AS (SELECT done_at::BIGINT * 1000 AS t FROM q WHERE state = 'landed' AND done_at IS NOT NULL),
gaps AS (SELECT t, t - lag(t) OVER (ORDER BY t) AS gap FROM done)
SELECT 'projects', (SELECT count(*) FROM p)::TEXT
UNION ALL SELECT 'tickets', (SELECT count(*) FROM q)::TEXT
UNION ALL SELECT 'tickets_landed', (SELECT count(*) FROM q WHERE state = 'landed')::TEXT
UNION ALL SELECT 'tickets_conflict', (SELECT count(*) FROM q WHERE state = 'conflict')::TEXT
UNION ALL SELECT 'tickets_rejected', (SELECT count(*) FROM q WHERE state = 'rejected')::TEXT
UNION ALL SELECT 'unfinished', (SELECT count(*) FROM q WHERE state IN ('queued', 'merging'))::TEXT
UNION ALL SELECT 'landed_changes', (SELECT count(*) FROM sub)::TEXT
UNION ALL SELECT 'landed_without_record', (SELECT count(*) FROM sub WHERE NOT EXISTS (SELECT 1 FROM l WHERE l.project_id = sub.project_id AND l.submitted = sub.submitted))::TEXT
UNION ALL SELECT 'recorded_not_on_main', (SELECT count(*) FROM l WHERE NOT EXISTS (SELECT 1 FROM line WHERE line.project_id = l.project_id AND line.snapshot = l.landed))::TEXT
UNION ALL SELECT 'landed_twice', (SELECT count(*) FROM (SELECT landed FROM lc GROUP BY project_id, landed HAVING count(*) > 1) x)::TEXT
UNION ALL SELECT 'main_snapshots', (SELECT count(*) FROM line)::TEXT
UNION ALL SELECT 'main_not_derived', (SELECT count(*) FROM line JOIN root r USING (project_id) WHERE line.change_id IS NULL AND line.n < r.n)::TEXT
UNION ALL SELECT 'change_twice_on_main', (SELECT coalesce(sum(n - 1), 0) FROM (SELECT count(*) AS n FROM line WHERE change_id IS NOT NULL GROUP BY project_id, change_id HAVING count(*) > 1) x)::TEXT
UNION ALL SELECT 'setup_snapshots', (SELECT count(*) FROM line JOIN oldest o USING (project_id) WHERE NOT line.ticketed AND line.n > o.n)::TEXT
UNION ALL SELECT 'main_without_ticket', (SELECT count(*) FROM line JOIN oldest o USING (project_id) WHERE NOT line.ticketed AND line.n < o.n)::TEXT
UNION ALL SELECT 'landings_before_stop', (SELECT count(*) FROM done WHERE t < :STOP)::TEXT
UNION ALL SELECT 'landings_after_stop', (SELECT count(*) FROM done WHERE t >= :STOP)::TEXT
UNION ALL SELECT 'first_landing_after_stop_ms', (SELECT coalesce(((min(t) - :STOP) / 1000)::TEXT, '') FROM done WHERE t >= :STOP)
UNION ALL SELECT 'longest_gap_after_stop_ms', (SELECT coalesce((max(gap) / 1000)::TEXT, '') FROM gaps WHERE t >= :STOP AND t <= :STOP + 120000000)
UNION ALL SELECT 'longest_gap_before_stop_ms', (SELECT coalesce((max(gap) / 1000)::TEXT, '') FROM gaps WHERE t < :STOP AND t >= :STOP - 30000000);
