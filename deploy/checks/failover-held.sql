-- Is `main`'s landing lease held now in the failover run's project(s), and
-- are landings flowing? `holder|landed`: the holder of the unexpired lease
-- (empty while none holds it; landing/service.rs `take_lease`: a name random
-- per server start, which each server's stats.json gives as
-- `landing_holder`) and the run's tickets landed so far. :T0 is the run's
-- start on the database's clock (µs).
WITH p AS (SELECT DISTINCT project_id FROM landing_queue WHERE created_at >= :T0)
SELECT COALESCE((SELECT string_agg(l.holder, ';' ORDER BY l.project_id) FROM landing_leases l
                 WHERE l.branch = 'main' AND l.project_id IN (SELECT project_id FROM p)
                   AND l.expires_at >= (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT), ''),
       (SELECT count(*) FROM landing_queue WHERE project_id IN (SELECT project_id FROM p) AND branch = 'main' AND state = 'landed');
