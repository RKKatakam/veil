-- The landing lease of `main` in the failover run's project(s): who holds
-- it and its fencing epoch (landing/service.rs `take_lease`: the epoch
-- rises at every take). :T0 is the run's start on the database's clock (µs).
SELECT string_agg(l.holder || ' epoch ' || l.epoch, '; ' ORDER BY l.project_id)
FROM landing_leases l
WHERE l.branch = 'main'
  AND l.project_id IN (SELECT DISTINCT project_id FROM landing_queue WHERE created_at >= :T0);
