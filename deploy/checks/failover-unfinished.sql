-- Tickets of the failover run still waiting to land (queued, or held by a merge).
SELECT count(*) FROM landing_queue
WHERE created_at >= :T0 AND branch = 'main' AND state IN ('queued', 'merging');
