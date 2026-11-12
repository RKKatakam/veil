-- 't' once the tip of every failover project's `main` is in the derived
-- graph (the deriver writes a branch's history in order, so its ancestors are too).
SELECT bool_and(EXISTS (SELECT 1 FROM graph g WHERE g.project_id = b.project_id AND g.snapshot = b.target))
FROM branches b
WHERE b.name = 'main'
  AND b.project_id IN (SELECT DISTINCT project_id FROM landing_queue WHERE created_at >= :T0);
