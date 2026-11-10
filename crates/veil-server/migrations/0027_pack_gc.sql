-- Pack compaction and garbage collection (S29, docs/HUB.md §13.37):
--   * packs.discarded_at: when a pack turned discarded (state = 2), so the
--     sweep deletes its storage object and row after the grace window;
--   * unreferenced_objects: when an object of a project was first seen
--     unreferenced, so nothing is deleted inside the retention window
--     (thin clones hold no server anchors, and a push may be about to
--     reference an object it uploaded or probed).
ALTER TABLE packs ADD COLUMN IF NOT EXISTS discarded_at BIGINT;

CREATE TABLE IF NOT EXISTS unreferenced_objects (
    project_id BIGINT NOT NULL REFERENCES projects(id),
    object_id TEXT NOT NULL,
    since_ms BIGINT NOT NULL,
    PRIMARY KEY (project_id, object_id)
);
