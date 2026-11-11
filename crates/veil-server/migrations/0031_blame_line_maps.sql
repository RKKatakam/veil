-- Kept blames written before BUG-1893's fix may give a line to the wrong
-- change (the server's line maps differed from the engine's `map_lines`
-- at a last line without its newline, and at a changed line equal to an
-- unchanged one further on), and later blames of a file start from them.
-- They are a cache (0015_file_history_and_blame.sql): emptied here, and
-- kept again by the next blame job of each file. `TRUNCATE`, whose time
-- does not grow with the table (BUG-1383); idempotent. (`blame_paths`,
-- the paths they name, stays: a path's key never changes.)
TRUNCATE blame_memo;
