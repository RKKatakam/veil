# rc-client notes
- BUG-1930 filed: conflict in a renamed secret resolved in own change → server refuses (server confirmed on PG).
- restore of a renamed secret from history (carried_sealed): recorded plain at once (vl files shows public) → no server refusal. Sound.
- BUG-1931 filed: sandbox guard (BUG-1840 fix) discards edits to files that already held a sealed file's non-secret value.
- BUG-1932 filed: sandbox guard misses sealed secrets in conflict (sealed_files_in_tree Conflict arm dead).
