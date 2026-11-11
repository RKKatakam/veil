# rc-client notes
- BUG-1930 filed: conflict in a renamed secret resolved in own change → server refuses (server confirmed on PG).
- restore of a renamed secret from history (carried_sealed): recorded plain at once (vl files shows public) → no server refusal. Sound.
- BUG-1931 filed: sandbox guard (BUG-1840 fix) discards edits to files that already held a sealed file's non-secret value.
- BUG-1932 filed: sandbox guard misses sealed secrets in conflict (sealed_files_in_tree Conflict arm dead).
- BUG-1910 move checked on a moved tip with later change, dirty wc, workspace: all kept as conflicts; undo restores (server run srv6). Other members see a landed snapshot without predecessors (srv5) → no hostile supersede by a member.
- Revert experiments: reconcile off → bug_1911 x4, bug_1833 squash, halves property fail; writer's walk back → bug_1897 x2 fail.
- Sound by test/experiment: restore of a renamed secret (recorded plain); sparse sandbox socket (show/diff/log/blame/--follow/-S/-G: nothing outside src/); file modes 0600 for checkout/resolve/undo/new/ws switch of sealed + conflicted sealed; BUG-1831 sampler on ~110 realistic patterns (only `[é]x` flagged); BUG-1830 heads after squash/abandon/split/rebase/undo.
- Sound by reading: pin per authority (update_entry(authority)), only `vl login` accepts a new key; web-enroll signature: own context, hub name + single-use challenge bound; BUG-1874 no env token; api.rs blame/log_entries_with merge; BUG-1835; BUG-1836/1837 attempts (duplicate/split clear attempts); BUG-1573 NOT_RUN (command never run twice).
- Not reached: thin-clone server blame --follow inside a sparse sandbox (origin path names outside --only?); attempts that edited a folder later lost (move_to_view → rebase_attempts); id-prefix revisions from a sandbox on a thin clone under --no-network (server resolve after the local check).
