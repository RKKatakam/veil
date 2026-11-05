# Review evals: bugs that escaped a merged review

Each row is a bug a merged branch introduced and review missed. Whenever the review process changes (the `veil-review` skill, an agent brief, `verify-fast.sh`), check the new process against every row: would it catch the bug now?

Add a row for every escape, and name the layer that should have caught it (see the skill's "Layers, not one gate").

| # | Escape | Introduced by | Where | Should have been caught by | Now caught by |
|---|---|---|---|---|---|
| 1 | Merging the performance wave with the sealing fixes dropped `verified_visibility` from `change()` | a hand-resolved merge conflict | `crates/veil-core/src/api.rs` (`change()`) | step 6: never hand-resolve a semantic conflict; re-review a hand resolution | skill step 6.1 |
| 2 | Format-5 tree kinds (symlink, gitlink) not handled in patch code | the Git-parity stream P branch, based on a commit before format 5 | `crates/veil-core/src/patch.rs` | lens 2 (every new enum kind in every match); checking the merge base | skill lens 2, plus "Lessons" |
| 3 | Git-only date helpers broke the WASM build | Git-parity stream P | `crates/veil-core/src/patch.rs` | layer 4 (check-wasm on every `veil-core` merge) | `verify-fast.sh` runs check-wasm |
| 4 | BUG-759: after a soft reset following a hostile pull, the pulled policy is pinned as the member's own | the colocated fix wave (the BUG-740 fix covered only pulls still in `HEAD`) | colocated policy pin (`crates/vl/src/colocate_cmd.rs`, `crates/veil-core/src/wc_policy.rs`) | lens 2 (fix the bug's whole class); layer 7 (deep randomized property run) | `deep-props.sh` once per round; pinned regression test |
