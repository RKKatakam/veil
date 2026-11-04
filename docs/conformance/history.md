# Conformance: history, diff, merge and rewriting

Veil checked against the history-related parts of Git's and Jujutsu's test
suites: what `vl diff`, `vl log`, revisions, `vl merge`, `vl rebase`,
`vl squash`, `vl abandon`, `vl describe`, `vl edit`, `vl evolog` and the
op log do, compared with `git diff/log/rev-list/merge/rebase` and jj's
equivalents, plus Veil-only variants of the same scenarios with cloaked,
isolated and embargoed content.

Tests: `crates/vl/tests/conformance_history/` (one binary; modules `diff`,
`log`, `revisions`, `merge`, `rewrite`, `veil_angles`). Run them with
`cargo test -p vl --test conformance_history`, and the bug reproductions
with `-- --ignored`. Baseline: `integration` @ `8dbdb61`.

## Summary

* **201 tests**: 187 pass, 14 are `#[ignore]`d bug reproductions (all 14
  fail when run with `--ignored`). The whole binary runs in about 2 s.
* **12 bugs** (BUG-240 … BUG-251; details in `docs/BUGS.md`, section
  "Conformance findings: history, diff, merge and rewriting"):
  * high: **BUG-251**. Auto-rebasing a merge when one of its parents moves
    drops files that the other parent still has. The merge is rebased one
    parent at a time; nothing warns.
  * medium: **BUG-244** (a criss-cross merge silently takes one side's
    resolution), **BUG-243** (a file/directory conflict silently drops the
    directory side's files), **BUG-247** (a second `vl undo` redoes,
    whereas the guide says "go further back"), **BUG-249** (an embargoed
    merge stores the fix's plaintext as an unreferenced public blob).
  * low: BUG-240 (duplicate parents from `vl merge X --into X` / `vl new
    X X`), BUG-241 (`vl diff` shows nothing for an executable-bit change),
    BUG-242 (`vl diff -r A --from B` ignores `-r`), BUG-245 (`vl show`
    doesn't mention recorded conflicts), BUG-246 (no-op rebase/describe
    rewrites and re-signs descendants), BUG-248 (`vl push` doesn't record
    `origin/<tag>`), BUG-250 (the guide says squashing a resolution keeps
    the conflict mark; it clears it).
* **Held:** every Veil-specific merge/rewrite scenario kept cloaked
  plaintext out of everything an outsider can read: conflict markers in
  cloaked files, a policy change racing a public edit, rebases of cloaked
  lines and of `.veilpolicy` edits (including a conflicted
  `.veilpolicy`), squash and abandon across cloak boundaries, embargoed
  merges that are reworded, squashed into, rebased onto, abandoned and
  undone, and non-member `diff`/`show`/`log`. Isolated files and
  quarantined secrets were never recorded by a rewrite. Change ids were
  stable across every rewrite, and undo/`op restore` restored the exact
  prior view (graph, tags, workspaces) after rebase, squash, abandon,
  describe and merge.

### Deliberate differences (documented Veil behaviour, not bugs)

* **No staging, no `--continue`/`--abort`.** Conflicts never stop a merge or
  rebase: they are recorded on the snapshot (`×`, `(conflict)`) with diff3
  markers (`<<<<<<< ours`, `||||||| original`, `=======`, `>>>>>>> theirs`)
  and cleared by editing the file in the conflicted change (or by squashing
  a resolution into it). Git's t3418 (`--continue`), t3407 (`--abort`) and
  t3403 (`--skip`) have no equivalent; `vl undo` is the abort.
* **Modify/delete and binary conflicts** keep the surviving side, or ours
  for binaries, unmarked but flagged, like Git's working tree. **D/F**
  conflicts do the same, but drop the other side (BUG-243).
* **Merging an ancestor or a descendant** still records a merge snapshot
  (no "Already up to date", no fast-forward), like `jj new A B`. The
  content is the expected one (`merging_an_ancestor_changes_no_content`,
  `merging_a_descendant_takes_its_content`).
* **A change emptied by a rebase is kept** (empty, with its description),
  like jj without `--skip-emptied`; Git drops it.
* **`vl commit` and `vl merge` move tags** at the parent / destination
  (documented "pitfall"); rebase, squash, abandon and describe make tags
  follow their change.
* **Abandoning a merge** reparents its children onto both of the merge's
  parents (jj semantics). Abandoning an embargoed merge therefore turns
  its child into a plain merge of the cloaked fix line, which stays sealed.
* **Revisions are deliberately minimal** in 1.0: `@`, `name@`, tags, remote
  tags, change/snapshot id prefixes, `root`, `X-`. There are no ranges,
  `::`, `|`, functions, `~N` or `^`; all of them are rejected cleanly
  (`revset_operators_are_rejected_not_misread`). There is no `log --
  PATH`, no `diff -- PATH` and no output templates.
* **The diff of a conflicted merge is empty** (relative to the auto-merged
  parents, which already hold the markers), as in jj; the resolution
  shows up as the next change's diff.
* **Files written before `vl cloak` are recorded publicly** by the automatic
  snapshot that `vl cloak` itself takes first. The guide says to set the
  policy before the next command. The Veil tests cloak first, then write.
* **On an unreleased embargoed line, conflicts are not recorded** in snapshot
  metadata (only reported and left as markers), by design (ARCHITECTURE §7).

## Pending features (acceptance scenarios for the feature wave)

The Git-parity round built rename and copy detection (in `diff`, `show`,
`status` and `log --follow`; not yet in merges), path-limited `log`, the
`-r` ranges `A..B`, `::B`, `..B` and `A..`, blame, `log -S`/`-G`, `grep` and
bisect (`crates/vl/tests/history_cli.rs`,
`crates/veil-core/tests/history_tools.rs`, `history_rename.rs`). Their
scenarios below are still to port; until then their rows keep the status
`pending feature`.

| Feature | Scenarios to port when it lands |
|---|---|
| Rename / copy detection | t4001, t4003, t4005, t4007, t4008, t4009, t4023, t4043, t4206, t4219 (`log --follow`), t6402, t6412, t6414, t6422, t6423, t6425, t6429, t6434, t3401, t4130; jj test_diff_renamed_file_and_dir, test_diff_rename_in_merge_commit. Veil detects renames in diffs, status and `log --follow`; a rename on one side of a merge plus an edit on the other is still a modify/delete conflict. |
| Path-limited diff and log (`diff -- PATH`, `log -- PATH`) | t4010, t4045 (`--relative`), t4208, t4216 (bloom), t6004, t6012, t6016, t6111, t6130–t6137 (pathspecs); jj test_log_filtered_by_path, test_diff_relative_paths. |
| Revset language (ranges, ancestry, set operators, functions) | t6000, t6003 (`--topo-order`/`--date-order` choices), t6005 (`--count`), t6009, t6013 (`--reverse`), t6014 (`--all`), t6017, t6018 (globs), t6019 (`--ancestry-path`), t6100, t6600 (reachability); jj test_revset_output.rs, lib test_revset.rs, test_revset_optimized.rs, test_default_revset_graph_iterator.rs. |
| Log/diff output formats and templates | t4205, t4207, t4026, t4013 option matrix (`--name-only`, `--name-status`, `-p --stat` combos), t4047 (dirstat), t4049, t4052, t4073 (stat widths); jj template tests in test_log_command.rs and test_evolog_command.rs. |
| Diff algorithms and whitespace options | t4033 (patience), t4050 (histogram), t4065 (anchored), t4071 (minimal), t4061 (indent heuristic), t4015 `-w`/`-b` options, t4032, t4055 (`-U`), t4051 (function context), t4018/t4025 (hunk headers), t4034 (word diff); jj test_diff_ignore_whitespace, test_diff_color_words*, test_diff_skipped_context*. |
| Blame / annotate | t8001–t8015, t8020; jj test_file_annotate_command.rs. |
| Cherry-pick, duplicate, revert/backout | t3500–t3514; jj test_duplicate_command.rs, test_revert_command.rs, lib test_rewrite_duplicate.rs. |
| Splitting and absorbing changes | t3452 (`history split`); jj test_split_command.rs (non-interactive `split PATHS` would map), test_absorb_command.rs, test_parallelize_command.rs, test_diffedit_command.rs. |
| Rebase variants (`--insert-after/before`, `-r` without descendants, multiple sources, `--skip-emptied`) | t3421 (`--keep-empty`), t3424; jj test_rebase_after, test_rebase_before, test_rebase_after_before, test_rebase_multiple_revisions, test_rebase_skip_emptied*, test_rebase_simplify_parents. |
| `squash --from/--into/--keep-emptied`, partial squash | jj test_squash_from_to*, test_squash_from_multiple*, test_squash_keep_emptied, test_squash_partial, test_squash_to_new_commit. |
| `simplify-parents`, `next`/`prev` | jj test_simplify_parents_command.rs, test_next_prev_commands.rs. Today `vl edit`/`vl new X` are the manual equivalents, and BUG-240 shows duplicate parents are not simplified. |
| Interactive conflict resolution (`resolve` with a merge tool) | jj test_resolve_command.rs (tool-driven parts); the edit-the-file parts are ported. |
| Git tags / `describe` | t6120 (no annotated tags in Veil 1.0). |
| Symlinks | t4004, t4011, t4115, t4122, t6405, t6415, jj test_diff_external_tool_symlink. |
| CRLF / attributes / textconv | t4030, t4042, t6406, t6413 (`text=auto`), t6418, t8006, t8007, t8010. Byte-exact CRLF merging is ported (`crlf_files_merge`). |
| `fix` (formatters over history) | jj test_fix_command.rs. |
| Bisect | t6002, t6030, t6041. |

## Git t4xxx: diff, log, patches

| Script | Status | Veil tests / reason |
|---|---|---|
| t4000-diff-format | ported | `diff::modified_line_shows_minus_and_plus`, `added_and_deleted_files_are_labelled` |
| t4001-diff-rename | pending feature | rename detection |
| t4002-diff-basic | ported | `diff::added_and_deleted_files_are_labelled`, `diff_from_to_and_its_reverse` (tree-to-tree comparison); the index/plumbing half is not applicable |
| t4003-diff-rename-1 | pending feature | rename detection |
| t4004-diff-rename-symlink | pending feature | rename detection, symlinks |
| t4005-diff-rename-2 | pending feature | rename detection |
| t4006-diff-mode | ported | `diff::mode_only_change_is_listed_by_stat`, `removing_the_executable_bit_is_recorded`, `mode_only_change_is_described_in_the_diff` (BUG-241) |
| t4007-rename-3 | pending feature | rename/copy detection |
| t4008-diff-break-rewrite | pending feature | rename detection (break/rewrite pairing) |
| t4009-diff-rename-4 | pending feature | rename detection |
| t4010-diff-pathspec | pending feature | path-limited diff |
| t4011-diff-symlink | pending feature | symlinks |
| t4012-diff-binary | ported | `diff::binary_change_is_summarised`, `added_binary_file_is_summarised`, `stat_lists_binary_and_text_changes` (no binary patches: `--binary` not applicable) |
| t4013-diff-various | ported | `diff::distant_edits_make_separate_hunks`, `deep_paths_are_diffed`, `show_prints_metadata_then_the_diff`, `diff_r_shows_that_changes_own_diff`, `latin1_text_is_diffed`; the option matrix is a pending feature (formats) |
| t4014-format-patch | not applicable | no mail/patch tools |
| t4015-diff-whitespace | ported | `diff::whitespace_only_edits_are_shown`, `line_ending_change_is_shown`; `-w`/`-b` options pending |
| t4016-diff-quote | ported | `diff::unusual_names_appear_in_the_diff`, `newline_in_a_file_name_is_escaped`, `escape_sequences_in_content_are_neutralised` |
| t4017-diff-retval | ported | `diff::diff_of_an_empty_working_copy_says_no_changes`, `diff_of_a_snapshot_with_itself_is_empty` (no `--exit-code` option: not applicable) |
| t4018-diff-funcname | pending feature | hunk-header function context |
| t4019-diff-wserror | not applicable | whitespace-error highlighting config |
| t4020-diff-external | not applicable | external diff drivers |
| t4021-format-patch-numbered | not applicable | mail tools |
| t4022-diff-rewrite | ported | `diff::file_emptied_and_filled` |
| t4023-diff-rename-typechange | pending feature | rename detection, symlinks |
| t4024-diff-optimize-common | ported | `diff::large_file_with_one_edit` (minimal output on a large file) |
| t4025-hunk-header | pending feature | hunk-header context |
| t4026-color | not applicable | colour config (Veil: `NO_COLOR`, no colour off a TTY) |
| t4027-diff-submodule | not applicable | submodules |
| t4028-format-patch-mime-headers | not applicable | mail tools |
| t4029-diff-trailing-space | ported | `diff::tabs_survive_in_diff_lines`, `whitespace_only_edits_are_shown` |
| t4030-diff-textconv | pending feature | attributes/textconv |
| t4031-diff-rewrite-binary | ported | `diff::text_turned_binary_is_summarised` |
| t4032-diff-inter-hunk-context | pending feature | context options; default behaviour in `nearby_edits_share_one_hunk` |
| t4033-diff-patience | ported | `diff::large_file_with_one_edit` (default algorithm); `--patience` pending |
| t4034-diff-words | pending feature | word diff |
| t4035-diff-quiet | not applicable | `--quiet`/exit-code options |
| t4036-format-patch-signer-mime | not applicable | mail tools |
| t4037-diff-r-t-dirs | ported | `diff::file_replaced_by_directory`, `directory_replaced_by_file` |
| t4038-diff-combined | ported | `diff::diff_of_a_clean_merge_is_empty`, `diff_of_a_conflicted_merge_and_its_resolution` (no combined format: deliberate) |
| t4039-diff-assume-unchanged | not applicable | index flags |
| t4040-whitespace-status | not applicable | index-based whitespace status |
| t4041-diff-submodule-option | not applicable | submodules |
| t4042-diff-textconv-caching | pending feature | textconv |
| t4043-diff-rename-binary | pending feature | rename detection |
| t4044-diff-index-unique-abbrev | not applicable | object-id abbreviation in patch headers (Veil headers carry no ids) |
| t4045-diff-relative | pending feature | path-relative diff |
| t4046-diff-unmerged | not applicable | index unmerged stages |
| t4047-diff-dirstat | pending feature | output formats |
| t4048-diff-combined-binary | ported | `merge::binary_conflict_keeps_ours_without_markers` (what a binary merge produces) |
| t4049-diff-stat-count | pending feature | stat options |
| t4050-diff-histogram | pending feature | diff algorithms |
| t4051-diff-function-context | pending feature | function context |
| t4052-stat-output | pending feature | stat widths/graphs (`--stat` is a name list in Veil) |
| t4053-diff-no-index | not applicable | diffing files outside a repository |
| t4054-diff-bogus-tree | not applicable | hostile tree objects are covered by the storage/fsck suites |
| t4055-diff-context | ported | `diff::nearby_edits_share_one_hunk`; `-U` pending |
| t4056-diff-order | not applicable | orderfile config |
| t4057-diff-combined-paths | not applicable | combined-diff format |
| t4058-diff-duplicates | not applicable | duplicate tree entries are refused by tree validation (storage suites) |
| t4059-diff-submodule-not-initialized | not applicable | submodules |
| t4060-diff-submodule-option-diff-format | not applicable | submodules |
| t4061-diff-indent | pending feature | indent heuristic |
| t4062-diff-pickaxe | pending feature | pickaxe search (`-S`/`-G`) |
| t4063-diff-blobs | not applicable | plumbing blob diff |
| t4064-diff-oidfind | not applicable | plumbing |
| t4065-diff-anchored | pending feature | diff algorithms |
| t4066-diff-emit-delay | not applicable | internal emit buffering |
| t4067-diff-partial-clone | not applicable | partial clone |
| t4068-diff-symmetric-merge-base | pending feature | revset ranges (`A...B`) |
| t4069-remerge-diff | pending feature | remerge-diff output |
| t4070-diff-pairs | not applicable | plumbing |
| t4071-diff-minimal | pending feature | diff algorithms |
| t4072-diff-max-depth | not applicable | plumbing option |
| t4073-diff-stat-name-width | pending feature | stat widths |
| t4074-diff-shifted-matched-group | pending feature | diff algorithm tuning |
| t4100–t4141 (apply) | not applicable | `git apply` / patch application: no patch tools in Veil |
| t4150–t4153, t4252–t4258 (am) | not applicable | mailbox application |
| t4200-rerere | not applicable | rerere |
| t4201-shortlog | not applicable | shortlog/mailmap summaries |
| t4202-log | ported | `log::log_of_a_fresh_repository`, `log_limit_elides_the_rest`, `log_labels_tags_workspaces_and_empty_changes`, `log_shows_placeholder_for_blank_descriptions`, `log_marks_conflicted_snapshots`, `log_hides_abandoned_and_rewritten_snapshots`; path filtering pending |
| t4203-mailmap | not applicable | mailmap |
| t4204-patch-id | not applicable | patch ids |
| t4205-log-pretty-formats | ported | `log::log_escapes_control_characters_in_descriptions`; formats pending |
| t4206-log-follow-harder-copies | pending feature | copy detection |
| t4207-log-decoration-colors | not applicable | colour config |
| t4208-log-magic-pathspec | pending feature | path-limited log |
| t4209-log-pickaxe | pending feature | pickaxe |
| t4210-log-i18n | not applicable | commit encodings (Veil descriptions are UTF-8) |
| t4211-line-log | pending feature | line-range log (blame family) |
| t4212-log-corrupt | not applicable | corrupt objects are the storage/fsck suites' area |
| t4213-log-tabexpand | not applicable | pretty-format tab expansion |
| t4214-log-graph-octopus | ported | `log::log_names_the_parents_of_a_merge` |
| t4215-log-skewed-merges | ported | `log::log_of_skewed_crossing_merges` |
| t4216-log-bloom | pending feature | path-limited log |
| t4217-log-limit | ported | `log::log_limit_zero`, `log_limit_must_be_a_number` |
| t4218-log-graph-indentation | ported | `log::log_of_skewed_crossing_merges`, `log_with_many_heads` |
| t4219-log-follow-merge | pending feature | rename following |
| t4300-merge-tree | ported | the merge engine through `vl merge` (`merge::*`); the plumbing command itself is not applicable |
| t4301-merge-tree-write-tree | ported | as t4300 (`merge::disjoint_edits_in_one_file_merge_cleanly`, `same_line_conflict_writes_diff3_markers`, `file_directory_conflict_is_flagged`) |

## Git t6xxx: revision walking, merging

| Script | Status | Veil tests / reason |
|---|---|---|
| t6000-rev-list-misc | ported | `revisions::revset_operators_are_rejected_not_misread`; ranges pending |
| t6001-rev-list-graft | not applicable | grafts |
| t6002-rev-list-bisect | pending feature | bisect |
| t6003-rev-list-topo-order | ported | `log::log_is_in_topological_order` |
| t6004-rev-list-path-optim | pending feature | path-limited log |
| t6005-rev-list-count | pending feature | revsets (`--count`) |
| t6006-rev-list-format | pending feature | log templates |
| t6007-rev-list-cherry-pick-file | pending feature | cherry-pick, path limiting |
| t6008-rev-list-submodule | not applicable | submodules |
| t6009-rev-list-parent | ported | `revisions::dash_suffix_walks_first_parents`, `dash_of_a_merge_is_its_first_parent`; `--min/max-parents` pending (revsets) |
| t6010-merge-base | ported | `revisions::merge_uses_the_nearest_common_ancestor`; criss-cross bases: `merge::criss_cross_*` (BUG-244) |
| t6011-rev-list-with-bad-commit | not applicable | corrupt objects (storage suites) |
| t6012-rev-list-simplify | pending feature | path-limited history simplification |
| t6013-rev-list-reverse-parents | pending feature | revsets (`--reverse`) |
| t6014-rev-list-all | pending feature | revsets (`--all`); `vl log` always shows every visible snapshot |
| t6016-rev-list-graph-simplify-history | pending feature | path-limited graph |
| t6017-rev-list-stdin | not applicable | plumbing stdin |
| t6018-rev-list-glob | pending feature | revsets (globs) |
| t6019-rev-list-ancestry-path | pending feature | revsets |
| t6020-bundle-misc | not applicable | bundles |
| t6021-rev-list-exclude-hidden | not applicable | hidden refs |
| t6022-rev-list-missing | not applicable | missing objects (storage suites) |
| t6030-bisect-porcelain | pending feature | bisect |
| t6040-tracking-info | not applicable | upstream tracking (remote tags are the remotes suite's area; see BUG-248) |
| t6041-bisect-submodule | not applicable | submodules |
| t6050-replace | not applicable | replace refs |
| t6060-merge-index | not applicable | index |
| t6099-merge-base-side-exhaustion | ported | `revisions::merge_uses_the_nearest_common_ancestor`, `merge::criss_cross_merge_with_agreeing_resolutions_is_clean` |
| t6100-rev-list-in-order | pending feature | revset ordering options |
| t6101-rev-parse-parents | ported | `revisions::dash_suffix_walks_first_parents`, `walking_past_the_root_fails`, `dash_of_a_merge_is_its_first_parent` (`^N`/`~N` are not Veil syntax: rejected) |
| t6102-rev-list-unexpected-objects | not applicable | hostile objects (storage suites); `vl tag set` / revisions only accept snapshots |
| t6110-rev-list-sparse | pending feature | path-limited history |
| t6111-rev-list-treesame | pending feature | path-limited history |
| t6112-rev-list-filters-objects | not applicable | partial clone filters |
| t6113-rev-list-bitmap-filters | not applicable | bitmaps |
| t6114-keep-packs | not applicable | pack internals |
| t6115-rev-list-du | not applicable | disk usage plumbing |
| t6120-describe | pending feature | Git tags (no annotated tags in 1.0) |
| t6130–t6137 (pathspec) | pending feature | path-limited commands |
| t6200-fmt-merge-msg | ported | `merge::merge_message_defaults_to_the_merged_revisions` (Veil's default message is `merge REVS`) |
| t6300–t6302 (for-each-ref) | not applicable | ref plumbing (`vl tag list` is the everyday-commands suite's area) |
| t6400-merge-df | ported | `merge::file_directory_conflict_is_flagged`, `directory_file_conflict_is_flagged`, `deleted_file_replaced_by_directory_merges`, `file_directory_conflict_keeps_both_sides_content` (BUG-243), `rewrite::rebase_across_a_file_directory_swap` |
| t6401-merge-criss-cross | ported | `merge::criss_cross_merge_with_different_resolutions_conflicts` (BUG-244), `criss_cross_merge_with_agreeing_resolutions_is_clean` |
| t6402-merge-rename | pending feature | rename detection |
| t6403-merge-file | ported | `merge::disjoint_edits_in_one_file_merge_cleanly`, `no_trailing_newline_merges`, `no_trailing_newline_conflict_has_markers`, `large_file_merge` |
| t6404-recursive-merge | ported | `merge::criss_cross_*` (recursive bases) |
| t6405-merge-symlinks | pending feature | symlinks |
| t6406-merge-attr | pending feature | attributes / merge drivers |
| t6407-merge-binary | ported | `merge::binary_conflict_keeps_ours_without_markers`, `binary_changed_on_one_side_is_clean` |
| t6408-merge-up-to-date | ported | `merge::identical_changes_on_both_sides_are_clean`, `merging_an_ancestor_changes_no_content`, `merging_a_descendant_takes_its_content` |
| t6409-merge-subtree | not applicable | subtree strategy |
| t6411-merge-filemode | ported | `merge::mode_change_and_content_change_combine`, `mode_change_on_one_side_merges` |
| t6412-merge-large-rename | pending feature | rename detection |
| t6413-merge-crlf | ported | `merge::crlf_files_merge` (byte-exact; no autocrlf) |
| t6414-merge-rename-nocruft | pending feature | rename detection |
| t6415-merge-dir-to-symlink | pending feature | symlinks |
| t6416-recursive-corner-cases | ported | `merge::emptied_file_against_an_edit_conflicts`, `criss_cross_*`; rename corner cases pending |
| t6417-merge-ours-theirs | not applicable | `-X ours/theirs` strategy options (no strategy options in Veil) |
| t6418-merge-text-auto | pending feature | attributes |
| t6419-merge-ignorecase | not applicable | case-folding filesystems are the working-copy suite's area |
| t6421-merge-partial-clone | not applicable | partial clone |
| t6422-merge-rename-corner-cases | pending feature | rename detection |
| t6423-merge-rename-directories | pending feature | rename detection |
| t6424-merge-unrelated-index-changes | not applicable | index |
| t6425-merge-rename-delete | pending feature | rename detection |
| t6426-merge-skip-unneeded-updates | ported | `merge::ignored_file_in_the_way_is_not_clobbered`, `isolated_file_survives_a_merge` (untouched files are not rewritten) |
| t6427-diff3-conflict-markers | ported | `merge::same_line_conflict_writes_diff3_markers`, `veil_angles::merge_conflict_in_a_cloaked_file_stays_sealed` |
| t6428-merge-conflicts-sparse | not applicable | sparse checkout |
| t6429-merge-sequence-rename-caching | pending feature | rename detection |
| t6430-merge-recursive | ported | `merge::changes_to_different_files_merge_cleanly`, `add_add_*`, `modify_delete_*`, `delete_modify_*`, `delete_delete_is_clean`, `octopus_*`, `unrelated_lines_*`, `both_sides_add_files_in_the_same_new_directory`, `conflicts_in_unusual_names` |
| t6431-merge-criscross | ported | `merge::criss_cross_merge_with_different_resolutions_conflicts` (BUG-244) |
| t6432-merge-recursive-space-options | pending feature | whitespace merge options |
| t6433-merge-toplevel | ported | `merge::merge_into_a_non_empty_working_copy_merges_into_it`, `merge_moves_tags_at_the_destination_only` (merge from the CLI; octopus in t6430) |
| t6434-merge-recursive-rename-options | pending feature | rename detection |
| t6435-merge-sparse | not applicable | sparse checkout |
| t6436-merge-overwrite | ported | `merge::ignored_file_in_the_way_is_not_clobbered`, `isolated_file_survives_a_merge`, `veil_angles::isolated_file_survives_rebase_squash_and_abandon` |
| t6437-submodule-merge | not applicable | submodules |
| t6438-submodule-directory-file-conflicts | not applicable | submodules (the D/F half: `merge::file_directory_*`) |
| t6439-merge-co-error-msgs | ported | `merge::merge_of_an_unknown_revision_records_nothing` |
| t6500-gc, t6501-freshen-objects | not applicable here | gc is covered by the remotes/storage conformance suite |
| t6600-test-reach | pending feature | revsets (reachability queries) |
| t6601-path-walk | not applicable | pack path-walk internals |
| t6700-tree-depth | not applicable | tree depth limits (storage suites; merge depth is guarded by `MAX_TREE_DEPTH`) |

## Git t34xx (rebase, history) and t35xx (cherry-pick, revert)

| Script | Status | Veil tests / reason |
|---|---|---|
| t3400-rebase | ported | `rewrite::rebase_moves_a_change_and_keeps_its_change_id`, `rebase_onto_a_descendant_or_itself_is_refused`, `conflicting_rebase_records_the_conflict`, `rebase_onto_a_conflicted_change`, `veil_angles::rebase_conflict_in_a_cloaked_file_stays_sealed` |
| t3401-rebase-and-am-rename | pending feature | rename detection |
| t3402-rebase-merge | ported | `rewrite::conflicting_rebase_records_the_conflict`, `descendants_of_a_conflicted_rebase_follow` (Veil always rebases by three-way merge) |
| t3403-rebase-skip | not applicable | no sequencer; conflicts never stop a rebase |
| t3404-rebase-interactive | ported (non-interactive parts) | `rewrite::editing_an_older_change_rebases_descendants` (edit), `squash_a_middle_change` (squash), `abandon_a_middle_change_rebases_descendants` (drop), `describe_an_ancestor_rebases_descendants_with_stable_ids` (reword); the todo-list UI is not applicable |
| t3405-rebase-malformed | ported | `rewrite::multi_line_descriptions_survive_a_rebase` (descriptions are not re-parsed); malformed commit objects are not applicable |
| t3406-rebase-message | ported | `rewrite::rebase_moves_a_change_and_keeps_its_change_id` (`Rebased …` output) |
| t3407-rebase-abort | ported | `rewrite::undo_restores_the_state_before_a_rebase` (undo is the abort) |
| t3408-rebase-multi-line | ported | `rewrite::multi_line_descriptions_survive_a_rebase` |
| t3409-rebase-environ | not applicable | hook environment |
| t3412-rebase-root | ported | `rewrite::rebasing_the_root_is_refused`, `rebase_onto_the_root_keeps_only_the_changes_own_diff`, `squashing_into_the_root_is_refused` |
| t3413-rebase-hook | not applicable | hooks |
| t3415-rebase-autosquash | ported | `rewrite::squash_a_middle_change`, `squash_folds_the_working_copy_into_its_parent` (fixup as an explicit squash) |
| t3416-rebase-onto-threedots | pending feature | revset ranges (`A...B`) |
| t3417-rebase-whitespace-fix | not applicable | whitespace fixing on apply |
| t3418-rebase-continue | not applicable | no sequencer |
| t3419-rebase-patch-id | pending feature | patch-id dropping of already-applied changes; Veil keeps them empty (`change_already_upstream_becomes_empty`) |
| t3420-rebase-autostash | not applicable | no stash needed: the working copy is a change (`rebase_without_source_moves_the_working_copy`) |
| t3421-rebase-topology-linear | ported | `rewrite::rebase_source_brings_its_descendants`, `change_already_upstream_becomes_empty` |
| t3422-rebase-incompatible-options | ported | `rewrite::rebase_with_unknown_revisions_fails` (missing `-d`); the option matrix is not applicable |
| t3423-rebase-reword | ported | `rewrite::describe_an_ancestor_rebases_descendants_with_stable_ids`, `veil_angles::describing_an_embargoed_merge_keeps_its_description_sealed`, `rewording_the_fix_after_the_embargoed_merge_keeps_the_embargo` |
| t3424-rebase-empty | ported | `rewrite::change_already_upstream_becomes_empty`, `squash_of_an_empty_change` |
| t3425-rebase-topology-merges | ported | `rewrite::rebase_a_merge_onto_one_destination`, `rebase_carries_a_descendant_merge` (BUG-251), `rebase_carries_a_descendant_merge_with_disjoint_files` |
| t3426-rebase-submodule | not applicable | submodules |
| t3427-rebase-subtree | not applicable | subtree |
| t3428-rebase-signoff | not applicable | trailers |
| t3429-rebase-edit-todo | not applicable | todo list |
| t3430-rebase-merges | ported | `rewrite::rebase_carries_a_descendant_merge*`, `rebase_onto_two_destinations_creates_a_merge` |
| t3431-rebase-fork-point | not applicable | reflog fork-point |
| t3432-rebase-fast-forward | ported | `merge::merging_a_descendant_takes_its_content`, `rewrite::rebase_onto_the_current_parent_is_a_no_op` (BUG-246) |
| t3433-rebase-across-mode-change | ported | `rewrite::rebase_across_a_mode_change` |
| t3434-rebase-i18n | not applicable | commit encodings |
| t3435-rebase-gpg-sign | not applicable | GPG (Veil signs every snapshot; signatures are another suite's area) |
| t3436-rebase-more-options | not applicable | committer-date and whitespace options |
| t3437-rebase-fixup-options | ported | `rewrite::squash_joins_descriptions` (Veil keeps both messages; no `amend!` forms) |
| t3438-rebase-broken-files | not applicable | broken todo/state files |
| t3440-rebase-trailer | not applicable | trailers |
| t3450-history | ported | `rewrite::each_rewrite_records_one_named_operation` |
| t3451-history-reword | ported | `rewrite::describe_an_ancestor_rebases_descendants_with_stable_ids`, `describe_with_the_same_message_is_a_no_op` (BUG-246) |
| t3452-history-split | pending feature | split |
| t3453-history-fixup | ported | `rewrite::squash_a_middle_change` |
| t3454-history-drop | ported | `rewrite::abandon_a_middle_change_rebases_descendants`, `abandon_under_a_dependent_edit_conflicts` |
| t3455-history-squash | ported | `rewrite::squash_*` |
| t3500–t3514 (cherry-pick, revert) | pending feature | cherry-pick / duplicate / revert (t3504 rerere, t3512/t3513 submodules, t3514 GPG: not applicable even then) |

## Git t8xxx (blame)

| Script | Status | Reason |
|---|---|---|
| t8001–t8015, t8020 | pending feature | blame / annotate (t8006/t8007/t8010 textconv and filters: attributes) |

## Jujutsu CLI tests

| File | Status | Veil tests / reason |
|---|---|---|
| test_rebase_command.rs | ported (in part) | `rewrite::rebase_*`, `tags_follow_rebased_changes`, `rebase_and_abandon_with_a_merge_of_child_and_ancestor` (bug_2600), `rebase_onto_the_current_parent_is_a_no_op` (BUG-246); `--after/--before`, `-r`, multiple sources, `--skip-emptied`: pending |
| test_squash_command.rs | ported (in part) | `rewrite::squash_*`; `--from/--into/--keep-emptied`, partial squash, editor: pending / not applicable |
| test_split_command.rs | pending feature | split (interactive selection not applicable) |
| test_abandon_command.rs | ported | `rewrite::abandon_*`, `double_abandon_fails_the_second_time`, `abandoning_another_workspaces_working_copy`; `--restore-descendants` pending |
| test_duplicate_command.rs | pending feature | duplicate |
| test_parallelize_command.rs | pending feature | parallelize |
| test_absorb_command.rs | pending feature | absorb |
| test_revert_command.rs (backout) | pending feature | revert |
| test_diff_command.rs | ported (in part) | `diff::*`; external tools, colour-words, context settings, templates: not applicable / pending |
| test_diffedit_command.rs | not applicable | interactive diff editor |
| test_interdiff_command.rs | pending feature | interdiff (`vl diff --from A --to B` compares trees, not changes) |
| test_log_command.rs | ported (in part) | `log::*`; templates, revsets, path filtering, word wrap: pending |
| test_evolog_command.rs | ported | `rewrite::evolog_*`; templates pending |
| test_revset_output.rs | ported (in part) | `revisions::*`; the revset language is pending |
| test_resolve_command.rs | ported (in part) | `merge::editing_the_file_in_the_merge_clears_the_conflict`, `editing_another_file_keeps_the_conflict`, `deleting_resolves_a_modify_delete_conflict`, `file_directory_conflict_is_flagged`; merge tools pending |
| test_file_annotate_command.rs | pending feature | annotate |
| test_next_prev_commands.rs | pending feature | `next`/`prev` |
| test_simplify_parents_command.rs | pending feature | simplify-parents (see BUG-240) |
| test_fix_command.rs | pending feature | `fix` |
| test_op_revert_command.rs | ported (rewrite side) | `rewrite::undo_restores_*`, `repeated_undo_walks_back_through_rewrites` (BUG-247); the operation commands themselves belong to the everyday-commands suite |

## Jujutsu library tests

| File | Status | Veil tests / reason |
|---|---|---|
| test_merge_trees.rs | ported | `merge::*` (clean, conflicting, add/add, delete, D/F, deep trees, binary, modes) through `vl merge` |
| test_merged_tree.rs | ported | `merge::octopus_*`, `new_with_two_parents_merges_and_records_conflicts`, `conflicts_in_unusual_names` |
| test_rewrite.rs | ported | `rewrite::*` (descendant rebasing, abandoned parents, merges, tags and workspaces following), `veil_angles::change_ids_survive_every_rewrite_of_a_cloaked_change` |
| test_rewrite_duplicate.rs | pending feature | duplicate |
| test_rewrite_transform.rs | not applicable | library transform API |
| test_revset.rs, test_revset_optimized.rs | ported (symbols only) | `revisions::*`; the language is pending |
| test_default_revset_graph_iterator.rs | ported | `log::log_is_in_topological_order`, `log_of_skewed_crossing_merges` |
| test_conflicts.rs | ported | `merge::same_line_conflict_writes_diff3_markers`, `no_trailing_newline_conflict_has_markers`, `add_add_different_conflicts` (marker format; jj's own conflict algebra is not Veil's model) |
| test_diff_summary.rs | ported | `diff::added_and_deleted_files_are_labelled`, `file_replaced_by_directory`, `directory_replaced_by_file` (`--stat`) |
| test_evolution_predecessors.rs | ported | `rewrite::evolog_lists_each_version_newest_first`, `evolog_after_squash_shows_the_parents_history` |
| test_mut_repo.rs | ported | `rewrite::each_rewrite_records_one_named_operation`, `op_restore_*`, `another_workspaces_working_copy_follows_a_rebase` |

## Veil-specific scenarios

All in `veil_angles`, each named after the Git/jj scenario it replays:

* **Cloaked files through merges and rebases**: `merge_conflict_in_a_cloaked_file_stays_sealed`
  (markers and resolution stay sealed; nothing on a public mirror),
  `rebase_conflict_in_a_cloaked_file_stays_sealed`, `clean_merge_of_a_cloaked_file_stays_sealed`,
  `conflict_between_a_cloaking_edit_and_a_public_edit_stays_sealed` (both merge directions),
  `file_added_under_a_directory_cloaked_by_the_other_side_is_sealed_from_then_on`,
  `non_member_diff_show_and_log_of_a_cloaked_merge_reveal_nothing`.
* **`.veilpolicy` in rewrites**: `rebasing_a_policy_change_keeps_its_cloaked_files_sealed`,
  `conflicted_policy_after_rebase_keeps_files_sealed` (marker lines are read as
  `isolate` rules with a warning, which fails safe),
  `merged_policy_that_exposes_cloaked_files_is_not_taken`.
* **Rewrites across cloak boundaries**: `abandoning_the_change_that_cloaked_a_file_keeps_the_childs_edit_sealed`,
  `squashing_a_cloaked_change_into_a_public_parent_keeps_it_sealed`,
  `rebasing_a_cloaked_line_onto_public_work_keeps_it_sealed`, `change_ids_survive_every_rewrite_of_a_cloaked_change`,
  `undo_of_a_cloaked_conflict_merge_restores_everything`.
* **Isolated and quarantined content**: `isolated_file_survives_rebase_squash_and_abandon`,
  `quarantined_secret_is_not_recorded_by_a_rewrite`, `merge::isolated_file_survives_a_merge`.
* **Embargoed history**: `embargo_fixture_hides_the_fix_from_outsiders`,
  `cloaked_fix_line_is_encrypted_at_rest_before_the_merge`, `embargoed_merge_stores_no_plaintext_of_the_fix` (BUG-249),
  `rebasing_onto_an_embargoed_merge_keeps_the_embargo`, `describing_an_embargoed_merge_keeps_its_description_sealed`,
  `rewording_the_fix_after_the_embargoed_merge_keeps_the_embargo`, `squashing_into_an_embargoed_merge_keeps_the_embargo`,
  `abandoning_an_embargoed_merge_leaks_nothing`, `undoing_an_embargoed_merge_restores_the_previous_state`,
  `conflict_on_an_embargoed_line_is_not_recorded_in_metadata`.

"Outsider" checks open the repository with a fresh identity that holds no
key and read every snapshot the op log still reaches, including
predecessors: public file contents and plaintext descriptions. "At rest"
checks scan every file under `.veil/`, including decoded pack entries.
