# Conformance: working copy and everyday commands

Veil checked against the working-copy parts of Git's and Jujutsu's test
suites. Every scenario that makes sense in Veil's model is an original Rust
test in one module of the `cli_conformance` binary, `crates/vl/tests/cli_conformance/conformance_worktree/` (one module per
topic), driving the real `vl` binary with an isolated `VEIL_HOME`:

```sh
cargo test -p vl --test cli_conformance conformance_worktree::                 # 267 pass, 15 ignored
cargo test -p vl --test cli_conformance -- --ignored conformance_worktree::    # the 15 bug reproductions (all fail)
```

## Summary

* **Tests:** 282 in 17 modules: 267 pass, 15 are `#[ignore = "BUG-2NN: …"]`
  reproductions. The binary runs in about 4 s.
* **Git scripts in this series:** 348 (t0xxx; t1500–t1517; t2xxx; t3xxx
  without t34xx/t35xx; t7xxx): **110 ported**, **24 pending feature**,
  **214 not applicable** (of which 26 belong to another conformance agent:
  merge, history, diff and storage).
* **jj test files:** 32 CLI and 9 library files listed below: 33 ported (in
  part or fully), 8 not applicable or pending feature.
* **Bugs found:** 11 (`docs/BUGS.md`, "Conformance findings: working copy
  and everyday commands"): 1 high, 5 medium, 5 low.

| ID | Sev. | One line |
|---|---|---|
| BUG-200 | high (fixed, working-copy wave 2) | A nested Veil repository's cloaked (and isolated/ignored-by-rule) files are recorded as public plaintext by the enclosing repository |
| BUG-201 | medium (fixed, working-copy wave 2) | `vl restore` fails half way across a file ↔ directory swap (and deletes the directory's files in one direction) |
| BUG-202 | medium (fixed, working-copy wave 2) | File names of 241–255 bytes are recorded but cannot be checked out or restored; the working copy is then stuck |
| BUG-206 | medium | A second `vl undo` redoes the first instead of going further back, as the guide says |
| BUG-207 | medium | Snapshot ids printed by `vl evolog` for earlier versions do not resolve as revisions |
| BUG-208 | medium (fixed, working-copy wave 2) | `vl restore` in a merge working copy restores from the first parent only, deleting the other parent's files |
| BUG-203 | low (fixed, working-copy wave 2) | A file re-included below an ignored directory: `vl policy check` says public, the snapshot never records it |
| BUG-204 | low (fixed, working-copy wave 2) | Path arguments: `\` is rewritten to `/`; an absolute path outside the repository is taken relative to its root |
| BUG-205 | low (fixed, working-copy wave 2) | `vl cat <directory>` reports a corrupt object |
| BUG-209 | low (fixed, working-copy wave 2) | `vl restore` leaves the directories it empties behind |
| BUG-210 | low | `vl tag set --cloak SCOPE` accepts unknown, non-member, reserved and malformed scopes |

### Deliberate differences from Git (documented Veil behaviour, tested as such)

* **No index, no untracked files.** Everything not ignored, isolated or
  quarantined is recorded by the next command; `add`, `rm --cached`,
  `stash` and `clean` become "nothing", `vl ignore`, `vl new @-`/`vl edit`
  and `vl restore`.
* **Switching never refuses or carries edits:** they are recorded in the
  change being left (`checkout::local_edits_stay_in_the_change_being_left`).
* **Files in the way are kept, not overwritten:** an ignored, isolated or
  quarantined local file where the target tracks one is left as is and
  reported (`kept …`), and an isolated one keeps its protection.
* **`vl commit -m ""` is allowed** (no description), as is an empty commit;
  messages are stored verbatim (no stripspace).
* **One policy file, at the root.** A `.veilpolicy` in a subdirectory is an
  ordinary file; "negation" is a later rule (last match wins).
* **Paths in output are relative to the root**, also when run from a
  subdirectory; names with control characters are printed escaped, not
  C-quoted.
* **`vl restore` of a path that matches nothing** prints `Restored 0
  path(s)` and succeeds (Git errors).
* **Tags are Veil's branches** and accept names Git refs refuse (see the
  hypothesis in `docs/BUGS.md`); there is no rename command.
* **Workspaces are virtual:** no directory; `vl ws switch` re-attaches the
  one project directory; `ws rm` keeps the workspace's change.
* **`vl undo`** keeps unrecorded edits and skips automatic snapshots; a
  second undo is a redo (contrary to the guide: BUG-206).
* **The current directory may be removed** by a checkout that deletes it
  (Git's t2501 keeps it).
* **Symlinks and FIFOs are skipped** (symlinks are a pending feature).

### Acceptance scenarios for pending features (from this series)

* **Line endings and attributes** (t0020–t0028, t0003, t2082, t3920):
  `autocrlf` round trip, `eol=lf|crlf` per path, renormalisation after an
  attribute change, `working-tree-encoding`, binary detection overriding
  text conversion, CRLF in commit messages.
* **Symlinks** (t0055, t2007, t7515, the symlink halves of t0050, t2201,
  t7300): record a link (not its target), check out a link over a directory
  and back, never write through a link into another directory, `status` of
  a link that changes target, `restore` of a deleted link.
* **Rename detection** (t7525, t7001, t4001 for the diff agent): `vl status`
  shows `R old -> new`, also for a case-only rename on macOS.
* **History search / grep** (t3201, t78xx): `vl log` by path, author,
  `-S`/`-G`; grep over a snapshot.
* **Git tags** (t7004 annotated/signed, t3800): Veil's annotated tags cover what applies; Veil does not interoperate with Git.

## Git scripts

Status per script, in order; consecutive scripts with the same status and
reason share a line.

| Script(s) | Status | Veil tests / reason |
|---|---|---|
| t0000-basic | not applicable | test-harness self-test |
| t0001-init | ported | `init::*` (all 18 tests: plain, deep, relative, reinit, EEXIST, EPERM, existing content and secrets, `.git` checkout, nested, long base path, identity) — BUG-200 |
| t0002-gitfile | not applicable | `.git` files (gitdir links): no equivalent; Veil has one `.veil` per repository |
| t0003-attributes | pending feature | attributes (`.gitattributes` equivalents): "line endings and per-path attributes" feature |
| t0004-unwritable | ported | `init::init_in_an_unwritable_directory_fails_and_leaves_nothing`, `status::status_with_an_unreadable_file`, `snapshot::an_unreadable_directory_keeps_its_recorded_content` |
| t0005-signals | ported | `snapshot::a_killed_snapshot_leaves_the_repository_usable` (kill -9 mid-commit) |
| t0006-date | not applicable | Git date parsing internals (`--until` parsing belongs to embargoes) |
| t0007-git-var | not applicable | `git var` |
| t0008-ignores | ported | `ignores::*` (24 tests: basename/anchored/leading-slash/trailing-slash/`**` patterns, last-match-wins re-include, escapes, comments, glob classes, case, trailing whitespace, fail-safe typos, editor scratch files, `vl policy check` as `check-ignore -v`) — BUG-203. Not applicable: `--stdin`, `-q/-v/-n` flags, global `core.excludesFile` and `info/exclude` (Veil has one policy file); symlinked exclude files (symlinks pending) |
| t0009-git-dir-validation | not applicable | `.git` directory validation (see t7450 for the reserved `.veil`) |
| t0010-racy-git | ported | `status::same_size_edits_in_quick_succession_are_noticed`, `status::an_edit_that_restores_the_old_mtime_is_noticed`, `snapshot::a_tree_rewritten_right_after_a_snapshot_is_noticed` |
| t0012-help … t0019-json-writer (6 scripts) | not applicable | help, SHA-1 collision detection, aliases, env helper, advice, JSON writer: Git internals |
| t0020-crlf … t0028-working-tree-encoding (9 scripts) | pending feature | CRLF and attributes: "line endings and per-path attributes" feature (acceptance: autocrlf round trip, renormalise, `eol=` per path, working-tree encodings); today `checkout::binary_empty_and_unterminated_files_round_trip` checks CRLF bytes are kept verbatim |
| t0029-core-unsetenvvars | not applicable | `core.unsetenvvars` (Windows) |
| t0030-stripspace | ported | `commit::multi_line_messages_are_kept` (Veil keeps messages verbatim, no stripspace: deliberate) |
| t0031-lockfile-pid | not applicable | Git lockfile PID format (Veil's lock is covered by the lock suites) |
| t0033-safe-directory … t0035-safe-bare-repository (3 scripts) | not applicable | `safe.directory` / bare-repository safety: Git config internals |
| t0040-parse-options … t0041-usage (2 scripts) | not applicable | parse-options / usage internals (clap); exit code 2 for usage errors checked in `commit::commit_and_describe_require_a_message` |
| t0050-filesystem | ported | `filesystem::case_only_pair_is_recorded_with_a_warning`, `nfc_and_nfd_spellings_are_two_files_on_linux_with_a_warning`, `checkout_of_a_case_collision_is_refused_on_a_folding_filesystem`, `unicode_collision_is_refused_only_where_the_filesystem_normalises`, `case_only_rename_on_linux_is_a_delete_and_an_add`, `status::status_warns_about_a_case_only_pair`. Symlink detection: pending (symlinks). Real case-insensitive aliasing can only run on macOS CI |
| t0051-windows-named-pipe … t0052-simple-ipc (2 scripts) | not applicable | Windows named pipes, simple IPC |
| t0055-beyond-symlinks | pending feature | "beyond symlinks": symlinks feature; today symlinks are skipped (`snapshot::fifos_and_symlinks_are_not_recorded_or_followed`) |
| t0056-git-C | ported | `init::repository_option_works_from_anywhere` (`-R` for `git -C`) |
| t0060-path-utils … t0068-for-each-repo (6 scripts) | not applicable | path utilities, run-command, revision-walking, dir-iterator, pathspec-file, for-each-repo: internals |
| t0070-fundamental … t0095-bloom (9 scripts) | not applicable | unit-test harness, sort, find-pack, cache-tree, bugreport, diagnose, bloom filters: internals |
| t0100-previous | not applicable | `@{-N}` previous-branch syntax: no checkout history in Veil |
| t0101-at-syntax | not applicable | `@{…}` reflog syntax: the op log replaces it (see `undo::*`) |
| t0200-gettext-basic … t0213-trace2-ancestry (9 scripts) | not applicable | gettext / trace2: Git's own i18n and tracing |
| t0300-credentials … t0303-credential-external (4 scripts) | not applicable | credential helpers (Veil does not run `git`) |
| t0410-partial-clone … t0411-clone-from-partial (2 scripts) | not applicable | partial clone (deferred to 1.1) |
| t0450-txt-doc-vs-help … t0500-progress-display (2 scripts) | not applicable | doc-vs-help consistency, progress display (Veil generates its reference from clap) |
| t0600-reffiles-backend … t0614-reftable-fsck (8 scripts) | not applicable | ref storage backends (files, reftable) |
| t1500-rev-parse | ported | `revisions::at_and_parent_suffixes_walk_first_parents`, `whitespace_around_a_revision_is_ignored`, `ids_that_are_not_snapshots_are_not_revisions`, `ids_printed_by_log_resolve`; `init::commands_find_the_repository_from_a_deep_subdirectory`, `commands_work_from_inside_the_metadata_directory`. Not applicable: `--git-dir`, `--path-format`, shallow, object/ref format, bisect, `:/` message search |
| t1501-work-tree | ported | `init::repository_option_works_from_anywhere` (GIT_WORK_TREE mapped to `-R`) |
| t1502-rev-parse-parseopt | not applicable | `rev-parse --parseopt` |
| t1503-rev-parse-verify | ported | `revisions::unknown_and_empty_revisions_fail_cleanly` (`--verify` semantics: every command refuses an unknown revision and records nothing) |
| t1504-ceiling-dirs | ported | `init::discovery_uses_the_nearest_enclosing_repository` (no ceiling variable in Veil) |
| t1505-rev-parse-last | ported | `revisions::evolog_snapshot_ids_resolve_as_revisions` (earlier versions of a change, Veil's nearest equivalent of "the last N") — BUG-207 |
| t1506-rev-parse-diagnosis | ported | `revisions::walking_past_the_root_is_an_error`, `unknown_and_empty_revisions_fail_cleanly` |
| t1507-rev-parse-upstream | not applicable | `@{upstream}`: remote tags are covered by the remotes agent |
| t1508-at-combinations | ported | `revisions::workspace_at_revisions_and_their_parents` (`name@`; Git's `@{…}` forms do not exist) |
| t1509-root-work-tree | not applicable | repository at `/` (needs root) |
| t1510-repo-setup | ported | `init::*` discovery tests (Veil has no GIT_DIR/GIT_WORK_TREE matrix) |
| t1511-rev-parse-caret | ported | `revisions::parent_suffix_of_a_merge_is_its_first_parent` (`X-` is `X^1`; `^2`, `~N` with N>1 typed as `X--…`) |
| t1512-rev-parse-disambiguation | ported | `revisions::ambiguous_change_id_prefix_is_refused`, `snapshot_id_prefixes_need_four_hex_digits`, `snapshot_id_prefixes_are_case_insensitive`, `a_tag_wins_over_an_id_prefix_that_spells_the_same`, `an_abandoned_change_id_no_longer_resolves`. Not applicable: object-type disambiguation (only snapshots are revisions), `core.disambiguate` |
| t1513-rev-parse-prefix | ported | `revisions::change_id_prefixes_of_any_unique_length` |
| t1514-rev-parse-push | not applicable | `@{push}` |
| t1515-rev-parse-outside-repo … t1517-outside-repo (2 scripts) | ported | `init::repository_commands_outside_a_repository_fail_with_a_hint` |
| t2000-conflict-when-checking-files-out … t2003-checkout-cache-mkdir (3 scripts) | ported | `checkout::file_to_directory_and_back_on_checkout`, `deep_directory_replaced_by_a_file` (checkout-index specifics are plumbing) |
| t2004-checkout-cache-temp … t2006-checkout-index-basic (3 scripts) | not applicable | checkout-index (plumbing); symlink variant: pending (symlinks) |
| t2007-checkout-symlink | pending feature | symlinks feature (checkout of a symlink over a directory) |
| t2008-checkout-subdir | ported | `restore::restore_paths_relative_to_the_current_directory` |
| t2009-checkout-statinfo | ported | `checkout::unchanged_files_are_not_rewritten`, `executable_bit_follows_the_checked_out_revision` |
| t2010-checkout-ambiguous | ported | `checkout::a_failed_checkout_leaves_the_working_copy_alone` (no file/ref ambiguity: paths and revisions are separate arguments) |
| t2011-checkout-invalid-head | ported | `workspaces::a_missing_checkout_record_is_survivable` |
| t2012-checkout-last | not applicable | `checkout -` (no checkout history; `vl undo` returns to the previous working copy: `undo::undo_of_new_and_edit_returns_to_the_previous_working_copy`) |
| t2013-checkout-submodule | not applicable | submodules |
| t2014-checkout-switch | ported | `checkout::local_edits_stay_in_the_change_being_left` (Git carries or refuses; Veil records the edits in the change being left: deliberate) |
| t2015-checkout-unborn | ported | `checkout::switching_in_a_fresh_repository` |
| t2016-checkout-patch | not applicable | `checkout -p` (interactive) |
| t2017-checkout-orphan | ported | `checkout::new_on_root_is_an_orphan_with_an_empty_tree` |
| t2018-checkout-branch | ported | `checkout::new_on_another_revision_checks_out_its_tree`, `read_only_tracked_files_are_replaced_by_checkout` |
| t2019-checkout-ambiguous-ref | ported | `checkout::a_failed_checkout_leaves_the_working_copy_alone` (no file/ref ambiguity: paths and revisions are separate arguments) |
| t2020-checkout-detach | ported | `checkout::new_on_a_tag_does_not_move_the_tag` (no detached HEAD in Veil) |
| t2021-checkout-overwrite | ported | `checkout::an_ignored_local_file_is_not_overwritten_by_a_tracked_one`, `an_isolated_local_file_is_not_overwritten_or_published`, `a_quarantined_file_survives_checkouts` (a file in the way of a directory: BUG-111, already filed) |
| t2022-checkout-paths | ported | `restore::restore_from_another_revision`, `restore_a_directory_over_a_file`, `restore_a_file_over_a_directory` — BUG-201 |
| t2023-checkout-m | not applicable | other conformance agent (merge): `checkout -m` |
| t2024-checkout-dwim | not applicable | DWIM remote-tracking branches, `--track` |
| t2025-checkout-no-overlay | ported | `restore::restore_from_a_revision_without_the_path_removes_it` |
| t2026-checkout-pathspec-file | not applicable | `--pathspec-from-file` |
| t2027-checkout-track | not applicable | DWIM remote-tracking branches, `--track` |
| t2030-unresolve-info | not applicable | index unresolve info |
| t2050-git-dir-relative | not applicable | relative GIT_DIR |
| t2060-switch | ported | `checkout::*` (`vl new`/`vl edit` replace `switch`; `switch -c` is `vl new` + `vl tag set`) |
| t2070-restore | ported | `restore::*` (19 tests) — BUG-201, BUG-204, BUG-208, BUG-209. `--staged`/`--worktree` not applicable (no index) |
| t2071-restore-patch | not applicable | `restore -p` (interactive) |
| t2072-restore-pathspec-file | not applicable | `--pathspec-from-file` |
| t2080-parallel-checkout-basics | ported | `checkout::checkout_of_many_files` (parallel checkout workers are an implementation detail) |
| t2081-parallel-checkout-collisions | ported | `filesystem::checkout_of_a_case_collision_is_refused_on_a_folding_filesystem` |
| t2082-parallel-checkout-attributes | pending feature | attributes feature |
| t2100-update-cache-badpath … t2108-update-index-refresh-racy (9 scripts) | not applicable | update-index (plumbing, index) |
| t2200-add-update | ported | `add_rm_mv::edits_everywhere_are_recorded_at_once` |
| t2201-add-update-typechange | ported | `add_rm_mv::a_directory_replaced_by_a_file`, `status::status_of_a_file_replaced_by_a_directory` (symlink typechange: pending) |
| t2202-add-addremove | ported | `add_rm_mv::additions_and_deletions_are_recorded_together` |
| t2203-add-intent | not applicable | intent-to-add (index) |
| t2204-add-ignored | ported | `ignores::ignored_files_are_not_scanned_or_quarantined`, `add_rm_mv::moving_a_file_into_an_ignored_directory_untracks_it` |
| t2205-add-worktree-config | not applicable | worktree config |
| t2206-add-submodule-ignored | not applicable | submodules |
| t2207-add-resolved | not applicable | other conformance agent (merge): add of resolved conflicts (conflict clearing on edit is in `status::status_lists_unresolved_conflicts_and_clears_them_on_edit`) |
| t2300-cd-to-toplevel | ported | `init::commands_find_the_repository_from_a_deep_subdirectory` |
| t2400-worktree-add | ported | `workspaces::ws_new_creates_a_virtual_workspace_on_the_parents_of_at`, `ws_new_on_a_given_revision`, `ws_new_refuses_duplicate_and_malformed_names`, `ws_exec_*`, `ws_write_and_cat_without_a_checkout`, `two_workspaces_on_one_base_are_independent` (virtual: no directory, a deliberate difference) |
| t2401-worktree-prune | ported | `workspaces::ws_rm_removes_the_workspace_but_keeps_its_change`, `ws_rm_of_the_attached_workspace_is_refused` (nothing to prune: no directories) |
| t2402-worktree-list | ported | `workspaces::ws_list_marks_the_attached_workspace` |
| t2403-worktree-move | ported | `workspaces::ws_switch_to_an_unknown_workspace_fails_and_changes_nothing` (no move: workspaces have no path; `ws switch` re-attaches the one directory) |
| t2404-worktree-config | not applicable | per-worktree config |
| t2405-worktree-submodule | not applicable | submodules |
| t2406-worktree-repair | ported | `workspaces::a_missing_checkout_record_is_survivable` |
| t2407-worktree-heads | ported | `workspaces::two_workspaces_on_one_base_are_independent`, `checkout::edit_of_another_workspaces_working_copy` |
| t2500-untracked-overwriting | ported | `checkout::an_ignored_local_file_is_not_overwritten_by_a_tracked_one`, `a_quarantined_file_survives_checkouts` |
| t2501-cwd-empty | ported | `checkout::checkout_from_a_directory_it_removes` (Git keeps the cwd; Veil removes it: noted difference) |
| t3000-ls-files-others … t3001-ls-files-others-exclude (2 scripts) | ported | `files::files_lists_only_what_is_recorded`, `ignores::default_policy_ignores_build_output_at_any_depth` (no "others": every file not kept out is recorded) |
| t3002-ls-files-dashpath | ported | `files::files_and_cat_with_dash_paths` |
| t3003-ls-files-exclude | ported | `files::files_lists_only_what_is_recorded`, `ignores::default_policy_ignores_build_output_at_any_depth` (no "others": every file not kept out is recorded) |
| t3004-ls-files-basic | ported | `files::files_lists_every_file_sorted_with_visibility_and_size`, `files_of_a_fresh_repository_lists_only_the_policy` |
| t3005-ls-files-relative | ported | `files::cat_paths_are_relative_to_the_current_directory` (`vl files` always lists from the root: deliberate) |
| t3006-ls-files-long | not applicable | `ls-files` long/format output options |
| t3007-ls-files-recurse-submodules | not applicable | submodules / subprojects |
| t3008-ls-files-lazy-init-name-hash | not applicable | index name-hash internals |
| t3009-ls-files-others-nonsubmodule | ported | `files::files_lists_only_what_is_recorded`, `ignores::default_policy_ignores_build_output_at_any_depth` (no "others": every file not kept out is recorded) |
| t3010-ls-files-killed-modified | ported | `files::files_lists_only_what_is_recorded` |
| t3011-common-prefixes-and-directory-traversal | ported | `ignores::double_star_prefix_does_not_match_a_longer_name`, `restore::restore_of_a_directory_matches_whole_components` |
| t3012-ls-files-dedup | not applicable | ls-files dedup of unmerged index entries |
| t3013-ls-files-format | not applicable | `ls-files` long/format output options |
| t3020-ls-files-error-unmatch | ported | `files::cat_of_a_missing_path_fails`, `files::cat_of_a_directory_is_a_clear_error` — BUG-205 |
| t3040-subprojects-basic … t3050-subprojects-fetch (2 scripts) | not applicable | submodules / subprojects |
| t3060-ls-files-with-tree | ported | `files::files_of_other_revisions` |
| t3070-wildmatch | ported | `ignores::character_classes_question_marks_and_alternatives`, `double_star_*` (wildmatch semantics through policy rules; Veil uses globset) |
| t3100-ls-tree-restrict … t3105-ls-tree-output (6 scripts) | ported | `files::files_of_other_revisions`, `files_shows_cloaked_files_with_their_scope`, `sizes_are_exact_for_large_files`, `files_and_cat_for_a_non_member` (ls-tree formats not applicable) |
| t3200-branch | ported | `tags::*` (18 tests: create, default `@`, delete, unknown, forward/backward/sideways, invalid names, hierarchy, sort, rewrites, abandon, root, cloaked) — BUG-210. Not applicable: upstream tracking, `--contains`, `-m` rename (no rename command: `tags::renaming_a_tag_by_set_and_delete`), reflogs, worktree checks |
| t3201-branch-contains | not applicable | `branch --contains/--merged` (history queries: pending "history search") |
| t3202-show-branch | not applicable | `show-branch` |
| t3203-branch-output | ported | `tags::tag_list_is_sorted`, `tag_set_creates_and_list_shows_it` |
| t3204-branch-name-interpretation | ported | `tags::invalid_tag_names_are_refused`, `unusual_but_legal_tag_names` |
| t3205-branch-color | not applicable | branch colours |
| t3206-range-diff | not applicable | range-diff (pending: no equivalent) |
| t3207-branch-submodule | not applicable | submodules |
| t3211-peel-ref | not applicable | peeling annotated refs |
| t3300-funny-names | ported | `filesystem::funny_names_round_trip_through_a_checkout`, `control_characters_in_names_are_recorded_and_printed_escaped`, `option_like_names_work_after_a_double_dash`, `a_name_of_240_bytes_round_trips`, `a_name_of_250_bytes_round_trips`, `restore_of_a_250_byte_name`, `a_backslash_in_a_path_argument_names_that_file`, `non_utf8_names_are_reported_and_left_alone` — BUG-202, BUG-204 |
| t3301-notes … t3321-notes-stripspace (13 scripts) | not applicable | notes (no equivalent) |
| t3600-rm | ported | `add_rm_mv::deleting_a_file_records_a_deletion_and_history_keeps_it`, `deleting_a_directory_records_every_file_in_it`, `re_adding_a_removed_file`, `a_deleted_recorded_edit_is_recoverable_from_the_op_log`; `rm --cached`: `ignores::ignoring_a_tracked_file_untracks_it_and_keeps_it_on_disk` |
| t3601-rm-pathspec-file | not applicable | `--pathspec-from-file` |
| t3602-rm-sparse-checkout | not applicable | sparse checkout (deferred to 1.1) |
| t3650-replay-basics | not applicable | other conformance agent (history): `git replay` |
| t3700-add | ported | `add_rm_mv::a_new_file_is_recorded_without_add`, `an_empty_file_is_recorded_and_an_empty_directory_is_not`, `a_new_executable_is_recorded_as_executable`, `many_new_files_in_one_snapshot`, `adding_a_credential_quarantines_the_file`; `ignores::vl_ignore_escapes_an_existing_name_with_glob_characters`, `undo_takes_back_an_ignore_rule` |
| t3701-add-interactive … t3702-add-edit (2 scripts) | not applicable | interactive add / `add -e` |
| t3703-add-magic-pathspec | not applicable | magic pathspecs |
| t3704-add-pathspec-file | not applicable | `--pathspec-from-file` |
| t3705-add-sparse-checkout | not applicable | sparse checkout (deferred to 1.1) |
| t3800-mktag | not applicable | mktag (plumbing; Git tags pending) |
| t3900-i18n-commit | ported | `commit::unicode_messages_round_trip` |
| t3901-i18n-patch | not applicable | i18n patches (mail tools) |
| t3902-quoted | ported | `filesystem::control_characters_in_names_are_recorded_and_printed_escaped`, `status::*` (names printed escaped, never C-quoted: deliberate) |
| t3903-stash | ported | `stash::*` (7 tests: `vl new @-` sets work aside, `vl edit` brings it back, list/show via log/show, drop via abandon, ignored and isolated stay, quarantined stays, combine via a merge) |
| t3904-stash-patch | not applicable | `stash -p`, `--pathspec-from-file` |
| t3905-stash-include-untracked | ported | `stash::new_on_the_parent_sets_work_aside` (new files go along, as `-u`), `stash::ignored_and_isolated_files_stay_on_disk` |
| t3906-stash-submodule | not applicable | submodules |
| t3907-stash-show-config | ported | `stash::set_aside_work_is_listed_and_shown` |
| t3908-stash-in-worktree | ported | `workspaces::commit_in_a_switched_workspace_moves_the_tag_at_its_parent`, `workspaces::ws_switch_swaps_the_files_and_keeps_both_sides` |
| t3909-stash-pathspec-file | not applicable | `stash -p`, `--pathspec-from-file` |
| t3910-mac-os-precompose | ported | `filesystem::recorded_spelling_is_kept_across_checkouts`, `unicode_collision_is_refused_only_where_the_filesystem_normalises`, `nfc_and_nfd_spellings_are_two_files_on_linux_with_a_warning` (NFC recording of new names needs a real macOS volume: see BUGS.md notes) |
| t3920-crlf-messages | pending feature | CRLF in messages (line endings feature) |
| t7001-mv | ported | `add_rm_mv::moving_a_file_is_a_delete_and_an_add`, `moving_a_directory_moves_its_files`, `moving_over_an_existing_file`, `moving_a_file_into_a_cloaked_directory_cloaks_it`, `renaming_a_file_to_a_secret_name_stops_recording_it` (rename detection pending) |
| t7002-mv-sparse-checkout | not applicable | sparse checkout / skip-worktree |
| t7003-filter-branch | not applicable | filter-branch |
| t7004-tag | ported | `tags::*` (Veil tags are local names; annotated and signed tags: `vl tag set -a`, `vl tag verify`), `visibility::a_cloaked_tag_stays_off_a_public_remote` |
| t7005-editor … t7006-pager (2 scripts) | not applicable | editor and pager (no editor prompt: `-m` is required) |
| t7007-show | not applicable | other conformance agent (diff/history): `git show` |
| t7008-filter-branch-null-sha1 | not applicable | filter-branch |
| t7010-setup | not applicable | setup internals |
| t7011-skip-worktree-reading … t7012-skip-worktree-writing (2 scripts) | not applicable | sparse checkout / skip-worktree |
| t7030-verify-tag … t7031-verify-tag-signed-ssh (2 scripts) | not applicable | verify-tag (signed tags pending) |
| t7060-wtstatus … t7062-wtstatus-ignorecase (3 scripts) | ported | `status::status_paths_are_relative_to_the_root`, `status_does_not_show_ignored_files`, `status_warns_about_a_case_only_pair` |
| t7063-status-untracked-cache | ported | `status::same_size_edits_in_quick_succession_are_noticed`, `snapshot::unchanged_snapshots_are_cheap` (the stat cache plays the untracked cache's role) |
| t7064-wtstatus-pv2 | not applicable | porcelain v2 output |
| t7101-reset-empty-subdirs | ported | `restore::restore_removes_directories_it_empties` — BUG-209 |
| t7102-reset | ported | `restore::restore_without_paths_resets_everything`, `restore_from_two_back_applies_the_whole_difference`; `--soft/--mixed` not applicable (no index); moving `@` back is `vl edit`/`vl new` |
| t7103-reset-bare | not applicable | reset in a bare repository |
| t7104-reset-hard | ported | `restore::restore_without_paths_resets_everything`, `restore_leaves_ignored_and_isolated_files_alone` |
| t7105-reset-patch | not applicable | `reset -p`, `--pathspec-from-file` |
| t7106-reset-unborn-branch | ported | `restore::restore_in_a_fresh_repository_empties_it` |
| t7107-reset-pathspec-file | not applicable | `reset -p`, `--pathspec-from-file` |
| t7110-reset-merge | ported | `restore::restore_in_a_merge_goes_back_to_the_merged_parents` — BUG-208 |
| t7111-reset-table | ported | `restore::restore_from_two_back_applies_the_whole_difference` |
| t7112-reset-submodule | not applicable | submodules |
| t7113-post-index-change-hook | not applicable | hooks (deferred) |
| t7201-co | ported | `checkout::new_on_another_revision_checks_out_its_tree`, `local_edits_stay_in_the_change_being_left` |
| t7300-clean | ported | `clean::*` (5 tests) |
| t7301-clean-interactive | not applicable | interactive clean |
| t7400-submodule-basic … t7426-submodule-get-default-remote (23 scripts) | not applicable | submodules |
| t7450-bad-git-dotfiles | ported | `filesystem::reserved_metadata_names_are_never_recorded` (`.veil` reserved in any case and depth) |
| t7500-commit-template-squash-signoff | ported | `commit::commit_describes_the_change_and_starts_a_new_one` (templates, `--squash`/`--fixup` and sign-off not applicable) |
| t7501-commit-basic-functionality | ported | `commit::*` (21 tests) |
| t7502-commit-porcelain | ported | `commit::multi_line_messages_are_kept`, `control_characters_in_messages_are_printed_escaped`, `messages_that_look_like_options` |
| t7503-pre-commit-and-pre-merge-commit-hooks … t7505-prepare-commit-msg-hook (3 scripts) | not applicable | commit hooks (deferred to 1.1) |
| t7506-status-submodule | not applicable | submodules |
| t7507-commit-verbose | not applicable | `commit -v` (editor) |
| t7508-status | ported | `status::*` (17 tests) |
| t7509-commit-authorship | ported | `commit::author_comes_from_veil_user_when_the_change_starts` |
| t7510-signed-commit | not applicable | GPG/SSH-signed commits (Veil signs every snapshot with the identity key; covered elsewhere) |
| t7511-status-index | not applicable | status of the index |
| t7512-status-help | ported | `status::status_lists_unresolved_conflicts_and_clears_them_on_edit` |
| t7513-interpret-trailers | not applicable | interpret-trailers |
| t7514-commit-patch | not applicable | `commit -p`, `--pathspec-from-file` |
| t7515-status-symlinks | pending feature | symlinks feature |
| t7516-commit-races | ported | `commit::an_edit_after_commit_belongs_to_the_next_change`, `undo::concurrent_commits_lose_no_file` |
| t7517-per-repo-email | not applicable | per-repo email config (identity is per device: `VEIL_USER`) |
| t7518-ident-corner-cases | ported | `commit::author_with_a_newline_cannot_forge_output` |
| t7519-status-fsmonitor | not applicable | fsmonitor (Veil has `vl watch`: `snapshot::watch_records_edits_as_they_happen`) |
| t7520-ignored-hook-warning | not applicable | commit hooks (deferred to 1.1) |
| t7521-ignored-mode | ported | `status::status_does_not_show_ignored_files` |
| t7524-commit-summary | ported | `commit::commit_summary_names_the_committed_and_the_new_change` |
| t7525-status-rename | ported | `status::status_shows_a_rename` (rename detection, Git-parity stream H) |
| t7526-commit-pathspec-file | not applicable | `commit -p`, `--pathspec-from-file` |
| t7527-builtin-fsmonitor | not applicable | fsmonitor (Veil has `vl watch`: `snapshot::watch_records_edits_as_they_happen`) |
| t7528-signed-commit-ssh | not applicable | GPG/SSH-signed commits (Veil signs every snapshot with the identity key; covered elsewhere) |
| t7600-merge … t7615-diff-algo-with-mergy-operations (15 scripts) | not applicable | other conformance agent (merge) |
| t7700-repack … t7706-repack-drop-filtered (7 scripts) | not applicable | other conformance agent (storage: repack/gc) |
| t7800-difftool | not applicable | difftool |
| t7810-grep … t7817-grep-sparse-checkout (8 scripts) | feature built, not ported | `vl grep` over a snapshot (`history_cli.rs`); the scripts' option matrix is still to port |
| t7900-maintenance | not applicable | maintenance scheduling (`vl gc` belongs to the storage agent) |

## Jujutsu test files

| File | Status | Veil tests / reason |
|---|---|---|
| cli `test_status_command.rs` | ported | `status::*` (clean, A/M/D, merge parents, conflicts, `st` alias, local-only/quarantined sections, cloaked workspace). Not applicable: fileset arguments, templates |
| cli `test_commit_command.rs` | ported | `commit::*` (commit, empty, multi-line, merge, summary). Not applicable: interactive `-i`, paths (partial commit: no equivalent in 1.0), `--reset-author`, editor |
| cli `test_new_command.rs` | ported | `checkout::new_without_arguments_starts_on_the_working_copy`, `new_with_several_parents_merges_their_trees`, `an_empty_undescribed_change_is_discarded_on_moving_away`, `new_on_root_is_an_orphan_with_an_empty_tree`. Not applicable: `--insert-before/after`, revset expressions |
| cli `test_describe_command.rs` | ported | `commit::describe_rewrites_a_change_and_tags_follow`, `describe_then_new_is_commit_without_moving_tags`, `describe_of_the_root_fails`, `descriptions_in_a_cloaked_workspace_are_cloaked`, `commit_and_describe_require_a_message`. Not applicable: editor, several revisions at once |
| cli `test_edit_command.rs` | ported | `checkout::edit_amends_an_older_change_and_rebases_descendants`, `edit_of_the_working_copy_is_a_no_op`, `edit_of_another_workspaces_working_copy`, `undo::undo_of_new_and_edit_returns_to_the_previous_working_copy` |
| cli `test_restore_command.rs` | ported | `restore::*` — BUG-201, BUG-208, BUG-209. Not applicable: `--changes-in`, `--into`, interactive |
| cli `test_workspaces.rs` | ported | `workspaces::*` (21 tests: new, list, switch, rm/forget, exec, ephemeral, write/cat, stale working copy, policy in sandboxes). Not applicable: workspace root paths, `update-stale` (Veil updates automatically) |
| cli `test_working_copy.rs` | ported | `snapshot::*`, `filesystem::*`, `checkout::binary_empty_and_unterminated_files_round_trip`, `checkout::checkout_of_many_files` — BUG-202 |
| cli `test_gitignores.rs` | ported | `ignores::*` (Veil's `ignore` tier; `.gitignore` files themselves are not read) — BUG-203 |
| cli `test_file_show_command.rs` | ported | `files::cat_*` — BUG-205 |
| cli `test_file_list_command.rs` | ported | `files::files_*`, `files::files_and_cat_for_a_non_member` |
| cli `test_file_chmod_command.rs` | ported (via the disk) | no `file chmod` command: `checkout::executable_bit_follows_the_checked_out_revision`, `snapshot::toggling_the_executable_bit_and_back`, `files::files_marks_executables` |
| cli `test_file_track_untrack_commands.rs` | ported | untrack = `vl ignore`: `ignores::ignoring_a_tracked_file_untracks_it_and_keeps_it_on_disk`, `removing_an_ignore_rule_tracks_the_file_again`, `undo_takes_back_an_ignore_rule` (auto-track only) |
| cli `test_file_delete_command.rs` | ported (via the disk) | `add_rm_mv::deleting_*` |
| cli `test_file_edit_command.rs`, `test_file_annotate_command.rs`, `test_file_search_command.rs` | pending feature | editor-driven edit (not planned), annotate/blame, grep |
| cli `test_tag_command.rs` | ported | `tags::*` (Veil tags are local names) — BUG-210 |
| cli `test_bookmark_command.rs` | ported (local behaviour) | `tags::*`: create, move, backwards guard, delete, rewrites, abandon. Not applicable: remote tracking, `track/untrack`, conflicted bookmarks |
| cli `test_advance_bookmarks.rs` | ported | `commit::commit_advances_every_tag_at_the_parent`, `commit_does_not_move_tags_elsewhere`, `commit_in_a_cloaked_workspace_does_not_move_main` |
| cli `test_undo_redo_commands.rs` | ported | `undo::*` — BUG-206. Not applicable: `jj redo` (no command; a second undo redoes) |
| cli `test_operations.rs` | ported | `undo::op_log_lists_operations_newest_first`, `snapshots_are_operations_but_idle_commands_add_none`, `undo_skips_the_automatic_snapshot`. Not applicable: `op show`, `op diff`, `--at-op`, templates |
| cli `test_op_restore_command.rs` | ported | `undo::op_restore_*` |
| cli `test_op_revert_command.rs` | not applicable | reverting a non-latest operation has no Veil command (only `undo` and `op restore`) |
| cli `test_op_integrate_command.rs` | not applicable | Veil serialises writers with a lock; there are no divergent operations to integrate |
| cli `test_concurrent_operations.rs` | ported | `undo::concurrent_commands_are_serialised`, `undo::concurrent_commits_lose_no_file`, `snapshot::concurrent_checkout_and_snapshot` |
| cli `test_root.rs` | ported | `init::the_root_snapshot_is_empty_and_immutable`, `revisions::root_spellings` |
| cli `test_global_opts.rs` | ported (`-R`, `--no-snapshot`) | `init::repository_option_works_from_anywhere`, `undo::no_snapshot_does_not_record_the_disk` |
| cli `test_abandon_command.rs` | ported (working-copy part) | `undo::undo_of_abandon_brings_the_files_back`, `tags::abandoning_a_tagged_change_moves_the_tag_to_its_parent` (history rewriting belongs to the history agent) |
| cli `test_evolog_command.rs` | ported (resolution part) | `revisions::evolog_snapshot_ids_resolve_as_revisions` — BUG-207 |
| cli `test_revset_output.rs` | ported (subset) | `revisions::*`: Veil has `@`, `name@`, `root`, tags, prefixes and `X-` only; the revset language is not applicable |
| cli `test_sparse_command.rs` | pending feature | sparse checkout (1.1) |
| lib `test_local_working_copy.rs` | ported | `snapshot::*`, `filesystem::*`, `checkout::file_to_directory_and_back_on_checkout`, `deep_directory_replaced_by_a_file`, `unchanged_files_are_not_rewritten`, `checkout::a_quarantined_file_survives_checkouts` (special files, unreadable dirs, crash debris, large files, file↔dir) |
| lib `test_local_working_copy_concurrent.rs` | ported | `snapshot::concurrent_checkout_and_snapshot`, `undo::concurrent_commits_lose_no_file` |
| lib `test_local_working_copy_executable_bit.rs` | ported | `snapshot::toggling_the_executable_bit_and_back`, `checkout::executable_bit_follows_the_checked_out_revision`, `restore::restore_restores_the_executable_bit`, `add_rm_mv::a_new_executable_is_recorded_as_executable` |
| lib `test_local_working_copy_sparse.rs` | pending feature | sparse checkout (1.1) |
| lib `test_init.rs` | ported | `init::*` |
| lib `test_workspace.rs` | ported | `workspaces::*` (through the CLI; the library API has its own tests in `veil-core`) |
| lib `test_id_prefix.rs` | ported | `revisions::ambiguous_change_id_prefix_is_refused`, `change_id_prefixes_of_any_unique_length`, `snapshot_id_prefixes_need_four_hex_digits` |
| lib `test_operations.rs` | ported (through the CLI) | `undo::*` |
| lib `test_load_repo.rs` | not applicable | loading at an old operation (`--at-op`) has no Veil equivalent |

## Veil-specific variants

`visibility::*` (12 tests) reruns the everyday scenarios with an isolated
`.env`, a quarantined credential and a cloaked file: commit, checkout round
trips, restore, undo and op restore, output of every inspecting command, a
copy of `.env` under another name, editor artefacts, case variants of secret
names, `ws exec` (`--with-isolated`, cloaked workspaces), a non-member's
edit of a cloaked file, and a cloaked tag pushed to a public remote. Each
greps the whole `.veil/` directory (and the remote) for the plaintext.
Further variants live next to their Git scenario (`init_lists_existing_secrets_as_local_only`,
`an_isolated_local_file_is_not_overwritten_or_published`,
`renaming_a_file_to_a_secret_name_stops_recording_it`,
`moving_a_file_into_a_cloaked_directory_cloaks_it`,
`outer_repository_does_not_record_a_nested_repositorys_cloaked_files` (BUG-200)).
