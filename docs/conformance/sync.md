# Conformance: remotes, storage and Git interop

Veil checked against Git's and Jujutsu's tests for clone, fetch, push,
pull and remotes, large files, `fsck`, `gc`/prune, and the Git bridge.
Tests: `crates/vl/tests/conformance_sync/` (one binary,
`cargo test -p vl --test conformance_sync`; about 5 s). Bugs:
[`docs/BUGS.md`](../BUGS.md), "Conformance findings: remotes, storage and
Git interop".

## Summary

* **200 tests**: 184 pass, 16 are `#[ignore = "BUG-NNN: …"]` reproductions
  (all fail when run with `--ignored`). SFTP tests run through a stand-in
  `ssh` serving the local OpenSSH `sftp-server` (skipped, with a message,
  where there is none); Git tests drive plain `git` against local bare
  repositories, offline.
* **Git scripts in this series:** 318: 177 t5xxx (t5304 included), t1050,
  t1450, t6500 and 138 t9xxx. Ported: 45; pending feature: 28; not
  applicable: 245 (smart/HTTP/wire protocols, Git's pack and index
  formats, submodules, svn/p4/cvs and other bridges).
* **Jujutsu:** 17 CLI test files (10 ported, 3 pending colocated mode, 4
  not applicable) and 10 library test files (7 ported, 1 pending, 2 not
  applicable).
* **Bugs found: 14** (BUG-280 … BUG-293): 4 medium, 10 low; no critical or
  high. No leak was found: public remotes, Git exports, team remotes and
  older-format mirrors never held cloaked or isolated plaintext, key rings
  (public), cloaked descriptions or tags, or an unreleased embargo, in any
  scenario tried (every object decompressed and grepped).
  * medium: BUG-280 (tags can never be deleted on a remote; pull
    resurrects deleted tags), BUG-285 (the same GitHub commit pulled by
    two members becomes two snapshots, then a duplicate on GitHub),
    BUG-288 (each retried rejected push re-sends its objects as a new
    pack), BUG-291 (`vl git remote rm` deadlocks on its own lock).
  * low: BUG-281 (push does not update `origin/*`), 282 (`remote rm`
    keeps `origin/*`), 283 (push into a non-Veil directory makes it a
    repository), 284 (`vl -R <bare remote>` only works for `fsck`; remotes
    cannot be gc'd), 286 (remote names not validated), 287 (a Veil remote
    may take a Git remote's name), 289 (fsck ignores packed unreachable
    objects), 290 (gc deltas do nothing above a few MiB), 292 (a failed
    `git import` keeps its remote), 293 (I/O errors reported as `not
    found: operation`).
* **Deliberate differences** (documented by Veil; tested as Veil
  behaves): only tags travel and pull never moves the working copy; pull
  *creates* local tags for new remote tags; no atomic push (other tags go,
  exit 1); `vl push --force` has no lease (`vl git push --force` does);
  pushing into a repository with a working copy moves its tags only;
  clones keep a `.veil` suffix in the directory name; tag names are ASCII;
  Veil remotes are paths or SSH only (`file://`, `http(s)://`, `git://`
  refused); Git time zones become UTC in Veil's exports and Veil keeps no
  committer; Git tags are not synced; symlinks and submodules stay in Git.

## Git: t5xxx

| Script(s) | Status | Veil tests / reason |
|---|---|---|
| t5000–t5004 (archive) | pending feature | `vl archive` (docs/BACKLOG.md "Missing everyday commands") |
| t5100 mailinfo, t5150 request-pull | not applicable | mail tools |
| t5200 update-server-info | not applicable | dumb HTTP protocol |
| t5300, t5301, t5302, t5306, t5308–t5311, t5313–t5316, t5318–t5320, t5322–t5335 | not applicable | Git's pack, index, bitmap, commit-graph and multi-pack-index formats |
| t5303 pack-corruption-resilience | ported | `integrity::{fsck_reports_a_damaged_pack, a_corrupt_object_on_the_remote_is_detected_by_pull_and_not_propagated}`, `clone::a_failed_clone_into_an_existing_empty_directory_leaves_it_empty`, `sftp::a_corrupt_object_on_an_ssh_remote_is_detected_by_clone` |
| t5304 prune | ported | `gc::{unreachable_objects_wait_out_the_grace_period, prune_now_deletes_unreachable_objects_at_once, abandoned_work_survives_gc_while_the_op_log_keeps_it, gc_keeps_what_only_a_remote_tag_reaches, gc_keeps_every_workspace_and_its_unrecorded_base, gc_with_bad_options_fails_with_usage}` |
| t5305 include-tag | pending feature | Git tags in the bridge (docs/RELEASE-1.0.md) |
| t5307 pack-missing-commit | ported | `integrity::{fsck_reports_a_missing_object_of_old_history, push_full_repairs_a_remote_that_lost_objects}` |
| t5312 prune-corruption | ported | `gc::gc_deletes_nothing_when_history_cannot_be_read` |
| t5317 pack-objects-filter-objects | pending feature | partial clone (deferred to 1.1+) |
| t5321 pack-large-objects, t5351 unpack-large-objects | ported | `large::*` |
| t5400 send-pack | ported | `push_pull::{push_fast_forwards_a_tag_and_reports_it, incremental_push_and_pull_send_only_what_is_new}` |
| t5401, t5402, t5403, t5407, t5411, t5412, t5544, t5571 (hooks) | pending feature | hooks (deferred, docs/RELEASE-1.0.md) |
| t5404 tracking-branches | ported | `push_pull::{a_partially_rejected_push_sends_the_other_tags_and_exits_1, a_rejected_push_leaves_the_remote_tag_alone, push_updates_the_remote_tags (BUG-281), a_deleted_tag_stays_deleted_after_push_and_pull (BUG-280)}`, `git_bridge::git_push_updates_the_remote_tags` |
| t5405 send-pack-rewind | ported | `push_pull::{a_diverged_push_is_rejected_with_exit_1_and_a_recovery_hint, force_push_overwrites_a_diverged_tag_and_keeps_the_old_history_on_the_remote}` |
| t5406 remote-rejects | ported | `push_pull::a_diverged_push_is_rejected_with_exit_1_and_a_recovery_hint`, `formats::a_new_repository_cannot_push_into_a_format_1_remote_and_leaves_it_untouched` |
| t5408 send-pack-stdin, t5409 colorize-remote-messages, t5410 receive-pack | not applicable | plumbing / wire protocol |
| t5413 connectivity-check | ported | `integrity::{a_corrupt_local_object_is_detected_by_push_and_not_sent, a_corrupt_object_on_the_remote_is_detected_by_pull_and_not_propagated}` |
| t5500 fetch-pack, t5502 quickfetch, t5552, t5554 (negotiators) | not applicable | smart protocol and pack negotiation (Veil's incremental pull is covered by `push_pull::incremental_push_and_pull_send_only_what_is_new`) |
| t5501, t5519, t5604, t5613, t5615, t5618 (alternates) | not applicable | alternates |
| t5503 tagfollow, t5525 fetch-tagopt | pending feature | Git tags in the bridge |
| t5504 fetch-receive-strict | ported | `integrity::a_corrupt_object_on_the_remote_is_detected_by_pull_and_not_propagated`, `formats::a_remote_in_a_newer_format_is_refused_without_writing` |
| t5505 remote | ported | `remotes::*` (BUG-282, BUG-286, BUG-287) |
| t5506 remote-groups, t5565 push-multiple, t5566 push-group | not applicable | no remote groups |
| t5507 remote-environment | ported | `VEIL_SSH` in every `sftp::*` test |
| t5509 namespaces, t5511 refspec, t5535 symref, t5582 negative-refspec | not applicable | no refspecs or symbolic refs (`-t TAG` is the selection: `push_pull::push_dash_t_sends_only_the_named_tags`) |
| t5510 fetch | ported | `push_pull::{pull_creates_new_tags_and_remote_tags, pull_after_the_remote_moved_backwards_keeps_the_local_tag, pull_prunes_remote_tags_that_are_gone_from_the_remote (BUG-280)}`, `git_bridge::{git_fetch_moves_remote_tags_and_pull_moves_local_tags, a_branch_deleted_on_github_is_reported_and_the_local_tag_kept}` |
| t5512 ls-remote | not applicable | no ls-remote; inspecting a bare remote is BUG-284 |
| t5513 fetch-track | ported | `push_pull::{pull_creates_new_tags_and_remote_tags, pull_of_a_diverged_tag_warns_and_keeps_both_sides}` |
| t5514 fetch-multiple | ported | `push_pull::two_remotes_have_separate_remote_tags` |
| t5515 fetch-merge-logic, t5521 pull-options, t5524 pull-msg | not applicable | FETCH_HEAD and pull's merge/rebase options (Veil's pull never merges) |
| t5516 fetch-push | ported | `push_pull::*`, `remotes::a_relative_remote_path_resolves_against_the_repository_root_from_a_subdirectory`, `push_pull::push_into_a_repository_with_a_working_copy_moves_tags_only` (deliberate) |
| t5517 push-mirror | ported (partly) | mirror-like pushes of all tags: `push_pull::push_and_pull_of_many_tags`, `visibility::*`; removal of tags is BUG-280 |
| t5518 fetch-exit-status | ported | exit codes in `push_pull::{push_and_pull_with_nothing_new_are_no_ops, pull_from_a_vanished_remote_fails_and_changes_nothing}` |
| t5520 pull | ported | `push_pull::{pull_moves_tags_but_never_the_working_copy, pull_with_unrecorded_edits_keeps_them, pull_from_an_empty_remote_succeeds_with_nothing, undo_reverts_a_pull_and_a_second_pull_redoes_it}` |
| t5522 pull-symlink | pending feature | symlinks |
| t5523 push-upstream, t5528 push-default, t5553 set-upstream | not applicable | no upstream configuration: push sends all tags (or `-t`) to `origin` or the named remote |
| t5526, t5531, t5572, t5614, t5617 (submodules) | not applicable | submodules |
| t5527 fetch-odd-refs | ported | tag names with `/` and dots in `push_pull::pull_creates_new_tags_and_remote_tags` (UTF-8 names refused: deliberate) |
| t5529 push-errors | ported | `push_pull::{push_dash_t_with_an_unknown_tag_fails_before_touching_the_remote, push_dash_t_with_a_remote_tag_name_fails}`, `remotes::push_and_pull_to_an_unknown_remote_fail_with_a_hint` |
| t5530 upload-pack-error, t5545 push-options, t5546 receive-limits, t5548 push-porcelain, t5567 one-time-script, t5570 git-daemon | not applicable | wire protocol and server options |
| t5532 fetch-proxy | not applicable | Veil runs the user's `ssh`/`git` |
| t5533 push-cas | ported | `git_bridge::{git_push_force_does_not_clobber_commits_never_fetched, git_push_force_overwrites_what_was_fetched}`; Veil-remote `--force` has no lease (deliberate) |
| t5534 push-signed, t5573 pull-verify-signatures | pending feature | signed tags / a "require signed" policy (docs/BACKLOG.md) |
| t5536 fetch-conflicts | ported | `push_pull::two_remotes_have_separate_remote_tags`, `remotes::remote_add_refuses_the_name_of_a_git_remote` (BUG-287) |
| t5537, t5538, t5539, t5542 (shallow), t5616 partial-clone, t5620 backfill | pending feature | partial and sparse clone (deferred) |
| t5540, t5541, t5549–t5551, t5555, t5557–t5564, t5581, t5584 (HTTP) | not applicable | HTTP transports |
| t5543 atomic-push | ported (deliberate difference) | `push_pull::{a_partially_rejected_push_sends_the_other_tags_and_exits_1, after_a_rejection_merge_and_push_again}` |
| t5547 push-quarantine | ported | `integrity::a_corrupt_local_object_is_detected_by_push_and_not_sent`, `push_pull::a_retried_rejected_push_sends_nothing_new` (BUG-288) |
| t5574 fetch-output | ported | messages asserted throughout `push_pull::*` and `git_bridge::*` |
| t5580 unc-paths | not applicable | Windows |
| t5583 push-branches | ported | `push_pull::push_and_pull_of_many_tags` |
| t5600 clone-fail-cleanup | ported | `clone::{clone_of_a_missing_source_fails_and_leaves_nothing, a_failed_clone_into_an_existing_empty_directory_leaves_it_empty}`, `integrity::a_clone_killed_midway_can_be_redone`, `sftp::a_connection_dropped_mid_clone_leaves_nothing`, `git_bridge::a_failed_git_import_can_be_retried_with_the_right_url` (BUG-292) |
| t5601 clone | ported | `clone::*`, `sftp::{scp_style_remote_round_trip, an_ssh_that_cannot_connect_fails_clone_push_and_pull_cleanly}` |
| t5602 clone-remote-exec | ported | `git_bridge::option_like_git_urls_never_reach_git_as_options`, `remotes::malformed_ssh_urls_are_refused` |
| t5603 clone-dirname | ported | `clone::{clone_without_a_destination_uses_the_last_path_component, clone_keeps_a_dot_veil_suffix_in_the_default_directory_name}`, `sftp::clone_over_ssh_derives_the_directory_name_or_asks_for_one` |
| t5605 clone-local | ported | `clone::{clone_of_an_empty_repository_then_push_back, clone_of_a_directory_that_is_not_a_repository_fails_and_leaves_nothing, clone_of_a_repository_with_a_working_copy}` |
| t5606 clone-options, t5611 clone-config, t5612 clone-refspec, t5621 clone-revision | not applicable | `vl clone` has no options |
| t5607 clone-bundle, t5700–t5750 (protocol v1/v2, bundle URIs), t5801, t5802 (remote helpers), t5810–t5812, t5814, t5815 (protocol whitelists) | not applicable | bundles and transports |
| t5608 clone-2gb | not applicable | scale (the 1 GB / 5 GB benchmark is a release gate); 5 MiB files in `large::*` |
| t5609 clone-branch, t5610 clone-detached | ported | `clone::{clone_starts_on_main_then_trunk_then_master_then_the_first_tag, clone_of_a_repository_without_main_starts_on_its_first_tag}` |
| t5619 clone-local-ambiguous-transport | ported | `remotes::a_colon_after_a_slash_is_a_local_path` |
| t5813 proto-disable-ssh | ported (partly) | `remotes::unsupported_url_schemes_are_refused`; the rest is Git config |
| t5900 repo-selection | not applicable | `.git` suffix search; Veil opens exactly the path given |

## Git: large files and maintenance

| Script | Status | Veil tests |
|---|---|---|
| t1050 large | ported | `large::{a_large_binary_file_round_trips_through_push_clone_and_cat, gc_stores_a_small_edit_of_a_one_mib_file_as_a_delta, gc_stores_a_small_edit_of_a_four_mib_file_as_a_delta (BUG-290), diff_of_a_large_binary_file_does_not_dump_it, a_secret_deep_inside_a_large_file_is_quarantined, two_thousand_small_files_push_and_clone, a_large_file_round_trips_through_the_git_bridge, a_file_that_grows_large_and_shrinks_to_empty}` |
| t1450 fsck | ported | `integrity::fsck_*`, `integrity::{pull_full_repairs_a_damaged_local_object, push_full_repairs_a_remote_that_lost_objects}` (BUG-289) |
| t6500 gc | ported | `gc::{gc_of_an_empty_repository, gc_with_bad_options_fails_with_usage, gc_twice_is_idempotent, gc_concurrent_with_commits_loses_nothing, gc_compression_options_keep_the_repository_usable, undo_works_after_op_log_pruning, gc_keeps_cloaked_content_and_content_it_cannot_read, push_and_pull_work_after_gc_on_both_sides}`; auto-gc, cruft packs and `--keep-largest-pack` are not applicable |

## Git: t9xxx

| Script(s) | Status | Veil tests / reason |
|---|---|---|
| t9300 fast-import | ported | `git_roundtrip::{git_import_preserves_the_fast_export_scenarios, a_git_file_to_directory_change_imports, a_change_id_header_from_git_is_honoured, a_git_symlink_is_reported_and_survives_a_veil_push, nfc_and_nfd_names_round_trip_byte_for_byte}` |
| t9350 fast-export | ported | `git_roundtrip::{veil_history_exports_with_change_ids_authors_merges_and_modes, an_empty_veil_commit_exports_as_an_empty_git_commit, deletions_and_type_changes_export_correctly, names_with_quotes_and_backslashes_round_trip, git_to_veil_to_git_keeps_every_commit_id, veil_to_git_to_veil_keeps_change_ids, two_replicas_export_the_same_commits, a_multi_paragraph_message_survives_import, author_time_survives_but_the_time_zone_becomes_utc}` |
| t9304 fast-import-marks | ported (analogue) | `.veil/git/map`: `git_roundtrip::{a_lost_git_map_is_rebuilt_without_duplicating_commits, veil_never_reimports_its_own_exports}` |
| t9301 notes, t9302, t9303 (pack internals), t9351 anonymize | not applicable | Git notes and pack options |
| t9305 signatures, t9306 signed tags | pending feature | Git commits are unsigned in 1.0; Git tags (bridge) |
| t9904 url-parse | ported | `remotes::{ssh_url_forms_are_accepted, malformed_ssh_urls_are_refused, a_colon_after_a_slash_is_a_local_path, unsupported_url_schemes_are_refused}`, `sftp::{ssh_url_user_and_port_reach_ssh_and_the_path_is_absolute, ssh_url_tilde_path_is_relative_to_the_login_directory}` |
| t9001 send-email, t9002 column, t9003 help-autocorrect, t9850 shell, t9901 web--browse, t9902 completion, t9903 bash-prompt | not applicable | not Git interop (completion and help belong to the everyday-commands series) |
| t9100–t9169 (svn), t9200 cvsexportcommit, t9400–t9402 cvsserver, t9600–t9604 cvsimport, t9800–t9836 (p4), t9500–t9502 gitweb, t9700 perl, t9210, t9211 scalar | not applicable | other bridges and tools |

## Jujutsu CLI tests

| File | Status | Veil tests / reason |
|---|---|---|
| test_git_clone.rs | ported | `clone::*`, `git_bridge::{git_import_brings_branches_as_tags_and_checks_out_main, git_import_of_an_empty_git_repository, git_import_of_a_missing_repository_fails_cleanly}` |
| test_git_fetch.rs | ported | `git_bridge::{git_fetch_moves_remote_tags_and_pull_moves_local_tags, a_branch_created_on_github_becomes_a_tag_on_pull, a_branch_force_pushed_on_github_is_reported_and_local_tags_stay, a_branch_deleted_on_github_is_reported_and_the_local_tag_kept}`, `git_roundtrip::the_same_github_commit_pulled_by_two_members_is_one_snapshot` (BUG-285), `push_pull::undo_reverts_a_pull_and_a_second_pull_redoes_it` |
| test_git_push.rs | ported | `git_bridge::{git_push_*, a_deleted_tag_deletes_the_git_branch_or_at_least_stays_deleted (BUG-280)}`, `push_pull::push_of_a_tag_set_in_another_workspace` |
| test_git_import_export.rs | ported | `git_bridge::{git_import_and_fetch_again_import_nothing, git_export_writes_the_bridge_and_prints_commits_without_pushing}`, `git_roundtrip::*` |
| test_git_remotes.rs | ported | `git_bridge::{git_remote_add_list_rm_and_duplicates, git_remote_rm_removes_the_remote_and_its_remote_tags (BUG-291), a_relative_git_remote_path_is_stored_absolute, credentials_in_git_remote_urls_are_redacted}`, `remotes::*` |
| test_git_init.rs | ported | `git_bridge::{git_import_brings_branches_as_tags_and_checks_out_main, git_import_into_a_repository_with_its_own_history}` |
| test_git_private_commits.rs | ported (analogue) | cloaked workspaces are Veil's private commits: `git_bridge::git_push_exports_only_the_public_view`, `visibility::*` |
| test_git_colocated.rs, test_git_colocation.rs | pending feature | colocated Git mode (1.1) |
| test_git_root.rs | pending feature | colocated Git mode |
| test_bookmark_command.rs (remote tracking, conflicted bookmarks) | ported | tracking: `push_pull::{pull_creates_new_tags_and_remote_tags, push_updates_the_remote_tags (BUG-281)}`; conflicted (diverged) tags: `push_pull::{pull_of_a_diverged_tag_warns_and_keeps_both_sides, after_a_rejection_merge_and_push_again}`; deletion: BUG-280 |
| test_concurrent_operations.rs | ported | `concurrency::*`, `git_bridge::concurrent_git_pushes_from_one_repository_are_safe`, `sftp::two_concurrent_ssh_pushes_both_land` |
| test_util_command.rs (`util gc`) | ported | `gc::*` |
| test_debug_command.rs, test_debug_init_simple_command.rs | not applicable | no debug commands; `vl fsck -v` and `vl doctor` are tested by `integrity::*` and existing suites |
| test_advance_bookmarks.rs, test_gitignores.rs | not applicable here | everyday-commands series (commit moving tags, ignore rules) |

## Jujutsu library tests

| File | Status | Veil tests / reason |
|---|---|---|
| test_git.rs | ported | `git_roundtrip::*`, `git_bridge::*` (import/export, divergence, deleted and force-pushed branches, change-id headers) |
| test_git_backend.rs | not applicable | Git as Veil's storage backend does not exist |
| test_load_repo.rs | ported | `formats::*` |
| test_bad_locking.rs | ported | `concurrency::a_push_killed_while_holding_the_remote_lock_does_not_block_the_next`, `integrity::{a_push_killed_midway_leaves_a_consistent_remote, a_pull_killed_midway_leaves_a_consistent_repository}` |
| test_concurrent_operations.rs, test_commit_concurrent.rs, test_merge_operations.rs | ported | `concurrency::*`, `gc::gc_concurrent_with_commits_loses_nothing` (Veil serialises writers on a lock rather than merging concurrent operations; docs/BACKLOG.md) |
| test_operations.rs | ported | `push_pull::undo_reverts_a_pull_and_a_second_pull_redoes_it`, `gc::undo_works_after_op_log_pruning` |
| test_index.rs | pending feature | a history index (docs/BACKLOG.md); nothing to test yet |
| test_local_working_copy_concurrent.rs | not applicable here | working-copy series |

## Acceptance scenarios for pending features

* **Git tags in the bridge** (t5305, t5503, t5525, t9306): an annotated and a
  lightweight Git tag import as Veil tags (or a separate namespace) without
  becoming branches on the next push; a Veil release tag exports as a Git
  tag; a cloaked tag never does; a tag on an unreleased embargo is held
  back; deleting either side is reported.
* **Tag deletion on remotes** (BUG-280 fix): `vl push --delete TAG` (or a
  tracked deletion) removes the tag on Veil and Git remotes; `vl pull`
  prunes `origin/TAG` and does not recreate a tag deleted locally since
  the last pull; a teammate's pull then drops it too.
* **Colocated Git mode** (test_git_colocated): `git status` in a colocated
  directory never shows cloaked plaintext; `git commit` there imports like
  a GitHub commit; isolated files stay out of `.git`.
* **Hooks** (t5401, t5571): a pre-push hook sees the public view only for
  public remotes.
* **Partial and shallow clone** (t5537, t5616): a shallow clone of a team
  remote still verifies signatures and key rings; deepening fills in.
* **Signed commits and a "require signed" policy** (t5534, t5573, t9305).
* **Symlinks** (t5522): a Git symlink imports as a symlink; checkout never
  writes through one (BUG-025 class).
* **Thin packs / chunking** (t1050 "packsize"): a 64-byte edit of a 4 MiB
  file sends far less than 4 MiB.
* **`vl archive`** (t5000–t5004): an archive of a snapshot holds the
  public view for non-members, never cloaked plaintext.
