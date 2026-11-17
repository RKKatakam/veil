# Test Suite Speed, Sharding, and Server Isolation Proposal

> **Principle (Claude Code team):** *"If your tests are flaky you'll train the agent to run them again rather than fixing the failing code. If your tests are slow, the agent will do fewer tests… Heavier tests are best deployed before you've committed."*

This document presents live measurements from `integration` (`ff29db9b`) on the shared 32-vCPU / 30 GiB RAM machine (`~/.cache/veil-orch/heavy-lock.sh`, `-j 8`, warm `sccache`, PostgreSQL 17 on `veil-shared-pg:5435`, YugabyteDB `2025.2.8.1` on `veil-shared-yb:5436`, MinIO on `veil-shared-s3:9010`), an exhaustive isolation audit of all 970 tests in `crates/veil-server/tests/server_hub/`, and a concrete, ranked engineering proposal.

---

## 1. Measurements

### 1.1 Codebase & Test Binary Shape

| Crate | `src/` LOC | Unit Tests (`#[ignore]`) | `tests/` LOC | Integration Binaries | Integration Tests (`#[ignore]`) | Notes |
|---|---:|---:|---:|---:|---:|---|
| `veil-core` | 66,132 | 198 (0) | 41,395 | 10 | 943 (26) | 16 deep property tests gated on `VEIL_DEEP_PROPS=1` |
| `vl` | 41,138 | 73 (0) | 37,467 | 9 | 1,177 (13) | Spawns `vl` (`107 MiB` debug binary) subprocesses |
| `veil-server` | 62,942 | 116 (1) | 74,780 | 1 (`server_hub`) | 970 (18) | 939 active standard + 13 active `hostile_` (`--features containers`) |
| `veil-bench` | 7,240 | 20 (1) | 0 | 0 | 0 | Benchmarks |
| **Total** | **177,452** | **407 (2)** | **153,642** | **20** | **3,090 (57)** | **46.4% of all Rust code (`153,642 / 331,094` LOC) is in `--test` binaries** |

**Key structural finding:** `sccache` only caches `--crate-type lib` / `rlib` / `proc-macro` compilations and **never** caches `--crate-type bin` (which Cargo uses for every unit-test harness, integration test binary, and `vl`/`veil-server` binary). Consequently, 46.4% of the repository's Rust LOC—including the single `74,780`-LOC, `257 MiB` `server_hub` binary—recompiles and relinks through GNU `ld` 2.46 from scratch whenever `target/` is deleted.

---

### 1.2 End-to-End Pipeline Breakdown (`verify-fast.sh` vs. `verify-server.sh`)

#### `verify-fast.sh` (~5.5 min wall today; `8.15 GB` across 3 `target/` trees, then `rm -rf target`)

Measured under `heavy_acquire` (`-j 8`, warm `sccache`, `TMPDIR=/tmp/claude-1000/carbon3`):

| Step | Command / Target Dir | Wall Time | Notes |
|---|---|---:|---|
| Metadata | `cargo metadata --format-version=1` | `0.17s` | Required to bypass `vl`'s mutually-conflicting `fuse`/`macfuse` features |
| Build workspace tests | `cargo nextest run --no-run --workspace --all-targets -j 8` (`target/`) | **`52.60s`** | `3.28 GB` in `target/`; `+224` `sccache` `Non-cacheable (crate-type)` calls |
| Run workspace tests | `cargo nextest run --workspace --all-targets` (`2,497` tests) | **`180.16s`** | `sum = 2,491.23s`, `p50 = 0.229s`, `p90 = 1.396s`, `p99 = 17.334s`, `max = 176.606s` |
| Parallel lint lane | `cargo clippy --all-targets` (`target/lint`, runs alongside nextest) | `10.51s` | **Bug:** omits `--workspace`, so `veil-server` and `veil-bench` are skipped (`21.32s` with `--workspace --features veil-server/containers` sharing `target/`) |
| Parallel doc lane | `cargo doc --no-deps --workspace` (`target/lint`, runs alongside nextest) | `28.09s` | Rebuilds proc-macros & metadata into separate `target/lint` |
| WASM build matrix | `bash scripts/check-wasm.sh` (`target/wasm-check`, sequential) | **`109.00s`** | **10 sequential `cargo` invocations** across 4 feature/target combos + `--release` WASM build |
| Ignored BUG tests | `bash ~/.cache/veil-orch/verify-ignored.sh` (`target/`, sequential) | **`43.61s`** | Uses `cargo test -- --ignored` (`19.43s` via `nextest --run-ignored only`); runs 11 open-bug repros (9 fail) whose exit code `verify-fast.sh` discards |
| Teardown | `rm -rf target` | `~2.5s` | Destroys `8.15 GB` of fresh artifacts right before `verify-server.sh` |
| **Total (`verify-fast.sh`)** | *(build+nextest overlapped with lint+doc, then WASM, then ignored)* | **`~332–388s` (`5.5–6.5m`)** | **1 single test (`bug_1294`, `176.6s`) dictates 98.2% of the `180.2s` nextest wall time** |

> **Paper-cut bug found in `~/.cache/veil-orch/verify-fast.sh`:** Setting `TMPDIR="$PWD/.scratch/tmp"` inside T3 worktrees (`/home/kittu/.t3/worktrees/veil/t3-<8hex>-<16hex>/.scratch/tmp/...`) pushes Unix domain socket paths over `SUN_LEN` (`108` bytes), deterministically failing 5 `vl::cli_workspaces` tests (`confine_cli` ×4, `p1pass_confine_cli` ×1) that pass `2,497 / 2,497` with `TMPDIR=/tmp/claude-1000/<agent>`.

#### `verify-server.sh` (~35.5 min standard; ~81.5 min quiet to 2.5+ hours contended with `VEIL_VERIFY_HOSTILE=1`)

Measured across our heavy-lock run (`carbon3`) and `ff29db9b` verification logs (`merge-round-1116` and `fable`):

| Phase | Step | Engine | Wall Time | Share of Standard (`35.5m`) | Share of Full `HOSTILE=1` (`81.5m` quiet) |
|---|---|---|---:|---:|---:|
| **Build** | `cargo build --bins` (`vl` `107 MiB`, `veil-server` `178 MiB`) + `server_hub` (`257 MiB`) | Host | **`90.0s` (`1.5m`)** reusing `target/` (`~135s` cold after `rm -rf target`) | `4.2%` | `1.8%` |
| **Migrate** | Create + migrate 36 SQL files (`v1..42`) | PG 17 | **`1.3s`** (`0.37s` `CREATE DB` + `0.95s` migrate) | `<0.1%` | `<0.1%` |
| **Migrate** | Create + migrate 36 SQL files (`v1..42`) | YB 2025.2 | **`32.8s`** (`0.77s` `CREATE DB` + `32.0s` migrate) | `1.5%` | `0.7%` |
| **Unit+Lint** | `veil-server --lib` (116 tests) + `clippy --features containers` | Host | **`~40.0s` (`0.7m`)** | `1.9%` | `0.8%` |
| **PG Suite** | `server_hub --skip hostile_` (`939` tests, `libtest` 32 threads) | PG 17 + S3 | **`394.2s–411.6s` (`6.6–6.9m`)** (`616.6s` via `nextest -j 16`, peak RSS `5.6 GiB`) | `18.6%` | `8.1%` |
| **YB Suite** | `server_hub --skip hostile_` (`939` tests, `libtest` `--test-threads=8`) | YB + S3 | **`1,369.0s–1,383.5s` (`22.8–23.1m`)** | **`64.6%`** | **`28.2%`** |
| **PG Load** | `load-postgres`: 8 parallel processes × `concurrency` (`64` tests) | PG 17 + S3 | **`~75.0s` (`1.3m`)** | `3.5%` | `1.5%` |
| **YB Load** | `load-yugabyte`: 3 parallel processes × `concurrency` (`24` tests) | YB + S3 | **`~155.0s` (`2.6m`)** | **`7.3%`** | `3.2%` |
| *Hostile PG* | `hostile-postgres` (`13` tests, `--test-threads=1`, `HOSTILE=1` only) | PG 17 + S3 | *`982.3s–990.6s` (`16.4m`)* | — | *`20.2%`* |
| *Hostile YB* | `hostile-yugabyte` (`13` tests, `--test-threads=1`, `HOSTILE=1` only) | YB + S3 | *`1,767.7s` (`29.5m` quiet; up to `~9,000s` / `2.5h` under catalog contention)* | — | ***`36.2%`*** *(up to >80% contended)* |
| **Total** | **Standard (`HOSTILE=0`) / Full (`HOSTILE=1` quiet)** | **Both** | **`~2,130s` (`35.5m`) / `~4,890s` (`81.5m` quiet, `2.5h+` contended)** | **`100%`** | **`100%`** |

**How much of `verify-server.sh` is YugabyteDB?**
- **Standard (`VEIL_VERIFY_HOSTILE=0`):** `32.8s` (migrate) + `1,376s` (`server_hub`) + `155s` (`load-yugabyte`) = **`1,564s` (`26.1 min` out of `35.5 min` = `73.5%`)**.
- **With `VEIL_VERIFY_HOSTILE=1`:** `1,564s` + `1,768s` (`hostile-yugabyte`) = **`3,332s` (`55.5 min` out of `81.5 min` = `68.2%` on an idle cluster, rising past `80%` / `2.5+ hours` when concurrent DDL triggers catalog stalls)**.
- **Hidden cause of the 23-minute YugabyteDB `server_hub` run:** Inside `server_hub`, **32 tests** create and migrate a fresh database from scratch (`32 × 32.8s = ~1,050s` = **`17.5 minutes` of serial and unserialized migration DDL** embedded inside the 23-minute test run!).

---

### 1.3 Workspace `nextest` Distribution & Top 50 Slowest Tests (`2,497` tests)

- **Totals:** `2,497` tests (`0` failed), cumulative CPU test time `2,491.23s` (`41.5 min`), wall `179.90s` (`3.00 min`), `p50 = 0.229s`, `p90 = 1.396s`, `p99 = 17.334s`, `max = 176.606s`.
- **Skew:** Only **9 tests (`0.36%`)** take `>= 30s` (`sum = 637.98s`), and **49 tests (`1.96%`)** take `>= 10s` (`sum = 1,287.50s`, `51.7%` of all test time). `2,175` tests (`87.1%`) finish in `< 1s`.

| Rank | Time (s) | Suite / Test |
|---:|---:|---|
| 1 | 176.606 | `veil-core::core_durability metadata_lock::bug_1294_lock_free_commits_keep_their_files` |
| 2 | 107.397 | `veil-core::core_props oplog_merge::bug_2464_rewrites_follow_in_long_runs_replayed` |
| 3 | 73.260 | `veil-core::core_props oplog_merge::bug_1503_a_merge_rebase_of_a_commit_made_since_the_shared_history_is_not_taken_for_undone` |
| 4 | 61.002 | `veil-core::core_props oplog_merge::bug_1503_rewrites_follow_in_long_runs` |
| 5 | 56.255 | `veil-core::core_props oplog_merge::bug_2464_guard_two_settlers_rebase_one_commit_replayed` |
| 6 | 48.646 | `vl::cli_features history_cli::history_tools_never_reveal_confidential_content` |
| 7 | 40.917 | `vl::scale_findings_cli many_concurrent_commands_all_succeed` |
| 8 | 39.589 | `veil-core::core_props team_vault_props::replicas_converge` |
| 9 | 34.305 | `veil-core blame::tests::s14c2_trimmed_map_lines_equals_the_whole_texts_diff` |
| 10 | 26.796 | `vl::cli_security embargo_copy_cli::random_rewrites_and_working_copy_commands_never_push_what_an_unreleased_embargo_withholds` |
| 11 | 26.078 | `veil-core::core_props oplog_merge::every_write_survives_concurrent_merges_memory` |
| 12 | 25.930 | `veil-core::core_security ring_shares::the_servers_devices_never_enter_a_ring` |
| 13 | 24.445 | `veil-core::core_props oplog_merge::every_write_survives_concurrent_merges_with_describes_memory` |
| 14 | 23.721 | `veil-core::core_props oplog_merge::bug_2464_guard_a_describe_s_rebase_from_the_shared_history_replayed` |
| 15 | 23.600 | `vl::cli_basic working_copy_cli::s7_watcher::clifast_review_status_and_commit_with_the_watcher_match_a_full_scan_over_a_walk_of_changes` |
| 16 | 22.544 | `vl::cli_workspaces mount_cli::a_mount_writes_and_renames_large_files_without_holding_them` |
| 17 | 22.003 | `veil-core::core_props hostile_labels_props::hostile_labels_never_make_new_plaintext_readable_outside_its_audience` |
| 18 | 21.826 | `veil-core::core_security adversarial7_core::conflicts::conflict_and_diff_time_is_linear_on_crafted_input` |
| 19 | 20.743 | `vl::cli_workspaces mount_props::a_mount_under_grants_moves_undo_and_crashes_matches_the_model` |
| 20 | 20.363 | `veil-core::core_props adversarial6_props::a_mutated_ring_verifies_only_to_the_same_state` |
| 21 | 20.271 | `vl::cli_adversarial adversarial8::sandbox::a_busy_repository_lock_at_record_time_keeps_the_run` |
| 22 | 19.554 | `veil-core::core_props oplog_merge::bug_1295_every_write_survives_with_undo_and_restore` |
| 23 | 18.685 | `vl::cli_security embargo_copy_cli::random_rewrites_never_push_what_an_unreleased_embargo_withholds` |
| 24 | 18.202 | `veil-core::core_security adversarial5_scanner::random_tokens_under_v6_keys_are_found` |
| 25 | 17.334 | `veil-core::core_engine watched::a_watched_build_on_a_loaded_cache_records_what_a_full_scan_does_disk` |
| 26 | 17.024 | `veil-core::core_props oplog_merge::merges_keep_every_operation_memory` |
| 27 | 16.590 | `veil-core::core_props adversarial2_props::visibility_invariants_hold_with_one_embargo_at_a_time` |
| 28 | 16.459 | `veil-core::core_props adversarial2_props::visibility_invariants_hold_with_overlapping_embargoes` |
| 29 | 16.409 | `veil-core::core_props policy_fold_props::a_folded_edit_is_never_weaker_than_both_policies` |
| 30 | 16.361 | `vl::cli_workspaces confine_cli::s6r2_a_daemon_folder_made_again_during_a_run_stays_hidden` |
| 31 | 14.974 | `veil-core::core_working_copy symlinks::a_sandbox_never_resolves_outside_itself_through_any_links` |
| 32 | 12.951 | `veil-core::core_sync remote_init_race::concurrent_first_pushes_to_an_empty_remote_all_succeed` |
| 33 | 12.756 | `veil-core::core_durability crash::rvgaps_crash_during_rewrites` |
| 34 | 12.400 | `veil-core::core_durability crash::crash_during_gc` |
| 35 | 12.127 | `veil-core::core_props oplog_merge::rewrites_follow_with_refs_to_old_versions_memory` |
| 36 | 12.030 | `vl::cli_workspaces confine_cli::killing_vl_at_any_moment_leaves_nothing_and_the_next_run_recovers` |
| 37 | 11.834 | `vl::cli_workspaces workspace_undo_props::undo_and_switch_never_lose_an_unrecorded_edit` |
| 38 | 10.977 | `vl::cli_adversarial adversarial_cli_abuse::hostile_revsets_never_panic` |
| 39 | 10.921 | `vl::cli_workspaces mount_cli::bug_1365_open_files_of_a_mount_are_not_held_in_memory` |
| 40 | 10.730 | `vl::cli_basic gc::background_maintenance_starts_only_where_allowed_and_once` |
| 41 | 10.659 | `veil-core::core_props oplog_merge::rewrites_follow_through_concurrent_merges_memory` |
| 42 | 10.535 | `vl::cli_workspaces confine_cli::a_hung_systemctl_after_a_scoped_run_does_not_keep_vl_from_recording` |
| 43 | 10.521 | `vl::cli_workspaces confine_cli::a_slow_systemd_user_manager_does_not_hang_vl` |
| 44 | 10.512 | `veil-core::core_durability adversarial2_durability::two_contenders_never_both_take_over_a_dead_lock` |
| 45 | 10.275 | `veil-core::core_security scanner::a_chunk_boundary_inside_a_code_line_is_not_a_configuration_line` |
| 46 | 10.172 | `veil-core::core_engine watched::a_watched_build_on_a_loaded_cache_records_what_a_full_scan_does_memory` |
| 47 | 10.128 | `vl::cli_adversarial adversarial7::serve::silent_connections_never_lock_other_clients_out` |
| 48 | 10.072 | `veil-core::core_durability adversarial6_lock::a_garbage_lock_file_is_handled_within_the_wait` |
| 49 | 10.013 | `veil-server store::tests::bug_1622_a_full_bound_on_indexes_is_answered_busy_through_every_reader` |
| 50 | 9.528 | `veil-core::core_props hostile_labels_props::a_merge_of_two_scopes_never_moves_the_pending_edit` |

#### Top 20 Workspace Modules by Cumulative Time (of 215)

| Rank | Total (s) | Share | Count | Max (s) | Module |
|---:|---:|---:|---:|---:|---|
| 1 | 452.15 | 18.1% | 40 | 107.397 | `veil-core::core_props::oplog_merge` |
| 2 | 188.07 | 7.5% | 5 | 176.606 | `veil-core::core_durability::metadata_lock` |
| 3 | 102.18 | 4.1% | 30 | 12.756 | `veil-core::core_durability::crash` |
| 4 | 101.30 | 4.1% | 52 | 16.361 | `vl::cli_workspaces::confine_cli` |
| 5 | 93.95 | 3.8% | 288 | 3.586 | `vl::cli_conformance::conformance_worktree` |
| 6 | 90.23 | 3.6% | 219 | 1.715 | `vl::cli_conformance::conformance_history` |
| 7 | 84.13 | 3.4% | 29 | 48.646 | `vl::cli_features::history_cli` |
| 8 | 71.70 | 2.9% | 127 | 3.944 | `vl::cli_conformance::conformance_sync` |
| 9 | 65.92 | 2.6% | 35 | 20.271 | `vl::cli_adversarial::adversarial8` |
| 10 | 60.09 | 2.4% | 20 | 26.796 | `vl::cli_security::embargo_copy_cli` |
| 11 | 46.68 | 1.9% | 10 | 22.544 | `vl::cli_workspaces::mount_cli` |
| 12 | 42.33 | 1.7% | 6 | 22.003 | `veil-core::core_props::hostile_labels_props` |
| 13 | 41.06 | 1.6% | 10 | 23.600 | `vl::cli_basic::working_copy_cli` |
| 14 | 40.92 | 1.6% | 1 | 40.917 | `vl::scale_findings_cli` |
| 15 | 40.28 | 1.6% | 7 | 34.305 | `veil-core::blame` |
| 16 | 39.59 | 1.6% | 1 | 39.589 | `veil-core::core_props::team_vault_props` |
| 17 | 33.58 | 1.3% | 4 | 16.590 | `veil-core::core_props::adversarial2_props` |
| 18 | 30.54 | 1.2% | 9 | 25.930 | `veil-core::core_security::ring_shares` |
| 19 | 30.02 | 1.2% | 13 | 21.826 | `veil-core::core_security::adversarial7_core` |
| 20 | 27.59 | 1.1% | 3 | 17.334 | `veil-core::core_engine::watched` |

---

### 1.4 `server_hub` on PostgreSQL: Distribution, Top 50 Slowest Tests, and `setup_project` Cost (`939` tests)

- **Totals (`nextest --test-threads=16` on isolated DB `r198622xmain`):** `939` tests (`0` failed), cumulative test time **`9,137.31s` (`2.54` CPU-hours)**, wall `616.62s` (`10.28 min`; `394.23s` / `6.57 min` under `libtest` 32 threads), **`p50 = 7.111s`**, `p90 = 16.018s`, `p99 = 73.510s`, `max = 142.626s`. Peak cgroup RSS: **`5.6 GiB`** (`2.4 GiB` steady).
- **Why `p50` is `7.111s` (`708` of `939` tests = `75.4%` take `>= 5s`):** `support::setup_project(&hub)` (`crates/veil-server/tests/server_hub/support.rs:830`), called **`576` times** across `server_hub`, spawns **38 `vl` (`107 MiB` debug) subprocesses wrapped in 38 `/usr/bin/timeout` subprocesses = 76 fork/execs per call** (5 `vl login`s with Argon2/TLS handshakes, `init`, `remote add`, 3 commits+pushes, 3 `group create`, 3 `fingerprint`+`group add`, 4 `access` grants, `project_fingerprint`, and 4 full clones + `identity confirm`s). That is **`43,776` subprocess spawns per `server_hub` run** (`87,552` across PG + YB), accounting for ~65% of the median test's runtime!

| Rank | Time (s) | Test (`veil-server::server_hub`) | Notes |
|---:|---:|---|---|
| 1 | 142.626 | `landing::bug_1107_a_batch_of_one_line_changes_in_a_big_folder_stays_within_memory` | **Pure in-memory** (no DB/S3), yet run twice (PG + YB)! |
| 2 | 130.071 | `landing::a_submit_whose_base_is_past_its_walk_budget_is_answered_warming` | Large graph walk |
| 3 | 127.798 | `landing::bug_1302_a_submit_s_stack_never_walks_the_branch_s_history_per_change` | Large history stack |
| 4 | 126.766 | `landing::bug_1468_stepping_over_a_hidden_run_costs_the_same_however_long_the_run` | `own_database` |
| 5 | 115.524 | `landing::bug_1405_a_change_on_a_snapshot_of_the_branch_that_landings_does_not_know_lands` | Shared DB |
| 6 | 101.078 | `landing_hold::bug_1956_every_kind_of_edit_lands_as_landing_them_one_by_one` | Shared DB |
| 7 | 88.313 | `startup::bug_2482_an_index_migration_on_a_large_table_written_meanwhile_holds_every_row` | `4,000,000` PG / `300,000` YB rows; unserialized `fresh_database` |
| 8 | 78.077 | `startup::bug_2571_an_index_no_build_made_whole_fails_the_start_unrecorded_and_the_next_start_builds_it` | 5× online index rebuilds + 15s wait; unserialized `fresh_database` |
| 9 | 75.798 | `concurrency::shares_racing_a_removal_never_keep_a_removed_device` | Run **13×** per `verify-server.sh` (PG + YB + 8 PG load + 3 YB load) |
| 10 | 73.510 | `limits::bug_1331_vl_waits_out_a_rate_limit` | Real wall-clock rate-limit wait |
| 11 | 71.530 | `landing::bug_1272_a_stack_of_changes_in_a_big_folder_stays_within_the_batch_bound` | **Pure in-memory** (no DB/S3), run twice! |
| 12 | 63.871 | `landing::bug_1521_a_change_on_a_snapshot_many_hidden_changes_share_is_accepted_as_with_few` | Shared DB |
| 13 | 60.595 | `workspaces::s8kr_a_push_after_the_server_moved_costs_no_request_a_tag` | Many `vl` subprocesses |
| 14 | 60.472 | `blame::s14rd_review::bug_1307_a_job_blames_a_version_another_server_still_holds` | Multi-`TestHub` |
| 15 | 59.720 | `thin::s16_unreachable_or_warming_server_is_reported_clearly` | Backoff / timeout sleeps |
| 16 | 57.726 | `landing::bug_1409_a_change_on_more_hidden_changes_than_the_walk_budget_lands_as_it_would_with_none_below` | Shared DB |
| 17 | 50.297 | `blame::blame_and_history_match_the_projected_files` | Property walk |
| 18 | 49.516 | `prs::s21_c4::merge_check_past_underived_bound_answers_busy` | `own_database` (`Storage::Dir`) |
| 19 | 47.808 | `daemon::bug_1681_daemon_follow_polls_tips_every_second_while_idle` | Real-time 1s polling sleeps |
| 20 | 47.702 | `query::query_graph_matches_direct_walks` | Shared DB |
| 21 | 45.267 | `concurrency::bug_1593_a_landing_is_one_database_commit` | Run 13× per `verify-server.sh` |
| 22 | 44.030 | `query::s3rd_resolve_caps_reveal_no_withheld_snapshot` | Shared DB |
| 23 | 42.872 | `blame::s14rd3_review::bug_1554_one_persons_projects_fill_the_server_wide_job_limit` | Shared DB |
| 24 | 42.367 | `landing::bug_2510_a_server_new_to_a_projected_snapshot_resolves_it_without_reading_the_run_on_it` | `own_database` |
| 25 | 41.026 | `daemon::bug_1680_no_idle_renewals_warm_store_after_idle_and_server_backoff` | Real-time idle/backoff sleeps |
| 26 | 40.963 | `packs::bug_865_a_long_history_is_checked_several_at_once_with_the_same_answers` | Shared DB |
| 27 | 39.907 | `landing::bug_2510_a_server_new_to_a_committed_snapshot_resolves_it_without_reading_the_run_on_it` | `own_database` |
| 28 | 39.504 | `rc_server::bug_1924_a_pr_that_lands_after_its_request_was_answered_queued_is_landed` | Shared DB |
| 29 | 37.342 | `pack_merge_bg::bug_2462_a_busy_projects_packs_stay_bounded_under_a_sustained_listing_rate` | Sustained rate loop |
| 30 | 37.073 | `landing::only_the_lease_holder_lands_and_every_ticket_lands_once_across_servers` | Multi-`TestHub` |
| 31 | 36.907 | `cache::s9_cycle2::the_caches_answers_are_the_servers_for_every_viewer_and_project` | Shared DB |
| 32 | 35.368 | `landing::bug_1635_landings_waiting_for_their_outcome_never_fill_the_projects_bulkhead` | Shared DB |
| 33 | 34.010 | `search::search_every_route_is_bounded_at_scale` | Scale search |
| 34 | 33.245 | `landing::a_change_landed_by_any_route_at_any_depth_is_never_landed_again` | Shared DB |
| 35 | 32.965 | `prs::pr_projection_equivalence` | Shared DB |
| 36 | 32.944 | `cache::s9_adversarial::the_caches_answers_are_the_servers_byte_for_byte` | Shared DB |
| 37 | 31.703 | `packs::a_push_of_more_than_max_objects_lands_and_releases_every_share` | Large pack push |
| 38 | 31.464 | `startup::bug_2571_an_index_whose_build_returned_it_incomplete_is_built_again_before_the_migration_is_recorded` | 3× online index builds; unserialized `fresh_database` |
| 39 | 30.713 | `limits::every_landing_bound_refuses_clearly_names_nothing_hidden_and_never_half_lands` | Custom `limits` |
| 40 | 29.583 | `adversarial_s10::bug_1911_a_renamed_secret_taken_apart_by_split_or_squash_is_accepted` | Shared DB |
| 41 | 29.096 | `branch_landing::bug_2221_is_below_matches_is_ancestor_over_random_histories_in_two_projects` | Random histories |
| 42 | 28.519 | `landing_hold::bug_1955_a_batch_read_on_several_threads_is_the_batch_built_on_one` | Shared DB |
| 43 | 28.212 | `rv_gaps::rvgaps_thin_clone_of_a_partial_viewer_answers_as_their_full_clone` | Thin clone |
| 44 | 27.693 | `clone_one::a_fresh_clone_cut_before_its_one_barrier_is_refused_never_usable` | Shared DB |
| 45 | 27.011 | `workspaces::s8jr_a_push_costs_no_request_a_tag` | Shared DB |
| 46 | 26.678 | `limits::every_connection_slot_comes_back_in_bounded_time` | Connection timeout sleep |
| 47 | 26.384 | `landing::bug_1466_a_change_with_many_revisions_landed_long_ago_is_not_landed_again` | Shared DB |
| 48 | 25.796 | `adversarial_s10::bug_1053_a_change_of_ten_thousand_files_lands_on_s3` | 10,000-file S3 upload |
| 49 | 25.349 | `cache::s9_cycle2::bug_1183_a_body_that_never_arrives_holds_its_connection_slot` | Slowloris timeout |
| 50 | 25.054 | `embargo_prs::guarantee_1_embargoed_pr_is_visible_only_to_members_and_admins_and_nonexistent_to_outsiders` | Shared DB |

#### Top 25 `server_hub` Modules by Cumulative PG Time (of 58)

| Rank | Total (s) | Share | Count | Max (s) | Module |
|---:|---:|---:|---:|---:|---|
| 1 | 1,884.61 | 20.6% | 121 | 142.626 | `landing` |
| 2 | 833.29 | 9.1% | 64 | 60.595 | `workspaces` |
| 3 | 363.41 | 4.0% | 44 | 60.472 | `blame` |
| 4 | 304.26 | 3.3% | 28 | 36.907 | `cache` |
| 5 | 277.61 | 3.0% | 69 | 49.516 | `prs` |
| 6 | 270.45 | 3.0% | 44 | 11.907 | `agents` |
| 7 | 269.19 | 2.9% | 22 | 73.510 | `limits` |
| 8 | 252.10 | 2.8% | 21 | 47.808 | `daemon` |
| 9 | 241.12 | 2.6% | 14 | 88.313 | `startup` |
| 10 | 240.39 | 2.6% | 13 | 101.078 | `landing_hold` |
| 11 | 229.69 | 2.5% | 16 | 25.054 | `embargo_prs` |
| 12 | 224.35 | 2.5% | 23 | 16.428 | `rv_core2` |
| 13 | 220.48 | 2.4% | 29 | 47.702 | `query` |
| 14 | 211.30 | 2.3% | 19 | 40.963 | `packs` |
| 15 | 198.27 | 2.2% | 19 | 16.018 | `shares` |
| 16 | 173.83 | 1.9% | 49 | 59.720 | `thin` |
| 17 | 173.82 | 1.9% | 8 | 75.798 | `concurrency` |
| 18 | 151.81 | 1.7% | 20 | 17.264 | `sync` |
| 19 | 149.27 | 1.6% | 11 | 28.212 | `rv_gaps` |
| 20 | 146.33 | 1.6% | 17 | 34.010 | `search` |
| 21 | 135.80 | 1.5% | 8 | 29.096 | `branch_landing` |
| 22 | 123.97 | 1.4% | 10 | 15.454 | `embargo` |
| 23 | 115.79 | 1.3% | 12 | 20.774 | `grants` |
| 24 | 114.32 | 1.3% | 16 | 20.061 | `adversarial` |
| 25 | 111.73 | 1.2% | 12 | 29.583 | `adversarial_s10` |

---

### 1.5 Server Test Isolation & Database-Wide State Audit (`970` tests across `58` modules)

#### Classification of all `970` tests in `crates/veil-server/tests/server_hub/`

| Isolation Class | Active Standard (`939`) | Active `hostile_` (`13`) | `#[ignore]` (`18`) | Total (`970`) | Hazard Summary |
|---|---:|---:|---:|---:|---|
| **Shared DB + Shared S3 bucket** (`TestHub::start` / `start_with_ttl` / `start_with_limits`) | **875** (`93.2%`) | **13** (`100%`) | **17** | **905** | Collides on DB-wide background loops, DDL, catalog versions, fixed IDs, global queries |
| **Shared DB + S3 fault proxy -> Shared S3 bucket** (`landing_hold::bug_1982`, `store_s3::bug_2430`, `sync::bug_861`, `sync::bug_1005`) | **4** (`0.4%`) | 0 | 0 | **4** | Shares run DB and run S3 bucket |
| **Own DB (serialized via `support::own_database`) + Shared S3 bucket** (`branch_count` ×4, `commits` ×1, `grants` ×2, `landing` ×3, `landing_speed` ×2, `pack_gc` ×2, `shares` ×1 PG-only, `thin` ×1) | **16** (`1.7%`) | 0 | 0 | **16** | **Collides in S3!** Fresh DB resets `projects_id_seq = 1`, writing `p/1/...` over the run DB's project 1 (`BUG-2620`); never dropped until script exit |
| **Own DB (UNSERIALIZED, bypasses `support::MIGRATING`) + Shared S3 / SQL-only** (`startup` ×11, `blame::migration_0015` ×1) | **12** (`1.3%`) | 0 | 0 | **12** | Concurrent online index builds stall YB catalog (`BUG-2582`, `BUG-2571`); `startup.rs:69` leaks cluster-wide `CREATE ROLE` |
| **Own DB (serialized via `BUG-2580` guard) + Own `Storage::Dir`** (`embargo_prs::bug_2580`, `grants::bug_1083`, `landing_hold::bug_1955`, `pack_gc::guarantee_5`, `prs::merge_check_past_underived_bound_answers_busy`) | **5** (`0.5%`) | 0 | 0 | **5** | Fully isolated, but costs `32.8s` per test on YB and leaks its YB tablets until script exit |
| **Pure in-memory (no `TestHub`, no DB, no S3)** (`prs` classifiers ×12, `landing::bug_1107`/`1272`/`1684`, `store_s3` unit mocks ×3, `adversarial_s10` ×2, `adversarial_s4` ×1, `derived` ×1, `grants` ×1, `rv_s26` ×1, `startup` ×1, `thin` ×1, `web_html` ×1) | **27** (`2.9%`) | 0 | **1** | **28** | Pure CPU/memory tests (~`250s` sum) needlessly compiled into `server_hub` and executed **twice** (PG + YB) |

#### Database-Wide & Cluster-Wide State Written or Scanned Across Tests

1. **Background `embargo::run_loop` on every `TestHub` (`lib.rs:270`, `embargo.rs:790`) + 32 explicit `embargo::release_due` / `release_one` calls** (`embargo.rs`, `embargo_prs.rs`, `landing.rs:7645`, `rv_access.rs`, `rv_landing.rs`): scans `SELECT project_id, embargo_id FROM embargo_lines WHERE released_at IS NULL AND until_ms <= ...` **across the entire database** without `project_id` scoping. Any `TestHub` with a separate store (`BUG-2457`, `BUG-2580`) or fault-injected store marks other tests' embargoes `failed`.
2. **Global `LISTEN` / `NOTIFY` (`lib.rs:266-268`, `caches.rs:746`):** every `TestHub` listens on DB-wide channels (`veil_epoch`, `veil_tips`, `veil_Invalidation`), waking every concurrently running test's `TestHub` on every commit.
3. **Unscoped `landing::resume` (`src/landing/mod.rs:631`, called in `landing.rs:6287-6288`, `rv_core2.rs:1302`):** executes `UPDATE landing_queue SET state = 'queued' WHERE ...` **without `WHERE project_id = ...`**, touching concurrent tests' queued landings.
4. **Database-wide schema catalog inspection (`pack_gc.rs:1418`, `src/pack_gc.rs:2102`):** queries `information_schema.columns` across the entire database (`BUG-2532`).
5. **DDL & Triggers (`52` sites across `blame.rs`, `branch_count.rs`, `commits.rs`, `pack_gc.rs`, `shares.rs`, `startup.rs`):** On YugabyteDB, DDL is non-transactional (`BUG-2570`) and bumps table/cluster catalog versions, causing concurrent DML in shared DBs to fail with SQLSTATE `40001` (`SchemaVersionMismatch`, `BUG-2532`), while concurrent online index builds across *any* databases on the shared cluster stall YB's master for 10–14 min (`BUG-2582`).
6. **Hardcoded primary keys & unscoped `DELETE`/`UPDATE`s (`audit_details.txt`):** `blame.rs:3466-3476` inserts fixed `groups.id` (`900_001..900_003`) and `people.id` (`700_001..700_005`), colliding when `projects_id_seq` or `groups_id_seq` reaches those ranges or when two blame tests overlap (`BUG-2600`); `BUG-2530` came from unscoped cleanup deletes.
7. **S3 Key Collisions (`src/store.rs:83` `p/{project}/{..}/{..}`, `src/pack.rs:92` `p/{project}/pack/{name}`):** Object keys are namespaced only by integer `project_id`. Every `own_database` starts `projects_id_seq` at `1`, so all 28 `own_database` tests + the main run DB overwrite and GC `p/1/...` in the shared `VEIL_TEST_S3_BUCKET` (`BUG-2457`, **`BUG-2620`**).
8. **Tablet & Orphaned DB Leaks:** `36` migrations create `71` tables + `40` indexes (`~110+` DocDB tablets per YB DB). Over 20 `own_database` DBs stay alive until `verify-server.sh` exits (`>2,500` extra live tablets inside YB's `3 GiB` tserver limit), and `veil-shared-pg` currently holds **180+ orphaned databases** from non-`r<pid>x` prefixes (`l*`, `s28x*`, `t*`, `veil_fresh_*`).

---

## 2. Proposal (a): Four-Tier Verification Pipeline

Today agents face a binary choice: `verify-fast.sh` (`5.5–6.5 min`, zero `server_hub` coverage) or `verify-server.sh` (`35.5 min` standard, `81.5 min–2.5 h` with `HOSTILE=1`), serialized behind a single global mutex where queue waits reached **2 hours** this week. Following the Claude Code team's guidance, we split verification into four explicit tiers matched to defect class and cost.

### 2.1 Pipeline Summary

| Tier | When It Runs | Target Wall | Heavy-Lock Tokens (`of 16`) | Exact Scope |
|---|---|---:|---:|---|
| **Tier 0: Inner Loop** | During edits (every 1–3 min) | **`5–35s`** | `0` (pure Rust) or `3` (1–5 server tests) | Single package/module `cargo nextest run -E ...` or `bash scripts/server-tests.sh postgres <filter>` on persistent `target/` |
| **Tier 1: Fast Iteration (`verify-fast.sh`)** | Every agent iteration / before handoff | **`3.5–5.5 min`** *(≤ 4.0m non-server; ≤ 6.0m with server diff)* | **`6` tokens** *(can run concurrently alongside a Tier 2/3 job!)* | Workspace `nextest` (`2,488` tests; excludes the 9 `>=30s` soak tests) + workspace `clippy --all-targets --features veil-server/containers` + `cargo doc` (all sharing `target/`) + path-gated fast WASM `cargo check` (`~18s` instead of `109s` when WASM/core paths untouched) + if `crates/veil-server/` changed: affected PG `server_hub` module(s) + if SQL/migrations/tx-isolation changed: the **65-test YB Differential Canary** (`~90s` with worker DB pool) |
| **Tier 2: Pre-Merge Gate (`verify-premerge.sh`)** | Once when branch is ready to land | **`~11–15 min`** | **`10` tokens** | Full workspace `nextest` including the 9 `>=30s` soak tests + full `check-wasm.sh` (`45s` deduplicated) + **full PG `server_hub` (`939` tests, isolated via `CREATE DATABASE ... TEMPLATE`, `~3.8m` after `setup_project` snapshot)** + `load-postgres` (`8` copies, `~1.2m`) + **65-test YB Differential Canary** (`~1.5m`) *(escalates to full YB `server_hub` if `migrations/`, `src/db.rs`, `src/landing/`, or `src/pack_gc.rs` changed)* |
| **Tier 3: Merge-Train / Pre-Release / Scheduled** | Batch merge-round on `integration` (every N merges / pre-release / 2h cron) | **`~28–42 min`** *(down from `81.5m–2.5h`)* | **`16` tokens** *(exclusive)* | Full YB `server_hub` (`939` tests on `W=8` pre-migrated DB pool, `~7–9m` down from `23m` once `32 × 32.8s` cold migrations + `setup_project` CLI spawns are eliminated) + `load-yugabyte` (`3` copies, `~2.5m`) + `hostile-postgres` (`~10m` parallelized across 2 isolated DBs) + `hostile-yugabyte` (`~16m` quiet with `yb-ddl.lock`) + `verify-ignored.sh` (`19s`) + `scripts/deep-props.sh` |

### 2.2 Exact Test Placement Rationale

1. **Move the 9 workspace soak tests (`>= 30s`, `sum = 638.0s`) from Tier 1 to Tier 2 (`nextest` profile `fast` vs `premerge`):**
   - `metadata_lock::bug_1294` alone runs 200 serial iterations (`176.6s`) and sets **98.2%** of workspace `nextest` wall time (`179.9s`). Cutting just those 9 soak tests (or running `bug_1294` at `N=25` in Tier 1 = `~22s` and `N=200` in Tier 2 via env var, zero Rust change needed if filtered via `.config/nextest.toml` `default-filter = "not test(bug_1294|bug_2464_rewrites_follow_in_long_runs_replayed|bug_1503_a_merge_rebase|bug_1503_rewrites_follow|bug_2464_guard_two_settlers|history_tools_never_reveal|many_concurrent_commands_all_succeed|replicas_converge|s14c2_trimmed_map_lines)"`) drops workspace `nextest` wall time from **`180.2s` to `~68s`** while keeping `2,488 / 2,497` (`99.64%`) of tests in Tier 1 and `100%` in Tier 2.
2. **Stop running the 27 pure in-memory `server_hub` tests twice under PG and YB (`~250s` CPU each, including `#1` `landing::bug_1107` at `142.6s` and `#11` `landing::bug_1272` at `71.5s`):**
   - Those 27 tests never call `TestHub`, PostgreSQL, YugabyteDB, or MinIO. Filtering them out of the YB run (and moving them to `veil-server --lib` or running them once in the PG/host pass) saves ~3–4 minutes of pure CPU contention during YB runs with **zero** coverage loss.
3. **Move `verify-ignored.sh` (`43.6s`) to Tier 3 / bug-sweep:**
   - `verify-fast.sh` currently runs `verify-ignored.sh || true` on every iteration and **discards its exit code**, burning `43.6s` to confirm that 9 known open bugs still fail. Move it to Tier 3 (and switch it to `cargo nextest run --run-ignored only`, cutting its runtime from `43.6s` to `19.4s`).
4. **Which YugabyteDB-only behaviours require YugabyteDB per SQL/tx change vs. Tier 3?**
   PostgreSQL catches 100% of SQL syntax, relational logic, projection/grant/embargo semantics, HTTP/TLS routing, and S3 store bugs at **3.5× faster** per-test speed and **280× faster** DB creation (`115 ms` template clone vs `32.8s` cold migrate). YugabyteDB differs from PostgreSQL in **7 specific distributed-storage behaviours**:

| # | YugabyteDB-Specific Behaviour | Historical Bugs | Modules Exercising It (65-Test YB Differential Canary) | Tier Placement |
|---:|---|---|---|---|
| 1 | **Non-transactional DDL** (`yb_ddl_transaction_block_enabled=off`; failed migration leaves partial DDL committed) | `BUG-2570` | `startup::*` (`14` tests) | **Tier 1/2** whenever `migrations/` or `src/db.rs` changes; **Tier 3** always |
| 2 | **Online `CREATE INDEX CONCURRENTLY` stage races** (`indislive`/`indisready`/`indisvalid` lost under catalog bump) | `BUG-2482`, `BUG-2571`, `BUG-2582` | `startup::bug_2482*`, `startup::bug_2571*`, `blame::migration_0015` (`6` tests) | **Tier 1/2** when `migrations/` or `src/db.rs` changes; **Tier 3** always |
| 3 | **`40001` `SchemaVersionMismatch` & DocDB `ReadRestart` / `Conflict` retries** (`db::is_retryable`) | `BUG-838`, `BUG-2532`, `BUG-2465` | `concurrency::*` (`8`), `landing_speed::*` (`4`), `branch_count::bug_2447*`/`2450` (`4`) | **65-test YB Canary in Tier 2** (and Tier 1 on SQL changes) |
| 4 | **`SERIALIZABLE` vs `READ COMMITTED` FK read-lock conflicts on DocDB tablets** | `BUG-1957`, `BUG-2135`, `BUG-2341` | `landing::only_the_lease_holder*`, `landing::bug_1635*`, `packs::a_push_of_more_than_max_objects*`, `shares::*` (`12` tests) | **65-test YB Canary in Tier 2** |
| 5 | **Distributed clock skew / cross-tablet visibility lag** | `BUG-2560`, `BUG-2468` | `caches::*` (`6`), `embargo_prs::guarantee_3*` (`4`), `grants::bug_1082` (`1`) | **65-test YB Canary in Tier 2** |
| 6 | **Tablet RPC / DDL catalog latencies & `TRUNCATE` cost** | `BUG-890`, `BUG-2521` | `startup::s3rd3_migration_21*`, `pack_gc::guarantee_2*`, `pack_gc::bug_1782*` (`6` tests) | **65-test YB Canary in Tier 2** |
| 7 | **Advisory locks unsupported / semantics differ on YB** | `BUG-1066` (`shares.rs:1024` skips YB) | `shares` / `locks` (`4` tests) | **65-test YB Canary in Tier 2** |
| — | *Full 939-test YB regression + `hostile-yugabyte` + `load-yugabyte`* | Broad interactions | All `58` modules + `hostile_` + `3×` load copies | **Tier 3** (every merge-train batch & before release) |

---

## 3. Proposal (b): Sharding, Parallelism, and Heavy-Lock Redesign (30 GiB RAM / 32 vCPUs)

### 3.1 Measured Resource Footprint on the 30 GiB Machine

| Component | Steady RAM | Peak RAM | Peak CPU (`-j 8`) | Bottleneck |
|---|---:|---:|---:|---|
| Shared containers (`veil-shared-yb` `3.0 GiB` cap + `veil-shared-pg` `0.6 GiB` + `veil-shared-s3` `0.3 GiB`) | `~3.8 GiB` | `~4.4 GiB` | `2–8` cores | YB tserver hard-capped at `3 GiB` (`--memory_limit_hard_bytes=3221225472`) |
| OS + T3 orchestrator + idle agent shells + `sccache` daemon | `~3.5 GiB` | `~4.5 GiB` | `1–2` cores | leaves **`~21 GiB` free RAM** (`free=22GB` measured at lock acquire) |
| `verify-fast.sh` (`cargo` `-j 8` + workspace `nextest`) | `~2.2 GiB` | `~4.8 GiB` | `8–16` cores | `rustc`/`ld` linking debug test binaries |
| `server_hub` on PostgreSQL (`nextest -j 16` / `libtest` 32 threads) | `~2.4 GiB` | **`5.6 GiB`** | `8–14` cores | Spawning `vl` subprocesses + `landing::bug_1107` / `bug_1272` |
| `server_hub` on YugabyteDB (`--test-threads=8`) | `~1.8 GiB` | `~4.2 GiB` | `4–8` cores | **YB tserver `3 GiB` RAM + YB master catalog lock**, NOT host RAM |

**Crucial insight:** Host RAM has **`~21 GiB` available**, and a full `server_hub` run peaks at **`5.6 GiB`**. Running a single binary FIFO lock (`heavy-lock.sh`) leaves **50–75% of host RAM and 60–80% of the 32 vCPUs idle** during YugabyteDB I/O waits while 6 agents sit blocked for up to 2 hours!

### 3.2 Replace Binary `heavy-lock.sh` with a 16-Token Weighted Semaphore + `yb-ddl.lock`

Upgrade `~/.cache/veil-orch/heavy-lock.sh` from a 1-slot FIFO lock to a **16-token weighted FIFO semaphore** (preserving strict FIFO head-of-line fairness so large jobs never starve, plus a reserved 3-token fast lane):

| Job Type | Token Cost (of `16`) | Peak Host RAM | What Can Co-Run Safely |
|---|---:|---:|---|
| `server-tests.sh postgres <filter>` (1–15 tests, reusing built `server_hub`) | **`3`** | `~1.2 GiB` | Up to 5 targeted server checks at once, or alongside `verify-fast` (`6`) + `verify-premerge` (`10` -> waits `~3m` max, never `2h`) |
| **Tier 1 (`verify-fast.sh`, `-j 6`)** | **`6`** | `~4.5 GiB` | Can run **simultaneously beside Tier 2 (`10` tokens = `16/16`, `~10 GiB` combined RSS << `21 GiB` free)** or two Tier 1 jobs + one targeted PG check (`6+6+3 = 15`) |
| **Tier 2 (`verify-premerge.sh`)** | **`10`** | `~5.6 GiB` | Can co-run with one Tier 1 (`6`) or two targeted PG checks (`3+3`) |
| **Overlap PG + YB inside `verify-server.sh` / Tier 3** | **`12`** | `~8.5 GiB` | PG (`veil-shared-pg`) and YB (`veil-shared-yb`) are **separate containers and engines**: running PG `server_hub` (`-j 12`) in parallel with YB `server_hub` (`-j 6`) saves the entire **`6.6 min` PG wall time** immediately! |
| **Tier 3 Hostile / Load / Benchmarks (`veil-bench`)** | **`16` (Exclusive)** | `~10 GiB` | Runs alone so latency/throughput assertions (`BUG-2468`, `BUG-2511`, `BUG-2521`, `BUG-2601`) see zero noisy-neighbour jitter |

**Dedicated cross-process `yb-ddl.lock` (`flock ~/.cache/veil-orch/yb-ddl.lock`):**
- Even when two jobs share the machine or multiple threads run inside one `server_hub`, **any** DDL or online index build on `veil-shared-yb` must acquire `yb-ddl.lock`. Today `support::MIGRATING` (`support.rs:39`) is an **in-process `std::sync::Mutex`**, which neither protects cross-process runs nor covers `startup.rs`'s 11 `fresh_database` callers or `blame.rs:1142` (`BUG-2582`).

### 3.3 `nextest` Test-Groups, Partitioning, and Two Required `support.rs` Fixes Before Switching `server_hub` to `nextest`

Add `.config/nextest.toml` with heavy-test concurrency caps so memory spikes and rate-limit/timing tests never collide:
- `test-group = "heavy-mem"` (`max-threads = 2`): `landing::bug_1107`, `landing::bug_1272`, `landing::bug_1684`, `derived::bug_2380`, `startup::bug_2482*`, `adversarial_s10::bug_1053`.
- `test-group = "yb-ddl"` (`max-threads = 1`): `startup::*`, `blame::migration_0015*`, `pack_gc::bug_1782*`.
- `test-group = "timing-sensitive"` (`max-threads = 2`): `daemon::bug_1680*`, `daemon::bug_1681*`, `limits::*`, `thin::s16_unreachable*`.
- **Sharding:** `nextest --partition hash:1/2` and `hash:2/2` cleanly splits PG `server_hub` across 2 template-cloned DBs if multi-process execution is desired, **provided two intra-process assumptions in `support.rs` are updated first**:
  1. `support::unique()` (`support.rs:60`): `AtomicU64` starts at `0` in every `nextest` child process, reducing uniqueness across processes to 4 random bytes (`2^16 = 65k` birthday bound -> collides across 939 processes, `BUG-2211`). Fix: include `std::process::id()` or 8 random bytes (`random_bytes::<8>()`).
  2. `support::MIGRATING` (`support.rs:39`): `std::sync::Mutex` is per-process. Fix: use `flock` on `/tmp/veil-test-migrating.lock` (or `~/.cache/veil-orch/yb-ddl.lock`).
  *(Note: until `setup_project` is snapshot-templated, `libtest` in-process threads is faster than `nextest` for `server_hub`—`394s` vs `617s`—because `TestHub` shares TLS/crypto warmup in one address space and avoids 939 binary startup taxes on a `257 MiB` executable.)*

---

## 4. Proposal (c): Default Per-Test Server Isolation (Database + S3 Namespace)

### 4.1 Live Microbenchmarks: Database Creation, Migration, and `TEMPLATE` Cloning

Measured directly against `veil-shared-pg` (PostgreSQL 17) and `veil-shared-yb` (YugabyteDB `2025.2.8.1`) across all 36 migration files (`v1..42`, `71` tables, `40` indexes):

| Operation | PostgreSQL 17 (`veil-shared-pg`) | YugabyteDB 2025.2 (`veil-shared-yb`) | Implication |
|---|---:|---:|---|
| `CREATE DATABASE` (empty) | **`369 ms`** | **`770 ms`** | Fast on both, creates 0 user tablets |
| Cold `veil_server::db::migrate` (`v1..42`) | **`~950 ms`** | **`31,994 ms` (`32.0s`)** | **`32 × 32.8s = 17.5 min`** wasted inside YB `server_hub` today! |
| No-op `veil_server::db::migrate` (already at `v42`) | **`45 ms`** | **`106 ms`** | Schema-hash reuse across runs costs `0.1s` |
| `CREATE DATABASE ... TEMPLATE <migrated_tpl>` (serial ×5) | **`101–219 ms` (`115 ms` median)** | **`FAILS` (`61 ms`)**: `ERROR: FLAGS_enable_db_clone is disabled` | **PG supports per-test template cloning out of the box; YB does not** |
| `CREATE DATABASE ... TEMPLATE` (`8` concurrent workers after `ALTER DATABASE tpl WITH IS_TEMPLATE true`) | **`8/8` succeeded in `< 200 ms` wall** | N/A (`FLAGS_enable_db_clone` off) | Marking `IS_TEMPLATE true` eliminates PG's template-source connection lock |
| `TRUNCATE` all 70 tables between tests | `~18 ms` | **`~18,000 ms` (`250–280 ms/table`)** + catalog version bump (`BUG-2521`) | **Never use `TRUNCATE` on YugabyteDB** |
| Pure DML reset (`DELETE FROM projects CASCADE; DELETE FROM people CASCADE; ...` on 12 root tables) | `~2 ms` | **`8–15 ms`**, **zero DDL**, **zero catalog version bump** | Ideal inter-test reset for YugabyteDB worker DB pool |

### 4.2 Engine-Aware Default Isolation Architecture (`TestHub::start()`)

Make **every** `TestHub::start()` isolated in **both SQL state and S3 object keys** by default—without tests having to opt into `start_own()` after a flake is discovered:

#### 1. PostgreSQL: Per-Test `CREATE DATABASE ... TEMPLATE` + `DROP DATABASE ... WITH (FORCE)` on `Drop`
- Once per run (`1.3s`), create and migrate `<prefix>tpl`, then execute:
  ```sql
  ALTER DATABASE <prefix>tpl WITH IS_TEMPLATE true ALLOW_CONNECTIONS false;
  ```
- Every `TestHub::start()` clones `<prefix>t_<n>` via `CREATE DATABASE <name> TEMPLATE <prefix>tpl` (**`115 ms` median**, `8/8` parallel-safe). Across `912` DB-backed tests at 16–32 threads, total template-cloning wall overhead is **`~4–7 seconds` for the entire 939-test suite**—cheaper than the 32 cold migrations `server_hub` already runs today!
- When `TestHub` drops (and no secondary `TestHub` shares its URL), close its `PgPool` and `DROP DATABASE IF EXISTS <name> WITH (FORCE)` asynchronously (`~40 ms`), keeping live database count bounded at `<= test_threads` instead of leaking hundreds of DBs. (Also add a sweep in `verify-server.sh` to drop the 180+ historic non-`r<pid>x` orphan DBs on `veil-shared-pg` older than 6 hours.)

#### 2. YugabyteDB: Fixed Pool of `W = 8` Pre-Migrated Worker Databases + Pure-DML Reset
- Why not 912 separate DBs on YB? `912 × 32.8s = 8.3 hours` of migrations and `100,000+` tablets (crashing the `3 GiB` tserver). *(Optional follow-up: test adding `--enable_db_clone=true` on `yb-master`/`yb-tserver` in `scripts/shared-services.sh`, which uses DocDB snapshot hardlinks in ~1–2s, though tablet count still requires immediate `DROP DATABASE` on `TestHub::drop`.)*
- Without container flag changes, maintain a **persistent, schema-hash-keyed pool of `W = 8` pre-migrated databases** on `veil-shared-yb`: `veil_yb_slot_<schema_blake3_8>_0 .. 7` (`8 × 110 = 880` tablets total—**3× fewer live tablets** than a single `verify-server.sh` run leaks today!).
  - When `migrations/*.sql` hash matches, startup migration cost drops from `32.8s` + `17.5 min` in-suite to **`8 × 106 ms = 0.85s`**.
  - An RAII `DbLease` checks out one of the `W = 8` worker DBs for the duration of a single test (`--test-threads=8` maps 1:1 to the 8 slots—**zero concurrent tests ever share a database!**).
  - Before returning the lease to the pool, `TestHub::drop` awaits server shutdown (stopping `embargo::run_loop`, `caches::listen`, and `pack_gc` tasks cleanly!) and executes a single pure-DML batch on the 12 root tables (all `ON DELETE CASCADE` children clear automatically, or explicit `DELETE` in FK order where non-cascading):
    ```sql
    DELETE FROM webauthn_challenges; DELETE FROM webauthn_credentials; DELETE FROM web_enrollments;
    DELETE FROM challenges; DELETE FROM sessions; DELETE FROM group_managers; DELETE FROM group_members;
    DELETE FROM device_vouches; DELETE FROM device_expected; DELETE FROM projects; DELETE FROM devices; DELETE FROM people;
    ```
    Cost: **`< 15 ms`**, **zero DDL**, **zero `40001` catalog version bumps**.
  - **Only the 17 genuine DDL/schema-mutating tests** (`startup` ×11, `blame::migration_0015` ×1, `branch_count` trigger tests ×4, `pack_gc::bug_1782` ×1) request a disposable `TestHub::start_ddl_own()`, which acquires the cross-process `yb-ddl.lock`, creates one DB, runs the test, and **immediately `DROP DATABASE`s on `Drop`** so tablet count never accumulates. The remaining 15 tests that previously used `own_database` only for row-count/embargo/serializable isolation (`grants::bug_1082`/`1088`, `landing::bug_1468`/`2510`×2, `landing_speed::bug_1941`/`2465`, `commits::bug_2390`, `pack_gc::guarantee_2`/`5`, `embargo_prs::bug_2580`, `grants::bug_1083`, `landing_hold::bug_1955`, `prs::merge_check*`, `thin::s3rd3`) now get full DB isolation from the `W = 8` pool for `15 ms` instead of `15 × 32.8s = 8.2 minutes`!

#### 3. Object-Store (S3 / MinIO) Per-Test Namespace Isolation (Zero Extra Buckets)
- **Root cause of `BUG-2620` & `BUG-2457`:** `store.rs:83` (`p/{project}/{..}/{..}`) and `pack.rs:92` (`p/{project}/pack/{name}`) key S3 objects solely by `projects.id`. Every fresh DB resets `projects_id_seq = 1`, so multiple DBs sharing `VEIL_TEST_S3_BUCKET` overwrite and GC each other's `p/1/...` objects!
- **Two zero-cost ways to isolate S3 keys per test (`0 ms` setup):**
  1. **Zero-`src/`-change option (pure test-harness SQL):** When initializing or resetting each isolated test DB, advance `projects_id_seq` to a unique disjoint range per test lease (`lease_counter` atomic / `flock` counter):
     ```sql
     SELECT setval('projects_id_seq', $1 * 1000000, false);
     SELECT setval('people_id_seq',   $1 * 1000000, false);
     SELECT setval('groups_id_seq',   $1 * 1000000, false);
     ```
     Every test's projects receive globally unique IDs (`1_000_001`, `2_000_001`, ...), making `p/{project}/...` completely disjoint in the shared bucket while also preventing coincidence masking with hardcoded test IDs (`700_001`, `900_001`, `BUG-2600`)!
  2. **Explicit prefix option (4-line `Storage::S3` addition when `src/store.rs` is open):** Add `prefix: String` (default `""` in production, `t/{unique_lease_id}/` in `TestHub`), prepending it in `S3Store` (`{prefix}p/{project}/...`). Makes `pack_gc` bucket listings physically incapable of seeing another test's prefix even under raw SQL inserts.

### 4.3 Flake & Contention Audit: Which Bugs This Architecture Prevents

| Bug ID | Failure Mechanism This Week | Prevented By Proposed Architecture? | Mechanism |
|---|---|---|---|
| **`BUG-2530`** | Shared-DB cleanup / unscoped `DELETE` mutated concurrent test rows | **Yes (100%)** | Per-test DB (PG template / YB 1-test-per-slot lease) |
| **`BUG-2532`** | `pack_gc::bug_1782` `ALTER TABLE bisects` bumped YB schema version -> `40001` in shared DB, and concurrent DDL broke `audit_schema_columns` | **Yes (100%)** | Dedicated `start_ddl_own()` + no shared-DB neighbours |
| **`BUG-2570`** | Failed online migration step re-ran non-transactional DDL on YB | **Kept caught + isolated** | Caught by `startup::bug_2482_every_index...` (Tier 1) + 65-test YB Canary |
| **`BUG-2580`** | `TestHub` with `Storage::Dir` on shared DB ran `embargo::run_loop`, marking S3 tests' due embargoes `failed` (`embargo_prs::guarantee_3`) | **Yes (100%)** | Every `TestHub` has its own DB; background loops never see other tests' rows |
| **`BUG-2582`** | Multiple `own_database` / `startup.rs` online index builds ran concurrently on YB, stalling master 10–14m | **Yes (100%)** | Machine-wide `yb-ddl.lock` (`flock`) + dropping 15 non-DDL `own_database` migrations on YB |
| **`BUG-2600`** | Hardcoded `groups.id` (`900_001..3`) / `people.id` (`700_001..5`) in `blame.rs` collided in shared DB | **Yes (100%)** | Per-test DB reset + disjoint `setval` sequence strides |
| **`BUG-2620`** | Fresh `own_database` reset `projects.id = 1` while sharing `VEIL_TEST_S3_BUCKET`, colliding on `p/1/...` S3 keys | **Yes (100%)** | Per-lease `projects_id_seq` stride (`* 1_000_000`) + `Storage::S3` prefix |
| **`BUG-2468`, `BUG-2511`, `BUG-2521`, `BUG-2601`** | Load-sensitive latency/timeout flakes (`TRUNCATE` catalog stalls, 3,000+ leaked YB tablets starving 3 GiB tserver, CPU oversubscription) | **Yes (~90%+ reduction)** | Zero `TRUNCATE` on YB, `DROP DATABASE` on `Drop` (`880` tablets vs `3,500+`), `nextest` `timing-sensitive` group, exclusive `16`-token lock for load/hostile |

---

## 5. Proposal (d): Build-Time & Test-Fixture Savings

1. **Stop `rm -rf target` at the end of `verify-fast.sh` and unify `target/`, `target/lint`, and `target/wasm-check` (`-90s to -135s` per server check, `-4.9 GB` disk):**
   - `verify-fast.sh` currently builds **three separate target trees** (`8.15 GB`) and deletes all of them at exit, forcing `verify-server.sh` (and every subsequent `verify-fast.sh`) to recompile and relink all `378` non-`sccache`able crate-type `bin` targets (`52.6s` workspace + `90–135s` server).
   - Keep one per-worktree `target/` (with `CARGO_INCREMENTAL=0` so `sccache` stays cache-eligible for `rlib`s without incremental `.rcgu.o` bloat, ~`3.8 GB` steady) and delete `target/` **only in a worktree-close/handoff hook or disk-low reaper (`< 25 GB` free)**, not between edit-test iterations.
2. **Pre-seeded `setup_project` Template Snapshot (`-3.0 min` on PG, `-8.0+ min` on YB):**
   - `setup_project(&hub)` (`support.rs:830`) is called **`576` times** per `server_hub` run and spawns `76` subprocesses (`38` `vl` + `38` `timeout`) to build the exact same deterministic 5-person (`admin`, `sec`, `fin`, `dev`, `contractor`), 3-group, 3-commit repository!
   - Materialize `setup_project` **once per suite run** (`~7s`), snapshot its SQL rows (into `<prefix>seeded_tpl` on PG or an in-memory row/S3-object fixture replayed in `< 50 ms` + `cp -al --reflink=auto` of the 5 client working directories), and let the ~550 tests that don't test `vl login`/`vl group` itself call `setup_project_fast(&hub)`. Even converting half of callers saves **`~20,000` `vl` process spawns (`~3 min` wall on PG, `~8 min` wall on YB)**. Also invoke `vl` with in-process `Command` timeout helper instead of spawning `/usr/bin/timeout` (`-21,888` fork/execs).
3. **Fix `sccache` `basedirs` for Dynamic T3 Worktrees + Cache Shared Test Support as an `rlib` + Fast Linker (`-45s` per `server_hub` edit):**
   - `~/.config/sccache/config` lists `357` static worktree paths in `basedirs`; newly created T3 worktrees (`/home/kittu/.t3/worktrees/veil/t3-*`) are **missing**, silently causing `0%` cross-worktree `sccache` hits on workspace `rlib`s! Auto-append `$PWD` via `sccache-basedirs.sh` (or use `RUSTFLAGS="--remap-path-prefix=$PWD=/veil-ws"`).
   - Extract `crates/veil-server/tests/server_hub/support.rs` (`1,429` LOC) into a workspace `veil-test-support` `rlib` crate (so `sccache` caches it) and install `lld` or `mold` (`RUSTFLAGS="-C link-arg=-fuse-ld=lld"`) to cut linking the `257 MiB` `server_hub` binary from `~22s` (GNU `ld` 2.46) to `~2–3s`.
4. **Streamline `scripts/check-wasm.sh` (`109.0s -> ~18s` Tier 1 / `~42s` Tier 2):**
   - Today `check-wasm.sh` invokes `cargo` **10 times sequentially** in `target/wasm-check`. Combining independent `--package` flags into 3 `cargo check` invocations sharing `target/` and reserving the `--release` WASM codegen step (`Step 4`) for Tier 2 (or when `crates/veil-core` / `wasm` files change) cuts `91s` (`1.5 min`) off every Tier 1 run.
5. **Fix the Two Bugs in `~/.cache/veil-orch/verify-fast.sh`:**
   - Set `TMPDIR="/tmp/claude-$(id -u)/${AGENT_NAME:-fast}-$$"` instead of `"$PWD/.scratch/tmp"` (fixes the 5 `SUN_LEN` Unix socket failures in T3 worktrees).
   - Pass `--workspace --all-targets --features veil-server/containers` to `cargo clippy` sharing `target/` so `veil-server` and `veil-bench` lints are actually checked in Tier 1.

---

## 6. Ranked Proposal Summary

Ranked by **effective wall-clock minutes saved per developer/agent check (including lock-queue wait)** and **flakes eliminated**:

| Rank | Change | Minutes Saved per Check | Flakes Prevented | Effort | Touch Scope |
|---:|---|---|---|---|---|
| **1** | **Four-Tier Pipeline (`verify-fast` ≤ 4.5m, `verify-premerge` ~13m, Tier 3 merge-train)** — defer full 939-test YB + Hostile + `verify-ignored` to Tier 3; run 65-test YB Canary on SQL/tx diffs; move 9 `>=30s` workspace soak tests (`bug_1294` = `176.6s`) to Tier 2 & 27 pure in-memory `server_hub` tests out of YB | **`-22 to -68 min`** per server iteration (`81.5m -> 13m` pre-merge; `5.8m -> 3.8m` Tier 1) | Eliminates timeout/retry churn on unrelated YB catalog stalls | **S–M** (`~1 day`) | `scripts/`, `.config/nextest.toml`, `~/.cache/veil-orch/` (zero `.rs` required) |
| **2** | **16-Token Weighted `heavy-lock.sh` + Cross-Process `yb-ddl.lock` + Overlap PG & YB** — let Tier 1 (`6`) co-run beside Tier 2 (`10`), add `3`-token fast lane for `server-tests.sh`, run PG & YB concurrently in Tier 3, serialize all YB DDL via `flock` | **`-30 to -120 min` queue wait** + **`-6.6 min`** direct Tier 3 wall | **`BUG-2582`**, **`BUG-2571`**, **`BUG-2468`**, **`BUG-2601`** | **S** (`~0.5 day`) | `~/.cache/veil-orch/heavy-lock.sh`, `scripts/verify-server.sh` |
| **3** | **Default Per-Test DB + S3 Isolation** — PG `CREATE DATABASE ... TEMPLATE` (`115 ms`, `DROP` on `Drop`); YB `W=8` pre-migrated schema-hashed DB pool (`<15 ms` DML reset, dropping 15 non-DDL `own_database` cold migrations = **`-14 min` on YB!**); per-lease `projects_id_seq` `setval` stride / S3 key prefix | **`-14 to -17 min`** on YB `server_hub` (`23m -> ~8m`) | **`BUG-2530`**, **`BUG-2532`**, **`BUG-2580`**, **`BUG-2582`**, **`BUG-2600`**, **`BUG-2620`**, **`BUG-2521`** | **M** (`~2 days`, after `fable` lands) | `crates/veil-server/tests/server_hub/support.rs`, `startup.rs`, `scripts/verify-server.sh` |
| **4** | **Pre-Seeded `setup_project` Snapshot + Direct In-Process Timeout** — snapshot/clone the 5-person repository fixture instead of spawning `76` subprocesses × `576` tests (`43,776` spawns/run) | **`-3.0 min`** on PG (`6.6m -> ~3.6m`), **`-6 to -8 min`** on YB | **`BUG-2511`** (subprocess CPU/pipe starvation under load) | **M** (`~1.5 days`) | `crates/veil-server/tests/server_hub/support.rs` |
| **5** | **Persistent Unified `target/` + `check-wasm.sh` Deduplication + `verify-fast.sh` Fixes** — stop `rm -rf target` between checks, merge 3 target dirs (`8.15 GB -> 3.8 GB`), path-gate WASM `--release`, fix short `TMPDIR` (`SUN_LEN`) & `--workspace` clippy | **`-2.0 min`** on Tier 1 + **`-1.5 to -2.2 min`** rebuild tax entering `verify-server` | Fixes **5 deterministic `SUN_LEN` socket failures** in T3 worktrees | **S** (`~0.5 day`) | `~/.cache/veil-orch/verify-fast.sh`, `scripts/check-wasm.sh`, worktree cleanup hook |
| **6** | **Auto-Register T3 Worktrees in `sccache` / `--remap-path-prefix` + `veil-test-support` `rlib` + `lld`/`mold`** — restore cross-worktree `sccache` hits and shrink `257 MiB` `server_hub` link time | **`-0.8 to -1.5 min`** per cold worktree / `server_hub` relink | None (pure developer/agent velocity) | **S–M** (`~1 day`) | `scripts/sccache-basedirs.sh`, `.cargo/config.toml`, `crates/veil-test-support` |

---

## 7. Non-Negotiables: What Must NOT Be Lost

1. **Full 939-test YugabyteDB coverage before release and on every merge-train batch (Tier 3):** Tiering moves full YB off *every non-SQL inner iteration*, never off `integration` merge batches or release gates. Any diff touching `crates/veil-server/migrations/`, `src/db.rs`, transaction isolation levels, advisory locks, or retry loops must still run the YB Differential Canary (or full YB) **before merge** in Tier 2.
2. **All 13 `hostile_` suites (`hostile-postgres` + `hostile-yugabyte`):** These catch multi-fault network/storage/crash races that unit and standard tests cannot. Keep 100% of them in Tier 3 (under `16`-token exclusive lock + `yb-ddl.lock` so they run in `~26 min` predictable quiet time instead of `2.5 hours` of catalog-lock thrash).
3. **Parallel Load Copies (`load-postgres` 8× and `load-yugabyte` 3× of `concurrency`):** Keep `load-postgres` in Tier 2 (`~75s`) and `load-yugabyte` in Tier 3 (`~155s`); intentionally run all copies against **one shared database** inside the load step (unlike unit/integration `server_hub`), because cross-connection contention on one DB is the exact property `load-*` exists to stress.
4. **Deep Property Tests (`VEIL_DEEP_PROPS=1`, `scripts/deep-props.sh`), the 9 `>=30s` Workspace Soak Tests (`bug_1294` at 200 iterations, `oplog_merge` long replays), and `verify-ignored.sh`:** Keep all 9 soak tests in Tier 2 (`100%` pre-merge enforcement) and keep `deep-props.sh` + `verify-ignored.sh` in Tier 3.
5. **WASM & Feature-Matrix Compilation Guarantees (`check-wasm.sh`):** Every feature combination (`wasm32-unknown-unknown`, non-FUSE, FUSE, `--release` WASM) remains enforced before merge in Tier 2.
