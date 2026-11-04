# Scale round: build plan

From `integration` @ 4a62259. This round is Scion phase 0 (`docs/design/scion-for-developers.md`) plus the owner's three serverless items. Designs and threat reviews:

| # | item | file | format 6? |
|---|---|---|---|
| 1 | lock-free, resumable pushes (SFTP and path remotes) | `1-lock-free-push.md` | no |
| 2 | lock-free op log | `2-lock-free-oplog.md` | **yes** (op-heads layout, operation fields) |
| 3 | history index (commit-graph, Bloom filters) | `3-history-index.md` | no (a device-local cache) |
| 4 | background cleanup; streaming pull and Git import | `4-background-cleanup-streaming.md` | no |
| 5 | copy-on-write checkouts of the project directory | `5-reflink-checkouts.md` | no |
| 6 | partial clone, fetch on demand, bounded cache | `6-partial-clone.md` | **yes** (`repo.json` `partial`) |
| 7 | agent attribution | `7-agent-attribution.md` | **yes** (`Snapshot.agent`) |
| 8 | sandbox resource limits | `8-sandbox-limits.md` | no |
| 9 | scale benchmark and gates | `9-scale-benchmark.md` | no |

**Rules for builders:**
- Every builder brief appends its item's numbered threat review. Each point is a required test: a property, race, crash or hostile-input test. The adversarial passes start from the same lists.
- Suggested bug range: **BUG-700 to BUG-799**.

## 1. One combined format-6 proposal

One bump: `REPO_FORMAT = 6`, `min_vl_for_format(6)` = this round's release. It follows `FORMAT.md` §4.

1. **Snapshots** gain `agent: Option<Attribution>` (`{agent, task?: Text, prompt?: Text, run?}`; item 7).
   - **Encoding:** canonical JSON, placed before `signature`, omitted when absent, so every existing snapshot keeps its bytes, id and signature.
   - **Format gate:** `Object::min_repo_format` returns 6 for a snapshot that has it; `ObjectStore::check_storable` and `PackSink` refuse it below 6.
   - **Validation** on decode (lengths, printable characters) makes a hostile value `Corrupt`.
2. **Operations** gain:
   - `workspace: Option<String>`, the workspace the command was for (undo scoping, item 2);
   - `rewritten: BTreeMap<ObjectId, Vec<ObjectId>>`, a transaction's rewrites, empty meaning abandoned (merging concurrent operations, item 2).

   Both are omitted when empty. `OpStore::put` refuses either below format 6, as it does `View::uses_format_5` below 5.
3. **The op-log layout:** `.veil/op_heads/<hex>` (empty files) replaces `.veil/op_head`.
   - At format 6, `op_head` is not written, and **if present it is read as one more head**. It is then merged and removed, which covers a format-5 writer racing the upgrade (item 2, threat 9).
   - Remotes use the same layout, always with one head, written under the lock.
4. **`repo.json`** gains `partial: {remote, since?, recent?, only?, cache_limit}` (`deny_unknown_fields`, device-local).
   - It is refused as corrupt below format 6, or when `remote` is not a configured remote, a path in `only` is not a valid `VPath`, or `cache_limit` is 0.
   - `colocated` together with `partial` is refused.
5. **Not format changes** (device-local or ignored by older readers; each is listed in `FORMAT.md`'s inventory):

   | path | what | versioned by |
   |---|---|---|
   | `.veil/index/graph/` | history index | its own magic (`VEILCG01`); unreadable means rebuild |
   | `.veil/objects/incoming/<id>/` | staging (push and pull on remotes; transactions locally) | invisible to every reader; older clients never list it |
   | `.veil/local/push/`, `.veil/local/spool/` | push journal and spool | none |
   | `.veil/local/wc/<ws>.lock`, `.veil/gc.lock` | working-copy lock and gc lease | none |
   | `.veil/local/maintenance.log` | maintenance log | none |
   | `.veil/objects/cache/`, `.veil/local/promisor/` | partial clone's cache and remote inventory | — |
   | `.veil/local/attribution.json`, `.veil/local/attribution/` | attribution settings and side records | — |
   | `[exec.limits]` in `config.toml` | sandbox limits | — |

6. **Cryptography.**
   - No new signing context: attributed snapshots stay under `snapshot`, because `unsigned_id` hashes the full canonical encoding. `CRYPTO.md` gets the argument, to be confirmed by the crypto reviewer.
   - One new BLAKE3 context, `veil 2026 graph-bloom v1`, in `crypto/domains.rs` `BLAKE3_CONTEXTS`. It keys the Bloom filters and is not a secret.
7. **Upgrade `5 → 6`.** Under `.veil/lock` **and** the gc lease:
   - `verify`;
   - **before** the commit point, step `6:op-heads` creates `op_heads/<current op_head>` (harmless to format-5 readers);
   - `set-format` (the commit point);
   - after it, `op_head` is removed.

   Nothing is rewritten: every object, operation, id and signature stays. `vl upgrade --remote NAME` does the same on a remote.
8. **Remotes and clones.**
   - **A format-5 remote** refuses attributed snapshots with the usual "upgrade it with `vl upgrade --remote <name>`".
   - **Lock-free pushes work against format-5 remotes:** the staging directory is invisible to older clients.
   - **A partial clone is always format 6.** Pushing an attributed change from it to a format-5 remote fails with the hint; pushing anything else works.
   - **An older vl refuses a format-6 repository outright.** This is the point: it would ignore `op_heads/`, read unfetched objects as redacted, and drop `agent` when rewriting.
9. **Fixtures:** `tests/fixtures/format-6/`, generated once with `generate.sh <vl> <out> <format-5 set>`.
   - **The set:**
     - attributed snapshots: a public one with a plaintext task, one whose prompt is sealed for a scope, and one on an embargoed line with task and prompt sealed under the embargo key;
     - an op log with two heads and a merge operation carrying `rewritten` and `workspace`;
     - a partial clone's `repo.json`;
     - the `upgraded/` set.
   - **`encodings.txt`** gains an attributed snapshot and an operation with `rewritten`.
   - **`format_compat.rs`:**
     - format-6 objects are `Unsupported` in a format-5 store;
     - a `partial` marker below 6 is refused;
     - an `op_head` written after the upgrade is merged;
     - `5 → 6` keeps every id.

## 2. Build streams and file ownership

Rule: a stream edits only what it owns. Where two streams share a file, ownership is **by function** and is listed. Shared append points (`lib.rs`, `cli.rs`, `main.rs` dispatch, `Cargo.toml` members, `docs/reference/json.md`, `ARCHITECTURE.md` sections) go through stream 0's stubs, or are one-line appends the orchestrator resolves at merge.

Process rules: never run `cargo fmt`; scratch work goes in `.scratch/`; builds use `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=line-tables-only`; a merged worktree's `target/` is deleted at once.

**Stream 0: wiring stubs and trace hooks** (orchestrator, size XS, about 2 h, before any agent)
- **`cli.rs`:**
  - `Exec` flattens `limits::LimitArgs` and `attribution_cmd::AgentArgs`;
  - `Describe` flattens `AgentArgs`;
  - `Clone` flattens `partial_cmd::CloneArgs`;
  - new `Fetch(partial_cmd::FetchArgs)`, `Partial(partial_cmd::PartialCmd)` and `Agent(attribution_cmd::AgentCmd)`;
  - `OpCmd::Heads` and `Undo { op: Option<String> }`;
  - `Push { no_resume }`, `Index(IndexCmd::Rebuild)`.
- **`main.rs`:** one dispatch line each. Handlers say "not yet implemented".
- **New empty modules:**
  - `veil-core`: `trace`, `graph_index`, `bloom`, `maintenance`, `promisor`, `attribution`, `vfs::clone_source`;
  - `vl`: `limits`, `attribution_cmd`, `partial_cmd`.
- **Stub hooks**, each a no-op with its call site inserted now:
  - `attribution::stamp(&mut snap, repo)` in `Transaction::write_snapshot` and `rewrite`;
  - `maintenance::maybe_spawn(&repo)` in `Ctx::finish`;
  - `clone_source::for_project(&ctx)` where `Ctx` makes the project directory's `DiskBackend`;
  - `trace::{lock_wait, lock_hold, read, walk}` at their sites in `lock.rs` (`acquire_in`, drop), `store.rs` (`snapshot`, `tree_object`, `get_raw`), `repo.rs` (each walk function) and `remote.rs` (`committed_closure`, `push_closure`, `embargo_withheld`, `ancestors_in`).
- **`error.rs`:** `VeilError::Unavailable { remote, why }`. It is not `is_unreadable()` and is unused until C.
- **`Cargo.toml`:** member `crates/veil-bench` (a skeleton), outside `default-members`.

**B: benchmark and instrumentation** (size M; first agent)
- Owns `crates/veil-bench/**`, `crates/veil-core/src/trace.rs` and `docs/design/scale/BENCH.md`.
- **Milestone B1** (about 1 day): `trace.rs`, plus the `small` and `1g` profiles and the single-process cases. The **baseline** on 4a62259 goes into BENCH.md.
- **B2:** the N-agents, `cloaked-1g`, `git-100k` and `5g` profiles, plus the gate checker (`veil-bench report --gate`).

**F: format-6 foundation** (size M; t0, beside B)
- **Owns:**
  - `object.rs` (`Attribution`, the field, `validate`, `min_repo_format`);
  - `store.rs` `check_storable` only;
  - `repo.rs` `REPO_FORMAT`, `min_vl_for_format` and `RepoConfig` (`partial`, `check_supported`);
  - `oplog.rs`: encoding and layout primitives only (`Operation::{workspace, rewritten}`, the `op_heads/` read/write primitives, the format refusals);
  - `upgrade.rs` (`6:op-heads`);
  - `fsck.rs` (all heads, staging and `op_head` notes);
  - `crypto/domains.rs` (the Bloom context);
  - `docs/FORMAT.md`, `docs/CRYPTO.md`, `tests/fixtures/**`, `tests/format_compat.rs`.
- **Done when** the fixtures exist, the encodings are appended, and the compatibility tests pass. Until O lands, the repository behaves as format 5 with the new layout (a single writer).

**G: storage** (size L; G1 at t0, the rest after the baseline)
- **G1** (about 0.5–1 day, merged first; P and C need it): `StorageBackend::create_stream` and `StreamWriter` (`vfs/mod.rs`, plus the stream functions in `vfs/disk.rs`, `vfs/sftp.rs` and `vfs/memory.rs`), and `pack::PackWriter`.
- **G2:**
  - `gc.rs`;
  - `maintenance.rs` (consolidation, geometric merging, bitmap prune, auto spawn, gc lease use);
  - `store.rs`'s read path (`read_raw`'s miss: reload and re-probe; `contains`; listing functions);
  - `cmd_gc` in `main.rs`.
- Item 4, except streaming pull (P) and Git import (S).

**I: history index** (size L; t0)
- **Owns:**
  - `graph_index.rs`, `bloom.rs`;
  - `repo.rs`'s graph-query section (`topo_children_first` through `merge_base_tree_at`, `visible_snapshots`, `ancestors*`);
  - `revset.rs`, `confinement.rs`, `blame.rs`, `bisect.rs`, `search.rs`;
  - in `commands.rs`, only `check_current`, `carried_embargo` and `merged_in_signed_by`;
  - in `crates/vl/src/api.rs`, the log functions (`log_entries_with` and its helpers);
  - `crates/vl/src/history.rs`;
  - the `visible_snapshots` caller in `main.rs`, and `patch_cmd.rs`'s `topo_children_first` call.
- **Milestones:**
  - **I1** (merged early): `GraphIndex` with generations, `is_ancestor`, `range`, `topo_iter`, `merge_bases`, `descendants_among`, `embargo_merges` and `by_change_id`, with `repo.rs` delegating;
  - **I2:** Bloom filters, `log -- PATH`, `blame`;
  - **I3:** the remaining callers it owns.
- **Other streams switch their own call sites after I1:** O (`rebase_descendants`), P (`embargo_withheld`, `committed_closure`, `push_closure`, `ancestors_in`), S (`ChangeIndex`, export and colocate order).

**O: lock-free op log** (size XL; after F)
- **Owns:**
  - `oplog.rs`'s behaviour (`merge_views`, `settle`, ancestor-head pruning);
  - `transaction.rs`;
  - `repo.rs` `open`, `reload`, `transaction`, `init_with` and `update_config`;
  - `lock.rs` (`RepoLock::acquire_at` for the gc lease, the working-copy `flock` helper);
  - `store.rs`'s write path (`begin_staging`, `write_loose`, `write_if_absent`, `sync_barrier`, publish, the staging sweep);
  - `workspace.rs` (the `snapshot_workspace_with` compare-and-swap, `undo_target`, `redo_target`, `undo_keeping_edits`, `restore_operation_keeping_edits`);
  - `working_copy.rs`;
  - `crates/vl/src/ctx.rs`;
  - `crates/vl/src/mount.rs`'s recording and locking;
  - `crates/vl/src/sandbox.rs` `finish` (the recording step only);
  - `git/colocate.rs` `follow`'s locking only.
- **New tests:** `tests/oplog_concurrency.rs` (a multi-process scheduler with crash and power-loss injection), and `undo_redo_props.rs` with the second actor.

**P: push and pull** (size L; the phase split starts after B1, the spooling after G1)
- **Owns:** `remote.rs` (all of it), `push_plan.rs`, `cmd_push` and `cmd_pull` in `main.rs`, and the remote-staging report in `crates/vl/src/doctor.rs`.
- **Covers:** item 1 (including the path-aligned `known`) and item 4's streaming pull.
- **Tests:** `tests/push_two_phase.rs`, plus extensions of `sftp_sync.rs`, `push_plan.rs`, `remote_lock.rs` and `crash.rs` (push and pull sweeps).

**S: streaming Git import** (size M; after I1)
- Owns `git/import.rs`, `git/map.rs`, `git/mod.rs`, `git/export.rs`, and `git/colocate.rs` except `follow`'s locking.
- Item 4's import section, and the `ChangeIndex` and export-order switches.

**L: sandbox limits** (size M; t0, independent)
- **Owns:**
  - `crates/vl/src/limits.rs`;
  - in `crates/vl/src/sandbox.rs`: `run_command`, `Interrupts` and `sweep_stale` (the cgroup part);
  - the limits section of `crates/vl/src/doctor.rs`;
  - the guide page.
- Item 8.

**A: agent attribution** (size M; after F, with `revset.rs` after I)
- **Owns:**
  - `attribution.rs` (`stamp`, the sealing rules, the side record, configuration);
  - `crates/vl/src/attribution_cmd.rs`;
  - the agent line in `crates/vl/src/api/text.rs` and in `shape.rs`;
  - the `agent()` function in `revset.rs` (after I merges);
  - the `ws exec` and mount flag plumbing (`exec_persistent`'s option struct; `mount.rs` `state.json`), by function, after L and O.
- Item 7.

**R: reflink checkouts** (size S–M; any free slot, after O for `Ctx`)
- Owns `vfs/clone_source.rs`, `checkout.rs` (`apply_changes` ordering and the clone path), `vfs/disk.rs` `clone_known`, and in core `sandbox.rs` the trusted-source helper.
- Item 5.

**C: partial clone** (size XL; last)
- **Owns:**
  - `promisor.rs`;
  - the `read_raw` miss hook in `store.rs` (after G2);
  - in `remote.rs`, the clone and partial functions (after P);
  - checkout batching (after R);
  - the `opendir` prefetch in `mount/fs.rs`;
  - `cmd_clone` and `partial_cmd.rs`;
  - **step C2:** the audit of every `Missing` / `is_unreadable()` site in `veil-core`, which touches many files and so runs only once every other stream has merged.
- Item 6.

**X: conditional, streaming large-file builder** (backlog). Taken only if B's `5g` numbers show the builder over the 512 MiB gate. It would own `builder.rs`'s read, hash and seal path.

## 3. Order and dependencies

```text
t0 ── 0 ──┬── B1 (trace + baseline) ── B2 (agents, cloaked, 5g) ·································· final gate run
          ├── F ──────────┬── O ─────────────────────┬── R
          │               └── A (revset part after I) │
          ├── G1 ──┬── P ─────────────────────────────┤
          │        └── G2 ────────────────────────────┤
          ├── I1 ──┬── I2/I3                          │
          │        └── S                              │
          └── L                                       │
                            adversarial pass A ◄──── O, P, I, G merged (concurrency, durability, index)
                                                      C (after P, G2, O, I, R) ── C2 audit ── adversarial pass B (C, A, R)
```

- **The baseline decides the middle.** F, G1, I1 and L are foundations or independent work and start at t0. After B1's baseline, O, P and G2 are ordered by which gate is worst: lock waits favour O and P; walks favour I2/I3; RSS favours G2, and possibly X.
- **Pipeline merges:** each stream merges as soon as it is green, and fix waves from pass A run beside C when their files are disjoint.
- **Dependencies that are real** (not just convenient):
  - O needs F's layout and fields;
  - P's spool needs G1;
  - C needs P (push from partial clones), G2 (the read-miss path), O (staging and promotion) and I (anchors use `range`);
  - A's `revset.rs` part needs I's edits there;
  - R needs O's `Ctx` to call the stub hook;
  - S needs I1.

## 4. Size estimates

| stream | size | production LOC (est.) | tests (est.) | agent time |
|---|---|---|---|---|
| 0 | XS | 250 | – | orchestrator, 2 h |
| B | M | 1,800 (harness 1,500, trace 300) | 300 | 1–1.5 days (plus run time) |
| F | M | 800 | 900 + fixtures | 0.5–1 day |
| G | L | 2,200 (G1 600) | 1,600 | 2 days (G1 0.5) |
| I | L | 2,500 | 2,000 (property tests against naive walks) | 2 days |
| O | XL | 3,000 | 3,000 (multi-process scheduler, crash and EIO sweeps) | 3 days |
| P | L | 1,800 | 1,600 | 1.5–2 days |
| S | M | 900 | 800 (crash and resume equivalence) | 1 day |
| L | M | 1,100 | 700 | 1 day |
| A | M | 900 | 900 | 1 day |
| R | S–M | 600 | 500 | 0.5–1 day |
| C | XL | 3,000 | 2,500 (server-logging SFTP harness, offline matrix, audit table) | 3 days |
| X | M (conditional) | 1,000 | 600 | 1 day |

That is about 19 agent-days without X: roughly 5 working days with four streams at a time, and 9–10 with two.

## 5. Disk: how many streams at once

- **Measured now:** **17 GB free** on `/` (ext4). The brief's ~35 GB is not there. `/tmp` is tmpfs (7 GB, RAM-backed) and is not used for builds or benchmarks. ext4 also means item 5's real reflinks can't be exercised on this machine (see its note).
- **Each agent build** uses 4–8 GB. Benchmarks: `small` under 1 GB, `1g` about 5 GB, `cloaked-1g` about 6 GB, `5g` about 10 GB at peak (item 9's table).

| free disk | builds at once | benchmarks allowed meanwhile |
|---|---|---|
| **17 GB (today)** | **2** | `small` only. `1g` or `cloaked-1g` with **one** build running. `5g` with **none** |
| 25 GB | 3 | `1g` with 2 builds running |
| 35 GB (the brief) | **4** | `1g` beside 3 builds. `5g` with at most 1 build running |

- **Recommendation:**
  - before the round, delete the `target/` directories of merged or abandoned worktrees under `~/.t3/worktrees/veil/` to get toward 35 GB;
  - run 2 streams at once until then;
  - never run `5g` while anything builds;
  - keep each build at `CARGO_PROFILE_DEV_DEBUG=line-tables-only`.
- **Sharing one `CARGO_TARGET_DIR`** across streams does not help: Cargo locks the directory, so the builds would run one after another.

## 6. Top risks for the adversarial passes

1. **"Missing means redacted"**, now reachable three new ways:
   - an unfetched object in a partial clone (item 6, threat 1);
   - a reader racing loose-object consolidation (item 4, threat 2);
   - a reader racing staging publication (item 2).

   Any of them can make a checkout write an embargo fallback over a member's cloaked file, a push skip history, or gc and fsck misjudge.
   - *Harness:* a fault-injecting store wrapper that turns random reads into "transiently absent" and "remote unreachable". Commands must either succeed with identical results or fail without writing.
   - Plus C2's audit table of every `is_unreadable()` site.
2. **Concurrency without the repository lock** (item 2). Covers:
   - lost view updates;
   - cross-process adoption of objects that are not durable (fsyncgate, BUG-044);
   - two recorders of one directory (BUG-361/362/117);
   - the 5→6 upgrade race;
   - undo removing another workspace's work.
   - *Harness:* `oplog_concurrency.rs`'s multi-process scheduler. Random `vl` commands across 2–8 processes and workspaces, with crash, `kill -9` and power loss at random mutations, and these invariants: `fsck` clean, no committed change lost, every visible snapshot complete.
3. **Embargoes under concurrency and through the index.**
   - A concurrent rebase escaping an embargo (item 2, threat 3).
   - A stale generation after a redacted parent arrives (item 3, threat 4).
   - A corrupt or tampered index steering `embargo_withheld` (item 3, threat 6).
   - *Harness:* extend `adversarial7`'s public-mirror grep. After every step, push to a public mirror and grep decoded objects for the fix's names. Run it with the index on, off, corrupted, and rebuilt mid-run.
4. **Confidentiality of new local and remote artefacts.**
   - The index's Bloom filters (item 3, threats 1–2): byte-identical with and without keys.
   - The fetch pattern (item 6, threats 2–3): a server-side request log compared with the scope batches.
   - Attribution task and prompt on cloaked and embargoed lines (item 7, threats 1–2).
   - Public staging after a rejected push (item 1, threat 4).
5. **The two-phase push.** The boundary disappearing between the phases (item 1, threat 2); the dry run drifting from the push (threat 12); the format-5 compatibility of staging (threat 13).
   - *Harness:* `push_plan.rs`'s property test with a second client force-pushing and pruning between the phases.
6. **Secrets moving between sandboxes and the project directory**: reflink sources (item 5, threats 1–3), and limits killing `vl` before it cleans up injected files (item 8, threat 2).
   - *Harness:* `ws exec --with-isolated` with background writers, followed by `ws switch` and memory-limit kills. Grep the project directory and history for injected values.

**Pass A** (after O, P, I, G) takes risks 1 (G and O parts), 2, 3 and 5. **Pass B** (after C, A, R) takes 1 (C part), 4 and 6. Both are Opus at high effort, and nothing ships with an open critical or high bug.
