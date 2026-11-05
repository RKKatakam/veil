# 2. A lock-free operation log

Status: design and threat review (Scion 1.3). **Requires format 6** (`PLAN.md` §2): an older vl reads only `.veil/op_head`, and would silently fork the log.

## The problem

`Repo::transaction` (`repo.rs`) takes `RepoLock` (`.veil/lock`) and holds it until the `Transaction` drops. Everything a command computes happens inside it. For a working-copy snapshot (`Repo::snapshot_workspace_with`, `workspace.rs`) that includes:
- building the tree: reading and hashing every changed file;
- the scanner;
- policy;
- sealing;
- then the auto-rebase (`Transaction::rebase_descendants`) and the confinement check.

So N agents recording N sandboxes queue on one file. `ws exec` recordings fail after the 15 s local wait (BUG-551), `vl watch` and a mount's timer contend with every command, and a long pull blocks the repository for its whole run.

The lock does real work today, and each of these jobs needs a replacement:
1. **Serialising `op_head`.** It is the only mutable pointer of the log. A transaction's view is "the head's view plus my changes".
2. **The durability protocol for unsynced objects** (§9):
   - a failed barrier removes its objects (BUG-044);
   - a dead holder's objects are re-hashed by the next holder (`fsck::recover_interrupted_writes`, the `recover_window`, BUG-096).

   Both assume that nobody else can adopt those objects in between.
3. **`expected_wc` checks** (BUG-361, BUG-362): a snapshot is recorded only into the working copy it was checked out from, checked under the lock.
4. **Metadata read-modify-writes:** key rings, embargo records, team-vault records, the local vault and `repo.json`.
5. **gc**, which holds the lock for its whole run.

## Design sketch

### Operation heads (format 6)

```text
.veil/op_heads/<hex op id>     empty files: the current heads of the op log
.veil/ops/<hex op id>          operations, unchanged (content-addressed JSON)
.veil/op_head                  not written at format 6; if present, read as one more head (threat 9)
```

- **Writing** (`OpStore::publish`):
  1. Write the operation durably (`OpStore::put`, as now).
  2. Create `op_heads/<new>` with `create_new` (durable).
  3. Remove `op_heads/<p>` for each parent `p`. A crash between 2 and 3 leaves a head that is an ancestor of another, and readers drop it.
- **Reading** (`OpStore::heads`):
  - list `op_heads/`;
  - drop every head that is an op-graph ancestor of another (a walk over `Operation::parents`, which stops at operations older than the oldest head's timestamp minus one hour, or at a pruned operation);
  - if one remains, that is the view. If several remain, see "Merging" below.

### Transactions without the lock

- **Start.** `Repo::transaction` no longer acquires `RepoLock`. It records the **base**: the set of heads it read and their merged view.
- **Objects are staged, not shared** (the replacement for item 2 of the list above). `ObjectStore::begin_staging(tx)` sends new loose objects to `.veil/objects/incoming/tx-<pid>-<boot hash>-<start ms>-<rand>/ab/cdef…`. Reads look there first. Nobody else ever looks in another transaction's staging.
- **`Transaction::commit`:**
  1. `rebase_descendants` and `check_confinement`, as today, against the base view.
  2. **The barrier** syncs the staging directory. If it fails, the staging directory is removed and the commit fails (nobody else could have adopted those objects).
  3. **Publish:**
     - rename each staged object into its fan-out directory, skipping any that a published copy already holds;
     - sync every fan-out directory touched, **and the fan-out directory of every object this transaction found already present instead of writing it** (`write_if_absent` returning `false`). This makes another process's just-renamed copy durable before our operation references it.
  4. **Re-check under compare-and-swap semantics.** Re-read the heads. For every workspace whose snapshot this transaction recorded with `SnapshotOptions::expected_wc`, check that the pointer is still the expected one in the new heads' merged view. If not, the result is `superseded`, exactly as today.
  5. `OpStore::publish`, with `parents` = the base heads (sorted).
  6. `Repo::settle()`: re-list the heads. If there are several (someone committed concurrently), write the merge operation now.
- **Staging left by dead processes.** `fsck` reports it, and `Repo::open` sweeps it: a directory is removed only when its pid is provably dead by `lock.rs`'s rules (`process_alive_with` with the pid namespace, zombies, pid reuse by start time, boot id). A directory from a previous boot is removed too. Nothing in it was ever published, so this needs no recovery window. **`recover_interrupted_writes` and the `"recover"` lock flag remain only for format-5 repositories and for remotes.**
- **Pull** writes its packs into its staging directory and publishes them at commit, the same way (item 4).

### Merging concurrent operations

`oplog::merge_views(base: &View, sides: &[(&Operation, &View)]) -> MergedView` is a deterministic 3-way merge against the nearest common ancestor operation:

| field | rule |
|---|---|
| `heads` | 3-way set merge: kept if both sides kept it, or one side added it; dropped if one side removed it and the other did not re-add it |
| `workspaces[name]` | 3-way. Both changed, differently: the side whose operation id sorts first wins; the other side's working copy stays visible as a head and is named in a warning ("concurrent edits of workspace W kept as change X"). With the per-workspace lock (below) this only happens for commands that move a workspace without recording it |
| `tags[name]` | 3-way. Both moved: if one target descends from the other, take the descendant; otherwise the first by operation id wins, and the other target becomes a visible head with a warning. Release tags (with `annotation`) are immutable, so two different ones created concurrently keep the first |
| `remote_tags`, `remote_release_tags` | 3-way per key; both changed: the first by operation id wins (a cache of remote state; the next pull corrects it) |

- **Rewrites travel with the operation.** Format 6 adds `Operation::rewritten: BTreeMap<ObjectId, Vec<ObjectId>>` (old snapshot → its replacements; empty means abandoned; omitted when empty), filled from `Transaction::rewritten`.
- **The merge applies each side's rewrites to the other side's new snapshots.** It is a `Transaction::for_merge(repo, merged_view, rewritten_union)` that runs the existing `rebase_descendants`, limited to snapshots that are new on the other side (bounded with item 3's `GraphIndex::descendants_among`), then `check_confinement`.
  - **A rewrite that the merged view would turn into an embargo escape is dropped:** the moved change stays on its old parents, and the warning names it (threat 3).
  - Both sides rewrote the same snapshot differently: both replacements stay visible. That is a divergent change, as two snapshots with one change id already are.
- **The merge operation never fails for a policy reason**; it degrades as above (threat 18). Its `timestamp` is the maximum of its parents' timestamps, `user` is `"veil"`, `description` is `merge N concurrent operations`, and `parents` are sorted. **Two processes merging the same heads therefore write byte-identical operations** with the same id, and `create_new` of the same head file simply loses to itself.
- **Read-only commands** (`log`, `status` without changes, `show`) merge in memory and write nothing.

### What still takes a lock

| lock | file | taken by | held for |
|---|---|---|---|
| metadata lock | `.veil/lock` (unchanged file and protocol, fencing on remotes) | `Keychain` read-modify-writes, `Repo::vault_update`, `team_vault`, `Repo::update_config`, `vl upgrade`, push phase B on remotes | milliseconds to seconds |
| working-copy lock | `.veil/local/wc/<ws>.lock` (`flock`, device-local; `.`/`..` spelt as for sandboxes) | `Ctx` for the attached workspace, from the snapshot through the checkout and the `checkout.json` write; `ws exec` (beside its sandbox lock); mount recordings; `ws write` | one command's working-copy work |
| gc lease | `.veil/gc.lock` (item 4) | gc and maintenance | the gc run |

- **One recorder per directory.** The working-copy lock keeps BUG-361/362 and BUG-117 impossible: two processes never snapshot or materialise one workspace's directory at once. The `expected_wc` check at commit (step 4) catches everything else.
- **Upgrades in flight.** Transactions also re-read `repo.json`'s `format` at commit. A repository upgraded since the transaction began fails it with "repository was upgraded; run the command again".

### Undo, redo and `op restore`

Format 6 adds `Operation::workspace: Option<String>`: the workspace the command was run for, which is the attached one for project-directory commands and `NAME` for `ws exec NAME`, `ws write NAME` and mounts.

- **`Repo::undo_target(ws)`** (`workspace.rs`) walks the op graph newest first (by timestamp, then id). It skips automatic snapshots and merge operations, as it skips automatic snapshots today. It takes the first command whose `workspace` is `ws` or `None` (repository-wide commands: tags, pulls, remote changes).
  - With `undo_of`/`redo_of`, repeated undo and redo keep jj's semantics.
- **`vl undo` applies the undo as a 3-way revert:** `merge_views(base = target.view, sides = [current, target's parent view])`, so other workspaces' concurrent operations stay.
  - When no other workspace's operation landed after the target, this result equals today's "restore the parent's view", and `undo_keeping_edits` re-applies recorded edits exactly as now.
  - The property test against jj's model keeps passing for the single-actor case.
- **`vl undo --op ID`** undoes a given operation.
- **`vl op restore ID`** restores a whole view. If operations of other workspaces landed after `ID`, it refuses without `--force` and lists them, since their work would leave the view (it stays recoverable in the log).
- **`manual_undo` operations** are refused as today (BUG-116).

### Unchanged

- The op log stays device-local and is never synced.
- Remotes keep a single head: they are written only by push phase B and remote gc, both under the lock (format-6 remotes use the `op_heads/` layout with exactly one file).
- `vl op log` prints merge operations with their parents. A debugging command, `vl op heads`, lists the heads.

## Threat review

1. **A lost view update in a merge.** Two concurrent commands change different keys (two `vl tag set`; a commit in workspace `a` and one in workspace `b`).
   - *Invariant:* every committed operation's change to a view key is in the merged view, unless the other side changed the same key, in which case one wins and the loser's target stays a visible head.
   - *Test:* a property test: random pairs (and triples) of commands run concurrently through `Transaction` hooks, compared with a model that applies them sequentially per key.
2. **A child left on a rewritten parent.** A amends X into X′ while B commits Y on top of X.
   - *Invariant:* after the merge, Y's change is rebased onto X′ (the jj behaviour), using `Operation::rewritten`.
   - *Test:* run both through a barrier. The merged view shows Y on X′, X hidden, and `vl evolog` intact.
3. **Escaping an embargo through concurrency (BUG-681 class).** A rebases change X onto public `main`. Concurrently, B makes X part of unreleased embargo E (an embargoed merge of the fix line holding X). Each check passes on its own view, so the merged view holds a copy of the fix outside the embargo.
   - *Invariant:* the merged view never holds a change outside an embargo that either side had inside it. The merge re-runs `check_confinement` and drops violating rewrites.
   - *Test:* the interleaving above with deterministic hooks, then `vl push` to a public remote. Grep every decoded object there for the fix's file names: none.
4. **Two recorders of one workspace** (`vl watch`, a mount, `vl status` in two terminals). This is the BUG-361/362/117 class.
   - *Invariant:* at most one process snapshots or checks out a given workspace's directory at a time (the working-copy lock), and a snapshot is recorded only into the working copy it was materialised from (`expected_wc` at commit).
   - *Test:* `adversarial_cli_crash` style: 8 concurrent `vl status` loops while files change. No edit is lost, no stray side change appears, and the final working copy equals the disk.
5. **Adopting an object that is not durable** (the BUG-044 class across processes). B finds an object A just wrote and reuses it. A's barrier fails, or A dies, and power is lost.
   - *Invariant:* an operation references only objects that were published after their writer's successful barrier, or that this transaction synced itself; publication renames are made durable by the referencing transaction's own directory syncs.
   - *Test:* `EioBackend`, shared by two simulated processes: A's barrier fails while B adopts; then a power loss. B's operation is complete, and `fsck` passes.
6. **A torn publication.** A crash between renames publishes some objects and writes no operation.
   - *Invariant:* published objects are content-addressed and complete, so partial publication is unreachable garbage at worst.
   - *Test:* the `crash.rs` sweep over snapshot, commit, rebase, merge, push and pull, with renames and head-file creations as mutations, in all three modes.
7. **Removing a live transaction's staging.** A process sweeps staging that belongs to a live transaction (pid reuse, another pid namespace, a `.veil` shared by two hosts over NFS).
   - *Invariant:* staging is removed only when its owner is provably gone by `lock.rs`'s rules. Otherwise it stays, and `vl doctor` reports it.
   - *Test:* `ProcessProbe` simulations: a zombie, a reused pid with another start time, an unknown namespace (kept), another host's name (kept).
8. **A head pointing at nothing.** A planted or torn `op_heads/` entry names a missing or undecodable operation.
   - *Invariant:* `Repo::open` fails as for a damaged `op_head` today, and `fsck` (which works without `Repo::open`) names the head file. A head file is created only after its operation is durable.
   - *Test:* plant a head for a random id. `vl status` fails with the fsck hint, and `vl fsck` reports exactly that file.
9. **The upgrade race.** A format-5 process (an older vl, or this vl opened before `vl upgrade`) commits after the 5→6 commit point by writing `op_head`. Its operation would never be seen.
   - *Invariant:* at format 6, a present `op_head` file names one more head; the next writer merges it in and removes the file.
   - *Test:* after an upgrade, write an operation and `op_head` the way format 5 does. The next command merges it, and the tag it set is in the view.
10. **Merge storms.** With N agents, many processes see the same heads and each writes a merge.
    - *Invariant:* merging the same set of heads always yields a byte-identical operation.
    - *Test:* two processes `settle` the same three heads; `ops/` gains one file.
11. **Undo removes someone else's work.** A human's `vl undo` undoes an agent's commit, or restoring a parent view drops concurrent agents' operations.
    - *Invariant:* undo without `--op` targets the caller's workspace (or repository-wide) commands, and applies as a 3-way revert that keeps every other operation's changes.
    - *Test:* extend `undo_redo_props.rs` with a second actor on another workspace, committing between the first actor's commands. The jj-model property holds for actor 1, and none of actor 2's changes disappear.
12. **`op restore` drops concurrent work.**
    - *Invariant:* it refuses without `--force` when operations of other workspaces landed after the target.
    - *Test:* `adversarial6_cli`: restore after another workspace committed fails and lists the operation; it succeeds with `--force`.
13. **Ancestry after pruning.** `gc --keep-ops-days` removes the operations that link two heads.
    - *Invariant:* an unknown op ancestry counts as "not an ancestor", which costs a harmless extra merge and never drops a head.
    - *Test:* prune, then commit concurrently. Both commits are in the merged view.
14. **A transaction outlives gc's grace period.** A long pull or a slow sandbox recording references an object that became unreachable meanwhile, and gc deletes it after the grace period.
    - *Invariant:* a transaction older than half the grace period freshens (`ObjectStore::has`) every pre-existing object its new trees reference before it publishes.
    - *Test:* `SimClock`: start a transaction, run gc twice across 61 minutes with the object unreachable, then commit. The object is present, and `fsck` passes.
15. **Concurrent writes to a key ring or the vault** now race transactions instead of being serialised with them.
    - *Invariant:* every read-modify-write of `meta/` and the vault holds `.veil/lock` (unchanged), and no transaction reads metadata it then rewrites outside that lock.
    - *Test:* `metadata_lock.rs`: concurrent `scope grant` + `pull` + `commit`. No grant is lost.
16. **Features that relied on the lock:**
    - **sandboxes:** step 7's recording no longer waits for the lock (the BUG-551 failure goes away);
    - **mounts:** they record through `snapshot_workspace_with` and follow the workspace, both unchanged;
    - **`vl serve` / `vl watch`:** `Repo::reload` merges heads.

    - *Invariant:* each keeps its existing guarantee with the lock removed.
    - *Test:* the existing mount, sandbox and serve suites, plus one interleaving test each: a mount timer racing `vl commit`; `ws exec` recording racing `vl rebase` of its base.
17. **The embargo release staged in `.veil/local/releases/`** is outside the view.
    - *Invariant:* unchanged: undo and redo never release, and a 3-way undo of a release operation is refused as today.
    - *Test:* `embargo_release.rs`: run the release-undo cases with a concurrent commit.
18. **A merge that always fails.** One poisoned head (an invariant check erroring) makes every later command fail.
    - *Invariant:* the merge never fails for policy reasons (it drops rewrites and keeps both targets visible). Only I/O and corruption fail it, and `fsck` names them.
    - *Test:* make one side's rewrite violate confinement. Later commands succeed and warn once.

## Open decisions

1. **The layout.**
   - *Recommendation:* the `op_heads/` directory (jj's model), and format 6.
   - The alternative, keeping `op_head` and appending to a log file under a short lock, still serialises every commit and keeps the cross-process durability problem.
2. **Conflicted tags** (jj has them).
   - *Recommendation:* not this round. Keep one target, keep the other visible, and warn. A real conflicted-tag view field would need its own format addition and CLI.
3. **What `vl undo` undoes.**
   - *Recommendation:* the caller's workspace's last command (above).
   - jj undoes the last operation globally, which under agents is almost never what the human meant.
4. **When to merge.**
   - *Recommendation:* writers merge right after they publish (`settle`); readers merge in memory. Nothing merges in the background.
5. **Whether pull should stage packs, not loose objects.**
   - *Recommendation:* yes for more than 256 objects (pull already packs), as item 4 specifies.

## As built / threat review (stream O)

Written before the build, from the design above and a read of the code at `integration` 1799b89; kept up to date as built. Every numbered item has a test, named in brackets.

### Decisions taken while building

- **Which transactions are lock-free.** A repository at format ≥ 6 on a non-network backend, opened as a project (`Repo::open`). Format ≤ 5 repositories keep `op_head`, the lock and the unsynced-object protocol unchanged. Remotes are opened with `Repo::open_remote`: their transactions keep `.veil/lock` (push phase B, remote gc), with one head in `op_heads/`. On a network backend (SFTP) objects keep the unsynced protocol and lock recovery; on a disk remote they are staged like local ones, so no writer ever leaves an unsynced object under its final name at format 6.
- **Staging.** `.veil/objects/incoming/tx-<owner>/ab/cdef…`, `<owner>` = `<host hash>-<boot hash>-<pid>-<pid start>-<ms>-<random>`. A pull's spool is `incoming/pull-<owner>` of its transaction. `owner_gone` (lock.rs) applies the lock's takeover rules to that name: same host, boot and pid namespace with the pid provably dead or reused (start time differs), or this process's own name not registered any more (a dropped transaction), or the same host with `ms` before this boot. Everything else is kept. `Repo::open` sweeps dead owners' directories; `vl fsck` notes live ones.
- **An aborted transaction publishes too.** A transaction dropped without committing still syncs and publishes what it staged, as today's drop barrier keeps unsynced objects: the stat cache may already name them (a superseded snapshot keeps its cache). Only a failed barrier voids a staging directory.
- **Publication order** (`Transaction::commit`): rebase and confinement; barrier over the staging directory (a failure removes it); rename every staged object over its final name (content-addressed, so replacing a concurrent identical copy is harmless and keeps a gc-freshened copy); a second barrier over every fan-out directory touched and every fan-out directory of an object found already present; the threat-14 freshening; the compare-and-swap re-checks; `OpStore::publish`; `settle`.
- **Merging at open, not only in memory (a deviation).** The design lets read-only commands merge in memory. A merge that drops an escaping rewrite (threat 3) must have run before any command uses the view: push computes what to send from the view it opened. So `Repo::open` and every transaction start settle several heads on disk (the merge is deterministic, so concurrent settlers write one operation). `Repo::open_remote` merges in memory without rewrites (remotes have one head; only a lock-free writer inside a bare directory makes two), and push settles it under the lock before writing.
- **Per-field merge of workspaces and tags.** `WorkspaceState::wc` and `cloak` merge separately, as do a tag's `(target, annotation)` and its `cloak`. A cloak conflict keeps the cloaked side: a concurrent `ws cloak`/`tag cloak` never loses to a move. A release tag's target and annotation are one unit (never torn apart). A key changed on one side and removed on the other keeps the change (no lost update); its old value stays reachable from the log.
- **`Operation::workspace`** is the repository's command workspace (`Repo::set_command_workspace`, set by `Ctx` to the attached workspace, by `ws exec`, `ws write` and mounts to theirs, by `snapshot_workspace_with` to the recorded one). Repository-wide commands (tag set/delete/move, push, pull, remote add/remove) clear it with `Transaction::repository_wide`. Written only at format ≥ 6.
- **Undo and redo** compute their 3-way revert inside their transaction, from its base view, never from a view read before it (that would revert work committed in between). The revert side wins a conflict; a workspace whose working copy the revert restores carries its edits as before, and the snapshot that held them leaves the heads.
- **Working-copy lock.** `lock::WcLock` (`flock` on `.veil/local/wc/<ws>.lock`, re-entrant within a process), taken by `Ctx` for recording and checkout, by `vl watch` per recording, by `ws exec`'s recording, `ws write` and mount recordings.

### Threats, mechanisms and tests

| # | threat | mechanism | test |
|---|---|---|---|
| 1 | lost view update in a merge | `oplog::merge_views` 3-way per key; property test against a sequential per-key model | `oplog_merge::merge_views_matches_sequential_model` (core_props), `oplog_concurrency::concurrent_tag_sets_all_land` |
| 2 | child left on a rewritten parent | `Operation::rewritten`, `Transaction::for_merge` re-runs `rebase_descendants` | `oplog_concurrency::amend_racing_child_rebases_child` |
| 3 | embargo escape through concurrency | merge re-runs confinement against every side's view; an escaping rewrite is reversed (the moved change back on its old parents) and named in a warning | `oplog_concurrency::concurrent_rebase_cannot_escape_embargo` (pushes to a public remote and greps decoded objects) |
| 4 | two recorders of one workspace | `WcLock`, plus `expected_wc` re-checked against the current heads at commit | `oplog_processes::concurrent_status_loops_lose_nothing` (cli), `oplog_concurrency::expected_wc_cas_supersedes` |
| 5 | adopting a non-durable object | staging per transaction; nobody reads another's staging; publish after a barrier; directory syncs for adopted objects | `oplog_concurrency::eio_barrier_never_adopted` |
| 6 | torn publication | renames and head creation are mutations in the crash sweeps (all three modes) | `crash::crash_during_*` (snapshot, commit, rebase, merge, push, pull) and `crash::crash_during_settle` |
| 7 | removing live staging | `lock::owner_gone` with the lock's rules | `oplog_concurrency::staging_sweep_keeps_live_owners` (zombie, reused pid, unknown namespace, other host, previous boot) |
| 8 | a head pointing at nothing | `Repo::open` fails; `fsck` names the head file | `oplog_concurrency::planted_head_fails_open_and_fsck_names_it`, cli `oplog_cli::planted_head_status_fails_with_fsck_hint` |
| 9 | the upgrade race | a stray `op_head` at format 6 is one more head, merged and removed | `format_compat::op_head_written_after_upgrade_is_merged` |
| 10 | merge storms | deterministic merge operation (timestamp, user, description, sorted parents, derived change ids) | `oplog_concurrency::two_settlers_write_one_merge` |
| 11 | undo removes someone else's work | `undo_target(ws)` per workspace; 3-way revert | `undo_redo_props::two_actor_undo_keeps_other_work` |
| 12 | `op restore` drops concurrent work | refusal without `--force`, listing the operations | cli `oplog_cli::op_restore_refuses_over_other_workspace` |
| 13 | ancestry after pruning | unknown ancestry is "not an ancestor" | `oplog_concurrency::pruned_ancestry_keeps_both_heads` |
| 14 | a transaction outlives gc's grace | a transaction older than half the grace period freshens every pre-existing object its new objects and its view reference | `oplog_concurrency::long_transaction_survives_gc` (`SimClock`-style injected clock) |
| 15 | metadata read-modify-writes race transactions | key rings, vault, embargo records and `repo.json` keep `.veil/lock` | `metadata_lock::grant_racing_lock_free_commits` |
| 16 | features that relied on the lock | sandbox, mount and serve suites; interleavings below | `oplog_concurrency::mount_recording_racing_commit`, `oplog_concurrency::exec_recording_racing_rebase_of_base` |
| 17 | embargo release outside the view | unchanged: undo/redo never release; release undo refused as today | `oplog_concurrency::release_undo_with_concurrent_commit` |
| 18 | a merge that always fails | merges degrade instead of failing for policy reasons; a warning is printed once, by the process that writes the merge | `oplog_concurrency::poisoned_side_degrades_and_warns_once` |
| 19 | lost update through a whole-view replacement (undo, redo, `op restore` computed before their transaction) | computed inside the transaction from its base | `oplog_concurrency::undo_racing_commit_keeps_commit` |
| 20 | a concurrent move dropping a cloak setting (wider audience) | per-field merge, the cloaked side wins | `oplog_merge::cloak_survives_concurrent_move` |
| 21 | a release tag's target torn from its annotation | `(target, annotation)` merged as one unit | `oplog_merge::release_tag_never_torn` |
| 22 | the stat cache naming objects an aborted transaction discarded | aborted transactions publish what they staged | `oplog_concurrency::superseded_snapshot_keeps_objects` |
| 23 | two pulls deleting each other's spool (BUG-800 follow-up) | `incoming/pull-<owner>` per transaction; cleanup by `owner_gone` | `oplog_concurrency::two_pulls_at_once` |
| 24 | a hostile `op_heads/` (non-hex names, a directory, a symlink) | only 64-hex regular files are heads; others are ignored and noted by fsck | `oplog_concurrency::hostile_op_heads_entries_ignored` |
| 25 | many writers on the disk backend lose an operation, or views differ | stress with threads and processes; every committed tag lands, `fsck` clean, one head after settle | `oplog_concurrency::many_threads_no_lost_operation`, cli `oplog_processes::many_processes_no_lost_operation` |
