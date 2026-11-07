# 3. A history index (commit-graph)

Status: **built** (stream I), except the Bloom filters (I2, see "As built"). **No repository format change.** The index is a device-local cache with its own magic and version, and it is rebuilt whenever it cannot be read.

## As built (2026-11-05)

The design below was simplified where a simpler rule closes the same threat:
- **Generations are corrected commit dates** (Git's v2), not topological levels: `max(timestamp, 1 + max(parents))`. Open decision 1 rejected them because authors choose timestamps, but pruning needs only that generations strictly decrease along every edge, which holds for any timestamps. A false timestamp only makes some walk longer. Plain levels made every walk read all of `main` to rule out an old branch or an old tag (measured: `status` with a change and `log -n 20` read 100 % of `small`).
- **The index holds no parents.** Walks read every snapshot they visit and take parents from the object, so a damaged index can only cost time; threat 6's parent checks are unnecessary. Entries hold the generation, the change id and two flags: `embargo` set, and an embargoed snapshot among the ancestors (`FLAG_EMBARGO_LINE`, derived from the parents). The embargo checks (`embargo_withheld`, `active_embargoes`, `carried_embargo`) walk only lines with that flag: with no embargo in the history, nothing.
- **No `GEN_UNKNOWN`.** A missing parent is ignored in the child's generation, and listed in its layer. When one arrives the index is voided and recomputed (threat 4): checked on open, after each commit and on `Repo::reload`.
- **Layers are named `L-<epoch>-<lo>-<hi>.vcg`**, created with `create_new` one slot at a time, so appenders never lose one another's layers and no `chain` file is rewritten. Voiding writes the next epoch's marker `E-<n>` first, so a layer appended concurrently from the old epoch is never mixed in.
- **No `vl index rebuild`.** Entries missing from disk are computed from the store on first use and persisted at the next commit (or once 256 accumulate). A damaged layer voids the index.
- **`topo_iter`** is Kahn's algorithm made lazy: exploration only as deep as the next node to emit, and a root is examined only once its timestamp could be the next one emitted. Its output is exactly `topo_children_first`'s (property-tested, threat 12).
- **Not built yet:** the Bloom filters (`log -- PATH`, `blame`) and the push and pull walks (`committed_closure`, `push_closure`, `ancestors_in`, stream P). `log -n 20 -- <hot file>` reads 24 % of `small`'s history without them; whether `1g` needs them is for the gate run.
- **Measured** on `small` (1,073 snapshots), snapshots read before → after: `status` with 1 or 100 modified files 1,073 → 3; `commit` 1,073 → 1; `log -n 20` 1,073 → 92; `log -n 20 -- <hot file>` 1,073 → 255; `tag set` and `ws exec` 1 → 1; push still 1,073 (stream P). N = 64 agents: 1,757 landings per minute (baseline 397, partly from BUG-801's fix).

## The problem: the walks that read all history

Every snapshot is a plaintext object, so all of these are correct, but each reads every reachable snapshot:

| walk | callers that run it on everyday commands |
|---|---|
| `Repo::topo_children_first(roots)` (full Kahn sort) | `Transaction::rebase_descendants` (**every** commit that rewrites anything, over `start_view.refs() ∪ view.refs()`), `revset::resolve_set` (`A..B`, `A..`), `revset::local_history` (the BUG-105 shadow check), `blame::blame` (orders all ancestors first), `bisect` |
| `Repo::visible_snapshots()` | `api::log_entries_with` (`vl log` with no revset builds the whole list before applying `-n`), `confinement::active_embargoes`, `remote::embargo_withheld`, `commands::check_current`, `revset.rs` change-id resolution, `history.rs`, `main.rs` |
| `Repo::ancestors(id)` / `is_ancestor` / `common_ancestor` / `merge_bases` (full ancestor sets) | `remote::embargo_withheld` (twice per unreleased embargo), `commands::carried_embargo`, `commands::merged_in_signed_by`, `bisect` |
| `remote::committed_closure`, `push_closure`, `ancestors_in` | every push and pull |

`Confinement::new` calls `embargo_withheld`, so since BUG-681 every rewrite that moves parents walks the history once per unreleased embargo.

## Design sketch

### Files

```text
.veil/index/graph/chain            text: one layer name per line, base first (replaced atomically)
.veil/index/graph/layer-<sum>.vcg  an immutable layer (content-addressed by its BLAKE3)
```

A layer:

```text
"VEILCG01" | count u32 | base_count u32 (entries in the layers below)
| fanout[256] u32 | ids[count] (sorted)
| records[count]:
    generation u32 | parent1 u32 | parent2 u32 | extra_parents_off u32
    | timestamp i64 | change_id [16] | flags u8 | bloom_off u32
| extra_parents (u32 lists) | change_ids_sorted [(change_id, position)]
| missing_parents [(position, parent id)] | bloom data | BLAKE3(all preceding bytes)
```

- **Parents** are global positions (`base_count + index`) into the chain, or `NONE`, or `MISSING`. A missing parent is not in the local store (redacted by an embargo, or never pulled) and is also listed in `missing_parents` by id.
- **Generation** is the topological level: 1 + the largest of the parents' levels, and 1 for the root.
  - It is `GEN_UNKNOWN` (`u32::MAX`) when any parent is missing or has `GEN_UNKNOWN`. That propagates to descendants until the parent arrives (threat 4).
  - Timestamps are not trusted for pruning: a snapshot's `timestamp` is chosen by its author.
- **`flags`** (plaintext fields of the snapshot): `EMBARGO_MERGE` (`embargo` set, with 2+ parents), `BLOOM_FULL`, `BLOOM_UNKNOWN`. (The design's `CLOAKED` and `WRAPPER` flags went with the snapshot's `cloak` field and embargo wrappers in repository format 8.)
- **The Bloom filter** (changed paths, against the first parent): Git's parameters, 10 bits per entry, 7 hashes (BLAKE3-keyed, context `veil 2026 graph-bloom v1`), at most 512 entries; above that `BLOOM_FULL` means "maybe" for every path.

### What goes into the Bloom filter: the public projection

The filter is computed from **what a reader with no keys sees**, never from decrypted trees (threat 1). `graph_index::changed_paths(store, tree, parent_tree)` diffs the two trees:
- **Plaintext directories** (`EntryKind::Dir` with `visibility.is_public()`, the rule `remote::local_trees` uses): descend; add every changed path and each of its ancestor directories.
- **A changed entry that is not a public directory** (a sealed directory, a file sealed or not): add its path. A sealed directory is not descended into; its path is added as a **boundary key**, `"\x01" ‖ path`. (Sealed directories were removed in repository format 8.)
- **An embargo wrapper tree**: Removed in repository format 8 (only secret files are encrypted).
- **A snapshot whose trees are not local** (a partial clone, item 6): `BLOOM_UNKNOWN`.

A query `maybe_touches(id, path)` answers true if the filter holds `path`, or holds `"\x01" ‖ a` for any ancestor directory `a` of `path` (including the root `"\x01"`), or the entry is `FULL` or `UNKNOWN`. False means "provably unchanged for every reader".

### API (`crates/veil-core/src/graph_index.rs`, `bloom.rs`)

```rust
impl Repo { pub fn graph(&self) -> &GraphIndex }        // opened lazily, shared
impl GraphIndex {
    fn generation(&self, id) -> Option<Gen>;             // None: not indexed (compute on the fly)
    fn parents(&self, id) -> Option<&[ObjectId]>;
    fn is_ancestor(&self, a, b) -> Result<bool>;         // gen cut-off: stop below gen(a)
    fn is_ancestor_of_any(&self, a, refs) -> Result<bool>;
    fn range(&self, include, exclude) -> RangeIter;      // A..B, lazily, children first
    fn topo_iter(&self, roots) -> TopoIter;              // lazily; the same order as topo_children_first (threat 12)
    fn merge_bases(&self, a, b) -> Result<Vec<ObjectId>>;// paint-down with gen cut-off
    fn descendants_among(&self, roots, of) -> Result<HashSet<ObjectId>>; // walk from roots down to min gen(of)
    fn embargo_merges(&self) -> impl Iterator<Item = ObjectId>;          // flagged entries
    fn by_change_id(&self, change_or_prefix) -> Vec<ObjectId>;
    fn maybe_touches(&self, id, path) -> bool;
}
```

- **Unindexed snapshots** are read from the store and cached in memory. The index is an accelerator and is never required.
- `topo_iter` uses Stolee's incremental topological walk (Git's `--topo-order` since 2.20). Generation numbers tell it when an in-degree count is complete, so it emits **exactly** the order of the full Kahn walk (`topo_children_first`'s heap by timestamp) without reading all history.

### Writing

- **After every commit,** `Transaction::commit` calls `graph().append(new snapshot ids)`: one small layer, best-effort. An error is a warning, and the index stays incomplete.
- **Pull** appends its snapshots after the operation.
- **Compaction** (item 4's maintenance) merges layers geometrically, each at least twice the size of the next, and drops entries of snapshots gc collected. Old layer files are removed 10 minutes after the chain stopped naming them, so a reader that opened the old chain can finish.
- **Lost updates are harmless.** The `chain` file is replaced with `write` (temp, rename). Two concurrent appenders can lose one layer from the chain, which only leaves those snapshots unindexed until the next append re-indexes them.
- **Building from scratch** (`vl index rebuild`, or automatically when `chain` is missing and the repository has more than 1,000 snapshots): stream the snapshots parents-first through an id → position map (about 40 bytes per snapshot), writing one layer.

### Callers switched (by the stream that owns each file; see `PLAN.md`)

- `repo.rs`: `ancestors` is kept (callers that really want the set). `is_ancestor`, `common_ancestor`, `merge_bases` and `topo_children_first` delegate to `GraphIndex`. `visible_snapshots` becomes an iterator (`visible_iter`), and callers that only need the first page stop early.
- `Transaction::rebase_descendants`: `descendants_among(view.refs(), rewritten)` instead of `topo_children_first(all refs)`.
- `remote::embargo_withheld`:
  - candidates come from `embargo_merges()` filtered by visibility (`is_ancestor_of_any(m, view.refs())`);
  - the merged-in set is `range(include = extra parents, exclude = first parent)`;
  - `confinement::active_embargoes` likewise.
- `remote::committed_closure`, `push_closure`: `range(include = tips, exclude = remote refs)`.
- `commands::carried_embargo`: walk with a stop at a generation below the oldest unreleased embargo merge.
- `commands::merged_in_signed_by`: `range(others, into)`. `commands::check_current`: `is_ancestor_of_any`.
- `api::log_entries_with`: `topo_iter(view.refs())` with `-n`. `log -- PATH`: skip entries where `maybe_touches` is false (and still diff the ones where it is true). `blame::blame`: `topo_iter([rev])` lazily, with `maybe_touches` skipping commits that cannot touch the path.
- `revset.rs`: change-id prefixes through `by_change_id`. `local_history` (the BUG-105 check) becomes `is_ancestor_of_any`.
- **`log -S` / `-G` (`search.rs`)** without a path stays a per-snapshot content scan: a whole-history query by definition, exempt from the gate (item 9). With `-- PATH`, the Bloom filter skips snapshots. With `-n`, it stops early.

## Threat review

1. **Sealed paths leak into the index.** Bloom filters built from decrypted trees would let anyone holding `.veil/` (a stolen laptop, a backup, an agent on the machine without the identity) test "did any change touch `deploy/.env.acquisition`", which at-rest sealing hides.
   - *Invariant:* the index bytes are a function of plaintext objects only: built with no identity, they are byte-identical to the index built with every key.
   - *Test:* a property test over random histories with sealed secret files, isolated files and embargoes. `vl index rebuild` with `VEIL_HOME` empty and then with the full identity must give identical files.
2. **The fix's file names under an embargo.** Removed in repository format 8 (only secret files are encrypted). Embargoes are not encrypted, and an unreleased embargo is withheld from every push.
3. **A false negative in the Bloom filter.** `vl log -- p` and `blame` miss a change, or a security check that someday uses the filter misses something.
   - *Invariant:* `maybe_touches(id, p) == false` implies that the full diff of `id` against its first parent, for **any** reader, changes nothing at or below `p`.
   - *Test:* a property test against the full diff for every reader (no keys, member of S) over trees with sealed files, renames, conflicts, symlinks and `BLOOM_FULL` edits (600 files).
4. **A stale generation after a missing parent arrives.** A public clone sees an embargoed merge with its extra parents redacted. After the release, the next pull brings them. Had the merge been given a finite generation, a parent arriving with a higher one would break `gen(a) < gen(b)`, and `is_ancestor` would answer false. `embargo_withheld` and confinement would then miss the fix line, and something withheld would be pushed.
   - *Invariant:* no entry with a missing parent, or a parent with `GEN_UNKNOWN`, has a finite generation; `GEN_UNKNOWN` never prunes a walk. When a snapshot listed in any layer's `missing_parents` arrives, the layers from the lowest one holding that entry are rebuilt.
   - *Test:* public clone, embargoed merge, release, pull. `is_ancestor`, `range` and `embargo_withheld` equal the naive walks, and a public push afterwards sends exactly what the naive push sends.
5. **A torn or corrupt layer.**
   - *Invariant:* every layer is checksummed and its records are bounds-checked on open. Any failure ignores the whole chain (with a note), so queries fall back to object reads, and the next maintenance rebuilds it. A layer never gives a wrong answer silently.
   - *Test:* flip each byte (sampled) and truncate each layer; every query equals the naive walk.
6. **A tampered index steers a security decision.** A crafted layer says X is not an ancestor of Y, and `embargo_withheld` stops early and sends the fix.
   - *Invariant:* walks behind push filtering, `embargo_withheld`, confinement and `merged_in_signed_by` read each snapshot they visit anyway (for `embargo` and signatures). They check that the index's parents equal the object's, and that each edge's generation strictly decreases. A mismatch raises `IndexCorrupt`, which drops the index and re-runs the walk without it.
   - *Test:* craft a layer with a wrong parent and one with a non-decreasing generation. `embargo_withheld` returns the naive result, and the index is marked bad.
7. **Entries for collected snapshots.**
   - *Invariant:* a resolution through the index (`by_change_id`, prefixes) is confirmed against the store, and an id that is not present is skipped.
   - *Test:* abandon, `gc --prune-now`, then resolve the old change id's prefix: "no such revision", not an error from a missing object.
8. **Concurrent appenders and compaction.**
   - *Invariant:* index writes only ever make the index less complete, never wrong. A reader whose layer was removed re-reads `chain` and retries once, then falls back.
   - *Test:* 8 threads committing while a compactor runs in a loop; every query equals the naive walk.
9. **A hostile history makes indexing cost too much.** A 10⁶-long chain, a 10,000-parent merge, a commit touching 10⁵ paths, a tree at `MAX_TREE_DEPTH`.
   - *Invariant:* indexing is linear in snapshots plus changed paths; per-entry Bloom work is capped (`BLOOM_FULL` at 512), the diff is iterative and bounded by `MAX_TREE_DEPTH`, and memory is the id → position map.
   - *Test:* `deep_trees.rs`-style generators. Rebuild time and peak RSS stay within 2× linear.
10. **Generation overflow.**
    - *Invariant:* levels saturate at `u32::MAX − 1`, which is treated as unknown.
    - *Test:* a unit test with a forced level.
11. **Format and upgrade.**
    - *Invariant:* an unknown magic or version is treated as "no index" and rebuilt; it is never an error. The index is not in `FORMAT.md`'s list of synced or versioned data, only in the inventory as a cache.
    - *Test:* write `VEILCG02` in a layer; commands work, and the next maintenance rewrites the layer.
12. **The output order of `log` changes.** Shape- and order-pinning tests, users' scripts and `--json` consumers rely on today's order.
    - *Invariant:* `topo_iter` yields exactly `topo_children_first`'s sequence.
    - *Test:* a property test comparing the full sequences on random DAGs with equal timestamps, criss-cross merges and redacted parents.
13. **Interactions with other features:**
    - **sandboxes and the mount:** they never see `.veil`;
    - **the team vault:** nothing indexed;
    - **partial clone:** item 6 keeps the snapshot graph complete, so generations are exact, and only Bloom filters of unfetched trees are `UNKNOWN`;
    - **`vl serve`:** queries go through the same API, so they return only what the reader may see.

    - *Invariant:* the index is never copied out of `.veil/` by any Veil command.

## Open decisions

1. **Generation definition.**
   - *Recommendation:* the topological level. Corrected commit dates (Git's v2) rely on timestamps, which authors choose.
2. **Bloom parameters.**
   - *Recommendation:* Git's (10 bits per entry, k = 7, 512 cap), revisited with item 9's numbers.
3. **Storing changed-path lists** (exact, not Bloom), so that `log -S` could skip unchanged files.
   - *Recommendation:* no. They are larger, and the public-projection rule already gives most of the benefit through `maybe_touches`.
4. **Whether `vl index` is a user command.**
   - *Recommendation:* only `vl index rebuild` and `vl doctor`'s report. Maintenance does the rest.
