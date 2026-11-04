# Veil architecture

Veil is built as a stack of small layers. Each layer only depends on the ones
below it, and nothing above the VFS layer knows a disk exists.

```text
┌──────────────────────────────────────────────────────────────────────┐
│ vl CLI   (clap grammar, auto-snapshot, checkout pointer, rendering)  │
├──────────────────────────────────────────────────────────────────────┤
│ Features  workspace · commands · embargo · remote · vault            │
├──────────────────────────────────────────────────────────────────────┤
│ Graph     repo · transaction (auto-rebase) · oplog (views) · revset  │
├──────────────────────────────────────────────────────────────────────┤
│ Trees     builder (policy gate) · checkout · merge · tree/TreeView   │
├──────────────────────────────────────────────────────────────────────┤
│ Policy    policy (.veilpolicy tiers) · secrets (scanner)             │
├──────────────────────────────────────────────────────────────────────┤
│ CAS       object · store (BLAKE3, unsealing) · pack · gc             │
├──────────────────────────────────────────────────────────────────────┤
│ Crypto    crypto (VeilEnvelope) · identity (X25519) · keychain       │
├──────────────────────────────────────────────────────────────────────┤
│ VFS       StorageBackend: DiskBackend · MemoryBackend · OverlayBackend│
└──────────────────────────────────────────────────────────────────────┘
```

## 1. VFS layer

`StorageBackend` is a small synchronous trait (`read`, `read_range`, `write`,
`create_new`, `list_dir`, `metadata`, `remove_*`, `set_executable`, plus an
optional `known_id` hint). The trait takes `&self`, so a backend can be
shared as `Arc<dyn StorageBackend>`.

* **DiskBackend** does atomic writes (temp file plus rename) and ignores
  symlinks.
* **MemoryBackend** is a flat `BTreeMap<VPath, Node>`. Because the
  descendants of `a/` are contiguous in string order, directory listings are
  range scans. File buffers are `Arc`-shared.
* **OverlayBackend** is copy-on-write. An in-memory upper layer and a
  whiteout set sit over any read-only lower layer. Ancestor whiteouts hide
  whole subtrees.
* **TreeView** (in `tree.rs`) is a lazy, read-only backend over a snapshot
  tree. It only loads and decrypts the nodes that are actually read.

The same `.veil/` layout lives on any backend. A repository, its working
copy, a remote and an agent sandbox are all just backends. The repository
lock is also built on `create_new`, so it behaves the same on disk and in
memory.

**The `known_id` hint** is what makes ephemeral workspaces O(changes). A
`TreeView` reports the CAS id of every node. An overlay forwards the hint only
for paths with no writes or whiteouts at or below them. When a hint matches
the parent tree, the builder reuses the whole subtree without reading it. As
a safeguard, hints are disabled whenever `.veilpolicy` itself changed, so a
policy change always reclassifies everything.

## 2. Content-addressable store

```text
object      = tag || payload            id = BLAKE3(object)
veil:blob\n   raw bytes
veil:tree\n   JSON { entries: [ {name, kind, id, size, executable, visibility, fallback} ] }
veil:snap\n   JSON Snapshot
veil:seal\n   u16 scope_len | scope | nonce[24] | XChaCha20-Poly1305(ciphertext of an encoded object)
```

Objects are stored *loose* (`.veil/objects/ab/cdef…`, the canonical
encoding as-is) until `vl gc` moves them into a *pack* (§9). Lookups check
loose objects first, then packs. Either way the id is the BLAKE3 of the
canonical, uncompressed encoding, and `get_raw` / `put_raw` always return and
accept that encoding, so sync and fsck never see compression.

Sealed objects describe themselves: the envelope names the scope that opens
it. `ObjectStore::open` peels sealed layers using the keychain. A missing key
and a wrong key both surface as `Redacted`. A missing object surfaces as
`Missing`. Callers treat both as "exists, but not for you".

**Deterministic sealing.** The nonce is
`BLAKE3-keyed(derive(key), scope ‖ 0 ‖ plaintext)[..24]` (SIV-style).
Re-snapshotting an unchanged cloaked file therefore gives the same id. That
means deduplication and no-op snapshots still work for encrypted content. The
cost is that equal plaintexts under the same scope are linkable, the same
trade-off convergent-encryption backups make. Descriptions and wrapped keys
use random nonces.

## 3. Identities, scopes and the keychain

* An **identity** is an X25519 keypair, stored outside the repository
  (`$VEIL_HOME/identity.json`, mode 0600). Its public form is `veil1<hex>`.
* A **scope** (`team`, `ops`, …) is a random 256-bit key. Its **key ring**
  (`.veil/meta/keyrings/<scope>.json`) holds the key wrapped to each
  member's public key with an ECIES-style sealed box: an ephemeral X25519 key,
  a BLAKE3 key-derivation step, then XChaCha20-Poly1305 with AAD
  `wrap:<scope>`. Rings are safe to publish and travel with every push and
  pull. Each ring carries a key fingerprint, so two independently created
  scopes with the same name are never merged.
* The **`local` scope** key is derived from the identity secret and the
  repository id. It is never stored and protects only device-local state:
  the vault.

## 4. Visibility policy, and where it is enforced

| Tier | In the snapshot graph? | Synced to team remote | Synced to public remote |
|---|---|---|---|
| `public` | plaintext | ✓ | ✓ |
| `cloak <scope>` | ciphertext | ✓ (ciphertext) | ✗ withheld (entry kept, redacted) |
| `isolate` | **never** | ✗ | ✗ |
| `ignore` | never | ✗ | ✗ |
| embargoed (merge) | ciphertext + plaintext fallback | ✓ | fallback only until release |

The **builder** (`builder.rs`) is the single point where content enters the
CAS, and it applies these rules in order:

1. Ignored paths are skipped.
2. Isolated paths, including the built-in secret rules (`.env`, `.env.*`,
   `*.pem`, `*.key`, SSH private keys, `*.tfstate`, …), are reported back and
   never hashed into the store. A user's plain `public` rule cannot override a
   built-in secret. `cloak` can (the file is shared encrypted), and so can an
   explicit `public!`.
3. Public files are scanned for credentials (AWS, GitHub, GitLab, Slack,
   Stripe, Anthropic, OpenAI, Google, JWT, private keys, and high-entropy
   `password = "…"` assignments). A hit **quarantines** the file: it stays
   local and is not snapshotted.
4. Cloaked files are sealed under their scope. In a cloaked workspace, every
   public file is sealed under the workspace scope, and the description is too.
5. Embargoed entries stay embargoed until their embargo is released.
6. Entries this reader cannot materialise (no key, or withheld by a public
   remote) are **carried over** instead of being treated as deletions. A
   partial view can never accidentally delete hidden content.

Local-only files (isolated and quarantined) are backed up into the vault, so
`vl ws exec --with-isolated` can inject `.env` into a sandbox without it ever
touching history.

## 5. The snapshot graph

```rust
struct Snapshot {
    parents: Vec<ObjectId>, change_id: ChangeId, tree: ObjectId,
    description: Text /* Plain | Sealed */, author, timestamp,
    predecessors: Vec<ObjectId>,   // evolution log
    conflicts: Vec<String>,        // paths with unresolved markers
    cloak: Option<String>,         // cloaked line of work
    embargo: Option<String>,       // embargo introduced here
}
```

* **There is a universal root** (all-zero change id, empty tree, timestamp 0),
  so every repository shares it and unrelated histories can be exchanged.
* **Change ids** are 128-bit random values, shown in reverse-hex (`z…k`) so
  they never look like snapshot ids. They survive amend, describe, rebase and
  squash.
* **The working copy is a snapshot.** Every `vl` command first runs
  `snapshot_workspace`, which builds a tree from the working copy. If the
  tree changed, it *rewrites* the working-copy snapshot: same change id, new
  tree, predecessor recorded. No index, no `add`.
* **Views and the operation log.** A `View` holds the visible heads,
  workspaces (`name → working copy`), tags and remote tags. Every transaction
  writes one `Operation { parents, user, time, description, view }`. Undo and
  `op restore` simply reinstate an older view, and then the CLI checks out
  the difference.
* **Transactions auto-rebase.** Rewrites and abandons go into a
  `rewritten` map. On commit, every visible descendant is rebased in
  topological order with a 3-way tree merge
  (`base = old parent tree, ours = new parent tree, theirs = child tree`).
  Tags and workspaces are then re-pointed, and an abandoned working copy gets
  a fresh empty change. Empty, undescribed working-copy changes you move away
  from are abandoned automatically.
* **Merging** is tree-level. Identical subtrees resolve by id, and files
  changed on both sides go through diff3 (`diffy`). Conflicts are written as
  markers and recorded on the snapshot until the file is edited. Visibility
  is preserved, and merges re-normalise visibility against the destination
  policy.

## 6. Workspaces

A workspace is only a named pointer in the view. It owns no directory.

* The **project directory** is attached to one workspace at a time.
  `.veil/local/checkout.json` records which workspace and which snapshot were
  last materialised, which gives *stale working copy* detection. If the view
  moved underneath the directory (an undo, another process, an interrupted
  command), any local edits are saved as their own change before catching up.
  Nothing is lost.
* **Virtual workspaces** (`vl ws new`) exist only in the DAG. They are edited
  through overlays (`vl ws write`), materialised into a throwaway directory
  for one command (`vl ws exec`), or attached to the project directory
  (`vl ws switch`). Two tasks can never fight over a directory.
* **Ephemeral workspaces** (`Repo::ephemeral_workspace`) are an
  `OverlayBackend` over a `TreeView`. Creating one is O(1) and committing one
  is O(changes). They never touch disk and are dropped afterwards. This is
  the primitive for agent sandboxes and parallel CI tasks.

## 7. Delayed-visibility (embargoed) merges

`vl merge X --embargo [--until T] [--scope S]`:

1. Creates an embargo record holding a fresh key, wrapped under scope `S`,
   plus an optional deadline.
2. Builds the merged tree. Then every file that differs from the first parent
   is sealed under `embargo/<id>`, with the first parent's version kept as
   that entry's `fallback`.
3. Readers without the key (a public mirror, non-members) see the main line
   exactly as it was before the merge. Members see the merge.
4. **Release** (manual, or automatic on the first `vl` run by a key holder
   after the deadline) publishes the key in the record. Snapshot ids do not
   change, nothing is rewritten, and the next push carries the
   now-releasable objects.

## 8. Synchronisation

`remote::push` and `remote::pull` work between any two backends. Filtering
happens *during the object walk*: a public remote never receives sealed
objects except those of released embargoes, never receives cloaked tags, and
nothing is ever transferred under the `local` scope. Isolated content cannot
be pushed at all, because it was never in the graph. Key rings and embargo
records are merged as unions; a released key wins. Tags fast-forward. A
diverged tag is reported and left alone (`--force` overrides on push).

## 9. Storage: packfiles, caches and garbage collection

### Pack format

A pack is two files in `.veil/objects/pack/`, both named after the BLAKE3
checksum of the pack data. All integers are little-endian.

```text
pack-<sum>.pack   "VEILPAK1" | count u32 | entry* | BLAKE3(all preceding bytes)
  entry           kind u8 | raw_len u64 | [base id: 32 bytes, deltas only] | data
    0 stored      data = canonical encoding (sealed objects, incompressible data)
    1 zstd        data = zstd frame of the canonical encoding
    2 delta       data = zstd frame compressed with the canonical encoding of
                  `base` (in the same pack) as a raw-content dictionary

pack-<sum>.idx    "VEILIDX1" | count u32 | fanout[256] u32 | ids[count] (sorted)
                  | offsets[count] u64 | lengths[count] u64 | pack sum | BLAKE3(all preceding bytes)
```

* **Lookup.** `fanout[b]` counts ids whose first byte is `<= b`. A lookup
  is one fan-out step, then a binary search over one bucket, then a ranged
  read (`StorageBackend::read_range`) of one entry. A process that reads a
  pack often (more than 64 entries; packs up to 256 MiB) loads it into memory
  once instead.
* **Deltas.** A zstd frame "compressed against" the base object as a
  dictionary is a compact delta with no extra code. GC groups objects by the
  path where it found them (files and directories separately), newest version
  first, and tries each version against the previous one. A delta is kept
  only if it beats plain zstd by more than an eighth. Chains are at most 10
  deep, so recent versions are cheap to read and old ones are deltas. Bases
  met while reading go into a bounded cache.
* **Sealed objects** are stored as they are: ciphertext does not compress,
  and deltas between ciphertexts never help.
* **Integrity.** Opening a pack checks the index checksum, that the index
  names this pack, the pack header and trailer, and that every entry lies
  inside the file. Every object read is decompressed and **re-hashed against
  its id**, so a flipped bit, a truncated file or a wrong base surfaces as
  `Corrupt`, never as wrong content. If a pack cannot be opened, lookups
  that miss report `Corrupt` rather than `Missing`, because "missing" means
  "redacted" to the rest of the engine. `ObjectStore::verify_packs` does a
  full check, and `gc` refuses to run on a store with a broken pack.
* **Atomic publication.** The `.pack` is written before its `.idx`, and
  readers find packs only through `.idx` files. Old packs are removed index
  first. A reader whose pack disappears (a concurrent gc replaced it)
  rescans the pack directory and retries.

### Caches

`ObjectStore` keeps decoded trees, snapshots and decompressed delta bases in
weight-bounded LRU caches (`cache.rs`). A tree weighs `entries + 1`, a
snapshot 1, a base its size in bytes. The defaults are 200k tree entries,
20k snapshots and 64 MiB of bases, adjustable with
`ObjectStore::set_cache_limits`.

### Garbage collection (`vl gc`)

`gc` holds the repository lock (`RepoLock`) for its whole run and works in
this order:

1. **Inventory.** List every loose and packed object *before* looking at
   reachability. Objects written after this point, for example by a `vl`
   process that is building a snapshot and waiting for the lock, are not in
   the inventory, so gc never touches them.
2. **Op-log pruning** (`--keep-ops-days N`, off by default). Delete
   operations older than the window. The current operation and its parents
   are always kept, so `vl undo` works and can itself be undone. `op log`
   and op-id prefixes end where the log was pruned.
3. **Mark.** The roots are the views of every retained operation (heads,
   workspaces, tags, remote tags), the universal root, the project
   directory's checkout pointer (`.veil/local/checkout.json`; the CLI diffs
   the working copy against it), and keep markers. From there gc walks
   snapshot → parents and tree, tree → entries, and file entry → object and
   embargo `fallback`. An embargoed entry's pre-merge content is therefore
   kept even after the fallback becomes its only reference. Snapshot
   `predecessors` (the evolution log) are weak references, as they already
   are for sync: `vl evolog` stops where history was collected.
4. **Grace period, two phases.** An unreachable object is first recorded in
   `objects/gc/pending` with the time gc first saw it unreachable. A later
   gc deletes it only if it is still unreachable after `--grace-minutes`
   (default 60). `--prune-now` sets the grace period to zero.
5. **Freshening.** Any process that touches a pending object through `has`,
   `get_raw`, `put` or `put_raw` writes a keep marker
   `objects/gc/keep/<id>` and then makes sure a loose copy exists, in that
   order. Markers are roots for the next gc, and a kept object's grace period
   restarts. Each loose object gc deletes goes through three steps: read it,
   delete it, then check for a marker; if a marker appeared, gc restores it.
   Packed garbage needs no such step: the freshening process has its own
   loose copy. So a process that starts using an object in the middle of a
   gc keeps it, unless that process runs longer than the grace period.
6. **Repack.** Write one new pack with everything kept: reachable objects
   plus pending ones. Then delete the pruned ops, the now-packed loose files
   and the old packs, and finally write the new pending list.
7. **Refuse to guess.** If any operation, snapshot or tree on the way cannot
   be read (missing, corrupt, or sealed without a key), gc still packs but
   deletes nothing, and reports why.

Benchmark (`cargo test --release -p veil-core --test storage_bench --
--ignored --nocapture`): 3,000 source files, 300 commits and 30 abandoned
experiments, about 8,000 objects. They take 36.5 MiB loose and 3.2 MiB after
`vl gc` (8.5 MiB without deltas), or 2.6 MiB once the experiments are
pruned. Reading every object costs about 2.3 µs each loose and 6.5 µs each
packed, with a warm page cache. The packed cost is zstd decompression, the
BLAKE3 verification that loose reads skip, and the loose-first probe.

## Threat model (MVP)

**Protected against:**

* accidental commits of secrets (engine rules plus the scanner, with no ignore
  file to forget);
* leaking cloaked content or names of cloaked tags to public remotes;
* readers of a team remote who are not in a scope (they get ciphertext only);
* pre-release disclosure of embargoed changes to non-members;
* tampering with ciphertext or moving it between scopes (AEAD bound to the
  scope).

**Not protected against (yet), and documented honestly:**

* *File names, sizes and tree shape* of cloaked files are visible. The object
  format can already seal trees; the policy hook for that is still to come.
* *Equality leakage* from deterministic sealing (see §2).
* *Revocation* does not re-encrypt history; rotate secrets after revoking.
* *Time-based embargo release* relies on key holders' engines and is not
  time-lock cryptography.
* Content committed in plaintext **before** a path was cloaked stays readable
  in those older snapshots. `vl cloak` warns when this applies.

## Limitations and roadmap

* Network transport: remotes are paths to other repositories (any
  `StorageBackend`). Next is an HTTP/QUIC object protocol with
  have/want negotiation.
* Performance: a stat cache (mtime and size → entry) for `DiskBackend`
  snapshots, and incremental push instead of a full graph walk. `gc`
  always rewrites everything into one pack, built in memory; incremental
  packing (small packs merged geometrically), streaming pack writes and
  cross-pack deltas are next. Sync sends canonical objects, not packs.
* Sealed directory nodes (hide names), scope key rotation, and per-snapshot
  signatures with the identity key.
* First-class conflicts (jj-style) instead of conflict markers.
* Front-ends: a FUSE mount of `TreeView` plus overlay for zero-copy
  checkouts, and a WASM build of `veil-core` with `MemoryBackend`.
* Symlink support in `DiskBackend`.
