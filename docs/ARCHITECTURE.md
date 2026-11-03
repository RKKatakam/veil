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
│ CAS       object · store (BLAKE3, transparent unsealing)             │
├──────────────────────────────────────────────────────────────────────┤
│ Crypto    crypto (VeilEnvelope) · identity (X25519) · keychain       │
├──────────────────────────────────────────────────────────────────────┤
│ VFS       StorageBackend: DiskBackend · MemoryBackend · OverlayBackend│
└──────────────────────────────────────────────────────────────────────┘
```

## 1. VFS layer

`StorageBackend` is a small synchronous trait (`read`, `write`,
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
  snapshots, packfiles with zstd, and incremental push instead of a full
  graph walk.
* Sealed directory nodes (hide names), scope key rotation, and per-snapshot
  signatures with the identity key.
* First-class conflicts (jj-style) instead of conflict markers.
* Front-ends: a FUSE mount of `TreeView` plus overlay for zero-copy
  checkouts, and a WASM build of `veil-core` with `MemoryBackend`.
* Symlink support in `DiskBackend`.
