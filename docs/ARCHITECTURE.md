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
│ Crypto    crypto (VeilEnvelope) · identity (X/Ed25519) · keychain    │
├──────────────────────────────────────────────────────────────────────┤
│ VFS       StorageBackend: DiskBackend · MemoryBackend · OverlayBackend│
└──────────────────────────────────────────────────────────────────────┘
```

## 1. VFS layer

`StorageBackend` is a small synchronous trait (`read`, `read_range`, `write`,
`create_new`, `list_dir`, `metadata`, `remove_*`, `set_executable`, plus an
optional `known_id` hint and an optional `stat_clock`). The trait takes
`&self`, so a backend can be shared as `Arc<dyn StorageBackend>`.

`Metadata` carries change-detection stamps next to kind, size and the
executable bit: `mtime`, `ctime` and `inode`, each `Option`al. `None`
means "unknown, always re-read". `stat_clock()` returns the current reading
of the clock those stamps are measured on, or `None` if the backend's stamps
must not be trusted (which disables stat caching):

| Backend | `mtime` / `ctime` / `inode` | `stat_clock` |
|---|---|---|
| `DiskBackend` | ns since the epoch / ns / inode number (Unix; mtime only elsewhere) | wall clock, ns, `exact: false` |
| `MemoryBackend` | per-backend write-generation counter / – / – | current generation, `exact: true` |
| `OverlayBackend`, `TreeView` | – (mixed or immutable sources) | `None` (they use `known_id`) |

* **DiskBackend** does atomic, durable writes (temp file, fsync, rename,
  fsync of the directory; see §9) and ignores symlinks.
* **MemoryBackend** is a flat `BTreeMap<VPath, Node>`. Because the
  descendants of `a/` are contiguous in string order, directory listings are
  range scans. File buffers are `Arc`-shared. Every file write takes a fresh
  value from a monotonic generation counter, reported as `mtime`.
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
encoding as-is) until `vl gc` moves them into a *pack* (§10). Lookups check
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

### Identities

* An **identity** is one 32-byte secret, stored outside the repository
  (`$VEIL_HOME/identity.json`, mode 0600). Two keypairs come from it:
  * **X25519** (the secret itself) for receiving wrapped scope keys. Its
    public key `veil1<hex64>` is the **member id**.
  * **Ed25519** for signing. The seed is
    `BLAKE3-derive("veil 2026 ed25519-seed v1", secret)`, so identity files
    written before signatures existed load unchanged and get a stable
    signing key.
* The **full public identity** is `veil1<x25519-hex><ed25519-hex>` (128 hex
  digits). `vl identity show` prints it, and `vl scope grant` should be
  given it. A grant made with the short member id still works for
  decryption, but the ring cannot bind a signing key to that member: their
  signatures show as "unknown key" and they cannot be an effective admin.
* Secrets in memory are wrapped in `zeroize::Zeroizing`: the identity secret,
  the derived signing seed, key-encryption keys, unwrapped scope and embargo
  keys, and the keychain's key cache. Keys returned by value (`Key` is
  `Copy`) are not tracked.

### Scopes, key generations and envelope labels

* A **scope** (`team`, `ops`, …) is a sequence of random 256-bit keys called
  **generations**. Generation 0 is created with the scope. Every revocation
  (and every `vl scope rotate`) starts generation *n+1* with a fresh key,
  wrapped only to the members that remain.
* Each key has a public **key id** (`BLAKE3-derive("…key-fingerprint v1",
  key)[..8]`). A sealed object names its generation in its envelope label:
  `team#<key-id>`. A bare `team` label means generation 0. Every envelope
  written before generations existed has a bare label, so those still open.
  The label is the AEAD associated data, so a generation cannot be swapped
  without detection. The binary `Envelope` format did not change.
* New content is always sealed under the **current** generation
  (`Keychain::sealing_key`). Unchanged cloaked files keep their existing
  sealing when re-snapshotted, so a rotation does not rewrite the working
  copy. Content that changes after a revocation moves to the new generation.
* **History stays readable for members.** Each rotation carries the previous
  generation's key sealed under the new key (`previous`). Anyone holding the
  newest key can walk back through every older generation, which includes
  members granted after the rotation. A revoked member keeps the keys they
  were given up to the revocation. Those keys were already in their hands,
  so nothing is lost by keeping them. They never receive a later key.
* The **`local` scope** key is derived from the identity secret and the
  repository id. It is never stored and protects only device-local state:
  the vault.

### Key rings: a signed membership log

`.veil/meta/keyrings/<scope>.json` (format 2) holds only a **log**: an
append-only, hash-chained list of signed changes.

```text
RingChange { seq, prev, timestamp, signer, signing_key, op, signature }
op = Genesis { key_id, members[], proof }      seq 0 only
   | Grant   { member }                        add, or change name/role/signing key
   | Revoke  { member, rotation }              remove + new generation
   | Rotate  { rotation }                      new generation, same members
member   = { id, name, signing_key?, role: admin|member, generation, wrapped }
rotation = { generation, key_id, previous: [{key_id, sealed}], wrapped: {id → key} }
```

* `seq` is the ring's **epoch**: the change's position in the log. `prev` is
  the chain hash of the previous change: a BLAKE3 hash in derive-key mode
  over the signing body plus the signature. The signature is Ed25519 over a
  domain-separated encoding of
  `(scope, seq, prev, timestamp, signer, signing_key, op)`. Because `scope`
  is in the signed body, a change cannot be moved to another scope's ring.
* **Authorisation.** The state (members, roles, generations) is *derived* by
  replaying the log. Nothing in the file is trusted unless the replay
  verifies:
  * the genesis must be signed by one of the admins it creates;
  * every later change must be signed with the *registered* signing key of a
    member who is an **admin at that point of the log**;
  * a grant must wrap the current generation;
  * a rotation must be generation *n+1*, use a fresh key id, carry the
    previous key, and wrap the new key to **exactly** the remaining members
    (so a revoked member cannot be smuggled into the new generation);
  * the last admin can be neither revoked nor demoted.

  A ring that fails to verify gives no keys at all.
* **Genesis proof.** The genesis carries a MAC, made with the generation-0
  key, over `(scope, key_id, signer, signing_key)`. Every reader who can
  unwrap generation 0 checks it, along with each rotation's `previous` chain.
  This stops someone who does not know the key from creating a "genesis"
  that claims an existing scope's key id. For example, they cannot copy the
  real wrapped keys and name themselves admin.
* **Roles.** The creator of a scope is its admin. `vl scope grant` adds
  members (`--admin` adds admins). Only admins may grant, revoke or rotate.
  Plain members can read and write content.
* **Which change wins: fast-forward only.** When rings meet during push or
  pull (`Keychain::merge_ring`):
  1. An incoming ring that does not verify is **rejected**, with a warning.
  2. If the local log is a prefix of the incoming log, the incoming ring is
     taken (fast-forward).
  3. If the incoming log is a prefix of the local log, it is a stale or
     replayed ring and is **ignored**.
  4. If the logs have diverged (concurrent admin edits, or a fork made by a
     since-revoked admin), the **local ring is kept**. A warning lists the
     changes that were not applied, and an admin re-applies them by hand.

  Membership is never merged as a union. So
  `revoke → push → pull from a replica that still lists the member` leaves
  the member revoked, in both directions. A stale replica's ring is a prefix
  of the new one, so it can neither overwrite the remote nor survive a pull.
* **Legacy rings.** Format-1 rings (an unsigned `members` map plus `key_id`)
  still load and decrypt. They upgrade to a signed log the first time a
  member grants, revokes, rotates or creates an embargo: that member becomes
  admin, and the other legacy members keep their wrapped generation-0 keys.
  An unsigned ring never overrides a signed one, and two different legacy
  rings are not merged (the local one is kept).

### Signatures

| Object | What is signed | Checked |
|---|---|---|
| ring change | its body (above) | on every load; rejected on pull if invalid |
| embargo record | `(id, scope, wrapped, until, created, description, scope_key, key_id)` | on pull; signer must be (or have been) a member of the scope |
| embargo release | `(id, released_key, released_at)`; the key must also match the committed `key_id` fingerprint | on pull and on every key lookup |
| snapshot | its **unsigned id** (BLAKE3 of the encoding without `signature`) | shown by `vl log` / `vl show`; invalid ones reported on pull |

* **Snapshot signatures and content ids.** `Snapshot.signature` is part of
  the encoding, so the snapshot id commits to it. The signed value is the id
  the snapshot would have *without* the signature. Two consequences follow:
  * Stripping or swapping a signature produces a different object, and
    children (which name their parents by id) no longer point at it.
  * Ed25519 signing is deterministic, so a no-op re-snapshot keeps its id.
* **Author vs. signer.** `author` is a claimed name. The **signer** is
  whoever *produced this exact snapshot*. `Transaction` signs every snapshot
  it writes. That includes the auto-rebase: when Bob's rewrite rebases
  Alice's change, the result keeps `author: alice`, is signed by Bob, and
  its `predecessors` names Alice's original, which still carries her
  signature (`vl evolog`). `vl show` reports this as "signed by bob
  (rewritten; author alice)". A rewrite whose content (ignoring the
  signature) is identical keeps the original snapshot and its signer.
* **Status.** Each signature has one of these statuses:
  * `good`: valid, by a signing key that some ring binds to the claimed
    member;
  * `unknown`: valid, but the key is unknown, or it does not belong to the
    claimed member;
  * `bad`: does not verify;
  * `unsigned`.

  `vl log` marks each snapshot with `✓`, `✓<signer>`, `?signer`,
  `✗bad-signature` or `unsigned`.
* **Embargo deadlines.** Only a record whose creation signature is `good`
  can trigger an automatic release. If a record arrives with a tampered
  deadline, its signature fails and the pull rejects it. An attacker can
  also strip the signature: the record is then accepted only as "unsigned",
  and an unsigned record is never auto-released. This matters because a key
  holder's engine would otherwise publish the key early. If the local
  record differs from an incoming one in any signed field, the local record
  is kept.

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
   `password = "…"` assignments). A hit **quarantines** the file: the
   offending content stays local and is not snapshotted.
   * A **never-tracked** file is left out of the tree.
   * A **tracked** file keeps the parent's entry, so history still holds
     the previous, safe version. The edit is *held back*, not recorded as a
     deletion (`BuildReport::quarantine_kept`; `vl status` shows
     `Q path (rule; edit held back; history keeps the previous version)`).
     The previous entry is only kept if it is itself safe. Encrypted
     entries always are. A public one is re-scanned, because it may date from
     a `public!` rule that has since been removed. If it fails, the file is
     dropped from the new snapshot as before.
   * Unchanged public content is normally not re-scanned ("scanned when it
     entered the parent"). That shortcut is disabled whenever `.veilpolicy`
     differs from the parent's, so dropping `public!` re-checks everything.
   * **Checkout never overwrites or removes local content it did not
     materialise.** A path in the diff is only written or deleted if the file
     currently holds exactly the `from` version (checked through the stat
     cache, or by reading it). Anything else, above all a quarantined edit,
     is left in place and reported as `kept`. The next snapshot quarantines
     it again on top of the new tree. `vl restore <path>` deliberately
     discards a quarantined edit.
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

### The stat cache

Every `vl` command snapshots the project directory. Without help that means
reading and hashing every file. The stat cache (`statcache.rs`) avoids it.
The CLI keeps one per workspace as device-local state in
`.veil/local/statcache/<workspace>.cache`. It is loaded once per session, used
by every snapshot and checkout (`snapshot_workspace_cached`,
`build_from_cached`, `checkout_tree_cached`), and rewritten only when it
changed. The in-memory cache follows the directory when another workspace is
attached.

* **Records are content facts, not policy decisions.** Each record holds
  path → stamp (mtime, ctime, inode, size, executable), the blob id of the
  plaintext, whether the scanner found it clean, and (for cloaked files)
  which object it seals to under which scope. The builder still classifies
  every path against the current policy every time. A fact is only used where
  the builder would otherwise need the bytes: a public file reuses the
  parent's entry, or the cached blob if it was scanned clean; a cloaked file
  reuses the cached sealed id for the same scope. Embargoed entries, cloak
  failures and quarantined files are never served from the cache.
* **Keyed on policy and keys.** As defence in depth the whole cache is
  dropped when the `.veilpolicy` blob id changes, or when a fingerprint of
  the identity, every scope's key fingerprint and every embargo's
  released/readable state changes.
* **Racy mtime.** Each record stores `verified_at`, the clock reading taken
  before the build stat'ed and read the file. A record is trusted only if
  `max(mtime, ctime) + window ≤ verified_at`. The window is 2 s for
  whole-second stamps (ext3, HFS+, FAT, many network filesystems) and 100 ms
  for sub-second stamps (the kernel's coarse clock, exFAT's 10 ms). On a
  generation clock it is 0. A file written in the same tick it was verified
  is therefore re-read on the next run, which records a later `verified_at`.
  A file with a future stamp is never trusted.
* **Checkout invalidates** every path it writes or removes. It does not
  insert records for what it wrote: through the generic backend API it
  cannot stat *the* file it wrote, so a concurrent edit between the write and
  the stat would be recorded under the checked-out content. Written files are
  re-read once by the next snapshot instead.
* The cache is binary with a trailing BLAKE3 checksum. A missing, corrupt or
  foreign-version cache is just empty. It only accelerates; failing to save
  it is a warning.
* Two further cheap wins make the cached path fast. Unchanged directories
  reuse the parent's tree id instead of re-encoding, re-hashing and
  re-checking it. `Policy` matches all rules with one `GlobSet` instead of
  two matchers per rule.

`vl status` on a clean 20,000-file working copy (1,000 cloaked, 500 ignored;
ext4, warm page cache, release build) went from about 145 ms to about
55 ms. After a one-file edit it went from about 150 ms to about 74 ms.
What remains is mostly the one `lstat` per file and the per-directory
`readdir`, plus decoding the parent's ~1,200 tree objects (JSON). Run the
benchmark with
`cargo test --release -p vl --test bench_status -- --ignored --nocapture`.

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
be pushed at all, because it was never in the graph. Key rings are signed
logs that only fast-forward (§3). Stale, tampered or forged rings are
ignored or rejected with a warning, and membership is never merged as a
union. Embargo records are accepted only if signed by a scope member, or as
flagged legacy records. A release is accepted only if the published key
matches the committed fingerprint. Snapshots whose signature fails to verify
are reported. Tags fast-forward. A diverged tag is reported and left alone
(`--force` overrides on push).

## 9. Locking, crash safety and `fsck`

**The repository lock** (`lock.rs`) is the file `.veil/lock`, created with
`create_new`, so it behaves the same on every backend. It holds JSON: a random
per-acquisition token, the holder's pid, host name, boot identity (Linux boot
id plus pid namespace) and a lease (10 s by default).

* While a `RepoLock` lives, a heartbeat thread renews the lease every 2.5 s.
  However long a transaction runs, its lock never looks stale. (The MVP stole
  any lock older than 120 s, even from a live process.)
* A contender removes someone else's lock only when the lease has expired
  **and** the holder is provably gone. That means either the same machine
  (same host, boot id and pid namespace) with a pid that no longer runs, or a
  lease last renewed before this machine booted. A holder on another host,
  or a live process that stopped renewing (suspended, stuck), is never robbed.
  The contender times out with an error naming the holder.
* Each process keeps a registry of the tokens its live locks hold. A lock
  file with this process's pid and an unregistered token was leaked, for
  example by a crash that prevented the file from being removed. It is
  reclaimed immediately.
* Steals are serialised through `.veil/lock.steal` (also `create_new`).
  Under that guard, the stealer re-reads the lock and removes it only if it
  still has the exact bytes that were judged stale. Two stealers can never
  both win.
* Fencing: before moving `op_head`, a transaction checks that the lock still
  carries its token (`RepoLock::ensure_held`).
* On disk, `create_new` writes the content to a synced temp file and
  hard-links it into place. A contender therefore never sees a half-written
  lock. Unparseable content (left by older versions or a non-atomic fallback)
  is reclaimed only after it stays unchanged for a full lease.

**Crash ordering.** Every transaction writes in this order: objects (the
snapshot, trees and blobs it references), then the operation, then
`op_head`. Pull and push copy objects and shared metadata (key rings,
embargo records) before the transaction that references them. `init` writes
`repo.json` last, because it is what makes a directory a repository.
`DiskBackend::write` and `create_new` return only once the data is durable:
the file is fsynced, renamed, and its directory fsynced, and new directories
are synced into their parents. So the program order of writes is also their
durability order. After a crash at any point, `op_head` names a complete
operation whose view references only complete objects. The worst leftovers
are unreachable objects, an operation that never became the head, temp files
and a lock that will be reclaimed. Undo is unaffected.

The cost is a few fsyncs per object written. A batched barrier (sync every
touched directory once before writing the operation) is the obvious
optimisation once packs land.

**`vl fsck`** (`fsck.rs`) is read-only and works without `Repo::open`, so it
can diagnose a damaged `op_head`. It re-hashes and decodes every object,
including unreachable ones, and opens sealed objects it holds keys for. It
walks reachability from the current view and from every retained operation:
snapshot → parents and tree, tree → entries and embargo fallbacks. It
rejects tree entry names such as `..`, and checks that key rings and embargo
records parse and are filed under their own names. It also checks that every
operation matches its id, that every parent exists, and that the head points
at a real operation. A missing object is classified by the visibility of the
entry that references it:

| finding | meaning | exit code |
|---|---|---|
| corrupt | hash mismatch, undecodable, missing public file / tree / snapshot / op parent, broken metadata | 1 |
| warning | sealed under an unexpected scope, embargo without a record, missing embargo fallback | 0 |
| redacted (expected) | cloaked or embargoed content absent, e.g. in a clone of a public remote | 0 |
| note | leftovers of interrupted commands: dangling operations, unreachable objects, temp files, a lock | 0 |

**Crash-injection tests** (`crates/veil-core/tests/crash.rs`). A
`FaultyBackend` wraps `MemoryBackend` and fails the N+1-th mutation and every
later one, with the fatal write either lost or applied. For snapshot, commit,
rebase, merge, embargoed merge, push, public push, pull and init, the tests
sweep every N. After each crash the repository must open and pass `fsck`.
The operation must appear either not at all or exactly once on top of the old
head. Every previously visible snapshot must keep identical content. Running
the operation again must succeed, which also exercises reclaiming the crashed
process's lock.

## 10. Storage: packfiles, caches and garbage collection

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

## Threat model

**Protected against:**

* accidental commits of secrets (engine rules plus the scanner, with no ignore
  file to forget);
* leaking cloaked content or names of cloaked tags to public remotes;
* readers of a team remote who are not in a scope (they get ciphertext only);
* pre-release disclosure of embargoed changes to non-members;
* tampering with ciphertext or moving it between scopes or key generations
  (AEAD bound to the envelope label);
* **revoked members reading new content.** Revocation rotates the scope key,
  and the revoked identity never receives the new generation;
* **resurrecting a revoked member by syncing.** Rings fast-forward, so stale
  replicas and replayed old rings are ignored;
* **tampered or forged rings.** Every change must be signed by an admin
  authorised at that point of the log. Reordering, removing or editing a
  change breaks the hash chain or the signature. A forged genesis that
  claims an existing key fails the genesis proof for every key holder;
* **forged or tampered embargo records.** A moved deadline, a changed scope
  or a wrong published key is rejected. Unsigned records never auto-release;
* **stripped or transplanted snapshot signatures.** The id commits to the
  signature, and a transplant fails verification. Both show in `vl log`.

**Not protected against (yet), and documented honestly:**

* *File names, sizes and tree shape* of cloaked files are visible. The object
  format can already seal trees; the policy hook for that is still to come.
* *Equality leakage* from deterministic sealing (see §2).
* *Revocation is forward-only.* A revoked member keeps every key up to the
  revocation, and with it all history sealed before it (including unchanged
  files that are still sealed under an old generation). They also keep
  anything they already decrypted. Rotate the underlying secrets.
* *First contact is trust-on-first-use.* A fresh clone accepts the first
  valid ring it sees. A malicious remote can serve a **fork** created by an
  admin who was revoked later: the fork is valid at its fork point. Also, a
  remote can withhold newer changes (a freshness or rollback attack against
  replicas that never saw them). Replicas that already hold the newer log
  reject both. Out-of-band pinning of the ring head is future work.
* *Concurrent admin edits are not merged automatically.* Diverged logs keep
  the local ring and warn, and an admin re-applies the missing changes.
* *Snapshot signatures are advisory.* Unsigned and unknown-key snapshots are
  shown but not rejected, and there is no "require signed" policy yet.
  `author` is a free-form claim; only the signer is authenticated.
* *Members granted by short member id* (without a signing key) cannot sign
  ring changes, and their snapshot signatures show as unknown.
* *Rings on a non-member remote* (for example a bare remote without an
  identity) cannot check the genesis proof. Members check it when they pull.
* *Time-based embargo release* relies on key holders' engines and is not
  time-lock cryptography.
* Content committed in plaintext **before** a path was cloaked stays readable
  in those older snapshots. `vl cloak` warns when this applies.

## Limitations and roadmap

* Network transport: remotes are paths to other repositories (any
  `StorageBackend`). Next is an HTTP/QUIC object protocol with
  have/want negotiation.
* Performance: a binary tree encoding (decoding the parent's JSON trees is
  now a large share of a cached `vl status`), incremental push instead of a
  full graph walk, recording checked-out files in the stat cache (needs a
  backend write that returns the stat of the file it wrote), and batched
  fsync barriers. `gc` always rewrites everything into one pack, built in
  memory; incremental packing (small packs merged geometrically), streaming
  pack writes and cross-pack deltas are next. Sync sends canonical objects,
  not packs.
* Sealed directory nodes (hide names); a "require signed snapshots" policy;
  pinning a ring head out of band; automatic re-application of concurrent
  ring changes.
* First-class conflicts (jj-style) instead of conflict markers.
* Front-ends: a FUSE mount of `TreeView` plus overlay for zero-copy
  checkouts, and a WASM build of `veil-core` with `MemoryBackend`.
* Symlink support in `DiskBackend`.
