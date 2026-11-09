# Veil architecture

> **Sources of truth:** `docs/OVERVIEW.md` (what Veil is) and `docs/VISIBILITY.md` (who can see what). The server's design is `docs/HUB.md`. Where this document disagrees with them, they win.

**What Veil is.** Veil is a server-centric version control system. The `vl`
client is always connected to the Veil server (the Hub), which stores every
project and enforces every permission. It is not Git and not offline-first.

**Goals:**
* **The ordinary permission model:** the creator is the admin; everything
  is private by default; admins create groups, choose group managers and
  give groups or people access to folders; `public` folders are visible to
  everyone on Earth. The server enforces it on every request.
* **Code is plain text on the server.** Only secret files (`.env`, keys)
  are encrypted, and personal private keys never leave the machine.
* **Agents at scale**, on the Scion design (`docs/HUB.md` §9).
* **History you can rewrite and undo:** change ids, auto-snapshots, an
  undoable op log, workspaces and sandboxes.

**What this document describes.** The built **client engine**: the layers
below, the op log, packs, the history index, gc, embargoes, the secret
scanner, workspaces. The server's milestone S1 is built (`docs/HUB.md`
§13), and `vl` syncs only through it (§8). Today's client still restricts
paths by encrypting them for a *scope* (cloaking, §3–§4), described as
built facts; folder access on the server replaces it, and the next part of
the simplification pass removes it. Path and SFTP remotes were removed in
its first part.

Veil is built as a stack of small layers. Each layer only depends on the ones
below it, and nothing above the VFS layer knows a disk exists.

Veil does not interoperate with Git (no import, export, sync, colocation, submodules, Git file formats or Git-format patches). Owner decision, 2026-11-05: permanent.

```text
┌──────────────────────────────────────────────────────────────────────┐
│ vl CLI   (clap grammar, auto-snapshot, checkout pointer, rendering)  │
├──────────────────────────────────────────────────────────────────────┤
│ Features  workspace · commands · embargo · remote · vaults           │
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

Without the `os` feature (the WASM build, §13) the same stack runs over
`MemoryBackend`, overlays or a backend the embedder provides.

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
  fsync of the directory; see §9) and never follows a symlink. Checkout
  instead stages each file (`write_staged`: a temp file beside it,
  unsynced), makes them all durable with one barrier, renames them into
  place, and makes the names durable with a second (BUG-818). Files up
  to 256 KiB are read and staged on up to 8 threads (larger ones one at a
  time: memory stays bounded), and renamed into place on as many; a
  barrier fsyncs on up to 256 threads, so that ext4 commits them in a few
  journal transactions (performance round 2). A link is a
  leaf of its own: `NodeKind::Symlink` in `metadata` and listings, its
  target from `read_link`, created atomically by `write_link` (`symlinkat`
  to a temp name, `renameat`); `read` never reads through one. A path below
  a file is simply missing (ENOTDIR is "not found"), as on every backend.
  `list_dir_full` additionally reports what `list_dir` leaves out:
  *special* entries (sockets, FIFOs, devices, a `vl ws mount`) and names
  that are not valid UTF-8, which a `VPath` cannot represent. The builder
  warns about the latter and checkout never writes through or over the
  former (§4). **Every write, removal and read below the root** resolves
  its path with `openat(…, O_NOFOLLOW | O_DIRECTORY)` on each component,
  relative to the directory before it (`vfs::beneath`; the same walk on
  Linux and macOS): a path below a symlinked directory is refused, and a
  directory swapped for a link mid-write cannot redirect the write, which
  lands in the very directory that was checked (symlinks design, threat
  1; this replaced an `lstat` loop with a check-to-use window). Removing a
  directory empties it through descriptors opened the same way. The
  engine's own `.veil/` is written by path: it may be a link to another
  disk, and nothing from a tree is written there. `metadata` and listings
  stay plain `lstat`s (they only ever lead to such a read or write).
  `MemoryBackend`, `OverlayBackend`, `TreeView`, `SparseView` and
  `SandboxFs` hold links the same way, and a backend without them says so
  (`supports_links`), which checkout reports per link.
* **MemoryBackend** is a flat `BTreeMap<VPath, Node>`. Because the
  descendants of `a/` are contiguous in string order, directory listings are
  range scans. File buffers are `Arc`-shared. Every file write takes a fresh
  value from a monotonic generation counter, reported as `mtime`.
* **OverlayBackend** is copy-on-write. An upper layer (in memory by
  default; any backend with `OverlayBackend::with_upper`, which a `vl ws
  mount` keeps on disk) and a whiteout set sit over any read-only lower
  layer. Ancestor whiteouts hide whole subtrees. A file in the way of a
  directory is an error, exactly as on the other backends; it is never
  whited out implicitly.
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
veil:tree\n   0x02 binary entries (format 2)  |  JSON { entries: [ {name, kind, id, size, executable, visibility} ] } (format 1)
veil:snap\n   JSON Snapshot
veil:sea2\n   u16 scope_len | scope | AES-SIV(ciphertext of an encoded object)        (format 3)
veil:seal\n   u16 scope_len | scope | nonce[24] | XChaCha20-Poly1305(ciphertext)  (formats 1–2, legacy)
```

Every cryptographic construction, its standard and its limits are in
[CRYPTO.md](CRYPTO.md).

The first payload byte of a tree or snapshot is its encoding version (`{`
for JSON), and a repository writes trees in the encoding of its format
(`repo.json`): format-2 repositories write compact binary trees, format-1
repositories keep writing JSON, and every encoding is read forever. The
empty tree is always JSON, so the universal root never changes. Newer
encodings, formats and object kinds fail as `Unsupported` ("needs a newer
vl"). [FORMAT.md](FORMAT.md) inventories every persisted structure, the
evolution rules, `vl upgrade` and the compatibility fixtures.

Objects are stored *loose* (`.veil/objects/ab/cdef…`, the canonical
encoding as-is) until `vl gc` moves them into a *pack* (§10). Lookups check
loose objects first, then packs. Either way the id is the BLAKE3 of the
canonical, uncompressed encoding, and `get_raw` / `put_raw` always return and
accept that encoding, so sync and fsck never see compression.

**Everything read is verified.** Objects arrive from remotes and live in a
`.veil/` that anyone with file access can edit, so the store treats them as
hostile:

* Every read is re-hashed against its id. Loose objects are hashed by
  `ObjectStore::read_raw`, packed ones by `Pack::get`; a corrupt loose copy
  falls back to a good packed copy if there is one, and otherwise surfaces
  as `Corrupt`. Decoded trees and snapshots are cached, so they are hashed
  once per process; blobs are hashed on every read (BLAKE3 runs at several
  GiB/s, small next to I/O and decryption).
* `put` and `put_raw` re-verify an existing copy instead of trusting it, so
  a damaged object is **repaired** by putting it again, e.g. by pulling it
  from a remote that has a good copy. The cost is one read of the existing
  copy whenever an object that is already stored is put again.
* Trees are accepted only in **canonical form** (`Object::decode`): the
  exact bytes the encoder writes (`serde_json`'s output for JSON trees; the
  shortest varints and no explicit defaults for binary ones), entries
  strictly sorted by name (so unique), and every name a single safe component: not empty, `.` or `..`,
  no `/` or NUL, and never `.veil` in any ASCII case, at any depth (as Git
  refuses `.git`). The builder skips `.veil` directories at every depth for
  the same reason, and `put_tree` refuses to write a tree it could not read
  back. Checkout additionally refuses any path through `.veil`, and
  `VPath::join` asserts its component in release builds too.
* Envelope scope labels are at most 65,535 bytes (`MAX_SCOPE_LEN`); `seal`
  refuses longer ones rather than encode a truncated length.

Sealed objects describe themselves: the envelope names the scope that opens
it. `ObjectStore::open` peels sealed layers using the keychain. A missing key
and a wrong key both surface as `Redacted`. A missing object surfaces as
`Missing`. Callers treat both as "exists, but not for you".

**Deterministic sealing.** Format-3 repositories seal objects with AES-SIV
(RFC 5297, CMAC-AES-256 + CTR-AES-256 under `HKDF-SHA256(scope key)`, the
label as associated data, no nonce); formats 1–2 used, and still write, a
keyed-BLAKE3-derived XChaCha20-Poly1305 nonce (CRYPTO.md C1, C1L).
Re-snapshotting an unchanged sealed secret file therefore gives the same id. That
means deduplication and no-op snapshots still work for encrypted content. The
cost is that equal plaintexts under the same scope are linkable, the same
trade-off convergent-encryption backups make. Descriptions, sealed keys and
the vault use XChaCha20-Poly1305 with random nonces.

## 3. Identities, scopes and the keychain

> Today's client, before the server. With the server, access to folders is
> the server's permission model (`docs/VISIBILITY.md`); scopes, key rings and
> HPKE wraps are the mechanism for **secret files** only
> (`docs/HUB.md` §6, §8). Device identities stay.

### Identities

* An **identity** has two keypairs, stored outside the repository
  (`$VEIL_HOME/identity.json`, mode 0600):
  * **X25519** for receiving wrapped scope keys (HPKE, RFC 9180, in format
    3; a legacy sealed box in formats 1–2; CRYPTO.md C3, C3L). Its public
    key `veil1<hex64>` is the **member id**.
  * **Ed25519** for signing. Identities created by this release have an
    independent random seed. Older identity files derive it as
    `BLAKE3-derive("veil 2026 ed25519-seed v1", x25519_secret)`; they load
    unchanged, keep their signing key, and `vl identity show` marks them
    legacy (CRYPTO.md C4).
* The **full public identity** is `veil1<x25519-hex><ed25519-hex><binding-hex>`
  (256 hex digits): the two public keys and the **binding**, the signing
  key's signature over the X25519 key (CRYPTO.md C4). `vl identity show`
  prints it, and `vl scope grant` should be given it. The binding proves
  that the holder of the signing key chose this member id, so nobody can
  register someone else's signing key as theirs (BUG-069); a grant refuses
  a full identity without one. A grant made with the short member id still
  works for decryption, but the ring cannot bind a signing key to that
  member: their signatures show as "unknown key" and they cannot be an
  effective admin.
* Secrets in memory are wrapped in `zeroize::Zeroizing`: the identity secret,
  the derived signing seed, key-encryption keys, unwrapped scope keys, and
  the keychain's key cache. Keys returned by value (`Key` is
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
  (`Keychain::sealing_key`). Unchanged sealed secret files keep their existing
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
* **Replacing the identity** (`vl identity new --force`) changes that key.
  A vault sealed by the previous identity is never overwritten and never
  stops a command that does not need it. Snapshots skip backing up isolated
  files into it, and `vl secret`, `vl run` and `ws exec --with-isolated`
  fail with an explanation. The replaced identity is kept
  (`$VEIL_HOME/retired/`, mode 0600) so the vault can be **re-keyed**:
  `identity new --force` re-keys the vault of the repository it runs in, and
  `vl identity recover-vault [--from FILE]` re-keys any other one. Deleting
  the retired file (and the vault) is the way to really forget the old
  identity.
* **Admin rights after a replacement.** The new identity is not an admin
  of anything. `vl identity new --force` warns, before replacing it, about
  scopes of the repository it runs in where the identity is the only
  admin. `vl identity recover-admin [--from FILE] [--revoke-old]` then lets
  the retired identity sign the hand-over: a grant that makes the new
  identity an admin, in every scope of the repository where the retired
  one is an admin (and, with `--revoke-old`, a revocation of the retired
  one by the new admin, which rotates the key). BUG-089.

### Key rings: a signed membership log

`.veil/meta/keyrings/<scope>.json` (format 2) holds only a **log**: an
append-only, hash-chained list of signed changes.

```text
RingChange { seq, prev, timestamp, signer, signing_key, op, signature }
op = Genesis { key_id, members[], proof }      seq 0 only
   | Grant   { member }                        add, or change name/role/signing key
   | Revoke  { member, rotation }              remove + new generation
   | Rotate  { rotation }                      new generation, same members
member   = { id, name, signing_key?, binding?, role: admin|member, generation, wrapped }
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
    (so a revoked member cannot be smuggled into the new generation). The
    one exception: a member whose id is a low-order X25519 point, to which
    no key may be wrapped, may be left out (BUG-070);
  * a member's `binding`, if present, must be a valid signature by their
    signing key over their member id's X25519 key, and a signing key can
    belong to only one member id over the whole log (BUG-069);
  * the last admin can be neither revoked nor demoted.

  A ring that fails to verify gives no keys at all.
* **Project binding** (format 7, BUG-845). Every ring but `team` names its
  project in its signed genesis: the hash of the project's `team` ring's
  genesis. A ring naming another project gives no keys and is never taken
  (`Keychain::bound`). In a clone of a Veil server project, `team` itself is
  trusted only if its fingerprint is the one the device confirmed outside
  the server (`.veil/local/project-anchor`; `docs/HUB.md` §13.12).
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
  member grants, revokes or rotates: that member becomes
  admin, and the other legacy members keep their wrapped generation-0 keys.
  An unsigned ring never overrides a signed one, and two different legacy
  rings are not merged (the local one is kept).

### Signatures

| Object | What is signed | Checked |
|---|---|---|
| ring change | its body (above) | on every load; rejected on pull if invalid |
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
    member (if rings disagree about a key, a ring that proved the binding
    wins; otherwise the key counts as unknown);
  * `unknown`: valid, but the key is unknown, or it does not belong to the
    claimed member;
  * `bad`: does not verify;
  * `unsigned`.

  `vl log` marks each snapshot with `✓`, `✓<signer>`, `?signer`,
  `✗bad-signature` or `unsigned`.

### The team vault (`team_vault.rs`)

`vl secret … --scope S` keeps secrets for the members of a scope, as
shared metadata that syncs like rings: `.veil/meta/vault/<scope>/<id>.json`,
one **immutable record per write**.

* **Record.** Compact JSON `{format, scope, sealed, timestamp, signature}`.
  `sealed` is the entry's name *and* value (`null` for a deletion), plus
  `since` (below), as JSON padded to a multiple of 128 bytes and sealed
  with XChaCha20-Poly1305 under a random nonce. The key is the scope's
  current generation key, and the label `vault:<scope>#<key-id>` is
  authenticated (CRYPTO.md C12). `signature` is the writer's Ed25519
  signature (context `vault-entry`) over `{format, scope, sealed,
  timestamp, signer}`. The file name is BLAKE3 of the file's bytes, which
  must be the record's canonical encoding. Names are sealed, so `STRIPE_LIVE_KEY`
  is not visible to a team remote's operator.
* **What counts.** The vault is a function of (records, verified ring),
  so replicas with the same records and ring agree, whatever order the
  records arrived in. A record counts if its signature verifies, its label
  names a generation of the ring, it opens to a valid entry, and its signer
  is a **current** member whose registered signing key made the signature.
  Per name, the counting record with the greatest `(timestamp, signing key,
  record id)` wins; a winning deletion hides the name. A writer stamps
  `max(now, winner + 1)` (a Lamport bump), so a write beats everything its
  writer had pulled, whatever the clocks.
* **Compaction** deletes a record only when a newer record by the *same
  signer* for the same name exists. Whatever a later ring says about that
  signer, the newer record decides both or neither, so compaction never
  changes the vault and replicas still converge (property-tested in
  `team_vault_props.rs` against an uncompacted archive). It runs after each
  write and, for scopes the pusher can open, on the remote after a push.
* **Revocation** (`Keychain::revoke_with_vault`, used by `vl scope revoke`).
  The revoked member's records stop counting at once (not "from now on":
  their timestamps are self-asserted, so a revoked member could backdate a
  write). Entries whose winning record they wrote are re-signed by the
  revoking admin under the new generation (deletions too), so they don't
  vanish or fall back to an older value. The report lists every live entry
  they could read: `since ≤` the last generation they held. `since` is the
  generation under which that exact value was first sealed, carried over
  when the same value is written again (re-signing, re-sealing after a
  rotation), so re-signing doesn't hide an exposure but a new value does.
  `vl secret list --scope S --exposed-to M` recomputes it at any time.
  Since compaction deletes superseded records, a device also remembers, in
  `.veil/local/vault-history/<scope>.json`, a keyed hash of every value each
  name held with its first generation (CRYPTO.md C12). A write of a value
  seen before takes that `since` (going back to a leaked value after a
  rotation or a deletion stays exposed, BUG-521), and `--exposed-to`
  consults it too.
* **Rotation.** New writes use the current generation; existing records keep
  theirs (members walk the key chain) and are re-sealed on their next write.
* **Stale rings** (BUG-524). `vl secret set|rm --scope` first
  fast-forwards the scope's ring from every team remote
  (`remote::refresh_ring`), and warns when none could be checked. On push,
  `sync` re-seals the pusher's own records sealed under a generation older
  than the destination ring's current one and stamped after the next
  generation started (written before this device
  pulled a rotation): the local ring is fast-forwarded, the entry re-sealed
  under the current generation with its `since`, stamped 1 ms later, and
  the stale record is not sent. Any other record sealed under a generation
  g after generation g+1 started (by its timestamp), readable by a member
  revoked in between (`Staleness`), is copied, reported by name on push and
  pull, and marked `stale_generation` in the vault, to be set again.
* **Clocks** (BUG-522). Push and pull both report the records they refuse.
  A write replaces (deletes) its writer's own records of the name stamped
  more than a day ahead, and is stamped by the clock; on the next push, such
  records of theirs on the remote are deleted when this device holds a
  later write of that name. A winning write of someone else's stamped that
  far ahead makes the write an error that names the clocks to check.
* **Names and size.** New writes need shell identifiers
  (`[A-Za-z_][A-Za-z0-9_]*`); records with `.` or `-` written before still
  count. A scope's live entries are capped at 256 KiB in all, counted as
  `execve` counts environment strings (BUG-523).
* **`vl run`** (`crates/vl/src/team_secret.rs`) loads the team vaults of the
  `--scope`s given, or of the scopes `vl run --remember` stored in
  `.veil/local/run-scopes.json`; none by default (BUG-520). It never sets
  names that are not identifiers or that decide what runs or loads
  (`team_vault::is_execution_variable`: `PATH`, `LD_*`, `DYLD_*`,
  `BASH_ENV`, `ENV`, `NODE_OPTIONS`, `PYTHON*`, `GIT_*`, `HOME`, `TMPDIR`,
  proxies and CA bundles, tool configuration paths, …) from a team vault,
  and warns about them. Before running it adds up arguments and environment
  and compares them with `ARG_MAX`; over it (or on `E2BIG`) the error names
  each loaded scope's size and largest entries.
* **Sync** (`sync_meta`, §8): team destinations only, after the rings are
  merged. A record the receiver lacks is copied if it passes the checks
  above against the receiver's ring, except that records of *former*
  members are copied (they would count again after a re-grant) and reported
  once. Records with a bad signature, an unknown generation, a signer who
  was never a member, a timestamp more than a day ahead, or (where the
  local identity can open them) content that does not decrypt, are refused,
  and push and pull both say so. A non-member relays records it cannot read.
* **Older vl** never looks at `.veil/meta/vault/`: it neither reads nor
  rewrites records, and it does not relay them (FORMAT.md §2). No format
  change was needed.
* **Undo.** Writes are outside the view, like ring changes: `manual_undo`
  operations whose message says how to reverse them by hand.

## 4. Visibility policy, and where it is enforced

> **Only secret files are ever encrypted** (`docs/VISIBILITY.md`). Who may
> see a folder is an access line, which the server enforces; on the device
> it is a plain `public` rule. `cloak` seals secret files only (`.env`,
> keys and the like: the built-in secret rules); on any other path a
> `cloak` line isolates the path, with a warning. Repository formats 7 and
> earlier also sealed folders, lines of work and embargoed merges; format 8
> removed that (FORMAT.md §5).

| Tier | In the snapshot graph? | Synced to team remote | Synced to public remote |
|---|---|---|---|
| `public` | plaintext | ✓ | ✓ |
| `cloak <scope>` (secret files only) | ciphertext | ✓ (ciphertext) | ✗ withheld (entry kept, redacted) |
| `isolate` | **never** | ✗ | ✗ |
| `ignore` | never | ✗ | ✗ |
| embargoed merge (§7) | plaintext | ✗ withheld until release | ✗ withheld until release |

The **builder** (`builder.rs`) is the single point where content enters the
CAS, and it applies these rules in order:

1. Ignored paths are skipped. That includes, built in and at any depth,
   the metadata of other version control systems: a `.git` directory or
   `.git` file (worktrees), `.jj/`, `.hg/`, `.svn/`, in any ASCII case and
   with HFS+-ignorable code points (`policy::vcs_metadata`). No `.veilpolicy` rule records them (not `** public`,
   not `vendor/ public!`, not a cloak), except a `public!` rule whose
   pattern names the directory itself (`fixtures/repo/.git/ public!`).
   Lifting that ignore counts as weakening for the accepted policy below.
   Checkout never writes VCS metadata that an older snapshot recorded, nor
   removes it.
   **Editor scratch files** are ignored too, built in and at any depth
   (`policy::editor_artefact`, any ASCII case of the fixed parts): Vim,
   Neovim and nano swap files `.B.swp` … `.B.swa`, Vim undo files `.B.un~`,
   Kate swap files `.B.kate-swp`, backups `B~` and `B.~N~` (Emacs, Vim with
   `backup`, gedit), Emacs auto-save `#B#` and lock links `.#B`, JetBrains
   safe-write files `B___jb_tmp___` / `B___jb_old___`, LibreOffice locks
   `.~lock.B#`. Only an `isolate` rule, or a `public!` rule whose own file
   name spells such a file (`*~ public!`, `*.sw? public!`), applies to one;
   lifting the ignore is a weakening. Every `vl` command snapshots, so
   without this an open editor's swap file would be recorded (BUG-098).
2. **Protection follows the name** (BUG-098). An *editor or backup
   artefact* of a file `D/B` is a file in the same directory `D` named as
   one of the scratch files above (Vim's swap file of `B` is `.B.swp`,
   but of `.env` it is `.env.swp`: both `B` and `.B` are tried), or a
   backup copy `B.orig`, `B.rej`, `B.bak`, `B.backup`, `B.old`, `B.tmp`,
   `B.temp`, `B.save`, `B.sav` (also numbered: `B.bak2`, `B.save.1`). Names
   are unwrapped up to four layers (`.env.bak~` → `.env.bak` → `.env`). The
   artefact gets the base's protection where its own is weaker, whatever
   its own rules say (no rule of the artefact's undoes it; only a change of
   the base's classification does):
   * base **isolated** (a built-in secret, or a user rule) → the artefact
     is isolated: local-only, listed by `vl status` as `L`, backed up in
     the vault like the file;
   * base **cloaked** under `s` → the artefact is cloaked under `s` (never
     another scope), unless its own classification keeps it on the device:
     scratch files stay ignored, backup copies are sealed under `s`;
   * base **ignored** → the artefact is ignored (unless isolated);
   * base public → the artefact's own classification (a scratch file stays
     ignored, a backup copy of a public file is an ordinary file).

   Directories are never artefacts. `vl policy check` names the base
   (`… an editor or backup artefact of deploy/id_ed25519`). The derivation
   is part of classification, so the accepted policy below pins it: an
   incoming policy that would publish an artefact (by lifting the scratch
   rule, or by publishing its base) is held back. The secret scanner also
   reads NUL-separated text such as Vim's swap format (rule 4), as defence
   in depth.
3. Isolated paths, including the built-in secret rules (`.env`, `.env.*`,
   `*.pem`, `*.key`, SSH private keys, `*.tfstate`, …), are reported back and
   never hashed into the store. A user's plain `public` rule cannot override a
   built-in secret (the warning about it stops once a later rule decides
   the path, e.g. the `public!` of `vl expose --force`). `cloak` can (the
   file is shared encrypted), and so can an explicit `public!`. Built-in
   secret rules and user `cloak`/`isolate` rules match case-insensitively. Rules that expose or untrack do not. Policy
   rules fail safe: an invalid scope (`validate_scope_name`), an unknown tier
   or a missing tier isolates the pattern. A protective rule whose glob does
   not compile matches its literal name.
   * **A policy from someone else never weakens local protection
     silently** (`policy::working_copy_policy`, `wc_policy.rs`). Isolated
     files never enter history, so nothing but the policy protects them,
     and `.veilpolicy` is shared: it arrives by merge, pull, checkout of
     another change, rebase or undo. Each working copy keeps,
     device-locally, the policy its member last *accepted*
     (`.veil/local/accepted-policy`). Snapshots of the repository's own
     directory classify every path under both; where `.veilpolicy`
     **weakens** the accepted classification, the accepted one applies and
     the path is reported as held back (`BuildReport::policy_held_back`; a
     directory the accepted policy ignores, such as `.git/`, is reported
     once, as a whole).
     Weakening is: isolated → cloaked or public; cloaked → public or
     another scope; `public` → `public!` (scanning off); `ignore` lifted
     from a built-in secret, from VCS metadata or from an editor scratch
     file (or from an artefact of an ignored built-in secret). Moving to `isolate` or
     `ignore` never weakens (the file stays on the device either way), and
     strengthening applies at once. A held-back tracked file keeps its
     entry: an incoming
     `.env public!` plus a decoy tracked `.env` cannot get the member's own
     `.env` recorded as an edit of it, and nothing is recorded as deleted.
   * The accepted policy moves forward on its own only when that cannot
     weaken anything the member did not ask for: on first use (a new
     repository, a clone, the first snapshot after upgrading), when the
     rules are unchanged (comments and spacing never count), when the only
     changes are `isolate`/`ignore` rules appended to the accepted ones and
     dropped `public!` rules (so an exposure a teammate reverted cannot come
     back silently later), and when the member edits `.veilpolicy`
     themselves (by hand or with `vl cloak|isolate|expose|ignore`): then
     exactly their edit, relative to the tree the working copy was checked
     out from, is applied to the accepted policy (`policy::fold_edit`), so
     editing a policy that arrived from someone else does not accept what
     that someone else changed. Rules are last-match-wins, so a rule's
     position is part of its meaning: the edit is a line diff applied *in
     place*, each added rule landing between the same accepted rules as in
     the member's file (BUG-073: appending them let `notes/** public`
     written above `notes/private.md isolate` override it). Where that place
     is ambiguous (the member added rules exactly where the pending change
     removed some), their rules go after the removed ones (deciding where
     both match, as in their file), or else before them. It is refused where
     the member moved a rule of the pending change. The result is then
     checked exhaustively: no path may be classified by it more weakly than
     by both the old accepted policy and the member's file. The check runs
     over rule combinations, not paths (a path's class depends only on its
     built-in state, the `public!` rules it matches and the last rule that
     applies, so every built-in state × set of `public!` rules × last rule
     per policy covers every path and every glob overlap; rules with the
     same pattern and case handling count as one), within a fixed work
     budget. When the fold is refused, only the `isolate`/`ignore` rules the
     member added are appended to the accepted policy (that never weakens
     anything), and every snapshot warns that the rest of the edit waits for
     `vl policy accept` (the held-back warning then says that a path may be
     held back by the member's own edit, not only by the pending change). The accepted policy's first line (a comment)
     records which edit it folded, so a snapshot that saved it but was not
     recorded does not fold the same edit twice. Anything else waits for
     `vl policy accept`, which lists the local files whose protection it
     weakens.
   * Only a real edit counts as the member's. A command that writes
     `.veilpolicy` from another revision without moving the working copy
     (`vl restore [--from REV]`, BUG-101) snapshots with
     `SnapshotOptions::policy_incoming`, so what it brought in is guarded
     like a pulled policy. Every other route (`vl new`, `edit`, `ws switch`,
     `undo`, `op restore`, `merge`, `rebase`) moves the working
     copy to a tree that holds the incoming policy, so there is no
     difference to mistake for an edit (`policy_routes_cli.rs` covers each).
   * What is at `.veilpolicy` never makes a snapshot less protected than
     the accepted policy (`policy::read_policy_file`, BUG-106/107). A
     **missing** file is not taken as the member's edit (deleting every rule
     at once is an accident far more often than a decision): the accepted
     policy guards the built-in rules, every snapshot warns, and
     `vl policy accept` accepts having none. A **symlink** (a dotfiles
     manager, `stow`, a monorepo's shared policy) is followed, inside or
     outside the repository, to a regular file of at most 1 MiB whose name
     says it is a policy (`*veilpolicy*`: `.veilpolicy`, `dot_veilpolicy`,
     `shared.veilpolicy`), so a hostile checkout's
     `.veilpolicy -> /proc/self/environ` is never parsed and echoed in
     warnings (FIFOs and devices are refused, the open is non-blocking), but a change in its
     target is never the member's edit, since it changes by routes Veil
     does not see: strengthening applies at once, weakening waits for
     `vl policy accept`. Its tracked entry is kept as for any symlink (the
     warning says teammates do not get the change), and `vl cloak|isolate|
     expose|ignore` refuse to write over the link. Following was chosen
     over refusing to snapshot: "nothing in the working copy can fail a
     snapshot", and the pin already makes following safe. An **unreadable**
     file, a directory, a dangling or looping link: the accepted policy
     applies as it is, every snapshot warns, nothing is accepted, and
     `vl policy accept` refuses until it is fixed.
   * Only the repository's own directory (the backend it was opened on)
     is guarded and can move the accepted policy. Sandboxes of
     `vl ws exec`, overlays, ephemeral workspaces and imported trees hold
     no local-only files of the member (injected secrets are caught by
     `InjectedSecrets`) and use their own `.veilpolicy`; an agent editing
     `.veilpolicy` in a sandbox cannot accept it for the member, nor
     weaken it (below). In a
     `ws exec` sandbox only a regular, readable `.veilpolicy` is an edit:
     a deleted, unreadable, symlinked or directory one is replaced, for the
     snapshot, by the `.veilpolicy` of the tree the sandbox was synced from
     (`sandbox::PolicyPin`), which is applied and recorded unchanged, with
     a warning (BUG-553/554). A sandbox has no accepted pin of its own that
     could keep guarding its next run, so the recorded policy is the pin.
   * **A command is not the member** (BUG-560). In a sandbox the editor of
     `.veilpolicy` is the command (an agent, typically), not the member, so
     its edit is an incoming change. Recordings of files a command wrote
     (`ws exec` sandboxes, full, sparse and ephemeral, and mounts:
     `SnapshotOptions::policy_from_command`) are pinned by the recorded
     policy, the `.veilpolicy` of the tree the files were synced from
     (`Repo::command_policy`, `policy::command_edit`). An edit that cannot
     weaken it (the same rules, appended `isolate`/`ignore` rules, dropped
     `public!` ones, or anything the exhaustive check of the fold proves
     never weaker) is recorded and applies. One that only inserts `cloak`,
     `isolate` or `ignore` rules is recorded unless it weakens a path of
     the snapshot (a cloak rule lifting `target/ ignore`, or moving a
     sealed secret file to another scope). Anything else (truncating the file,
     removing a rule, `public!`, `** public`, retargeting a scope) is
     **held back**: it applies where it is stronger, the recorded
     classification where it would be weaker (reported as for a pull,
     `BuildReport::policy_held_back`), and the tree keeps the recorded
     `.veilpolicy` (`BuildReport::policy_edit_held`). The next run starts
     from that tree, so it is pinned the same way, and no device state is
     needed. A deleted, symlinked or unreadable `.veilpolicy` in a mount is
     held back the same way. The edit stays where the command made it (the
     sandbox's files, the mount's overlay; a throwaway sandbox loses it,
     with a warning) until the member records it with `vl policy accept
     --workspace NAME` (`Repo::accept_workspace_policy`), which lists the
     paths it weakens; that recording reclassifies them. The mount counts
     as a command: tools and agents write there too. `vl ws write` is the
     member's own command and records what it is given; `vl serve` has no
     method that writes a file (its `snapshot` records the project
     directory, under the accepted policy). The
     stale-checkout recovery path (`build_from`, `commit_fs_as_child` on the
     working copy) is guarded but never treats a policy difference as the
     member's edit.
   * UX: every snapshot that holds something back warns (path, accepted →
     wanted tier) and `vl status` lists `P` entries; a checkout that
     changes `.veilpolicy` warns at once; `vl policy show` lists pending
     weakenings, `vl policy check <path>` says when a classification is
     the accepted one, and `vl scan` uses the effective policy. As a CI
     gate, `vl scan --policy-from FILE` takes its rules from FILE only (the
     base branch's policy), needs no repository, and counts every file of
     the checkout as public except FILE's `public!` paths (BUG-115).
   * Considered and rejected: refusing the incoming `.veilpolicy` at merge
     time (as for sealed content). Merge cannot see the working copy's
     isolated files, and pull + `vl new`, checkout, rebase and undo bypass
     merge entirely; the working-copy snapshot is the one place
     every route meets.
4. Public files are scanned for credentials (AWS, GitHub, GitLab, Slack,
   Stripe, Anthropic, OpenAI, Google, JWT, private keys, passwords in URLs
   (`postgres://app:<password>@db`), and high-entropy `password = …` /
   `API_KEY=…` / `JWT_SECRET: …` / `GITLAB_TOKEN=…` / `APP_KEY=…`
   assignments in their common shapes: quoted (escaped quotes included) or
   not, the rest of a configuration line, `define('KEY', '…')`,
   `env["KEY"] = …`, Kubernetes `name:`/`value:` pairs, XML elements (with
   attributes or CDATA) and `key="…" value="…"` attributes, plist entries,
   SQL `WITH PASSWORD '…'` / `IDENTIFIED BY '…'`, Google app passwords).
   A hit **quarantines** the file: the offending content stays local and
   is not snapshotted.
   * The scanner (`secrets.rs`) reads every file, whatever its size or
     encoding. Binary files are not skipped. Text in NUL-padded encodings
     (UTF-16/32, with or without a BOM) is scanned a second time with the
     NULs removed, in 256 KiB chunks with a 16 KiB overlap (where the NUL
     positions show UTF-16/32, a non-ASCII character next to ASCII text
     becomes a space, so it is not glued to a token). A chunk counts
     as such text if the file has a BOM, if 1/32 of its bytes are NUL, or
     if the chunk or its overlap holds a run of 8 ASCII characters in
     UTF-16 (text in a non-Latin script has almost no NULs in UTF-16, and
     UTF-16 may start near the end of a chunk). Text whose lines end in NUL
     instead of newline (Vim's swap files store each line NUL-terminated,
     a block's lines last to first) is searched again with its lines joined
     by newlines, in file order and in reverse, when such lines hold at
     least half of the file's non-NUL bytes; it counts as binary data for
     the PEM rule. Token rules run as one
     alternation, so the regex literal prefilter makes a single pass.
     The assignment rule runs on an ASCII-lowercased copy of each chunk,
     because `(?i)` keywords defeat the prefilter. Values must look like
     credentials: whole references (`$X`, `${X}`; a `$` *inside* a random
     password is no reference), placeholders (`<key>`), hashes and
     encrypted values (`$2b$…`, `ENC(…)`), code (`os.getenv("X")`,
     `Option<String>,`; scanner v7: any call, index or list made of names,
     `lookup(user)`, `self.users[c.name]`, `[token]`, a type annotation
     `KEY: Flags = 2`, a JSON object followed by `,`) and identifiers made of words
     (`settings.SECRET_KEY`; long words are judged by letter-pair
     frequencies, so `qzvxkwprmtfhjlnb` is no word) do not count, and the
     entropy bar is lower for short, hex and lower-case values. The rest of
     a line counts only where the key starts a configuration line (after a
     newline or NUL, indentation, `export`/`set`/`ENV`/`ARG`, `- `, a
     quote); each chunk's window starts at a line start, so a chunk
     boundary inside a code line does not make one. A PEM
     header inside binary data needs key material after it (after a real
     or an escaped `\n`, as in a service-account JSON key inside a `.tar`).
     Uncompressed archives (`.tar`, stored `.zip` entries) are scanned as
     their bytes are; compressed ones (`.tar.gz`, deflated `.zip`, `.docx`,
     `.jar`) are not decompressed.
   * Pre-filter (scanner v6): an Aho-Corasick pass over the lowercased chunk
     finds the eight keyword words (`password`, `passwd`, `secret`,
     `token`, `key`, `salt`, `pwd`, `identified`). A chunk without one is
     not searched by the assignment rule (whose regexes are compiled only
     for the first chunk with one: they take more time to compile than
     the rest of a one-file commit; the token rules compile on another
     thread while the command starts, `secrets::prepare`, and only text
     holding one of their literals is searched for tokens at all:
     `TOKEN_LITERALS`, which a test checks against the prefixes each
     rule's pattern allows), and the search is limited to
     from the first to 16 KiB past the line of the last. On each line with
     a keyword, the `:`/`=` that ends a configuration key is replaced by a
     stand-in (`C`/`E`, upper-case letters never occur in the lowercased
     copy), and the rest-of-line value only matches after one: code lines
     like `let secret = config.secret_key.clone();` are no longer
     candidates. A keyword its left context rules out (`mytoken`,
     `monkey`) is dropped before capture groups are computed, with their
     work still counted, and so is (scanner v7) a match running to the end
     of its line whose value, without blanks, no key's rule could accept
     (references and code: `os.environ["X"]`, `${X}`; capture groups cost
     more than the rest of the search, and these are most matches in code
     and configuration). On such a configuration line, the dots of the key
     become `_` (`stripe.api.key` → `stripe_api_key`), as do those of the
     `key="…"` / `name="…"` attributes of an XML line.
   * Time is linear in the input: repetitions that could hold another match
     are bounded, so a search reads at most about 1 KiB past its match, and
     the work redone after restarting inside a rejected match is counted;
     past 16 times the input the file is reported (`scan-limit`) and
     quarantined. Crafted input scans at 25+ MiB/s, ordinary text at
     590–860 MiB/s (dense synthetic corpus) or 2.2–2.5 GiB/s (real
     source; 1.9 GiB/s JavaScript): 1.4–2.4× the previous scanner (v5).
     Scanner v7 is level with v6 on clean code and binary data, and 8–12 %
     faster on the mixed corpus (the value check before capture groups).
   * Keys: the credential keywords match anywhere in an identifier
     (`DB_PASSWORD`, `spring.datasource.password`), plural or numbered
     (`API_KEYS`, `PASSWORD2`), plus up to six suffix words
     (`DB_PASSWORD_PROD_EU_WEST_1`, `aws_secret_access_key`) unless one
     of them says the value is something else (`password_hash`,
     `token_url`, `secret_name`, `…_file`, `…_path`). The generic `secret`
     and `token` only count as a word of their own (`JWT_SECRET`, not
     `mytoken`), and `token` not after a word that names a non-credential
     (`csrf_token`, `next_page_token`, `cancellation_token`). Keys are
     split into words at `_`, `-` and camelCase humps (scanner v6), and at
     `.` in the key of a configuration line or an XML entry (scanner v7:
     `api.key=`, `<entry key="api.key">`, not `obj.key = …` in code): `secret`,
     `token` and `pwd` also count at a hump (`githubToken`, `stripeSecret`,
     `dbPwd`, not after a one-letter Hungarian prefix: `nToken`), and so
     do suffix words (`apiKeyProd`; not `tokenizer`, `passwordless`), with
     the same exclusions (`tokenUrl`, `passwordHash`). `key` and `salt` need
     a word before them: a secret's (`APP_KEY`, `RAILS_MASTER_KEY`,
     `accessKey`, `LICENSE_KEY`, WordPress's `AUTH_KEY` … `NONCE_SALT`), or
     any word but a non-secret's (`primary`, `cache`, `public`, `sort`,
     `partition`, …), and then the value must be 16+ random characters (32
     hex) and not a UUID. The pre-v6 compound keywords (`api_?key`,
     `secret_?access_?key`, `client_?secret`, `access_?token`, …) still
     count anywhere in an identifier. Keys found by a v6 rule (at a hump,
     with camelCase suffix words, `pwd`, the newer `*_KEY` names, any
     `<WORD>_KEY`) need a value that is clearly a literal: quoted or one
     token on the key's line, not an unquoted name in code (`Key:
     TypeName,`, except after `;` in a connection string), not made of
     words (two thirds of its letters in words of 3+ letters), not a UUID.
     Typed declarations (`API_KEY: &str = "…"`, `apiKey: string = "…"`,
     `api_key: str = "…"`), template literals, XML attributes on any
     element, `<entry key="…">` / `<property name="…"><value>` elements and
     Dockerfile `ENV`/`ARG` lines count. A camelCase spelling of a key an
     older rule found (`dbPassword`, `apiKey`, `_authToken`, `clientSecret`;
     scanner v7) is held to the same, except that an unquoted token in code
     counts, as before v6: `.npmrc`'s `//host/:_authToken=…`, a URL's query
     string (`?accessToken=…&`, the value ending at `&`), keyword arguments.
     A key a v6 rule rejects restarts the search inside it, so an older
     keyword there still counts (`secretKey`: `key` after `secret`;
     `ACCESS_KEY_SECRET`). A URL password must not
     be a word, a number or a reference (`user:password@`,
     `postgres:postgres@`, `${USER}:${PASS}@` do not count); it is judged
     percent-decoded, may contain `:`, and `:\/\/` (JSON) counts as `://`.
     `secrets::RULES_VERSION` is part of the stat-cache key, so "scanned
     clean" facts from an older scanner are not reused.
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
   * **`vl restore` is a checkout of some paths** (BUG-201, BUG-209,
     `checkout::restore_paths`): the working copy is snapshotted first, so
     every edit it can record is in `@`'s tree, and the diff from that
     tree to the source, restricted to the paths given, goes through
     checkout's rules: removals before writes (a file and a directory can
     trade places either way), nothing in the way that checkout did not
     write is deleted, emptied directories are removed. By default the
     source is what `vl status` compares with: the parent of `@`, or for a
     merge its merged parents (BUG-208), as in jj. Path arguments are
     relative to the current directory; a path outside the repository is
     refused, and `\` is an ordinary character (BUG-204).
     **A version put back keeps its audience** (BUG-481). The restored
     files are not judged as edits of `@`'s entries (whose audience is
     `@`'s, often public): a sealed secret (as its object proves) and a
     conflict entry are recorded as the entry they were written from
     (`SnapshotOptions::carried`), the conflict exactly as it was (and
     listed as a conflict of `@` again). A plaintext version is an ordinary
     edit: the policy decides its sealing, which can only narrow it. A
     sealed version this reader cannot read is not restored (it is
     reported `redacted`). The other routes
     that put recorded versions into `@` already keep them: `vl resolve
     --ours/--theirs/--base` takes a term's entry as recorded, `vl new`/`vl
     edit` check a tree out as it is, and split/squash halves keep each
     version's sealing (below).
5. Secret files a `cloak` line names are sealed under its scope (the
   built-in secret rules name the paths that may be sealed: `.env`,
   `.env.*`, keys…, and their public examples; `policy::names_secret`). A
   `cloak` line on any other path isolates it instead, with a policy
   warning, and `vl cloak` refuses such a pattern; an editor or backup
   artefact of a sealed secret takes its scope.
   * **Labels are claims; objects are authority** (BUG-103). The parent
     entry's visibility label comes from history, which anyone who can push
     to a team remote writes. Before new content is
     sealed, the builder checks the label against the object it points to
     (`builder::verify_sealing`: plaintext blob → public, envelope label
     `s` or `s#<key-id>` → cloaked under `s`; a public entry whose id is
     the blob id of the file's content is plaintext by construction, so
     unchanged files cost nothing). A mismatch (Mallory relabels Alice's
     `team` file `cloaked:mal`, or `public`) is reported
     (`BuildReport::relabelled`, with a warning) and the decision is taken
     on the object's real sealing. A label whose object is absent (a
     public remote withheld it) or sealed under no audience never decides
     the sealing of an edit: the edit is held back
     (`cloak_failures`). The same check runs wherever history decides the
     audience of new content: three-way merges and rebases
     (`merge::merge_file`) and merge normalisation
     (`embargo::normalize_tree`). As a backstop, the builder never seals
     under a label that is not a scope, and `vl cloak --scope` refuses a
     name that is not a scope you are a member of (`validate_scope_name`,
     BUG-124/210).
   * **Sealed content keeps its audience.** A tracked file the parent holds
     sealed under scope `s` stays sealed under `s` (as verified above), edited or not, whatever
     the workspace or the current policy says, unless this very snapshot
     edits `.veilpolicy` so that the path's classification changes. That is
     how `vl expose` and `vl cloak --scope` work, and an expose to `public`
     still goes through the secret scanner below. A policy that arrived by
     merge, `vl new`, rebases, squashes and splits never move sealed
     content to another audience
     (splitting by hunk: §5, "Shaping history").
     **The rule only ever keeps a file out of public view; it never takes
     an audience the policy does not name** (BUG-125). When the policy (as
     pinned by the accepted policy) cloaks the path under `P` and the
     parent's verified sealing is another scope `Q`, with no edit of
     `.veilpolicy` in this snapshot re-keying it, an *edit* is sealed for
     neither: it is held back (`cloak_failures`; the file stays local,
     history keeps the recorded entry as it is), and unchanged content
     keeps its entry. That state has no honest route of its own (a re-key
     edits the policy in the same snapshot, and an incoming re-key the
     member has not accepted is a held-back policy, which waits for `vl
     policy accept` like any other); Mallory, who can push, produces it by
     replacing `secrets/db.yml` on `main` with a genuine object sealed for
     `mal`, a scope Alice is also in. Sealing Alice's edit for `Q` hands it
     to whoever put the object there. Sealing it for `P` with a warning was
     the alternative, and is rejected for the same reason as in merges
     (next rule): the edit holds the `Q` content it was made from, and
     membership is not ordered, so neither scope is safe to pick for the
     other's content; it would also undo, on the member's next edit, a
     teammate's genuine re-key the member has not yet accepted. The report
     names the way out: `vl cloak --scope P PATH` (a deliberate re-key, by
     this rule's own exception) or, for an incoming re-key, `vl policy
     accept`. A file the policy leaves public (sealed by an earlier `vl
     cloak --scope` that the policy no longer names) is not affected: it
     keeps its parent's scope as before.
   * **Merging never moves content between scopes** (BUG-123). When the two
     sides of a file are (verifiably) sealed for different scopes,
     `merge::merge_file` seals nothing for either audience: the result
     would hold both sides' content, readable by the members of one. The
     file is a conflict, and one side's entry is kept exactly as it is:
     the side whose scope is the base's (the other side moved the file to
     another audience, so in an auto-rebase onto a `main` where the file
     was replaced by a `mal`-sealed object, Alice's pending `team` edit is
     kept, sealed for `team`), else ours. Neither scope is taken as the
     narrower one: membership is not ordered and changes over time.
     Likewise merge normalisation reseals a merged-in edit for the
     destination's audience only when it was public; content sealed for
     another scope is not resealed, and the destination keeps its own
     entry (reported).
   * **Conflicts never move content between audiences** (format 4). A
     conflict entry keeps every version sealed as it was, so a public
     conflict may name a sealed version: its object is withheld from public
     remotes and readers without its key see it redacted. The file with
     markers is rendered per reader (`conflict::materialize`): its audience
     is that of a file merged from the sides (never wider than any side it
     shows), a side or base is shown only when it is public or verifiably
     sealed exactly as that file, anything
     else is a `(not shown: …)` line, and with two scopes only the side the
     merge rule keeps (the base's scope, else ours) is shown. The rules
     below for markers apply to that rendering as they did to stored
     marker files. Merge normalisation never reseals or publishes a
     conflict entry.
   * **Conflict markers show the base only to its own audience**
     (BUG-126). A conflicted text merge writes diff3 markers, whose
     "original" section is the merge base's version. That section is
     written only when the base is public or is verifiably sealed exactly
     as the result is. Otherwise, for example
     with a base sealed for `team` and two sides that both exposed the file,
     or a base sealed for `ops` and two `team` sides, the markers show the
     two sides only (Git's `merge` conflict style). Before the fix, the
     public result carried the `team` text into the snapshot and public
     remotes. The alternative, sealing the conflicted
     result for the narrowest audience involved, is rejected: scopes are
     not ordered (see the previous rule), so there is often no narrowest,
     and it would hide both sides' public edits from public readers
     because of a section that only helps the person resolving the
     conflict. That person can still read the base (`vl cat -r` on the
     merge base). A clean merge never holds a line of the base that neither
     side has, so only the markers are affected.
     The same holds for the **virtual merge base** of a criss-cross merge
     (BUG-127). Where the two merge bases disagree, it keeps their common
     ancestor's version, and it is sealed as the merge bases are. When that
     ancestor's audience is not theirs (an ancestor sealed for `team`, two
     public merge bases), the virtual base keeps nothing there instead. The
     two later versions still both differ from it there and conflict, and
     the ancestor's text is never stored for a wider or other audience.
   * A reader without the key who edits a sealed secret cannot seal the
     edit: it is held back (`BuildReport::cloak_failures`; the file stays
     local) and the recorded entry is kept, as is any tracked file this
     reader cannot seal.
6. An embargoed merge's files are plain and recorded like any others; the
   embargo withholds the history from pushes (§7). (Formats 7 and earlier
   sealed them under an embargo key.)
7. Entries this reader cannot materialise (no key, or withheld by a public
   remote) are **carried over** instead of being treated as deletions. A
   partial view can never accidentally delete hidden content.

The working copy itself is untrusted ground. Nothing in it can fail a
snapshot (and with it every command), and nothing is dropped silently:

* Leftovers of an interrupted `DiskBackend` write (`.name.vltmpXXXXXXXX`,
  `name` cut to its first 32 bytes so that a name near the filesystem's
  255-byte limit still has a temp name that fits, BUG-202) are crash
  debris and are skipped.
* A directory (other than the root) that holds a `.veil` directory, or a
  symlink named `.veil`, is a **nested repository**: a vendored project, a
  monorepo member, `vl init` run in the wrong place. Like Git with an
  embedded repository, the enclosing repository records nothing of it,
  whatever its policy says: the nested repository's sealed secret files are
  plaintext on disk and only its own policy knows they are secret
  (BUG-200, `vfs::holds_repository`). It is reported once, in `vl status`
  (`N inner/`, `BuildReport::nested`); anything tracked there before is
  recorded as deleted (the files stay on disk). The same walk serves
  every route (snapshots, `vl watch`, `vl ws exec` sandboxes); `vl scan` and `vl policy check` skip it and say so. Checkout
  (and `vl restore`) never write or remove anything inside one
  (`CheckoutReport::nested`). A plain *file* named `.veil` is only
  skipped itself. The CI gate `vl scan --policy-from` does scan nested
  repositories: a CI checkout publishes their files.
* A directory the policy ignores is never descended into (Git's rule), so
  no later rule re-includes a file below it (`build/ ignore` then
  `build/keep.txt public` records nothing under `build/`); `vl policy
  check` reports such a path as ignored via the directory's rule
  (BUG-203).
* An unreadable file or directory (permission denied) is reported. A tracked
  one keeps its previous entry, an untracked one stays out, and the command
  goes on, so `vl ignore` still works.
* Names that are not valid UTF-8 cannot be recorded and are reported on
  every snapshot.
* A tracked path that is now a socket or device (or, below format 5, a
  symlink) is never followed. Its tracked entry is kept and reported.
  Checkout and `vl restore` never write, remove or prune at or below such
  an entry (`CheckoutReport::blocked`), so a `vendor -> /shared/vendor`
  link never receives pulled files.
* **Symlinks (format 5)** are recorded as symlink entries whose object is
  the target string, read with `readlinkat`, never followed: a link is
  classified by its own path (`Policy::classify_link`: as a file, and a
  link spelling `.git`, `.jj`, `.hg` or `.svn` is VCS metadata), scanned,
  and sealed under its scope exactly as file content (a cloaked link's
  target never reaches a public remote; a link named `id_rsa` is
  isolated; a token in a target is quarantined). A target that is not
  UTF-8, holds a NUL or exceeds `PATH_MAX` is unrepresentable (reported,
  a tracked link keeps its entry). A new target outside the repository,
  or at a path the policy isolates, is reported
  (`BuildReport::link_warnings`). Only a parent entry of the same kind is
  a link's previous version: a file replaced by a link is a new leaf
  (`T` in `vl status`), its old version kept in history. `.veilpolicy` is
  never recorded as a link (it is read through, BUG-058), and a link named
  `.veil` makes its directory a nested repository. The stat cache is not
  used for links (one `readlinkat` costs less).
* **Checkout of links** writes them with `write_link` (the target as it
  is) through the no-follow walk. A link at a path is replaced or removed
  only when it is the version `from` materialised (same `readlink`
  bytes); any other link is the user's and is kept (`kept_local`, or
  `blocked` where a file of the tree would replace it). A hostile
  target (NUL, over `PATH_MAX`, empty) fails that path only. A link is
  never written from anything but its own entry. A conflict with a symlink side
  is materialised as its **shown side, as it is**
  (`conflict::shown_side`: ours, unless ours deleted it), never as a file
  of markers, which would turn a link target into file content a later
  edit could publish (threat 12); the builder keeps the conflict while
  that side is untouched, and anything else at the path resolves it (only
  for a reader of every side). `name_collisions` counts links as names, so
  `A -> …` and `a/` in one tree are refused on a folding filesystem
  (CVE-2021-21300's shape).
* **Protection follows content across a rename** (renames design,
  builder hardening): a new public file or link whose plaintext equals
  that of a cloaked entry the same snapshot deletes (verified sealing,
  key held) is sealed as that entry was, unless a rule of the policy
  explicitly classifies the new path (`Builder::protect_moves`).
* A path the working copy's filesystem refuses (a name too long for it,
  a character it cannot hold, permission denied on one directory) never
  stops a checkout and never wedges the working copy: it is reported
  (`CheckoutReport::failed`), left out and recorded as such in the
  checkout record (`Materialised::hidden`), so the next snapshot carries
  its entry instead of recording a deletion, and every command tries
  again (BUG-202). A full or read-only filesystem still stops the
  checkout. `DiskBackend` takes a name too long to exist as "nothing
  there" when reading.
* A tree whose `.veilpolicy` cannot be read (a directory, a symlink, sealed
  for a scope this reader lacks: only a hostile or corrupt tree records
  one) never blocks a checkout or a merge: the policy this member last
  accepted applies there, with a warning (BUG-121,
  `Policy::load_or_accepted`). A snapshot of a working copy holding such a
  `.veilpolicy` already falls back to the accepted policy.

Local-only files (isolated and quarantined) are backed up into the vault, so
`vl ws exec --with-isolated` can inject `.env` into a sandbox without it ever
touching history. The backup of a file that disappears from the working
copy, whatever removed it, moves to `VaultData::removed` for 30 days instead
of being pruned at the next snapshot (`vl secret files`, `vl secret
recover PATH`); it is the last copy of content that is in no snapshot. The sandbox is then snapshotted with those contents as
`InjectedSecrets`. Any new or changed file, of any tier, that contains one of
the injected values is quarantined (`injected-isolated-secret`), so a command
cannot record a copy under another name. The values are: each `KEY=value`
value that looks like a secret (8+ characters, and either 20+ characters or a
mix of character classes, so `localhost` or `3000` never match), plus the
whole content and every whitespace-free line of 24+ characters (key
material). Binary files (PKCS#12 bundles, Java keystores, DER keys:
anything that is not UTF-8), and the DER inside every PEM block of a text
file, are matched as bytes (BUG-099): the whole content, plus 32-byte
windows every 16 positions of the raw bytes, of their base64 (the three
alignments) and of their hex (both cases). So a verbatim or partial copy
(47+ bytes), a `base64`/PEM/`xxd -p` re-encoding, and a PEM key converted
to DER are all quarantined. Only windows over distinctive bytes (3/4
distinct) count, so padding and the ASN.1 structure every key of a kind
shares never match an unrelated keystore or certificate. Matching is one
rolling-hash pass per checked file, behind a 128 KiB bit filter; each
injected file contributes at most about 74 000 windows (larger files get
a proportionally larger stride, up to 16 MiB of content) and all together
at most 2^18.

## 5. The snapshot graph

```rust
struct Snapshot {
    parents: Vec<ObjectId>, change_id: ChangeId, tree: ObjectId,
    description: Text /* Plain only, format 8 */, author, timestamp,
    predecessors: Vec<ObjectId>,   // evolution log
    conflicts: Vec<String>,        // conflicted paths (format 4: an index of the tree's conflict entries)
    embargo: Option<String>,       // embargo introduced here
    agent: Option<Attribution>,    // format 10: {agent, task?, prompt?, run?}
    abandoned: Option<String>,     // format 10: a recorded dead end, and why
    attempts: Vec<ObjectId>,       // format 10: the change's dead ends (≤ 32)
}
```

* **Agent attribution** (`Snapshot.agent`, format 10) is set only by the
  process: `Repo::set_attribution`, which `vl` fills from its own
  `VEIL_AGENT…` environment and `ws exec --agent` flags
  (`crates/vl/src/agent.rs`), and the server from an agent session's
  record for API commits (`docs/HUB.md` §13.27). `Transaction` stamps what
  the transaction produces (`write_snapshot`, `rewrite`), except an empty
  undescribed change and an abandoned attempt; `keep_attribution` (rebase,
  duplicate) keeps each change's own. It is inside the signed encoding.
* **Attempts** (`vl attempt drop`, `Repo::drop_attempt`): the version is
  copied with `abandoned` set (and stored without becoming a head), and the
  change starts again from its parents, listing it in `attempts` and
  naming it as its predecessor. `Transaction::check_parents` and
  `check_no_abandoned_refs` (at commit) keep abandoned snapshots out of
  parents, heads, workspaces and tags; gc, fsck, pushes and pulls follow
  `attempts` like parents. Validation is `Snapshot::validate_format_10`, on
  every decode and write.
* **There is a universal root** (all-zero change id, empty tree, timestamp 0),
  so every repository shares it and unrelated histories can be exchanged.
* **Change ids** are 128-bit random values, shown in reverse-hex (`z…k`) so
  they never look like snapshot ids. They survive amend, describe, rebase and
  squash.
* **The working copy is a snapshot.** Every `vl` command first runs
  `snapshot_workspace`, which builds a tree from the working copy. If the
  tree changed, it *rewrites* the working-copy snapshot: same change id, new
  tree, predecessor recorded. No index, no `add`.
  The scan runs **before** the repository lock is taken (BUG-801): new
  objects are staged in memory (`ObjectStore::begin_staging`, up to
  32 MiB), never written or adopted, so a clean working copy is recorded
  without the lock at all. A changed one takes the lock, checks that the
  workspace, the accepted policy and the scanner's rules are what the scan
  saw, then writes the staged objects and records the tree; if anything
  moved meanwhile, or the new content was too large to stage, the tree is
  built again under the lock. That is formats ≤ 5. From format 6 (the
  lock-free op log, §9) there is no lock to avoid: the snapshot builds
  inside its transaction, with its objects staged on disk, and its commit
  fails ("superseded") if an operation that landed meanwhile moved the
  workspace; a caller that did not name the working copy it materialised
  builds again.
* **Views and the operation log.** A `View` holds the visible heads,
  workspaces (`name → working copy`), tags and remote tags. Every transaction
  writes one `Operation { parents, user, time, description, view }` (format
  6 adds `workspace`, the workspace the command was for, and `rewritten`,
  its rewrites; concurrent operations are merged, §9 "The lock-free op
  log"). Undo and
  `op restore` reinstate an older view, and then the CLI checks out the
  difference. Uncommitted edits survive both: the automatic snapshots of the
  attached workspace at the top of the op log are not commands, so undo
  skips them and undoes the operation before. The edits they recorded are
  re-applied on the restored working copy with a 3-way merge
  (`Repo::undo_keeping_edits`, `Repo::restore_operation_keeping_edits`), in
  every workspace that has the same working copy before and after (an undo
  that would delete a workspace holding recorded edits is refused).
* **Undo and redo** follow jj. An undo records `undo_of` (the operation it
  undid), a redo `redo_of` (the undo it took back). `Repo::undo_target`
  walks back from the head: automatic snapshots of the attached workspace
  are skipped, an undo jumps to before the operation it undid, and a redo
  stands for the command it re-applied; the first other operation is what
  `vl undo` undoes. So repeated undos go further back, and undo, redo, undo
  undoes the same command twice. `Repo::redo_target` walks the same way
  but stops at the newest undo not yet redone (a redo jumps to before its
  undo); any other command ends the walk, so a new command clears what
  could be redone. Undo restores the view of the undone operation's parent
  keeping the edits recorded since that operation; redo restores the view of
  the operation itself, keeping the edits recorded since its parent. A
  property test checks random command/undo/redo/edit sequences against
  jj's model (a history stack and a redo stack). Undos written before
  `undo_of` existed are plain operations: undoing one redoes it, once.
* **Undo per workspace (format 6).** `Repo::undo_target(ws)` walks the op
  graph newest first (by timestamp, then id, across merged branches, and
  on a log written since operation times were clamped never an operation
  before one that descends from it: equal times follow the op log's
  ancestry, reading only the operations of that time it needs, BUG-1402,
  BUG-1433; on an older log, with an operation older than its parent, an
  operation can still come before an older descendant reached only by
  another branch, BUG-1432) and
  skips merges of concurrent operations and other workspaces' commands: it
  takes the newest command whose `workspace` is `ws` or none (tags, push,
  pull, remotes: repository-wide). An agent working in its own workspace
  never moves a human's undo. The undo is a **3-way revert**,
  `oplog::revert_views(base = the undone operation's view, revert = its
  parent's, current)`: what the undone command changed goes back, what
  every other operation changed since stays; the reverting side wins what
  both changed, a removal included (undoing `ws new` removes the
  workspace again, and is refused, as before, if it holds edits recorded
  since). It is computed inside the undo's own transaction, from its base
  view, so a command that lands meanwhile is never reverted by accident.
  Redo reverts the undo the same way. With no other workspace's operation
  since the target, the result is exactly the old "restore the parent's
  view", and the jj-model property keeps passing; a second property adds an
  actor committing in another workspace between the first actor's commands
  (`two_actor_undo_keeps_other_work`). `vl undo --op ID` undoes one
  operation; `vl op restore ID` restores a whole view, and refuses without
  `--force` when other workspaces recorded operations after `ID` (their
  work would leave the view; it stays in the op log).
* **Commit and tags.** `vl commit` (`Repo::commit`) moves the tags that
  pointed at the working copy's first parent to the committed change, so
  `main` follows commits made on it. `vl commit --no-advance` moves no tag,
  and an annotated release tag never moves. The CLI names the tags that
  stayed and how to move them. (Formats 7 and earlier had cloaked lines of
  work, on which only cloaked tags moved, BUG-075.)
* **Transactions auto-rebase.** Rewrites and abandons go into a
  `rewritten` map. On commit, every visible descendant is rebased in
  topological order with a 3-way tree merge (`Repo::rebase_tree`):
  `base` = the merge of its old parents, `ours` = the merge of its new
  parents, `theirs` = its own tree. `vl rebase` moves its source the same
  way. A merge one of whose parents moved is thus re-merged, as Jujutsu
  does, never rebased by the moved parent's diff alone, which would drop
  what its other parents hold (BUG-251). Conflicts of the new parents' own
  merge are recorded when their markers reach the result unchanged.
  Tags and workspaces are then re-pointed, and an abandoned working copy gets
  a fresh empty change. Empty, undescribed working-copy changes you move away
  from are abandoned automatically.
* **Rewrites that change nothing change nothing.** `Transaction::rewrite`
  keeps the old snapshot (and its signer) when the new one differs only in
  predecessors, timestamp or signature; `vl rebase` onto the parents a
  change already has, and `vl describe` with its current message, record no
  operation (BUG-246). A parent named twice (`vl new X X`, `vl rebase -d X
  -d X`) is recorded once, and `vl merge X --into X` is refused (BUG-240).
* **Merging** is tree-level. Identical subtrees resolve by id, and files
  changed on both sides go through diff3 (`diffy`).
  * **Bounded text work** (`textmerge.rs`, BUG-484). diffy's Myers diff
    costs `(N + M) · D` for `D` differing lines, with no limit, so every
    diff and three-way merge goes through `textmerge` (`merge`,
    `create_patch`), which first measures the cost by running diffy's own
    algorithm with a step counter (and a linear lower bound on `D` that
    rejects full rewrites at once). Within 4 Mi steps plus 128 per line
    (and 8,192 edits), diffy computes the result, unchanged; past it, a
    merge is one conflict holding every side whole between the lines all
    three share at the start and end (the layout diffy would give such a
    conflict, so it parses back the same), and a diff is one hunk
    replacing the differing middle. Both are correct, only coarser, and
    the cost of any input is linear: a merge of two rewritten 20,000-line
    versions takes 30 ms in a debug build instead of 50 s, and the worst
    crafted input (reordered lines) about 0.5 s.
  * **First-class conflicts** (repository format 4, `conflict.rs`). A file
    that does not merge becomes a tree entry of kind `conflict` naming a
    conflict object: the versions involved as Jujutsu records them, an
    alternating sum of adds and removes (`ours − base + theirs`), each
    version a file entry without its name (id, executable bit, visibility)
    or "no file". Nothing is written into content. Merging
    flattens its inputs (any of which may be a conflict) into one sum,
    cancels equal adds and removes, and takes jj's trivial resolution (one
    add left, or every side made the same change); only then does it try
    diff3 by content (every version readable text, each further side
    merging cleanly into the result so far). So rebasing a conflicted change
    onto a parent that already holds its change, or back where it was,
    resolves it, and rebases and auto-rebases carry conflicts instead of
    stopping. A modify/delete conflict is a sum with a "no file" side.
    Versions are recorded with their verified sealing (BUG-103), so a
    forged label is not carried into a conflict.
  * **Materialisation** (`conflict::materialize`) happens only when a file
    is written or shown: checkout, `vl cat`, `vl restore`, a tree view, a
    diff, a snapshot comparing an edited copy. What only
    describes a conflict (`vl status`, `vl ls`, `vl resolve --list`, the
    JSON output, a checkout's executable bit) uses `conflict::inspect`,
    which reads every version but never merges their text (BUG-484);
    `vl ls` reports no size for an unresolved conflict. It
    renders for one audience (§4 rule 5): two readable text sides get
    diffy's diff3 markers (`<<<<<<< ours`, `||||||| original` when the base
    is shown, `=======`, `>>>>>>> theirs`, longer than 7 characters when a
    line of the content already starts with as many marker characters);
    more sides, or a side this reader cannot read, get every side whole in
    one block, an unreadable side as a `(not shown: …)` line; modify/delete,
    binary content and two scopes show one side as it is, without markers.
    A copy written while a side was unreadable is recorded in the
    materialisation record (`Materialised::from_fallback`), so it is not
    taken for an edit and is rewritten once
    the side becomes readable.
  * **Snapshots** (`Builder::conflict_entry`): a copy exactly as checkout
    wrote it keeps the conflict entry. The stat cache notes a copy found to
    be the conflict's rendering (under the reserved name `:conflict`), so
    an unchanged copy is not rendered again to compare. Markers removed (or no longer
    parseable): a resolution, built as an edit of the side that decided the
    materialised file's audience, so every rule for edits applies (scanning,
    sealed content keeping its audience, held-back edits). Markers partly
    edited but parseable: still a conflict, its sides parsed back from the
    copy as jj does (text outside the markers belongs to every side; a base
    that was not shown is empty there, BUG-127), each sealed as a
    resolution would be; a copy that simplifies (both sides edited to the
    same text) is recorded as it is. More-than-two-sided copies are not
    parsed back: any edit resolves them as the file is. A reader who cannot
    read every side cannot resolve: an edit is held back
    (`cloak_failures`), a deletion carried. Deleting the file otherwise
    resolves the conflict as a deletion.
  * **`Snapshot::conflicts`** stays the list `vl log` and `vl status` read.
    From format 4 every snapshot a transaction writes gets it as an index
    (`Transaction::indexed`, `conflict::index_conflicts`): the conflict
    entries of its tree, found by a tree diff from the snapshot it was
    derived from (the one it rewrites, else its first parent), plus the
    older kinds the operation carried (marker conflicts from before the
    upgrade, files moved aside by a file/directory conflict), less those
    resolved since. A change on top of a conflicted merge therefore holds
    the conflict too (`vl status` says which parent recorded it); an empty,
    undescribed change that only inherits conflicts is abandoned like any.
  * **`vl resolve PATHS --ours|--theirs|--base|--side N`**
    (`Repo::resolve_conflicts`) replaces conflict entries of the working
    copy by one version exactly as recorded (no content is read or sealed,
    so a version keeps its audience); `vl resolve --list` lists them.
  * **Below format 4** (marker conflicts an upgraded repository still
    holds), conflicts were written as markers into the file and recorded on the snapshot until the file is
    edited, as before; a conflict entry such a merge meets is replaced by
    its file of markers first (refused when a version cannot be read).
    `vl merge` records them on the merge and continues on a new change on
    top, so `vl status` lists the conflicts of `@` and those of its parents
    whose file `@` has not touched yet.
  * **Merge base.** Each further parent is merged into the result so far
    against the merge base of the parents merged so far and that parent
    (`Repo::merge_bases`: common ancestors that are not ancestors of another
    common ancestor). After a criss-cross merge there are several; they are
    combined into a **virtual merge base** (`Repo::merge_base_tree`),
    recursively against their own merge bases, as Git's recursive/ort
    strategies do. Where the merge bases disagree, the virtual base keeps
    their common ancestor's version (for text, per conflicting hunk), so two
    earlier resolutions that disagree conflict again rather than one being
    taken silently (BUG-244). Git writes conflict markers into its virtual
    base instead; with a line diff3, those markers line up with one side's
    resolution and let it win.
  * **File/directory conflicts** keep both sides (BUG-243): the directory
    keeps the name, and the file moves aside to `NAME~ours` or
    `NAME~theirs` (the side it came from; `NAME~theirs~2`, … if taken).
    Both paths are recorded as conflicted. Two directories (or two files)
    merge as such even when the base had the other kind at that name.
  * **Renames are followed** (`merge::follow_renames`, Git-parity feature
    2). Before the directory walk, renames base → ours and base → theirs
    are detected with `rename::detect` (exact, then inexact within its
    limits; copies are not followed), but only when one side deleted a
    file the other side changed and added a file: most merges skip
    detection entirely. A rename the other side cares about is applied to
    the trees that did not make it (the base, and the other side when it
    edited the file), so the walk merges the versions at one path: an
    edit follows a rename, and two identical renames merge there. A rename
    onto a name the other side took (rename/add), or one that needs a
    directory where the other side has a file, is not followed. In a real
    merge, rename/delete is a conflict entry at the new name (the renamed
    version against no file), and rename/rename to two names a conflict
    entry at both (each holding its side's version against no file, so
    `vl resolve --ours|--theirs` on both keeps one name); below format 4
    the files stay and are flagged. A virtual merge base follows renames
    too (criss-cross merges). `VEIL_MERGE_RENAMES=0` turns it off.
    *Audiences* (§4 rule 5, design 2's threat review): detection reads as
    a public mirror does (`Reader::Public`), so the inexact pass reads
    plaintext only and sealed content pairs only by exact object id (an
    equality any reader of the trees sees). The result never depends on
    the merger's keys, and a merger without a key never reads a sealed
    version (an exact rename of it resolves trivially). A pair is kept
    only when both versions have the same kind and the same *verified*
    audience (labels are claims, BUG-103), so content never moves between
    a public file and a sealed one, or between scopes. The pairing only
    chooses which entries are combined; `merge_file`'s rules decide the
    result's sealing as for any file. Renames are reported (`MergeOutcome::renames`, printed by
    `vl merge`, `vl rebase`, `vl cherry-pick`), never stored. Directory
    renames (Git `ort`'s detection of files added into a renamed
    directory) are not followed.
* **Shaping history: `vl split` and partial `vl squash`** (`selection.rs`,
  `hunks.rs`, `Repo::split`, `Repo::squash_into`). A change from its base
  (the merge of its parents) to its tree is listed as *units*: one per
  changed file, or one per file/directory swap (a file replaced by a
  directory of that name, or the reverse, whose halves cannot be taken
  apart). A *text* unit offers its hunks (exactly `vl diff`'s hunks, so
  scripts number them from `vl diff --json`), each hunk's *blocks* (runs of
  edits separated by unchanged lines: the picker's `s`, a spec's `N.M`) and
  its executable-bit change; every other unit is *whole* and is moved as
  recorded, never read or resealed. A selection gives two trees on the
  base: the base with what was chosen, and the base with the rest
  (`selection::halves`), each file being the old text with the chosen
  blocks applied, byte for byte.
  * **Split** writes the first change (chosen tree, the original's
    parents and cloak, a new change id, `-m`'s description) and rewrites
    the original onto it with **its tree unchanged**. The remainder keeps
    the change id and description, as in Jujutsu: it is the change being
    worked on (when it is `@`, nothing on disk moves), its tags and
    descendants follow it through the rewrite map, and nothing needs a
    rebase, because a snapshot holds a full tree, not a diff. The first
    part is the new, smaller piece, which is what the user names and
    describes. A split that leaves either part empty is refused: an empty
    first part is `vl new REV-`, an empty second part `vl describe`.
  * **Squash** moves the chosen part into the destination. Into the
    parent: the parent gets the chosen tree, the source keeps its tree.
    Into an ancestor: the chosen part is merged into it, the changes in
    between are rebased (in the transaction, `Transaction::rebase_now`),
    and the source is then set back to its own tree (it held everything
    already). Into a descendant: the source gets the rest, the changes in
    between are rebased without the chosen part, and the destination keeps
    its tree. Into an unrelated change: the source gets the rest and the
    chosen part is merged into the destination. A source left with nothing
    is abandoned and its description joined, as a whole squash always did;
    otherwise both keep their descriptions.
  * **Audiences** (§4 rule 5). Hunks are offered only when the reader can
    read both versions (a version it cannot read makes the file whole:
    nobody chooses lines they cannot see), both labels are verified against
    their objects, and the new version's audience holds the old one's (old
    public, or sealed exactly as the new). A file in between holds lines
    of both versions and is sealed exactly as the new one, so a hunk of a
    sealed secret stays sealed for its scope in both halves; a half equal
    to a version is
    that version's entry itself. An exposure or re-key, `.veilpolicy`,
    conflicts (entries, and older marker conflicts), binary and non-UTF-8
    files are whole. A conflict therefore moves whole, keeping its
    entry and its place in the conflict index; it cannot be split by hunk
    (resolve it first).
  * Each is one transaction: `vl undo` restores the view exactly. A
    selection is made before the transaction (an interactive pick can take
    minutes), so the transaction re-checks that the change and destination
    are still in the history and unchanged, and refuses otherwise.
    A property test (`veil-core/tests/core_engine/split_squash.rs`) checks, over random
    edits (text, binary, adds, deletes, executable bits, sealed secrets) and
    random selections, that the halves are the selection and its complement,
    that every entry keeps one of its versions' audiences, that squashing
    the halves together gives the original tree, and that undo restores the
    view. Another (`vl/tests/adversarial7/rewrites.rs`) runs random
    sequences of squash, split, rebase, restore and resolve through the
    binary, publishing every change to a public mirror after each command
    and searching the mirror's decoded objects for every secret written.
* **Copying changes: `vl duplicate` and `vl cherry-pick`**
  (`duplicate.rs`, `Repo::duplicate`, `Repo::cherry_pick`). A copy is a new
  change (new change id, the source's author as a claim, the time of the
  copy), signed by whoever copies it. Its tree is the auto-rebase merge of
  the source onto the new parents (`Repo::rebase_tree`), so a copy of a
  merge applies what the merge changed, conflicts are recorded as entries,
  and renames are followed. Without a destination a copy sits beside its
  source; a source whose parent is copied too goes onto that parent's
  copy. `vl cherry-pick` copies its sources one after the other onto `@-`,
  rebases `@` onto the last copy, and moves the tags at `@-` as `vl commit`
  would (`TagKept` rules; never an annotated tag). One transaction: `vl
  undo` restores the view exactly. *Audiences:* a copy is a tree merge
  only: sealed secrets keep their sealing on any line (`-x` appends its
  origin line to the description). A source an unreleased embargo withholds
  (`remote::embargo_withheld`) is refused unless every new parent is
  inside the same embargo, and an unreleased embargoed merge is refused:
  a copy elsewhere would publish the fix's names before the release (the
  same route through `vl restore --from` is BUG-681).
* **Visibility never silently widens.** Publishing a sealed secret is an
  explicit act by a member (`vl expose --force`, which turns off the secret
  scanner for that path). It is never a side effect:
  * a file merged by diff3 keeps the sealing of whichever side is sealed
    (ours first). This matters for auto-rebase, where "ours" is the new,
    possibly public, parent;
  * `vl merge` (`embargo::normalize_tree`) may seal content, but never
    re-keys sealed content or makes it public;
  * a merged `.veilpolicy` that would change the audience of existing
    sealed files (`prod/.env cloak ops` → `prod/.env cloak opz`, or →
    `public!`) is **not taken**. The destination's policy is kept and `vl
    merge` warns. Applying it is a deliberate edit on the destination. So
    a pull request that only edits the policy cannot re-encrypt files to a
    scope its author controls;
  * a squash keeps a recorded conflict only if the squashed change left the
    file untouched, or has the conflict itself;
  * the builder rule above (sealed content keeps its audience) covers
    working copies.

## 6. Workspaces

A workspace is only a named pointer in the view. It owns no directory.

* The **project directory** is attached to one workspace at a time.
  `.veil/local/checkout.json` records which workspace and which snapshot were
  last materialised, which gives *stale working copy* detection. If the view
  moved underneath the directory (an undo, another process, an interrupted
  command), any local edits are saved as their own change before catching up.
  Nothing is lost. The snapshot itself is checked against the pointer
  under the repository lock (`SnapshotOptions::expected_wc`): if another
  process moved the workspace between the session's look and the
  snapshot's transaction, nothing is recorded and the session looks again,
  so a directory is never recorded into a working copy it was not checked
  out from. Looking again re-reads the checkout record too (BUG-362).
  A session looks up to ten times, backing off between looks (5 ms
  doubling to 200 ms, with jitter, about a second in all), before it gives
  up with "the working copy keeps moving under this command": each lost
  look means another command really moved the workspace, so only that many
  commands running at once in the same directory can exhaust it (three
  looks were too few for a handful of concurrent `vl new` and `vl describe`
  under load).
  A view that moved *with* the directory is not a stale directory: another
  command recorded it (or moved `@` to the same tree, `commit`, `new`) and
  has not rewritten `checkout.json` yet. `Ctx::directory_holds` checks that
  every change from the recorded snapshot to `@` is already on disk; if so
  the directory is taken to hold `@` and edits are recorded into it,
  instead of being moved into a side change and out of the directory
  (BUG-361).
* **Moving the directory is journalled** (`working_copy.rs`,
  `Repo::move_working_copy`). Before checkout touches a file, the target
  workspace and snapshot are written to `checkout.json` as `pending`;
  afterwards the record says the directory holds the target. A command
  killed in between (or a checkout that fails half way) leaves "somewhere
  between `snapshot` and `pending`", and the next command finishes the move
  (`Repo::resume_working_copy`) before it records anything. Checkout only
  writes a file that still holds what `snapshot` put there or already holds
  the target, and keeps anything else, so running it again from `snapshot`
  is deterministic. The directory belongs to the pending workspace from the
  moment the journal is written. Before this, `vl ws switch` (whose
  attachment exists only in `checkout.json`) could be interrupted after
  replacing files, and the next command recorded the mix into the workspace
  it was leaving (BUG-113). The crash harness sweeps `ws switch` across
  every write (`crash_during_workspace_switch`). gc keeps the pending
  snapshot as well as the materialised one.
  **Checkout's files are durable before the record says so** (BUG-818):
  each file is staged beside its path, one barrier makes every staged file
  durable, they are renamed into place, a second barrier makes the names
  and the checkout's removals durable, and only then does checkout return
  and the caller save `checkout.json`. Whenever the power fails, each path
  holds its old version or its complete new one, never a torn file that a
  snapshot would record as an edit. A failed barrier (EIO) fails the
  checkout with the move still pending; finishing it rewrites every file
  that already holds the target, since an earlier write may never reach
  the disk. Staged copies a crash leaves are temp names snapshots ignore,
  and finishing the move removes them. Swept by
  `crash_during_workspace_switch` (power loss tears staged copies) and
  `eio_during_workspace_switch` (each barrier fails in turn).
* **Checkout never deletes what it did not write.** A file is overwritten
  or removed only if it holds what `from` put there. A directory where the
  target has a file is removed only once checkout has emptied it (a
  directory holding an isolated `private/notes.md`, an ignored build tree,
  untracked work, even only a symlink, is left as is); a file where the
  target has a directory (a quarantined `cfg` where the tree has
  `cfg/settings.json`) is kept too. Both are reported as
  `CheckoutReport::obstructed` and the paths they stand in the way of are
  not written; the next snapshot records the directory as it is, as for a
  kept local edit (BUG-110, BUG-111). Before this, the first case ran
  `remove_dir_all` on never-recorded content and the second failed the
  checkout half way, after the view had moved, bricking every command.
* **`vl watch` re-reads the pointer every tick** (`Ctx::refresh`). One
  long-lived session judged the directory against the pointer it read at
  start, so after another command moved the working copy it "recovered"
  the user's new files into a stray change and removed them from disk
  (BUG-117). When the directory is behind the view (another command has
  moved it and may still be checking it out), the watcher yields; only if
  it stays behind for 10 s (or two intervals) does it recover it as any
  command would.
* **What was materialised from what.** `checkout.json` also records
  (`checkout::Materialised`) the files checkout left out because this reader
  could not read them (no key for their scope yet), the conflicts it wrote
  with a side it could not read, and, for a one-directory clone, the tree
  actually materialised. When such content becomes readable (`vl scope
  grant` + `vl pull`), the next command fills it in before snapshotting,
  and again at its end, so a grant that arrives during the command shows at
  once. Local edits are never overwritten. Without the record the next
  snapshot would see the files as deleted. The builder also consults it (`BuildOptions::materialised`): a
  file that was never materialised is never recorded as deleted. The
  clone-then-grant onboarding flow depends on this.
* **`vl commit` is one operation.** It records the project directory and
  commits it in one transaction (`SnapshotOptions::commit`,
  `commands::commit_in`, `Ctx::commit`): one op-log entry, half the
  journal commits of a snapshot followed by a commit. `vl undo` takes back
  both (the edits the commit recorded leave `@` and the directory; `vl
  redo` brings them back). With pre-commit or commit-msg hooks the
  directory is recorded first (the hooks read `VEIL_SNAPSHOT`), as its own
  automatic snapshot; a stale directory's recovery is also its own
  operation.
* **Commands that edit the working copy are operations of their own.**
  `vl expose`, `cloak`, `isolate`, `ignore` and `restore` write files and
  record the result under their own operation description, not as the
  automatic snapshot that `vl undo` skips as "the user's uncommitted
  edits". So `vl undo` reverts them (an accidental `vl expose` above all),
  and edits made after them are kept as usual.
* **Undo and commands outside the view.** An operation may carry
  `manual_undo`: its effect lies outside the view (a key ring, the remotes
  in `repo.json`, the local vault, the accepted policy, the directory's
  attachment), so restoring an older view does not revert it. `vl scope
  create|grant|revoke|rotate`, `vl remote add|rm`, `vl secret
  set|rm|import`, `vl policy accept` and `vl ws switch` record such an
  operation (`Repo::record_outside_view`, `Repo::record_workspace_switch`).
  `Repo::undo_keeping_edits` refuses to undo one and returns its
  instructions, instead of skipping it and undoing an unrelated, earlier
  operation (BUG-116); `vl op restore` warns about each one it passes. A
  switch is the exception the CLI can reverse: `vl undo` of `vl ws switch`
  switches back (recorded as a switch with `undo_of`, so the next undo goes
  further back), and `vl redo` switches again, so undo never undoes the
  automatic snapshot of the workspace just left, which held that
  workspace's last edits (BUG-100). A property test drives random
  switch/edit/commit/undo/redo sequences through the binary and checks that
  no edit is ever lost.
* **Virtual workspaces** (`vl ws new`) exist only in the DAG. They are edited
  through overlays (`vl ws write`), materialised into a throwaway directory
  for one command (`vl ws exec`), or attached to the project directory
  (`vl ws switch`). Two tasks can never fight over a directory.
* **Links in sandboxes** (symlinks design, threat 7; BUG-708, BUG-709).
  `SandboxFs` materialises a tree's symlink only when it provably resolves
  beneath the sandbox root whatever other links the tree holds
  (`vfs::sandbox_link_check`): its target is relative, made of `..`
  components first and names after them only (`../../lib/tool.sh`, never
  `lib/../tool.sh`), and the `..` components do not climb above the root.
  Every link sits in a real directory at its own depth (writes never go
  through a link), so the leading `..` climb real directories, and each
  later name is a real entry or a link obeying the same rule; a `..` after
  a name is what a chain needs (`u -> ../../../..` and `x ->
  u/../../../../../.env` are each lexically inside, together they reach
  the project's isolated `.env`). Absolute targets are never materialised:
  what they name depends on the reader (`/proc/self/cwd/../../.env` is
  the sandbox itself, then the project), so a lexical check of them proves
  nothing; the project directory and `$VEIL_HOME` (given by the CLI) are
  only named in the message. Checkout reports it `failed`, so the materialisation record keeps
  it hidden and recording the run carries the link; full, `--only` and
  `--ephemeral` sandboxes and `vl bisect run`'s alike. A mounted workspace
  (`vl ws mount`) serves links as they are, as the project directory holds
  them: it is the user's own view of the workspace, with no promise to
  keep the project's isolated files from what runs in it. Reflink clones are made in the
  destination's directory opened without following links.
* **`ws exec` sandboxes** (`veil_core::sandbox`, `vfs::SandboxFs`, the
  CLI's `sandbox.rs`). Each virtual workspace has one persistent sandbox,
  `.veil/local/sandboxes/<ws>/` (`0700`; `.` and `..` are spelt `%2e`,
  `%2e%2e`): `files/` (the command's working directory), `manifest.json`,
  `statcache`, `lock`, and `guard.sealed` once secrets were injected. The
  **manifest** says which tree the files are
  (`tree`: synced to, then recorded as), the materialisation record
  (`Materialised`, as for the project directory), the boot they were
  written in, a `running` marker (a run is syncing), a `pending` record
  (the files hold a command's output that is not recorded yet), the
  quarantined files the last run left, `guard_checked`, and `only`, the
  paths of a sparse sandbox (`None`: the whole tree). The
  per-file half of the manifest is the sandbox's own stat cache: blob id
  and stamp (size, mtime, ctime, inode, executable bit) of every file.
  A run:
  1. takes the sandbox's `flock` (a second run in the workspace waits) and
     reloads the view;
  2. decides whether the sandbox can be trusted (`rebuild_reason`): no
     manifest, an unreadable or other-version one, another workspace's, a
     `running` marker left by a run that died in its sync, another boot
     (sandbox files are never fsynced, so after a power loss they may be
     torn), an invalid `only` path, a tree gc removed, `files/` missing or
     replaced (a symlink). Any of these: rebuild. **A rebuild never
     deletes unrecorded work** (`set_aside`, BUG-548): quarantined files
     and files outside a sparse set that the tree does not have as they
     are are copied back into the rebuilt sandbox (`reimport`); when other
     files differ from both the previous tree and the new one (hand edits,
     or torn files: Veil cannot tell them apart), when the manifest cannot
     be read, or when it records a `pending` run that cannot be recorded
     (another boot), the previous files are moved whole to
     `unrecorded-<ms>-<rand>/` with a warning (`vl doctor` lists these, `vl
     ws rm` refuses without `--force`). What goes is the tree's own
     content, ignored and isolated output, and injected files. A trusted
     sandbox whose manifest records a `pending` run is not rebuilt: that
     run's output is recorded first (steps 7 to 9, from the manifest and
     the guard file), then this run goes on. `--record-only` stops there;
  3. writes `running` and the boot durably;
  4. **syncs**: `checkout_recorded` from the manifest's tree to the
     workspace's, with the sandbox's stat cache, so only the diff is
     touched and every checkout rule holds (files that hold something else
     are kept and reported, nothing is written through a symlink). Writes
     go through `SandboxFs`: atomic but unsynced, and, where the project
     directory's stat cache vouches that one of its files holds the
     object, a copy-on-write clone of it (`StorageBackend::clone_known`:
     `FICLONE` on Linux, `fclonefileat` on macOS; the source is fstat'ed
     before and after the clone, and the first `EOPNOTSUPP`/`EXDEV`
     switches cloning off for the run);
  5. **vouches** for the public files it just wrote (`vouch_written`):
     their content ids are known, so if waiting out the stat cache's racy
     window costs less than re-reading them it waits, re-stats them, and
     records those whose stamp did not move. Sealed secret files
     are left to the builder, which verifies their sealing (BUG-103);
  6. with `--with-isolated`, plans the injection (never through a symlink
     or over a directory; what each path holds now is the stash), adds the
     files to the sandbox's **guard** and saves it with the planned
     injection, durably (`guard.sealed`, sealed under `local`), starts the
     reaper and tells it on its pipe what it injected (path, blob id,
     stash), then writes the files. It then writes `pending` (the run, the
     snapshot synced to, `-m`, the start time, the files outside the set)
     and clears `running`, durably: **from here on the files are the
     command's output and are never wiped**. It runs the command with
     `GIT_CEILING_DIRECTORIES` set to the sandbox (and `find_root` never
     resolves a repository from inside `.veil/`), with SIGINT/SIGQUIT
     ignored by `vl` and SIGTERM/SIGHUP forwarded to the command (BUG-550),
     so they stop the command, not the recording. **On Linux the command
     is confined** (`confine.rs`, `docs/design/scale/9-confinement.md`):
     `bwrap` binds the sandbox at the project's canonical path, the
     system read-only, an empty tmpfs `HOME` and `/tmp`, the allow-list
     through overlays whose upper layers are the workspace's own
     (`.veil/local/sandboxes/<ws>/layers-<hash of the workspace's id>`, thrown away with
     `--ephemeral` or `--with-isolated`; the real folders are never
     written, BUG-1025), and a tmpfs over the Veil home (and over the Veil home
     and the project under every other name an allowed link gives them,
     BUG-848), in new user, pid, IPC and UTS namespaces
     (`--disable-userns`, `--die-with-parent`, `--new-session`; `vl` arms
     the parent-death signal itself before the exec, BUG-851). `vl`
     checks it with a run of `true` before step 1 touches anything.
     Limits go through a systemd user scope (`systemd-run --scope`,
     with `--expand-environment=no` where it knows it, execs `bwrap` in
     place; every `systemd-run`
     and `systemctl` call has a 5 s deadline, BUG-849/850) or
     `RLIMIT_CPU` and polling; `vl` and the reaper are outside them. `bwrap` has its own
     process group and the command no terminal, so `vl` forwards
     SIGINT/SIGQUIT to the command's process group and SIGTERM/SIGHUP to
     the command, through a pidfd;
  7. records with `expected_wc` = the snapshot it synced to, through
     `PolicyPin` (the recorded `.veilpolicy` when the sandbox's is not a
     regular, readable file), as the command's output
     (`policy_from_command`: an edit of `.veilpolicy` that weakens the
     recorded one is held back, §4, BUG-560) and with the guard of every isolated file
     ever injected into the sandbox (not only this run's: BUG-547). If the
     workspace moved meanwhile, the result is saved as a child of that
     snapshot instead of reverting the move. The snapshot it was recorded
     as goes into `pending` at once (durably), so a cleanup that fails
     later is resumed without recording twice. A recording that fails
     (the repository lock busy past its 15 s wait, BUG-551) leaves
     `pending` as it is: the error says the output stays;
  8. cleans up: injected files out again (`remove_injected`: each
     injected path, and each file quarantined by the injected-secret
     guard, gets what the snapshot recorded there if that is new, else
     what was there before the injection, else the recorded version, else
     nothing); for a sparse run, the strays (below); then, in a sandbox
     with a guard, `scrub`: every file changed since the last check
     (ctime ≥ `guard_checked`, or this run's start), wherever it is
     (ignored, isolated, outside the set, nested repositories, names that
     are not UTF-8) and not vouched for by the stat cache, is read, and
     each one holding an injected value is put back to its recorded
     version or removed (BUG-546). The guard's saved injection is then
     dropped;
  9. writes the manifest without `pending` (and the new `guard_checked`),
     saves the stat cache, tells the reaper it finished (`K` on the pipe)
     and releases the lock.
  **No failure path deletes unrecorded output.** An error (or a panic)
  before step 6 leaves `running`: the next run rebuilds, keeping
  unrecorded work as above. After it, `pending` stays until steps 7 to 9
  are done, by this run or the next one (or `--record-only`). If `vl`
  dies, the reaper (the `vl` binary re-executed, in its own process
  group, waiting on a pipe only `vl` holds) takes the lock and, if the
  manifest still names the dead run, takes out each injected file that
  still holds exactly what was injected (putting back the stash); it
  touches nothing else. **Background processes** the command leaves
  running are not killed (a dev server is often the point): the guard
  that every later recording applies, and the scrub, are what keep
  anything they write out of history and out of later commands' reach.
  `vl ws rm` takes the lock (refusing while a run holds it), refuses
  without `--force` if the manifest lists quarantined files or a
  `pending` run, or a rebuild kept files aside, then removes the whole
  directory. `vl doctor` lists sandboxes, flags interrupted runs,
  unrecorded runs, kept directories and sandboxes of removed workspaces.

  **Sparse sandboxes** (`--only PATH…`, `vfs::SparseSet`,
  `vfs::SparseView`). The paths are resolved by the CLI's path rules
  (`Ctx::repo_path`, BUG-204) and must name something in the workspace's
  tree (so a nested repository, never in a tree, cannot be chosen); the
  set is normalised (sorted, a path inside another dropped, the root
  meaning the whole tree) and always holds `.veilpolicy`, which the
  snapshot needs to classify anything. Step 4 checks out
  `restrict(tree, set)` (the tree with only the set's entries and the
  directories leading to them; new tree objects are written to the store
  as any build writes them) from `restrict(manifest tree, manifest set)`:
  a different set (or none) is the same incremental checkout, adding and
  removing only what differs. Step 7 records a `SparseView` of the
  sandbox instead of the sandbox: inside the set it is the sandbox;
  outside it is a `TreeView` of the synced tree whose `known_id` vouches
  for every entry, so the builder reuses whole directories outside the
  set by id without listing them (it gives `.veilpolicy` its blob id, so
  an unchanged public policy keeps these hints on); directories leading
  into the set are merged (the sandbox's entries that lead in, the tree's
  that do not; a spine directory of the tree stays whatever the sandbox
  has in its place, so removing it in the sandbox deletes only the set's
  files under it, BUG-552). Everything the builder decides (policy, sealed
  secrets, conflicts, quarantine) is decided as for a full working copy
  whose files outside the set did not change: a policy edit, or a scanner
  upgrade, turns the hints off and the builder reads the outside files
  from the tree to reclassify them (slow, exact). A superseded run (step
  7) saves the same view as a child of the snapshot it started from.
  In step 8, `strays` lists the files the command wrote outside the
  set that a full snapshot would record (ignored or isolated by neither
  the policy the command started with nor the one it left, BUG-549; not a
  nested repository, special file or crash debris, not quarantined by an
  earlier run); they are reported, never recorded, and removed from the
  sandbox (with the directories that leaves empty), so a later, wider set
  never mistakes them for workspace content. The same listing taken
  right after the sync (before injection) names what was outside the set
  before the command ran: hand edits in the sandbox, and files a narrower
  set's checkout kept because they held something else. Those are not
  the command's output: they stay, unrecorded, reported on every run,
  until a run whose set holds them records them. Quarantined files of earlier
  runs that a narrower set leaves outside stay, and stay in the manifest
  for `vl ws rm`'s guard. `--with-isolated` injects every isolated file,
  inside the set or not: they are what the command runs with (`.env` at
  the root), not what it edits, and outside the set nothing is recorded
  anyway; the injected-secret guard and `remove_injected` work unchanged.
  `--ephemeral --only` checks out `restrict(REV's tree, set)` and records
  a `SparseView` the same way.

  `--ephemeral` runs use a throwaway directory instead, created `0700`
  under `$TMPDIR` and restricted to the user before the command runs, and
  removed when `vl` exits (by `vl`, by the reaper, or by the next `ws exec`
  sweeping sandboxes whose owning process, the pid in the name, is gone).
  The command's stdout is its own: `vl` reports on stderr.
* **Mounted workspaces** (`vl ws mount`, `crates/vl/src/mount.rs`; the
  file system in `mount/fs.rs`, the FUSE adapter in `mount/fuse.rs`). A
  workspace served as a directory through FUSE (the `fuser` crate, pure
  Rust on Linux: mounting goes through `fusermount3`; macFUSE on macOS,
  opt-in feature `macfuse`). `vl` is built with the `fuse` feature by
  default; without it, or without `/dev/fuse`, the command says so and
  nothing else changes (the mount tests skip themselves).
  * *Layers.* `MountFs` serves an `OverlayBackend` whose lower layer is a
    `ReaderView` of the snapshot `base` and whose upper layer is a
    `DiskBackend` on `.veil/local/mounts/<ws>/upper` (`0700`). The
    `ReaderView` is a `TreeView` that shows exactly what checkout would
    write for this reader (§4 rule 5): an entry it cannot read is absent
    for `lookup`, `stat` and `read`, not only for `readdir` (a `TreeView`
    answers `metadata` for every entry); a directory holding nothing it
    can read is absent (checkout would not create it); conflicts are
    materialised with markers for this reader. A non-member never
    receives sealed bytes: they are never decrypted, and a redacted
    conflict is all there is to read. The `ReaderView` is built
    again with the repository's current keys every time the server looks
    at the workspace (every second, and before every recording), so a
    grant pulled meanwhile shows in the mount, and a
    recording always judges what the mount shows with the keys the builder
    uses (BUG-534).
  * *Requests.* `MountFs` is the whole file system in terms of inode
    numbers, handles and errno (so it is unit-tested over
    `MemoryBackend`s, without a kernel); the adapter only translates.
    **Open files live on disk** (BUG-561): the first write or `truncate`
    of a file only the lower layer has copies it up into the upper layer
    (durably: temp file, fsync, rename), and from then on reads and
    writes go straight to that upper file, opened in place
    (`mount::fs::UpperFiles`, `DiskFiles`: `O_NOFOLLOW`, `pread`/`pwrite`,
    `ftruncate`), synced on `flush` (every `close`), `fsync` and `release`.
    A `truncate` is a hole, so a sparse file costs nothing until data is
    written, and memory never grows with a file's size; a file only the
    lower layer has is read once while it is open (one decryption per
    open). A file unlinked while open keeps its content for its handles
    (the open descriptor). A crash can leave an upper file part-written,
    as any file system can a file being written, but never a torn
    copy-up. No file grows past the largest object Veil records
    (`VEIL_MAX_OBJECT`, 4 GiB): a larger `truncate` or write offset is
    `EFBIG`, and a panic in a request fails that request with `EIO`; the
    mount and the other open files go on (BUG-536). Deletions append a whiteout to the journal
    `.veil/local/mounts/<ws>/whiteouts` before they take effect, so a
    crash can only resurrect a deleted file, never lose one. A whiteout
    that hides files this reader cannot read (a directory deleted with
    files it never showed) first records them in
    `.veil/local/mounts/<ws>/unseen`; every recording passes them to the
    builder as never materialised (`Materialised::hiding`), so they are
    carried, never recorded as deleted, even after a grant made them
    readable (BUG-534). They are forgotten once no whiteout hides them.
    `opendir` takes the directory's listing and `readdir` reads from it,
    so offsets stay put while entries are deleted (`rm -rf`,
    `remove_dir_all`); `readdir` from offset 0 (`rewinddir`) lists afresh
    (BUG-537). A rename
    copies the source (a directory: its whole subtree) into the upper
    layer, then removes it; a file the upper layer already holds is
    renamed in it instead (O(1), holes kept; an open one follows), so only
    files the lower layer alone has are copied. `.veil` cannot be created; a
    symlink is created as it is in format 5 (`EPERM` below it) and served
    as a leaf inode (`readlink`; `MountFs` never resolves a path through a
    link: a lookup below one is `ENOTDIR`, an `open` of one `ELOOP`, so a
    link to `../../.veil/local/vault.sealed` leads nowhere inside the
    mount); hard links and special files are refused (`EPERM`), only the executable
    bit of a mode is kept. No `allow_other` (the kernel keeps every other
    user, root included, out), `default_permissions`, modes `0700`/`0600`,
    `nosuid`, `nodev`; names and attributes are cached by the kernel for
    1 s.
  * *The serving process* (`vl ws mount --foreground`, or that command
    started in the background in its own session) holds
    `.veil/local/mounts/<ws>/lock` (`flock`) for its life and writes
    `state.json` (pid, boot, mountpoint, control socket, `base`). It runs
    the FUSE session in a thread and, in its main thread, answers the
    control socket (`record`, `unmount`, `status`; one JSON line each),
    looks every second whether the workspace moved, records every
    `--record-every` seconds while there are changes, and on SIGINT,
    SIGTERM or SIGHUP unmounts (a second signal: lazily). When the session
    ends (unmounted by `vl ws unmount`, by a signal or by `fusermount -u`)
    it records once more and cleans up.
  * *Recording* is `Repo::snapshot_workspace_with` over the merged overlay,
    with `expected_wc = base`, the path of `vl ws write` and `ws exec`,
    as the operation "record the mount of workspace '<ws>'"
    (`mount_record_op_description`), which `vl undo`, `vl redo` and `vl op
    restore` skip like the automatic snapshot of the attached workspace,
    whichever workspace is attached, carrying what it recorded over
    (BUG-538), as a command's output (`policy_from_command`: an edit of
    `.veilpolicy` that weakens the recorded one is held back and stays in
    the overlay, §4, BUG-560):
    policy, scanner, sealing (the cloaked-workspace rules included),
    isolation and quarantine all apply, and `known_id` hints keep it
    O(changes). Requests wait while it reads the overlay. Afterwards
    (`MountFs::reconcile`) the overlay is put over the recorded tree,
    keeping only what still differs from it: files the recording left
    out (isolated, ignored, quarantined, held back) and whiteouts still
    hiding something. What the mount shows does not change. Triggers:
    `vl ws unmount`; every other `vl` command that snapshots
    (`Ctx::open` asks each live mount over its socket before opening the
    repository, so the command's view includes the mount, as it includes
    the project directory; a mount that changed nothing since its last
    recording answers at once); the timer; the end of the session.
  * *Concurrency rule: the mount follows the workspace.* Refusing every
    command that could move a mounted workspace (commit, describe, rebase
    and auto-rebase of descendants, undo, `op restore`, `ws write`, `ws
    exec`) would be intrusive and still racy, so the mount follows
    instead. When the workspace's working copy is no longer `base`, the
    files that changed between the two trees are compared with the
    overlay (its upper files and whiteouts). No overlap: the overlay is
    put over the new tree as it is (`switch_lower`), and the mount shows
    the other command's change. Overlap (both changed a file since the
    mount last recorded, which the recording before every command makes
    rare): the overlay as it is is first saved with
    `Repo::commit_fs_as_child_with` as a change on top of `base`, the
    overlapping parts are dropped from it, then it follows; the warning
    names the change. Where the overlay already shows exactly what the
    new tree has (the mount's own recording, whose `base` a crash kept
    from `state.json`; the same edit made twice) there is no conflict and
    nothing is saved, so recovery after a crash between a recording and
    `state.json` is idempotent (BUG-539). Nothing is lost either way. Only `vl ws switch` to a
    mounted workspace is refused (the directory and the mount would both
    record into it), and `vl ws rm` while it is mounted. A workspace that
    disappears (undo of its `vl ws new`) gets the overlay saved as a
    change on top of `base`, and the mount unmounts itself.
  * *Crash recovery.* The overlay is on disk, so a dead process loses
    nothing that was closed. `vl ws unmount` finds no process behind the
    socket and the lock free, detaches the dead mount (`fusermount3 -u
    -z`), and records the overlay in-process with the same code; `vl ws
    mount` of the workspace detaches it and serves the overlay as it is,
    after recording it. `vl doctor` and every other command warn about a
    mount whose process died. After an unmount, an overlay that still
    holds files (isolated, ignored, quarantined) stays for the next mount;
    `vl ws rm` wants `--force` for it.
  * *The mountpoint* must be an empty directory outside the project
    directory and outside every other Veil repository (no ancestor holds a
    `.veil`, the rule of BUG-200): the builder walking a repository would
    otherwise walk into the mount and record another workspace's files,
    cloaked ones in plaintext (BUG-535). And whatever repository is made
    around a mount later, `DiskBackend::list_dir_full` lists a directory
    on another device than its parent that is a FUSE mount of a Veil
    workspace (`/proc/self/mountinfo`: type `fuse.veil` or source
    `veil:<ws>`; `statfs` on macOS) as a special entry, like a symlink:
    never followed, recorded or written through.
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
  plaintext, whether the scanner found it clean, and (for sealed secret files)
  which object it seals to under which scope. The builder still classifies
  every path against the current policy every time. A fact is only used where
  the builder would otherwise need the bytes: a public file reuses the
  parent's entry, or the cached blob if it was scanned clean; a sealed secret file
  reuses the cached sealed id for the same scope. Cloak failures and
  quarantined files are never served from the cache.
* **Keyed on policy and keys.** As defence in depth the whole cache is
  dropped when the `.veilpolicy` blob id changes, or when a fingerprint of
  the identity or every scope's key fingerprint changes.
* **Racy mtime.** Each record stores `verified_at`, the clock reading taken
  before the build stat'ed and read the file. A record is trusted only if
  `max(mtime, ctime) + window ≤ verified_at`. A record learnt inside that
  window (a file edited just before the command: every `vl commit` right
  after an edit) can therefore never vouch for anything, and does not by
  itself make the cache rewrite itself (at 10,000 files a 1 MB fsynced
  write). The window is 2 s for
  whole-second stamps (ext3, HFS+, FAT, many network filesystems) and 100 ms
  for sub-second stamps (the kernel's coarse clock, exFAT's 10 ms). On a
  generation clock it is 0. A file written in the same tick it was verified
  is therefore re-read on the next run, which records a later `verified_at`.
  A file with a future stamp is never trusted.
* **Listed ahead** (`prefetch.rs`, performance round 3). On a disk, a
  working copy of more than 250 files (as the cache counted them) has its
  directories listed on up to 7 threads while the walk runs: each listing
  stats its files relative to the open directory (`DirListing::stats`),
  classifies them against the policy, and loads the directory's tree from
  the parent snapshot. The walk takes a listing that is ready, waits for one
  being made, or lists the directory itself; the workers start after the
  run's clock reading and never descend where the walk does not (ignored
  directories, nested repositories, `.veil`). Every listing is one
  observation of the directory taken before its files are read, as the
  walk's own would be, so nothing it decides changes.
* **Checkout invalidates** every path it writes or removes. It does not
  insert records for what it wrote: through the generic backend API it
  cannot stat *the* file it wrote, so a concurrent edit between the write and
  the stat would be recorded under the checked-out content. Written files are
  re-read once by the next snapshot instead.
* **Line endings** (§16). A record of content holding a CR also keeps an
  `EolFact`: a fingerprint of the `.veilattributes` files the path is under
  (a hash of their bytes, so checking it parses nothing), whether `vl
  renormalize` would change the file, and the blob recorded for it when
  that is not the content itself (a CRLF copy of an LF version). `content`
  is always the blob id of the bytes on disk, which checkout's `holds` and
  the sandbox's reflink clones rely on. Such a record is trusted only for
  the same fingerprint and only to keep the parent entry; anything else
  re-reads the file once.
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
Binary trees (format 2) then cut decoding the parent's ~1,200 trees from
12.4 ms to 0.7 ms; on tmpfs a clean status went from 72–77 ms to 58–59 ms
and a one-file edit from 77–99 ms to about 63 ms (FORMAT.md §7). What
remains is mostly the one `lstat` per file and the per-directory
`readdir`. Run the benchmark with
`cargo test --release -p vl --test cli_bench -- --ignored --nocapture bench_status::`.

## 7. Delayed-visibility (embargoed) merges

**Embargoes are permissions, not encryption** (owner, 2026-11-06;
`docs/VISIBILITY.md`). Repository formats 7 and earlier sealed an embargoed
merge under an embargo key behind a wrapper tree, with the pre-merge tree as
the outsiders' view; format 8 removed all of it (FORMAT.md §5). What is left:

`vl merge X --embargo [--until T] [--scope S]`:

1. Creates a plain **embargo record** (`keychain.rs`: `format` 2, `id`,
   `scope`, `until`, `released_at`, `created`), synced like key rings. It
   names the group that may see the fix before release (`S`) and the
   deadline, nothing else.
2. Records an **ordinary merge**: plain files, an ordinary description, its
   conflicts listed as for any merge. The snapshot names the embargo
   (`Snapshot::embargo`).
3. **The merge and the history it brings in are withheld** (§8,
   `remote::embargo_withheld`): the merge itself and every snapshot
   reachable only through its merged-in parents (the fix, and how it was
   made). No push sends them, to any remote, and a tag or a commit that
   builds on them is not pushed either (`push_closure`). The server will
   enforce who may see an embargoed merge before release; until it does, an
   embargoed merge stays on the device (`docs/HUB.md` §13.8).
4. **Release**: `vl embargo release` (previewed and confirmed), or the
   deadline passing (`EmbargoRecord::is_released`). Snapshot ids do not
   change, nothing is rewritten, and the next push carries the withheld
   history.
   * **Staged until it leaves (BUG-109).** `vl embargo release` first
     *stages* the release in device-local state
     (`.veil/local/releases/<id>.json`), never read by a sync. This
     repository treats the embargo as released at once. The next push (to
     any remote) writes it into the synced record just before the record is
     sent (`publish_staged_releases`). Until then `vl undo` right after the
     release deletes the staged release: the embargo is unreleased again,
     and nothing reached any remote. Once published, `vl undo` of the
     release is refused, and changes nothing. `vl op restore` to an
     operation before a staged release takes it back too, and warns about
     published ones; "before" is the op log's, from the restore
     operation's own parents (the `release embargo <id>` operations they
     reach and the restored one does not), never a comparison of times,
     which a clock set back would get wrong (BUG-1400), nor the heads read
     before the restore's transaction (BUG-1404). And a push publishes a
     staged release only if the op log holds it in force (its latest
     `release embargo <id>` operation in the heads' history, not taken
     back by an undo or op restore in force); the others are taken back
     first, and the push names each in a warning with what to run (`vl
     embargo release <id>`): a restore or undo stopped between its commit
     and its take-back cannot publish the release, nor can one an older
     `vl` staged without its operation (BUG-1487). Never silent, never
     early. The check runs at the push only (and in `vl embargo list`,
     `vl embargo release` and `vl show --json`, which never say a release
     the op log took back will publish), not at every open (BUG-1533); gc
     never prunes the operation of a staged release, nor anything newer,
     so the check always finds it (BUG-1532). `vl embargo release`
     records its operation before it stages the release. Redoing the undo of a release is refused: undo and
     redo never release.
   * **Preview.** `vl embargo release` shows the embargoed merge, the
     withheld history it publishes, the tags that carry it and the remotes
     the next push goes to, and asks for confirmation (`--yes` skips it,
     and is required when stdin is not a terminal).
   * **Who may release** is the server's to decide: a record a remote hands
     over is merged as it is (`Keychain::merge_embargo`: a record whose
     scope, deadline or creation differ from the local one's is refused,
     a release it carries is taken). The client no longer judges releases
     against key rings (BUG-108 was that check); rings are for secrets only.

**Nothing copies the fix out (BUG-681).** `confinement.rs` judges every
route that copies content from one revision into another. A snapshot is
*confined* to an unreleased embargo when it is the embargo's withheld
history, or builds on it (what `push_closure` refuses: the extra parents of
the embargoed merge do not count). Content of a confined snapshot goes only
into a change confined to the same embargo: `vl restore --from` checks the
source against `@`, `squash_into` the source against the destination,
`duplicate` the source against the new parents (which must be on the fix
line, not the embargoed one). `Transaction::commit` checks every rewrite
that changed a snapshot's parents: a confined change must still be confined
to its embargo in the view the transaction ends with, so `vl rebase` of
work on the fix onto a public line, or `vl abandon` of the fix under such
work, is refused, while rebasing or splitting the fix itself is fine: the
embargoed merge is rebased with it and the result is still withheld. The
refusals name the change and the embargo only.

**Embargoes never overlap.** `vl merge --embargo` is refused if the line it
merges into, or any line it merges in, already carries an unreleased
embargo (an ancestor, itself included, is an embargoed merge whose embargo
is unreleased, or unknown to this repository). The message names the
embargo: release it first, then merge. Nothing is recorded, not even the
embargo record. Two embargoes may coexist on *separate* lines.

**Trade-offs.**
* Until release, the main line's later commits on top of the merge are
  withheld too (they build on it). Release early, or keep unrelated work on
  another line and merge it after the release.
* Anyone with the repository on their disk reads the fix: an embargo is
  enforced by what `vl` sends and, with the server, by its permissions,
  not by cryptography.
* One unreleased embargo per line (see above).

## 8. Synchronisation

**`vl` pushes and pulls only through the Veil server**, which checks every
permission and sends each person only what they may see (`docs/HUB.md`
§13.5; the client is `crates/vl/src/hub.rs`). Path and SFTP remotes were
removed in the simplification pass, part 1.

* **Pull** asks for the branch tips, the snapshots it lacks, then trees from
  the root down and the files it needs, one request per tree level, never
  sending a list of what it has. What arrives is written through
  `remote::Incoming`: loose below 16 objects, otherwise streamed into packs
  (each `.pack`, a barrier, then its `.idx`, durably), all before the
  pull's operation; every frame is checked against its id on arrival
  (`hub::wire::read_frames`). The branches are then recorded with
  `remote::apply_remote_tags`, with every rule below.
* **Push** uploads the snapshots the server lacks and, of their trees, what
  differs from their parents at the same path, collecting the server's
  upload receipts; then one request moves each branch by compare-and-swap.
  Objects go first: an interrupted push leaves only unreferenced objects
  on the server. `pre-push` hooks run before it (§13).

**The in-process transfer.** `remote::push` and `remote::pull` move history
between two repositories in one process (any two backends). Nothing on the
command line reaches them: the engine's tests use them, with in-memory or
local stores, to check the visibility filters below, and `vl`'s debug
builds use them as a test fixture (`crates/vl/src/test_remotes.rs`, active
only with `VEIL_TEST_PATH_REMOTES`). A push runs under the receiver's lock:
it decides the tags against the receiver's view (a rejected tag's history
is not copied, BUG-288), walks the pushed history object by object, writes
what the receiver lacks with `put_raw` (which re-verifies a copy it already
has), then the operation. A pull walks the sender's tagged history the same
way under the local lock. Filtering
happens *during the object walk*: a public remote never receives sealed
objects, and nothing is ever transferred under the `local` scope. Metadata follows
(`sync_meta`): key rings and team-vault records go to team remotes only
(§3, "The team vault"), and embargo records go everywhere. Isolated content cannot
be pushed at all, because it was never in the graph. A conflict
object (format 4) is plaintext and travels with its entry; the walk then
visits every version it names as any object, so a public remote receives
the conflict and its public versions, never a sealed one (a public clone
renders it with that version redacted). `gc` keeps, and `fsck` checks, every
version a reachable conflict names.

**Embargoed history.** Before walking, `push` computes, for every
unreleased embargoed merge in the local graph, the merge itself and the
snapshots that only its merged-in (non-first) parents reach: the fix, and
how it was made (`remote::embargo_withheld`).
* No remote receives any of them, team or public: an embargo is a
  permission the server will enforce, and until it does nothing of it
  leaves the device.
* A tag that would publish withheld history (a tag on the merge, on the
  fix, or on a commit that builds on either) is skipped with a reason; the
  rest of the push goes ahead.
* After the release, the next push sends them, with unchanged snapshot
  ids.

Key rings are signed
logs that only fast-forward (§3). Stale, tampered or forged rings are
ignored or rejected with a warning, and membership is never merged as a
union. Embargo records are plain: one whose scope, deadline or creation
differ from the local one's is refused, a release it carries is taken.
Snapshots whose signature fails to verify
are reported. The object walk is iterative and refuses trees nested deeper
than `MAX_TREE_DEPTH` (1,024) levels (merge, normalisation, the builder and `fsck` are iterative too, and bounded by the same
limit, because a tampered local `.veil/` is not depth-checked on arrival), measured as each tree's height so
that shared subtrees cannot hide depth. Remote tags with an invalid name, or
whose target is missing or not a snapshot, are skipped with a warning. Tags
fast-forward. A diverged tag is reported and left alone
(`--force` overrides on push). A local **release tag** (annotated, format 5)
never moves on a pull, and keeps its annotation: when the remote holds it
at another target (a teammate's `vl tag set --force`, or a hostile remote),
`remote::apply_remote_tags` records that target as `<remote>/<name>` and reports
it (`SyncReport::release_tags_kept`, "origin moved release tag v1.0 from X
to Y; your release tag v1.0 stays at X"), at every pull until the user
decides; only `vl tag set <name> -r <remote>/<name> --force` takes it
(BUG-703).
Commits, merges and rewrites never move a release tag
(`commands::tag_kept`, the merge loop and the re-pointing in
`Transaction::rebase_descendants` skip it), so its signed annotation always
matches it. `vl tag set` over one is refused without `--force`, which
writes a new atag keeping the old message unless `-m` gives one; the
annotation is never dropped silently.

**Deleting tags (BUG-280).** A push never deletes anything on the server.
Pull prunes `<remote>/<tag>` for tags gone from
the remote and keeps a local tag of that name (a teammate's deletion never
deletes yours). A local deletion sticks, the way jj tracks a deleted
bookmark against its remote bookmark: `vl tag delete` records the tag and
its target in `.veil/local/deleted_tags.json` (`remote::deleted_tags`;
repository-local, outside the view, so no format change), and pull does
not recreate the tag while the remote's tag is that
target or behind it. When the remote moved past it, the tag comes back
with a warning and the record goes. Records are dropped once the tag
exists locally again.

**Removing remotes.** `vl remote rm` drops the remote tags `<name>/*` in
one operation,
then remove the remote from its configuration, so an interruption leaves
a configured remote to remove again, never remote tags of a remote that is
gone. Remote names are validated (`remote::validate_remote_name`).

**Names a remote cannot hijack.** Revsets resolve tags before change ids,
and change ids are visible to every reader of a remote. So `pull` never
creates a local tag whose name is a change-id or
snapshot-id prefix of local history or of what the pull brings in; it
warns, and `<remote>/<name>` still names the snapshot. A change id
matching several visible snapshots resolves to the one in local history
(reachable from this repository's heads or working copies) when the
others are only reachable through tags: a snapshot someone pushed with
another person's change id cannot make that change divergent (BUG-105).

**Creating a repository** (the in-process transfer). The first push to an
empty store initialises it under its lock and re-checks once the lock is
held, so when several pushes reach an empty store at once one creates it
and the others push to it normally (BUG-120). An error while checking is an
error, never a reason to initialise over what may be a repository; a
directory that holds other files is refused (BUG-283). On the server, the
first push to a project that does not exist creates it, with the pusher as
its admin.

## 9. Locking, crash safety and `fsck`

**The repository lock** (`lock.rs`) is the file `.veil/lock`, created with
`create_new`, so it behaves the same on every backend. It holds JSON: a random
per-acquisition token, the holder's pid and process start time, host name,
boot identity (Linux boot id plus pid namespace), a lease (10 s by default)
and, once renewed, when it was acquired on the backend's own stamp clock.

* While a `RepoLock` lives, a heartbeat thread renews the lease every 2.5 s.
  However long a transaction runs, its lock never looks stale. (The MVP stole
  any lock older than 120 s, even from a live process.)
* A contender takes over someone else's lock only when the holder is
  provably gone. That means either the same machine (same host, boot id and
  pid namespace) with a pid that no longer runs, or an expired lease last
  renewed before this machine booted. A dead pid is taken over **at once**,
  without waiting for the lease: the pid may be reused, but never by the
  process that wrote that token. That makes recovery from `kill -9` or
  Ctrl-C instant. A zombie (killed or exited, not yet reaped by its parent,
  such as an IDE or agent harness that killed a hung `vl`) is dead too: on
  Linux every thread in `/proc/<pid>/task` shows state `Z` or `X` (the main
  thread alone shows `Z` after a `pthread_exit` while others still run), on
  macOS `proc_pidinfo` reports `SZOMB`. A holder on another host, or a live
  process that stopped renewing (suspended, stuck), is never robbed. The
  contender times out with an error naming the holder.
* "No longer runs" needs proof: a zombie, or `kill(pid, 0)` failing with
  `ESRCH`. A missing `/proc/<pid>` alone is not, because `/proc` may hide
  other users' processes (`hidepid=2`, systemd's `ProtectProc=invisible`):
  `kill` then answers `EPERM` for another user's live holder, which is
  waited for. `/proc` is only consulted when it describes this process's
  own pid namespace (`/proc/self` names our pid); a `/proc` mounted for
  another one (`unshare -p` without `--mount-proc`) would describe other
  processes under the same pids, so `kill` alone decides and start times
  are not used. `hidepid=1` (entries visible, contents not) counts as
  running. These setups need root to build, so the tests inject what such
  a `/proc` shows through `LockContext::probe` (`ProcessProbe`), and the
  production decision (`process_alive_with`) runs on it. Legacy `"<pid> <millis>"` lock files
  (from local-only earlier versions) are judged as locks of this machine.
* A reused pid does not keep a dead holder's lock. The lock records the
  holder's start time (`pid_start`: `starttime` from `/proc/<pid>/stat` on
  Linux, `proc_pidinfo` on macOS). A live process under that pid with
  another start time is someone else, so the holder is gone and the lock
  is taken over at once. Locks without it (older versions) are taken over
  once their lease has expired if the process under their pid started more
  than a minute after the lock's `acquired` time.
* Each process keeps a registry of the tokens its live locks hold, and of
  the thread holding each. A lock file with this process's pid and an
  unregistered token was leaked, for example by a crash that prevented the
  file from being removed. It is reclaimed immediately.
* `RepoLock::acquire_reentrant` returns a nested handle (which neither
  renews nor releases) when the calling thread already holds the lock.
  Metadata writers use it, so they work both on their own and inside a
  transaction. Transactions themselves never nest.
* Takeovers are serialised through `.veil/lock.steal` (also `create_new`).
  Under that guard, the contender re-reads the lock and, only if it still
  has the exact bytes that were judged stale, replaces it with its own lock
  in one atomic write. Two contenders can never both win, and no third
  process can slip in between the removal and the new lock.
  A guard left by a contender that crashed mid-takeover is never removed
  by anyone else. Check-then-remove would let two contenders that both
  judged it dead each remove "it", the second one deleting the guard the
  first had just created, and both would take over. Instead it is
  *replaced* in one write by a contender holding a sub-guard named after the
  dead guard's bytes, `.veil/lock.steal.<hash>`, claimed by the same rule
  (one level further down if its holder crashed too). Those bytes are
  never written again (they hold a random token), so each dead guard has
  one winner, and every guard file is removed only by its holder. A
  sub-guard is left behind only if a contender crashes while holding one;
  if the guard it was named after is gone by then, nobody contends for it
  again. It is harmless. `vl fsck` reports every leftover guard and
  sub-guard, and the next takeover (after its recovery) and `vl doctor`
  clear the provably stale ones (`lock::clear_stale_guards`), each by
  *claiming* it under the protocol above and then releasing it, so a live
  contender's guard is never touched.
* **Network remotes: fencing leases.** *Unused since SFTP remotes were
  removed (simplification pass, part 1): no backend is `is_network()` any
  more. The code and its tests (`core_sync/remote_lock.rs`) stay until a
  follow-up removes them.* On an `is_network()` backend
  (SFTP), other hosts can never prove a holder gone, so a client that
  crashed mid-push would lock the remote forever. Its lock is a *fencing*
  lock (`"fencing": true`; lease 30 s, renewed every 5 s):
  * the holder remembers, on its monotonic clock, when its last successful
    renewal *started*; once that is a whole lease ago it stops renewing and
    `ensure_held` fails, so it never publishes after its lease, however
    long it was suspended or partitioned;
  * any host may take over an expired fencing lock: after seeing the same
    lock bytes unrenewed for `lease + grace` (15 s) on its own monotonic
    clock (no clock comparison, so skew does not matter), or at once when
    `renewed` is older than `lease + grace + skew` (skew allowance 2 min)
    by its wall clock. A contender facing a fencing lock waits at least
    `lease + grace`, so the next push recovers a crashed one;
  * safety: the holder's last renewal started before the contender first
    saw its bytes, the holder stops publishing a lease after that start,
    and the contender waits `grace` longer still. The residual risk is a
    holder stalled for more than `grace` *between* its final check and the
    single `op_head` write (SFTP has no compare-and-swap); its token check
    catches every later step;
  * renewal and release are fenced the same way. A renewal reads the file,
    checks the token, then rewrites it, so a takeover that lands in between
    would be overwritten. A contender takes over only `lease + grace` after
    the previous renewal started, so a renewal write that returns before
    the holder's lease lapses landed before any takeover; one that returns
    later counts as losing the lock (both sides then fail instead of both
    publishing), and a holder whose lease lapsed never removes the lock
    file on release;
  * clock skew beyond the allowance: a contender whose clock runs more
    than `lease + grace + skew` (165 s) ahead of a live holder's takes its
    lock over at once by the wall-clock rule. The holder fails at its next
    renewal or `ensure_held`, so this normally costs a failed push. Two
    races no longer need a stall then: a takeover landing between a
    renewal's check and its write is overwritten (the contender fails), and
    one landing between the holder's final check and its `op_head` write
    lets both publish;
  * locks without the flag (local holders, older versions) keep the rule
    above and are never taken over from another host. The takeover guard
    is a fencing lock too, so a contender that crashed mid-takeover on
    another host is cleared after its 5 s lease plus grace.

  `LockContext` carries the clock and host identity: the tests simulate
  hosts, skew, suspension and crashes with `SimClock`.
* Fencing: before moving `op_head`, a transaction checks that the lock still
  carries its token (`RepoLock::ensure_held`). A holder whose lock file was
  replaced behind its back (tampering) fails with `Locked` instead of
  recording its operation over someone else's.
* On disk, `create_new` writes the content to a synced temp file and
  hard-links it into place. A contender therefore never sees a half-written
  lock. Unparseable content (left by older versions or a non-atomic fallback)
  is reclaimed only after it stays unchanged for a full lease.
* Every way round the acquisition loop passes the deadline and the
  back-off, whatever the lock path reads back as. A lock or takeover guard
  path that is a symlink (or a socket, a device) defeats `create_new` yet
  reads as absent, since backends never follow symlinks; it is reported at
  once (`.veil/lock is a symlink, not a lock file; … remove .veil/lock`),
  and never removed on the user's behalf
  (BUG-119).

**Shared metadata under the lock.** Every read-modify-write of key rings,
embargo records, team-vault records and the vault holds the repository lock (`Keychain` and
`Repo::vault_update` take it reentrantly). Push and pull copy objects and
merge metadata *inside* their transaction, under the destination's lock.
Two concurrent `grant`s, or a `grant` racing a `pull`, cannot lose an
update. From format 6 local transactions no longer hold the lock, so these
writers race transactions instead of queueing behind them; they still
serialise among themselves (`metadata_lock::grant_racing_lock_free_commits`).
The local vault's backup of isolated files, which every command's snapshot
refreshes, reads the vault first and takes the lock only when the backup
changes.

**The lock-free op log (format 6, `docs/design/scale/2-lock-free-oplog.md`).**
Local transactions (`Repo::open`, a format-6 repository not over a network)
take no lock:

* **Heads.** The log's heads are empty files `.veil/op_heads/<id>`. A
  transaction records the heads it started from (its *base*) and publishes
  its operation with them as parents (`OpStore::publish`: write the
  operation durably, `create_new` its head file, remove the parents' head
  files). Readers drop a head that is an op-graph ancestor of another (a
  crash between the last two steps); the walk stops an hour below the oldest
  head and at pruned operations, where unknown ancestry counts as "not an
  ancestor" (an extra merge: the merge base walk, `OpStore::split`, has no
  such floor and finds the operation a side forked from however long ago,
  BUG-803). A transaction whose base operation was pruned while it ran
  (`gc --keep-ops-days`) fails at commit rather than publish an operation
  with no common history (BUG-804). A head naming a missing operation
  fails `Repo::open`, with `fsck` naming the file; non-head entries are
  ignored.
* **Staging.** A transaction keeps its new file contents (blobs, sealed
  or not) of up to 1 MiB in memory (32 MiB in all; past that they are
  written out as a pack). Its trees and snapshots stay loose until gc, as
  before: status, log and the other history reads find them uncompressed,
  and never read a pack for them. At
  commit, 256 or more contents become **one pack** in `objects/pack/`
  (compressed a few MiB at a time on up to 8 threads; the `.pack` made durable, then its
  `.idx`, durably, as a pull writes its packs): an import of 10,000 files
  makes two files durable instead of 10,000 objects with a fsync and a
  rename each. A registered transaction's pack is as safe from gc as its
  renamed loose objects (the deletion fence, `maintenance.rs`). Fewer
  objects, larger ones, and every object in memory (`MemoryBackend`,
  where a loose object costs nothing) are loose objects in the
  transaction's own directory, `objects/incoming/tx-<owner>/`
  (`ObjectStore::begin_tx_staging`), which only it reads. The operation
  it records, and its empty head file, are staged there too
  (`stage_unsynced`: the staging directory itself is never synced, since
  nothing ever names a file in it). At commit: one barrier makes every
  staged file's content durable (a failure removes the directory, and
  nobody can have adopted those objects); each object is renamed over its
  final name (`publish_unsynced`; content-addressed, so replacing a
  concurrent identical copy is harmless), then a second barrier over every
  fan-out directory touched and every fan-out directory of an object the
  transaction found already present instead of writing it (another
  process's rename may not be durable yet), each on a thread of its own;
  then the operation is renamed into `ops/` and a third barrier syncs that
  directory; then the head file is renamed into `op_heads/` and a fourth
  barrier syncs it (`OpStore::publish_staged`). Each name becomes durable
  only after everything it depends on did: an operation names only objects
  published after their writer's successful barrier (BUG-044's class,
  across processes), and a head only an operation already durable. A
  transaction superseded at its compare-and-swap removes the operation it
  staged with the directory (nothing named it). Four barriers in sequence,
  where there were about twenty (performance round 3). A
  transaction whose staging overlapped a failed barrier of another one on
  the same backend value (they share its write batch) voids itself
  (`StorageBackend::barrier_failures`). A dropped transaction publishes what
  it staged too (a stat cache may already name it). `<owner>` encodes the
  host, boot, pid, pid start time and creation time: `Repo::open` removes
  the staging and pull spools of owners that are provably gone by the
  lock's rules (`lock::owner_gone`), and `fsck` notes the others.
  `recover_interrupted_writes` and the lock's `"recover"` flag remain for
  formats ≤ 5 and network remotes.
* **Compare-and-swap.** A snapshot that recorded a workspace
  (`Transaction::expect_wc`) re-reads the heads at commit and fails
  ("superseded") if their merged view moved that workspace; the check and
  the publication are one step for the threads of a process (a static
  mutex, BUG-806). Every commit re-reads `repo.json` and fails if the
  repository was upgraded meanwhile.
  `lock::WcLock` (`flock` on `.veil/local/wc/ws-<name>.lock`, re-entrant
  within a process) keeps one recorder per workspace directory: the
  project directory's `Ctx` for its recording and its checkout, `ws exec`,
  `ws write` and mount recordings. A holder acts only on what it reads
  **after** taking the lock: `Ctx::lock_dir` re-reads the view and
  `checkout.json` under it, as another recorder may have finished while
  it waited. Read at start-up, a view older than the checkout record made
  the directory look stale, and its edits went into a "recovered
  working-copy edits" change and off the disk (BUG-1084). A move of the
  directory to another workspace (`vl ws switch`, `Ctx::finish`) holds
  the locks of both workspaces, taken in name order, and a recorder whose
  directory was attached elsewhere while it waited locks that workspace
  instead (BUG-1121). `ws write` writes over the `@` it reads under the
  lock and records with `expected_wc`, so it never reverts what landed
  meanwhile (BUG-1120). A command that writes into the directory itself
  (`vl restore`, `vl renormalize`, the policy commands, `vl access`, `vl
  secret recover`) holds `lock_dir` from before it reads the directory
  until its closing snapshot (BUG-1125); `finish` prints the warnings of
  a merge its re-read wrote (BUG-1126).
* **Merging (`Repo::settle`).** Several heads are merged into one operation
  at open and before every transaction: folded in id order, each against
  the nearest common operation, by `oplog::merge_views`, a 3-way merge per
  key. After a criss-cross (two settlers that listed different heads
  merged some of the same operations, each with others) the sides share
  more than that operation holds: a key whose value on one side was
  introduced by an operation only that side reaches, and on the other
  side was not, takes the changed side's value (`oplog::shared_base`), so
  a side still holding the shared history's older value never wins
  against a newer commit (BUG-1294); a key both sides introduced a value
  for has no base value, so the two are merged as two changes, even when
  one is a write back to the common operation's value (BUG-1296). The
  walk that finds the operations only one side reaches ends only below
  every operation it walked as one side's: a merge has its newest parent's
  timestamp, and a common descendant of the same timestamp must still mark
  its ancestor common (BUG-1297). Per key (heads: kept if every side kept it or some side added it;
  workspaces, tags, remote tags: one side's change wins, two different
  changes go to the first side and the other target stays a visible head
  (through the rest of the fold too: a later step's dropped head never
  hides a loser, BUG-1298), with a warning printed once by the process that writes the merge; a
  removal loses to a change; a workspace's or tag's cloak merges separately
  and a cloaked side wins; a release tag's target and annotation are one
  unit and win over an ordinary tag). Each side's `rewritten` is applied to
  the other's new snapshots (`Transaction::for_merge` runs the auto-rebase:
  a child committed on a snapshot amended meanwhile moves onto the amended
  one); both sides rewriting one snapshot differently is a divergent change,
  and a rewrite that was undone is not applied. What undoes a command's
  rewrite is read from the op log, never from a view: an operation with
  `undo_of` takes back the operation it names, an op restore
  (`restore_of`, or on older restores the operation named in its
  description) every operation between the restored one and its parents,
  unless the undo or restore is itself taken back (an undo of the
  restore, a redo of the undo); each rewrite of the operation taken back
  goes, and another command's rewrite of the same snapshot still applies
  (BUG-802, BUG-1299, BUG-1434). Showing an old snapshot again undoes
  nothing: a ref on it that a command which saw each rewrite of what it
  shows set (a tag on the old version, a workspace on it, an undo's
  revert) stays where it is, and every other ref follows the rewrite. A
  rewrite only merges recorded (the op log does not say which command it
  is) is still judged by the views: not applied when a head that saw it
  shows its old snapshot, or a side shows it where the fold step's shared
  history does not (BUG-1295). On one side, a rewrite replaces an earlier
  one of the same snapshot when its operation descends from the earlier
  one's; two that stand and differ are a divergent change, which nothing
  follows, and a merge does not revisit that decision when one of them is
  taken back later (BUG-1444). Open (BUG-1488): when a command that saw
  a rewrite rewrites the old version again, the merge's answer depends
  on whether the two rewrites first meet in one fold step (the second
  replaces the first) or not (divergent); the intended rule is
  divergence while both versions are visible.
  The confinement check runs against **every side's view**: a rewrite that
  would move a change out of an unreleased embargo either side had it in
  is dropped and its replacement rewritten back, so the change stays
  inside, and a warning names the change and the embargo, never a file.
  The merge never fails for a policy reason: a snapshot whose rebase is
  refused stays on its old
  parents, with what is built on it, and the warning names it (BUG-805).
  Its timestamp is its
  parents' latest (a command's operation is strictly later than its parents,
  whatever the clock says: a millisecond after the newest when the clock
  is behind, so times still separate a command from its parents and the
  op log's walks end near the heads, BUG-1485, BUG-1486), its user `veil`, and what it creates derives its change
  ids from its parents: two processes merging the same heads write the same
  operation, and `create_new` of its head file loses to itself. Merging at
  open, rather than in memory for read-only commands as the design
  allowed, is deliberate: a command such as push computes what to send from
  the view it opened, and an escaping rewrite must already be dropped
  there.
* **Bare repositories** (`Repo::open_remote`: the receiver of the
  in-process transfer, and old path remotes) keep `.veil/lock` for their
  transactions (a push, gc), with one head in `op_heads/`; objects are
  staged like local ones.
* **Pull spools** are `incoming/pull-<owner>` of their transaction, so
  concurrent pulls never touch each other's.
* **gc** marks from every head and from what live transactions staged
  (their trees may be all that references an older object), and a transaction older than half the grace period freshens
  every pre-existing object it references before it publishes.

**Crash ordering.** Every transaction writes in this order: objects (the
snapshot, trees and blobs it references), then a durability barrier, then
the operation, then `op_head` (format 6: the objects, the operation and its
empty head file staged, a barrier, the objects' renames, a barrier, the
operation's rename, a barrier, the head file's rename, a barrier, the
removal of its parents' head files). The crash harness tears what no
barrier covered, drops staged names, and keeps the unsynced renames of
every other directory, so that a name made durable before what it depends
on fails `crash_during_one_operation_commit` and the other sweeps. Pull and push copy objects and shared metadata
(key rings, embargo records) before the operation that references them.
`init` writes `repo.json` last, because it is what makes a directory a
repository.

* `DiskBackend::write` and `create_new` return only once the data is
  durable: the file is fsynced, renamed, and its directory fsynced, and new
  directories are synced into their parents.
* Inside a transaction, objects are written with
  `StorageBackend::write_unsynced` instead: temp file, rename, no fsync. The
  backend remembers each file. `StorageBackend::sync_barrier` then fsyncs
  all of them at once, a thread each (up to 32), so that ext4 or XFS
  share journal commits (two new files: 0.42 ms instead of 0.70; four:
  0.73 instead of 1.36 on ext4 NVMe), and then every touched directory
  once (one thread per 16: after the files' fsyncs they are mostly clean). `Transaction::commit` runs the barrier
  before writing the operation, and `Transaction`'s `Drop` runs it again,
  before the lock is released, so an aborted transaction leaves nothing
  unsynced either. Barriers on one backend are serialised, so a barrier
  never returns while another thread is still syncing writes the caller
  depends on.
* **A failed barrier voids what it covered.** After an `fsync` error, Linux
  marks the failed pages clean: the files read back intact from the page
  cache but are not on disk, and a retried `fsync` succeeds without
  writing anything. Reusing such an object (the store skips objects that
  exist and verify) in a later, acknowledged transaction would lose it at
  the next power loss. So the object store remembers which loose objects
  it wrote unsynced since the last successful barrier, and when a barrier
  fails it removes them and syncs the removals. Nothing references them
  yet, and a retry writes fresh copies. If they cannot be removed, the
  transaction does not release the lock. It leaves the lock file behind,
  flagged `"recover": true`, and any contender (this process, another, any
  host) takes it over at once and runs crash recovery, which rewrites them
  as new files or removes them. Push and pull use the same store barrier
  before writing a pack index. `crash.rs` sweeps this with a failing
  barrier at every point of snapshot, merge, push and pull, with and
  without removals failing too, followed by a retry and a power loss.
* So after a crash at any point, `op_head` names a complete operation whose
  view references only complete, durable objects. The worst leftovers are
  unreachable objects, an operation that never became the head, temp files
  and a lock that will be reclaimed.
* Unsynced objects can outlive their writer only if it dies holding the
  lock. A process that is killed leaves intact but possibly not yet durable
  objects. A power loss can leave them empty or truncated under their final
  names. A later transaction must not reuse such an object instead of
  writing its own copy (the store skips objects that exist). So right after
  a takeover, the new holder runs `fsck::recover_interrupted_writes` under
  the lock. It re-hashes the loose objects modified since the dead holder
  took the lock, removes those that fail, and rewrites (as new files) and
  syncs the rest. That moment is known on the backend's own stamp clock:
  the holder stats its lock file right after acquiring it and records the
  stamp in every renewal (`since_stamp`). A lock never renewed is still the
  file written at acquisition, so its own stamp serves. The window then
  starts five minutes earlier on wall-clock filesystems (clock steps) and
  exactly there on generation-stamped ones. Fanout directories not modified
  since are skipped without listing them. Older locks, and backends without
  usable stamps, fall back to the holder's wall-clock `acquired`
  time minus an hour, or to every loose object. If recovery fails, the
  lock is left flagged for the next contender rather than released.
* A recovery that fails or dies must not narrow the next one (BUG-096).
  The new holder's own `since_stamp` only covers its own writes, not the
  dead holder's objects it had not reached yet. So the window it is
  recovering is written into its lock file with the takeover itself
  (`"recover_window"`: `{"stamp": …}`, `{"wall": …}` or `"all"`), and
  renewed with it, until the recovery has succeeded; only then is it
  dropped. The next contender recovers the union of that window and the
  holder's own (the earlier stamp; mixing a stamp with a wall-clock time
  means every loose object). The lock is marked to be left behind from
  the takeover until recovery succeeds, so an error or a panic in between
  leaves it flagged. `adversarial5_durability` sweeps a failed barrier
  with unremovable objects, then a takeover whose every mutation in turn
  fails once or crashes the process (with and without a power loss
  before the next process, and twice in a row), then a retry, an
  acknowledged commit and a power loss.
  Until then `fsck` reports torn unreachable objects under a leftover lock
  as a note.
* Undo is unaffected.

Cost: `vl init` of 2,000 small files on ext4 went from 1.6–2.0 s to
0.11–0.14 s, and of 20,000 files from 17–19.6 s to 1.0–1.05 s (release
build). The number of fsyncs is about the same; they now run concurrently
instead of one after the other, and each directory is synced once.

**`vl fsck`** (`fsck.rs`) is read-only and works without `Repo::open`, so it
can diagnose a damaged `op_head`. It re-hashes and decodes every object,
including unreachable ones, and opens sealed objects it holds keys for. It
walks reachability from the current view and from every retained operation:
snapshot → parents and tree, tree → entries. It
rejects tree entry names such as `..`, and checks that key rings and embargo
records parse and are filed under their own names. It also checks that every
operation matches its id, that every parent exists, and that the head points
at a real operation. A missing object is classified by the visibility of the
entry that references it:

| finding | meaning | exit code |
|---|---|---|
| corrupt | hash mismatch, undecodable, missing public file / tree / snapshot / op parent, broken metadata | 1 |
| warning | sealed under an unexpected scope, embargo without a record | 0 |
| redacted (expected) | a sealed secret absent, e.g. in a clone of a public remote | 0 |
| note | leftovers of interrupted commands: dangling operations, unreachable objects, temp files, a lock | 0 |

**Crash-injection tests** (`crates/veil-core/tests/core_durability/crash.rs`). A
`FaultyBackend` wraps `MemoryBackend` and fails the N+1-th mutation and every
later one, with the fatal write either lost or applied. The barrier is a
mutation too. In a third mode, *power loss*, the fatal write is lost and
every write not yet covered by a barrier is torn (removed, emptied or
truncated). A separate sweep (`EioBackend`) fails one barrier at a
time with Linux's post-error semantics, retries the command, then cuts the
power (see above). For snapshot, commit,
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
  pack often (more than 64 entries) loads it into memory once instead, for
  packs up to 16 MiB, within one budget of 64 MiB for the whole process
  (least recently used first out; each backend reads its own copy), so a
  history walk never holds the whole store (BUG-800). Larger packs are
  always read by range.
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
  `Corrupt`, never as wrong content.
* **Decompression limits** (BUG-490). A pack may come from a hostile
  remote, and a few KiB of zstd RLE blocks decode to gigabytes. An entry
  declaring more than 4 GiB (`VEIL_MAX_OBJECT`, e.g. `8G`; the server's
  planned object limit) is refused before anything is
  decoded, and an index of more than 2^25 entries is refused. A frame must
  declare exactly the entry's size, and decoding stops (in both decoders,
  libzstd and `ruzstd`) as soon as it would produce more, or a second
  frame. Up to 64 MiB an object is decoded into a buffer of its size;
  above, it is streamed into its hash first (1 MiB at a time, the window
  at most 128 MiB) and decoded into memory only once that matched its id,
  so content that is not the object costs decoding time, never memory. A
  pull downloads at most 2 GiB of packs to its spool on disk for its bulk
  read (BUG-800: it used to be memory), each to the size its index
  implies, and fails first, naming the space needed, if the disk lacks
  it; objects in further packs are read one at a time. If a pack cannot be opened, lookups
  that miss report `Corrupt` rather than `Missing`, because "missing" means
  "redacted" to the rest of the engine. `ObjectStore::verify_packs` does a
  full check, and `gc` refuses to run on a store with a broken pack.
* **Atomic publication.** The `.pack` is written before its `.idx`, and
  readers find packs only through `.idx` files. Old packs are removed index
  first.
* **Streaming writes** (BUG-800). gc, push and pull write packs with
  `PackWriter`: the same bytes as `PackBuilder` (which stays for small
  packs), streamed through `StorageBackend::create_stream` (on disk a temp
  file created with `O_EXCL`, fsynced, renamed, then the directory fsynced;
  elsewhere buffered). Memory holds the `(id, offset, length)` table, the delta
  depths and 1 MiB of pack data. The header's count is patched at the end,
  and the trailer's BLAKE3 is computed while streaming (the first 1 KiB
  chunk, holding the count, is kept, the rest is hashed as the subtrees
  BLAKE3's tree has at any length, and the two are merged at the end), so
  nothing is read back. Sync keeps the last version seen at each path as
  the next one's delta base, 64 MiB of them at most. A reader whose pack disappears (a concurrent gc replaced it)
  rescans the pack directory and retries.

### Caches

`ObjectStore` keeps decoded trees, snapshots and decompressed delta bases in
weight-bounded LRU caches (`cache.rs`). A tree weighs `entries + 1`, a
snapshot 1, a base its size in bytes. The defaults are 200k tree entries,
20k snapshots and 64 MiB of bases, adjustable with
`ObjectStore::set_cache_limits`.

### Thin clones: fetch on demand (`promisor.rs`)

A thin clone of a server project (format 9, `docs/HUB.md` §13.21) keeps
two object stores: `.veil/objects/` (every snapshot it fetched, and
everything it made; never evicted) and `.veil/cache/` (trees and files
fetched from the server; evicted least recently written first, down to 80 %
of its bound, never what a workspace's working copy or the checkout record
pins). A read neither holds goes to the server at the snapshot and path
where the process met the object (recorded as trees are decoded); what
arrives is re-hashed before use. The server's "not there for you" is
`Missing`; a server that cannot be reached is `Unavailable`, which no
caller reads as hidden. Snapshots are never fetched by a read: graph
queries that reach the clone's boundary fetch history pages and run again
(`Repo::exact`). gc, fsck and maintenance never fetch.

### The history index (`graph_index.rs`)

Graph queries that used to read every reachable snapshot (the auto-rebase
after each commit, `log -n`, change-id lookup, `tag set`'s ancestry check,
the embargo walks behind push filtering and confinement, blame's ranks)
stop early using each snapshot's **generation**, a corrected commit date:
the larger of its timestamp and 1 plus the largest generation of its
parents in the store. Generations strictly decrease along every parent
edge whatever timestamps authors chose, so a walk for `a` below `b` stops
soundly at every snapshot below `a`'s generation; a false timestamp can
only make a walk longer. The index is a device-local cache in
`.veil/index/graph/` (`docs/design/scale/3-history-index.md`):
- **What it holds:** per snapshot, its generation, change id, whether
  `embargo` is set, and whether any ancestor has it set (so embargo checks
  skip every line that does not build on an embargoed merge). Only
  plaintext snapshot fields, so it is the same with and without keys.
  Walks take parents from the objects, never from the index.
- **Never required:** an entry not on disk is computed from the store on
  first use and persisted at the next commit (or once 256 have
  accumulated). A damaged or unreadable index is dropped and computed again.
- **Concurrency:** layers are created with `create_new_unsynced` (as
  exclusive as `create_new`, and never synced: a cache), one slot each, and
  merged geometrically (what the rule merges in several steps is written
  as one layer); concurrent appenders never overwrite one another. A layer
  a power loss tore (missing, empty, half written) fails its checksum and
  the index is rebuilt (`crash::a_power_loss_tears_history_index_layers_and_they_are_rebuilt`).
  Bare repositories compute it in memory only.
- **A parent that arrives later** (the fix of a released embargo, pulled
  into a public clone) could carry a larger generation than its indexed
  child. Each layer lists the parents that were missing; when one is
  present, the index is voided (a new epoch) and rebuilt.

### Garbage collection and maintenance (`vl gc`, `gc.rs`, `maintenance.rs`)

`vl gc` runs three tasks: **prune**, then **consolidation** of loose
objects, then **geometric merging** of packs
(`docs/design/scale/4-background-cleanup-streaming.md`). On a lock-free
repository (format ≥ 6, local) it holds the **gc lease** (`.veil/gc.lock`,
an `flock`: one gc at a time, never stale) and not `.veil/lock`, so writers
and metadata updates never wait for it; elsewhere (format ≤ 5, remotes) it
holds `.veil/lock` for its whole run, as their transactions do. Under its
hold it re-reads `repo.json` and stops if the format changed (`vl upgrade`
takes the lease too).

Pruning:

1. **Inventory.** Every pack index and the loose listing, *before*
   reachability. Each copy of an object has a position (pack by pack, then
   the sorted loose ids), found by a binary search of each pack's ids and of
   the loose list: no set of all ids is built. Objects written after this
   point are not in the inventory, so gc never touches them.
2. **Op-log pruning** (`--keep-ops-days N`, off by default). Operations
   older than the window go. Every head file's operation and its parents
   are always kept, so `vl undo` works and can be redone. `op log` and
   op-id prefixes end where the log was pruned.
3. **Mark into a bitmap**, one bit per position (objects outside the
   inventory, written since, in a small set). The roots are the views of
   every retained operation (heads, workspaces, tags, remote tags), the
   universal root, the project directory's checkout pointer
   (`.veil/local/checkout.json`; the CLI diffs the working copy against it,
   and `vl gc` adds the one it read itself), and keep markers. From there
   gc walks snapshot → parents and tree, tree → entries (a subtree already
   marked is not entered again), and file entry → object. Snapshot
   `predecessors` (the evolution log) are weak references, as they already
   are for sync: `vl evolog` stops where history was collected. Memory is
   the bitmap, the walk stack, the packs' index tables and the caches'
   limits, never object content (measured: about 15 bytes per object
   beyond the index tables, `maintenance::pruning_memory_is_the_inventory_bits_not_the_objects`).
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
6. **Packed garbage** goes by rewriting a pack only when its deletable
   garbage is more than a quarter of its bytes, or the pack is at most
   16 MiB, or the grace period is zero: its other entries are copied as
   stored into a new pack (a delta whose base goes is stored whole). The
   big old pack keeps its garbage (pending) until that share is reached.
7. **The deletion fence (lock-free repositories, BUG-811).** Every deletion
   (loose garbage, a rewritten pack's old copy, pruned operations) happens
   under `.veil/local/gc/fence`, raised only once no transaction is
   registered (`objects/incoming/live-<owner>`, from before it reads the
   heads until it has published; `Repo::open` and reload register too while
   they read the op log): gc waits up to 5 s for a quiet moment,
   then raises it and waits up to 60 s for the rest (new transactions wait
   for it), and otherwise deletes nothing that run and says so. With the
   fence raised it also takes `.veil/lock` (BUG-814): writers that hold it
   instead of registering (a push into a bare repository collected with
   `vl -R`) are then finished or
   not started; if it stays held, nothing is deleted that run. Under the
   fence it reads its roots again and marks what they reach (what was
   published or reused meanwhile), prunes only operations of its first
   listing, and gives a loose copy to anything that became reachable whose
   pack goes. Before it deletes anything it writes a new prune epoch
   (`.veil/local/gc/epoch`, first, so that a gc killed part-way still
   moved it: BUG-815); a transaction whose process read its view
   under an older epoch checks at commit that what its view gained and its
   new objects name is present ("… run the command again" otherwise).
8. **Refuse to guess.** If any operation, snapshot or tree on the way cannot
   be read (missing, corrupt, or sealed without a key), gc deletes nothing,
   and reports why.

**Consolidation** packs every loose object (all of them for `vl gc`; those
older than 10 minutes for `--auto`) into one new pack, reachable or not:
what the prune just found unreachable goes into a pack of its own, which a
later prune drops whole. Successive versions of a path, found by walking
the new snapshots' new trees, are delta candidates. The order is the
durability argument: the `.pack` (fsynced, renamed, its directory
fsynced), then the `.idx` written durably, and only then each loose file
is removed. **Geometric merging** then merges the smallest packs so that
each remaining one is at least twice the next smaller one (Git's
`repack --geometric=2`), copying entries as stored; the big old pack is
not rewritten. Readers never take an object for missing meanwhile: a miss
is `Missing` only after a loose probe, a reload of the pack list and a
second loose probe, and a pack whose index vanished while it was being
opened counts as removed, not broken. **Crash debris** is removed by every
run: stream temp files (`.stream-<owner>.vltmp…`, which name their
process) whose owner is provably gone, owner-less temp files a day old,
and dead transactions' staging, spools and registrations.

**Background maintenance.** After a command (`Ctx::finish`), `vl` starts
`vl gc --auto` detached (its own process group, `nice 10`, idle I/O
priority on Linux, output to `.veil/local/maintenance.log`, 0600, kept to
1 MiB) when `maintenance::auto_due` says so: about 6,700 loose objects
(estimated from 16 of the 256 fan-out directories), more than 50 packs, or
a week since the last prune. Not for a bare repository, not with
`VEIL_GC_AUTO=0`, and by default not when `CI` is set; not again within
10 minutes. `--auto` consolidates and merges every time, and prunes (with
the default grace, keeping the op log) only a week after the last prune or
once the operations since rewrote 10,000 snapshots. It exits at once if
the lease is held.

Benchmark (`cargo test --release -p veil-core --test core_bench --
--ignored --nocapture storage_bench::`): 3,000 source files, 300 commits and 30 abandoned
experiments, about 8,000 objects. They take 36.5 MiB loose and 3.2 MiB after
`vl gc` (8.5 MiB without deltas), or 2.6 MiB once the experiments are
pruned. Reading every object costs about 2.3 µs each loose and 6.5 µs each
packed, with a warm page cache. The packed cost is zstd decompression, the
BLAKE3 verification that loose reads skip, and the loose-first probe.

**The scale benchmark** (`crates/veil-bench`, run by `scripts/bench-scale.sh`;
not a default workspace member, so the normal build and tests skip it)
generates a seeded repository of 100 MB to 5 GB with a realistic history
(merges, renames, cloaked scopes, an embargo), times every everyday command
as a separate release `vl` process with its peak RSS, runs N concurrent
agents, and counts snapshot decodes and lock waits from an `strace` of the
command. Its design is `docs/design/scale/9-scale-benchmark.md`; the
numbers at 1 GB, and what they rank, are in `docs/design/scale/BASELINE.md`.

## 12. Read commands: one API, text or JSON (`crates/vl/src/api.rs`)

The read commands (`status`, `log`, `diff`, `show`, `ls`, `workspace list`,
`tag list`, `op log`, `scan`, `secret list`) are split
in two:

* **A function in `api`** takes the repository context (`&Ctx`, or `&Repo`
  where nothing else is needed) and returns a typed result: plain Rust
  structs deriving `serde::Serialize`. It prints nothing. `vl serve --local`
  calls exactly these functions (section 14).
* **A renderer** turns the result into text (`api::text`, the output the
  commands always had, byte for byte; `render::one_line` delegates to it) or
  into one JSON document (`api::emit_json`) when `--json` is given.

`log` and `diff` are also lazy (`api::log_entries_with`, `api::item_diff`
per change), so the text output still stops early when its reader goes away
(`vl log | head`); `--json` collects everything into one document.

**The results hold raw data**: paths, names, descriptions and file lines as
stored. The text renderer escapes them (`render::safe`) at the last moment;
the JSON writer relies on JSON's own escaping and additionally writes DEL,
the C1 controls and the bidirectional overrides as `\uXXXX`, so neither
output can drive a terminal (`api::to_json`).

**Confidentiality is structural.** A result is built from the same reads
the text output made, so it holds no more than the text shows: content this
reader cannot decrypt becomes a `Redaction` (a reason and the text's
message, never bytes); a description sealed for a scope the reader is not in
becomes `null` plus a `HiddenText` naming the scope; `secret list` reads the
vault's key set only, so a value never enters a result; scan findings carry
the scanner's already-redacted excerpt. `crates/vl/tests/cli_basic/json_cli.rs` runs
every read command on every revision as a non-member, a public-mirror
reader and the owner, and checks no sealed secret, isolated plaintext or
vault value appears.

**Tiers.** `vl ls` and `vl status` name each file's tier as *this reader*
sees it (`api::entry_tier`): `public` (plaintext), `cloaked` (a sealed
secret file, and the reader holds the key), `redacted`
(sealed for someone else, or withheld here: decided by opening the object,
never by the label alone), and from the working copy's build report the
local-only `isolated`, `quarantined` and `ignored` (the builder records
ignored paths, a directory once, in `BuildReport::ignored_paths`). `vl ls`
merges the snapshot's files with the local-only ones for `-r @`; `vl
files` keeps its older format for scripts.

**Schemas** are named `veil.<command>/<n>` in a leading `schema` field and
documented in `docs/reference/json.md` (hand-written; `docgen` keeps it
when it regenerates the reference). Additive changes keep the version;
anything else bumps it. The shape tests pin every key and type, and fail if
a key is missing from `json.md`. Two write commands take `--json` too,
`vl split` and `vl squash` (`api::shape`, `veil.split/2`, `veil.squash/2`),
because scripts and agents need to know which change got what; their
interactive picker (`crates/vl/src/picker.rs`) writes to stderr, so stdout
still carries only the document. A failure under `--json` prints a
`veil.error/1` document on stdout too, unless the command had already
printed its own (`api::json_emitted`), so stdout carries at most one
document; clap's usage errors (exit 2) stay text.

### History read tools (`blame`, `grep`, `search`, `rename`, `bisect`)

`vl blame`, `vl grep`, the `vl log` filters, `vl bisect` and rename
detection (Git-parity stream H; designs in `docs/design/git-parity/1-…`,
`2-…`, `3-…`) are read commands like the others: engines in `veil-core`,
results in `api` (`veil.blame/2`, `veil.grep/2`, additive fields in
`veil.log/2`, `veil.diff/2`, `veil.status/2`), `crates/vl/src/history.rs`
for the CLI, and `blame`/`grep` methods in `vl serve`.

* **One reader of content.** Every one of them reads file content through
  `blame::readable_version(store, entry, reader)`: `Plain` (public, or
  sealed for a key this reader holds: the envelope's label is checked
  *before* the decrypter is called) or `Redacted` (a reason and for whom,
  never bytes). `Reader::Public` reads as a public mirror (plaintext only):
  `vl blame --public`. The engines count what they opened (`ReadStats`); the tests
  assert outsiders open nothing sealed.
* **`rename.rs`** (computed, never stored). An exact pass pairs deleted and
  added entries of the same kind and id (sealed objects only with the same
  sealed id, conflicts with the same conflict id, never empty files) in
  linear time; an inexact pass (Git's span hash: line chunks of at most 64
  bytes, score = shared bytes / larger size) runs only on `Plain` content,
  only while `sources × destinations ≤ limit²` (1000²), within a 1 GiB
  byte budget, a 16 MiB file cap and a comparison budget; past any of them
  only exact pairs are reported (`truncated`). Destinations are assigned
  greedily by score then path; a deleted source is renamed once. `vl diff`,
  `vl show` and `vl status` detect renames by default (`-M=N`, `-C`,
  `--no-renames`); `vl log -S/-G` pairs renames before counting;
  `--follow` (log, blame) follows the rename source where a path appears.
* **`blame.rs`.** Lines open at the starting snapshot walk the ancestors in
  topological order (each snapshot once, whatever the timestamps); a
  parent whose readable version is identical takes every line without a
  diff. A line goes to the first
  parent that holds it; a parent whose version is redacted stops the lines
  it might hold (unattributed, "sealed"). Line diffs use
  `textmerge::fits` (BUG-484): past the limit only the shared start and end
  map and the result is `coarse`. The walk stops at `--max-changes`
  (default 100 000) or when its work passes 2²⁹ (lines compared plus what
  each diff's search cost: `D²` for `D` edits, the whole work limit for a
  coarse diff; about 2 s of the worst case in a release build); open lines
  are reported unattributed.
* **`search.rs`.** `Searcher::check` per log entry, so `vl log` stays lazy
  and `-n` stops the search. Paths compare entries against every parent (a
  merge is listed only where it differs from all of them); `-S` counts with
  `memchr::memmem` (or an escaped case-insensitive regex), memoised per
  object id in memory only (counts, no plaintext, never on disk); `-G`
  checks added and removed lines of the bounded diff; merges are not
  pickaxe-searched (as `git log` without `-m`). A snapshot whose versions to
  read are redacted is `Skipped`, never counted on ciphertext. Regexes use
  the `regex` crate (linear time) with a 1 MiB program and 8 MiB DFA limit;
  patterns over 64 KiB are refused. `--author` matches the claim,
  `--signed-by` the signer the keychain verifies.
* **`grep.rs`** searches the files of a snapshot (`tree::walk_files`), never
  the working copy: local-only files are in no snapshot, so they are neither
  searched nor counted. `Redacted` files are counted in `skipped.sealed`. Files over 256 MiB are skipped,
  matching lines over 1 MiB are cut; worker threads (with the `os` feature)
  and results sorted by path.
* **`revset::resolve_set`**: `X`, `::B`, `A..B`, `..B`, `A..` (DAG
  differences, children first); `vl log -r`, `vl bisect`.
* **`bisect.rs`** holds the pure graph functions: candidates are the
  ancestors of the bad snapshot that are not ancestors of a good one (the
  root never), the next candidate splits them most evenly (exact ancestor
  counts up to 2048 candidates, a topological sum beyond), and `verdict`
  maps exit codes as Git does. The state is device-local
  (`.veil/local/bisect.json`, `deny_unknown_fields`, at most 1 MiB, a
  regular file only); anything unexpected makes `vl bisect` refuse with
  "run `vl bisect reset`", and nothing else reads it. Interactive steps
  check the candidate out with `Repo::new_change` (the empty step change is
  abandoned when the user moves on); `good`/`bad` refuse to leave a step
  change holding edits without `--discard`. `vl bisect run` never touches
  the working copy and records nothing: each candidate is checked out into
  `sandbox::Sandbox` (the `ws exec --ephemeral` directory, reaped if `vl`
  dies), with no isolated file and no vault value unless `--with-isolated`;
  a candidate with hidden files is skipped unless
  `--trust-partial`. `vl serve` never offers `bisect`.

## 13. Builds without an operating system (WASM)

`veil-core` builds for `wasm32-unknown-unknown` (browsers, Web Workers, any
WebAssembly host) with `--no-default-features --features wasm`. Nothing
above the VFS layer needed changing for it: the work was keeping what
needs a host behind cargo features, so the engine core (object store,
packs, trees, snapshots, op log, merge, policy, scanner, crypto,
keychain, embargoes, sync, gc, fsck, `MemoryBackend`, overlays) compiles
and runs without them. The user's view is in
[guide/embedding.md](guide/embedding.md).

| Feature | Default | Gates |
|---|---|---|
| `os` | on | `DiskBackend` (`std::fs`, fsync, `libc`), the lock's host introspection (`/proc`, `sysctl`, `kill`, `gethostname`, `std::process::id`) and heartbeat thread, the worker threads that compress packs, `Instant` as the monotonic clock |
| `zstd` | on | the zstd C library (`zstd-sys`): compressed and delta pack entries written and read |
| `ruzstd` | off | the pure-Rust zstd decoder (`pack::pure`) |
| `wasm` | off | `ruzstd` + getrandom's `wasm_js` (WebCrypto) backend |

`lib.rs` refuses to compile with neither `zstd` nor `ruzstd`: every
build must read every pack. `vl` uses the defaults, so the native build,
its behaviour and its performance are what they were (the only change on
that path is that the gc pending cache asks `clock::monotonic` for
`Instant`'s elapsed time).

**The clock** (`clock.rs`). Every timestamp the engine records comes from
`now_millis()`, which asks the clock installed with `clock::set_clock`
(process-wide), else the system clock. `wasm32-unknown-unknown` has none
(`SystemTime::now()` panics there), so time stands at 0 until the embedder
installs one. That is fail-safe: deadlines, grace periods and leases are
all "wait until time has passed", so nothing happens early. Monotonic time
(`clock::monotonic`) is `Instant` with `os` and the installed wall clock,
made non-decreasing, without it. The lock's `SystemClock` uses both. This
is also the hook for a trusted time source (HUB.md §8.2) and for
deterministic tests.

**The lock without `os`** keeps the file protocol of §9 but has no host to
introspect. The holder's "host" and "boot" are a random name per engine
instance (`instance-<16 hex>`), its pid 0. So:

* a lock of another instance on a shared backend is *another host's* lock,
  which §9 never takes over (no instance can prove another is gone);
* within one instance, the same-process rules hold: a lock whose token no
  live `RepoLock` of this instance holds was leaked and is reclaimed at
  once, and a lock flagged for recovery is taken over;
* `LockOptions::default().wait` is zero: the engine runs on one thread, so
  a held lock is held by someone who cannot release it while we wait, and
  there may be no clock to wait on (a busy wait on a clock that stands
  still would never end);
* there is no heartbeat (no threads). Nobody else ever takes the lock over,
  so an unrenewed lease is harmless.

The limitation: an instance that dies holding the lock of a *persistent,
shared* backend (IndexedDB across tabs) leaves `.veil/lock` behind for good,
and so does any lock file this instance did not write: an unreadable one
(native vl reclaims it after a lease unchanged) or a lock of a native
process copied along with the repository (native vl checks its pid). Each
fails with `Locked` naming the holder; removing `.veil/lock` by hand is the
remedy.
Single-writer use, and in-memory repositories, never meet it. The server's web
client, if it shares storage between tabs needs a lock built on the
platform's own (Web Locks API) behind `StorageBackend::create_new`.

**Packs without zstd.** The loose object format always was the
uncompressed canonical encoding, so only packs involve zstd:

* *Reading* uses `ruzstd`, which decodes every entry the C library writes.
  Delta entries are zstd frames compressed against their base as
  *raw-content* history (a dictionary, or a prefix with long-distance
  matching above 2 MiB, BUG-290). `ruzstd` only loads *formatted*
  dictionaries (magic, id, entropy tables, three repeat offsets, then
  content), so the base is given to it behind a fixed 112-byte header:
  tables cut from a trained dictionary and the repeat offsets 1, 4, 8,
  which are exactly what a raw-content dictionary starts with. The tables
  are never consulted: a frame compressed against raw content has no
  earlier tables to repeat, so its first block always carries its own. The
  frame must declare the recorded length, decoding stops as soon as the
  output would exceed it, the window is capped at 2^27 as for libzstd, and
  the result is re-hashed against its id like every pack read. Tests check
  the pure decoder against libzstd's output (plain frames at levels 1–19,
  dictionary and prefix deltas, property tests on random edits) and that
  damaged frames and random bytes are errors, never a panic.
* *Writing* (`PackBuilder` and `PackWriter`, so gc and sync) stores every entry as kind 0.
  Packs are larger but the format is unchanged; every vl reads them, and
  the next native `vl gc` recompresses them.

**Randomness**: getrandom's `wasm_js` backend (WebCrypto through
wasm-bindgen). A plain WebAssembly host without JavaScript glue builds
with `--cfg getrandom_backend="custom"` and `ruzstd` instead of `wasm`, and
supplies a `__getrandom_v03_custom` function (getrandom 0.4.3 does not
compile with both `wasm_js` and the custom backend).

**What is not there without `os`**: `DiskBackend`,
process-based lock recovery, worker threads (packs are compressed on the
calling thread), and the CLI.

**Testing.** `tests/portable.rs` runs in both configurations: the smoke
scenario (`examples/wasm_smoke.rs`: init, write, snapshot, read back, log,
diff, seal and unseal under a scope, an outsider, merge, pull, gc), the
format fixtures written by native vl (zstd frames and deltas) opened from
memory and verified, the installed clock, gc and reopen, and the lock
rules. CI's `wasm` job (`scripts/check-wasm.sh`) builds the crate for
`wasm32-unknown-unknown`, runs `portable` and the example natively with
the WASM feature set, runs the decoder tests (`--features ruzstd`), clippy
over the portable configurations, and finally the example compiled to
WebAssembly under node, whose only imports are a clock and randomness. The
example is about 4 MB of WebAssembly in a release build (1.2 MB gzipped),
2.2 MB (0.85 MB) with `opt-level = "z"`, fat LTO and stripped symbols;
the scenario takes about 50 ms.
## 14. The local server (`vl serve --local`, `crates/vl/src/serve.rs`)

A long-running process that serves one repository to editors and agents
over a Unix socket, `.veil/local/sock`, in newline-delimited JSON-RPC 2.0
(the contract: `docs/reference/json-rpc.md`).

**One code path with the CLI.** A read method builds its result with the
same `api` function `vl <command> --json` calls and serialises it with the
same writer (`api::to_json`), so a result is the CLI's line byte for byte;
`serve_cli.rs` compares them for every read command and every revision, as
a member and as a non-member. The write methods (`snapshot`, `describe`,
`new`, `commit`, `split`, `squash`) are `api::recorded`, `api::describe`,
`api::new_change`, `api::commit` and `api::shape::{split, squash}`, which
`vl describe`, `vl new`, `vl commit`, `vl split` and `vl squash` call too
(`split` and `squash` take a plan's `files`; there is no picker over the
socket).
Each calls one `Repo` method, i.e. one transaction under the repository
lock, so the server takes the lock exactly as the command does and records
the same operation (`vl undo`, `vl op restore` work on it). Server-only
glue reuses `main.rs`: the bare-repository refusal, the gate scan, the error
hint, and the `vl watch` tick.

**No state between requests.** Each request runs `Ctx::open` on the
repository root, exactly as a `vl` process does (identity, view, checkout
record, stat cache, the automatic snapshot), then
`Ctx::finish` if it snapshotted or wrote. Nothing is cached, so no request
can see a view older than the last operation that finished before it, and
the lock is never held between requests. Within the server, requests that
touch the working copy are serialised by a mutex (two in-process snapshots
racing would only retry, but the checkout record is read-modify-write);
reads with `"snapshot": false` skip both the snapshot and `finish`, never
write, and run in parallel. Against other processes the server is just
another `vl`.

**Bound to a repository, not to a path** (BUG-485). Opening by path every
time means a moved repository (`mv proj proj-old`) would leave the server
acting on whatever `proj` names next: another repository, or the nearest
one above it. So the server records at start the `(dev, ino)` of the root
and of `.veil`, and `repo.json`'s `repo_id`. Each request checks the two
inodes before `Ctx::open` (opened without its snapshot), then the root
`find_root` found, the `repo_id` and the inodes again, and only then
snapshots; the `watch` thread checks the inodes before each read of the
operation head, and `policy_from` is resolved only after the check. The
accept loop checks, every second, the inodes and that
`<root>/.veil/local/sock` *by path* is still the socket it bound (its
`.veil/local` descriptor follows a move, so it alone cannot tell). Any
mismatch refuses the request and stops the server, which unlinks its socket
through that descriptor. The engine works on paths, so a directory
descriptor cannot be threaded through it, and a server that followed its
repository would still listen where no client looks; what remains is the
race every `vl` process has, a move during a request.

**Access control** has three layers, each sufficient against another local
user:

1. `.veil/local` is opened with `O_DIRECTORY | O_NOFOLLOW`, must belong to
   the user (and so must `.veil`), and is made `0700`.
2. The socket is bound under `umask 0177` (no moment where it is wider than
   `0600`). It is bound and probed by its relative name after `fchdir` into
   the checked directory descriptor, which also lifts the ~104-byte limit on
   socket paths; this happens before any thread starts (the client is
   single-threaded).
3. Each accepted connection's peer credentials (`SO_PEERCRED` on Linux,
   `getpeereid` on macOS) must name the server's effective uid; others are
   closed unanswered. The client checks the server's credentials the same
   way, so it never sends a commit message to someone else's socket.

**Confidentiality** is the CLI's: the server answers as the user who
started it, through the same functions, so redactions, hidden descriptions
and the absence of secret values carry over unchanged (section 12). No
parameter is a path except `scan`'s `policy_from`, which is canonicalised
and must lie inside the repository, outside `.veil/`; nothing runs a
program. No string in the params (member names included) may hold a NUL,
which no command-line argument can (BUG-486); `api` refuses
one in a description too (`api::check_message`).

**Limits.** A request line is read up to 1 MiB without buffering more
(`read_line`); a longer one is refused and the connection closed (after a
short drain, so the close does not reset the connection before the client
reads the error). At most 32 clients, 64 requests per batch; a client that
does not read its answers for 60 s is dropped; JSON nesting is bounded by
`serde_json`'s recursion limit. A panic in a request is caught and answered
as an internal error.

Connections are bounded in time too (BUG-495): a connection must send its
first request within 30 s, and every request must arrive within 30 s of its
first byte (each read gets `SO_RCVTIMEO` set to what is left), or it is
closed (with a `-32600` for a half-sent request). Between requests a client
may stay silent, as an editor does. Each connection has a slot in a table
(state idle, busy or evicted, `watch` subscription, last activity); when
all 32 are taken, a newcomer takes the slot of the idle connection silent
longest, if it has been silent 10 s and is not subscribed to `watch`: the
slot is marked evicted under a compare-and-swap (so a request that just
arrived keeps it) and the connection shut down. Otherwise the newcomer gets
`-32001`, written by a thread of its own (at most 32 at once) so a client
that reads nothing never holds up the accept loop. The three durations can
be set in milliseconds through `VEIL_SERVE_IDLE_MS`,
`VEIL_SERVE_REQUEST_MS` and `VEIL_SERVE_EVICT_MS` (for tests).

**Lifetime.** The server holds an exclusive `flock` on
`.veil/local/serve.lock` for its life, so a second server refuses to start,
and a socket found at start-up is necessarily a dead server's: it is
removed if it is a socket nobody accepts on, and anything else at that path
is left alone. SIGINT, SIGTERM and SIGHUP write to a self-pipe watched by
the accept loop's `poll`; the server then stops accepting, unlinks the
socket if it is still the inode it bound, and waits up to 30 s for requests
in flight. It also exits if its socket disappears (the repository was
deleted), or if the repository is no longer at its path (see above).

**Notifications.** `watch` starts a thread per subscribed connection that
polls the operation head (one small file read) every `interval_ms` and
sends `changed` with the new head's `op.log` entry. With `working_copy` it
first runs the `vl watch` tick (snapshot, yielding to a command that is
checking the directory out), under the server's working-copy mutex. There
is no filesystem notification (inotify, FSEvents); a saved file is seen at
the next snapshot.

**Not served** (future work): `vl ws exec` and `vl run` (they run
programs), push/pull, and filesystem-event based notifications.

## 15. Hooks (`crates/vl/src/hooks.rs`)

Commands `vl` runs at fixed points (feature 5a of the Git-parity round;
user guide: `docs/guide/hooks.md`). They are a CLI concern: the engine never
starts a process, and `veil-core` has no hook API.

| point | call site | input | a failure |
|---|---|---|---|
| `pre-commit` | `cmd_commit`, `cmd_describe` of `@`, `serve` `commit` / `describe` | env `VEIL_SNAPSHOT`, `VEIL_WORKSPACE` | refuses |
| `commit-msg` | after `pre-commit` | `$1`: the message, `0600` in `.veil/local/tmp/` | refuses; an edit is used |
| `pre-push` | `cmd_push` | argv remote, `redact_url(url)`, `public`/`team`; stdin one line per tag | refuses |
| `post-checkout` | `run()`, after `ctx.finish()`, for `new`, `edit`, `ws switch` | old and new snapshot ids | warning |

**Sources.** Device-local hooks (`$VEIL_HOME/hooks/<name>`, then
`.veil/hooks/<name>`) run as they are, like `.git/hooks`. Nothing from a
tree can create them: `.veil` is never a tree entry (BUG-002). Repository
hooks come from the tracked TOML file `.veilhooks` (`[pre-commit] run =
[argv…]`, `files = […]`, or `[[pre-push]]` arrays). The parser is strict
(unknown hooks or keys, non-array `run`, paths that are not canonical and
relative or that point into `.veil`/`.git`, over 64 KiB, over 16 commands
per hook or 64 arguments are errors), and a file that does not parse runs
nothing and warns.

**Trust.** `vl hooks trust` records in `.veil/local/hooks-trust.json`
(`{version: 1, veilhooks: <blake3>, trusted: [{hook, command, digests,
indirect}]}`, `0600`, written by rename) the BLAKE3 of `.veilhooks` and the
state of every repository path a command names: each argv element that
names a repository path in any spelling (`hooks::classify` normalises
`./a`, `a//b`, `a/./b` to `a/b`, and reads the value of `--opt=a` and
`VAR=a`; BUG-701), whether or not a file is there (`absent` and `directory`
are states too), its `files`, and, for a known build tool (`make`, `npm`,
`cargo`, `pytest`, `python -m`, … in `INDIRECT`), the tool's own files
(`Makefile`, `package.json`, …). A directory is pinned as `tree:<blake3>`
of a manifest of every file below it (kind, path, content digest; at most
1024 entries and 64 MiB, no links) when `files` names it or the command's
program may run it (`python*`, `pypy*`, `node`, `bun`: `python3 tools` runs
`tools/__main__.py`; BUG-700); otherwise it is the command's data, as the
project directory it runs in is, and only `directory` is pinned. The
project root (`.`) is never pinned: it is the hook's working directory.
Build tools need `--i-understand-indirect`; they are recognised as the
program or anywhere after a known launcher (`hooks::LAUNCHERS`: `env`,
`nice`, `timeout`, `nohup`, `sudo`, `stdbuf`, `vl`, …; BUG-702).
`hooks::refusal` makes trust refuse, whatever the files hold, a command
that runs code given as text (`sh -c`, `bash -ec`, `python3 -c`, `node
-e`, `perl -e`, `ruby -e`, `php -r`, an `awk` program without `-f`, `env
-S`), runs its arguments through a shell or takes them from its input
(`xargs`, `watch`, `parallel`, …), gives the project root to an interpreter
that would run it (`python3 .`), or has an argument that names the project
in a way that cannot be pinned (through `..`, by absolute path, through
`/proc` or `/dev/fd`, under `.veil` or `.git`, glued to a short option as
in `-Iscripts/x`, in a `PATH`-like list). A record made by an older `vl`
for such a command, or one missing a path this `vl` pins, does not count
as trust. A repository hook runs only when the whole
record matches: any change to any pinned path untrusts every command of the
file (all or nothing, so a security check is never silently dropped while
the rest still runs), and each command that would have run it warns,
naming the paths and the change that last touched them (a bounded
first-parent walk). The record is device-local: never synced, never in a
tree, and written only by `vl hooks trust`, on a terminal or with `--yes`,
never from inside a hook (`VEIL_HOOK` set) and with no `vl serve` method.
It is re-checked against the files after the confirmation, so what is
trusted is what was shown.

**Execution.** `std::process::Command`, no shell. A pinned file the command
runs or is given is read once (`O_NOFOLLOW`, a regular file, at most 64
MiB), hashed, compared with its trusted digest, and written to
`.veil/local/hooks-run/<digest prefix>-<unique>` (`0700`, directory `0700`);
the argv gets that copy (after its `--opt=` or `VAR=` prefix), which is
removed afterwards. A `tree:` directory is read whole, checked against its
manifest digest, and copied the same way (a private directory). A script swapped
between the check and `exec` cannot run (copy-then-exec). Programs named
bare are resolved on a cleaned `PATH` (absolute entries outside the
project only) and must resolve outside the project; an absolute argument
inside the project is refused. The environment is cleared and rebuilt from
`ALLOWED_ENV` (`HOME`, `USER`, `LOGNAME`, `LANG`, `TERM`, `TMPDIR`, `TZ`,
`VEIL_HOME`) plus `LC_*`, the cleaned `PATH`, and `VEIL_HOOK`,
`VEIL_SNAPSHOT`, `VEIL_WORKSPACE`: no vault values (`vl run` is the
explicit route), no inherited `VEIL_*`/`GIT_*`. stdout and stderr both go to
`vl`'s stderr (never into `--json` or a `vl serve` reply); stdin is
`/dev/null` except for `pre-push`. The hook gets its own process group:
`VEIL_HOOK_TIMEOUT` (1 s to 7 days, default 600 s, anything else an error
before anything runs) kills the group; the group is also killed once the
hook exits; SIGINT/SIGTERM/SIGHUP/SIGQUIT received meanwhile are forwarded
to the group and re-raised under `vl`'s own disposition once the hook is
gone. `ETXTBSY` on a fresh copy is retried.

**No lock, re-checked.** No repository lock is held while hooks run (each
`Repo` method takes it for its own transaction), so a hook may run `vl`.
After `pre-commit`/`commit-msg`, `before_commit` reloads the view and, when
the command snapshots, records the directory again; if the operation log
moved (a file the hook edited, a `vl describe` it ran), the commit is
refused: the edits are in `@`, nothing is lost. `before_push` compares the
tags instead. `vl` started inside a hook runs no hooks (no recursion).

**Input never carries sealed content.** No hook input carries file content.
`pre-push` lines name each tag whose target differs from the server's
(`<tag> <snapshot> <remote-snapshot-or-0>`, `hooks::push_lines`), as the
push sends it. A trusted hook runs as the user in the project directory
and can read what the user can: that is the documented trust boundary.

**Where hooks do not run.** `ws exec` sandboxes and FUSE mounts record
through the engine, not through `cmd_commit`, and `vl` inside a sandbox
finds no repository (`find_root`).

## 16. Attributes and line endings (`attributes.rs`)

Feature 7 of the Git-parity round (design and threat review:
`docs/design/git-parity/7-attributes-line-endings.md`; user guide:
`docs/guide/line-endings-and-attributes.md`). No format change:
`.veilattributes` is a tracked file, and conversion only decides which
bytes are recorded and written.

**Reading.** `attributes::Attrs` reads `.veilattributes` itself, lazily:
only the directories of the paths asked about, each file once
(`AttrSource`: a working copy's backend, never through a symlink, or a
recorded tree, where a file the reader cannot open counts as absent with a
warning), and parses a file only when an attribute is asked for. The
device-local `.veil/local/attributes` (`ObjectStore::local_attributes`) has
the highest priority. Matching ports Git's `wildmatch.c` and `attr.c`
exactly (basename versus pathname patterns, `**` rules, `[attr]` macros
from the top level only, the built-in `binary`, `!name`, the precedence of
deeper files and later lines). Exact names
and `*suffix` patterns are indexed, so a megabyte of them costs a lookup
little. Limits: 1 MiB per file (ignored as a whole), Git's 2 048 bytes per
line.

**Conversion** (`Conversion`, `to_odb`, `to_worktree`) follows Git's
`convert.c` with `core.autocrlf=false` and LF native, with one deviation:
`to_odb` refuses a lossy conversion (`ToOdb::Lossy`: a lone CR, or CRLF
mixed with lone LF), which Git performs with a warning.

* **Recording** (`builder::Builder::line_endings`, before hashing,
  scanning and sealing, on the one buffer). A file holding no CR costs
  nothing. A file that still stands for its parent entry keeps it (its
  bytes, or the CRLF rendering checkout wrote for it, `Materialised::crlf`),
  whatever the attributes now say: changing `.veilattributes` never
  re-records a file (`BuildReport::renormalizable` lists those a
  renormalisation would change). Otherwise the attributes of the working
  copy decide. `LineEndings::Renormalize` (`vl renormalize`, an operation of
  its own) ignores the parent for the paths selected.
* **Checkout** (`checkout::apply_changes`) converts what it writes with the
  attributes of the tree it checks out (files, conflict renderings),
  records each CRLF write in `Materialised` (absent in older
  records: no conversion assumed), and never reflinks a file it converts.
  `holds` (may this file be replaced?) accepts the recorded bytes, the CRLF
  rendering recorded for the path, or bytes the `from` tree's attributes
  normalise to the version: an attribute change neither wedges an unedited
  file nor hides an edit.
* **Conflicts.** Markers are rendered on LF content and converted for the
  working copy; the builder undoes the conversion before comparing or
  parsing a copy back.

**Diff and merge.** `-diff`/`binary` make `vl diff` and `show`
show binary (`api::content`, attributes of the working copy, as Git). In
`merge.rs`
stream R's `content_merge` seam picks the content merge (`strategy`,
`attribute_merge`) from the attributes of `ours` with the followed renames
applied, so a renamed file merges under the attributes of its new path,
read as the merged file's audience reads them (`MergeAttrs`,
`attributes::AudienceTreeSource`, BUG-705): a `.veilattributes` sealed for
another audience gives its last public version or nothing, so a sealed
`merge=union` never decides a public result, and a member and a
non-member merge the same public files alike: `Binary` (whole-file conflict), `Union`
(`textmerge::merge_union`), a device driver, or the built-in line merge.
A driver or union gets the base only when `base_shown` (its audience is
the result's), never runs across an `audience_clash`, and its output is
sealed by `merged_visibility`. A virtual merge base never runs a driver.

**Drivers are device-local.** `.veilattributes` only names a driver. The
engine knows only what the device registered on the store
(`DeviceDrivers`, `ObjectStore::set_device_drivers`); the CLI registers
`attr_cmd::LocalDrivers` from `$VEIL_HOME/config.toml` and
`.veil/local/config.toml`, and nothing else. Its runner follows the hooks
trust model (§15): a program on a cleaned `PATH` or absolute, never inside
the project; scrubbed environment; `vl`'s process group (Ctrl-C stops
both); 60 s limit; merge
inputs in a fresh 0700 directory under `.veil/local/tmp/`, removed
afterwards; textconv input on stdin, output never stored.

## Threat model

**Trust boundary.** Every security finding must name an attacker outside this boundary, what that attacker controls, and the concrete harm. A finding that needs something inside the boundary to be hostile is out of scope: it is recorded as such, not fixed.

**With the server** (`docs/HUB.md` §3; milestone S1 is built to it, §13):

*Trusted:*

* **the Veil server, with plain-text code,** branch tips, group and admin records, folder access and metadata. It enforces every permission. Someone who breaks into it reads the code; that is accepted (`docs/OVERVIEW.md`, non-goals);
* **regional caches** (`veil-server cache`, `docs/HUB.md` §13.18; owner-delegated, 2026-11-07), run by the server's operator, inside the server's boundary. A cache holds the caches' token, hash-checked objects (secret files only as ciphertext), the server's public grant key and nothing else: no key that opens a secret, no session, no database and no permission authority. It serves an object only under a grant the server signed, a request signed by the grant's device, a chain checked from the grant's root, and access epochs the server confirmed within 5 s; past that it fails closed and passes requests to the server. **A compromised cache** can serve what it already holds to anyone, so it is as trusted as the object store; it can never sign a grant or read a secret;
* each person's device and OS account, and the identity and key files on it. Anyone who can run commands as the person, read their process memory or replace the `vl` binary already holds their keys. Protecting key files at rest is a backlog item, not a bug;
* each person's own deliberate commands, including `public!`, `--force`, `--no-verify` and their own edits to `.veilpolicy` (the server still checks who may change access). Veil warns but obeys;
* the OS, the file system, and the toolchain and dependencies `vl` was built with.

*Not trusted:*

* **the server, with secrets.** It stores only their ciphertext and never holds a key that opens them. Personal private keys never reach it. **Nor can it hand a secret out:** a key is granted only by a signed change in the key ring, never by the server's group records, which a compromised server could rewrite: a ring admin's grant, or a member's share that carries a proof only someone outside the server can make (an invite join, or the person's own vouch), which every reader's replay checks (`docs/HUB.md` §13.6, §13.12);
* people outside a folder's access, including others in the same project, and members after they are removed;
* anything that arrives by push, pull, fetch or merge: trees, names, descriptions, policies, hooks and metadata;
* the network, and other OS users on the same machine;
* **a command confined by `vl ws exec`** (Linux, `docs/design/scale/9-confinement.md`; owner, 2026-11-06). It runs as the person, but for files it is outside the trust boundary: it cannot read the person's private files (keys, the rest of the home, the Veil identity, the real repository and other workspaces' sandboxes) or write outside its sandbox, and the files it leaves are untrusted input to `vl`. By the owner's choice it gets the environment variables, and the network unless `--no-network` (with `--private-ports`, a loopback of its own and outbound access through `pasta`; milestone S8); it reaches its person's `vl` only through the workspace socket, which runs workspace commands on its own workspace as the `vl` outside (`crate::ws_socket`, `9-confinement.md` item 17); what it is given (the environment, injected secrets, the allow-list) it can use and send anywhere; what it writes to the allow-list stays in its workspace's layers, read by that workspace's later confined runs only. An unconfined run (`--unconfined`, or `vl bisect run`) is the person's own deliberate command.

Secret files are sealed for scopes (§3–§4), so teammates outside a secret's scope, and revoked members after their revocation, are not trusted with it. `vl` syncs only through the Veil server; path and SFTP remotes, whose operators were not trusted, were removed in the simplification pass, part 1. The engine still enforces its filters on any repository-to-repository transfer (`remote::push`/`pull`, in process), so they are kept and tested.

The lists below describe what today's client protects, and what not.

**Protected against:**

* accidental commits of secrets (engine rules plus the scanner, with no ignore
  file to forget);
* leaking sealed secrets to public remotes;
* readers of a team remote who are not in a secret's scope (they get
  ciphertext only);
* pre-release disclosure of embargoed changes by `vl`: an unreleased
  embargoed merge, the history it brings in and anything built on it are
  never pushed (§7, §8);
* publishing a secret as a side effect. Rebase, `new`, squash, a policy
  edit that arrives by merge, and push never move sealed content to a wider
  audience; only `vl expose --force` does. No merge moves content from one
  scope to another;
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
* **a conflicting embargo record from a remote.** A record whose scope,
  deadline or creation differ from the local one's is refused; who may
  release is the server's to enforce;
* **stripped or transplanted snapshot signatures.** The id commits to the
  signature, and a transplant fails verification. Both show in `vl log`;
* **hostile trees and metadata from a remote.** Path traversal (`..`, `/`),
  writes into `.veil/`, non-canonical trees, stack exhaustion by deep
  nesting, dangling tags and terminal escape sequences in names and
  descriptions (the CLI escapes control and bidi characters) are refused
  (§2, §8).
* **forged visibility metadata from a remote or an import** (BUG-103).
  Visibility labels of tree entries are written by whoever produced the
  snapshot (anyone who can push to a team
  remote), so they are *claims*, never authority. The
  audience of **new** content (an edit, merged or rebased content) is
  decided from trusted inputs only: the accepted policy pin and the
  *verified* sealing of
  the parent entry, i.e. the scope in the envelope label of the object
  itself (bound to the ciphertext by the AEAD), checked against the label
  the entry claims. A mismatch is hostile: the snapshot warns
  (`BuildReport::relabelled`) and seals under what the object really is.
  New content is never sealed under a key generation (`team#<old>`, which a revoked member holds), `local`, or
  a scope the label merely names (§4, rule 5).
* **code execution from a teammate's content** (§15). Nothing that arrives
  by pull or merge runs: repository hooks run only from
  bytes this device pinned by digest (copy-then-exec), with a scrubbed
  environment and a timeout; `.veil/hooks` cannot be written from a tree.

**Not protected against (yet), and documented honestly:**

* *File names, sizes and tree shape* of sealed secret files are visible to anyone
  who can read the repository. With the server, people without access to a
  folder don't receive its names at all (HUB.md §5.4).
* *Equality leakage* from deterministic sealing (see §2).
* *Revocation is forward-only.* A revoked member keeps every key up to the
  revocation, and with it all history sealed before it (including unchanged
  files that are still sealed under an old generation). They also keep
  anything they already decrypted. Rotate the underlying secrets.
* *Team-vault metadata* (§3): a team remote's operator sees how many
  records a scope has, their sizes in 128-byte steps, write times and
  signers, though no names or values. They can also withhold records, so a
  fresh clone may see an older value or a deleted secret come back; replicas
  that already hold the newer record keep it. A current member can write
  any value, and stamp it up to a day ahead (it still loses to any later
  write by someone who pulled it).
* *First contact is trust-on-first-use.* A fresh clone accepts the first
  valid ring it sees. A malicious remote can serve a **fork** created by an
  admin who was revoked later: the fork is valid at its fork point. Also, a
  remote can withhold newer changes (a freshness or rollback attack against
  replicas that never saw them). Replicas that already hold the newer log
  reject both. Out-of-band pinning of the ring head is future work.
* *Concurrent admin edits are not merged automatically.* Diverged logs keep
  the local ring and warn, and an admin re-applies the missing changes.
* *A trusted hook is code running as you.* It can read what you can in the
  project (and run `vl cat`). Trusting a build tool (`make`, `npm`) trusts
  what its pinned files pull in further, which is not pinned (§15).
* *Snapshot signatures are advisory.* Unsigned and unknown-key snapshots are
  shown but not rejected, and there is no "require signed" policy yet.
  `author` is a free-form claim; only the signer is authenticated.
* *Members granted by short member id* (without a signing key) cannot sign
  ring changes, and their snapshot signatures show as unknown.
* *Bindings recorded in rings* start with repository format 3. In
  format-1/2 rings (and grants made before bindings existed) the admin's vl
  checked the binding but readers cannot, so a hostile admin can record an
  unbound grant of a signing key nobody in that ring holds yet. It is
  believed only where no ring proves a binding for the key.
* *What a public remote reveals about scopes.* Public remotes receive no
  key rings (BUG-077): a clone of a public mirror cannot list scopes'
  members, roles, names or membership history. What stays visible there:
  scope names (in the labels of redacted tree entries and in embargo
  records); the member id and signing key of whoever signed a public
  snapshot (the signature names them), with the snapshot's free-form
  `author`; and embargo records themselves (scope, deadline, release).
  Without rings, a public clone shows every snapshot signature as
  "unknown key". Rings that an earlier vl pushed to a public remote stay
  there (removing them would lock members out of a team remote added as
  public by mistake); every public push warns about them until someone
  deletes `.veil/meta/keyrings/` on that remote. Team remotes still hold
  the full rings, so anyone who can read a team remote sees the
  membership.
* *Rings on a non-member remote* (for example a bare remote without an
  identity) cannot check the genesis proof. Members check it when they pull.
* *Embargoes are not encryption.* Anyone with the repository on their disk
  (a teammate's clone, a backup) reads an embargoed fix; `vl` only never
  sends it before the release, and the server's permissions are what
  protects it there. The deadline is a plain field: a passed deadline
  counts as released everywhere.
* *An embargo release is final once pushed.* Until the next push it is
  staged locally and `vl undo` takes it back (§7).
* *History withheld by an embargo* is computed from the local graph, by
  **change**, in one place (`remote::Withheld`; push, the copy checks of
  `confinement`, `vl blame --public`, the JSON tiers and the commit check
  all ask it). For each visible merge of an unreleased embargo, the fix
  line is the history behind its other parents and not behind its first
  parent, plus the merge, for the merge and every earlier version of it
  (`predecessors`). Every version of a change of a fix line is withheld
  (unless behind the first parent: already on the public line), whatever
  its snapshot id, and so is everything that descends from one. Queries
  walk the graph index from the snapshots asked about down to the first
  parents, never the whole history. Every transaction that changes the
  visible embargoed merges, or rewrites anything, keeps two invariants
  (`Transaction::check_withheld`): a version of a withheld change still
  visible afterwards is still withheld, unless the embargo was released or
  withdrawn; and every withheld snapshot the transaction rewrote (not
  abandoned) has visible successors that are still withheld, unless the
  embargo was released (BUG-1040: work withheld only because it descends
  from the merge, holding the fix after `vl squash -r fix --into` it). A
  squash or abandon of the merge while a change built on it survives, a
  squash of it into the fix, or a rebase of it onto other parents is
  refused; a merge of concurrent operations drops such a rewrite (BUG-942,
  943, 990, 1015, 1016, 1040). An embargo is *withdrawn* when no visible
  snapshot carries it any more and the transaction rewrote nothing it
  withheld, only dropped it (the merge undone, or abandoned bare): nothing protects the fix line any
  more, `vl embargo list` says `withdrawn`, and the next push that
  publishes it warns (BUG-1017). `vl blame --public` refuses a revision a
  push withholds (BUG-991).
* Content committed in plaintext **before** a path was cloaked stays readable
  in those older snapshots. `vl cloak` warns when this applies.

## Limitations and roadmap

* **The server's later milestones** ([HUB.md](HUB.md) §13.9): embargoed
  merges cannot be pushed to the server yet, so with path
  remotes gone (the simplification pass, part 1) they stay on the device
  until the server takes them. The lock's fencing leases for network
  backends (§9) are unused since SFTP went, and are still to be removed.
* Performance: recording checked-out files
  in the stat cache (needs a backend write that returns the stat of the
  file it wrote). `gc` always rewrites everything it keeps, into packs of
  at most about 128 MiB each, streamed (BUG-800); incremental packing
  (small packs merged geometrically) and cross-pack deltas are next. gc
  and pull still hold a few table entries per object of the store (the
  inventory, the reachability set), so their memory still grows with the
  number of objects, though no longer with their size.
* With the server, people without access to a folder receive neither its
  files nor their names (a per-viewer projection, [HUB.md](HUB.md) §5.4).
  A "require signed snapshots" policy.
* Conflicts (format 4): parsing back partly edited copies of conflicts of
  more than two sides (today any edit of such a copy resolves it as the
  file is), hunk-level rendering of many-sided conflicts, directory
  versions in a conflict (file/directory conflicts still move the file
  aside), and an external merge tool for `vl resolve`.
* Front-ends: the FUSE mount (§6) has no NFS fallback for machines
  without FUSE, holds an open file in memory, renames a directory by
  copying it, and is not tested on macOS in CI; the project directory
  itself is never a mount. (The WASM build of `veil-core` exists, §13; a
  browser front-end on it, a persistent browser `StorageBackend` and a
  lock that works across tabs do not yet.)
* Attributes (§16): `filter`, `ident` and `working-tree-encoding` are not
  supported (bytes are recorded as they are on disk); the FUSE mount shows
  recorded line endings (no conversion on read); a converted file
  (`eol=crlf` on disk) is cached through its `EolFact` but checkout never
  reflinks it; mixed-ending files are recorded unchanged where Git would
  normalise them; patterns match case-sensitively on every device.
