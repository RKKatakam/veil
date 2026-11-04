# Veil architecture

Veil is built as a stack of small layers. Each layer only depends on the ones
below it, and nothing above the VFS layer knows a disk exists.

```text
┌──────────────────────────────────────────────────────────────────────┐
│ vl CLI   (clap grammar, auto-snapshot, checkout pointer, rendering)  │
├──────────────────────────────────────────────────────────────────────┤
│ Features  workspace · commands · embargo · remote · git · vault      │
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
| `SftpBackend` | – (another machine's clock) | `None` |

* **DiskBackend** does atomic, durable writes (temp file, fsync, rename,
  fsync of the directory; see §9) and ignores symlinks: `metadata` reports
  nothing at one and `read` refuses one. A path below a file is simply
  missing (ENOTDIR is "not found"), as on every backend. `list_dir_full`
  additionally reports what `list_dir` leaves out: *special* entries
  (symlinks, sockets, devices) and names that are not valid UTF-8, which a
  `VPath` cannot represent. The builder warns about the latter and checkout
  never writes through or over the former (§4). `write`, `write_unsynced`
  and `create_new` themselves also refuse a path below a symlinked
  directory, whoever calls them (one `lstat` per directory above the path),
  except under the engine's own `.veil/`, which may be a link to another
  disk.
* **MemoryBackend** is a flat `BTreeMap<VPath, Node>`. Because the
  descendants of `a/` are contiguous in string order, directory listings are
  range scans. File buffers are `Arc`-shared. Every file write takes a fresh
  value from a monotonic generation counter, reported as `mtime`.
* **OverlayBackend** is copy-on-write. An in-memory upper layer and a
  whiteout set sit over any read-only lower layer. Ancestor whiteouts hide
  whole subtrees. A file in the way of a directory is an error, exactly as
  on the other backends; it is never whited out implicitly.
* **SftpBackend** (`vfs/sftp*.rs`) is a repository on another machine,
  reached through the user's own `ssh` (`ssh … -s -- host sftp`, as
  `sftp(1)` runs it; `VEIL_SSH` replaces the command), so `~/.ssh/config`,
  the agent, `known_hosts` and ProxyJump just work and the server needs only
  SSH. It speaks SFTP version 3 itself: a small pipelined client in which
  any number of threads keep any number of requests in flight, a reader
  thread routing replies by request id. `write` is a temp file opened with
  `O_EXCL`, written with every chunk in flight, `fsync@openssh.com`, then
  `posix-rename@openssh.com`; `write_unsynced` skips the fsync and queues
  the file, and `sync_barrier` opens, fsyncs and closes every queued file in
  one pipelined batch. `create_new` writes a synced temp file and
  `hardlink@openssh.com`s it into place (fails if the target exists), or
  falls back to `OPEN` with `CREAT|EXCL`. `read` stats and opens in one
  round trip and reads everything in the next (255 KiB requests, short
  reads re-requested, a probe past the expected end). "No such file" maps
  to `NotFound`, other statuses to `Io` with a matching `ErrorKind`, a lost
  connection to `ConnectionAborted`. SFTP cannot fsync a directory, so a rename is as durable
  as the server's file system makes it after the file itself was synced.
  `is_network()` is true: its lock is a fencing lease (§9) and sync batches
  requests (§8). Remote URLs are `ssh://[user@]host[:port]/path` (`/~/` for
  the home directory) and scp-style `[user@]host:path`; as in Git, a `:`
  after a `/` makes a local path.
  *A hostile or broken server* can neither hang the client nor exhaust its
  memory (BUG-065, BUG-066). A writer thread sends requests, so a server
  that stops reading never blocks a caller. Every request has its own
  timeout: 300 s (`VEIL_SFTP_TIMEOUT`, in seconds), counted from when it
  was sent or from the latest reply to an *earlier* request (servers answer
  in order, so a deep pipeline on a slow link is progress); the handshake
  has the same timeout. Replies to later requests, or to none at all, never
  extend it, and more than 16 replies to requests never made close the
  connection as a protocol error. Packets over 1 MiB are refused. One
  `read` accepts the size the server stated plus 16 MiB (the file may have
  been replaced between the stat and the open; Veil's mutable files are
  small, packs and objects never change), and never more than 4 GiB
  (`VEIL_SFTP_MAX_FILE`, e.g. `8G`); `read_range` reads exactly what was
  asked, within the same ceiling. A directory listing accepts 1,000,000
  entries (`VEIL_SFTP_MAX_LISTING`) and 256 MiB of names, and
  `remove_dir_all` descends 256 levels. Each limit fails the operation with
  a message that names it. Status messages from the server are stripped of
  control characters before they reach the terminal.
  *Why not a library:* `openssh-sftp-client` (with `openssh`) also drives
  the system `ssh`, but is async-only: a tokio runtime under a synchronous,
  `&self`, multi-threaded `StorageBackend`, for a protocol that takes a few
  hundred lines. `russh` and `ssh2` (libssh2) bring their own SSH
  implementation, so the user's config, agent forwarding, ProxyJump,
  ControlMaster, FIDO keys and known_hosts handling would all have to be
  re-created (or would silently differ), and `ssh2` adds a C dependency.
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
veil:tree\n   0x02 binary entries (format 2)  |  JSON { entries: [ {name, kind, id, size, executable, visibility, fallback} ] } (format 1)
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
Re-snapshotting an unchanged cloaked file therefore gives the same id. That
means deduplication and no-op snapshots still work for encrypted content. The
cost is that equal plaintexts under the same scope are linkable, the same
trade-off convergent-encryption backups make. Descriptions, sealed keys and
the vault use XChaCha20-Poly1305 with random nonces.

## 3. Identities, scopes and the keychain

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
| embargo record | `(id, scope, wrapped, until, created, description, scope_key, key_id)` (`description` is always empty) | on pull; signer must be (or have been) a member of the scope |
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
    member (if rings disagree about a key, a ring that proved the binding
    wins; otherwise the key counts as unknown);
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
| embargoed (merge) | sealed tree + pre-merge fallback | ✓ (merged-in history: cloaked part only) | fallback only until release |

The **builder** (`builder.rs`) is the single point where content enters the
CAS, and it applies these rules in order:

1. Ignored paths are skipped. That includes, built in and at any depth,
   the metadata of other version control systems: a `.git` directory or
   `.git` file (worktrees, submodules), `.jj/`, `.hg/`, `.svn/`, in any
   ASCII case and with HFS+-ignorable code points
   (`policy::vcs_metadata`; the Git bridge's refusal of `.git` entries uses
   the same test). No `.veilpolicy` rule records them (not `** public`,
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
     another change, rebase, Git import or undo. Each working copy keeps,
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
     `undo`, `op restore`, `merge`, `rebase`, `git pull`) moves the working
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
     `shared.veilpolicy`), so a hostile Git checkout's
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
     `.veilpolicy` in a sandbox cannot accept it for the member. The
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
     isolated files, and pull + `vl new`, checkout, rebase, Git import and
     undo bypass merge entirely; the working-copy snapshot is the one place
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
     `Option<String>,`) and identifiers made of words
     (`settings.SECRET_KEY`; long words are judged by letter-pair
     frequencies, so `qzvxkwprmtfhjlnb` is no word) do not count, and the
     entropy bar is lower for short, hex and lower-case values. The rest of
     a line counts only where the key starts a configuration line. A PEM
     header inside binary data needs key material after it (after a real
     or an escaped `\n`, as in a service-account JSON key inside a `.tar`).
     Uncompressed archives (`.tar`, stored `.zip` entries) are scanned as
     their bytes are; compressed ones (`.tar.gz`, deflated `.zip`, `.docx`,
     `.jar`) are not decompressed.
   * Time is linear in the input: repetitions that could hold another match
     are bounded, so a search reads at most about 1 KiB past its match, and
     the work redone after restarting inside a rejected match is counted;
     past 16 times the input the file is reported (`scan-limit`) and
     quarantined. Crafted input scans at 24+ MiB/s, ordinary text at
     300–450 MiB/s (dense synthetic corpus) or ~1.5 GiB/s (real source).
   * Keys: the credential keywords match anywhere in an identifier
     (`DB_PASSWORD`, `spring.datasource.password`), plural or numbered
     (`API_KEYS`, `PASSWORD2`), plus up to six suffix words
     (`DB_PASSWORD_PROD_EU_WEST_1`, `aws_secret_access_key`) unless one
     of them says the value is something else (`password_hash`,
     `token_url`, `secret_name`, `…_file`, `…_path`). The generic `secret`
     and `token` only count as a word of their own (`JWT_SECRET`, not
     `mytoken`), and `token` not after a word that names a non-credential
     (`csrf_token`, `next_page_token`, `cancellation_token`). `key` alone
     is no keyword; a short list of `*_KEY` / `*_SALT` names is (`APP_KEY`,
     `RAILS_MASTER_KEY`, `ENCRYPTION_KEY`, `SIGNING_KEY`, `AccountKey`,
     WordPress's `AUTH_KEY` … `NONCE_SALT`), as a word or camelCase hump. camelCase
     generic tokens (`githubToken`) are not matched; `authToken`,
     `accessToken`, `apiKey`, `clientSecret` are. A URL password must not
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
5. Cloaked files are sealed under their scope. In a cloaked workspace, every
   public file it introduces is sealed under the workspace scope, and the
   description is too.
   * **Sealed content keeps its audience.** A tracked file the parent holds
     sealed under scope `s` stays sealed under `s`, edited or not, whatever
     the workspace or the current policy says, unless this very snapshot
     edits `.veilpolicy` so that the path's classification changes. That is
     how `vl expose` and `vl cloak --scope` work, and an expose to `public`
     still goes through the secret scanner below. A policy that arrived by
     merge, `vl new <cloaked change>` in an ordinary workspace, rebases and
     squashes never move sealed content to another audience.
   * **"Now sealed" never reads as "deleted".** A file the policy says is
     public but that is sealed because of the line it is edited on (a
     cloaked workspace, or sealed content keeping its audience) carries its
     **last public version** as the entry's `fallback`, as an embargoed
     file does: the parent's public entry, or the fallback the parent's
     sealed entry already carried. Readers without the key (public remotes,
     the Git projection, members of other scopes) see and check out that
     version; key holders see the edit. Squash into a cloaked change
     (`seal_introduced`), merges into a cloaked line (`normalize_tree`) and
     diff3 merges (`merged_visibility`: the other side's public version
     when there is one, so a rebase onto a public edit shows the newer
     public version) keep the same rule. Edited back to that version, the
     file is recorded public again. A file the *policy* cloaks (`vl cloak`)
     carries no fallback: hiding it is the point, so public readers lose it.
     The fallback reveals nothing new (it was public), and nothing reads a
     cloaked entry's fallback as its content: merges and declassification
     read the sealed object itself (no key: refused), so the old version is
     never re-sealed or published in place of the edit.
   * A reader without the key who edits such a file cannot seal the edit:
     it is held back (`BuildReport::cloak_failures`; the file stays local)
     and the recorded entry is kept, as is any tracked file this reader
     cannot seal. Deleting the copy shown is not a deletion of the sealed
     content (it is carried, rule 7). Before this rule (BUG-074), such an
     edit made the public side see the file deleted, on GitHub as a commit
     deleting it.
6. Embargoed entries stay embargoed until their embargo is released, and a
   tree under an unreleased embargo stays under it (§7). A key holder's
   edit of an embargoed file is secret-scanned like a public one, because
   the release publishes it; a hit is quarantined and the previous (sealed)
   entry kept. An embargoed entry only stays under the embargo while its
   path would be public anyway: once the policy (or the line's cloak) seals
   the path under a scope, an edit, or a merge, seals it under that scope
   instead, so the release never publishes it.
7. Entries this reader cannot materialise (no key, or withheld by a public
   remote) are **carried over** instead of being treated as deletions. A
   partial view can never accidentally delete hidden content.

The working copy itself is untrusted ground. Nothing in it can fail a
snapshot (and with it every command), and nothing is dropped silently:

* Leftovers of an interrupted `DiskBackend` write (`.name.vltmpXXXXXXXX`)
  are crash debris and are skipped.
* An unreadable file or directory (permission denied) is reported. A tracked
  one keeps its previous entry, an untracked one stays out, and the command
  goes on, so `vl ignore` still works.
* Names that are not valid UTF-8 cannot be recorded and are reported on
  every snapshot.
* A tracked path that is now a symlink (or socket, device) is never
  followed. Its tracked entry is kept and reported. Checkout and
  `vl restore` never write, remove or prune at or below such an entry
  (`CheckoutReport::blocked`), so an untracked `vendor -> /shared/vendor`
  link never receives pulled files.

Local-only files (isolated and quarantined) are backed up into the vault, so
`vl ws exec --with-isolated` can inject `.env` into a sandbox without it ever
touching history. The sandbox is then snapshotted with those contents as
`InjectedSecrets`. Any new or changed file, of any tier, that contains one of
the injected values is quarantined (`injected-isolated-secret`), so a command
cannot record a copy under another name. The values are: each `KEY=value`
value that looks like a secret (8+ characters, and either 20+ characters or a
mix of character classes, so `localhost` or `3000` never match), plus the
whole content and every whitespace-free line of 24+ characters (key
material).

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
  `op restore` reinstate an older view, and then the CLI checks out the
  difference. Uncommitted edits survive both: the automatic snapshots of the
  attached workspace at the top of the op log are not commands, so undo
  skips them and undoes the operation before. The edits they recorded are
  re-applied on the restored working copy with a 3-way merge
  (`Repo::undo_keeping_edits`, `Repo::restore_operation_keeping_edits`).
* **Commit and tags.** `vl commit` (`Repo::commit`) moves the tags that
  pointed at the working copy's first parent to the committed change, so
  `main` follows commits made on it. On a **cloaked line** (the workspace
  or the change is cloaked under `S`) only tags cloaked under `S` move: an
  uncloaked tag is what public remotes and Git receive, and cloaked work
  reaches it only through an explicit `vl merge` (published after a scan,
  or embargoed) or `vl tag set`. `vl commit --no-advance` moves no tag. The
  CLI names the tags that stayed and how to move them (BUG-075).
* **Transactions auto-rebase.** Rewrites and abandons go into a
  `rewritten` map. On commit, every visible descendant is rebased in
  topological order with a 3-way tree merge
  (`base = old parent tree, ours = new parent tree, theirs = child tree`).
  Tags and workspaces are then re-pointed, and an abandoned working copy gets
  a fresh empty change. Empty, undescribed working-copy changes you move away
  from are abandoned automatically.
* **Merging** is tree-level. Identical subtrees resolve by id, and files
  changed on both sides go through diff3 (`diffy`). Conflicts are written as
  markers and recorded on the snapshot until the file is edited. `vl merge`
  records them on the merge and continues on a new change on top, so
  `vl status` lists the conflicts of `@` and those of its parents whose
  file `@` has not touched yet.
* **Visibility never silently widens.** Declassification (any move from
  cloaked or embargoed to more visible) is an explicit act by a member: a
  `vl merge` of a cloaked line of work, or a `vl expose`, both of which go
  through the secret scanner. It is never a side effect:
  * a file merged by diff3 keeps the sealing of whichever side is sealed
    (ours first). This matters for auto-rebase, where "ours" is the new,
    possibly public, parent;
  * `vl merge` (`embargo::normalize_tree`) may seal content, but never
    re-keys sealed content or makes it public, with one exception. Files of a
    merged-in **cloaked line of work** become public when both the
    destination's policy and the merged policy say so. Each is scanned
    first: a hit is left out of the merge (the destination keeps its own
    version), and `vl merge` lists what it published and what it
    quarantined. A file the destination holds sealed keeps that audience
    even if the merged side exposed or re-keyed it;
  * a merged `.veilpolicy` that would change the audience of existing
    sealed files (`prod/ cloak ops` → `prod/ cloak opz`, or → `public!`)
    is **not taken**. The destination's policy is kept and `vl merge` warns.
    Applying it is a deliberate edit on the destination. So a pull request
    that only edits the policy cannot re-encrypt files to a scope its author
    controls;
  * squashing a cloaked change into a public parent seals the joined
    description; squashing anything into a cloaked change seals what it
    brings (a public file keeping its last public version as fallback,
    §4 rule 5). A squash keeps a recorded conflict only if the squashed
    change left the file untouched, or has the conflict itself;
  * the builder rule above (sealed content keeps its audience) covers
    working copies.

## 6. Workspaces

A workspace is only a named pointer in the view. It owns no directory.

* The **project directory** is attached to one workspace at a time.
  `.veil/local/checkout.json` records which workspace and which snapshot were
  last materialised, which gives *stale working copy* detection. If the view
  moved underneath the directory (an undo, another process, an interrupted
  command), any local edits are saved as their own change before catching up.
  Nothing is lost.
* **What was materialised from what.** `checkout.json` also records
  (`checkout::Materialised`) the files checkout left out because this reader
  could not read them (no key for their scope yet), the files it wrote from
  an embargo fallback, and, when the snapshot's tree is an embargo wrapper
  this reader saw as its fallback, the tree actually materialised. When
  such content becomes readable (`vl scope grant` + `vl pull`, an embargo
  release), the next command fills it in before snapshotting, and again at
  its end, so a grant or release that arrives during the command shows at
  once. Local edits are never overwritten. Without the record the next
  snapshot would see the files as deleted, or reverted to the pre-embargo
  content. The builder also consults it (`BuildOptions::materialised`): a
  file that was never materialised is never recorded as deleted. The
  clone-then-grant onboarding flow depends on this.
* **Commands that edit the working copy are operations of their own.**
  `vl expose`, `cloak`, `isolate`, `ignore` and `restore` write files and
  record the result under their own operation description, not as the
  automatic snapshot that `vl undo` skips as "the user's uncommitted
  edits". So `vl undo` reverts them (an accidental `vl expose` above all),
  and edits made after them are kept as usual.
* **Virtual workspaces** (`vl ws new`) exist only in the DAG. They are edited
  through overlays (`vl ws write`), materialised into a throwaway directory
  for one command (`vl ws exec`), or attached to the project directory
  (`vl ws switch`). Two tasks can never fight over a directory.
* **The `ws exec` sandbox** holds plaintext (cloaked files and, with
  `--with-isolated`, vault secrets), so it is private and never outlives
  `vl`. It is created `0700` under `$TMPDIR` and everything in it is
  restricted to the user before the command runs. A reaper process (the `vl`
  binary re-executed, in its own process group) waits on a pipe that only
  `vl` holds. When `vl` exits for any reason, `kill -9` included, the pipe
  closes and the reaper removes the directory. As a last resort, each
  `ws exec` sweeps the same user's sandboxes whose owning process (the pid
  is in the name) no longer exists (Linux). The command's stdout is its own:
  `vl` reports on stderr.
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
Binary trees (format 2) then cut decoding the parent's ~1,200 trees from
12.4 ms to 0.7 ms; on tmpfs a clean status went from 72–77 ms to 58–59 ms
and a one-file edit from 77–99 ms to about 63 ms (FORMAT.md §7). What
remains is mostly the one `lstat` per file and the per-directory
`readdir`. Run the benchmark with
`cargo test --release -p vl --test bench_status -- --ignored --nocapture`.

## 7. Delayed-visibility (embargoed) merges

`vl merge X --embargo [--until T] [--scope S]`:

1. Creates an embargo record holding a fresh key, wrapped under scope `S`,
   plus an optional deadline. Records are synced to every remote, so the
   record carries **no message**: its `description` field is always empty
   (the engine takes none; the field stays, signed, so records remain
   readable and verifiable by every version). The merge snapshot's description is sealed
   under the embargo key instead, and becomes readable on release.
2. Builds the merged tree and stores it as an **embargo wrapper**
   (`embargo.rs`). This is a small plaintext tree whose marker entry `embargo`
   points at the merged tree, **sealed whole** under `embargo/<id>`, with the
   first parent's tree as its `fallback`. Inside the sealed side, every
   directory that differs from the fallback is itself a sealed tree, and
   every public file that differs is sealed under the embargo key, with the
   pre-merge version as its fallback. Content that was already sealed
   (cloaked under a scope) stays as it is, so releasing the embargo never
   declassifies cloaked files. The wrapper's other entries list, by id,
   every object reachable only through the sealed side. Relays, `gc` and
   `fsck` cannot open sealed trees, and the list is how they find, keep and
   transfer those objects.
3. `ObjectStore::tree` resolves a wrapper transparently: key holders see the
   merge, everyone else sees the pre-merge tree **exactly**. The fix's new
   file names, the new sizes and even *which* files changed are hidden.
4. **The merged-in history is withheld** until release (§8). The fix's own
   snapshots are ancestors of the merge, so pushing the merge would
   otherwise publish the fix in plaintext.
5. An unreleased embargo is **sticky**. A key holder's later snapshots,
   merges and rebases on top of it are re-wrapped under the same embargo,
   with the merge of the inputs' public views as their fallback. A reader
   without the key cannot record edits on top of it: the builder holds them
   back (`BuildReport::held_back`, reported with the embargo's id), because
   that reader sees only the pre-merge tree and recording on top of it would
   silently revert the fix for everyone. After the release they are
   recorded. Merging such history without the key is refused.
   Descriptions written on such a line by a key holder (`commit`, `describe`,
   `new -m`, squash, a plain merge into it) are sealed under the embargo key
   too, and its snapshots record no conflict list: snapshot metadata is
   public, and conflicted file names would tell outsiders what the fix
   touches. The command that produced the conflicts still reports them, and
   the markers are in the files.
6. **Release** (manual, or automatic on the first `vl` run by a key holder
   after the deadline) publishes the key in the record. Snapshot ids do not
   change, nothing is rewritten, and the next push carries the
   now-releasable objects *and the withheld history*.
7. After the release, the builder records what the working copy holds: a
   file written back to its pre-embargo content is a revert, and is
   recorded. The builder does not guess whether a working copy is stale. A
   non-holder's working copy materialised before the release still holds
   the fallback versions; the CLI records which paths it materialised from
   a fallback (or could not materialise) and checks them out again once it
   learns of the release, before snapshotting.

**Embargoes never overlap (1.0).** At most one unreleased embargo per line:

* `vl merge --embargo` is refused if the line it merges into, or any line it
  merges in, already carries an unreleased embargo: its tree is a wrapper of
  an unreleased embargo, or an ancestor (itself included) is an embargoed
  merge whose embargo is unreleased, or unknown to this repository. The
  message names the embargo: release it first, then merge. Nothing is
  recorded, not even the embargo record.
* No other route nests one embargo inside another either. A merge, rebase,
  auto-rebase or `vl new` whose inputs sit under two different unreleased
  embargoes is refused (`merge_trees`), and `embargo::wrap` refuses content
  or a fallback under another unreleased embargo. Two embargoes may coexist
  on *separate* lines (say `main` and a release branch cut before the
  first merge); those lines are combined after one of them is released.
* Why: nesting wrapped the second fix under the first embargo's key, so
  releasing the first published the second (BUG-041), and releasing the
  second first revealed the first's changed file names and sizes
  (BUG-047). Supporting both orders needs per-embargo layering of the
  sealed tree; that is future work.

**Scopes.** The embargo's scope is the audience before release, so content
readable by anyone else must not be part of it:

* A team remote receives the fix's history only where it is cloaked under
  the embargo's own scope, and only if it does not build on anything
  withheld (§8). A fix line cloaked under a wider scope (`--cloak team`,
  `--embargo --scope sec`) is withheld from the team remote until release.
* An embargoed merge that adds or changes files cloaked under *another*
  scope is refused: the wrapper keeps such content sealed under its own
  scope (so the release cannot declassify it), which would let every member
  of that scope read the change before the release. Embargo under that
  scope, or make those changes after the release.

**Trade-offs.**
* Until release, outsiders see the main line's pre-merge tree. That
  includes commits that key holders make on top of the merge: their public
  changes also stay hidden until release, because everything below the
  embargoed root is sealed. Release early, or keep unrelated public work on
  another line and merge it after the release.
* Non-holders (outsiders and team members outside `S`) cannot commit on top
  of the embargoed merge until release; they can work on its first parent.
* The public sees the merge snapshot and its first-parent history, with the
  extra parents redacted: their ids, but no objects. `vl log` shows the
  merge as merging a snapshot it does not have.
* Cost: every key holder's snapshot on an embargoed line re-seals the
  directories it changes, a cost in proportion to the changed region.
* One unreleased embargo per line (see above). A second security fix waits
  for the first release, or is embargoed on a separate line.
* Conflicts on an embargoed line are not recorded on snapshots until the
  release (see step 5).

## 8. Synchronisation

`remote::push` and `remote::pull` work between any two backends. Filtering
happens *during the object walk*: a public remote never receives sealed
objects except those of released embargoes, never receives cloaked tags, and
nothing is ever transferred under the `local` scope. Isolated content cannot
be pushed at all, because it was never in the graph. File fallbacks are
plaintext and travel with their entries: a clone of a public remote checks
out the last public version of a file edited on a cloaked line (§4 rule 5),
and records it as shown from a fallback (§6), never as deleted.

**Embargoed history.** Before walking, `push` computes, for every
unreleased embargoed merge in the local graph, the snapshots that only its
merged-in (non-first) parents reach: the fix, and how it was made.
* A public remote receives none of them. A team remote receives only the
  ones cloaked under the embargo's own scope (content and descriptions
  sealed for exactly its audience), and none that builds on a withheld
  one. Plaintext history, history cloaked under another (even wider) scope,
  and whatever descends from either within the fix are withheld there too,
  because team remotes are also read by people outside the embargo's
  scope. A fix line that starts with a plaintext commit is therefore
  withheld whole, and the merge is still pushed with its parent redacted.
* The merge reaches the remote with those parents **redacted**. If a tag
  would publish withheld history any other way (a tag on the fix itself, or
  a commit that builds on the fix without going through the embargoed
  merge), that tag is skipped with a reason; the rest of the push goes
  ahead.
* Graph walks (`Repo::snapshot_opt`, `ancestors`, `topo_children_first`,
  `parents_tree`, `gc`, `fsck`) treat a missing parent as absent. `fsck`
  reports a withheld parent as an expected redaction, so clones of such a
  remote work normally.
* After the release, the next push fills the parents in, with unchanged
  snapshot ids.

### Incremental transfer and packs on the wire

Over a WAN, sync costs round trips, so neither side re-walks or re-checks
what the other provably has (`remote.rs` has the details):

* **The receiver's committed view is a complete closure**: transactions
  write objects, a barrier, then the operation, so everything reachable
  from the receiver's committed view is present. Presence alone proves
  nothing (a crashed transfer leaves snapshots without trees), so only
  reachability counts. Two refinements keep it exact: the non-first parents
  of an embargoed merge (possibly redacted when it was sent) count only if
  the receiver holds them in a pack, and on a public receiver embargo
  wrappers are always revisited (what they hold may have been withheld then
  and be releasable now).
* **Push** walks the remote view's closure on the *local* graph, sends only
  the snapshots outside it, and skips every subtree reachable from the
  known snapshots they build on. Everything sent goes into one pack with
  deltas between versions of the same path (`PackBuilder`), written to the
  remote's pack directory inside its transaction: the pack unsynced, a
  barrier, then the index durably. A crash leaves at worst an invisible
  pack (no index) or a complete one whose operation never landed. Tag
  fast-forward checks run on the local graph too.
* **Pull** lists the remote's objects (pack indexes and loose fan-out
  directories, many requests in flight), skips every snapshot the local
  committed view reaches, and at the first object it lacks downloads, in
  parallel, every remote pack and loose object it lacks. The walk then
  runs locally; objects already present are read locally, never fetched.
  When the remote holds objects the walk did not need, a local walk of the
  committed view finds references to them: that fills gaps such as a clone
  of a public mirror now pulling from a team remote, or embargoed content
  released since. More than 256 new objects are stored locally as a pack.
* Filtering is unchanged: whatever crosses passes the same `allowed`,
  decoding and depth checks as before.
* `vl push --full` / `vl pull --full` is the object-by-object walk of
  everything, which re-verifies the receiver's copies: it repairs a
  damaged object, and fills content a push receiver lacks below snapshots
  it already has (a gap a plain push does not detect).

Benchmark (`cargo test --release -p veil-core --test sftp_bench --
--ignored --nocapture`): 3,000 files, 300 snapshots, about 7,850 objects,
through a local OpenSSH `sftp-server` with an artificial delay in both
directions (release build):

| operation | full walk, 2 ms RTT | incremental, 2 ms RTT | incremental, 50 ms RTT |
|---|---|---|---|
| first push | 87.5 s, 63,720 requests, 41 MiB sent | 0.51 s, 122 requests, 2.6 MiB | 5.3 s |
| clone | 52.7 s, 40,904 requests, 37 MiB | 0.41 s, 80 requests, 2.6 MiB | 2.4 s |
| push, up to date | 68.3 s, 47,400 requests | 0.08 s, 58 requests | 1.9 s |
| push of 1 new snapshot | 68.4 s | 0.14 s, 85 requests | 3.1 s |
| pull of 1 new snapshot | 52.9 s | 0.11 s, 75 requests | 2.2 s |

The full walk's requests are almost all one round trip each, so at 50 ms
it would take about 25 times its 2 ms time (not run). The incremental
costs at 50 ms are a fixed number of round trips: opening the remote,
the lock, metadata, the operation; a pull also reads every remote pack
index (0.4 MiB here).

Key rings are signed
logs that only fast-forward (§3). Stale, tampered or forged rings are
ignored or rejected with a warning, and membership is never merged as a
union. Embargo records are accepted only if signed by a scope member, or as
flagged legacy records. A release is accepted only if the published key
matches the committed fingerprint. Snapshots whose signature fails to verify
are reported. The object walk is iterative and refuses trees nested deeper
than `MAX_TREE_DEPTH` (1,024) levels (merge, normalisation, embargo
sealing, the builder and `fsck` are iterative too, and bounded by the same
limit, because a tampered local `.veil/` is not depth-checked on arrival), measured as each tree's height so
that shared subtrees cannot hide depth. Remote tags with an invalid name, or
whose target is missing or not a snapshot, are skipped with a warning. Tags
fast-forward. A diverged tag is reported and left alone
(`--force` overrides on push).

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
* **Network remotes: fencing leases.** On an `is_network()` backend
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
    lets both publish. `vl doctor --remotes` measures each SSH remote's
    clock against this machine's (the modification time of a probe file it
    creates and removes in the remote's `.veil/`) and warns beyond 60 s,
    half the allowance, since two clients can be off in opposite directions;
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

**Shared metadata under the lock.** Every read-modify-write of key rings,
embargo records and the vault holds the repository lock (`Keychain` and
`Repo::vault_update` take it reentrantly). Push and pull copy objects and
merge metadata *inside* their transaction, under the destination's lock.
Two concurrent `grant`s, or a `grant` racing a `pull`, cannot lose an
update.

**Crash ordering.** Every transaction writes in this order: objects (the
snapshot, trees and blobs it references), then a durability barrier, then
the operation, then `op_head`. Pull and push copy objects and shared metadata
(key rings, embargo records) before the operation that references them.
`init` writes `repo.json` last, because it is what makes a directory a
repository.

* `DiskBackend::write` and `create_new` return only once the data is
  durable: the file is fsynced, renamed, and its directory fsynced, and new
  directories are synced into their parents.
* Inside a transaction, objects are written with
  `StorageBackend::write_unsynced` instead: temp file, rename, no fsync. The
  backend remembers each file. `StorageBackend::sync_barrier` then fsyncs
  all of them, several at a time so that ext4 or XFS share journal commits,
  and every touched directory once. `Transaction::commit` runs the barrier
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
  usable stamps (SFTP), fall back to the holder's wall-clock `acquired`
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

## 11. Git interop (`git/`)

Teams keep GitHub or GitLab, their CI and their code review: Veil tags
become Git branches and Git commits become snapshots. The module is behind
the `git` cargo feature (on by default); it needs a disk-backed repository
because Git does.

```text
.veil/git/repo.git      bare Git repository (gix), the bridge
  refs/heads/<tag>          what Veil last exported for the tag
  refs/remotes/<r>/<b>      branch <b> of Git remote <r>, as last fetched or pushed
.veil/git/map           c <commit> <snapshot> <veiled embargoes>      every pair
                        s <snapshot> <commit> <import|export|publish> <pending embargoes>
.veil/git/cache         projection and conversion memo (safe to delete)
.veil/git/remotes.json  Git remote name → URL
```

### Export: what Git may see

Git sees exactly what a clone of a `--public` Veil remote sees, decided by
how each object is *sealed*, never by which keys this replica holds:

* **Which snapshots.** The public push's own functions select them
  (`remote::embargo_withheld`, `remote::push_closure`). Cloaked tags are
  never exported. The merged-in history of an unreleased embargoed merge is
  withheld: the merge's extra parents are dropped from its Git commit. A tag
  that would publish withheld history (a tag on the fix, a commit building
  on it) is skipped with the same reason `vl push` gives.
* **Which tree** (`git/project.rs`, the *public projection*). Plaintext
  objects are visible. Objects sealed under a scope or `local` are not:
  their entries are left out and a directory left empty disappears. An
  embargo wrapper resolves to its sealed side once released, otherwise to
  its fallback; a file whose content is hidden shows its fallback if it has
  one: an embargoed file its pre-merge version, a public file edited on a
  cloaked line its last public version (§4 rule 5). So a cloaked edit is
  exported as a commit that leaves the file as it was, never one that
  deletes it, and a Git commit made on that view imports as an edit of it
  (the import's `base` is the same projection). A `.git` entry, which
  Git cannot hold, is left out with a warning, in every spelling that
  names it on macOS (any case, HFS+-ignorable code points such as
  `.g\u{200C}it`, as Git's `is_hfs_dotgit`); import refuses them too. Isolated files were never in
  the graph.
* **Which message.** Plain descriptions as they are. A description sealed
  for a scope becomes `(description withheld: cloaked)`, one sealed under
  an unreleased embargo `(description withheld: under embargo)`. Only
  released embargo keys are ever used to open anything.

Tests check this by dumping every object of the produced Git repositories
(`git cat-file --batch-all-objects --batch`) and grepping for the
plaintext of cloaked files, isolated files, cloaked descriptions and
embargoed fixes.

**Commits are deterministic.** Tree, parents (the commits of the Git-visible
parents, root dropped), author and committer both set to the snapshot's
author (`Name <email>` is split; a bare name gets an empty email) at its
timestamp in UTC, the message, and a `change-id` header holding the change
id in reverse hex, as Jujutsu writes it. No signature, no other header. Two
machines exporting the same snapshot produce the same commit.

**Exported commits are pinned.** Once exported, a snapshot keeps its commit
(the mapping), so Veil only ever appends to Git history. The one case where
the public view of an existing snapshot changes is an embargo release. Each
exported commit records the unreleased embargoes that shaped it; when one is
released, export recomputes that snapshot and, if Git would now see
something different, writes a **publication commit** on top of the pinned
one: the released tree, parents `[pinned commit, newly visible parents…]`
(that is, the fix's own history), the released description, no `change-id`
header (it would make the change look divergent to Jujutsu). Descendants
exported before the release (they were sealed by stickiness) get one too,
linking to their parent's publication commit. `vl git push` is then a
fast-forward.

The same holds for commits that came from Git. The mapping records, for
every commit, the embargoes that were unreleased in the view it shows
(*veiled*): an exported commit pinned under an embargo, and a Git commit
made on top of one (it shows the pre-fix files too). On release, such an
imported commit also gets a publication commit, parents `[imported commit,
newly visible parents…]`, whose tree is the imported commit's tree with
*only the release's change* to the snapshot's public view applied
(carry-over from the projection through the old veil to the current one).
GitHub's edits, and paths Veil never recorded, are kept; the fix reaches
GitHub past any number of GitHub commits.

**Carry-over in the other direction.** Paths Git has but Veil never
recorded, because Veil isolated or quarantined them at import, or because
Veil cannot represent them (symlinks, submodules), must not be deleted by
the next Veil commit. The exported tree is a path-wise three-way merge of
Git trees: `base` = the public projection of the first parent's snapshot,
`ours` = the first parent's Git commit, `theirs` = the public projection of
this snapshot. Paths Veil did not change keep Git's version; paths Veil
changed (deleted included) take Veil's. For a parent Veil exported itself,
`ours == base` and the result is the projection exactly.

### Import: Git commits that never saw everything

`git/import.rs` imports every commit reachable from the fetched branches
that is not mapped yet, parents first (Kahn's algorithm, oldest first).
Each commit becomes a snapshot:

* **parents**: the parents' snapshots (the root for a root commit);
* **author / timestamp**: `Name <email>` and the author time (UTC, ms);
* **description**: the message, plaintext (it is public in Git already);
* **change id**: the `change-id` header (Jujutsu), unless a visible change
  already has that id (a forged header must not make the user's change
  divergent), otherwise derived from the commit id, so re-importing gives
  the same snapshot id (the importer's signature is deterministic too);
* **tree**, as a three-way merge (`merge::merge_trees`):
  * `ours` = the parents' Veil tree (`Repo::parents_tree`): everything,
    cloaked and embargoed content included;
  * `base` = its public projection *as the commit's author saw it*: through
    the veil of the Git parents' commits. A Git commit made after a
    release on the pre-release view (the merge as pinned, or a Git commit
    on it) shows the pre-fix files; against the released tree that would
    read as a revert of the fix;
  * `theirs` = the Git commit built **through the policy gate**: a
    read-only `StorageBackend` over the Git tree is snapshotted by the
    builder on top of `base`, so isolation, secret scanning and cloaking
    apply exactly as for a working copy. Reuse hints (unchanged
    subdirectories and blobs, proven by content identity) keep this
    O(changes).

  Entries Git never saw are in `ours` only, so they are carried over
  untouched, just as the builder carries entries a reader cannot see. Git's
  edits apply. A file both sides changed is diff3-merged and keeps `ours`'
  sealing, so nothing sealed is widened. Under an unreleased embargo the
  result is re-wrapped (key holder) or the commit is **held back** with
  its descendants (no key), as the builder does for edits on top of an
  embargo.
* A Git commit that edits `.veilpolicy` so that sealed files would change
  audience (`secrets/ cloak team` → `public!`) is not taken: the Veil
  policy is kept and the import warns, as `vl merge` does.
* What Veil refused (isolated, quarantined, no key for the scope, not
  representable) is reported per path. It stays in Git (see carry-over).

### Remotes, divergence and transport

`vl git fetch` runs `git fetch --prune <url> +refs/heads/*:refs/remotes/<r>/*`
in the bridge, imports, and records `<r>/<branch>` remote tags. A branch
whose new tip does not descend from the previous one was **force-pushed**
on the Git side: it is reported, the snapshots it dropped stay in Veil, and
local tags never move backwards. `vl git pull` also creates or
fast-forwards local tags; a diverged tag is left alone with a hint (`vl
merge <r>/<branch>`). Like `vl pull`, it never moves the working copy (a
change of the user's own; rewriting it under them would be surprising):
`vl rebase -d <tag>` does. The usual working-copy handling still runs at
the end of the command (§6: anything that became readable is filled in). `vl git push` exports, then pushes
`<commit>:refs/heads/<tag>` for each tag. A branch that moved on the Git
side is rejected (non-fast-forward). `--force` uses
`--force-with-lease=<branch>:<last fetched>`, so it can only overwrite what
this replica has seen.

Network transport is the system **`git` binary** (`$VEIL_GIT` overrides the
path), with gix for all object reading and writing:

* gix (0.90) has fetch but no push;
* `git2`/libgit2 would bring its own credential callbacks and SSH
  implementation (libssh2), which ignore `~/.ssh/config`, `ProxyJump`,
  FIDO keys and most credential helpers;
* the `git` binary uses exactly what the user already configured:
  credential helpers (osxkeychain, libsecret, `gh auth git-credential`),
  SSH config and agent, `insteadOf`, proxies. Jujutsu moved to the same
  approach. Veil passes `--git-dir` and explicit refspecs, removes
  `GIT_DIR`-style variables, disables auto-gc in the bridge (exported
  commits may be referenced only by the mapping), and refuses URLs that
  `git` could read as options.

**Commits Veil exported are never imported.** Before importing an
unmapped commit, import checks whether it is Veil's own: one with a
`change-id` header naming a visible change is exported again (through the
veils of earlier release states, if a release shaped it) and recognised if
the commit id is the same; one without, on top of a commit whose view a
release changed, is checked against the publication commit export would
write. A header alone proves nothing (anyone can write one). So a lost
`.veil/git/map` is rebuilt by the next fetch as well as by the next export,
and a second replica that holds the same Veil history (from a Veil remote)
maps the first one's exports to the same snapshots. An earlier import of
the same commit is found by its derived change id.

**Untrusted branches.** A branch that cannot be imported (an unreadable or
hostile tree, `.veilpolicy` as a symlink, held back by an embargo) is
reported with its name and the reason; the other branches are imported and
the command succeeds. Deleted branches are found from the remote tags Veil
recorded, not from the bridge's tracking refs (which `git fetch --prune`
has already moved, even if the import then failed). `vl git pull` does not
create a local tag whose name is also a change id or snapshot id prefix of
the repository (tags win in revsets); `<r>/<branch>` names it. Credentials
in a remote URL (`https://user:token@host`) are replaced by `***` in every
message and in `vl git remote list`. A relative local path given to `vl git
remote add` is stored absolute, and `git` always runs in the bridge
directory, so the remote is the same from any directory.

Every mapped object is re-checked before use; one that has gone (Veil gc
of an abandoned import, Git gc) is treated as unmapped and recomputed,
which gives the same result. A crash between writing objects and the map
therefore only costs recomputation. Export and import run under the
repository lock.

## Threat model

**Protected against:**

* accidental commits of secrets (engine rules plus the scanner, with no ignore
  file to forget);
* leaking cloaked content or names of cloaked tags to public remotes;
* leaking cloaked, isolated or embargoed content, cloaked descriptions or
  cloaked tags to a Git remote (Git sees what a public remote sees, §11),
  and losing cloaked files when a commit made in Git is imported;
* readers of a team remote who are not in a scope (they get ciphertext only);
* pre-release disclosure of embargoed changes to non-members: their
  content, their messages, their history, and their file names, sizes and
  set of changed files (the embargoed tree is sealed whole);
* declassification as a side effect. Rebase, `new`, squash, a policy edit
  that arrives by merge, and push never move cloaked or embargoed content
  to a wider audience. Only an explicit merge of a cloaked line or an
  `expose` does, with the secret scanner applied;
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
  signature, and a transplant fails verification. Both show in `vl log`;
* **hostile trees and metadata from a remote.** Path traversal (`..`, `/`),
  writes into `.veil/`, non-canonical trees, stack exhaustion by deep
  nesting, dangling tags and terminal escape sequences in names and
  descriptions (the CLI escapes control and bidi characters) are refused
  (§2, §8).

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
  snapshot (the signature names them) and of whoever created or released
  an embargo (the record's signatures), with the snapshot's free-form
  `author`; and embargo records themselves (scope, deadline, the wrapped
  key as ciphertext). Without rings, a public clone shows every snapshot
  signature as "unknown key", and accepts embargo records unverified: it
  holds no scope key, so it can never auto-release, and a published key
  is checked against the record's fingerprint and by the AEAD of the
  content it opens. Rings that an earlier vl pushed to a public remote stay
  there (removing them would lock members out of a team remote added as
  public by mistake); every public push warns about them until someone
  deletes `.veil/meta/keyrings/` on that remote. Team remotes still hold
  the full rings, so anyone who can read a team remote sees the
  membership.
* *Rings on a non-member remote* (for example a bare remote without an
  identity) cannot check the genesis proof. Members check it when they pull.
* *Time-based embargo release* relies on key holders' engines and is not
  time-lock cryptography.
* *Embargo metadata that remains visible:* that an embargoed merge exists,
  its parents' ids (the merged-in ones are redacted, not hidden), its
  author, its timestamp, the embargo's scope and deadline, and the
  ciphertext sizes on team remotes. The embargo record and the wrapper do
  not name files, and the record carries no description (the field is
  always empty). (Overlapping embargoes, which used to reveal one
  another's files, are refused in 1.0, §7.)
* *History withheld by an embargo* is computed from the local graph. If the
  embargoed merge is undone or abandoned before a push, nothing protects
  the fix branch any more; it is then an ordinary change.
* *Stale working copies after a release.* A working copy materialised by a
  non-holder before the release still holds the pre-merge files. The
  builder records what is on disk (a revert to the pre-embargo content is
  a real edit), so the CLI must check such paths out again when it learns
  of a release, before snapshotting (§7, step 7).
* *Other scopes on an embargoed line.* Content sealed under a scope stays
  under that scope, never under the embargo key (which the release
  publishes). So a cloaked line of work on top of an embargoed line (its
  files and descriptions), and a key holder's follow-up edits there of
  files cloaked by policy under another scope, are readable before the
  release by members of that scope who are not in the embargo's. The
  embargoed merge itself refuses such changes (§7); for follow-ups, use the
  same scope for the cloak and the embargo.
* *Git sees what a public remote sees*, including the metadata a public
  remote keeps: names of public files, that a cloaked snapshot or an
  embargoed merge exists (an empty-looking commit with a placeholder
  message), its author and time. History imported from Git is public by
  definition; cloaking a path later does not hide its Git history.
* Content committed in plaintext **before** a path was cloaked stays readable
  in those older snapshots. `vl cloak` warns when this applies.

## Limitations and roadmap

* Network transport: remotes are paths or SSH remotes (`SftpBackend`, §1,
  §8); no smart server protocol (have/want negotiation, server-side
  packing) is planned for 1.0; the post-1.0 protocol is designed in
  [HUB.md §4](HUB.md#4-the-smart-sync-protocol). Remote packs accumulate, one per push, and a
  pull reads every index, so consolidating small remote packs (by the
  pushing client, which holds their objects) is next. A plain push does not
  notice content a remote lacks below snapshots it already has
  (`vl push --full` fills it).
* Performance: recording checked-out files
  in the stat cache (needs a backend write that returns the stat of the
  file it wrote). `gc` always rewrites everything into one pack, built in
  memory; incremental packing (small packs merged geometrically), streaming
  pack writes and cross-pack deltas are next. Sync builds its packs in
  memory too, and a pull holds the remote packs it downloads in memory.
* Sealed directory nodes for cloaked paths, to hide their names (embargoes
  already seal their trees, §7); a "require signed snapshots" policy;
  pinning a ring head out of band; automatic re-application of concurrent
  ring changes.
* First-class conflicts (jj-style) instead of conflict markers.
* Front-ends: a FUSE mount of `TreeView` plus overlay for zero-copy
  checkouts, and a WASM build of `veil-core` with `MemoryBackend`.
* Symlink support in `DiskBackend`.
* Git interop: Git tags (annotated or not) are not imported or exported,
  only branches; Git authors' time zones are not kept (export writes UTC);
  carry-over of Git-only paths follows the first parent only; `vl git`
  does not check out after a pull (use `vl new <tag>` or `vl edit`).
