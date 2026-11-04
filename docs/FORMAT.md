# Veil on-disk formats

From 1.0 on, a repository written by any vl release stays readable by every
later release. This document lists everything Veil persists, how each part
is versioned, the rules for changing any of it, and how `vl upgrade`
migrates a repository.

All integers are little-endian unless noted. "JSON" means exactly what
`serde_json` writes for the Rust type, with no extra whitespace unless noted.

## 1. Versioning model

There is one **repository format**, a number in `.veil/repo.json`:

| format | first vl | what it adds |
|---|---|---|
| 1 | 0.1.0 | everything below, trees in JSON |
| 2 | 1.0.0 | binary trees (§3) |
| 3 | 1.0.0 | standard cryptography: AES-SIV sealed objects (`veil:sea2`), HPKE-wrapped ring keys (ring format 3); see [CRYPTO.md](CRYPTO.md) |
| 4 | 1.0.0 | first-class conflicts: conflict objects (`veil:conf`, §3.6) and conflict entries in binary trees (flag bit 6) |
| 5 | 1.0.0 | Git parity: symlink and gitlink tree entries (flag bit 7 and a kind byte, §3.7) and conflict terms (§3.6), annotated tags (`veil:atag`, §3.8; `Tag.annotation`, `View.remote_release_tags`), the `colocated` marker of `repo.json` |

* `vl init` writes the newest format (`repo::REPO_FORMAT`). `vl clone` takes
  the format of its source, so that what the clone writes can be pushed
  back and read by everyone who reads the source. A bare remote created by
  `vl push` is created at the newest format.
* A reader **refuses a newer repository format before reading anything
  else** (`Repo::open`, `fsck`, `vl upgrade`): an older vl never
  half-understands, and never rewrites, newer data. The error names the
  release it needs when `repo.json` says so (`min_vl`).
* A reader reads **every older format**, and keeps writing it unchanged:
  a format-1 repository written by vl 1.0 is still a format-1 repository
  that vl 0.1.0 can read. Nothing changes until someone runs `vl upgrade`.
* Some parts carry their own version as well (objects, packs, rings,
  embargo records, caches), because they travel between repositories or
  outlive one process. Their rules are below.

`VeilError::Unsupported` is the error for "written by a newer vl" (and for
"the destination's format may not hold this"). It is never treated as
"redacted": nothing is silently skipped or carried over because it could
not be understood.

## 2. Inventory

| Path / structure | Encoding | Version | Synced? | Notes |
|---|---|---|---|---|
| `.veil/repo.json` | pretty JSON `{format, repo_id, remotes, min_vl?, colocated?}` | `format` | no | written last by `init`, rewritten atomically by `upgrade` (commit point). `colocated: {git_dir}` (format 5, `deny_unknown_fields`) marks a project directory colocated with Git; a repository below format 5 carrying it is refused as corrupt, and so is a `git_dir` that is empty, absolute, holds `..`, `\\` or NUL, or names `.veil`. An older vl refuses the whole directory by its format, so it never snapshots a colocated directory without its guards |
| objects (§3) | `tag ‖ payload`, id = BLAKE3 | tag + encoding byte | yes | loose: `.veil/objects/ab/cdef…` (the canonical bytes) |
| — blob | `veil:blob\n` ‖ bytes | none needed: any bytes are valid | yes | a new blob encoding would be a new tag |
| — tree | `veil:tree\n` ‖ `{` JSON (v1) or `0x02` binary (v2) | encoding byte | yes | §3 |
| — snapshot | `veil:snap\n` ‖ `{` JSON (v1) | encoding byte | yes | canonical (§3.3). `conflicts` lists conflicted paths; from format 4 it is an index the engine keeps (every conflict entry of the tree, plus marker conflicts carried from older formats), same field and encoding |
| — conflict (format 4) | `veil:conf\n` ‖ `0x04` ‖ binary terms (§3.6) | encoding byte | yes | refused below format 4; plaintext (ids and labels only, never content); one with a symlink or gitlink term refused below format 5 |
| — annotated tag (format 5) | `veil:atag\n` ‖ `{` canonical JSON (§3.8) | encoding byte | yes, with its tag | refused below format 5; plaintext but for a cloaked tag's message (sealed); never sent to a public remote when that message is sealed |
| — sealed (formats 1–2) | `veil:seal\n` ‖ u16 **big-endian** label length ‖ label ‖ nonce[24] ‖ XChaCha20-Poly1305 ciphertext | tag | yes | the plaintext is another object's encoding; nonce derived from the plaintext (legacy, CRYPTO.md C1L); still written by format-1/2 repositories |
| — sealed (format 3) | `veil:sea2\n` ‖ u16 **big-endian** label length ‖ label ‖ SIV[16] ‖ AES-SIV ciphertext | tag | yes | AES-SIV-CMAC-512 under `HKDF-SHA256(scope key)`, AD = `[label]` (CRYPTO.md C1); refused below format 3 |
| — embargo wrapper | an ordinary tree with an `embargo` marker entry | as trees | yes | `embargo.rs`. Since BUG-104 the listed entries omit ids the fallback tree reaches (the pre-merge versions of changed files); same encoding, and every reader keeps those objects through the fallback, so no new version |
| packs `.veil/objects/pack/pack-<sum>.pack` | `VEILPAK1` ‖ count u32 ‖ entries ‖ BLAKE3 | magic digit | no (sync sends canonical objects) | entry kinds 0 stored, 1 zstd, 2 delta; 3–15 reserved. A delta is a zstd frame read with its base as a raw-content dictionary; above 2 MiB of base plus object it is written with the base as a *prefix* and long-distance matching (BUG-290), with a window of at most 2^27, which every zstd decoder accepts by default: the same bytes to every reader, so no new version. Builds without the zstd C library (WASM, ARCHITECTURE.md §13) write kind 0 only and read 1 and 2 with a pure-Rust decoder (a delta's base given to it as a formatted dictionary: a fixed header, then the base); no new version either |
| pack indexes `pack-<sum>.idx` | `VEILIDX1` ‖ count ‖ fanout ‖ ids ‖ offsets ‖ lengths ‖ pack sum ‖ BLAKE3 | magic digit | no | |
| operations `.veil/ops/<id>` | JSON `Operation {parents, timestamp, user, description, view, manual_undo?, undo_of?, redo_of?}`, id = BLAKE3 of the bytes | repository format | no (device/repository-local) | `manual_undo` (absent unless set) marks an operation whose effect lies outside the view; `undo_of` / `redo_of` (absent unless set, hex operation ids) mark an undo and a redo, so repeated undos go further back (BUG-247). Older readers ignore all three (an older `vl undo` then treats an undo as a plain operation, as it always did); operations written before them have none, so no version bump or upgrade step. Format 5: a view's tags may carry `annotation` (hex id of a `veil:atag`) and the view `remote_release_tags` (`"<remote>/<name>"` → atag id); both omitted when absent or empty, so earlier views keep their bytes, and an operation using either is refused below format 5 (`OpStore::put`), so a format-4 vl never meets one (it refuses the repository and the remote by format before reading a view). |
| `.veil/op_head` | hex id | fixed | no | |
| pruned-ops list `.veil/ops_pruned` | one hex id per line | fixed | no | append-only |
| key rings `.veil/meta/keyrings/<scope>.json` | pretty JSON `KeyRing` | `format` (0/1 legacy, 2 signed log, 3 signed log that may hold HPKE-wrapped keys) | yes | readers reject `format > 3` (no keys, a warning on sync); a ring with an HPKE wrap must say 3, and a format-1/2 repository refuses to store it |
| — wrapped key (in a ring change) | JSON: legacy `{ephemeral, sealed}` or HPKE `{hpke, enc, ct}` | shape + `hpke` suite string | yes | legacy written by format 1–2, HPKE by format 3 (CRYPTO.md C3/C3L); unknown fields or suites refused |
| — member binding (in a genesis member or grant) | `"binding": hex(Ed25519 signature)`, after `signing_key`; absent when not recorded | ring format 3 | yes | written from repository format 3 only (CRYPTO.md C4); a ring with one must say format 3, so format-1/2 repositories and older vl never receive it. Added to ring format 3 before any release wrote that format; the format-3 fixtures predate it and carry none |
| embargo records `.veil/meta/embargoes/<id>.json` | pretty JSON `EmbargoRecord` | implicit 1; a later format adds `"format": N` | yes | readers reject `format > 1` |
| team-vault records `.veil/meta/vault/<scope>/<id>.json` | compact JSON `VaultRecord {format, scope, sealed, timestamp, signature}`; `sealed` is the JSON envelope (C2) of the padded JSON `{name, value, since}` under label `vault:<scope>#<key-id>`; `<id>` = hex BLAKE3 of the file, which must be exactly the canonical encoding | `format` (1); unknown fields refused | yes, team remotes only | immutable, never rewritten: a write adds a record, compaction deletes superseded ones (ARCHITECTURE §3). A newer `format`, unknown fields or a non-canonical file make the record not count, with a warning; nothing is rewritten. Older vl never read, write or relay the directory, so no repository format change |
| staged embargo releases `.veil/local/releases/<id>.json` | pretty JSON `{released_key, released_at, release_signature}` (the record's release fields) | none: unknown or invalid content is ignored (the embargo stays unreleased) | no (device-local; honoured only by the identity that signed it) | written by `vl embargo release`, moved into the record by the next push or Git export, deleted by `vl undo` (BUG-109); an older vl ignores it, i.e. the release is not yet made |
| team-vault value history `.veil/local/vault-history/<scope>.json` | compact JSON `{names: {<name hash>: {<value hash>: <generation>}}}`: keyed BLAKE3 (key `derive_key(TEAM_VAULT_HISTORY, local vault key)`, CRYPTO.md C12) of each name, and of each value it held, with the first key generation that value was sealed under; at most 256 values per name | none: unreadable content reads as empty | no (device-local) | new in this release (BUG-521); no repository format change. Only makes `since` of later writes, and `--exposed-to`, more conservative; losing it forgets what this device saw. An older vl ignores it |
| `vl run` default scopes `.veil/local/run-scopes.json` | compact JSON `{scopes: [<scope>…]}` | none | no (device-local) | new in this release, written by `vl run --remember` (BUG-520). Missing: `vl run` loads no team vault unless `--scope` is given. An older vl ignores it (and loads every scope) |
| vault `.veil/local/vault.sealed` | envelope (label `local`) around JSON `VaultData {secrets, files, removed?}` | repository format | no (device-local) | `removed`: backups of vanished isolated files with `removed_at`, kept 30 days; older readers ignore it |
| deleted tags `.veil/local/deleted_tags.json` | pretty JSON object: tag name → hex snapshot id | none (a missing file is empty) | no | written by `vl tag delete`, read and pruned by pull (`remote::deleted_tags`). Outside the view and the op log; an older vl ignores the file and never rewrites it, so no repository format change |
| stat cache `.veil/local/statcache/<ws>.cache` | `veil:statcache\n` ‖ version u32 ‖ … ‖ BLAKE3 | `VERSION` (1) | no | any mismatch reads as empty: a cache, never data |
| scanner markers `.veil/local/scanned/<ws>.version` | decimal `secrets::RULES_VERSION` | itself | no | a mismatch re-scans once |
| accepted policy `.veil/local/accepted-policy` | the text of the `.veilpolicy` this device's member last accepted (empty: none) | as `.veilpolicy` | no (device-local) | missing: the next working-copy snapshot records the current `.veilpolicy` |
| checkout state `.veil/local/checkout.json` | pretty JSON `{workspace, snapshot, materialised?, pending?: {workspace, snapshot}}` | repository format | no | gc keeps both snapshots; `pending` is the journal of an unfinished move of the directory |
| colocated Git state `.veil/git/colocated.json` | pretty JSON `State {version, last_head?, last_head_ref?, refs, held, hooks_installed, index_key?, index_head?, skip, frozen, frozen_reason?, local_only, mirrored?}` | `version` (1) | no (device-local) | colocated Git mode only (`git/colocate.rs`); readers refuse a newer `version` and a corrupt file (never a silent reset of the guards). Paths in `skip` are Git paths, non-UTF-8 bytes as `\xNN` |
| colocated Git lock `.veil/git/colocate.lock` | empty file, `flock`ed | none | no | serialises follow and mirror between `vl` processes |
| `.veil/.git` | an empty bare Git repository | none | no | colocated mode only: Git treats `.veil` as a nested repository, so `git clean -fdx` and `git stash -a` leave it alone; removed by `vl git uncolocate` |
| `ws exec` sandbox `.veil/local/sandboxes/<ws>/` (`.`/`..` spelt `%2e`/`%2e%2e`) | `manifest.json`: pretty JSON `{version, workspace, tree?, snapshot?, materialised?, boot, running?, only?, quarantined?, pending?, guard_checked?}` (`pending`: `{run, base, message?, started, kept?, injected?, recorded?}`, the command's unrecorded output; `guard_checked`: ns since the epoch); `statcache` in the stat-cache format above; `lock` (empty, `flock`ed); `files/` the sandbox's files; `guard.sealed` (an `Envelope` sealed under `local`: JSON `{files: [[path, hex]], injection?: {run, paths, stash: [[path, hex, executable]]}}`); `unrecorded-<ms>-<rand>/` previous files a rebuild kept whole | `version` (1) | no (device-local) | new in this release; no repository format change; `pending`, `guard_checked` and `guard.sealed` are additions an older reader ignores. Any other version, an unreadable manifest, a `running` marker, another boot, a non-empty `only` (reserved for sparse sandboxes): the sandbox is rebuilt, keeping unrecorded work (re-imported, or kept whole in `unrecorded-…/`). A `pending` run is recorded before anything else. gc does not keep `tree`: a missing one is rebuilt. An older vl ignores the directory |
| `ws mount` state `.veil/local/mounts/<ws>/` (`.`/`..` spelt `%2e`/`%2e%2e`) | `state.json`: pretty JSON `{version, workspace, base, mountpoint?, pid?, boot?, socket?}` (`base`: hex id of the snapshot the overlay is over); `upper/` the overlay's written files and directories; `whiteouts`: one JSON string (a path) per line, appended; `unseen`: the files the whiteouts hide that the mount never showed (carried by every recording), one JSON string per line, rewritten; `lock` (empty, `flock`ed by the serving process); `log`; `ctl` the control socket (or one under `$XDG_RUNTIME_DIR`, named in `state.json`) | `version` (1) | no (device-local) | new in this release; no repository format change. Holds user data (isolated and unrecorded files): never wiped. Another `version` is refused (unmount with that vl). A torn last line of `whiteouts` is skipped. `unseen` is new in the round-8 mount wave and optional (absent: nothing to carry); a vl from before it ignores it. An older vl ignores the directory |
| lock `.veil/lock`, `.veil/lock.steal` | JSON lock info (legacy: `"<pid> <millis>"`) | none: unknown fields are ignored, unparseable content is reclaimed only after a full unchanged lease | no | transient; a live holder rewrites it every 2.5 s, so an older reader never steals a newer holder's lock |
| gc pending `.veil/objects/gc/pending` | `VEILGCP1` ‖ count u32 ‖ (id, ms)* ‖ BLAKE3 | magic | no | damaged/unknown reads as empty: only restarts the grace period |
| gc keep markers `.veil/objects/gc/keep/<id>` | empty files | none | no | |
| upgrade journal `.veil/upgrade.json` | pretty JSON `{from, to, started, done[]}` | — | no | present only during `vl upgrade` |
| public identity (what `vl identity show` prints and `vl scope grant` takes) | `veil1` ‖ hex(X25519 32) ‖ hex(Ed25519 32) ‖ hex(binding 64); the short `veil1` ‖ hex(X25519) is a member id; the earlier `veil1` ‖ hex(X25519) ‖ hex(Ed25519) still parses, but a grant refuses it | length | no (pasted between people) | the binding is deterministic, so the string never changes |
| identity `$VEIL_HOME/identity.json`, `retired/` | legacy JSON `{name, public, secret, signing?}` (signing key derived); format 2 `{format: 2, name, public, signing, encryption_secret, signing_secret}` (independent keys) | `format` (absent = legacy) | no | outside the repository; new identities are format 2 whatever the repository format; format 2 has no `secret` so older vl refuse it; readers reject `format > 2` |
| `.veilpolicy` | text, one rule per line | grammar is fail-safe: unknown tiers isolate | yes (it is a tracked file) | |

Signed bodies have their own fixed encodings and must never change: the ring
change body (`RingChange::signing_body`), the embargo body
(`EmbargoRecord::body`), the team-vault record body
(`VaultRecord::signing_body`, pinned by a unit test), the snapshot's *unsigned id* (the id of its
encoding without `signature`) and, from format 5, the annotated tag's unsigned id
(`Atag::unsigned_id`, context `tag`). A format change that touches a signed type
needs a new signing context.

## 3. Objects

### 3.1 The encoding byte

For structured objects (trees, snapshots) the first payload byte after the
tag is the **encoding version**:

| byte | meaning |
|---|---|
| `{` (0x7B) | format-1 JSON (trees, snapshots); canonical JSON (annotated tags, format 5) |
| 0x02 | binary tree (format 2) |
| 0x03–0x1F | reserved for later versions → `Unsupported` ("needs a newer vl") |
| anything else | corrupt |

A tag shaped like an object tag (`veil:` + four lowercase letters or digits
+ `\n`) that this build does not know is `Unsupported`, not corrupt.

### 3.2 Binary trees (encoding 2)

```text
tree    = 0x02 | count uvarint (>= 1) | entry{count}
entry   = name_len uvarint | name (UTF-8) | flags u8
          | kind u8                         if flags.KIND (format 5)
          | id [32]
          | size uvarint                    if flags.SIZE    (then size != 0)
          | label_len uvarint | label UTF-8  if tier != public (scope / embargo id)
          | fallback [32]                   if flags.FALLBACK
flags   = bit 0 DIR · bit 1 EXECUTABLE · bit 2 SIZE · bit 3 FALLBACK
          bits 4–5 tier: 0 public, 1 cloaked, 2 embargoed, 3 reserved
          bit 6 CONFLICT (format 4): `id` names a conflict object (§3.6);
                every other bit must be clear (a conflict entry has no
                size, executable bit, label or fallback of its own)
          bit 7 KIND (format 5): a kind byte follows the flags,
                1 symlink, 2 gitlink (0 and 3–255 `Unsupported`);
                DIR, EXECUTABLE and CONFLICT must be clear, SIZE,
                FALLBACK and the tier keep their meaning (§3.7)
uvarint = unsigned LEB128, shortest form
```

* **Canonical by construction.** Defaults are omitted (their flag clear)
  and never written explicitly, varints must be minimal, entries are
  strictly sorted by name (so unique) and pass the same name rules as JSON
  trees (`.veil` refused at any depth, no `/`, NUL, `.` or `..`), and
  nothing may follow the last entry. Decoding accepts exactly the bytes the
  encoder writes, so it does not need to re-encode to check.
* **Lossless.** It represents every `TreeEntry` the JSON encoding can
  (property-tested both ways), so trees can move between encodings without
  loss.
* **The empty tree is always format 1** (`veil:tree\n{"entries":[]}`); a
  binary tree with zero entries is corrupt. The empty tree is part of the
  universal root snapshot, so the root id (`72edc798…`) is the same in
  every repository of every format, and unrelated histories can still meet.
* **Size.** On the 20k-file benchmark layout the 1,201 trees take 882 KiB
  instead of 2,449 KiB.
* A reserved tier, or an unknown kind byte, is `Unsupported`. (Before
  format 4, bit 6 was reserved: a format-3 reader refuses a conflict entry
  as `Unsupported`, never misreading it; before format 5, bit 7 was: a
  format-4 reader refuses a symlink or gitlink entry the same way.)
* In JSON (format-1) trees a conflict entry is `"kind":"conflict"` with no
  other optional field. Only a format-4 repository may store a tree holding
  one, whatever its encoding (`Object::min_repo_format` decodes trees to
  check), and a format-4 repository writes binary trees anyway. Likewise
  `"kind":"symlink"` and `"kind":"gitlink"` (never `executable`) need
  format 5.

### 3.3 Snapshots

Snapshots stay JSON (encoding `{`). They are few per command (a `vl status`
decodes two), their signature is over the id of their own encoding, and
their ids are what other systems record (change ids, Git-bridge mappings),
so changing their encoding would cost much and gain little.

From this release a snapshot must also be **canonical**: exactly the bytes
`serde_json` writes for the decoded value. Every snapshot ever written by vl
already is (fields were only ever appended, with defaults omitted); a
non-canonical one is refused, because otherwise one signed snapshot could be
re-encoded under any number of ids, each with a valid signature.

### 3.4 Identity of objects across encodings

Ids stay `BLAKE3(canonical bytes)`. Each encoding is canonical, and a writer
uses exactly one tree encoding (that of its repository format), so a writer
gives each logical tree exactly one id. A format-2 repository can still hold
a format-1 copy of the same logical tree from before its upgrade: **equal
ids imply equal content, but after an upgrade equal content no longer
implies equal ids**. Every algorithm already treats "different id" as
"compare inside" (diff, merge, embargo sealing), so the only effect is
work, which the engine avoids:

* the builder reuses the parent's tree id for an unchanged directory
  (comparing entries, not bytes), so unchanged directories keep their
  format-1 trees and ids indefinitely;
* a merged directory equal to one side reuses that side's id.

### 3.5 Where the format is enforced

* `ObjectStore` writes trees in its repository's encoding (`set_format`,
  set by `Repo::open` from `repo.json`) and its `put_raw` **refuses** a
  binary tree in a format-1 repository, and an AES-SIV sealed object
  (`veil:sea2`) in a format-1 or 2 one (`Object::min_repo_format`,
  `check_storable`; the pack sink of incremental sync calls it too), a
  conflict object or a tree holding a conflict entry below format 4, and
  below format 5 a tree holding a symlink or gitlink, a conflict with
  such a term and an annotated tag (`ObjectStore::put` checks the same on
  the value, so engine code cannot write them either). The
  keychain follows the same format: it wraps keys with HPKE only from
  format 3 and refuses to store a format-3 ring below it. Push and pull copy objects with
  `put_raw`, so a format-1 remote or clone can never receive an object an
  older vl could not read: the push fails with "upgrade it with `vl upgrade
  --remote <name>`", and nothing is recorded.
* `fsck` reports a binary tree in a format-1 repository, an AES-SIV object
  or an HPKE ring in a format-1/2 repository, a conflict object or
  conflict entry below format 4, and any format-5 object or view field
  below format 5, as corruption, and a repository format newer than it
  knows. It checks every version a conflict names as it checks a file, a
  symlink or gitlink's object as a file's (and, when readable, its
  content: §3.7), and every annotated tag a view names (§3.8).
* `Object::encode()` is the format-1 encoding (unchanged API);
  `Object::encode_with(TreeEncoding)` and `ObjectStore::encode` give the
  encoding of a particular repository.

### 3.6 Conflict objects (format 4)

An unresolved conflict between versions of one file, as Jujutsu records
it: an alternating sum `add₀ − remove₀ + add₁ − … + addₙ` (a three-way merge
of `base`, `ours`, `theirs` is adds `[ours, theirs]`, removes `[base]`).

```text
conflict = 0x04 | removes uvarint (1 to 64) | term{2·removes + 1}
           -- terms in the order add₀, remove₀, add₁, remove₁, …, addₙ
term     = 0x00                                    (no file)
         | flags u8 | id [32]
           | size uvarint                          if flags.SIZE (then != 0)
           | label_len uvarint | label UTF-8       if tier != public
           | fallback [32]                         if flags.FALLBACK
flags    = bit 0 PRESENT (set) · bit 1 EXECUTABLE · bit 2 SIZE ·
           bit 3 FALLBACK · bits 4–5 tier (as in trees) ·
           bits 6–7 term kind (format 5): 0 file, 1 symlink, 2 gitlink,
           3 reserved (`Unsupported`); EXECUTABLE clear unless a file
```

* A term is what a file entry holds, without the name: each version keeps
  its own id, label, executable bit and fallback. The object itself is
  plaintext and carries no content, so it may be sent anywhere; the
  versions it names are sent or withheld one by one like any object (a
  public remote gets a public conflict naming a sealed version, never that
  version).
* Canonical by construction (as binary trees: defaults omitted, minimal
  varints, nothing after the last term). Decoding checks the shape only
  (one more add than removes, at least one remove, at most 64); the engine
  simplifies when it reads one, so a hostile unsimplified conflict is
  merely redundant. A reserved flag bit or tier, or a version byte from
  the reserved range, is `Unsupported`.
* The tree entry naming it has kind `conflict` (flag bit 6) and nothing else.
* **Format 5:** a term may be a symlink or a gitlink (a link/file or
  link/link conflict). Before format 5 bits 6–7 were reserved, so a
  format-4 reader refuses such a term as `Unsupported`; a conflict with one
  needs format 5. Link targets are never merged by line: two different
  targets are a conflict, and a conflict with a link term is never written
  out as a file of markers (a target would become file content).

### 3.7 Symlinks and gitlinks (format 5)

* **Symlink** (`EntryKind::Symlink`, kind byte 1): `id` names the blob of
  the link's *target bytes* (UTF-8, no NUL, at most 4096 bytes; `size` is
  its length), plaintext or sealed exactly like file content under the
  policy of the link's own path. Never executable; a fallback is allowed.
* **Gitlink** (`EntryKind::Gitlink`, kind byte 2): a Git submodule pointer;
  `id` names the blob `"<40 or 64 lowercase hex digits>\n"`, plaintext or
  sealed like a file. Never executable, never descended into.
* Both are leaves: `walk_files` and `diff_trees` list them, `lookup` never
  goes through them, and sync, gc, fsck, `push --dry-run` and embargo
  sealing treat their object as a file's (sealed, withheld, listed,
  published by the same rules). fsck warns about a readable target or
  pointer that breaks the rules above.
* The builder records a working copy's symlinks as symlink entries
  (their targets, read with `readlinkat`, never followed) and carries
  gitlinks; checkout writes symlinks as symlinks and gitlinks as empty
  directories (see ARCHITECTURE §4). A conflict with a symlink or gitlink
  term is materialised as one side, as it is, never as markers. Until the
  Git-bridge stream implements them, the Git export refuses a public one
  (a sealed one is omitted like a sealed file).

### 3.8 Annotated tags (`veil:atag`, format 5)

```text
atag = "veil:atag\n" ‖ canonical JSON, exactly what serde_json writes for
  {"name": tag name, "target": hex snapshot id,
   "kind": "annotated" | "lightweight-git",
   "message": {"plain": text} | {"sealed": envelope},
   "tagger": text, "timestamp": ms since the epoch,
   "signature"?: {"signer", "key", "sig"},
   "git"?: {"oid": lowercase hex 40|64, "raw": lowercase hex}}
```

* Canonical (a re-encoding must give the same bytes) and closed: unknown
  fields are refused. `name` passes the tag-name rules; the message is at
  most 1 MiB, the tagger at most 1 KiB without control characters, `raw`
  at most 1 MiB + 64 KiB; a lightweight Git tag has no `git` object.
* `signature`: Ed25519 over the atag's unsigned id, context `tag`
  (CRYPTO.md C5). A view's `Tag.annotation` must name an atag of the same
  `name` and `target` (`Atag::verify`): a push refuses a tag whose
  annotation is missing, not an atag, or names another tag or target, and
  a pull receives such a tag without its annotation (with a warning).
* A cloaked tag's message is sealed under its scope (CRYPTO.md C2). Push
  sends an atag only with its tag, after the tag's checks (cloaked tags
  and tags on embargo-withheld history stay here, their atags with them),
  and never sends an atag with a sealed message to a public remote,
  whichever tag names it.
* `View.remote_release_tags` names atags of Git release tags (the Git
  bridge). gc keeps every atag a retained view names and its target.

## 4. Rules for changing a format

1. **No ignorable fields.** An old reader that drops what it does not know
   would silently lose it when it rewrites the structure (a merge copies
   tree entries, a sync rewrites rings and records). Every addition is a
   new version that old readers refuse with `Unsupported`.
2. **A new object encoding** takes the next reserved encoding byte (or a new
   tag), must be canonical, must keep the empty tree in format 1, and needs
   a new repository format that enables writing it. Readers keep reading
   every old encoding forever.
3. **A new repository format** bumps `REPO_FORMAT`, adds a row to
   `min_vl_for_format` and to the table in §1, a transition in
   `upgrade::transition_steps` (idempotent steps; may be empty), and the
   `put_raw` rule for what the new format permits.
4. **Rings and embargo records** may only raise their `format` together
   with the repository format; readers reject newer ones (fail closed: no
   keys, no release). **Team-vault records** are immutable and never
   rewritten, so a later record format needs no repository format: readers
   skip records with a newer `format` (fail closed: the entry is not
   shown, with a warning) and never delete them.
5. **Signed bodies never change** (§2); use a new context instead.
6. **Every format change ships with a fixture set** written by the release
   that introduces it (`crates/veil-core/tests/fixtures/generate.sh`), and
   appends its new encodings to `tests/fixtures/encodings.txt`. The tests
   enforce this (§6).

## 5. Migrations: `vl upgrade`

Decision: **existing repositories keep working read-compatibly, forever.**
A format-1 repository opens, reads, verifies, syncs and keeps writing
format 1 with this release; there is no forced migration. `vl upgrade` is
the explicit opt-in to what a newer format adds (format 2: binary trees, a
faster `vl status`).

```text
vl upgrade [--dry-run] [--remote NAME] [--force]
```

1. Takes the repository lock (a dry run takes none and writes nothing) and
   writes the journal `.veil/upgrade.json`.
2. **verify**: runs `fsck` and counts trees by encoding. Any corruption
   stops the upgrade before anything changes (`--force` overrides).
3. One step per format transition. `1 → 2`, `2 → 3` and `3 → 4` have
   none: no object is rewritten.
4. **set-format**: rewrites `repo.json` with the new format and `min_vl`,
   atomically and durably. This is the commit point: before it the
   repository is entirely the old format, after it entirely the new one.
5. Steps that need the new format. `3:hpke-ring-keys`: for every scope this
   identity administers whose current key was ever wrapped with the legacy
   box, append a signed `Rotate` (a new generation, HPKE-wrapped to every
   member, carrying the previous key). Idempotent; a non-admin gets a note
   naming who can finish it; skipped for `--remote` (no identity). A
   member whose key is a low-order point gets no key and is named in a
   note; any other scope that cannot be rotated becomes a note too, never an
   error after the commit point (only I/O errors stop the step, and it
   resumes).
6. Removes the journal.

Each finished step is journaled before the next starts, so `vl upgrade`
after a crash resumes (it skips verification if it already passed, and
notices a commit point already reached; `tests/crash.rs` crashes 1→3 and
2→3 at every write). Old data is never removed. A remote is upgraded with
`--remote NAME` (checked structurally, without opening sealed content);
an SSH remote is reached over SFTP, as push and pull reach it.

An upgrade from format 3 (to 4) runs `3:hpke-ring-keys` too when one of
this identity's rings still needs it. In a repository that is already at
the newest format, `vl upgrade` still runs `3:hpke-ring-keys` when one of
this identity's rings needs it (a fresh
clone of an upgraded remote, or a clone a non-admin upgraded), and says so:
"Moved the key rings of this repository (format 3) to HPKE key wrapping".
Otherwise it reports "already at format 3", with a note for each scope
still waiting for its admin.

### Consequences

* **Object ids, change ids, signatures.** Unchanged. Nothing is rewritten,
  so every snapshot keeps its id, its signature stays valid, and change ids
  are untouched. Only objects written after the upgrade use binary trees.
* **Remotes.** A format-1 remote keeps working for everyone until something
  binary would be pushed to it; then the push fails and names the fix. The
  order for a team is: everyone installs vl ≥ 1.0, then `vl upgrade
  --remote origin`, then members upgrade their clones when they like.
  Pulling from a format-1 remote into a format-2 repository always works; a
  format-1 clone refuses to pull binary trees ("run `vl upgrade`").
* **Embargoes.** Sealed trees inside an embargo are written in the writer's
  encoding too. A format-1 relay cannot see inside them, but every embargo
  also has a plaintext wrapper tree in the same encoding, so the relay's
  `put_raw` refuses the push as a whole.
* **Git bridge.** Snapshot ids never change, so commit ↔ snapshot mappings
  stay valid across an upgrade. A bridge that computes tree ids itself must
  use `ObjectStore::encode` (or `put_tree`), not `Object::encode()`, which
  is the format-1 encoding.
* **Downgrades** are not supported: an older vl refuses a format-2
  repository with a message naming the release it needs.

### Format 5 (Git parity)

* **Nothing is rewritten** (`4 → 5` has no step): a format-4 snapshot never
  holds a link (links were never recorded), so every object, operation,
  id and signature stays as it is. `repo.json` gets the new format and
  `min_vl`.
* **Remotes and clones.** A format-4 remote or clone refuses symlink and
  gitlink trees, link-term conflicts and annotated tags ("upgrade it with
  `vl upgrade --remote <name>`"), and its operation store refuses a view
  naming one; an older vl refuses a format-5 repository or remote outright
  (so it never drops `Tag.annotation` by rewriting a view). The order for
  a team is the usual one.
* **Colocated directories** carry the `colocated` marker only at format 5:
  an older vl refuses the directory, and never snapshots it without the
  Git-side guards.

### Format 4 (first-class conflicts)

* **Decision: conflicts recorded before the upgrade stay as they are.** A
  format-3 merge wrote markers into the file and listed the path on the
  snapshot; that snapshot keeps its bytes, its id and its signature, and
  its descendants carry the marker conflict as before (it is resolved by
  editing the file). Rewriting them as conflict entries would change every
  snapshot id above them. Merges made after the upgrade record conflict
  entries.
* **What a format-4 repository still writes as markers:** merges under an
  unreleased embargo (the embargo's sealed trees never hold a conflict
  entry, whose versions keep their own sealing outside the embargo; a
  conflict entry the embargoed tree would take in goes in as its file of
  markers), and nothing else.
* **Remotes and clones.** A format-3 remote or clone refuses conflict
  objects and trees with conflict entries ("upgrade it with `vl upgrade
  --remote <name>`"): only history that holds an unresolved conflict is
  affected. An older vl refuses a format-4 repository outright ("this
  repository uses format 4, which needs a newer vl"), and a conflict entry
  or object met elsewhere as `Unsupported`.
* **The Git export** is unchanged in format: a conflict becomes the file of
  markers a public reader is shown (ARCHITECTURE.md §11).

### Format 3 (standard cryptography)

* **Nothing is re-sealed.** Sealed objects written before the upgrade keep
  the legacy construction, their bytes and their ids; re-sealing would
  change every tree and snapshot id above them and break every signature.
  Unchanged cloaked files keep their sealing when re-snapshotted. New and
  changed content is sealed with AES-SIV. For the security review this
  means pre-upgrade history stays under the legacy constructions forever
  (CRYPTO.md §5).
* **Rings.** The upgrading admin's rotation makes each ring format 3. A
  remote or clone at format 2 refuses it (and AES-SIV objects) with "run
  `vl upgrade` / `vl upgrade --remote <name>`". The order for a team is the
  one above: everyone installs this vl, `vl upgrade --remote origin`, one
  admin upgrades and pushes (others pull before upgrading, so the rotation
  is not made twice: two admins rotating concurrently diverge the ring, as
  any concurrent admin edits do).
* **Identities** created by this release have independent signing keys
  (identity format 2). Existing identity files keep their derived key
  (`vl identity show` says "legacy") and keep working everywhere; an
  older vl cannot load a new identity file.

## 6. Compatibility fixtures

`crates/veil-core/tests/fixtures/format-N/` holds the repositories that the
release introducing format N wrote, generated once by `generate.sh` and never
regenerated (from format 3 on, `generate.sh <vl> <out> <format-(N-1)>`, which
adds `home-dave`, a legacy identity granted to the scope, and `upgraded/`,
the previous set after `vl upgrade` with one more commit pushed, mixing old
and new constructions; from format 4 also a merge with conflict entries at
the tag `conflicted`, one resolved with `vl resolve`; from format 5 also
symlinks and gitlinks, public and sealed, a link/file conflict and
annotated tags, written through the engine by `write_format_5_extras` in
`format_compat.rs`): three identities (`home-alice`, `home-bob`, `home-carol`), the
project `alice/` (packed and loose objects, a cloaked directory, a ring with
a grant, a revocation and a rotation (key generation 2), a released and an
unreleased embargo, a cloaked tag, a vault, gc pending list, pruned ops,
stat cache and checkout state), and its `team-remote/` and
`public-mirror/`. The identity files are test-only keys.

`tests/format_compat.rs` and `crates/vl/tests/upgrade_cli.rs` check that
this build:

* opens, reads (as the admin, a member, a revoked member and an outsider),
  verifies signatures, rings, embargo records and the vault, and `fsck`s
  every fixture set and its remotes;
* keeps writing format 1 in a format-1 repository;
* upgrades with a dry run that writes nothing, keeps every id and the
  view, resumes after a crash on either side of the commit point, and
  refuses a corrupt repository without changing it;
* syncs across formats as described in §5;
* refuses newer repository formats, object encodings, flag bits, object
  kinds, pack versions, ring and embargo-record formats as `Unsupported`;
* writes only AES-SIV objects and HPKE wraps at format 3 and only the legacy
  ones at formats 1–2, upgrades 1→3 and 2→3 (rings rotated to HPKE, every
  object and id kept), and never lets format-3 cryptography reach a
  format-1/2 repository (push, pull, incremental and full);
* reads the format-4 set's conflict entries as each identity's audience
  allows (members both sides, the revoked member and the public mirror's
  readers neither), never lets a conflict reach a format-3 repository, and
  upgrades 3→4 keeping marker conflicts and every id;
* reads the format-5 set's links, gitlinks, link conflict and annotated
  tags as each identity's audience allows, verifies the signed atags,
  finds no sealed target, pointer or tag message on the public mirror,
  never lets a format-5 object reach a format-4 repository (push, pull,
  API), upgrades 4→5 rewriting nothing, and refuses the `colocated`
  marker below format 5.

Two checks make format changes impossible to miss:

* `every_repository_format_has_a_fixture_set` fails unless every format from
  `MIN_REPO_FORMAT` to `REPO_FORMAT` has a fixture set at that format;
* `encodings_match_the_golden_file` pins the bytes of every object encoding
  in `tests/fixtures/encodings.txt` (blob, empty tree, JSON and binary
  trees, root and full snapshots with a signature, sealed, sealed with
  AES-SIV, a conflict object, a binary tree with a conflict entry, binary
  trees with a symlink and with a gitlink, a conflict with a symlink term,
  and annotated tags: signed, sealed, imported from Git). Changing what is
  written fails until the change becomes a new format; then new lines are
  appended (`VEIL_BLESS_ENCODINGS=1`), never edited.

## 7. Measurements

Release build, Linux, warm cache.

| | format 1 (JSON trees) | format 2 (binary) |
|---|---|---|
| decode the 1,201 trees of the 20k-file layout (`tree_bench`) | 12.40 ms | 0.66 ms |
| their size | 2,449 KiB | 882 KiB |
| `vl status`, unchanged 20k files (`bench_status`, median) | 72–77 ms | 58–59 ms |
| `vl status`, one public file edited | 77–99 ms | 63 ms |
| `vl status`, one cloaked file edited | 77–84 ms | 62–69 ms |

The status runs alternate the vl 0.1.0 binary (format 1) and this build
(format 2) on the same machine, two runs each, on tmpfs. A format-1
repository opened by this build decodes its JSON trees as before.

```sh
cargo test --release -p veil-core --test tree_bench -- --ignored --nocapture
VL_BENCH_BIN=/path/to/old/vl cargo test --release -p vl --test bench_status -- --ignored --nocapture
```
