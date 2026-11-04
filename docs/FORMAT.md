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
| `.veil/repo.json` | pretty JSON `{format, repo_id, remotes, min_vl?}` | `format` | no | written last by `init`, rewritten atomically by `upgrade` (commit point) |
| objects (§3) | `tag ‖ payload`, id = BLAKE3 | tag + encoding byte | yes | loose: `.veil/objects/ab/cdef…` (the canonical bytes) |
| — blob | `veil:blob\n` ‖ bytes | none needed: any bytes are valid | yes | a new blob encoding would be a new tag |
| — tree | `veil:tree\n` ‖ `{` JSON (v1) or `0x02` binary (v2) | encoding byte | yes | §3 |
| — snapshot | `veil:snap\n` ‖ `{` JSON (v1) | encoding byte | yes | canonical (§3.3) |
| — sealed (formats 1–2) | `veil:seal\n` ‖ u16 **big-endian** label length ‖ label ‖ nonce[24] ‖ XChaCha20-Poly1305 ciphertext | tag | yes | the plaintext is another object's encoding; nonce derived from the plaintext (legacy, CRYPTO.md C1L); still written by format-1/2 repositories |
| — sealed (format 3) | `veil:sea2\n` ‖ u16 **big-endian** label length ‖ label ‖ SIV[16] ‖ AES-SIV ciphertext | tag | yes | AES-SIV-CMAC-512 under `HKDF-SHA256(scope key)`, AD = `[label]` (CRYPTO.md C1); refused below format 3 |
| — embargo wrapper | an ordinary tree with an `embargo` marker entry | as trees | yes | `embargo.rs` |
| packs `.veil/objects/pack/pack-<sum>.pack` | `VEILPAK1` ‖ count u32 ‖ entries ‖ BLAKE3 | magic digit | no (sync sends canonical objects) | entry kinds 0 stored, 1 zstd, 2 delta; 3–15 reserved |
| pack indexes `pack-<sum>.idx` | `VEILIDX1` ‖ count ‖ fanout ‖ ids ‖ offsets ‖ lengths ‖ pack sum ‖ BLAKE3 | magic digit | no | |
| operations `.veil/ops/<id>` | JSON `Operation {parents, timestamp, user, description, view}`, id = BLAKE3 of the bytes | repository format | no (device/repository-local) | |
| `.veil/op_head` | hex id | fixed | no | |
| pruned-ops list `.veil/ops_pruned` | one hex id per line | fixed | no | append-only |
| key rings `.veil/meta/keyrings/<scope>.json` | pretty JSON `KeyRing` | `format` (0/1 legacy, 2 signed log, 3 signed log that may hold HPKE-wrapped keys) | yes | readers reject `format > 3` (no keys, a warning on sync); a ring with an HPKE wrap must say 3, and a format-1/2 repository refuses to store it |
| — wrapped key (in a ring change) | JSON: legacy `{ephemeral, sealed}` or HPKE `{hpke, enc, ct}` | shape + `hpke` suite string | yes | legacy written by format 1–2, HPKE by format 3 (CRYPTO.md C3/C3L); unknown fields or suites refused |
| embargo records `.veil/meta/embargoes/<id>.json` | pretty JSON `EmbargoRecord` | implicit 1; a later format adds `"format": N` | yes | readers reject `format > 1` |
| vault `.veil/local/vault.sealed` | envelope (label `local`) around JSON `VaultData` | repository format | no (device-local) | |
| stat cache `.veil/local/statcache/<ws>.cache` | `veil:statcache\n` ‖ version u32 ‖ … ‖ BLAKE3 | `VERSION` (1) | no | any mismatch reads as empty: a cache, never data |
| scanner markers `.veil/local/scanned/<ws>.version` | decimal `secrets::RULES_VERSION` | itself | no | a mismatch re-scans once |
| accepted policy `.veil/local/accepted-policy` | the text of the `.veilpolicy` this device's member last accepted (empty: none) | as `.veilpolicy` | no (device-local) | missing: the next working-copy snapshot records the current `.veilpolicy` |
| checkout state `.veil/local/checkout.json` | pretty JSON `{workspace, snapshot}` | repository format | no | gc keeps its snapshot |
| lock `.veil/lock`, `.veil/lock.steal` | JSON lock info (legacy: `"<pid> <millis>"`) | none: unknown fields are ignored, unparseable content is reclaimed only after a full unchanged lease | no | transient; a live holder rewrites it every 2.5 s, so an older reader never steals a newer holder's lock |
| gc pending `.veil/objects/gc/pending` | `VEILGCP1` ‖ count u32 ‖ (id, ms)* ‖ BLAKE3 | magic | no | damaged/unknown reads as empty: only restarts the grace period |
| gc keep markers `.veil/objects/gc/keep/<id>` | empty files | none | no | |
| upgrade journal `.veil/upgrade.json` | pretty JSON `{from, to, started, done[]}` | — | no | present only during `vl upgrade` |
| identity `$VEIL_HOME/identity.json`, `retired/` | legacy JSON `{name, public, secret, signing?}` (signing key derived); format 2 `{format: 2, name, public, signing, encryption_secret, signing_secret}` (independent keys) | `format` (absent = legacy) | no | outside the repository; new identities are format 2 whatever the repository format; format 2 has no `secret` so older vl refuse it; readers reject `format > 2` |
| `.veilpolicy` | text, one rule per line | grammar is fail-safe: unknown tiers isolate | yes (it is a tracked file) | |

Signed bodies have their own fixed encodings and must never change: the ring
change body (`RingChange::signing_body`), the embargo body
(`EmbargoRecord::body`) and the snapshot's *unsigned id* (the id of its
encoding without `signature`). A format change that touches a signed type
needs a new signing context.

## 3. Objects

### 3.1 The encoding byte

For structured objects (trees, snapshots) the first payload byte after the
tag is the **encoding version**:

| byte | meaning |
|---|---|
| `{` (0x7B) | format-1 JSON |
| 0x02 | binary tree (format 2) |
| 0x03–0x1F | reserved for later versions → `Unsupported` ("needs a newer vl") |
| anything else | corrupt |

A tag shaped like an object tag (`veil:` + four lowercase letters or digits
+ `\n`) that this build does not know is `Unsupported`, not corrupt.

### 3.2 Binary trees (encoding 2)

```text
tree    = 0x02 | count uvarint (>= 1) | entry{count}
entry   = name_len uvarint | name (UTF-8) | flags u8 | id [32]
          | size uvarint                    if flags.SIZE    (then size != 0)
          | label_len uvarint | label UTF-8  if tier != public (scope / embargo id)
          | fallback [32]                   if flags.FALLBACK
flags   = bit 0 DIR · bit 1 EXECUTABLE · bit 2 SIZE · bit 3 FALLBACK
          bits 4–5 tier: 0 public, 1 cloaked, 2 embargoed, 3 reserved
          bits 6–7 reserved
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
* A reserved tier or flag bit is `Unsupported`.

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
  `check_storable`; the pack sink of incremental sync calls it too). The
  keychain follows the same format: it wraps keys with HPKE only from
  format 3 and refuses to store a format-3 ring below it. Push and pull copy objects with
  `put_raw`, so a format-1 remote or clone can never receive an object an
  older vl could not read: the push fails with "upgrade it with `vl upgrade
  --remote <name>`", and nothing is recorded.
* `fsck` reports a binary tree in a format-1 repository, an AES-SIV object
  or an HPKE ring in a format-1/2 repository as corruption, and a
  repository format newer than it knows.
* `Object::encode()` is the format-1 encoding (unchanged API);
  `Object::encode_with(TreeEncoding)` and `ObjectStore::encode` give the
  encoding of a particular repository.

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
   keys, no release).
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
3. One step per format transition. `1 → 2` and `2 → 3` have none: no
   object is rewritten.
4. **set-format**: rewrites `repo.json` with the new format and `min_vl`,
   atomically and durably. This is the commit point: before it the
   repository is entirely the old format, after it entirely the new one.
5. Steps that need the new format. `3:hpke-ring-keys`: for every scope this
   identity administers whose current key was ever wrapped with the legacy
   box, append a signed `Rotate` (a new generation, HPKE-wrapped to every
   member, carrying the previous key). Idempotent; a non-admin gets a note
   naming who can finish it; skipped for `--remote` (no identity).
6. Removes the journal.

Each finished step is journaled before the next starts, so `vl upgrade`
after a crash resumes (it skips verification if it already passed, and
notices a commit point already reached). Old data is never removed. A
remote is upgraded with `--remote NAME` (checked structurally, without
opening sealed content).

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
and new constructions): three identities (`home-alice`, `home-bob`, `home-carol`), the
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
  format-1/2 repository (push, pull, incremental and full).

Two checks make format changes impossible to miss:

* `every_repository_format_has_a_fixture_set` fails unless every format from
  `MIN_REPO_FORMAT` to `REPO_FORMAT` has a fixture set at that format;
* `encodings_match_the_golden_file` pins the bytes of every object encoding
  in `tests/fixtures/encodings.txt` (blob, empty tree, JSON and binary
  trees, root and full snapshots with a signature, sealed, sealed with
  AES-SIV). Changing what is
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
