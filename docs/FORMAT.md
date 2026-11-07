# Veil on-disk formats

From 1.0 on, a repository written by any vl release is readable by every
later release, or upgradable to what it reads, with one exception
approved by the owner, 2026-11-07: format 8, where only secret files are
encrypted, no longer reads formats 1 to 5 (dropping them was the owner's
request of 2026-11-06), and upgrades formats 6 and 7 only when they hold
nothing that the removed encryption of non-secret content wrote, refusing
otherwise rather than decrypting (§5, "Format 8"). This document lists everything Veil persists, how each part
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
| 5 | 1.0.0 | symlink tree entries (flag bit 7 and a kind byte, §3.7) and conflict terms (§3.6), annotated tags (`veil:atag`, §3.8; `Tag.annotation`) |
| 6 | 1.1.0 | the lock-free op log: heads in `.veil/op_heads/` instead of `.veil/op_head`, operations gain `workspace` and `rewritten` (§2, §5 "Format 6"). Not yet built: snapshot attribution (`Snapshot.agent`) and the `partial` marker for fetch on demand (`docs/design/scale/PLAN.md` §1) |
| 7 | 1.1.0 | key rings of ring format 4: invites, shares by members, a member's removal of their own device, and every ring but `team` naming its project (`docs/HUB.md` §13.12). No object encoding changes; the upgrade 6 → 7 rewrites nothing |
| 8 | 1.1.0 | **only secret files are encrypted.** Removed: sealed descriptions and tag messages (`{"sealed": …}`), cloaked tags and workspaces (`cloak` in views), snapshots on cloaked lines (`Snapshot.cloak`), embargoed tree entries (tier 2) and fallback versions (flag bit 3), sealed directories, embargo keys. Embargo records are plain (embargo record format 2). Decoders refuse what only those wrote; `vl upgrade` brings 6 and 7 to 8 when none of it is there (§5). Formats 1 to 5 are no longer opened |

* `vl init` writes the newest format (`repo::REPO_FORMAT`), and so do
  clones and remotes: this release opens format 8 only
  (`repo::MIN_REPO_FORMAT`).
* A reader **refuses a newer repository format before reading anything
  else** (`Repo::open`, `fsck`, `vl upgrade`): an older vl never
  half-understands, and never rewrites, newer data. The error names the
  release it needs when `repo.json` says so (`min_vl`).
* A reader refuses an **older format** too, with what to do: formats 6 and
  7 "run `vl upgrade`", formats 1 to 5 "upgrade it to format 7 first
  with a vl from before format 8". Objects that older formats wrote (JSON trees, legacy sealed
  objects, legacy key wraps) are still read wherever an upgraded repository
  holds them.
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
| `.veil/repo.json` | pretty JSON `{format, repo_id, remotes, min_vl?}` | `format` | no | written last by `init`, rewritten atomically by `upgrade` (commit point). A remote may be a Veil server (`veil://host[:port]/project` or `https://…`); a server remote cloned with `--only DIR` has `"only": "DIR"` (absent otherwise, so earlier files keep their bytes; an older vl ignores the field and cannot use a server remote) |
| objects (§3) | `tag ‖ payload`, id = BLAKE3 | tag + encoding byte | yes | loose: `.veil/objects/ab/cdef…` (the canonical bytes) |
| — blob | `veil:blob\n` ‖ bytes | none needed: any bytes are valid | yes | a new blob encoding would be a new tag |
| — tree | `veil:tree\n` ‖ `{` JSON (v1) or `0x02` binary (v2) | encoding byte | yes | §3 |
| — snapshot | `veil:snap\n` ‖ `{` JSON (v1) | encoding byte | yes | canonical (§3.3). `conflicts` lists conflicted paths; from format 4 it is an index the engine keeps (every conflict entry of the tree, plus marker conflicts carried from older formats), same field and encoding |
| — conflict (format 4) | `veil:conf\n` ‖ `0x04` ‖ binary terms (§3.6) | encoding byte | yes | refused below format 4; plaintext (ids and labels only, never content); one with a symlink term refused below format 5 |
| — annotated tag (format 5) | `veil:atag\n` ‖ `{` canonical JSON (§3.8) | encoding byte | yes, with its tag | refused below format 5; plaintext (a sealed message, which only formats 7 and earlier wrote, is refused) |
| — sealed (formats 1–2) | `veil:seal\n` ‖ u16 **big-endian** label length ‖ label ‖ nonce[24] ‖ XChaCha20-Poly1305 ciphertext | tag | yes | the plaintext is another object's encoding; nonce derived from the plaintext (legacy, CRYPTO.md C1L); written by format-1/2 repositories only, read wherever an upgraded repository holds one |
| — sealed (format 3) | `veil:sea2\n` ‖ u16 **big-endian** label length ‖ label ‖ SIV[16] ‖ AES-SIV ciphertext | tag | yes | AES-SIV-CMAC-512 under `HKDF-SHA256(scope key)`, AD = `[label]` (CRYPTO.md C1); refused below format 3 |
| packs `.veil/objects/pack/pack-<sum>.pack` | `VEILPAK1` ‖ count u32 ‖ entries ‖ BLAKE3 | magic digit | no (sync sends canonical objects) | entry kinds 0 stored, 1 zstd, 2 delta; 3–15 reserved. A delta is a zstd frame read with its base as a raw-content dictionary; above 2 MiB of base plus object it is written with the base as a *prefix* and long-distance matching (BUG-290), with a window of at most 2^27, which every zstd decoder accepts by default: the same bytes to every reader, so no new version. Builds without the zstd C library (WASM, ARCHITECTURE.md §13) write kind 0 only and read 1 and 2 with a pure-Rust decoder (a delta's base given to it as a formatted dictionary: a fixed header, then the base); no new version either |
| pack indexes `pack-<sum>.idx` | `VEILIDX1` ‖ count ‖ fanout ‖ ids ‖ offsets ‖ lengths ‖ pack sum ‖ BLAKE3 | magic digit | no | |
| operations `.veil/ops/<id>` | JSON `Operation {parents, timestamp, user, description, view, manual_undo?, undo_of?, redo_of?, workspace?, rewritten?}`, id = BLAKE3 of the bytes | repository format | no (device/repository-local) | `manual_undo` (absent unless set) marks an operation whose effect lies outside the view; `undo_of` / `redo_of` (absent unless set, hex operation ids) mark an undo and a redo, so repeated undos go further back (BUG-247). Older readers ignore all three (an older `vl undo` then treats an undo as a plain operation, as it always did); operations written before them have none, so no version bump or upgrade step. Format 5: a view's tags may carry `annotation` (hex id of a `veil:atag`) and the view `remote_release_tags` (`"<remote>/<name>"` → atag id); both omitted when absent or empty, so earlier views keep their bytes, and an operation using either is refused below format 5 (`OpStore::put`), so a format-4 vl never meets one (it refuses the repository and the remote by format before reading a view). Format 6: `workspace` (the workspace the command was run for; absent for repository-wide commands) and `rewritten` (hex snapshot id → its replacements, empty for abandoned; omitted when empty) come after `redo_of`, so every earlier operation keeps its bytes and id; an operation using either is refused below format 6 (`OpStore::put`). A merge of concurrent operations has several `parents` (sorted), `user` `"veil"`, `description` `merge N concurrent operations` and the largest of its parents' timestamps, so every process merging the same heads writes the same bytes. |
| `.veil/op_head` | hex id | fixed | no | formats 1–5: the single head, moved under the repository lock. At format 6 it is not written; if present (a format-5 writer racing the upgrade) it is read as one more head, merged by the next command and removed |
| `.veil/op_heads/<id>` (format 6) | empty files named by a 64-digit lowercase hex operation id | repository format | no | the heads of the op log. A transaction publishes its operation, creates its head file (`create_new`, durable) and then removes its parents' head files; readers drop a head that is an op-graph ancestor of another (a crash between those steps). Several heads are concurrent operations, which the next command merges. Any other entry is ignored (and noted by `fsck`). A remote has exactly one, written under its lock. Format-5 readers never look here (they refuse the repository by format) |
| transaction staging `.veil/objects/incoming/tx-<owner>/ab/cdef…` (format 6) | loose objects, as in `.veil/objects/` | none | no | a transaction's new objects until it publishes them (a barrier, then renames into place). A transaction with 256 or more new file contents (blobs, sealed or not; on disk) publishes them as one ordinary pack in `objects/pack/` instead (the `.pack` durable before its `.idx`); its trees and snapshots stay loose; nothing new on disk, every version reads it. `<owner>` = `<host hash>-<boot hash>-<pid>-<pid start>-<ms>-<random>`: removed by `Repo::open` only once its owner is provably gone (`lock::owner_gone`). Never read by anyone but its transaction. Older clients never list `incoming/` |
| transaction registrations `.veil/objects/incoming/live-<owner>/` (format 6) | an empty directory, `<owner>` as for staging | none | no | one per live lock-free transaction, from before it reads the heads until it has published, and per `Repo::open` or reload while it reads the op log (BUG-811): gc deletes only while none is registered. One whose owner is provably gone is ignored and removed (`Repo::open`, gc). Older clients never list `incoming/` |
| gc lease `.veil/gc.lock` | empty, `flock`ed | none | no (device-local) | new in this release (scale stream G2); one gc or background maintenance run at a time on a lock-free repository, which then takes no `.veil/lock`; `vl upgrade` takes it too. Released by the kernel when its holder ends. An older vl ignores it |
| gc state `.veil/local/gc/{fence,epoch,last-prune}` | `fence`: the deleting gc's owner tag; `epoch`: 32 random hex digits; `last-prune`: ms since the epoch, decimal | none | no (device-local) | new in this release. `fence` exists while gc deletes (transactions that meet it wait; one whose owner is gone is ignored); `epoch` changes whenever gc deleted something (a transaction whose process read its view under an older one checks the ids it carried, at commit); `last-prune` drives background pruning. Unreadable content reads as absent. An older vl ignores them |
| unfinished clone `.veil/local/clone-incomplete` | any text | none | no (device-local) | new in this release (BUG-837): written by `vl clone` before its repository exists, removed after its checkout. While it exists and `.veil/local/checkout.json` does not, commands refuse the directory as an interrupted clone; once the checkout's journal exists, the next command removes it and finishes the checkout. An older vl ignores it |
| maintenance log `.veil/local/maintenance.log` | text, one line per background run and its output | none | no (device-local) | 0600, emptied once past 1 MiB. Written by `vl gc --auto` started in the background |
| push expiry `.veil/local/push-expiry/<host>.json` (on a remote) | compact JSON object: push staging name → `[touched stamp seen (or null), when this host first saw it so (ms, its clock)]` | none: unreadable content reads as empty | no | new in this release (BUG-810): each host expires push staging by its own clock only. An older vl ignores it (and still expires by the `touched` stamp) |
| push staging `.veil/objects/incoming/push-<id>/` (any format) | a push's packs (`pack-<sum>.pack`, `.idx`) and `touched` (ms since the epoch, decimal) | none | no | `<id>` is 128 random bits in lowercase hex. A push's upload until its phase B renames the packs into `objects/pack/` (each `.pack` before its `.idx`). Never read, inventoried, counted or removed by readers, fsck (a note) or gc, except that gc and pushes remove a directory that the host running them has seen with the same `touched` for more than 7 days of its own clock (`push-expiry`, BUG-810). Older clients never list `incoming/`, so format-5 remotes take two-phase pushes unchanged |
| push journal `.veil/local/push/<hash>.json` | JSON `{version: 1, push_id, url, public, released, staged: [{name, objects, raw_bytes, pack_len}]}` | `version` | no (device-local) | `<hash>`: the first 32 hex digits of BLAKE3 of the remote's URL and the pushed tags. What an interrupted push staged; every entry is checked on the remote before it is reused, and a journal that does not parse, or of another version, is ignored |
| pull spool `.veil/objects/incoming/pull-<owner>/` | a pull's downloaded packs (`PackWriter` streams), and its loose objects under `loose/<hex id>` | none | no | one per pull (the transaction's owner), removed when the pull ends, or by `Repo::open` once its owner is gone. Format 5 used the fixed `incoming/pull`, emptied under the lock; `vl upgrade` to 6 removes it |
| working-copy locks `.veil/local/wc/ws-<name>.lock` (format 6) | empty, `flock`ed | none | no (device-local) | one recorder of a workspace's directory at a time (the project directory, `ws exec`, `ws write`, mounts); released by the kernel when the process ends. An older vl ignores the directory |
| pruned-ops list `.veil/ops_pruned` | one hex id per line | fixed | no | append-only |
| key rings `.veil/meta/keyrings/<scope>.json` | pretty JSON `KeyRing` | `format` (0/1 legacy, 2 signed log, 3 signed log that may hold HPKE-wrapped keys, 4 signed log that may hold `invite`, `uninvite`, `share` and `revoke_own` changes, and a genesis naming its project) | yes | readers reject `format > 4` (no keys, a warning on sync); a ring with an HPKE wrap must say 3 or more, a ring with a format-4 change must say 4; a format-1/2 repository refuses to store format 3, a format-3 to 6 one format 4 (`vl upgrade`) |
| — ring format 4 changes | `{"kind": "invite", person, key, expires_at}`, `{"kind": "uninvite", key}`, `{"kind": "share", member, proof: {"kind": "invite", key, signature} \| {"kind": "vouch", by, signature}}`, `{"kind": "revoke_own", member, rotation}`, in the signed body like every change; and `project` (32 lowercase hex digits) in a genesis, after `proof` | ring format 4 | yes | the rules the replay applies are in `docs/HUB.md` §13.12; a share and a `revoke_own` are signed by a current member, the others by an admin. `project` is the hash of the project's `team` ring's genesis change (BUG-845): every ring but `team` made in a format-7 repository holding a `team` ring carries it, `team` never does, and a reader refuses a ring naming another project (`Keychain::bound`) |
| — wrapped key (in a ring change) | JSON: legacy `{ephemeral, sealed}` or HPKE `{hpke, enc, ct}` | shape + `hpke` suite string | yes | legacy written by format 1–2, HPKE by format 3 (CRYPTO.md C3/C3L); unknown fields or suites refused |
| — member binding (in a genesis member or grant) | `"binding": hex(Ed25519 signature)`, after `signing_key`; absent when not recorded | ring format 3 | yes | written from repository format 3 only (CRYPTO.md C4); a ring with one must say format 3, so format-1/2 repositories and older vl never receive it. Added to ring format 3 before any release wrote that format; the format-3 fixtures predate it and carry none |
| embargo records `.veil/meta/embargoes/<id>.json` | pretty JSON `EmbargoRecord {format, id, scope, until, released_at, created}`, plain | `format` (2; format 1, without the field, held an embargo key) | yes | readers reject any format but 2: format 1 only in a repository before format 8 (`vl upgrade` refuses it), a newer one as `Unsupported`. Released when `released_at` is set or `until` has passed |
| team-vault records `.veil/meta/vault/<scope>/<id>.json` | compact JSON `VaultRecord {format, scope, sealed, timestamp, signature}`; `sealed` is the JSON envelope (C2) of the padded JSON `{name, value, since}` under label `vault:<scope>#<key-id>`; `<id>` = hex BLAKE3 of the file, which must be exactly the canonical encoding | `format` (1); unknown fields refused | yes, team remotes only | immutable, never rewritten: a write adds a record, compaction deletes superseded ones (ARCHITECTURE §3). A newer `format`, unknown fields or a non-canonical file make the record not count, with a warning; nothing is rewritten. Older vl never read, write or relay the directory, so no repository format change |
| staged embargo releases `.veil/local/releases/<id>.json` | pretty JSON `{released_at}` | none: invalid content is ignored (the embargo stays unreleased) | no (device-local) | written by `vl embargo release`, moved into the record by the next push, deleted by `vl undo` (BUG-109) |
| team-vault value history `.veil/local/vault-history/<scope>.json` | compact JSON `{names: {<name hash>: {<value hash>: <generation>}}}`: keyed BLAKE3 (key `derive_key(TEAM_VAULT_HISTORY, local vault key)`, CRYPTO.md C12) of each name, and of each value it held, with the first key generation that value was sealed under; at most 256 values per name | none: unreadable content reads as empty | no (device-local) | new in this release (BUG-521); no repository format change. Only makes `since` of later writes, and `--exposed-to`, more conservative; losing it forgets what this device saw. An older vl ignores it |
| `vl run` default scopes `.veil/local/run-scopes.json` | compact JSON `{scopes: [<scope>…]}` | none | no (device-local) | new in this release, written by `vl run --remember` (BUG-520). Missing: `vl run` loads no team vault unless `--scope` is given. An older vl ignores it (and loads every scope) |
| vault `.veil/local/vault.sealed` | envelope (label `local`) around JSON `VaultData {secrets, files, removed?}` | repository format | no (device-local) | `removed`: backups of vanished isolated files with `removed_at`, kept 30 days; older readers ignore it |
| deleted tags `.veil/local/deleted_tags.json` | pretty JSON object: tag name → hex snapshot id | none (a missing file is empty) | no | written by `vl tag delete`, read and pruned by pull (`remote::deleted_tags`). Outside the view and the op log; an older vl ignores the file and never rewrites it, so no repository format change |
| stat cache `.veil/local/statcache/<ws>.cache` | `veil:statcache\n` ‖ version u32 ‖ … ‖ BLAKE3 | `VERSION` (2: records gained a line-ending fact, `EolFact`) | no | any mismatch reads as empty: a cache, never data (a version-1 cache is re-read once) |
| history index `.veil/index/graph/L-<epoch>-<lo>-<hi>.vcg`, `E-<epoch>` | `VEILCG01` ‖ count u32 ‖ missing u32 ‖ ids (ascending) ‖ records (generation u64, change id, flags u8) ‖ missing parents ‖ BLAKE3 | magic | no (device-local cache) | new in this release; no repository format change. Layers are never synced: anything unreadable (another magic, a bad checksum, a torn or non-canonical file) voids the index, which is computed again from the store. An older vl ignores the directory |
| scanner markers `.veil/local/scanned/<ws>.version` | decimal `secrets::RULES_VERSION` | itself | no | a mismatch re-scans once |
| project anchor `.veil/local/project-anchor` (format 7) | the project fingerprint this device confirmed (`XXXX-XXXX-XXXX-XXXX-XXXX`), or empty: none yet | none: anything else reads as empty | no (device-local) | written in every clone of a Veil server project (`vl clone`, the first `vl pull`, `vl identity confirm`, `vl push` creating the project) from `$VEIL_HOME/hub.json`. While it exists, the keychain trusts only the `team` ring with that fingerprint and rings naming that project, and nothing while it is empty (BUG-845). Missing (a repository that is not such a clone): rings that name no project are trusted as before. An older vl ignores it |
| accepted policy `.veil/local/accepted-policy` | the text of the `.veilpolicy` this device's member last accepted (empty: none) | as `.veilpolicy` | no (device-local) | missing: the next working-copy snapshot records the current `.veilpolicy` |
| checkout state `.veil/local/checkout.json` | pretty JSON `{workspace, snapshot, materialised?, pending?: {workspace, snapshot}}`; `materialised` is `{view?, hidden?, fallback?, crlf?}` (`fallback`: conflicts written with a version this reader could not read, with the rendering written; `crlf`: paths written with CRLF line endings for `eol=crlf`) | repository format | no | gc keeps both snapshots; `pending` is the journal of an unfinished move of the directory; `crlf` is an addition an older vl ignores (a record without it means "written as recorded") |
| attributes `.veil/local/attributes`, drivers `.veil/local/config.toml` and `$VEIL_HOME/config.toml` | `.veilattributes` syntax; TOML `[merge.<name>] command = [argv…]`, `[diff.<name>] textconv = [argv…]` | none | no (device-local) | new in this release (feature 7); an older vl ignores them |
| `ws exec` sandbox `.veil/local/sandboxes/<ws>/` (`.`/`..` spelt `%2e`/`%2e%2e`) | `manifest.json`: pretty JSON `{version, workspace, tree?, snapshot?, materialised?, boot, running?, only?, quarantined?, pending?, guard_checked?}` (`pending`: `{run, base, message?, started, kept?, injected?, recorded?}`, the command's unrecorded output; `guard_checked`: ns since the epoch); `statcache` in the stat-cache format above; `lock` (empty, `flock`ed); `files/` the sandbox's files; `guard.sealed` (an `Envelope` sealed under `local`: JSON `{files: [[path, hex]], injection?: {run, paths, stash: [[path, hex, executable]]}}`); `unrecorded-<ms>-<rand>/` previous files a rebuild kept whole | `version` (1) | no (device-local) | new in this release; no repository format change; `pending`, `guard_checked` and `guard.sealed` are additions an older reader ignores. Any other version, an unreadable manifest, a `running` marker, another boot, a non-empty `only` (reserved for sparse sandboxes): the sandbox is rebuilt, keeping unrecorded work (re-imported, or kept whole in `unrecorded-…/`). A `pending` run is recorded before anything else. gc does not keep `tree`: a missing one is rebuilt. An older vl ignores the directory |
| `ws mount` state `.veil/local/mounts/<ws>/` (`.`/`..` spelt `%2e`/`%2e%2e`) | `state.json`: pretty JSON `{version, workspace, base, mountpoint?, pid?, boot?, socket?}` (`base`: hex id of the snapshot the overlay is over); `upper/` the overlay's written files and directories; `whiteouts`: one JSON string (a path) per line, appended; `unseen`: the files the whiteouts hide that the mount never showed (carried by every recording), one JSON string per line, rewritten; `lock` (empty, `flock`ed by the serving process); `log`; `ctl` the control socket (or one under `$XDG_RUNTIME_DIR`, named in `state.json`) | `version` (1) | no (device-local) | new in this release; no repository format change. Holds user data (isolated and unrecorded files): never wiped. Another `version` is refused (unmount with that vl). A torn last line of `whiteouts` is skipped. `unseen` is new in the round-8 mount wave and optional (absent: nothing to carry); a vl from before it ignores it. An older vl ignores the directory |
| lock `.veil/lock`, `.veil/lock.steal` | JSON lock info (legacy: `"<pid> <millis>"`) | none: unknown fields are ignored, unparseable content is reclaimed only after a full unchanged lease | no | transient; a live holder rewrites it every 2.5 s, so an older reader never steals a newer holder's lock |
| gc pending `.veil/objects/gc/pending` | `VEILGCP1` ‖ count u32 ‖ (id, ms)* ‖ BLAKE3 | magic | no | damaged/unknown reads as empty: only restarts the grace period |
| gc keep markers `.veil/objects/gc/keep/<id>` | empty files | none | no | |
| upgrade journal `.veil/upgrade.json` | pretty JSON `{from, to, started, done[]}` | — | no | present only during `vl upgrade` |
| public identity (what `vl identity show` prints and `vl scope grant` takes) | `veil1` ‖ hex(X25519 32) ‖ hex(Ed25519 32) ‖ hex(binding 64); the short `veil1` ‖ hex(X25519) is a member id; the earlier `veil1` ‖ hex(X25519) ‖ hex(Ed25519) still parses, but a grant refuses it | length | no (pasted between people) | the binding is deterministic, so the string never changes |
| server sessions `$VEIL_HOME/hub.json` | JSON `{servers: {"host:port": {ca?, token?, expires_at, person?, hub_key?}}}`, mode 0600 | none | no (device-local) | written by `vl login` and when a session is renewed; `ca` is a self-signed server's certificate (PEM) given to `vl login --ca` |
| server metadata (`veil-server`) | PostgreSQL/YugabyteDB schema, `crates/veil-server/migrations/` | `schema_migrations.version` (1) | no | migrations are applied in order, never edited once shipped; the object store holds plain Veil objects under `p/<project>/ab/cdef…` |
| identity `$VEIL_HOME/identity.json`, `retired/` | legacy JSON `{name, public, secret, signing?}` (signing key derived); format 2 `{format: 2, name, public, signing, encryption_secret, signing_secret}` (independent keys) | `format` (absent = legacy) | no | outside the repository; new identities are format 2 whatever the repository format; format 2 has no `secret` so older vl refuse it; readers reject `format > 2` |
| `.veilpolicy` | text, one rule per line | grammar is fail-safe: unknown tiers isolate | yes (it is a tracked file) | **access lines** (the Veil server, S1): a line whose fields after the pattern are all `public` or group/person names (lowercase letters, digits, `-`, `_`, `.`; never a tier word) is an access line, a plain `public` rule on the device. Older vl read such a line as an unknown tier and isolate its pattern: fail-safe, never a leak. New repositories get `cloak team` lines for shared secrets (`vl init`; `vl upgrade --sync-secrets` adds them) |

Signed bodies have their own fixed encodings and must never change: the ring
change body (`RingChange::signing_body`), the team-vault record body
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
          | label_len uvarint | label UTF-8  if tier != public (the scope)
flags   = bit 0 DIR · bit 1 EXECUTABLE · bit 2 SIZE · bit 3 reserved
          bits 4–5 tier: 0 public, 1 cloaked (a sealed secret file),
                2 and 3 reserved
          (Formats 7 and earlier wrote bit 3 FALLBACK, followed by a
          fallback id [32], and tier 2 embargoed, with the embargo id as
          the label; format 8 refuses both, and a cloaked DIR, as content
          only the removed encryption of non-secret content wrote.)
          bit 6 CONFLICT (format 4): `id` names a conflict object (§3.6);
                every other bit must be clear (a conflict entry has no
                size, executable bit or label of its own)
          bit 7 KIND (format 5): a kind byte follows the flags,
                1 symlink (0 and 2–255 `Unsupported`; 2 is reserved
                and never reused);
                DIR, EXECUTABLE and CONFLICT must be clear, SIZE
                and the tier keep their meaning (§3.7)
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
  format-4 reader refuses a symlink entry the same way.)
* In JSON (format-1) trees a conflict entry is `"kind":"conflict"` with no
  other optional field. Only a format-4 repository may store a tree holding
  one, whatever its encoding (`Object::min_repo_format` decodes trees to
  check), and a format-4 repository writes binary trees anyway. Likewise
  `"kind":"symlink"` (never `executable`) needs format 5.

### 3.3 Snapshots

Snapshots stay JSON (encoding `{`). They are few per command (a `vl status`
decodes two), their signature is over the id of their own encoding, and
their ids are what other systems record (change ids),
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
"compare inside" (diff, merge), so the only effect is
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
  below format 5 a tree holding a symlink, a conflict with
  such a term and an annotated tag (`ObjectStore::put` checks the same on
  the value, so engine code cannot write them either). The
  keychain follows the same format: it wraps keys with HPKE only from
  format 3 and refuses to store a format-3 ring below it. Push and pull copy objects with
  `put_raw`, so a format-1 remote or clone can never receive an object an
  older vl could not read: the push fails with "upgrade it with `vl
  upgrade`", and nothing is recorded.
* `fsck` reports a binary tree in a format-1 repository, an AES-SIV object
  or an HPKE ring in a format-1/2 repository, a conflict object or
  conflict entry below format 4, and any format-5 object or view field
  below format 5, as corruption, and a repository format newer than it
  knows. It checks every version a conflict names as it checks a file, a
  symlink's object as a file's (and, when readable, its
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
flags    = bit 0 PRESENT (set) · bit 1 EXECUTABLE · bit 2 SIZE ·
           bit 3 reserved (FALLBACK in formats 7 and earlier; refused) ·
           bits 4–5 tier (as in trees) ·
           bits 6–7 term kind (format 5): 0 file, 1 symlink, 2 and 3
           reserved (`Unsupported`; 2 is never reused); EXECUTABLE clear
           unless a file
```

* A term is what a file entry holds, without the name: each version keeps
  its own id, label and executable bit. The object itself is
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
* **Format 5:** a term may be a symlink (a link/file or link/link
  conflict). Before format 5 bits 6–7 were reserved, so a
  format-4 reader refuses such a term as `Unsupported`; a conflict with one
  needs format 5. Link targets are never merged by line: two different
  targets are a conflict, and a conflict with a link term is never written
  out as a file of markers (a target would become file content).

### 3.7 Symlinks (format 5)

* **Symlink** (`EntryKind::Symlink`, kind byte 1): `id` names the blob of
  the link's *target bytes* (UTF-8, no NUL, at most 4096 bytes; `size` is
  its length), plaintext or sealed exactly like file content under the
  policy of the link's own path. Never executable.
* Kind byte 2 is reserved, never reused: a tree entry holding it is
  `Unsupported` (a removed kind, so a stray old entry is never misread as
  something new).
* A symlink is a leaf: `walk_files` and `diff_trees` list them, `lookup` never
  goes through them, and sync, gc, fsck and `push --dry-run` treat their
  object as a file's (sealed, withheld, listed,
  published by the same rules). fsck warns about a readable target that
  breaks the rules above.
* The builder records a working copy's symlinks as symlink entries
  (their targets, read with `readlinkat`, never followed); checkout writes
  symlinks as symlinks (see ARCHITECTURE §4). A conflict with a symlink
  term is materialised as one side, as it is, never as markers.

### 3.8 Annotated tags (`veil:atag`, format 5)

```text
atag = "veil:atag\n" ‖ canonical JSON, exactly what serde_json writes for
  {"name": tag name, "target": hex snapshot id,
   "kind": "annotated",
   "message": {"plain": text},
   "tagger": text, "timestamp": ms since the epoch,
   "signature"?: {"signer", "key", "sig"}}
```

* Canonical (a re-encoding must give the same bytes) and closed: unknown
  fields are refused. `name` passes the tag-name rules; the message is at
  most 1 MiB, the tagger at most 1 KiB without control characters.
* `signature`: Ed25519 over the atag's unsigned id, context `tag`
  (CRYPTO.md C5). A view's `Tag.annotation` must name an atag of the same
  `name` and `target` (`Atag::verify`): a push refuses a tag whose
  annotation is missing, not an atag, or names another tag or target, and
  a pull receives such a tag without its annotation (with a warning).
* The message is plain text (formats 7 and earlier could seal a cloaked
  tag's message, `{"sealed": envelope}`; format 8 refuses it). Push sends
  an atag only with its tag, after the tag's checks (tags on
  embargo-withheld history stay here, their atags with them).
* gc keeps every atag a retained view names and its target.

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
4. **Rings and embargo records** may only change their `format` together
   with the repository format; readers reject other ones (fail closed: no
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

Decision (until format 8): **existing repositories keep working
read-compatibly.** `vl upgrade` was the explicit opt-in to what a newer
format adds (format 2: binary trees, a faster `vl status`). Format 8 is the
exception, below.

```text
vl upgrade [--dry-run] [--force]
```

1. Checks the repository's format (6 to 8; anything else is refused before
   any lock is taken, so nothing changes) and, below format 8, that it
   holds nothing format 8 removed (see "Format 8"). Then takes the gc
   lease and the repository lock (a dry run takes none and writes nothing)
   and writes the journal `.veil/upgrade.json`.
2. **verify**: the removed-content check again, under the lock, then
   `fsck`, and counts trees by encoding. Any corruption stops the upgrade
   before anything changes (`--force` overrides).
3. No format transition from 6 on rewrites anything: no object, operation
   or id changes.
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
notices a commit point already reached). Old data is never removed. A bare
repository (`vl -R DIR upgrade`) is upgraded structurally, without opening
sealed content.

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
* **Downgrades** are not supported: an older vl refuses a format-2
  repository with a message naming the release it needs.

### Format 8 (only secret files are encrypted)

Owner decision (2026-11-06): **only secret files are ever encrypted**
(`docs/VISIBILITY.md`). Format 8, and refusal (not a decrypting upgrade)
for a repository that holds removed content, were approved by the owner,
2026-11-07. Formats 7 and earlier could also encrypt change
descriptions and attribution, annotated-tag messages, tag names (cloaked
tags), whole lines of work (cloaked workspaces, whose public edits carried
a *fallback* version), embargoed merges (embargo keys, wrapper trees,
signed records) and folders. Format 8 removes all of it.

* **Why a new format.** An older vl reading a format-8 repository would
  write those things into it again (a cloaked workspace, a sealed message)
  and would treat plain embargo records as unknown; and a format-7
  repository may already hold them, which this build cannot read (its
  decoders refuse them) and must never silently treat as plain (a cloaked
  tag read without its `cloak` field would be pushed to a public remote).
  The format number keeps the two apart: an older vl refuses format 8 by
  number, and this vl opens only format 8.
* **`vl upgrade` from 6 or 7.** Nothing is converted: re-writing an object
  that holds encrypted content changes its id, and with it every tree,
  snapshot id and signature above it, the whole history. Instead the
  upgrade checks (`upgrade::removed_content`), structurally and without
  decrypting, every snapshot (an encrypted description, a `cloak` field),
  every annotated tag (a sealed message), every tree reachable from a
  snapshot (embargoed entries, fallback versions, encrypted directories,
  and an encrypted file or conflict side whose path no built-in secret rule
  names, such as a file under a cloaked folder, unless its lineage shows it
  is a secret: its object was a secret's in an earlier snapshot, a parent
  held a secret at that path, or a parent's secret of the same access left
  its path in this snapshot, a renamed secret that format 8 keeps sealed), the view of every retained operation
  (cloaked tags and workspaces, which an undo could bring back) and every
  embargo record (one holding a key). If it finds nothing, the upgrade
  writes `repo.json` and nothing else: every object, operation and id
  stays. If it finds anything, it **refuses before anything is written**
  and names each thing (path, snapshot, tag, workspace or embargo record);
  `--dry-run` lists them and exits 1.
* **A repository that holds removed content** (keys or not) stays at its
  format: this vl does not open it, and an older vl keeps working with it.
  Whoever holds the keys can read it with the vl that wrote it and start a new
  repository from a checkout of the files; the refusal says so. Holding
  the keys does not change the answer: unsealing would still rewrite the
  history.
* **Formats 1 to 5** are no longer read (the owner asked for it on
  2026-11-06; approved by the owner, 2026-11-07): opening, `fsck` and
  `vl upgrade` refuse them, saying to upgrade them to format 7 first with a
  vl from before format 8.
* **Objects of older formats** that an upgraded repository holds (JSON
  trees, legacy sealed objects, legacy key wraps, marker conflicts) are
  still read.

### Format 7 (key rings of ring format 4)

* **Nothing is rewritten** (`6 → 7` has no step): rings keep their format
  until a change needs ring format 4 (an invite, a share by a member, a
  member's removal of their own device, `docs/HUB.md` §13.12), which only
  a format-7 repository stores. `repo.json` gets the new format.
* **Rings name their project** (BUG-845). A ring created in a format-7
  repository that holds a `team` ring names the project in its genesis
  (`project`, the hash of `team`'s genesis), so it is ring format 4 from its
  first change. Rings made before keep their genesis (it is signed): they
  stay readable, and are trusted only where no project anchor is recorded.
  This was added to format 7 and ring format 4 before any release wrote
  them (owner decision, 2026-11-06), so neither version changed; the
  `format-7` fixture set was regenerated with it.
* **Clones of a Veil server project** are made at the newest format. A
  format-6 clone that pulls a ring of format 4 keeps its own ring and warns
  ("vl upgrade"): no keys are lost, it just receives none from shares until
  it is upgraded.
* **Keys per access rule** are not a format change: `cloak rule` is a
  policy word (`policy::RULE_SCOPE`); an older vl reads it as a scope named
  `rule`, holds no key for it, and keeps the file on the device. A project
  sealed with S1's one `team` key moves only through `vl upgrade
  --rule-keys` (admins), which lists every secret and who will hold its key
  first (`docs/HUB.md` §13.12, "Migration").

### Format 6 (the lock-free op log)

* **Steps.** `5 → 6` runs `5->6:op-heads` before the commit point: the
  operation `op_head` names gets its head file in `op_heads/` (harmless to
  format-5 readers, which never look there). After `set-format`,
  `6:remove-op-head` makes sure that head file exists (`op_head` may have
  moved if the upgrade was interrupted between the two steps), removes
  `op_head`, and removes format 5's fixed pull spool `incoming/pull`.
  Nothing else is rewritten: every object, operation, id and signature
  stays.
* **The upgrade race.** A process that opened the repository at format 5
  (an older vl, or this vl started before the upgrade) may commit after
  the commit point, by writing an operation and `op_head`. At format 6 a
  present `op_head` is read as one more head: the next command merges its
  operation in and removes the file. This vl's own format-5 transactions
  re-read `repo.json` under the lock before moving the head, and fail
  ("the repository was upgraded while this command ran") instead.
* **Remotes and clones.** `vl -R <bare repository> upgrade` does the same
  on a bare repository (an old path remote, upgraded structurally: no
  identity, no re-keying). A remote keeps one head, written under its lock, at every
  format. An older vl refuses a format-6 repository or remote outright: it
  would read only `op_head` and silently fork the log. Lock-free pushes and
  pulls work against format-5 remotes (the remote's side is unchanged).

### Format 5 (symlinks, annotated tags)

* **Nothing is rewritten** (`4 → 5` has no step): a format-4 snapshot never
  holds a link (links were never recorded), so every object, operation,
  id and signature stays as it is. `repo.json` gets the new format and
  `min_vl`.
* **Remotes and clones.** A format-4 remote or clone refuses symlink
  trees, link-term conflicts and annotated tags ("upgrade it with
  `vl upgrade`"), and its operation store refuses a view
  naming one; an older vl refuses a format-5 repository or remote outright
  (so it never drops `Tag.annotation` by rewriting a view). The order for
  a team is the usual one.
* **Removed before release (2026-11-05):** format 5 also had a gitlink
  entry and conflict-term kind (kind byte 2, now reserved and never
  reused), a `lightweight-git` atag kind with a `git` origin,
  `View.remote_release_tags` and the `colocated` marker of `repo.json`,
  all for Git interop, which Veil does not have. No repository in use held
  them: a gitlink entry is now `Unsupported` and such an atag corrupt; a
  leftover `remote_release_tags` or `colocated` key is ignored.

### Format 4 (first-class conflicts)

* **Decision: conflicts recorded before the upgrade stay as they are.** A
  format-3 merge wrote markers into the file and listed the path on the
  snapshot; that snapshot keeps its bytes, its id and its signature, and
  its descendants carry the marker conflict as before (it is resolved by
  editing the file). Rewriting them as conflict entries would change every
  snapshot id above them. Merges made after the upgrade record conflict
  entries.
* **Remotes and clones.** A format-3 remote or clone refuses conflict
  objects and trees with conflict entries ("upgrade it with `vl
  upgrade`"): only history that holds an unresolved conflict is
  affected. An older vl refuses a format-4 repository outright ("this
  repository uses format 4, which needs a newer vl"), and a conflict entry
  or object met elsewhere as `Unsupported`.

### Format 3 (standard cryptography)

* **Nothing is re-sealed.** Sealed objects written before the upgrade keep
  the legacy construction, their bytes and their ids; re-sealing would
  change every tree and snapshot id above them and break every signature.
  Unchanged sealed files keep their sealing when re-snapshotted. New and
  changed content is sealed with AES-SIV. For the security review this
  means pre-upgrade history stays under the legacy constructions forever
  (CRYPTO.md §5).
* **Rings.** The upgrading admin's rotation makes each ring format 3. A
  remote or clone at format 2 refuses it (and AES-SIV objects) with "run
  `vl upgrade`". The order for a team is the
  one above: everyone installs this vl, the shared repository is upgraded, one
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
symlinks, public and sealed, a link/file conflict and annotated tags,
written through the engine by `write_format_5_extras` in
`format_compat.rs`; from format 6 also concurrent operations, written last
by `write_format_6_extras`: a merge whose side carries `rewritten` and
`workspace`, and two heads left unmerged): three identities (`home-alice`, `home-bob`, `home-carol`), the
project `alice/` (packed and loose objects, through format 7 a cloaked directory, a ring with
a grant, a revocation and a rotation (key generation 2), a released and an
unreleased embargo, through format 7 a cloaked tag, a vault, gc pending list, pruned ops,
stat cache and checkout state), and its `team-remote/` and
`public-mirror/`. The identity files are test-only keys.

From format 8 on, `alice/` holds no cloaked tag, workspace or directory:
its sealed file is the secret `secrets/.env.notes`, its sealed link
`secrets/.env.current`, its embargoed work an ordinary workspace, and
`upgraded/` is skipped (the format-7 set cannot be upgraded: it holds what
format 8 removed).

`tests/core_format/format_compat.rs` and `crates/vl/tests/cli_basic/upgrade_cli.rs` check that
this build:

* opens, reads (as the admin, a member, a revoked member and an outsider),
  verifies signatures, rings, embargo records and the vault, and `fsck`s
  the format-8 set and its remotes; finds nothing sealed but secret files;
  finds neither the unreleased embargo's fix nor a secret on either remote;
  reads its links, link conflict and annotated tags as each identity's
  audience allows;
* refuses every set before format 8, by opening, `fsck` and `vl upgrade`,
  with what to do, and leaves it byte for byte unchanged: formats 1 to 5
  as no longer read, formats 6 and 7 naming what they hold that format 8
  removed (`--dry-run` lists it);
* upgrades a format-6 or format-7 repository that holds none of it,
  rewriting nothing;
* refuses newer repository formats, object encodings, flag bits, object
  kinds, pack versions, ring and embargo-record formats as `Unsupported`.

Two checks make format changes impossible to miss:

* `every_repository_format_has_a_fixture_set` fails unless every format from
  1 to `REPO_FORMAT` has a fixture set at that format;
* `encodings_match_the_golden_file` pins the bytes of every object encoding
  in `tests/fixtures/encodings.txt` (blob, empty tree, JSON and binary
  trees, root and full snapshots with a signature, sealed, sealed with
  AES-SIV, a conflict object, a binary tree with a conflict entry, a binary
  tree with symlinks, a conflict with symlink terms, a signed annotated
  tag, an operation). Changing what is written fails until the change
  becomes a new format; then new lines are appended
  (`VEIL_BLESS_ENCODINGS=1`), never edited. The lines of encodings only a
  removed feature wrote (the format-7 trees with an embargoed entry and
  fallback, the snapshot with a sealed description, the sealed atag, the
  operations with a cloaked workspace) stay in the file, and must be
  refused; their format-8 replacements end in `-8`.

## 7. Measurements

Release build, Linux, warm cache.

| | format 1 (JSON trees) | format 2 (binary) |
|---|---|---|
| decode the 1,201 trees of the 20k-file layout (`tree_bench`) | 12.40 ms | 0.66 ms |
| their size | 2,449 KiB | 882 KiB |
| `vl status`, unchanged 20k files (`bench_status`, median) | 72–77 ms | 58–59 ms |
| `vl status`, one public file edited | 77–99 ms | 63 ms |
| `vl status`, one sealed file edited | 77–84 ms | 62–69 ms |

The status runs alternate the vl 0.1.0 binary (format 1) and this build
(format 2) on the same machine, two runs each, on tmpfs. A format-1
repository opened by this build decodes its JSON trees as before.

```sh
cargo test --release -p veil-core --test core_bench -- --ignored --nocapture tree_bench::
VL_BENCH_BIN=/path/to/old/vl cargo test --release -p vl --test cli_bench -- --ignored --nocapture bench_status::
```
