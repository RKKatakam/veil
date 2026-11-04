<!-- Written by hand (not generated). crates/vl/tests/json_cli.rs checks that
     every field of every schema is documented here. -->

# JSON output

The read commands take `--json` and then print one JSON document instead of
text:

| Command | Schema |
|---|---|
| [`vl status`](status.md) | [`veil.status/1`](#veilstatus1) |
| [`vl log`](log.md) | [`veil.log/1`](#veillog1) |
| [`vl diff`](diff.md) | [`veil.diff/1`](#veildiff1) |
| [`vl show`](show.md) | [`veil.show/1`](#veilshow1) |
| [`vl workspace list`](workspace.md#vl-workspace-list) | [`veil.workspace.list/1`](#veilworkspacelist1) |
| [`vl tag list`](tag.md#vl-tag-list) | [`veil.tag.list/1`](#veiltaglist1) |
| [`vl op log`](op.md#vl-op-log) | [`veil.op.log/1`](#veiloplog1) |
| [`vl scan`](scan.md) | [`veil.scan/1`](#veilscan1) |
| [`vl secret list`](secret.md#vl-secret-list) | [`veil.secret.list/1`](#veilsecretlist1) |
| [`vl ls`](ls.md) | [`veil.ls/1`](#veills1) |
| [`vl resolve --list`](resolve.md) | [`veil.resolve.list/1`](#veilresolvelist1) |
| [`vl push --dry-run`](push.md) | [`veil.push.plan/1`](#veilpushplan1) |
| [`vl split`](split.md) (a write command) | [`veil.split/1`](#veilsplit1) |
| [`vl squash`](squash.md) (a write command) | [`veil.squash/1`](#veilsquash1) |
| [`vl blame`](blame.md) | [`veil.blame/1`](#veilblame1) |
| [`vl grep`](grep.md) | [`veil.grep/1`](#veilgrep1) |
| any of them, on failure | [`veil.error/1`](#veilerror1) |

```sh
vl status --json | jq -r '.changes[] | "\(.status) \(.path)"'
vl log -n 20 --json | jq -r '.entries[] | select(.empty | not) | .change_short'
vl diff --json | jq '[.files[].content.hunks[].lines[] | select(.kind == "added")] | length'
```

Every other flag of the command works as without `--json` (`vl log -n 5
--json`, `vl diff --from main --stat --json`), and so do the global ones:
like every command, a read command first snapshots the working copy unless
`--no-snapshot` is given.

## Conventions

* **One document per invocation**, on one line of standard output, followed
  by a newline. Nothing else is written to standard output. Warnings,
  progress and errors still go to standard error, as without `--json`.
* **`schema`** is the first field of every document: `veil.<command>/<version>`.
* **Field names** are `snake_case`. Every field documented here is always
  present; a field that has no value is `null`, and a list with no items is
  `[]`. The exceptions are marked *(optional)*: they were added to an
  existing schema for a new feature (renames, the `vl log` filters) and are
  absent, rather than `null`, when that feature does not apply, so documents
  without it are unchanged.
* **Enumerations** are lower-case strings (`added`, `no_key`, …). A consumer
  should treat a value it does not know as "other": new values may be added
  without a version bump.
* **Ids** are full lower-case hex: 64 digits for snapshot and operation ids
  (`snapshot_id`, `op_id`). Change ids (`change_id`, 32 digits) use Veil's
  reverse-hex alphabet `k`–`z`, exactly as the text output shows them and as
  revisions accept them. Wherever the text output shows a short form, the
  JSON has it too, as `…_short` (8 characters).
* **Times** are RFC 3339 in UTC, to the millisecond:
  `2026-11-04T09:24:56.748Z`.
* **Paths** are relative to the repository root, separated by `/`, with no
  leading `./` or `/`.
* **Strings are the raw data.** The text output escapes control characters in
  names, paths, descriptions and file content (`\x1b`); JSON carries them
  unchanged, and any JSON decoder gives back the original string. On the wire,
  besides what JSON itself escapes, DEL, the C1 control characters and the
  Unicode bidirectional overrides are written as `\uXXXX`, so a document
  printed straight to a terminal cannot drive it. Escape strings yourself
  before showing them to a person.

### Versioning

The version in `schema` changes only when a change could break a consumer:

* **Additive changes keep the version**: a new field in an object, a new
  value of an enumeration, a new kind of document.
* **Anything else bumps it** (`veil.status/2`): removing or renaming a field,
  changing its type or whether it can be `null`, or changing what a value
  means.

Ignore fields you do not know, and check `schema` before reading a document.

### Confidentiality

A JSON document never contains anything the text output of the same command
does not show to the same reader:

* Content you cannot decrypt (cloaked for a scope you are not in, withheld by
  a public remote, under an unreleased embargo) is reported as a
  [`redaction`](#redaction): a reason, never the content.
* A description sealed for a scope you are not in is `null`, with a
  [`description_hidden`](#hidden-description) that names the scope.
* Isolated files (`.env`, …) are listed by path in `vl status`; their
  content is never recorded, so it is never in any document.
* `vl secret list --json` lists secret **names**; values are never read into
  the result. `vl scan --json` gives the scanner's redacted excerpt (the
  first four characters and a length), as the text does.

### Exit status and errors

The exit status is the same with and without `--json`: 0 on success, 1 on
failure, and 1 from `vl scan` when a public file contains a secret (its
document is printed all the same, with `clean: false`).

When a command fails, `error: …` goes to standard error as always and, with
`--json`, a [`veil.error/1`](#veilerror1) document goes to standard output,
so a script that reads standard output always gets one document. Two
exceptions:

* **Usage errors** (an unknown flag, a missing argument) are reported by the
  argument parser before `vl` knows `--json` was asked for: text on standard
  error, exit status 2, nothing on standard output.
* If the command had already printed its document when a later step failed
  (finishing the working-copy checkout), no second document is printed:
  standard error and the exit status tell.

## Common objects

Objects that several documents share.

### Snapshot reference

A snapshot as the text shows it on one line (`kxqpvmkk ee720280 Add the
README`): in `status`, `show` (`parents`), `workspace list`, `tag list`.

| Field | Type | Meaning |
|---|---|---|
| `snapshot_id` | string | Snapshot id, 64 hex digits |
| `snapshot_short` | string | Its first 8 digits |
| `change_id` | string or null | The change id (reverse hex); null if the snapshot is not `available` |
| `change_short` | string or null | Its first 8 characters |
| `available` | bool | False when this repository cannot read the snapshot (withheld by an unreleased embargo on a public clone, or removed by `vl gc`): only its id is known, and every other field is null or false |
| `empty` | bool | The change makes no changes of its own (`(empty)`) |
| `description` | string or null | The full description (`""` if none is set); null if it is sealed for a scope you are not in |
| `description_hidden` | [hidden description](#hidden-description) or null | Why `description` is null |

### Hidden description

A description sealed for a scope you are not in (the text shows
`[cloaked:team]`).

| Field | Type | Meaning |
|---|---|---|
| `scope` | string | The scope it is sealed for |
| `reason` | string | `no_key` |

### Visibility

Who can read a file: the `visibility` of a change or diff entry.

| Field | Type | Meaning |
|---|---|---|
| `kind` | string | `public`, `cloaked` or `embargoed` |
| `scope` | string or null | The scope of a `cloaked` file |
| `embargo` | string or null | The embargo id of an `embargoed` file |

### Redaction

Content this reader cannot see, and why. It never carries the content.

| Field | Type | Meaning |
|---|---|---|
| `reason` | string | `no_key`: cloaked for a scope you hold no key for; `withheld`: a public remote never delivered it; `not_released`: under an embargo not released yet; `unwritable` (`status` only): readable, but this filesystem could not hold the file; `missing`: a public object absent from the store (damage, not a redaction: run `vl fsck`); `error`: the store could not read it |
| `message` | string | The explanation the text output prints (`cloaked:team; no key`) |

### Signature

| Field | Type | Meaning |
|---|---|---|
| `status` | string | `good` (by a known member), `unknown` (valid, but by a key no key ring knows), `bad` (does not match the snapshot) or `unsigned` |
| `signer` | string or null | The member's name, for `good`. It differs from the author when someone else rewrote the snapshot (a rebase) |
| `key` | string or null | The signing public key, in hex; null if unsigned |
| `key_short` | string or null | Its first 16 digits, as `vl show` prints them |

### Change

A changed path, as `vl status` lists it.

| Field | Type | Meaning |
|---|---|---|
| `path` | string | The file (for a rename or copy: its new path) |
| `status` | string | `added`, `deleted`, `modified`, `renamed` or `copied` (`R old -> new` and `C old -> new` in the text; `R087` with the score in `vl diff --stat`) |
| `from` | string *(optional)* | Renamed or copied: the path it came from |
| `score` | number *(optional)* | Renamed or copied: the similarity in percent (100 for an exact move) |
| `visibility` | [visibility](#visibility) | Of the new version (of the old one, for a deletion) |
| `redacted` | bool | The new version is unreadable here |
| `tier` | string | Its [tier](#tier) for this reader: `public`, `cloaked`, `embargoed` or `redacted` (`[redacted]` in the text, followed by the label of whom it is sealed for) |
| `conflict` | [conflict](#conflict) or null | The new version is an unresolved conflict (`[conflict]` in the text); `visibility` and `tier` are then those of the file with markers you are shown |
| `kind` | string | What the new version is (the old one for a deletion): `file`, `symlink`, `gitlink` (repository format 5) or `conflict` |
| `old_kind` | string or null | The old version's kind when a modification changed it, e.g. a file replaced by a symlink (`T path (file → symlink)` in the text); null otherwise |

### Conflict

An unresolved conflict recorded as data (repository format 4): the versions
of a file a merge could not combine. It never carries content. Null for a
file, and for a conflict recorded as markers in the file (older formats,
merges under an embargo), which is resolved by editing the file.

| Field | Type | Meaning |
|---|---|---|
| `sides` | number | Versions being combined (2 for an ordinary conflict) |
| `bases` | number | Base versions (1 for an ordinary conflict) |
| `versions` | array | Every version, sides and bases interleaved (side 1, base 1, side 2, …): `role` (`side` or `base`), `number` (1-based, per role), `visibility` ([visibility](#visibility) or null: null when this version has no file, i.e. added on one side only, or deleted) and `readable` (bool: you can read it) |
| `redacted` | bool | Some version is not shown in the file you are shown: sealed for another audience than that file's, or unreadable here |
| `unreadable_side` | bool | A side cannot be read here: you cannot resolve it (your edits of it are held back) |

### Tier

Where a file stands, for this reader, as `vl ls` shows it and `vl status`
marks it (`[cloaked:team]`; public files carry no mark):

| Tier | Meaning |
|---|---|
| `public` | Plaintext, sent to every remote (also a file of a released embargo) |
| `cloaked` | Encrypted for a scope you are in (`scope` names it); team remotes get the ciphertext, public remotes nothing |
| `embargoed` | Under an unreleased embargo whose key you hold (`embargo` names it) |
| `redacted` | Recorded, but sealed for someone else or withheld from this repository: you cannot read it (a [redaction](#redaction) says why) |
| `isolated` | Local only: never snapshotted, never pushed |
| `quarantined` | Kept out of the snapshot because it looks like it contains a secret |
| `ignored` | Not tracked at all |

### File diff

One file of `vl diff` and `vl show`.

| Field | Type | Meaning |
|---|---|---|
| `path` | string | The file (for a rename or copy: its new path) |
| `status` | string | `added`, `deleted`, `modified`, `renamed` or `copied` |
| `from` | string *(optional)* | Renamed or copied: the path it came from; `old` is that file's version |
| `score` | number *(optional)* | Renamed or copied: the similarity in percent |
| `old`, `new` | entry or null | The two versions; `old` is null for an added file, `new` for a deleted one |
| `content` | object or null | The changed lines; null with `--stat` |

An entry (`old`, `new`):

| Field | Type | Meaning |
|---|---|---|
| `visibility` | [visibility](#visibility) | Who can read this version |
| `executable` | bool | The executable bit |
| `mode` | string | `100644` or `100755`, as Git writes it; `120000` for a symlink and `160000` for a gitlink (repository format 5) |
| `readable` | bool | This reader can materialise this version (for an embargoed file: its pre-merge fallback counts) |
| `conflict` | [conflict](#conflict) or null | This version is an unresolved conflict; its content (and `visibility`, `executable`, `readable`) is that of the file with markers you are shown (`unresolved conflict` in the text) |
| `kind` | string | `file`, `symlink`, `gitlink` (repository format 5) or `conflict` |
| `target` | string or null | A symlink's target (`symlink PATH -> TARGET` in the text, escaped), when you can read it; null for a link sealed for someone else (its target is content) and for anything but a symlink. A symlink's `content` is the diff of its target |

`content`:

| Field | Type | Meaning |
|---|---|---|
| `binary` | bool | Either version is binary: no `hunks` (the text says `binary content differs`) |
| `hidden` | [redaction](#redaction) or null | Either version is unreadable here: no `hunks`, and why |
| `hunks` | array of hunks | The unified diff, 3 lines of context |

A hunk:

| Field | Type | Meaning |
|---|---|---|
| `old_start`, `old_lines` | number | The lines of the old version it covers (start counts from 1; 0 for an empty file) |
| `new_start`, `new_lines` | number | The same, in the new version |
| `lines` | array of lines | In order |

A line:

| Field | Type | Meaning |
|---|---|---|
| `kind` | string | `context`, `added` or `removed` |
| `text` | string | The line without its line break (a `\r` before it is kept) |
| `newline` | bool | False only for a last line that has no line break (`\ No newline at end of file`) |

## `veil.status/1`

`vl status --json`: the working-copy change and what the snapshot taken by
this command found.

```json
{"schema":"veil.status/1","workspace":{"name":"default","cloak":null},
 "working_copy":{"snapshot_id":"ee72…02c8","snapshot_short":"ee720280","change_id":"kxqp…slxt","change_short":"kxqpvmkk","available":true,"empty":false,"description":"","description_hidden":null},
 "parents":[{"snapshot_id":"37cd…e8f2","snapshot_short":"37cdc51f","change_id":"pqmv…ynro","change_short":"pqmvvlvm","available":true,"empty":false,"description":"Add the README","description_hidden":null}],
 "changes":[{"path":"README.md","status":"modified","visibility":{"kind":"public","scope":null,"embargo":null},"redacted":false,"tier":"public"}],
 "isolated":[".env"],"quarantined":[],"policy_held_back":[],"nested":[],"redacted":[],"conflicts":[]}
```

(Wrapped and shortened here; the real document is one line.)

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `veil.status/1` |
| `workspace` | object | The workspace the project directory is attached to: `name` (string) and `cloak` (string or null: the scope everything recorded in it is cloaked under) |
| `working_copy` | [snapshot reference](#snapshot-reference) | The working-copy change, `@` |
| `parents` | array of [snapshot references](#snapshot-reference) | Its parents (two or more for a merge) |
| `changes` | array of [changes](#change) | What `@` changes, compared with its parents |
| `isolated` | array of strings | Local-only files (isolated): never snapshotted or pushed. Their [tier](#tier) is `isolated` |
| `quarantined` | array | Public files kept out of the snapshot because they look like they contain a secret: `path`; `rule` (string: the first scanner rule that matched) and `line` (number: where); `state`: `never_recorded`, or `held_back` (an edit of a file history already has; history keeps the previous version); `tier`: always `quarantined` |
| `policy_held_back` | array | Local paths that keep the protection you accepted because `.veilpolicy` would weaken it (`vl policy accept` applies it): `path` (with a trailing `/` for a directory), `dir` (bool: a directory held back as a whole), `accepted` and `wanted` (strings: policy keywords such as `isolate`, `cloak ops`, `public!`), `tier` (the [tier](#tier) the accepted classification gives it: `isolated`, `ignored`, `cloaked` or `public`) and `scope` (string or null: of `cloaked`) |
| `nested` | array of strings | Directories that are repositories of their own; nothing in them is recorded here |
| `redacted` | array | Files of `@` that are absent on disk because you cannot read them: `path`, `redaction` (a [redaction](#redaction)) and `tier` (`redacted`, or for `unwritable` the file's own [tier](#tier)) |
| `conflicts` | array | Unresolved conflicts: `path`, `recorded_on` (string or null: the short change id of the parent, a merge, that recorded it with the same version; null if recorded on `@` itself) and `conflict` (a [conflict](#conflict), or null for markers in the file) |

## `veil.log/1`

`vl log --json`: the snapshot graph, children before parents and newest
first among unrelated snapshots, as the text draws it. `-n` limits it.

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `veil.log/1` |
| `entries` | array of entries | The snapshots, in log order |
| `truncated` | bool | `-n` cut the log short (the text prints `(more snapshots elided)`) |

An entry:

| Field | Type | Meaning |
|---|---|---|
| `snapshot_id`, `snapshot_short` | string | The snapshot id and its short form |
| `change_id`, `change_short` | string | The change id and its short form |
| `root` | bool | The universal root, `root()`: its `author`, `timestamp` and `signature` are null |
| `current` | bool | The working copy of the current workspace (`@`) |
| `author` | string or null | Who made the change |
| `timestamp` | string or null | When this snapshot was made |
| `signature` | [signature](#signature) or null | Its signature |
| `workspaces` | array of strings | Workspaces whose working copy this is (`name@` in the text) |
| `tags` | array | Local tags pointing here: `name`, and `cloak` (string or null: the scope of a cloaked tag, never pushed to public remotes) |
| `remote_tags` | array of strings | Tags last seen on a remote, as `remote/tag` |
| `empty` | bool | The change makes no changes of its own |
| `conflicts` | array of strings | Paths that still have conflict markers (`×` and `(conflict)` in the text) |
| `cloak` | string or null | The scope of a snapshot on a cloaked line of work |
| `embargo` | object or null | The embargo this merge introduced: `id` (string) and `released` (bool) |
| `description` | string or null | The full description; null if sealed for a scope you are not in |
| `description_hidden` | [hidden description](#hidden-description) or null | Why `description` is null |
| `parents` | array | The parents, first parent first: `snapshot_id`, `snapshot_short`, `change_short` (string or null) and `withheld` (bool: the parent is not in this repository, as with an unreleased embargo on a public clone; its `change_short` is then null) |
| `files` | array of strings *(optional)* | With `-S` or `-G`: the files that matched (every changed file with `--pickaxe-all`) |
| `not_searched` | array of [visibilities](#visibility) *(optional)* | With `--show-skipped`: this snapshot was not searched, because the versions `-S`/`-G` would read are sealed for these audiences |

With a filter (paths, `-r` excepted, `--author`, `--signed-by`, `-S`,
`-G`), the document has *(optional)* `search`: `searched` (number:
snapshots looked at), `skipped` (number: snapshots not searched because
what they change is sealed for you; listed in `entries` only with
`--show-skipped`) and `stopped` (bool: `--max-changes` ended the search).
`truncated` then means that `-n` stopped the search with snapshots left.

## `veil.diff/1`

`vl diff --json`, with `-r`, `--from`, `--to` and `--stat` as without it.

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `veil.diff/1` |
| `stat` | bool | `--stat` was given: every file's `content` is null |
| `files` | array of [file diffs](#file-diff) | The changed files, in path order |
| `renames_skipped` | bool *(optional)* | Present (and true) when inexact rename detection was skipped because of its limits (too many files): only exact renames are listed |

## `veil.show/1`

`vl show --json`: a snapshot's metadata and its diff against its parents.

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `veil.show/1` |
| `snapshot_id`, `snapshot_short` | string | The snapshot id and its short form |
| `change_id`, `change_short` | string | The change id and its short form |
| `root` | bool | The universal root (no signature) |
| `author` | string | Who made the change (empty for the root) |
| `timestamp` | string or null | When this snapshot was made |
| `signature` | [signature](#signature) or null | Its signature; null for the root |
| `parents` | array of [snapshot references](#snapshot-reference) | Its parents (the text lists them only for a merge) |
| `tags` | array of strings | Local tags pointing here |
| `cloak` | string or null | The scope of a snapshot on a cloaked line of work |
| `embargo` | object or null | The embargo this merge introduced: `id` (string); `state`: `pending`, `staged` (released here, not pushed yet), `released` or `unknown` (no record of it here); `until` (string or null: when a `pending` embargo is released automatically; null for a manual release) |
| `conflicts` | array of strings | Paths that still have conflict markers |
| `description` | string or null | The full description; null if sealed for a scope you are not in |
| `description_hidden` | [hidden description](#hidden-description) or null | Why `description` is null |
| `diff` | object | The snapshot's changes: `stat` (bool) and `files` (array of [file diffs](#file-diff)), as in [`veil.diff/1`](#veildiff1) |

## `veil.workspace.list/1`

`vl workspace list --json` (`vl ws list --json`).

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `veil.workspace.list/1` |
| `workspaces` | array | By name: `name`; `current` (bool: the project directory is attached to it); `cloak` (string or null); `working_copy` (a [snapshot reference](#snapshot-reference)) |

## `veil.tag.list/1`

`vl tag list --json`.

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `veil.tag.list/1` |
| `tags` | array | Local tags, by name: `name`; `cloak` (string or null: never pushed to public remotes); `target` (a [snapshot reference](#snapshot-reference)) |
| `remote_tags` | array | Tags as last seen on remotes: `name` (`remote/tag`) and `target` |

## `veil.op.log/1`

`vl op log --json`: the operation log, newest first; `-n` (default 20)
limits it.

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `veil.op.log/1` |
| `operations` | array | `op_id` and `op_short` (string: pass either to `vl op restore`); `timestamp`; `user`; `description` (what the operation did) |

## `veil.scan/1`

`vl scan --json`, and the CI gate `vl scan --policy-from FILE --json`.

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `veil.scan/1` |
| `mode` | string | `working_copy` (the repository's own policy), or `gate` (`--policy-from`: every file counts as public) |
| `policy_from` | string or null | The gate's trusted policy file, as given |
| `nested` | array of strings | Nested repositories, not scanned (`working_copy` only) |
| `files` | array | Files that contain secrets, or could not be read (`gate` only), in path order: `path`; `tier` (`public`, `cloaked`, `isolated`, or in a gate also `ignored`: the policy tier) and `scope` (string or null: of a cloaked tier); `protected` (bool: its tier keeps the secret out of public history; always false in a gate, as a Git checkout publishes every file); `findings` (array: `line`, `rule`, and `excerpt`, the scanner's redacted excerpt, never the secret); `error` (string or null: why the file could not be read, in a gate; it then has no findings and counts as exposed) |
| `exposed` | number | Files that would publish a secret (in a gate, unreadable files too) |
| `protected` | number | Cloaked or isolated files that contain secrets (`working_copy` only) |
| `clean` | bool | Nothing is exposed. False makes `vl scan` exit 1 |

## `veil.secret.list/1`

`vl secret list --json`: the names in this repository's local vault. Values
are never part of the document; `vl secret get NAME` prints one.

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `veil.secret.list/1` |
| `secrets` | array | By name: `name` (the environment variable `vl run` sets) |

`vl secret list --scope S --json` lists the live names of scope `S`'s team
vault (still never values). The document and its items gain these fields;
the local vault's document has none of them:

| Field | Type | Meaning |
|---|---|---|
| `scope` | string | The scope |
| `exposed_to` | object | Only with `--exposed-to`, which then keeps just the names that member could read: `member_id`; `name` (in the scope's ring); `current` (bool: still a member, so every entry is readable to them) |
| `secrets[].set_by` | string | Name, in the scope's ring, of the member who last set it |
| `secrets[].set_by_id` | string | Their member id |
| `secrets[].timestamp` | string | When (RFC 3339, UTC, the writer's clock) |
| `secrets[].timestamp_ms` | number | The same, in milliseconds since the epoch |
| `secrets[].generation` | number | Key generation the value is sealed under |
| `secrets[].stale_generation` | bool | Sealed under an old generation, after a revocation, by a writer whose key ring was out of date: the revoked member can read it. Set it again |

## `veil.ls/1`

`vl ls --json`: the files of a snapshot with their [tier](#tier), and for
the working copy its local-only files.

```json
{"schema":"veil.ls/1","snapshot":{"snapshot_id":"ee72…02c8","snapshot_short":"ee720280",…},"working_copy":true,"all":false,
 "entries":[{"path":".env","dir":false,"tier":"isolated","scope":null,"embargo":null,"recorded":false,"visibility":null,"size":21,"executable":false,"readable":true,"fallback":false,"redaction":null,"quarantine":null},
            {"path":"ops/keys.yml","dir":false,"tier":"redacted","scope":"ops","embargo":null,"recorded":true,"visibility":{"kind":"cloaked","scope":"ops","embargo":null},"size":310,"executable":false,"readable":false,"fallback":false,"redaction":{"reason":"no_key","message":"cloaked:ops; no key"},"quarantine":null}]}
```

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `veil.ls/1` |
| `snapshot` | [snapshot reference](#snapshot-reference) | The snapshot listed (`-r`, default `@`) |
| `working_copy` | bool | It is the working copy, just snapshotted: local-only files are listed too (false with `--no-snapshot`) |
| `all` | bool | `--all`: ignored paths are listed |
| `entries` | array | In tree order (depth first, by name within a directory), each: |
| `path` | string | The file (an ignored directory: the directory) |
| `dir` | bool | An ignored directory, listed as a whole (`--all`; never descended into) |
| `tier` | string | Its [tier](#tier): `public`, `cloaked`, `embargoed`, `redacted`, `isolated`, `quarantined` or `ignored` |
| `scope` | string or null | The scope of a cloaked file (also when `redacted`) |
| `embargo` | string or null | The embargo of an embargoed file (also when `redacted`) |
| `recorded` | bool | In the snapshot; false for local-only files |
| `visibility` | [visibility](#visibility) or null | The recorded entry's label; null when not recorded |
| `size` | number or null | Bytes: the recorded size, or the size on disk of a local-only file; null for a directory |
| `executable` | bool | The executable bit (`*` in the text) |
| `readable` | bool | You can read the content (for a local-only file: it is on disk) |
| `fallback` | bool | What you can read is the file's last public version: it was edited on a cloaked line of a scope you are not in |
| `redaction` | [redaction](#redaction) or null | Why a `redacted` file cannot be read. Never content |
| `quarantine` | object or null | A `quarantined` file: `rule` (string), `line` (number) and `state` (`never_recorded`, or `held_back`: history keeps the previous, recorded version) |
| `conflict` | [conflict](#conflict) or null | An unresolved conflict (`conflict: 2 sides` in the text); `tier`, `scope`, `visibility`, `size` and `executable` are those of the file with markers you are shown, `readable` says whether you can read every side |
| `kind` | string | `file`, `symlink`, `gitlink` (repository format 5) or `conflict` |
| `target` | string or null | A symlink's target (`PATH -> TARGET` in the text, escaped), when you can read it; null for a redacted link (its target is sealed content), a local-only link, and anything but a symlink. `size` is the target's length |

## `veil.resolve.list/1`

`vl resolve --list --json` (also `vl resolve --json`): the unresolved
conflicts of a snapshot (`-r`, default `@`).

```json
{"schema":"veil.resolve.list/1","snapshot":{"snapshot_id":"ee72…02c8",…},
 "conflicts":[{"path":"src/app.rs","conflict":{"sides":2,"bases":1,"versions":[{"role":"side","number":1,"visibility":{"kind":"public","scope":null,"embargo":null},"readable":true},…],"redacted":false,"unreadable_side":false}}]}
```

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `veil.resolve.list/1` |
| `snapshot` | [snapshot reference](#snapshot-reference) | The snapshot listed |
| `conflicts` | array | In path order: `path`, and `conflict` (a [conflict](#conflict); null for a conflict recorded as markers in the file, or a file moved aside by a file/directory conflict) |

## `veil.push.plan/1`

`vl push --dry-run [REMOTE] --json`: what a push would send, per remote
(every configured remote when none is named). Nothing is written to any
remote. The objects and tags listed are exactly what the push then sends,
unless someone else pushes in between.

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `veil.push.plan/1` |
| `remotes` | array | One plan per remote, by name: |
| `name` | string | The remote |
| `url` | string | Its URL, as configured |
| `public` | bool | A public remote: no cloaked content, cloaked tags or key rings |
| `error` | string or null | This remote could not be planned (unreachable, not a repository, a tag that builds on withheld history): the push would fail the same way. The other fields are then empty |
| `creates_remote` | bool | Nothing is there yet: the push would create the repository |
| `tags` | array | Each tag the push considers, by name: `name`; `action` (`create`, `update`, `unchanged`, `rejected`: the remote diverged and `--force` was not given, or `skipped`: held back by design, such as a cloaked tag on a public remote or a tag that would publish an unreleased embargo's history); `target` and `target_short` (the local target); `remote_target` (string or null: where the remote's tag is now); `message` (string or null: why it is rejected or skipped); `cloak` (string or null: the scope of a cloaked tag) |
| `snapshots` | number | Snapshots that would be sent |
| `objects` | number | Objects that would be sent, snapshots included |
| `trees` | number | Of which directory trees |
| `blobs` | number | Of which plaintext file contents |
| `sealed` | number | Of which ciphertext (cloaked or embargoed content, sealed trees) |
| `object_bytes` | number | Size of those objects before packing |
| `pack_bytes` | number | Size of the pack(s) the push would write: compressed, with deltas (what crosses the wire) |
| `snapshot_ids` | array of strings | The snapshots, in hex |
| `object_ids` | array of strings | Every object, in hex, in the order it would be sent |
| `withheld_objects` | number | Objects the visibility filter holds back (cloaked or embargoed content, on a public remote) |
| `withheld_snapshots` | array | History that stays here: snapshots reachable from the pushed tags only through an unreleased embargo (`snapshot_id`, `snapshot_short`, and `embargo`). Sent once the embargo is released |
| `releases` | array of strings | Embargoes whose staged release this push would publish (`vl embargo release`): afterwards it cannot be taken back |
| `files` | object or null | Public remotes only (null for a team remote): `published`, `withheld`, `embargoed_trees`, below |
| `published` | array | Each file whose content becomes public on this remote, by path: `path`; `exposure` (`new`: the path was never public there; `exposed`: it was there but withheld, cloaked or embargoed, until now; `modified`: already public there, new content); `size` (number or null: unknown for the last public version of a file edited on a cloaked line); `released_embargo` (string or null: public because this embargo was released) |
| `withheld` | array | Each file of the pushed history whose new content stays withheld: `path`; `reason` (`cloaked`: public remotes never receive it; `cloaked_edit`: edited on a cloaked line, the remote keeps its last public version; `embargoed`: under an unreleased embargo, the remote shows the pre-merge version); `scope` and `embargo` (strings or null); `message` (what the text prints) |
| `embargoed_trees` | array | Snapshots whose tree is under an unreleased embargo you hold no key for (`snapshot_id`, `snapshot_short`, `embargo`): the remote sees their pre-merge tree, and the files the embargo changes cannot be listed |
| `warnings` | array of strings | What the push would warn about |

The exit status is 1 where the push would fail: a remote that cannot be
planned, a tag the remote would reject, or a tag named with `-t` that
would be held back.

## `veil.split/1`

`vl split … --json`: the change was split, as one operation (`vl undo`
takes it back). Also the result of the `split` method of
[`vl serve --local`](json-rpc.md).

```json
{"schema":"veil.split/1","first":{"snapshot_id":"ebef…","change_short":"vulponvr","description":"part one",…},
 "second":{"snapshot_id":"4985…","change_short":"xzolylpw",…},
 "chosen":[{"path":"src/config.rs","whole":false,"hunks":["1","3.2"]},{"path":"README.md","whole":true,"hunks":[]}],
 "operation":{"op_id":"9135…","op_short":"9135cd1c"}}
```

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `veil.split/1` |
| `first` | [snapshot reference](#snapshot-reference) | The new change holding what was chosen, on the original's parents (a new change id) |
| `second` | [snapshot reference](#snapshot-reference) | The change that was split, now holding the rest, on top of `first`: the same change id and description, and exactly the same files as before |
| `chosen` | array | What went into `first`, in `vl diff` order: `path`; `whole` (bool: the file's whole change, or a file that can only move whole); `hunks` (array of strings, empty when `whole`: `"N"` for hunk N as `vl diff --json` lists it, from 1, `"N.M"` for the M-th edit of hunk N, `"mode"` for the executable-bit change) |
| `operation` | object | The head of the operation log afterwards: `op_id`, `op_short` |

**Choosing without a terminal.** `--hunks PATH:LIST` names hunks as in
`hunks` above (`src/config.rs:1,3.2,mode`); `--plan FILE` (`-` for standard
input) takes a plan document, whose paths are relative to the repository
root:

```json
{"schema":"veil.plan/1","files":[{"path":"src/config.rs","hunks":[1,"3.2"]},{"path":"docs"}]}
```

`schema` is optional; `files` lists `path` (a file, or a directory for
everything under it) and `hunks` (numbers or strings as above; leave it
out for the whole file). Unknown fields are refused. A path, hunk or edit
the change does not have is an error, so nothing is ever split differently
from what was asked.

## `veil.squash/1`

`vl squash … --json`: what moved, as one operation. Also the result of the
`squash` method of [`vl serve --local`](json-rpc.md).

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `veil.squash/1` |
| `destination` | [snapshot reference](#snapshot-reference) | The destination (the parent, or `--into`) with what moved |
| `source` | [snapshot reference](#snapshot-reference) or null | The source with what stayed (its change id and description); null when everything moved and it was abandoned |
| `source_abandoned` | bool | Everything moved: the source was abandoned and its description joined to the destination's |
| `moved` | array | What moved, as `chosen` in [`veil.split/1`](#veilsplit1) (every changed file, `whole`, for a squash of the whole change) |
| `operation` | object | The head of the operation log afterwards: `op_id`, `op_short` |

## `veil.blame/1`

`vl blame --json` (also `vl annotate`): who introduced each line of a file,
reading every version as you may see it. A version you cannot read is never
guessed through: lines whose history is sealed for you are unattributed.

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `veil.blame/1` |
| `path` | string | The file |
| `rev` | [snapshot reference](#snapshot-reference) | The snapshot whose version is annotated (`-r`) |
| `version` | string | `plain`, or `fallback`: you cannot read the file at `rev`, and its last public version (what your checkout shows) is annotated |
| `public` | bool | `--public`: annotated as a public mirror sees the history |
| `coarse` | bool | Some two versions differed too much to compare line by line: their differing middle is attributed whole |
| `stopped` | string or null | `max_changes` (`--max-changes` was reached) or `budget` (the work budget was spent); null when the walk finished |
| `visited` | number | Snapshot visits of the walk |
| `unattributed` | number | Lines with no change |
| `lines` | array of lines | One per line (of `-L START,END` only, if given) |
| `changes` | array of [snapshot references](#snapshot-reference) | Every change a line is attributed to, once, newest first (descriptions sealed for you are hidden, as everywhere) |

A line:

| Field | Type | Meaning |
|---|---|---|
| `line` | number | Its number, from 1 |
| `text` | string | The line, without its line break |
| `change`, `change_short` | string or null | The change that introduced it |
| `snapshot` | string or null | That change's snapshot id |
| `path` | string or null | The file's path there (another name with `--follow`) |
| `author` | string or null | That change's author: a claim, written by whoever made the snapshot |
| `timestamp` | string or null | When that snapshot was made |
| `unattributed` | object or null | Why there is no change: `reason` (`sealed`: the history it would move into is sealed for you; `max_changes`; `budget`) and `sealed_for` ([visibility](#visibility) or null: with `sealed`, for whom) |

## `veil.grep/1`

`vl grep --json`: the matches of a pattern in the files of a snapshot
(`-r`, default `@`, which the command snapshots first). It never searches
the working copy's local-only files (isolated, quarantined, ignored): they
are in no snapshot, and are not counted either. `-l`, `-c` and `-n` change
the text only; the document always lists every match.

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `veil.grep/1` |
| `rev` | [snapshot reference](#snapshot-reference) | The snapshot searched |
| `matches` | array | Every matching line, by path then line: `path`, `line` (number, from 1), `text` (the line without its break, cut at 1 MiB), `truncated` (bool: it was cut) and `tier` (below) |
| `files` | array | Every file with a match: `path`, `tier`, `scope` (string or null: of a cloaked file, or the embargo of an embargoed one), `count` (number: matching lines, up to `--max-count`), `binary` (bool: its lines are not listed unless `-a`) and `conflict` (bool: an unresolved conflict, searched as the file with markers you are shown) |
| `skipped` | object | What was not searched: `sealed` (files you cannot read and have no public version of), `binary` (binary files that matched, lines not listed), `too_large` (files over 256 MiB) |
| `searched` | number | Files of the snapshot considered |

`tier` is `public`, `cloaked` or `embargoed` (sealed, and you hold the
key), or `fallback`: the last public version of a file you cannot read.
Members see newer content there.

The exit status is 0 when something matched and 1 when nothing did, with
the document printed either way.

## `veil.error/1`

Printed instead of a command's document when it fails (see
[Exit status and errors](#exit-status-and-errors)).

```json
{"schema":"veil.error/1","error":{"message":"revision 'nosuch' not found","hint":null}}
```

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `veil.error/1` |
| `error` | object | `message` (string: what standard error shows after `error:`, unescaped) and `hint` (string or null: the `hint:` that follows it, if any) |

---

[All commands](README.md) · [User guide](../guide/README.md)
