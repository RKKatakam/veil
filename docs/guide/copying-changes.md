# Copying changes, and merges that follow renames

> Where this page mentions cloaking, scopes or isolated files, the server replaces them with folder access and encrypted secrets (see [OVERVIEW.md](../OVERVIEW.md) and [VISIBILITY.md](../VISIBILITY.md)). `vl` syncs only through the Veil server.

`vl duplicate` copies changes onto other parents, as new changes;
`vl cherry-pick` is its Git-style shortcut. Merges, rebases and copies
**follow renames**: when one side moved a file and the other edited it, the
edit lands at the new name instead of becoming a conflict.

The example: `main` holds `src/price.rs`. A fix of the tax rate was made on
a release line (`taxfix`), and meanwhile `main` moved the file to
`src/billing/price.rs`.

## `vl cherry-pick`: copy a change onto `@-`

```text
$ vl cherry-pick taxfix
Duplicated xwwzlqxw bac18750 Fix the tax rate
        as oxkszzzm bc84dfc8 Fix the tax rate
  rename: followed rename src/price.rs -> src/billing/price.rs
Moved main to the last copy
Updated 1 files, removed 0
Working copy now at: ooqsypoz 499dc7d0 (empty) (no description set)
$ vl log -n 4
@  ooqsypoz alice ✓ 2026-11-04 21:00:53 default@ 499dc7d0 (empty)
│  (no description set)
○  oxkszzzm alice ✓ 2026-11-04 21:00:53 main bc84dfc8
│  Fix the tax rate
○  lnwymrxv alice ✓ 2026-11-04 21:00:53 266d58a2
│  Move pricing into billing
│ ○  xwwzlqxw alice ✓ 2026-11-04 21:00:53 taxfix bac18750
│ │  Fix the tax rate
~  (more snapshots elided)
```

`vl cherry-pick REV…` is `vl duplicate REV… -d @-`, then `@` moves on top
of the copy, keeping what you had changed in it. As in Git:

- several revisions (or a range, `vl cherry-pick A..B`) are copied **one
  after the other**, oldest first, each onto the previous copy;
- the tags at `@-` move to the last copy, as `vl commit` moves them (not on
  a cloaked line, unless the tag is cloaked for that scope; never a release
  tag);
- a copy that conflicts is not refused: the conflict is recorded in the copy
  ([Conflicts](getting-started.md#conflicts)), and `vl resolve` clears it.

## `vl duplicate`: copy changes anywhere

```text
vl duplicate REV… [-d DEST…] [-m MSG | --keep-description] [-x] [--json]
```

- Each copy is a **new change** (a new change id), with the source's author
  and description and the time of the copy. You sign it: `vl log` shows the
  original author and your signature, never the original signer's.
- Without `-d`, each copy sits beside its source, on the same parents (as
  Jujutsu's `jj duplicate`). With `-d DEST` (repeat it for a merge), the
  copies go there.
- Copying a chain copies a chain: a source whose parent is also copied goes
  onto that parent's copy.
- The copy applies what the source changed relative to its own parents
  (the merge of them, for a merge), so a copy of a merge works too.
- `-m MSG` replaces the descriptions; `-x` appends
  `(duplicated from change ID)` to a plain description.
- One operation: `vl undo` removes every copy (and, for cherry-pick, puts
  `@` and the tags back).

`--json` prints `veil.duplicate/1` ([reference](../reference/json.md#veilduplicate1)):
the ids of each source and copy, its conflicts and the renames it followed,
never a description.

## Merges and rebases follow renames

`vl merge`, `vl rebase`, the automatic rebase of descendants, `vl
cherry-pick` and `vl duplicate` detect renames between the merge base and
each side, with the detection `vl diff` uses (exact renames, then files at
least 50 % similar, within the same limits), and then:

| One side | The other side | Result |
|---|---|---|
| renamed `a` to `b` | edited `a` | the edit is merged at `b`; nothing is left at `a` |
| renamed `a` to `b` | renamed `a` to `b` | the two versions are merged at `b` |
| renamed `a` to `b` | deleted `a` | a conflict at `b`: the renamed file against no file |
| renamed `a` to `b` | renamed `a` to `c` | a conflict at both `b` and `c`; keep one name with `vl resolve` |
| renamed `a` to `b` | added its own `b` | not followed: as before, a conflict at `a` and at `b` |

```text
$ vl merge feature
Merged okxyxwkk b72c3839 (empty) merge feature
  rename: followed rename src/price.rs -> src/billing/price.rs
Updated 1 files, removed 0
Working copy now at: uwwvstmm b519294d (empty) (no description set)
```

For rename/rename, `vl resolve b c --ours` keeps our name (`--theirs`
theirs); each path's conflict holds that side's version against "no file".

Directory renames are not detected: a file *added* on one side inside a
directory the other side renamed stays where it was added. Every file that
was in the directory follows on its own.

`VEIL_MERGE_RENAMES=0` turns rename following off (the merge then sees a
deletion and an addition, as Veil 1.0 did); any other value leaves it on.
Detection is bounded: past `deleted × added ≤ 1000²` pairs (or its byte
budget), only exact renames are followed, and the rest merge as before.

## Audiences: nothing moves to a wider one

Copies and rename-following merges are tree merges: they never decrypt
content into a wider audience, and never publish anything.

- **A cloaked change copied onto a public line** stays sealed: its files
  stay sealed for their scope, and a sealed description stays sealed (`-x`
  leaves it alone). The copy is on a public line, so it can be pushed; what
  a public remote receives is the sealed objects, which it cannot read.
- **A public change copied into a cloaked line** is sealed there, as
  anything that line introduces (`vl squash` into a cloaked change does the
  same), with the last public version as the fallback readers without the
  key see.
- **A conflict is copied as recorded**: each version keeps its own sealing.
- **A change an unreleased embargo withholds** (the fix, the changes
  that made it, work built on it, and the changes on the embargoed line)
  is refused, unless every new parent is on the fix line of the same
  embargo: a copy elsewhere would publish the fix's file names before the
  release. Merge it with `vl merge --embargo` instead. The embargoed merge
  itself cannot be copied before its release. See [Embargoes](embargoes.md#working-on-an-embargoed-line)
  for the other commands that copy content (`vl restore --from`,
  `vl squash`, `vl rebase`).
- **Renames are paired only within one audience.** A public file and a
  sealed one are never a rename, so an edit never moves from one into the
  other. Pairing reads only public content (sealed files pair only when
  they are the very same sealed object), so whether a rename is followed
  never depends on your keys, and a merge never reads what you cannot.
- **A cloaked file moved to a path the policy leaves public** stays sealed
  there when an edit follows it, even when `vl merge` publishes the rest of
  a cloaked line; `vl merge` warns, and only `vl expose` publishes it:

  ```text
  warning: docs/db.yml followed the rename of secrets/db.yml and stays sealed (cloaked:team) at its new path; `vl expose docs/db.yml` publishes it
  ```

Renames are computed when merging and reported to you; they are never
stored in a snapshot, the operation log or a remote.
