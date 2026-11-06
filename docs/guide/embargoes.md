# Embargoes: fixing a security issue in private

> The Veil server cannot take embargoed changes yet ([HUB.md](../HUB.md) §13.8, §13.9), and the path remotes that carried them (the "mirror" and "team remote" below) were removed in the simplification pass, part 1. Until the server's embargo milestone, an embargoed merge stays on the device where it was made; the rules below are what the engine enforces on any transfer.

An **embargoed merge** lands a fix on `main` now and publishes it later.
Until the release, everyone outside the embargo's scope (public remotes,
teammates not in the scope) keeps seeing `main`'s **pre-merge
tree**: no new file names, sizes or message, and none of the fix's history.
After the release, the same snapshot ids become readable, with nothing
rewritten.

> **With the server**, an embargo goes to chosen groups now and becomes public later (planned: `vl merge fix --into main --embargo-for <groups…> --until <date>`), and an embargoed PR doesn't exist for anyone else ([VISIBILITY.md](../VISIBILITY.md), "Hidden changes"). The commands below are today's client, before the server, where the audience is a *scope* (`--embargo --scope S`); this changes when the server lands (see [OVERVIEW.md](../OVERVIEW.md)).

1. [The workflow](#the-workflow)
2. [What the public sees](#what-the-public-sees)
3. [Deadlines and release](#deadlines-and-release)
4. [One embargo per line](#one-embargo-per-line)
5. [Working on an embargoed line](#working-on-an-embargoed-line)
6. [Limitations today](#limitations-today)

## The workflow

The fix must be developed **out of sight and off `main`**: in a separate,
cloaked workspace.

> **Why a cloaked workspace?** Everything recorded there is sealed for the
> scope, descriptions included, and `vl commit` there never moves an
> uncloaked tag: `main` stays where it is until you merge. (In an ordinary
> workspace `vl commit` moves the tags at the parent, so a fix committed on
> top of `main` would move `main` onto it before any embargo exists. If you
> must work in one, use `vl describe`, or `vl commit --no-advance`.)

**1. Create a cloaked workspace for the fix**, based on `main`:

```text
$ vl ws new fix-cve -r main --cloak team
Created virtual workspace fix-cve at ooquruqt 373d2ea3 (empty) (no description set)
  hint: no directory was created. Use `vl ws exec fix-cve -- <cmd>` or `vl ws switch fix-cve`.
```

`--cloak team` seals everything recorded there, descriptions included, so
pushing to the team remote before the merge doesn't publish it either.

**2. Work on it.** Attach your project directory to the workspace, edit,
and describe it (or commit, as often as you like: `main` does not move):

```text
$ vl ws switch fix-cve
Project directory attached to workspace fix-cve
Working copy now at: ooquruqt 373d2ea3 (empty) (no description set)
$ $EDITOR parser.py
$ vl describe -m "Fix CVE-2026-1234: empty buffer crash"
Described ooquruqt 2be318b2 Fix CVE-2026-1234: empty buffer crash
$ vl ws switch default
Project directory attached to workspace default
```

Your other work in `default` is untouched (it was recorded before the
switch). You can also work on the fix without switching, with
`vl ws exec fix-cve -- <cmd>` or `vl ws write fix-cve PATH < file`
(see [Workspaces](workspaces-and-agents.md)).

**3. Merge it into `main` under embargo:**

```text
$ vl merge fix-cve@ --into main --embargo --until +7d -m "Fix CVE-2026-1234"
Merged uqttozys af765f31 Fix CVE-2026-1234
  embargo 77932133a2: changed files are sealed for scope 'team'; everyone else sees the pre-merge content until 2026-11-11 04:09:55 UTC, or an earlier `vl embargo release 77932133a2`.
  public on release (from the cloaked line; secret-scanned): parser.py
Updated 1 files, removed 0
Working copy now at: ykskusvt 0ce6baf3 (empty) (no description set)

$ vl embargo list
77932133a2  scope:team  until 2026-11-11 04:09:55 UTC

$ vl log -n 4
@  ykskusvt alice ✓ 2026-11-04 04:09:55 default@ 0ce6baf3 (empty)
│  (no description set)
○  uqttozys alice ✓ 2026-11-04 04:09:55 main af765f31 [embargo:77932133a2]
│ │  Fix CVE-2026-1234  ⇠ merges pzkmnmrl, ooquruqt
│ ○  ooquruqt alice ✓ 2026-11-04 04:09:51 fix-cve@ 2be318b2 [cloaked:team]
│ │  Fix CVE-2026-1234: empty buffer crash
○    pzkmnmrl alice ✓ 2026-11-04 04:09:51 781e94dc
│  Parser
```

* `--scope S` (default `team`) is the audience before release. **Use the
  same scope as the fix workspace's `--cloak`**: a team remote only receives
  the fix's history if it is sealed for the embargo's own scope.
* "public on release" lists the fix's files that the merge moves from the
  cloaked line onto `main` (after a secret scan). They are sealed under the
  embargo, straight from their cloaked version (no plaintext copy is
  written to `.veil`), and become readable to others at the release. Only a
  line whose snapshots are all signed by current members of its scope is
  published this way. (A merge without
  `--embargo` lists them as "published from the cloaked line": public at
  once.)
* The deadline is shown in local time with its UTC offset, plus UTC
  (here the machine's zone is UTC).
* `main` moved to the merge, as `vl merge` moves tags at the change it
  merges into.

**4. Push as usual.** Team members in the scope see the fix; the public
mirror sees the pre-merge tree:

```text
$ vl push mirror
  pushed main → af765f31
Pushed 2 object(s) to public remote mirror; 2 cloaked/embargoed object(s) withheld
```

**5. Release** when the advisory goes out (or let the deadline do it), and
push again. `vl embargo release` first shows what becomes public and asks:

```text
$ vl embargo release 77932133a2
Releasing embargo 77932133a2 (scope team) publishes its key: everyone who receives your next push can read the fix.
  merge af765f31 Fix CVE-2026-1234
  1 snapshot(s) of the fix's history, withheld until now:
    2be318b2 Fix CVE-2026-1234: empty buffer crash
  on: main
  Your next push to any remote publishes it (remotes: mirror (public), origin).
  Until you push, `vl undo` takes the release back. After that it cannot be undone.
Release embargo 77932133a2? [y/N] y
Released embargo 77932133a2 in this repository. Your next push publishes the key; until then `vl undo` takes it back.
$ vl push mirror
  published embargo 77932133a2 (its key is in the pushed record now; the release can no longer be undone)
Pushed 6 object(s) to public remote mirror; 1 cloaked/embargoed object(s) withheld
```

In a script, pass `--yes` (without it, a release from a non-terminal is
refused).

**Released by mistake?** Until your next push, the release
exists only in your repository: the key is kept in device-local state that
no sync reads. `vl undo` right after it takes it back completely:

```text
$ vl undo
Undid: release embargo 77932133a2
Embargo 77932133a2 is unreleased again: its key had not left this repository.
```

(`vl embargo list` shows such a release as `released (not pushed yet)`.)
Once a push has published the key, `vl undo` of the release
refuses and changes nothing: a published key cannot be taken back, so
treat the fix as public. (Right after `vl push`, the first `vl undo` takes
back only what the push recorded about the remote, `mirror/main` and the
like; the next one reaches the release and refuses.)

**6. Clean up:** `vl ws rm fix-cve`.

## What the public sees

Before the release, a clone of the public mirror:

```text
$ vl clone embmirror carolemb
Cloned /tmp/vdoc/embmirror into /tmp/vdoc/carolemb (6 objects, 2 files)
  note: an embargoed merge is not readable to you yet; you see its pre-merge content until it is released.

$ vl log
@  wromyvwl carol ✓ 2026-11-04 04:09:55 default@ 7f4a20c3 (empty)
│  (no description set)
○  uqttozys alice ✓ 2026-11-04 04:09:55 main origin/main af765f31 [embargo:77932133a2]
│ │  [cloaked:embargo/77932133a2]  ⇠ merges pzkmnmrl, 2be318b2 (withheld)
○ │  pzkmnmrl alice ✓ 2026-11-04 04:09:51 781e94dc
│ │  Parser

$ cat parser.py
def parse(buf):
    return buf[0]

$ vl show main
…
Embargo   : 77932133a2 (until 2026-11-11 04:09:55 UTC)

    [cloaked:embargo/77932133a2]

(no changes)
```

After the release and a pull, the same snapshot is readable and the file is
filled in:

```text
$ vl pull
  updated main → 6eea7cdc
Pulled 8 object(s) from origin
Filled in 1 file(s) that became readable (a key arrived or an embargo was released), removed 0
$ cat parser.py
def parse(buf):
    if not buf:
        raise ValueError("empty")
    return buf[0]
```

| Before release, outsiders see | Outsiders never see before release |
|---|---|
| That an embargoed merge exists on `main` | The fix's content, file names, sizes, or *which* files changed |
| Its author, time, embargo id, scope and deadline | Its message (`[cloaked:embargo/…]`) |
| Its first parent, and the id of the merged-in parent (marked `withheld`) | The fix's own history |

The fix line's own snapshots stay cloaked for `team` after the release
(they were made in a cloaked workspace). The public gets the fix through
the merge.

## Deadlines and release

`--until TIME` takes `+7d`, `+12h`, `+30m`, `+2w` (also `s`), an RFC 3339
time (`2026-12-01T09:00:00Z`) or a date (`2026-12-01`, midnight local
time). Deadlines must be in the future and less than 100 years away:

```text
$ vl merge fix@ --into main --embargo --until 2020-01-01
error: '2020-01-01' is in the past; an embargo deadline must be in the future (use `vl embargo release` to publish now)
```

Without `--until`, the embargo lasts until `vl embargo release ID`.

**Automatic release is not a timer.** The deadline is acted on by the first
`vl` command a key holder runs after it, and the public sees the release
only once a key holder pushes:

```text
$ vl status
Released embargo af4a705f61: its release time has passed
…
```

Release is not time-lock cryptography: a key holder can release early, and
nobody can force a key holder to release.

**Who may release.** Only a *current* member of the embargo's scope (or
anyone's `vl`, once the deadline has passed). If you revoke someone who
was in the scope when the embargo was created, they still hold its key,
and could leak it or the fix by other means (revocation is forward-only).
But a release they make is ignored by every member's `vl` and by the team
remote: the embargo stays in force, and your next public push does not
publish the fix. `vl pull` warns about such a release
(`release ignored: … not a current member`), and `vl embargo list` shows
it next to the embargo. A member granted by short member id (without
their full identity) cannot release before the deadline either: re-grant
them with the identity `vl identity show` prints.

## One embargo per line

Veil keeps **at most one unreleased embargo per line**. A second
`--embargo` merge into (or of) a line that still carries one is refused,
and so is merging or rebasing two embargoed lines together:

```text
$ vl merge fix2@ --into main --embargo -m "second"
error: policy violation: cannot merge under a new embargo: the line it merges into (af765f31) already carries unreleased embargo 77932133a2, and embargoes cannot overlap; release the earlier embargo first (`vl embargo release 77932133a2`), then merge
```

Nothing is recorded when this happens. Your options:

* release the first embargo, then merge the second fix;
* or develop and embargo the second fix on a **separate line** (say a
  release branch cut before the first merge), and combine the lines after
  one of them is released.

## Working on an embargoed line

* **Key holders** (members of the scope) can keep committing on top of the
  embargoed merge. Those commits are sealed under the embargo too, messages
  included, and outsiders keep seeing the pre-merge tree **until the
  release**, even for unrelated public work. Release early, or keep
  unrelated public work on another line and merge it after the release.
* **Everyone else** (outsiders, and teammates not in the scope) cannot
  record edits on top of the embargoed merge. `vl` holds them back with a
  warning naming the embargo. Work on the merge's first parent instead.
* A tag that would publish the fix by another route (a tag on the fix line
  itself) is skipped by `vl push`.
* **Nothing copies the fix out of its embargo.** Until the release, the fix,
  work built on it and the embargoed line stay inside the embargo, and every
  command that would copy their content into a change outside it refuses,
  naming the change and the embargo (never a file): `vl restore --from`
  (with or without paths), `vl squash` (`--into` another line, or into the
  fix's own public parent), `vl duplicate` and `vl cherry-pick`, `vl rebase`
  of work built on the fix onto another line, and `vl abandon` of the fix
  while work is built on it.
  Inside the embargo they all work: restore from the fix into a change on
  the fix line, squash work on the fix into it, rebase or split the fix
  itself (the embargoed merge follows). `vl cat -r` reads it and changes
  nothing.
* Conflicts on an embargoed line are reported by the command that produced
  them but not recorded on the snapshot (conflicted file names would tell
  outsiders what the fix touches). They are written as markers into the
  file, never as a conflict entry (whose versions keep their own sealing,
  outside the embargo); an unresolved conflict the embargoed merge takes in
  goes under the embargo as its file of markers.

## Limitations today

* **Metadata stays visible**: that an embargoed merge exists, its author,
  time, scope and deadline, its parents' ids, and ciphertext sizes on team
  remotes.
* **One embargo per line** (above).
* **Release time is enforced by key holders' `vl`**, not by cryptography.
* **A pushed release is final.** Only an unpushed release can be undone
  (above).
* **A revoked member still holds the key.** Their release is refused, but
  nothing stops them leaking the key or the fix out of band.
* **The wrapper's size is visible**: outsiders cannot tell *which* files
  changed, but can estimate *how many* files and directories did.
* **Undoing the merge undoes the protection.** If the embargoed merge is
  undone or abandoned before a push, the fix line is an ordinary change
  again: only its cloak protects it.
* **Other scopes:** content cloaked under a *different* scope stays under
  that scope, and its members can read it before the release. An embargoed
  merge that adds or changes files cloaked under another scope is refused;
  use the same scope for the cloak and the embargo.

The design is in [`docs/ARCHITECTURE.md` §7](../ARCHITECTURE.md#7-delayed-visibility-embargoed-merges).

Next: [Workspaces and agents](workspaces-and-agents.md).
