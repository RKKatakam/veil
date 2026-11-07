# Embargoes: fixing a security issue in private

> The Veil server refuses embargoed merges until it enforces embargoes as permissions ([HUB.md](../HUB.md) §13.8, §13.9). Until then an embargoed merge stays on the device where it was made; the rules below are what the engine enforces on every transfer between repositories.

An **embargoed merge** lands a fix on `main` now and publishes it later.
An embargo is a **permission, not encryption** ([VISIBILITY.md](../VISIBILITY.md),
"Hidden changes"): a plain record of who may see the fix before the release
(`--scope`, default `team`) and an optional deadline. Nothing is encrypted.
Until the release, the embargoed merge and the history it brings in are
**withheld from every push**, and so are tags and commits that build on
them. After the release, the same snapshots are pushed, with nothing
rewritten.

> **With the server**, an embargo goes to chosen groups now and becomes public later (planned: `vl merge fix --into main --embargo-for <groups…> --until <date>`), and an embargoed PR doesn't exist for anyone else. The commands below are today's client, where the audience is named with `--embargo --scope S`.

1. [The workflow](#the-workflow)
2. [Deadlines and release](#deadlines-and-release)
3. [One embargo per line](#one-embargo-per-line)
4. [Working on an embargoed line](#working-on-an-embargoed-line)
5. [Limitations today](#limitations-today)

## The workflow

Develop the fix **off `main`**, in a separate workspace. A push sends
tags, so the fix's line is not pushed while no tag points into it.

> **Keep `main` still.** `vl commit` moves the tags at the parent, so a fix
> committed on top of `main` would move `main` onto it before any embargo
> exists. Use `vl describe`, or `vl commit --no-advance`.

**1. Create a workspace for the fix**, based on `main`:

```text
$ vl ws new fix-cve -r main
Created virtual workspace fix-cve at ooquruqt 373d2ea3 (empty) (no description set)
  hint: no directory was created. Use `vl ws exec fix-cve -- <cmd>` or `vl ws switch fix-cve`.
```

**2. Work on it.** Attach your project directory to the workspace, edit,
and describe it:

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
  embargo 77932133a2: the merge and the history it brings in stay with 'team' (pushes hold them back) until 2026-11-11 04:09:55 UTC, or an earlier `vl embargo release 77932133a2`.

$ vl embargo list
77932133a2  scope:team  until 2026-11-11 04:09:55 UTC
```

* `--scope S` (default `team`) names who may see the fix before release.
* The deadline is shown in local time with its UTC offset, plus UTC.
* `main` moved to the merge, as `vl merge` moves tags at the change it
  merges into. `vl log` marks the merge `[embargo:77932133a2]`, and `vl show` names the embargo.

**4. Push.** Before the release, the merge, the fix's history and anything
built on them are withheld from every receiver: a tag whose history reaches
them (here `main`) is skipped, with the reason, and receivers keep the
`main` they had. (Today the Veil server refuses a push that reaches an
embargoed merge at all: see the note at the top.)

**5. Release** when the advisory goes out (or let the deadline do it), and
push again. `vl embargo release` first shows what becomes public and asks:

```text
$ vl embargo release 77932133a2
Releasing embargo 77932133a2 (scope team) publishes the fix: your next push sends it, and everyone who may see the code can read it.
  merge af765f31 Fix CVE-2026-1234
  1 snapshot(s) of the fix's history, withheld until now:
    2be318b2 Fix CVE-2026-1234: empty buffer crash
  on: main
  Your next push to any remote publishes it (remotes: origin).
  Until you push, `vl undo` takes the release back. After that it cannot be undone.
Release embargo 77932133a2? [y/N] y
Released embargo 77932133a2 in this repository. Your next push publishes it; until then `vl undo` takes it back.
```

In a script, pass `--yes` (without it, a release from a non-terminal is
refused).

**Released by mistake?** Until your next push, the release exists only in
your repository. `vl undo` right after it takes it back completely:

```text
$ vl undo
Undid: release embargo 77932133a2
Embargo 77932133a2 is unreleased again: its release had not left this repository.
```

(`vl embargo list` shows such a release as `released (not pushed yet)`.)
Once a push has published the release, `vl undo` of it refuses and changes
nothing: treat the fix as public.

**6. Clean up:** `vl ws rm fix-cve`.

## Deadlines and release

`--until TIME` takes `+7d`, `+12h`, `+30m`, `+2w` (also `s`), an RFC 3339
time (`2026-12-01T09:00:00Z`) or a date (`2026-12-01`, midnight local
time). Deadlines must be in the future and less than 100 years away:

```text
$ vl merge fix@ --into main --embargo --until 2020-01-01
error: '2020-01-01' is in the past; an embargo deadline must be in the future (use `vl embargo release` to publish now)
```

Without `--until`, the embargo lasts until `vl embargo release ID`. Once
the deadline has passed, the embargo counts as released, and the next push
sends the fix.

**Who may release** is a permission the server will enforce; today's
client does not check it.

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

* You can keep committing on top of the embargoed merge. Those commits are
  withheld from pushes too **until the release**, even for unrelated work.
  Release early, or keep unrelated work on another line and merge it after
  the release.
* A tag that would publish the fix by another route (a tag on the fix line
  itself) is skipped by `vl push`.
* **Nothing copies the fix out of its embargo.** Until the release, the fix,
  work built on it and the embargoed line stay inside the embargo, and every
  command that would copy their content into a change outside it refuses,
  naming the change and the embargo (never a file): `vl restore --from`
  (with or without paths), `vl squash` (`--into` another line, or into the
  fix's own parent), `vl duplicate` and `vl cherry-pick`, `vl rebase`
  of work built on the fix onto another line, and `vl abandon` of the fix
  while work is built on it.
* **What the embargo withholds stays withheld.** The embargo withholds
  every version of every change on the fix line (the fix, how it was made,
  and the merge), whatever its snapshot id: an earlier version brought back
  by `vl undo --op`, `vl tag set -r`, `vl new` or `vl restore --from` is
  withheld too, and so is everything built on any of them. A rewrite never
  makes the fix line forget a change: dropping the fix from the merge's
  parents keeps it withheld. Until the release, a command after which a
  version the embargo withheld is still there but no longer withheld is
  refused ("release the embargo first, or abandon what is built on the
  merge too"): `vl abandon` of the merge, or `vl squash` of it into the
  change on top of it or into the fix, while a change built on it survives;
  `vl rebase` of the merge onto other parents (the fix first, the fix
  alone, or without the fix). A concurrent operation that does it (another
  workspace) is dropped when the operations merge.
  Inside the embargo they all work: restore from the fix into a change on
  the fix line, squash work on the fix into it, rebase or split the fix
  itself (the embargoed merge follows). `vl cat -r` reads it and changes
  nothing.

## Limitations today

* **The server does not take embargoed merges yet** (the note at the top).
* **One embargo per line** (above).
* **A pushed release is final.** Only an unpushed release can be undone
  (above).
* **Undoing the merge withdraws the embargo.** If the embargoed merge is
  undone, or abandoned with nothing built on it, before a push, the fix
  line is an ordinary change again, pushed as soon as a tag reaches it.
  `vl embargo list` then shows the embargo as `withdrawn`, and the push
  that publishes what it used to hold back warns. (Work built on the merge
  keeps it in history, so its fix stays withheld.)

Who sees what is described in [VISIBILITY.md](../VISIBILITY.md), "Hidden changes".

Next: [Workspaces and agents](workspaces-and-agents.md).
