# Embargoes: fixing a security issue in private

An **embargoed merge** lands a fix on `main` now and publishes it later.
Until the release, everyone outside the embargo's scope (public remotes,
GitHub, teammates not in the scope) keeps seeing `main`'s **pre-merge
tree**: no new file names, sizes or message, and none of the fix's history.
After the release, the same snapshot ids become readable, with nothing
rewritten.

1. [The workflow](#the-workflow)
2. [What the public sees](#what-the-public-sees)
3. [Deadlines and release](#deadlines-and-release)
4. [One embargo per line](#one-embargo-per-line)
5. [Working on an embargoed line](#working-on-an-embargoed-line)
6. [Limitations in 1.0](#limitations-in-10)

## The workflow

The fix must be developed **out of sight and off `main`**: in a separate,
cloaked workspace, without `vl commit`.

> **Why not `vl new main` + `vl commit`?** `vl commit` moves every tag that
> pointed at the parent, so committing a change made on top of `main`
> moves `main` onto the fix before any embargo exists. That happens in a
> separate workspace too. The next push then shows the public a cloaked
> change on `main` (the changed file disappears for them) before you
> merged anything. Use `vl describe` on the fix line instead: it records
> the message without moving tags.

**1. Create a cloaked workspace for the fix**, based on `main`:

```text
$ vl ws new fix-cve -r main --cloak team
Created virtual workspace fix-cve at ooquruqt 373d2ea3 (empty) (no description set)
  hint: no directory was created. Use `vl ws exec fix-cve -- <cmd>` or `vl ws switch fix-cve`.
```

`--cloak team` seals everything recorded there, descriptions included, so
pushing to the team remote before the merge doesn't publish it either.

**2. Work on it.** Attach your project directory to the workspace, edit,
and describe (don't commit):

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
  embargo and become readable to others at the release. (A merge without
  `--embargo` lists them as "published from the cloaked line": public at
  once.)
* The deadline is shown in local time with its UTC offset, plus UTC
  (here the machine's zone is UTC).
* `main` moved to the merge, as `vl merge` moves tags at the change it
  merges into.

**4. Push as usual.** Team members in the scope see the fix; the public
mirror and GitHub see the pre-merge tree:

```text
$ vl push mirror
  pushed main → af765f31
Pushed 2 object(s) to public remote mirror; 2 cloaked/embargoed object(s) withheld
```

**5. Release** when the advisory goes out (or let the deadline do it), and
push again:

```text
$ vl embargo release 77932133a2
Released embargo 77932133a2; push to publish it.
$ vl push mirror
Pushed 6 object(s) to public remote mirror; 1 cloaked/embargoed object(s) withheld
```

For GitHub, `vl git push` after the release adds one commit on top of the
branch that publishes the fix and links its history (a fast-forward).

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

## One embargo per line

Veil 1.0 keeps **at most one unreleased embargo per line**. A second
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
* Conflicts on an embargoed line are reported by the command that produced
  them but not recorded on the snapshot (conflicted file names would tell
  outsiders what the fix touches).

## Limitations in 1.0

* **Metadata stays visible**: that an embargoed merge exists, its author,
  time, scope and deadline, its parents' ids, and ciphertext sizes on team
  remotes.
* **One embargo per line** (above).
* **Release time is enforced by key holders' `vl`**, not by cryptography.
* **Undoing the merge undoes the protection.** If the embargoed merge is
  undone or abandoned before a push, the fix line is an ordinary change
  again: only its cloak protects it.
* **Other scopes:** content cloaked under a *different* scope stays under
  that scope, and its members can read it before the release. An embargoed
  merge that adds or changes files cloaked under another scope is refused;
  use the same scope for the cloak and the embargo.

The design is in [`docs/ARCHITECTURE.md` §7](../ARCHITECTURE.md#7-delayed-visibility-embargoed-merges).

Next: [Workspaces and agents](workspaces-and-agents.md).
