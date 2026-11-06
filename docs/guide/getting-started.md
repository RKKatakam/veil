# Getting started

> Where this page mentions cloaking, scopes or isolated files, the server replaces them with folder access and encrypted secrets (see [OVERVIEW.md](../OVERVIEW.md) and [VISIBILITY.md](../VISIBILITY.md)). `vl` syncs only through the Veil server.

1. [Install](#install)
2. [Your identity](#your-identity)
3. [Create a repository](#create-a-repository)
4. [No staging: every command snapshots](#no-staging-every-command-snapshots)
5. [The daily loop](#the-daily-loop)
6. [Change ids and snapshot ids](#change-ids-and-snapshot-ids)
7. [Revisions](#revisions)
8. [Undo anything](#undo-anything)
9. [Global options and environment](#global-options-and-environment)

## Install

See the [Install section of the README](../../README.md#install): release
binaries, the installer script, Homebrew and Cargo, for Linux and macOS.
Then check the machine:

```sh
vl --version
vl doctor
```

`vl doctor` explains anything about your setup that Veil cares about
(identity, filesystem, clock). See [Maintenance](maintenance.md#vl-doctor).

## Your identity

Veil identifies you by a key pair, not by a name and an email. The first
`vl` command that needs it creates one:

```text
$ vl identity show
Created new identity for 'alice' at /home/alice/.config/veil/identity.json
name        alice
public key  veil15dc25eaf4116d32ea46c6bc1cc0f2a62f04e962ecb4c585f4f827bd609b96d59711356edc60003febde90d2de5cedcaa3325c69855af8bb84621e091f68b75d422e081bbe9c366cc0debfd0f7553376afdd2173d39be908e8266c8fc7eb2421618d765d113e4bada98237e0870f19e09d905b31c90beac23f64be82fb7141d09
member id   veil15dc25eaf4116d32ea46c6bc1cc0f2a62f04e962ecb4c585f4f827bd609b96d59
signing key 711356edc60003febde90d2de5cedcaa3325c69855af8bb84621e091f68b75d4
stored at   /home/alice/.config/veil/identity.json
```

* **`public key`** is what you give teammates so they can grant you access
  to cloaked files (`vl scope grant`). Always share the full key.
* **`identity.json` holds your private keys.** It is created mode `0600`,
  once: several `vl` commands starting at the same time on a new machine
  all end up with the same identity.
  Back it up somewhere safe: without it you lose access to everything
  cloaked for you, and to your local secret vault (see
  [Maintenance](maintenance.md#backups)).
* It lives in `$VEIL_HOME` (default `$XDG_CONFIG_HOME/veil`, else
  `~/.config/veil`), shared by all your repositories.
* The name defaults to `$VEIL_USER`, then `$USER`. To choose it when the
  identity is created: `vl identity new --name "Alice Doe"`.

**The author recorded on snapshots** is `$VEIL_USER` if set, else the
identity's name. To record an email address with it, set it in your shell
profile before you start:

```sh
export VEIL_USER="Alice Doe <alice@example.com>"
```

A change takes its author when it is created, so set this before you begin
the change, not just before you commit it.

## Create a repository

```text
$ cd hello
$ vl init
Initialized Veil repository in /tmp/vdoc/hello/.veil
  identity   alice (veil15dc25eaf4116d32ea46c6bc1cc0f2a62f04e962ecb4c585f4f827bd609b96d59)
  scope      team (you are the only member)
  recorded   2 files
```

`vl init [path]` creates:

* `.veil/`, the repository (never edit it by hand);
* a `.veilpolicy` file, if there is none, with comments explaining the
  visibility tiers and two rules (`target/` and `node_modules/` are
  ignored). It is an ordinary tracked file. See
  [Secrets and visibility](secrets-and-visibility.md);
* a scope called `team`, with you as its only member and admin, used by
  `vl cloak` by default.

It also records whatever is already in the directory, except secrets: a
`.env` or a key file is listed as `local-only` instead.

To work on an existing Veil repository, `vl clone` it rather than running
`vl init` (see [Teams and remotes](teams-and-remotes.md#onboarding-a-teammate)).

## No staging: every command snapshots

There is no `add` and no index. **Every** `vl` command first records the
working copy as a new version of the current change, which is called `@`:

```text
$ vl status
Working copy changes:
A .veilpolicy
A main.rs
Workspace    : default
Working copy : @ uzpxpkxz 5b96d85b (no description set)
Parent       : zzzzzzzz 72edc798 (no description set)
```

`A main.rs` means "added in `@`, compared with its parent", not "staged".
It is already in the repository. Consequences:

* You cannot lose work by forgetting to add it. Edits are recorded the next
  time you run any `vl` command.
* You don't choose which files go into a change. Everything that is not
  ignored, isolated or quarantined goes in. Use [`.veilpolicy`](secrets-and-visibility.md)
  to keep things out, and `vl restore <path>` to drop an edit.
* `vl --no-snapshot <command>` skips the automatic snapshot, for the rare
  case you need to look at the repository without recording the disk.
* `vl watch` records continuously, as files change. It steps aside while
  another `vl` command in the same directory moves the working copy (a
  `vl commit` in another terminal), and picks up where that command left
  it.

## The daily loop

```text
$ sed -i 's/hello/hello, world/' main.rs
$ vl status
Working copy changes:
M main.rs
Workspace    : default
Working copy : @ yltznuyx ecdb49a1 (no description set)
Parent       : uzpxpkxz c85c3154 First version

$ vl diff
diff --veil a/main.rs b/main.rs
@@ -1,3 +1,3 @@
 fn main() {
-    println!("hello");
+    println!("hello, world");
 }

$ vl commit -m "Greet the world"
Committed yltznuyx 53414202 Greet the world
Working copy now at: xzsqlooo 1cb1ea35 (empty) (no description set)

$ vl log
@  xzsqlooo alice ✓ 2026-11-04 04:14:57 default@ 1cb1ea35 (empty)
│  (no description set)
○  yltznuyx alice ✓ 2026-11-04 04:14:57 main 53414202
│  Greet the world
○  uzpxpkxz alice ✓ 2026-11-04 04:14:57 c85c3154
│  First version
◆  zzzzzzzz 72edc798
   root()
```

| Command | What it does |
|---|---|
| `vl status` (`vl st`) | What `@` changes compared with its parent; local-only, quarantined and redacted files; conflicts in `@` |
| `vl diff` | The diff of `@` (`-r REV` for another change, `--from A --to B` between two, `--stat` for names only) |
| `vl log [-n N]` | The snapshot graph: change id, author, signature, time, tags and workspaces, snapshot id, description |
| `vl show [REV] [--stat]` | One snapshot's metadata and diff |
| `vl describe -m MSG [-r REV]` | Set the description of a change (default `@`). Does not start a new change |
| `vl commit -m MSG [--no-advance]` | Describe `@`, then start a new, empty change on top of it. **Moves tags that pointed at the parent** to the committed change (in a cloaked workspace, only tags cloaked under its scope; with `--no-advance`, none) |
| `vl new [REVS…] [-m MSG]` | Start a new change on top of `REVS` (default `@`); with several revisions, a merge. Moves no tags |
| `vl ls [-r REV] [PATHS…]`, `vl cat PATH [-r REV]` | List a snapshot's files with their tier (public, cloaked, isolated, …), or print one |

In `vl log`: `@` is your working copy, `○` another snapshot, `×` one with
conflicts, `◆` the root. `✓` is a good signature from the author (`✓bob`
means signed by bob, with a different author recorded). `default@` says
which workspace has the snapshot as its working copy, and `main` is a tag.

**`vl describe` + `vl new` is the same as `vl commit`**, except that `vl
commit` also moves tags along. You can describe a change before, during or
after working on it.

### Tags

Tags are named pointers, the closest thing to Git branches. `vl init`
creates none: make one when you want a name, for example for pushing.

```text
$ vl tag set main -r @-
Tag main → uzpxpkxz c85c3154 First version
$ vl tag list
main: yltznuyx 53414202 Greet the world
```

* A tag **follows its change** when that change is rewritten (`describe`,
  `rebase`, `squash`).
* `vl commit` moves every tag that pointed at the parent of `@` onto the
  committed change. That is how `main` moved above. In a cloaked workspace
  it moves only tags cloaked under the same scope, so cloaked work never
  reaches `main` by accident. `vl merge` moves tags
  that pointed at the change merged into. Pulls fast-forward tags.
* Nothing else moves a tag. `vl tag set` refuses to move one backwards or
  sideways unless you pass `--allow-backwards`.
* `vl tag set NAME --cloak [SCOPE]` makes a tag whose name is sealed for
  the scope. **The Veil server does not hide it yet:** `vl push` sends it
  as a branch everyone in the project sees (BUG-839).

## Change ids and snapshot ids

Every line of `vl log` shows two ids:

```text
○  yltznuyx alice ✓ 2026-11-04 04:14:57 main 53414202
   ^^^^^^^^ change id                       ^^^^^^^^ snapshot id
```

| | Change id | Snapshot id |
|---|---|---|
| Looks like | letters `k`–`z`: `yltznuyx` | hex: `53414202` |
| Identifies | a change, across all its versions | one exact version (content, description, parents) |
| Changes when | never | on every edit, describe, rebase or squash |

Because every command snapshots, a change gets a new snapshot id each time
you edit it. The change id stays. `vl evolog` shows the versions:

```text
$ vl evolog -r @-
2026-11-04 04:14:57  yltznuyx 53414202 Greet the world
2026-11-04 04:14:57  yltznuyx 95fbd25b Greet the world
2026-11-04 04:14:57  yltznuyx ecdb49a1 (no description set)
2026-11-04 04:14:57  yltznuyx ab0323d9 (empty) (no description set)
```

Use change ids in day-to-day work. Use snapshot ids when you mean one exact
version (to compare with `vl diff --from`, or after a change became
*divergent*: two visible snapshots with the same change id, which `vl`
reports when you use the change id). Every id `vl evolog` prints is a
revision, earlier versions included: `vl show ecdb49a1`, `vl cat -r ecdb49a1
FILE` and `vl restore --from ecdb49a1 FILE` reach a file as it was a few
snapshots ago. A change id always names the current version.

## Revisions

Wherever a command takes `REV`:

| Revision | Means |
|---|---|
| `@` | the working copy of the current workspace |
| `name@` | the working copy of workspace `name` (`default@`, `fix-cve@`) |
| `main` | a tag |
| `origin/main` | a remote tag: where `main` was on remote `origin` at the last pull or push |
| `yl`, `yltznuyx` | a change-id prefix (letters `k`–`z`), as short as is unique |
| `5341`, `53414202…` | a snapshot-id prefix, at least 4 hex digits |
| `root` | the root snapshot every history starts from |
| `X-`, `X--` | the first parent, grandparent… of `X`: `@-`, `main--` |

A tag name wins over a change-id prefix that happens to spell the same.
Prefixes must be unique among visible snapshots, or `vl` says
`change id prefix '…' is ambiguous`.

```sh
vl show yl --stat
vl diff --from main- --to main
vl cat main.rs -r uzpx
vl new main
```

## Undo anything

Every command that changes the repository is an **operation** in the
operation log. That includes the automatic snapshots. `vl commit` records
your edits and commits them as **one** operation, so `vl undo` takes back
both: the change is open again, without the edits the commit recorded
(`vl redo` brings them back).

```text
$ vl op log -n 3
c924f35b 2026-11-04 04:07:59 alice commit change yyntkszx
a39343fc 2026-11-04 04:07:58 alice snapshot working copy of 'default'
f1df66f3 2026-11-04 04:07:58 alice set tag main

$ vl undo
Undid: commit change yyntkszx
Working copy now at: yyntkszx 4094f80d (no description set)
```

* `vl undo` undoes the last operation. Run it again to go further back:
  each undo takes back the command before the one the previous undo took
  back (undos themselves are skipped, as in jj).
* `vl redo` re-applies what the latest undo took back; run it again to
  take back the undo before that. Any other command after an undo (a
  commit, a rebase, a tag move…) leaves nothing to redo; editing files
  does not.

```text
$ vl undo
Undid: commit change yyntkszx
$ vl undo
Undid: set tag main
$ vl redo
Redid: set tag main
```

* `vl op restore <id>` returns the whole repository (changes, tags,
  workspaces) to the state after operation `<id>`.
* Both **keep the files on disk that you had not recorded yet**: the
  automatic snapshot taken before `undo` is not what gets undone. What a
  command recorded as part of itself goes back with it: `vl commit`'s
  edits (with pre-commit or commit-msg hooks, which read the recorded
  snapshot, the edits are recorded first, as their own operation, and stay). After
  `vl ws switch`, `vl undo` switches back (and `vl redo` switches again);
  the edits of each workspace stay in that workspace. An undo that would
  delete a workspace holding recorded edits (undoing its `vl ws new`) is
  refused and changes nothing.
* Some commands change things the operation log does not hold: key rings
  (`vl scope create`, `grant`, `revoke`, `rotate`), remotes (`vl remote add`,
  `rm`), the local vault (`vl secret set`, `rm`, `import`) and the accepted
  policy (`vl policy accept`). They are operations too, so `vl undo` never
  skips past them to undo something older. Instead it refuses and says how
  to reverse them by hand. A revocation or a key rotation cannot be taken
  back at all.

```text
$ vl scope grant team 7f3a… --name bob
$ vl undo
error: cannot undo 'grant scope team to bob': key rings are append-only;
take the access back with `vl scope revoke team 7f3a…` (until you push, nobody else has received the key). …
```

  `vl op restore <id>` still goes back to an earlier operation, and warns
  about each such command it cannot revert.
* What already left the repository cannot be undone. `vl push` is an
  operation too, because it records `origin/main` and the other remote
  tags; undoing it only takes back what this repository remembers about the
  remote, never the push itself. An **embargo
  release** can be undone only until your next push; after
  that `vl undo` refuses it ([Embargoes](embargoes.md#the-workflow)).

Other ways to reshape history:

| Command | Effect |
|---|---|
| `vl edit REV` | Make `REV` the working copy: edit an older change in place. Its descendants are rebased automatically |
| `vl abandon [REV]` | Drop a change. Its descendants move onto its parent |
| `vl squash [-r REV] [--into DEST] [PATHS…] [-i]` | Fold a change, or the files or hunks you choose, into its parent (or `DEST`) |
| `vl split [-r REV] PATHS…`, `vl split -i` | Split a change in two (see [Shaping history after the fact](#shaping-history-after-the-fact)) |
| `vl rebase -s REV -d DEST` | Move a change and its descendants onto `DEST` (several `-d` for a merge) |
| `vl restore [PATHS…] [--from REV]` | Put files back as they are in `REV` (default: the parent of `@`, or for a merge its merged parents, as `vl status` compares): discards edits, and removes the directories it empties. A version keeps its audience: one sealed for a scope stays sealed, a conflict comes back as the same conflict, and a version you cannot read is not restored |
| `vl merge REVS… [-m MSG]` | Merge into `@` (or into `@-` when `@` is empty), then start a new change on top |
| `vl resolve [--list]`, `vl resolve PATHS --ours\|--theirs\|--base` | List unresolved conflicts, or keep one version of each (see [Conflicts](#conflicts)) |

### Shaping history after the fact

You never have to plan commits up front. Work in one change, then cut it
into pieces, or move pieces between changes, when you know what the pieces
are.

**`vl split`** cuts a change in two. What you choose goes into a new first
change on the original's parents; the rest stays in the change you split,
which becomes its child:

```text
$ vl split src/parser.rs -m "Parser: accept trailing commas"
First part:  vulponvr ebef2181 Parser: accept trailing commas
Second part: xzolylpw 4985bcf6 Teach the CLI about config files
```

The second part keeps the change id and the description: it is still the
change you were working on (if it was `@`, you are still on it, and nothing
in your directory changes), its tags and descendants stay on it, and
nothing needs rebasing, because its files are exactly what they were. Only
the first part is new; `-m` describes it.

To choose by hunk, add `-i`. Each hunk is shown with a question, as
`git add -p` asks:

```text
$ vl split -i
diff src/config.rs (modified)
@@ -10,7 +10,9 @@
 …
(1/3) Put this hunk in the first change [y,n,q,a,d,s,?]?
```

`y` takes the hunk, `n` leaves it, `s` splits it into smaller hunks where
unchanged lines separate its edits, `a` and `d` take or leave the rest of
the file, `q` leaves everything after it, and `?` lists the answers. A
change of the executable bit is a question of its own. `vl split -i PATHS`
asks only about those files.

**`vl squash`** moves the other way. With no arguments it folds `@` into
its parent, as always. Name paths, or use `-i`, to move only part of a
change; the rest stays where it was, with its description. `--into DEST`
moves into any change instead of the parent (an ancestor, a descendant or a
sibling); the changes in between are rebased:

```sh
vl squash src/parser.rs              # the parser fix belongs in @-
vl squash -i --into @--             # some hunks belong two changes down
```

Each split or squash is one operation: `vl undo` takes it back exactly.

**Without a terminal.** The picker reads one answer per line from standard
input, terminal or not, so a script can pipe answers in
(`printf 'y\nn\ns\ny\n' | vl split -i`). If the answers run out before every
question is answered, nothing changes (answer `q` to leave the rest). Agents
and scripts can name hunks instead: `--hunks src/config.rs:1,3` takes hunks
1 and 3 of that file, `2.1` the first edit of hunk 2, `mode` its
executable-bit change. The numbers are the hunks `vl diff -r REV --json`
lists (from 1). `--plan FILE` (or `-` for standard input) takes the same as
JSON, and `vl serve --local` offers `split` and `squash` taking that plan;
with `--json`, both commands print what they made
([`veil.split/1`, `veil.squash/1`](../reference/json.md#veilsplit1)).

**What can be split by hunk.** Visibility never changes: a hunk of a
cloaked file goes into the other change sealed for the same scope, and an
edit made on a cloaked line keeps showing its last public version to
everyone else. Some files only move whole, and the picker says why:

* a file you cannot read (sealed for a scope you are not in): you can move
  it, but not choose lines you cannot see;
* a conflicted file (resolve it first, or move the conflict as it is);
* a file whose visibility this change alters (exposed, cloaked or moved to
  another scope), and `.veilpolicy` itself;
* binary files, files that are not UTF-8 text, and a file replaced by a
  directory of the same name (or the reverse).

**Nothing empty.** A split that would leave either part empty is refused
(`vl describe` changes a description; `vl new REV-` starts an empty change
before one). A squash that moves everything abandons the source and joins
its description to the destination's, like a whole `vl squash`.

### Conflicts

A merge or rebase that conflicts still succeeds. The conflict is recorded
in the snapshot as data (the versions that did not merge, each kept as it
was), the snapshot is marked `(conflict)`, and the working copy gets the
file with conflict markers:

```text
$ vl merge tnorryvo -m "Merge experiment"
Merged wzsvkkoo da175042 (empty) Merge experiment
warning: conflicts in: README.md
Updated 2 files, removed 0
Working copy now at: tvpmolku a62f2614 (empty) (no description set)

$ cat README.md
<<<<<<< ours
two
||||||| original
# Demo
=======
one
>>>>>>> theirs
```

The markers exist only in your working copy: history holds the versions,
and each checkout writes the markers again. The change on top of the merge
holds the conflict too, so `vl status` lists it (`recorded on` names the
merge), and so do `vl ls` (`conflict: 2 sides`), `vl diff` and `vl resolve
--list`:

```text
$ vl resolve --list
C README.md  (conflict: 2 sides)
    ours     public
    base     public
    theirs   public
```

Resolve it in either of two ways:

* **Edit the file.** Once the markers are gone the file is resolved, as you
  left it. If you edit it but leave markers, it stays a conflict: the text
  outside the markers belongs to every side (as in Jujutsu), and each side
  keeps its own section. Deleting the file resolves the conflict as a
  deletion.
* **Keep one version** with `vl resolve PATH --ours`, `--theirs` or
  `--base` (`--side N` for a conflict of more than two sides). The version
  is kept exactly as it was recorded, sealed for whoever it was sealed for.

`vl undo` brings a resolved conflict back. Resolving in `@` leaves the
merge itself marked `(conflict)`; fold the resolution into the merge with
`vl squash` (or `vl edit` the merge and resolve there) to clear it.

Rebases carry conflicts instead of stopping: a rebased change that
conflicts with its new parent holds the conflict, and its descendants move
with it. Rebasing it again onto a parent that already has the change (or
back where it was) resolves it, as in Jujutsu.

Very different versions of a large file (two regenerated lockfiles, a
rewritten bundle) are not compared line by line: past a fixed amount of
work the file gets one conflict holding each version whole between the
markers, after the lines all of them share at the start and end. The same
limit applies to clean merges (such a file then conflicts) and to `vl
diff` (one hunk replaces the differing middle), so no file can stall a
command. `vl status`, `vl ls` and `vl resolve --list` never render a
conflict at all (`vl ls` shows no size for one).

A version you cannot read (sealed for a scope you are not in) is shown in
the markers as a `(not shown: …)` line. You cannot resolve such a conflict:
an edit of the file is held back (it stays local), and deleting it is not a
resolution. A member of the scope resolves it.

Repositories at an older format (before `vl upgrade` to format 4), and
merges under an embargo, still write the markers into the file itself;
such a conflict is resolved by editing the file in the conflicted change.

When one side has a file where the other has a directory of the same name,
both survive: the directory keeps the name, and the file is moved aside to
`NAME~ours` or `NAME~theirs` (the side it came from). Both paths are marked
as conflicted. Move what you need from the file into the directory (or the
other way round), then delete the moved-aside copy.

## Global options and environment

| | |
|---|---|
| `-R, --repository PATH` | Use the repository at `PATH` instead of searching upward from the current directory |
| `--no-snapshot` | Don't record the working copy before the command |
| `VEIL_HOME` | Where your identity lives (default `$XDG_CONFIG_HOME/veil` or `~/.config/veil`) |
| `VEIL_USER` | Your name on new changes (`Name <email>` records an email too) |
| `VEIL_FS_FOLDING` | Override the detected filename case/Unicode folding (see the README's platform notes) |
| `VEIL_MAX_OBJECT` | Largest object a pack may hold when read (default `4G`; a larger declared size is refused as damaged or hostile) |
| `NO_COLOR` | Disable colours (they are off anyway when output is not a terminal) |

Next: [Secrets and visibility](secrets-and-visibility.md).
