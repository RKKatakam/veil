# Getting started

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
* **`identity.json` holds your private keys.** It is created mode `0600`.
  Back it up somewhere safe: without it you lose access to everything
  cloaked for you, and to your local secret vault (see
  [Maintenance](maintenance.md#backups)).
* It lives in `$VEIL_HOME` (default `$XDG_CONFIG_HOME/veil`, else
  `~/.config/veil`), shared by all your repositories.
* The name defaults to `$VEIL_USER`, then `$USER`. To choose it when the
  identity is created: `vl identity new --name "Alice Doe"`.

**The author recorded on snapshots** is `$VEIL_USER` if set, else the
identity's name. Git only gets an email address if that author has one, so
if you push to GitHub, set it in your shell profile before you start:

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
To start from a Git repository, see [Using Veil with GitHub](github.md).

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
* `vl watch` records continuously, as files change.

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
| `vl files [-r REV]`, `vl cat PATH [-r REV]` | List a snapshot's files with their visibility, or print one |

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
* `vl tag set NAME --cloak [SCOPE]` makes a tag that public remotes and Git
  never see.

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
reports when you use the change id).

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
operation log. That includes the automatic snapshots.

```text
$ vl op log -n 3
c924f35b 2026-11-04 04:07:59 alice commit change yyntkszx
a39343fc 2026-11-04 04:07:59 alice snapshot working copy of 'default'
f1df66f3 2026-11-04 04:07:59 alice set tag main

$ vl undo
Undid: commit change yyntkszx
Working copy now at: yyntkszx 4094f80d (no description set)
```

* `vl undo` undoes the last operation. Run it again to go further back.
* `vl op restore <id>` returns the whole repository (changes, tags,
  workspaces) to the state after operation `<id>`.
* Both **keep the files on disk that you had not recorded yet**: the
  automatic snapshot taken before `undo` is not what gets undone.
* What already left the repository cannot be undone. An **embargo
  release** can be undone only until your next push or Git export; after
  that `vl undo` refuses it ([Embargoes](embargoes.md#the-workflow)).

Other ways to reshape history:

| Command | Effect |
|---|---|
| `vl edit REV` | Make `REV` the working copy: edit an older change in place. Its descendants are rebased automatically |
| `vl abandon [REV]` | Drop a change. Its descendants move onto its parent |
| `vl squash [-r REV]` | Fold a change into its parent |
| `vl rebase -s REV -d DEST` | Move a change and its descendants onto `DEST` (several `-d` for a merge) |
| `vl restore [PATHS…] [--from REV]` | Put files back as they are in `REV` (default `@-`): discards edits |
| `vl merge REVS… [-m MSG]` | Merge into `@` (or into `@-` when `@` is empty), then start a new change on top |

### Conflicts

A merge or rebase that conflicts still succeeds. The files hold conflict
markers, and the snapshot is marked `(conflict)`:

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

A conflict is cleared when you edit the conflicted file **in the
conflicted change itself**. After `vl merge`, that change is `@-`, not `@`,
so `vl status` does not list it (it only lists conflicts in `@`). Resolve it
like this:

```text
$ vl edit wzsvkkoo
$ vl status
…
Unresolved conflicts:
  C README.md
$ $EDITOR README.md
$ vl status
Working copy changes:
M README.md
…
$ vl new
```

Resolving in `@` and then running `vl squash` gives the right content but
leaves the merge marked `(conflict)` in `vl log`.

## Global options and environment

| | |
|---|---|
| `-R, --repository PATH` | Use the repository at `PATH` instead of searching upward from the current directory |
| `--no-snapshot` | Don't record the working copy before the command |
| `VEIL_HOME` | Where your identity lives (default `$XDG_CONFIG_HOME/veil` or `~/.config/veil`) |
| `VEIL_USER` | Your name on new changes (`Name <email>` gives Git an email) |
| `VEIL_GIT` | The `git` binary used by `vl git` |
| `VEIL_SSH` | The `ssh` command used for SSH remotes |
| `VEIL_FS_FOLDING` | Override the detected filename case/Unicode folding (see the README's platform notes) |
| `NO_COLOR` | Disable colours (they are off anyway when output is not a terminal) |

Next: [Coming from Git](coming-from-git.md).
