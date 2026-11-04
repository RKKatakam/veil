# Coming from Git

Veil's model is close to [Jujutsu](https://github.com/jj-vcs/jj)'s: the
working copy is a change, changes have stable ids, and every operation can
be undone. Add to that per-file encryption and engine-level secret handling.

## Concept map

| Git | Veil | Notes |
|---|---|---|
| commit | **snapshot** | Content-addressed (BLAKE3), signed by its author's key. Every `vl` command records one for the working copy |
| — | **change** | A unit of work with a stable **change id** (`yltznuyx`) that survives rewrites. Each version of it is a snapshot |
| `HEAD` + working tree | **`@`**, the working-copy change | Your files *are* a change, recorded on every command |
| index / staging area | *(none)* | Everything not ignored, isolated or quarantined is recorded |
| branch | **tag** | A named pointer. It follows rewrites and moves on `commit`, `merge` and pulls, never otherwise ([pitfalls](#pitfalls)) |
| `origin/main` | `origin/main` | A remote tag, updated by `vl pull`/`vl push` (or `vl git fetch` for Git remotes) |
| detached HEAD | *(normal)* | `@` never needs a tag |
| stash | *(not needed)* | Edits are already recorded in their change: `vl new @-` starts something else, `vl edit <change>` goes back |
| worktree | **workspace** | Virtual: exists in the repository, no directory needed ([Workspaces](workspaces-and-agents.md)) |
| reflog | **operation log** | Repository-wide, includes tags and workspaces: `vl op log`, `vl undo`, `vl op restore` |
| `.gitignore` | **`.veilpolicy`** | Also says what is cloaked (encrypted), isolated (local-only) or public ([Secrets and visibility](secrets-and-visibility.md)) |
| `git-crypt`, separate private repos | **cloaking** | `vl cloak secrets/`: encrypted for a scope, in the same repository |
| merge conflict state | conflicted snapshot | Conflicts are recorded in the snapshot as data and marked `×`; nothing blocks you. `vl resolve --list` lists them, `vl resolve PATH --ours` (or `--theirs`) picks a side |
| remote | remote | A Veil repository at a path or over SSH. Git remotes are separate: `vl git remote` |

## Cheat sheet

| Git | Veil |
|---|---|
| `git init` | `vl init` |
| `git clone URL` (a Git repo) | `vl init proj && cd proj && vl git import URL` ([GitHub](github.md)) |
| `git clone` (a Veil repo) | `vl clone SRC [DEST]` |
| `git status` | `vl status` (`vl st`) |
| `git add …` | *(nothing to do)* |
| `git add -p` | *(nothing to stage)*: `vl split -i` afterwards, to cut the change into the hunks you choose and the rest |
| `git commit -m MSG` | `vl commit -m MSG` |
| `git commit --amend` | keep editing, or edit `@-` with `vl edit @-`; fold `@` into it with `vl squash` |
| `git commit --amend -m MSG` | `vl describe -r @- -m MSG` |
| `git log --graph` | `vl log` (`-n N` to limit) |
| `git show REV` | `vl show REV` |
| `git diff` | `vl diff` |
| `git diff A B` | `vl diff --from A --to B` |
| `git diff --stat` | `vl diff --stat` |
| `git ls-files` | `vl ls` (with each file's tier: public, cloaked, isolated, …) |
| `git push --dry-run` | `vl push --dry-run` (also: what would become public, and what is withheld) |
| `git show REV:PATH` | `vl cat PATH -r REV` |
| `git checkout -- PATH`, `git restore PATH` | `vl restore PATH` (from `@-`, or a merge's merged parents; `--from REV` for another) |
| `git reset --hard` | `vl restore` (every path, from `@-`) |
| `git switch BRANCH` | `vl new BRANCH` (start on top of it) or `vl edit REV` (edit it in place) |
| `git switch -c NAME` | `vl new main`, work, then `vl tag set NAME -r @-` after committing |
| `git branch` | `vl tag list` |
| `git branch -f NAME REV` | `vl tag set NAME -r REV --allow-backwards` |
| `git branch -d NAME` | `vl tag delete NAME` |
| `git merge X` | `vl merge X` |
| `git rebase main` | `vl rebase -s FIRST -d main`, where `FIRST` is the first change of your line (`vl rebase -d main` alone moves only `@` and its descendants) |
| `git rebase --onto D X` | `vl rebase -s X -d D` |
| `git rebase -i` (squash) | `vl squash -r REV` (`vl squash -i`, or `vl squash PATHS`, moves only part) |
| `git rebase -i` (edit, to split a commit) | `vl split -r REV PATHS…` or `vl split -r REV -i` |
| `git rebase -i` (drop) | `vl abandon REV` |
| `git rebase -i` (reword) | `vl describe -r REV -m MSG` |
| `git stash` / `git stash pop` | `vl new @-` / `vl edit <change>` |
| `git worktree add` | `vl ws new NAME` + `vl ws switch NAME` or `vl ws exec NAME -- CMD` (each workspace keeps its own sandbox directory, synced incrementally) |
| `git reflog`, `git reset HEAD@{1}` | `vl op log`, `vl undo`, `vl op restore ID` |
| `git remote add NAME URL` | `vl remote add NAME URL` (Veil) / `vl git remote add NAME URL` (Git) |
| `git fetch` | `vl pull` / `vl git fetch` |
| `git pull` | `vl pull`, then `vl rebase -d main` |
| `git push` | `vl push` / `vl git push` |
| `git push --force` | `vl push --force` / `vl git push --force` |
| `git tag v1.0` | `vl tag set v1.0 -r REV` (a Veil tag; exported to Git as a **branch**) |
| `git tag -a v1.0 -m MSG` | `vl tag set v1.0 -r REV -a -m MSG` (a signed, immutable **release tag**; a Git tag on `vl git push`) |
| `git tag -v v1.0` | `vl tag verify v1.0` |
| `git push --tags` | `vl git push` (release tags the remote lacks are pushed; never forced: `--force-tags`) |
| `git push origin :refs/tags/v1.0` | `vl tag delete v1.0`, then `vl git push --delete-tag v1.0` |
| `git submodule update --init` | `vl submodule update` |
| `git submodule add URL PATH` | `vl submodule add URL PATH` |
| `.gitignore` entry | `vl ignore PATTERN` |
| `git rm --cached PATH` | `vl ignore PATH` (the file stays on disk, the next snapshot drops it) |
| `git mv A B` | `mv A B` |
| `git gc`, `git fsck` | `vl gc`, `vl fsck` |
| `.git/hooks/pre-commit` | `.veil/hooks/pre-commit`, or a repository's `.veilhooks` once you `vl hooks trust` it ([Hooks](hooks.md)) |
| `git commit --no-verify` | `vl commit --no-verify` |
| `git blame`, `git grep`, `git bisect`, `git log -S`/`-G`/`--follow`/`-- PATH` | `vl blame`, `vl grep`, `vl bisect`, `vl log -S`/`-G`/`--follow`/`-- PATH` ([Investigating history](investigating-history.md)) |
| `git format-patch A..B` | `vl format-patch A..B` (the public view: what `vl git push` would show; [details](github.md#patches-by-mail-vl-format-patch-and-vl-am)) |
| `git format-patch -M -C --binary` | `vl format-patch -M -C --binary` (`-M=N` for a threshold; [details](github.md#renames-symlinks-submodules-and-binary-files)) |
| `git am FILE`, `git am -3` | `vl am FILE`, `vl am -3` (new changes on `@-`, all or nothing; a 3-way conflict is recorded in the change) |
| `git revert`, `git cherry-pick` | *(no equivalent in 1.0)* |

## Pitfalls

### `vl commit` moves the tags at the parent

`vl commit` moves **every tag that pointed at the parent of `@`** onto the
change it commits, in any workspace (a cloaked one excepted, below):

```text
$ vl new main
$ echo other > other.txt
$ vl commit -m "Other line"
Committed vnuopxqm 39c00acd Other line
$ vl tag list
main: vnuopxqm 39c00acd Other line
```

That is what you want on `main`. It is not what you want when the work
must stay off `main` for now: a security fix, an experiment you intend to
merge later. For those:

* In a **cloaked workspace** (`vl ws new NAME --cloak`), `vl commit` moves
  only tags cloaked under the same scope. `main` and other uncloaked tags
  stay, and `vl` says so (`note: main not moved: this is a line cloaked
  for 'team' …`). Cloaked work reaches `main` only through `vl merge`
  (optionally `--embargo`) or `vl tag set`. The [embargo guide](embargoes.md)
  shows the workflow.
* Anywhere, `vl commit --no-advance` moves no tag, and `vl describe`
  records a message without committing.

### Tags don't move by themselves otherwise

* `vl new main` and editing do **not** move `main`. Only committing does.
* `vl merge X` moves the tags that pointed at the change merged *into*.
* `vl pull` and `vl git pull` fast-forward tags from the remote. They never
  move your working copy: run `vl rebase -d main` (or `vl new main`)
  afterwards.
* `vl push` and `vl git push` send **tags**, not your working copy. A change
  no tag points at is not pushed. Tag it first (`vl tag set main -r @-`).
* A tag that diverged from the remote is reported and left alone. Merge
  (`vl merge origin/main`) and push again.

### Every command records the disk

Including `vl log`. A half-written file is recorded as it is at that
moment. That is harmless (keep editing; the next snapshot replaces it in the
same change), but it means:

* **To drop an edit**, use `vl restore PATH`. Deleting the file records a
  deletion.
* **Files you never want recorded** go in `.veilpolicy` (`vl ignore`,
  `vl isolate`) *before* the next command. Build output in `target/` and
  `node_modules/` is ignored by the default policy.
* `vl --no-snapshot …` looks without recording.

### `vl pull` doesn't update your files

A pull updates tags (`main`, `origin/main`). Your working copy is a change
of your own, and moving it would rewrite it under you. Rebase it when you
want the pulled commits: `vl rebase -d main`.

### Merges

`vl merge X` merges into `@`, or into `@-` if `@` is empty (the usual case
right after a commit), and then starts a new change on top. Conflicts don't
stop the merge: see [Conflicts](getting-started.md#conflicts), including how
to clear the `(conflict)` mark.

### Secrets don't get committed, even if you try

A `.env` is never recorded, and a public file containing something that
looks like a credential is **quarantined**: `vl` warns and leaves it out
(or keeps its previous, clean version). `vl status` shows such files as `L`
and `Q`. See [Secrets and visibility](secrets-and-visibility.md#quarantine).

### Symlinks and submodules

A repository in format 5 (new repositories, or `vl upgrade`) records
symlinks as Git does: the link itself, mode `120000`, whose content is its
target string. Veil never follows one, for reading or writing.

```text
$ ln -s ../lib/tool.sh bin/tool
$ vl status
A bin/tool
$ vl ls bin
public                    14  bin/tool -> ../lib/tool.sh
$ vl diff
diff --veil a/bin/tool b/bin/tool
added file public
symlink bin/tool -> ../lib/tool.sh
new file mode 120000
$ vl cat bin/tool -r @-
../lib/tool.sh
```

* A link is classified by **its own path**: a link under a cloaked
  directory has its target sealed (`vl ls` shows `-> (target not shown)`
  to someone without the key, and a public remote never receives it), a
  link named `id_rsa` is isolated, and a target holding a token
  (`https://user:ghp_…@github.com/…`) is quarantined like a file. What the
  link points at is never read: `notes -> ~/.ssh/id_rsa` records the
  path, not the key.
* A link that points outside the repository (an absolute path, or `..`
  above the root) is recorded as it is, with a warning the first time:
  Veil never follows it, but your editor, build scripts and agents will.
  A link to a file the policy isolates records the name only.
* A file replaced by a link (or the reverse) shows as `T path (file →
  symlink)`; the old version stays in history.
* **Checkout never writes through a link.** A link is replaced or removed
  only when it is the version Veil wrote; a link you changed is kept. A
  path below a link (`vendor -> /shared/vendor` and a tree with
  `vendor/x`) is skipped, and every write opens each directory with
  `O_NOFOLLOW`, so even a directory swapped for a link while checkout runs
  receives nothing. On macOS a tree with both `A` (a link) and `a/` is
  refused before anything is written.
* A link/link or link/file **conflict** is written as one side, as it is
  (yours, unless you deleted it): never a file of markers holding a link
  target. `vl resolve --ours|--theirs` picks one and gets the right kind;
  replacing the link with a file (or editing it) resolves it too.
* `.veilpolicy` is never recorded as a link: a symlinked policy is read
  through, as before. A link named `.git` (or `.jj`, `.hg`, `.svn`) is VCS
  metadata and never recorded.
* **Submodules** (gitlinks, from a Git import or `vl submodule`) are
  carried: checkout makes the submodule's directory, empty, and Veil never
  records anything inside it, never reads its `.git`, and never removes it
  while it holds files.
* Where the filesystem cannot hold symlinks, checkout reports each link
  (`failed: … cannot hold symlinks`) and keeps it in history untouched.
* Below format 5 links stay invisible (never recorded, never followed;
  a tracked file replaced by one keeps its entry): `vl upgrade` to record
  them.

### No interactive commands

There is no editor prompt: `-m` is required for `commit` and `describe`.
There is no interactive hunk selection.

Next: [Using Veil with GitHub](github.md).
