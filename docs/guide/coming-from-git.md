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
| merge conflict state | conflicted snapshot | Conflicts are recorded in the snapshot and marked `×`; nothing blocks you |
| remote | remote | A Veil repository at a path or over SSH. Git remotes are separate: `vl git remote` |

## Cheat sheet

| Git | Veil |
|---|---|
| `git init` | `vl init` |
| `git clone URL` (a Git repo) | `vl init proj && cd proj && vl git import URL` ([GitHub](github.md)) |
| `git clone` (a Veil repo) | `vl clone SRC [DEST]` |
| `git status` | `vl status` (`vl st`) |
| `git add …` | *(nothing to do)* |
| `git add -p` | *(no equivalent in 1.0)*: split work by committing in steps |
| `git commit -m MSG` | `vl commit -m MSG` |
| `git commit --amend` | keep editing, or edit `@-` with `vl edit @-`; fold `@` into it with `vl squash` |
| `git commit --amend -m MSG` | `vl describe -r @- -m MSG` |
| `git log --graph` | `vl log` (`-n N` to limit) |
| `git show REV` | `vl show REV` |
| `git diff` | `vl diff` |
| `git diff A B` | `vl diff --from A --to B` |
| `git diff --stat` | `vl diff --stat` |
| `git ls-files` | `vl files` (with each file's visibility) |
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
| `git rebase -i` (squash) | `vl squash -r REV` |
| `git rebase -i` (drop) | `vl abandon REV` |
| `git rebase -i` (reword) | `vl describe -r REV -m MSG` |
| `git stash` / `git stash pop` | `vl new @-` / `vl edit <change>` |
| `git worktree add` | `vl ws new NAME` + `vl ws switch NAME` or `vl ws exec NAME -- CMD` |
| `git reflog`, `git reset HEAD@{1}` | `vl op log`, `vl undo`, `vl op restore ID` |
| `git remote add NAME URL` | `vl remote add NAME URL` (Veil) / `vl git remote add NAME URL` (Git) |
| `git fetch` | `vl pull` / `vl git fetch` |
| `git pull` | `vl pull`, then `vl rebase -d main` |
| `git push` | `vl push` / `vl git push` |
| `git push --force` | `vl push --force` / `vl git push --force` |
| `git tag v1.0` | `vl tag set v1.0 -r REV` (a Veil tag; exported to Git as a **branch**) |
| `.gitignore` entry | `vl ignore PATTERN` |
| `git rm --cached PATH` | `vl ignore PATH` (the file stays on disk, the next snapshot drops it) |
| `git mv A B` | `mv A B` |
| `git gc`, `git fsck` | `vl gc`, `vl fsck` |
| `git revert`, `git cherry-pick`, `git blame`, `git bisect`, `git log -- PATH` | *(no equivalent in 1.0)* |

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

### No interactive commands

There is no editor prompt: `-m` is required for `commit` and `describe`.
There is no interactive hunk selection.

Next: [Using Veil with GitHub](github.md).
