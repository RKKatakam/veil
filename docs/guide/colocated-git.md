# Colocated Git mode (experimental)

> **Experimental.** Colocated mode puts a real `.git` next to files Veil
> keeps private. Every route by which Git could pick them up is guarded and
> tested (see [What is guarded](#what-is-guarded)), but the mode has not yet
> been through its own dedicated adversarial review. It needs
> `--experimental`, and the guards have one documented hole you must know
> about: **`git push --no-verify` skips the push guard.** Use `vl git push`
> to publish.

Colocated mode keeps a real Git repository, `.git`, beside `.veil` in your
project directory, in step with Veil. IDEs, Git GUIs, `git blame`,
`git log`, pre-commit frameworks and every other tool that reads `.git`
keep working, and you can mix `git` and `vl` commands in the same
directory.

Git only ever sees the **public view**: exactly what a `--public` Veil
remote or GitHub would receive (see [Using Veil with GitHub](github.md)).
Cloaked files, isolated files (`.env`, keys), quarantined edits, cloaked
descriptions and tags, and the content of unreleased embargoes are not in
`.git`, and Git cannot add them.

## Starting

A new project with both:

```sh
vl init --colocate --experimental
```

An existing Git checkout (Veil adopts it):

```sh
cd my-git-project
vl init --colocate --experimental
```

```text
  added /config/master.key ignore  (from .gitignore:1; ignores config/master.key)
  added *.tfvars ignore  (from .gitignore:2; ignores prod.tfvars)
Initialized Veil repository in /home/alice/my-git-project/.veil
…
Imported 12 commit(s) from the colocated .git
Adopted the working copy is a change on Git's HEAD (3f2a9c1e04); uncommitted Git edits are its changes
Colocated /home/alice/my-git-project/.git with Veil (experimental). Git sees the public view only; see docs/guide/colocated-git.md
```

Before Veil records anything, every `.gitignore` pattern that ignores an
existing file becomes an `ignore` rule in `.veilpolicy`
(`vl policy import-gitignore` does the same later), so files Git ignores are
not recorded just because Veil never read `.gitignore`. After that,
`.veilpolicy` is the only policy: a teammate's `.gitignore` edit never
weakens what Veil protects.

An existing Veil working copy (it must be at repository format 5,
`vl upgrade`):

```sh
vl git colocate --experimental
```

Adoption is refused when `.git` is a file (a linked worktree or a
submodule) or a symlink, when the repository is bare, sets `core.worktree`
or uses SHA-256, when `GIT_DIR` or `GIT_WORK_TREE` is set, and while a Git
operation (rebase, merge, cherry-pick, revert, bisect) is in progress.

## Day to day

Use either tool. After every `vl` command:

* Veil tags are Git branches (`main` ↔ `refs/heads/main`), release tags are
  Git tags, and `HEAD` is the parent of your working copy (`@-`), on its
  branch when exactly one tag points there;
* new Git commits on local branches are Veil changes, and the branch's tag
  follows it (a rewritten branch keeps Veil's old version visible: nothing
  Git could not see is dropped);
* a `git checkout`, `git switch`, `git reset` or `git commit` moves the
  working copy with `HEAD`. Edits Git cannot see (your cloaked files) are
  carried along like Git carries unstaged edits; when the checked-out commit
  changes the same hidden file, your version stays in the previous change
  (it is printed) and the file takes the commit's.

```sh
git checkout -b feature        # Git
echo fix > a.c && git commit -am "Fix a.c"
vl status                      # Veil follows: tag `feature`, @ on top of the commit
vl commit -m "More"            # Veil: Git sees branch feature move
git log --oneline              # both commits, with Veil's description
```

Veil writes nothing while a Git operation is in progress (a rebase, a
merge, or a Git command holding `index.lock`, such as a pre-commit hook
calling `vl status`): commands work as usual, say
`Git operation in progress`, and Veil catches up when it ends.

## Commits made in Git

A commit you make with Git is kept as it is when it holds only what Veil
would export itself. When it holds something Veil keeps private (you forced
a cloaked file in with `git add -f`, or a secret Veil quarantines), Veil
**supersedes** it: it writes the public version of the same change,
moves your branch to it, and holds the original:

```text
Imported 1 commit(s) from the colocated .git
  held local Git commit f071bc3d0c holds secrets/new.yml (cloaked:team) (Veil keeps it private); replaced by 24c967b842 on its branch
note: the held commit(s) stay in .git until `vl git colocate --prune`; `git push` refuses them
```

`vl status` lists held commits until `vl git colocate --prune` expires
Git's reflogs (every unreachable reflog entry of `.git`) and runs
`git gc --prune=now`.

The `pre-commit` guard Veil installs refuses such a commit in the first
place: anything staged on a cloaked line or under an embargo, a file Veil
hides from Git, a path the policy does not make public, or public content
holding a secret. `git commit --no-verify` skips it; the commit is then
superseded as above.

## Pushing

`vl git push <remote>` is the way to publish: it sends Veil's export, never
a held commit. A plain `git push` runs the `pre-push` guard
(`vl git check-push`), which refuses held commits, commits Veil has not
imported yet (run `vl status` and push again) and `refs/stash`:

```text
error: Veil refuses this Git push (colocated guard):
  refs/heads/main: commit f071bc3d0c is held: holds secrets/x.yml (cloaked:team); Veil replaced it with 24c967b842
hint: `vl git push origin` pushes Veil's public view. `git push --no-verify` skips this check and can publish private content
```

**`git push --no-verify` skips the guard** (Git does not run the hook).
Nothing else can stop a deliberate bypass; `vl git colocate --status` shows
whether the hooks are installed and intact. A hook you had before is kept
as `<name>.veil-chained` and runs first. If you set `core.hooksPath`, Git
runs hooks from there and the guards do not run (Veil never changes it;
`--status` says so): call `vl git check-push "$@"` from your own `pre-push`.

## Cloaked work and embargoes: frozen mode

On a cloaked line (`vl ws new … --cloak`), under an unreleased embargo, or
when `@-` cannot be exported, Git sees **nothing** of your work: every index
entry is skip-worktree and `info/exclude` ends with `*`. `git status` and
`git diff` are clean, `git add -A` and `git commit -a` commit nothing, and
`git stash` stores nothing. `HEAD` stays at the last exportable change.
Git refuses checkouts that would change files there ("would be
overwritten"); use `vl new`, `vl edit` or `vl ws switch`. Commit with
`vl commit`.

## What is guarded

| Route | Guard |
|---|---|
| `git add -A`, `git add .`, IDE "stage all" | `info/exclude` holds every protective policy rule, the protected files on disk, and `*` in frozen mode, written before every `vl` command returns |
| `git commit -a`, `git diff`, `git stash` of a hidden edit | skip-worktree on every file whose content here may differ from Git's (all of them in frozen mode), set again by every command |
| Git clearing skip-worktree (`git sparse-checkout disable`, `git update-index --no-skip-worktree`) | the next `vl` command sets it again; `pre-commit` refuses; superseding; `pre-push` |
| `git add -f`, `--no-verify` commits | superseded, held, never pushed by Veil |
| A Git checkout recording sealed content as public | the working copy follows `HEAD` itself: hidden files are moved by Veil, never taken from Git as public edits |
| A pulled `.veilpolicy` that weakens protection | taken as incoming, held back by the policy you accepted |
| `git push` | `pre-push` guard (except `--no-verify`) |
| `git stash -a` | `refs/stash` is never imported nor pushed |
| `git clean -fdx`, `git stash -a` deleting `.veil` | `.veil/.git` marks `.veil` as a nested repository, which Git leaves alone (except `git clean -ffdx`) |
| A tree with `.git`, `.GIT`, … | refused on import and on checkout, as everywhere in Veil |
| A Git commit racing a `vl` command | every ref and `HEAD` write is a compare-and-swap; Veil never waits for or removes a Git lock |

## What Git can still do

* **`git stash -a`** stores ignored files, including cloaked and isolated
  plaintext, in `.git/objects` (local, never pushed) and deletes them from
  disk; **`git clean -fdx`** deletes them. Veil recorded cloaked files into
  `@` at your last `vl` command and keeps isolated files in the vault:
  `vl undo`, `vl restore` and `vl secret recover` bring them back. Only edits
  made since the last `vl` command are at risk (`vl watch` narrows that).
* A **`git checkout`** of an old commit that has a file you have since
  cloaked or isolated overwrites your copy without asking (Git treats
  ignored files as expendable). The same recovery applies.
* After Git **clears skip-worktree**, `git add` hashes the hidden file into
  a loose object in `.git` (local, never committed by the guards, never
  pushed). `vl git colocate --prune` removes it.
* `info/exclude` holds the **names** of protected files in plaintext, as
  `vl status` shows them; it is local and never pushed.
* A commit you pull with `git pull <url>` (not through a configured
  remote's tracking branch) is treated as local: if it differs from what
  Veil records (for example its `.veilpolicy` edit is held back), it is
  superseded on your branch.

## Status, pruning, stopping

```sh
vl git colocate --status     # excludes, skip-worktree count, frozen?, hooks, held commits, Git version
vl git colocate --prune      # expire reflogs, gc: held commits leave .git
vl git uncolocate            # stop: .git stays, a plain Git repository
```

`vl git uncolocate` removes the exclude block, the hooks (restoring chained
ones), the skip-worktree bits and the `.veil/.git` marker, and moves the
bridge back to `.veil/git/repo.git`. Files Veil hid from Git then show in
`git status`; some hold content Veil keeps private: do not `git add` them.
The repository stays at format 5, so an older `vl` never works in a
directory whose guards it would not keep.

## Where colocation does not apply

`vl ws exec` sandboxes, `--only` sparse sandboxes and mounted workspaces
have no `.git`. The team vault is untouched.

## Tested Git versions

The test suite (`crates/vl/tests/colocated_git_cli.rs`, the interleaving
property test `colocated_git_props.rs`) runs with whatever `git` is
installed and prints its version; this release was tested with Git 2.53 on
Linux. Git-version-specific behaviour of skip-worktree is the main reason
the mode is experimental.
