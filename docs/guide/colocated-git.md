# Colocated Git mode (experimental)

> **Experimental.** Colocated mode puts a real `.git` next to files Veil
> keeps private. Every route by which Git could pick them up is guarded and
> tested (see [What is guarded](#what-is-guarded)); a dedicated adversarial
> pass (round 9) found fifteen holes, and the fix wave closed the critical
> and high ones. It still needs `--experimental` until the Git-version
> matrix and macOS have been run. Know these before you start:
>
> * **`git push --no-verify` skips the push guard.** Use `vl git push` to
>   publish.
> * **Veil's repository lives in `.git/veil`.** `rm -rf .git` deletes it
>   too. Run `vl git uncolocate` first if you mean to throw `.git` away.
> * A tracked **`.gitignore` negation** (`!secrets/`, `!*.md`) outranks
>   everything Veil tells Git; Veil detects it and freezes Git commits, but
>   `git add -A` and `git stash -u` can still take what it un-hides into
>   your local `.git` (see [What Git can still do](#what-git-can-still-do)).

Colocated mode keeps a real Git repository, `.git`, in your project
directory, in step with Veil. IDEs, Git GUIs, `git blame`,
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
or uses SHA-256, when `GIT_DIR` or `GIT_WORK_TREE` is set, while a Git
operation (rebase, merge, cherry-pick, revert, bisect) is in progress, and
when Git tracks a `.veil` (`git rm -r --cached .veil` first).

Files you told Git to ignore your local edits of
(`git update-index --skip-worktree` or `--assume-unchanged`, the usual way
to keep a local `config/database.yml`) stay that way: Veil records the
committed version, never your edit, and keeps the bit. Clear the bit
(`git update-index --no-skip-worktree <file>`) when you want Veil to
record the edit.

```text
  kept config/database.yml (Git was told to hide its local edit; Veil keeps the committed version until you clear the bit)
```

### Where Veil's repository lives

Colocating moves Veil's repository into **`.git/veil`** and leaves `.veil`
as a symlink to it. The work tree is Git's to write: `git checkout`,
`git pull`, `git clean` and `git stash` may replace or delete anything
there (a commit adding a `.veil` file, `git clean -ffdx`), and Git treats
ignored files as expendable. Git never writes inside `.git` itself, so the
repository, its accepted policy and your device keys are out of reach of
anything a Git commit or command does. Veil finds the repository there
directly and never reads `.veil` in a colocated project; if something else
appears at `.veil` (a pulled commit put it there), the next `vl` command
moves it aside, unread, into `.git/veil/local/displaced/` and puts the
symlink back:

```text
warning: something else was at .veil (a Git checkout or pull wrote it?); it was never read and is kept in .git/veil/local/displaced/dot-veil-…
```

`git stash -a` takes the symlink with it; Veil does not put it back until
you pop or drop that stash, so `git stash pop` works. The other side of
this: **`rm -rf .git` now deletes Veil's repository too.**
`vl git uncolocate` moves it back to `.veil`.

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
`Git operation in progress`, and Veil catches up when it ends. The one
exception: a command that would put cloaked or embargoed work on disk
(`vl ws switch` onto a cloaked line, `vl edit` of a sealed change) is
refused meanwhile, because Veil must freeze Git's index first and cannot
while Git holds it:

```text
error: Git is busy (rebase): Veil cannot freeze .git before writing work Git must not see (the working copy is on a line cloaked for 'team'). Finish or abort the Git operation (or wait for the Git command to end), then run this again
```

Branches Veil cannot follow (a name that is not a valid Veil tag, such as
`issue#12`, or the name of a cloaked Veil tag) are left alone: Veil never
deletes a Git ref it did not write, nor moves `HEAD` off such a branch.

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

`vl status` lists held commits until `vl git colocate --prune` deletes the
reflog entries that name them and runs `git gc --prune=now`. Your stashes
and the rest of every reflog (a commit you can still reach with
`git reflog` after `git reset --hard`) are kept.

The `pre-commit` guard Veil installs refuses such a commit in the first
place: anything staged on a cloaked line or under an embargo (decided from
the repository as it is now, not from what the last command saw), a file
Veil hides from Git or keeps local, anything under `.veil`, a path the
policy does not make public, or public content holding a secret.
`git commit --no-verify` skips it; the commit is then superseded as above.

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
as `<name>.veil-chained` and runs first. If you (or a hook manager such as
husky or lefthook) set `core.hooksPath`, Git runs hooks from there and the
guards do not run. Veil never changes it, and every `vl status` warns:

```text
warning: core.hooksPath is set (.husky): Git runs hooks from there, so Veil's pre-commit and pre-push guards do not run. Call `vl git check-push "$@"` from your pre-push hook and `vl --no-snapshot git check-push --pre-commit` from your pre-commit hook, or unset it.
```

`vl status` warns in the same way when a guard hook is missing, and when
Git's sparse checkout is on (`core.sparseCheckout`): Git then rewrites the
skip-worktree bits Veil relies on at every checkout.

## Cloaked work and embargoes: frozen mode

On a cloaked line (`vl ws new … --cloak`), under an unreleased embargo, or
when `@-` cannot be exported, Git sees **nothing** of your work: every index
entry is skip-worktree and `info/exclude` ends with `*`. `git status` and
`git diff` are clean, `git add -A` and `git commit -a` commit nothing, and
`git stash` stores nothing. `HEAD` stays at the last exportable change.
Git refuses checkouts that would change files there ("would be
overwritten"); use `vl new`, `vl edit` or `vl ws switch`. Commit with
`vl commit`. Veil freezes Git *before* it writes cloaked work to disk, so
no Git command running meanwhile (an IDE's background `git add`) ever sees
it.

## What is guarded

| Route | Guard |
|---|---|
| A Git commit writing `.veil/…` (a forged accepted-policy pin) or a file named `.veil`, pulled with `git pull` | the repository is in `.git/veil`, where Git never writes; `.veil` is only a symlink, repaired by the next command (what Git put there is set aside unread); a local commit holding `.veil` is superseded; `pre-commit` refuses `.veil` paths |
| `git clean -fdx`, `git clean -ffdx`, `git stash -a` deleting the repository | the repository is in `.git/veil`, which they never touch |
| `git add -A`, `git add .`, IDE "stage all" | `info/exclude` holds every protective policy rule, the protected files on disk, and `*` in frozen mode, written before every `vl` command returns |
| A tracked `.gitignore` negation (`!secrets/`) that outranks `info/exclude` | detected at every command (Git itself is asked which protected paths it would not ignore): reported, and Git commits freeze until it goes; `pre-commit`, superseding, `pre-push` and `--prune` keep what Git hashed out of commits, remotes and `.git` |
| `git commit -a`, `git diff`, `git stash` of a hidden edit | skip-worktree on every file whose content here may differ from Git's (all of them in frozen mode), set again by every command, and set *before* cloaked work is written; a move onto cloaked work while Git is busy is refused |
| Git clearing skip-worktree (`git sparse-checkout disable`, `git update-index --no-skip-worktree`) | the next `vl` command sets it again; `pre-commit` refuses; superseding; `pre-push` |
| `git add -f`, `--no-verify` commits | superseded, held, never pushed by Veil |
| A Git checkout recording sealed content as public | the working copy follows `HEAD` itself: hidden files are moved by Veil, never taken from Git as public edits |
| A pulled `.veilpolicy` that weakens protection | taken as incoming, held back by the policy you accepted |
| A `.veilpolicy` Git wrote with `HEAD` back where Veil saw it (`git reset --soft` after a pull, `git stash pop`, `git checkout REV -- .veilpolicy`) | an edit of `.veilpolicy` is your own only if Git cannot have written it (see below); anything else is held back like a pull |
| `git push` | `pre-push` guard (except `--no-verify`) |
| `git stash -a`, or a stash made after Git cleared skip-worktree | `refs/stash` is never imported nor pushed; what a stash holds that Veil hides is reported at the next command |
| Your own skip-worktree / assume-unchanged bits | the edits stay unrecorded and the bits are kept |
| `git checkout` expanding `$Id$` (`ident`) | `info/attributes` turns `ident` off in the colocated work tree |
| `core.hooksPath` turning the guards off | every `vl status` warns |
| A tree with `.git`, `.GIT`, … | refused on import and on checkout, as everywhere in Veil |
| A Git commit racing a `vl` command | every ref and `HEAD` write is a compare-and-swap; Veil never waits for or removes a Git lock |

## Your edits of `.veilpolicy`

Git may write `.veilpolicy` between two `vl` commands by many routes, and
not all of them move `HEAD`: `git reset --soft HEAD~1` after a pull leaves
the pulled policy in the work tree as if you had typed it. So in colocated
mode an edit of `.veilpolicy` counts as yours (and is accepted at once,
even where it weakens the policy) only when Git cannot have written it:

* no Git operation is in progress, and the file has no conflict (no
  unmerged entries in Git's index, no conflict-marker lines);
* its content, cleaned as `git add` would clean it, is not a blob Git
  already has (pulled, stashed, or staged).

Anything else is guarded like a pull: rules that only add protection, and
a policy never weaker than the one you accepted, apply and are accepted;
what weakens protection waits for `vl policy accept`, and every command
says so. `vl cloak`, `vl isolate`, `vl expose` and `vl ignore` always
record exactly the rule they add as yours. If you `git add .veilpolicy`
before any `vl` command sees your edit, Git has the blob, so a weakening
edit then waits for `vl policy accept`.

## What Git can still do

These are leaks or losses by explicit Git action, all local to your
machine. Veil cannot stop them, because Git runs no hook for them; it
reports them at the next command.

* **A `.gitignore` negation** (`!secrets/`, `!.env`, `!*.md`, or an
  allow-list `.gitignore` that starts with `*` and re-includes what it
  keeps) outranks Veil's `info/exclude`: Git ranks every `.gitignore`
  above it, and nothing ranks above a `.gitignore`. Veil asks Git which
  protected paths it would no longer ignore, at every command that
  changed something:

  ```text
  warning: a .gitignore negation un-hides 2 protected path(s) from Git, and Git ranks .gitignore above Veil's excludes:
    exposed secrets/veil-probe (.gitignore:1: !secrets/)
    exposed .env (.gitignore:2: !.env)
  hint: `git add -A` and `git stash -u` would take such files. Git commits are frozen until the negation goes (commit its removal with `vl commit`); `vl git push` still sends only the public view.
  ```

  Until you remove the negation, `git add -A` hashes such a file into
  `.git` (a loose object, never committed by the guards, never pushed;
  `vl git colocate --prune` removes it once it is no longer staged) and
  `git stash -u` stores it in a stash and deletes it from disk
  (`git stash pop` brings it back).
* **`git stash -a`** stores ignored files, including cloaked and isolated
  plaintext, in a stash in `.git` and deletes them from disk; a stash made
  after Git **cleared skip-worktree** (`git sparse-checkout`,
  `git update-index --no-skip-worktree`) stores the hidden edit. A stash is
  never pushed by `git push` (the guard refuses `refs/stash`), but
  **`git bundle create --all`** and `git fast-export --all` include it.
  `vl status` names such a stash until it is dropped:

  ```text
  warning: Git's stash@{0} holds .env (isolated): content Veil keeps from Git is in a local stash (never pushed by `git push`, but `git bundle --all` carries it). Recover what you need (`git stash show -p`), then `git stash drop` it and `vl git colocate --prune`
  ```
* **`git clean -fdx`** (and `-ffdx`) deletes ignored files, cloaked and
  isolated ones included. Veil recorded cloaked files into `@` at your last
  `vl` command and keeps isolated files in the vault: `vl undo`,
  `vl restore` and `vl secret recover` bring them back. Only edits made
  since the last `vl` command are lost (`vl watch` narrows that).
* A **`git checkout`** of an old commit that has a file you have since
  cloaked or isolated overwrites your copy without asking (Git treats
  ignored files as expendable, and no Git hook can stop a checkout from
  writing). The next command says so and keeps the version Veil recorded
  in the previous change:

  ```text
  warning: Git's checkout overwrote secrets/db.yml (a file Veil hides from Git, which Git treats as expendable). Your version as of the last vl command is kept in change uyxntzkt: `vl restore --from uyxntzkt secrets/db.yml`. An edit made since then is lost
  ```

  An edit made since the last `vl` command is lost (`vl watch` narrows
  that). Putting such files in Git's index so that Git refused would show
  them as staged new files in `git status` and make `pre-commit` refuse
  every commit.
* After Git **clears skip-worktree**, `git add` hashes the hidden file into
  a loose object in `.git` (local, never committed by the guards, never
  pushed). `vl git colocate --prune` removes it.
* Checkout **filters** (Git LFS's `filter=lfs`) still run: Veil records
  the file as it is on disk (the full content, not the pointer).
* `info/exclude` holds the **names** of protected files in plaintext, as
  `vl status` shows them; it is local and never pushed.
* A commit you pull with `git pull <url>` (not through a configured
  remote's tracking branch) is treated as local: if it differs from what
  Veil records (for example its `.veilpolicy` edit is held back), it is
  superseded on your branch.

## Status, pruning, stopping

```sh
vl git colocate --status     # excludes, skip-worktree count, frozen?, hooks, held commits, exposures, stashes, Git version
vl git colocate --prune      # held commits leave .git (stashes and the rest of the reflog stay)
vl git uncolocate            # stop: .git stays, a plain Git repository
```

`vl git uncolocate` keeps the guards that keep protected files out of Git:
the exclude block stays in `.git/info/exclude` (so `git add -A` still
leaves `.env`, cloaked files and `.veil` alone), and so do the
skip-worktree bits of files whose content here is not Git's. It removes
the hooks (restoring chained ones; they need colocation) and the
`info/attributes` block, moves Veil's repository back from `.git/veil` to
`.veil`, and lists every file that holds content Veil keeps private:

```text
Stopped colocation: /home/alice/p/.git is a plain Git repository again
kept: the exclude block stays in /home/alice/p/.git/info/exclude (edit it away only if you mean Git to see these files)
warning: 2 file(s) here hold content Veil keeps private; never `git add -f` them:
  protected .env
  protected secrets/db.yml
warning: Git's pre-commit and pre-push guards are removed: nothing stops `git add -f` or a push of a commit made with it
```

It is refused on a cloaked line or under an embargo (a plain Git would see
that work): `vl ws switch` to a public line first. The repository stays at
format 5, so an older `vl` never works in a directory whose guards it
would not keep.

## Where colocation does not apply

`vl ws exec` sandboxes, `--only` sparse sandboxes and mounted workspaces
have no `.git` of their own (in a colocated project they live in
`.git/veil/local/`, where Git commands find no work tree). The team vault
is untouched.

## Tested Git versions

The test suite (`crates/vl/tests/colocated_git_cli.rs`, the interleaving
property test `colocated_git_props.rs`, and the round-9 adversarial tests
`adversarial9_colocated/`) runs with whatever `git` is installed and prints
its version; this release was tested with Git 2.53 on Linux. The
Git-version matrix and macOS (where `.VEIL` and `.veil` are one name) are
not run yet, which is why the mode is experimental.
