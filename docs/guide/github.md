# Using Veil with GitHub

Keep GitHub (or GitLab, or any Git host) for CI, code review and the
public: Veil tags become Git branches, and Git commits become Veil
snapshots. Git only ever sees what a **public** Veil remote would see.

1. [Start from an existing Git repository](#start-from-an-existing-git-repository)
2. [Push and pull](#push-and-pull)
3. [What GitHub sees, and never sees](#what-github-sees-and-never-sees)
4. [Round trips](#round-trips)
5. [Divergence](#divergence)
6. [Credentials and authorship](#credentials-and-authorship)
7. [Limits in 1.0](#limits-in-10)

## Start from an existing Git repository

```text
$ vl init my-project && cd my-project
$ vl git import git@github.com:me/my-project.git
  updated main → 80a91b59
Imported 1 commit(s) from origin
Working copy is now a change on main
Updated 1 files, removed 0
Working copy now at: krqvyyzm 692245f1 (no description set)

$ vl log
@  krqvyyzm alice ✓ 2026-11-04 04:10:07 default@ 692245f1
│  (no description set)
○  qzknoozp Alice <a@x> ✓alice 2026-11-04 04:10:07 main origin/main 80a91b59
│  Initial commit
◆  zzzzzzzz 72edc798
   root()
```

`vl git import SOURCE [--remote NAME]`:

* imports every branch's history, with authors, dates and messages; each
  branch becomes a tag (`main`) and a remote tag (`origin/main`);
* adds `SOURCE` as a Git remote called `origin` (see `vl git remote list`);
* on a fresh `vl init`, moves the working copy on top of `main` (or
  `master`/`trunk`), keeping its files. The new `.veilpolicy` from `vl init`
  is then a change of yours on top of `main`;
* signs the imported snapshots with your key (`✓alice` above: authored by
  `Alice <a@x>`, signed by alice, who imported it);
* applies your policy to everything it imports. A committed `.env`, or a file
  the scanner flags, is **not recorded** and is reported (it stays in Git):

```text
$ vl git pull
  not recorded .env (isolated by policy; it stays in Git)
  not recorded leak.js (quarantined (aws-access-key-id); it stays in Git)
  updated main → f2343f59
Imported 1 commit(s) from origin
```

`SOURCE` is anything `git` understands, or a local path. The bridge (a bare
Git repository) lives in `.veil/git/`.

## Push and pull

```sh
vl cloak secrets/                 # Veil-only from here on (see below)
vl commit -m "Add app and ops notes"
vl git push                       # every tag → a branch of the same name
```

```text
$ vl git push
Exported 1 commit(s)
  pushed main → 3439940773
```

| Command | Does |
|---|---|
| `vl git push [REMOTE] [-t TAG…]` | Export tags (all by default, except cloaked ones) as branches and push them |
| `vl git push --force` | Overwrite branches that moved on the Git side, but only if they still hold what you last fetched |
| `vl git fetch [REMOTE]` | Import new commits; update `REMOTE/BRANCH` remote tags. Local tags don't move |
| `vl git pull [REMOTE]` | Fetch, then create or fast-forward local tags from the branches |
| `vl git export [-t TAG…]` | Export into the local bridge without pushing; print each branch's commit |
| `vl git remote add\|list\|rm` | Manage Git remotes (separate from `vl remote`) |

**Only tags are pushed**, so a change must be tagged to reach GitHub. If you
commit on top of `main`, `vl commit` moves `main` for you (it moves tags
that pointed at the parent). Otherwise: `vl tag set main -r @-`.

**A pull never moves your working copy.** After `vl git pull`, rebase onto
the new `main` when you want the commits on disk:

```text
$ vl git pull
  updated main → b3a42769
Imported 1 commit(s) from origin
$ vl rebase -d main
Rebased srllptsq 7c959b8d (empty) (no description set)
Updated 1 files, removed 0
Working copy now at: srllptsq 7c959b8d (empty) (no description set)
```

Branches map to tags by name. Git **tags** (`v1.0` in Git) are neither
imported nor exported in 1.0, only branches. A Veil tag `v1.0` becomes a
Git *branch* `v1.0`.

## What GitHub sees, and never sees

Git sees exactly what a `--public` Veil remote sees.

| In Veil | On GitHub |
|---|---|
| Public files | As they are |
| Cloaked files (`vl cloak`) | **Absent.** A directory left empty disappears |
| Isolated files (`.env`, keys…) | Absent: they were never recorded |
| A description of a cloaked change | `(description withheld: cloaked)` |
| A snapshot made in a cloaked workspace | A commit with the author, the time and the placeholder message, and none of the cloaked files |
| A cloaked tag (`vl tag set --cloak`) | No branch: `skipped notes (cloaked tag is never exported to Git)` |
| An unreleased embargoed merge | The pre-merge tree, message `(description withheld: under embargo)`, and none of the fix's history |
| After `vl embargo release` | The next push adds one commit that publishes the fix and links its history |
| Change id | A `change-id` commit header (the one Jujutsu uses) |
| Your Veil signature | Not exported: Git commits are unsigned |

For example, a change described "Secret roadmap" in a cloaked workspace,
tagged `main` and pushed:

```text
$ git log -1 --format='%an %s'
alice (description withheld: cloaked)
```

What GitHub **does** learn, by design: the names and contents of public
files, who committed when, and that a cloaked or embargoed change *exists*
(an empty-looking commit). History imported from Git is public by
definition: cloaking a path later does not remove it from Git's history.
Everything committed before you cloaked a path stays readable in those
older commits. `vl cloak` warns when that is the case.

## Round trips

* **Commits made on GitHub never delete your cloaked files.** A Git commit
  never saw them, so Veil applies it on top of the full Veil tree. After a
  GitHub edit and `vl git pull`, `secrets/ops.md` is still there:

  ```text
  $ vl files -r main
  public                   887  .veilpolicy
  public                    18  README.md
  public                    18  app.py
  cloaked:team              11  secrets/ops.md
  public                     8  x.txt
  ```

* **Paths Git has but Veil refuses** (a committed `.env`, a quarantined
  file, symlinks, submodules) are reported, stay in Git, and are never
  deleted there by a later Veil push.
* **A Git commit that would widen a cloaked path's audience** by editing
  `.veilpolicy` is not taken. The import warns and keeps the Veil policy.
* **Deterministic.** The same snapshot always exports to the same commit,
  on any machine. `.veil/git/map` records commit ↔ snapshot.
* **Pull requests** work as usual. Push a tag for the branch
  (`vl tag set my-feature -r @-`, `vl git push -t my-feature`), open the PR
  on GitHub, and `vl git pull` after it is merged.

## Divergence

Divergence is reported, never resolved by losing data.

When someone pushed to the branch since your last fetch, your push is
rejected:

```text
$ vl git push
Exported 1 commit(s)
  rejected main ([rejected] (fetch first))
error: some branches were rejected: they moved on the Git side. Run `vl git pull origin`, merge, and push again (or push --force)

$ vl git pull
warning: tag 'main' has diverged from Git branch origin/main; nothing was lost on either side. Merge with `vl merge origin/main`, then `vl git push origin`
Imported 1 commit(s) from origin

$ vl merge origin/main -m "Merge GitHub"
Merged ouuvzvwk d8cc5e2d (empty) Merge GitHub
$ vl git push
Exported 1 commit(s)
  pushed main → e3b12aa0a1
```

* A branch **force-pushed on GitHub** is reported by `vl git fetch`. The
  Veil history it dropped is kept, and your tags don't move backwards.
* A branch **deleted on GitHub** is reported; your local tag is kept.
* `vl git push --force` only overwrites what you last fetched
  (`--force-with-lease`), so it cannot clobber commits you never saw.

## Credentials and authorship

* `vl git` runs your own **`git` binary** for fetch and push
  (`$VEIL_GIT` sets its path). Credential helpers (osxkeychain, libsecret,
  `gh auth setup-git`), `~/.ssh/config`, the SSH agent, `insteadOf` and
  proxies work as they do for Git. If `git push` works from a terminal,
  `vl git push` does too.
* **Author emails.** A Git commit's author is the Veil author. Veil records
  `$VEIL_USER` (or the identity's name), and Git gets an email only if that
  looks like `Name <email>`. Without one GitHub shows `alice <>` and can't
  link commits to your account:

  ```text
  $ git log --format='%an <%ae> %s' -2
  f277655 Alice Doe <alice@example.com> More app 2
  7b9c8ed alice <> More app
  ```

  Set `export VEIL_USER="Alice Doe <alice@example.com>"` in your shell
  profile. A change takes the author current when it was *created*, so the
  change you are in when you set it keeps the old name.
* Times are exported in UTC (Git time zones are not kept).

## Limits in 1.0

* Only branches map to tags; Git tags are not imported or exported.
* `vl git pull` does not check out (use `vl rebase -d main` or `vl new main`).
* Carry-over of Git-only paths follows the first parent only.
* Git commits are not signed.

Next: [Secrets and visibility](secrets-and-visibility.md).
