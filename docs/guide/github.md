# Using Veil with GitHub

Keep GitHub (or GitLab, or any Git host) for CI, code review and the
public: Veil tags become Git branches, and Git commits become Veil
snapshots. Git only ever sees what a **public** Veil remote would see.

1. [Start from an existing Git repository](#start-from-an-existing-git-repository)
2. [Push and pull](#push-and-pull)
3. [What GitHub sees, and never sees](#what-github-sees-and-never-sees)
4. [Round trips](#round-trips)
5. [Divergence](#divergence)
6. [Releases: Git tags](#releases-git-tags)
7. [Symlinks and submodules](#symlinks-and-submodules)
8. [Credentials and authorship](#credentials-and-authorship)
9. [Limits in 1.0](#limits-in-10)

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
○  qzknoozp Alice <a@x> unsigned 2026-11-04 04:10:07 main origin/main 80a91b59
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
* leaves the imported snapshots **unsigned** (`unsigned` above): a snapshot
  imported from Git is a function of the Git commit and of what Veil holds
  for its parents, nothing about who imported it. So every member who
  imports the same commit gets the same snapshot, and two members pulling
  from GitHub before they sync with each other don't end up with two copies
  of one change;
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
| `vl git push --delete BRANCH` | Delete a branch on the Git side (delete its tag first with `vl tag delete`); refused if it moved since you last fetched, unless `--force` |
| `vl git fetch [REMOTE]` | Import new commits; update `REMOTE/BRANCH` remote tags. Local tags don't move |
| `vl git pull [REMOTE]` | Fetch, then create or fast-forward local tags from the branches |
| `vl git export [-t TAG…]` | Export into the local bridge without pushing; print each branch's commit |
| `vl git remote add\|list\|rm` | Manage Git remotes (separate from `vl remote`) |

**Only tags are pushed**, so a change must be tagged to reach GitHub. If you
commit on top of `main`, `vl commit` moves `main` for you (it moves tags
that pointed at the parent; not from a cloaked workspace). Otherwise:
`vl tag set main -r @-`.

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
| A snapshot made in a cloaked workspace | A commit with the author, the time and the placeholder message, and none of the cloaked files. A public file it edited keeps its last public version |
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
error: 1 tag was rejected (main): origin has commits you don't have. Run `vl git pull origin`, `vl merge origin/main`, and push again (or `vl git push --force` to overwrite them)

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
* A tag you **deleted here** is not brought back by `vl git pull` while its
  branch hasn't moved (see
  [Deleting a tag](teams-and-remotes.md#deleting-a-tag)). Delete the branch
  with `vl git push --delete BRANCH`.
* A failed `vl git import` (a typo in the URL) leaves no Git remote behind:
  retry with the right URL.
* `vl git push --force` only overwrites what you last fetched
  (`--force-with-lease`), so it cannot clobber commits you never saw.

## Patches by mail: `vl format-patch` and `vl am`

Projects that take patches by mail (or in an issue) get Git's own format.
`vl format-patch` writes one mail per change, exactly as `git format-patch`
would on what `vl git push` exports:

```text
$ vl format-patch main..@- -o ../outgoing
../outgoing/0001-Say-hi.patch
../outgoing/0002-Say-hello-instead.patch
$ cat ../outgoing/0002-Say-hello-instead.patch
From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001
From: Alice Doe <alice@example.com>
Date: Wed, 4 Nov 2026 20:10:41 +0000
Subject: [PATCH 2/2] Say hello instead

---
 app.rs | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/app.rs b/app.rs
index 1b7c1e7d7369c0f9472f22e1378605d8a590ddf8..75275760623f7f5fe5ad07f415dc5b1a374c87cd 100644
--- a/app.rs
+++ b/app.rs
@@ -1,3 +1,3 @@
 fn main() {
-    println!("hi");
+    println!("hello");
 }
-- 
vl 0.1.0
```

* `REVSET` is `A..B` (what `B` has and `A` does not), `::B` (all of `B`'s
  history) or one change. `--stdout` writes one mbox instead of files;
  `--cover-letter` adds patch 0. Merges have no patch and are skipped.
* **A patch shows what GitHub would see.** The cloaked `secrets/db.txt`
  of "Say hi" is not in it, a cloaked description reads `(description
  withheld: cloaked)`, and a change that is the withheld fix of an
  unreleased embargo is refused before anything is written. `-o DIR`
  writes into a temporary directory first, so a refused series leaves
  nothing behind.
* A description line that looks like patch syntax (`diff --git …`, `---`,
  a `From ` line) is indented by one space, with a warning, so nobody's
  `git am` takes it for part of the patch.
* `--audience me` writes what *you* can read, cloaked content included.
  It is never the default, can't be abbreviated, needs `--yes` when the
  output is not a terminal, warns which scopes it holds, and puts them in
  an `X-Veil-Audience:` header of every mail. Unreleased embargo content
  also needs `--include-embargoed ID`. Use it only for someone in those
  scopes, and prefer pushing to a team remote.

`vl am` applies a series (a file, a directory of `.patch` files, or `-`
for standard input) as **new changes**, one per patch, on top of `@-`
(`-d REV` for another place). It keeps each patch's author, date and
message; the change is signed by you. Your working copy moves on top:

```text
$ vl am ../outgoing
Applied 2 patch(es):
  nmvnzsot 2ee1f0f8 Say hi
  quroxnlk 3314da20 Say hello instead
The working copy was rebased onto the last of them.
$ vl log -n 2
@  wsksumok Bob Roe <bob@example.com> ✓ 2026-11-04 20:10:47 default@ f40d4c58 (empty)
│  (no description set)
○  quroxnlk Alice Doe <alice@example.com> ✓Bob Roe <bob@example.com> 2026-11-04 20:10:41 3314da20
│  Say hello instead
```

A patch is someone else's content, so it goes through every check an
incoming change does:

* **All or nothing.** If any patch fails (a hunk that does not apply, a
  hostile path, a secret), nothing at all is recorded; `vl undo` takes back
  a whole applied series.
* Hunks must match exactly, at most 1000 lines from where they say (no
  fuzz, no whitespace or line-ending leniency, no `.rej` files).
* Paths outside the repository, `.veil/`, `.git/` (in any spelling), and
  names that would collide with an existing file on macOS are refused.
* A secret is quarantined as in any snapshot, which aborts the series:

  ```text
  $ vl am ../evil.patch
  error: policy violation: patch 1/1 (Add config): config.yml quarantined (aws-access-key-id): the patch adds what looks like a secret. Nothing was recorded; remove the secret from the patch, or make the path cloaked or isolated first
  ```

* A patch editing `.veilpolicy` to weaken it is recorded but **held back**
  (`P` in `vl status`) until you run `vl policy accept`, as a pulled
  change is. A file the patch writes is never recorded with less
  protection than the policy it was applied to gives it.
* A cloaked file you can read stays cloaked when a patch edits it; one you
  hold no key for cannot be patched.

**Not yet (phase 2):** rename detection in `format-patch -M` (a rename is a
deletion and an addition), symlinks and submodules (refused by `vl am`),
binary files (`Binary files … differ` on export, refused on import),
`--binary` and `--3way`.

## Releases: Git tags

A plain Veil tag (`vl tag set main`) is a **branch** in Git. An
**annotated** tag is a **release tag**: a Git tag, immutable, signed with
your Veil identity, and what GitHub releases and CI tag triggers act on.

```text
$ vl tag set v1.2.0 -r main -a -m "Release 1.2.0"
Release tag v1.2.0 → qzknoozp 80a91b59 Add the parser (signed)
$ vl tag verify v1.2.0
tag v1.2.0 → qzknoozp 80a91b59 Add the parser
kind:   annotated
tagger: Alice Doe <alice@example.com> 2026-11-04 10:12:03
    Release 1.2.0
verified: good signature by Alice Doe
$ vl git push
  pushed main → 80a91b59e1 (new branch)
  pushed tag v1.2.0 → 80a91b59e1 (new tag)
$ gh release create v1.2.0 --notes-from-tag     # or let CI do it
```

* **Immutable.** `vl tag set v1.2.0` again is refused; commits, merges and
  rewrites never move a release tag. `--force` replaces it (keeping its
  message unless you give `-m`); `vl tag delete` removes it.
* **Signed.** `vl tag verify` exits 1 unless the tag carries a valid Veil
  signature by a key one of your scopes knows. A tag imported from Git
  keeps its GPG or SSH signature (re-exported byte for byte, so it still
  verifies with `git tag -v`), but Veil never reports it as verified.
  Veil does not sign Git tags; GitHub shows Veil's as unverified.
* **Pushed, never forced.** `vl git push` pushes every release tag the
  remote does not have yet. If the remote has one with another target, the
  push is **rejected** (`tag exists with another target`): check why, then
  `vl git push --force-tags` if yours is right (it only replaces what you
  last fetched). `vl tag delete v1.2.0` then `vl git push --delete-tag
  v1.2.0` removes one from the remote.
* **Fetched, never moved.** `vl git fetch` records the remote's tags as
  `tag:origin/<name>` (`vl tag list`; `origin/<name>` too when no branch
  has that name). `vl git pull` creates a local release tag for each new
  one, and **never moves** an existing one. If the remote moved a tag you
  already have, you get a supply-chain warning:

  ```text
  warning: origin moved Git tag v1.0 from 3f2a91c0 to 9d81e0b2: Git tags should never move …
  warning: release tag v1.0 stays at 3f2a91c0; origin has it at 9d81e0b2 …
  ```

  `--no-tags` fetches branches only; `--prune-tags` forgets `origin/<tag>`
  for tags the remote deleted (your own release tags are never deleted).
  A tag of a tree or blob, a chain of more than 8 tag objects, a message
  over 1 MiB, or a name Veil refuses (or that looks like one of your
  change ids) is skipped and reported.
* **Private and embargoed releases.** A cloaked tag (`--cloak`) and its
  message (sealed for the scope) never reach Git. A release tag on the
  merge of an unreleased embargo **waits**: the push reports `release tag
  waits for the release of embargo …`, because GitHub would see the code
  without the fix, and a tag is permanent. After `vl embargo release`, the
  next push publishes it on the publication commit, which has the fix.
  A tag on the fix itself is skipped like the fix.

## Symlinks and submodules

Symlinks import from Git as Veil symlinks and export as Git symlinks
(mode `120000`), classified by the link's own path like a file: a link in
a cloaked directory has its target sealed (Git never sees it), a link
whose target holds a token (`https://u:ghp_…@github.com/…`) is held back,
and one Veil cannot represent (a non-UTF-8 or NUL target, over 4 KiB, a
symlinked `.gitmodules`) stays in Git untouched.

Submodules import as **gitlinks**: the pinned commit, never the
submodule's files. Nothing fetches them by itself, not even `vl git
pull`:

```text
$ vl submodule status
vendor/sdk  8ae1a6a11ad1  not checked out (`vl submodule update`)  https://github.com/acme/sdk.git
$ vl submodule update
  cloned vendor/sdk at 8ae1a6a11ad1
$ cd vendor/sdk && git pull && cd ../..     # work in it with Git
$ vl submodule set vendor/sdk 515dbe42d25943b4aec154d6dcbea83d65454db5
Pinned vendor/sdk to 515dbe42d259 (was 8ae1a6a11ad1)
$ vl submodule add https://github.com/acme/tool.git tools/tool
Added submodule tools/tool at 1c0ffee12345 (https://github.com/acme/tool.git)
```

* `.gitmodules` comes from your teammates, so it is untrusted: only `path`
  and `url` are read (`update = !command` never runs), URLs must be
  `https`, `ssh`, `git` or `host:path`; local paths and `file://` need
  `--allow-local`; `ext::` and other helper URLs, option-like values
  (`--upload-pack=…`) and names with `..` are refused, naming the
  submodule. A relative URL (`../sdk.git`) is resolved against your Git
  remote `origin`.
* The clone's Git directory lives in `.veil/local/submodules/`, never in
  `.git/modules`; the submodule directory gets a `.git` file.
* Veil never records files below a submodule, even if your policy names
  them: that repository decides where its files are published. If the
  submodule is in a cloaked directory its pin is sealed and Git does not
  get it; your public `.gitmodules` still names it, and export warns.

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

* `vl git pull` does not check out (use `vl rebase -d main` or `vl new main`).
* Release tags are not signed for Git (GitHub shows them unverified).
* Symlinks and submodules need repository format 5 (`vl upgrade`); the
  working copy materialises them as the working-copy support lands.
* Carry-over of Git-only paths follows the first parent only.
* Git commits are not signed.

Next: [Secrets and visibility](secrets-and-visibility.md).
