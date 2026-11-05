# 9. Colocated Git mode

Status: design and threat review. **The highest-risk feature of the round.** It requires **format 5** (so an older vl, which would not maintain the guards below, refuses the directory), plus features 6 (symlinks), 8 (bridge tags) and 5a (the hook runner, for the `pre-push` guard).

## The problem in one paragraph

The Git bridge's safety rests on two facts:
- Git only ever sees the **public projection** (`git/project.rs`).
- **Everything that comes from Git is already public**, so import may carry Git-only paths over (`GitBridge::carry`) and treat Git history as published (ARCHITECTURE §11, "History imported from Git is public by definition").

Colocation breaks both. A real `.git` sits beside a working copy that holds cloaked plaintext, isolated `.env` files and a member's embargoed fix. `git add -A`, `git commit -a`, `git checkout`, `git stash` and IDEs act on that directory without asking Veil, and a commit made there is **local and unpublished**, not public. Every rule below exists to restore those two facts.

## Design sketch

### Commands and state

```text
vl init --colocate [PATH]       new repository with .git, or adopt an existing Git checkout
vl git colocate                 colocate an existing Veil working copy
vl git colocate --status        report the guards (exclude block, skip-worktree count, held local commits, Git version)
vl git colocate --prune         expire reflogs of superseded local commits and run `git gc --prune=now`
vl git uncolocate               stop mirroring; .git is left as a plain Git repository
```

- **`repo.json` gains `colocated: {git_dir: ".git"}`.** That requires format 5; `repo.json` is device-local and never synced.
- **`git::default_git_dir`** (`git/mod.rs`) returns `<root>/.git` when colocated, otherwise `.veil/git/repo.git`.
- **Map and cache stay put:** `.veil/git/map` and `.veil/git/cache` do not move, and the commit ids are unchanged.
- **Migrating the bridge:** `vl git colocate` runs `git fetch <bridge> 'refs/*:refs/*'` into the new `.git` (a local fetch, no network), then switches.
- **`.veil/git/colocated.json`** (device-local): `{version:1, last_head, last_index_tree, held:[{commit, reason}], hooks_installed}`.

### What Veil writes into `.git`

Mirroring runs in `Ctx::finish` (`crates/vl/src/ctx.rs`), after every command that changed the view or the working copy, and in `vl serve`'s watch loop.

- **Objects:** only the public projection of snapshots. This uses the export code (`GitBridge::export_in`), extended to export `@-` (the parent of the attached workspace's working copy) even when no tag names it.
  - If `@-` cannot be exported (it is embargo-withheld), the nearest exportable ancestor is used and the guard switches to **frozen mode** (below).
- **Refs:** as the bridge already lays them out: `refs/heads/<tag>` for exported tags, `refs/tags/<name>` for release tags (feature 8), and `refs/remotes/<r>/<b>`.
  - `HEAD` is symbolic to `refs/heads/<tag>` when exactly one exported, uncloaked tag points at `@-`. Otherwise HEAD is detached at `@-`'s export.
  - **Every ref and HEAD write is a compare-and-swap** against the value read at the start of the command (gix `PreviousValue::MustExistAndMatch`). On mismatch Veil skips the write and the next command imports instead.
- **Index:** `.git/index` = the projection of HEAD's commit, written through `index.lock` (created exclusively; if it exists, the index refresh is skipped with a note, never waited for or removed). Then:
  - **skip-worktree** is set on every path whose working-copy content for this reader can differ from the projection: line-cloaked public files (fallback in Git, sealed edit on disk), embargoed files a key holder sees, conflicts whose rendering for this reader differs from the public one, and Git-only carried paths.
  - **Frozen mode:** when `@` is on a cloaked line or under an unreleased embargo, or `@-` is withheld, **every** index entry gets skip-worktree. Git then sees no modification at all, and `git commit -a` commits nothing.
- **`info/exclude`:** a generated block (`# BEGIN veil` … `# END veil`) holding:
  1. `/.veil/`;
  2. every protective rule of the effective policy (cloak, isolate, ignore, the built-in secret and artefact rules), translated to gitignore syntax with **no negations** (over-exclusion is the safe direction); case-insensitive rules become character classes;
  3. every path that is currently cloaked, isolated, quarantined or ignored on disk, with literal escaping, and `?` for characters gitignore cannot express;
  4. in frozen mode, `*`.
- **`.git/config`:** `core.autocrlf=false` (feature 7), `sparse.expectFilesOutsideOfPatterns=true` (so Git ≥ 2.37 does not clear skip-worktree on present files), and `gc.reflogExpireUnreachable` left at the user's setting.
- **Hooks:** `pre-push` (and `pre-commit`) are installed in `.git/hooks/`, chaining any existing hook (moved to `<name>.veil-chained` and called first). The `pre-push` hook runs `vl git check-push`; see point 6.

### What Veil reads from `.git`: `colocate::follow`

This runs at the start of every `vl` command, in `Ctx::open` (before the working-copy snapshot) and under Veil's repository lock.

1. **Git operation in progress** (`.git/rebase-merge`, `rebase-apply`, `MERGE_HEAD`, `CHERRY_PICK_HEAD`, `REVERT_HEAD`, `BISECT_LOG`, `index.lock`): no following and no mirroring. The working copy is snapshotted into `@` as usual, and every command says "Git operation in progress; Veil mirrors when it ends".
2. **Import new local refs** (`refs/heads/*`, `refs/tags/*`) with `import_tips`.
   - A commit not reachable from any fetched remote ref (`refs/remotes/*`, `refs/veil/tags/*`) is **local-origin**.
   - A local-origin commit is kept as the export of its snapshot **only if its tree equals the public projection of the snapshot it imported to** (it holds nothing Veil keeps private, refused or quarantined).
   - Otherwise it is **superseded**:
     - Veil exports the snapshot fresh (the projection);
     - moves the branch ref and HEAD from the original commit to it (compare-and-swap);
     - records the original in `held` with the reason ("adds `secrets/db.yml` (cloaked:ops)", "quarantined `config.yml` (aws-access-key)");
     - and never uses it as a carry-over source or a push parent.
   - A local branch that moved non-fast-forward (`git commit --amend`, `git rebase`) moves the Veil tag, **except** that old snapshots holding content Git could not see stay visible heads, with a warning, so a Git-side rewrite cannot drop cloaked work.
3. **If HEAD moved** away from `last_head` to commit `H` (snapshot `S_H`):
   1. Snapshot the working copy into the **old** `@`, restricted to the paths Git does not manage (excluded or skip-worktree; `SnapshotOptions` gains `only: Option<PathSet>`). This catches edits to hidden files made before the Git checkout.
   2. `@' = new change on S_H` (`vl new` semantics; an empty old `@` is abandoned as usual).
   3. Run a **Veil checkout of the hidden part**: from the old `@`'s tree to `S_H`'s tree, restricted to the paths Git does not manage, with the old `Materialised` record as the `from` side. This is the existing `checkout::restore_paths` machinery, so nothing Veil did not materialise is overwritten.
   4. Snapshot `@'`. Git-managed paths are taken as they are on disk (`H`'s content plus edits Git carried over); hidden paths now equal `S_H`'s materialisation.
4. **Mirror** (above) runs in `Ctx::finish`.

### Adopting an existing Git checkout (`vl init --colocate` where `.git` exists)

- **Refused** when `.git` is a gitfile (a linked worktree or submodule), when the repository is bare or sets `core.worktree`, when `GIT_DIR`/`GIT_WORK_TREE` are set, when a Git operation is in progress, or when the repository uses SHA-256 (gix bridge support is SHA-1 today).
- **`.gitignore` → `.veilpolicy`:** before the first snapshot, `vl policy import-gitignore` appends one `ignore` rule per gitignore pattern that matches an existing untracked-ignored file (computed with gix's exclude stack), so Rails' `config/master.key` or Terraform's `*.tfvars` are not recorded just because Veil never read `.gitignore`. This is the member's own edit, folded into the accepted policy.
- **Import:** all local branches, tags and remote-tracking refs, with the local-origin rule (unpushed commits that hold private content are superseded and listed). Then `@` = a new change on HEAD's snapshot, and the first snapshot records uncommitted edits.

## Threat review

1. **`git add -A` / `git add .` of cloaked or isolated files.**
   - *Invariant:* every path that is cloaked, isolated, quarantined or ignored on disk is matched by `info/exclude` **before control returns to the user** (written in `Ctx::finish`, and by `vl init --colocate` before it exits). Newly created files are covered by the translated policy patterns, and in frozen mode by `*`.
   - *Test:* create `secrets/new.yml` (a policy cloak) with no `vl` command in between, then `git add -A && git commit`; the commit lacks it. In a cloaked workspace, create `notes.md`, then `git add -A`; it is not added.
2. **`git commit -a` of a line-cloaked edit.** A public `README.md` edited in a cloaked workspace: Git's index holds the fallback, and the disk holds the sealed edit.
   - *Invariant:* frozen mode (every entry skip-worktree) whenever `@` is on a cloaked or embargo line. Outside frozen mode, every path whose readable content differs from the projection is skip-worktree.
   - *Test:* the scenario, then `git commit -a`; nothing is committed and `git status` is clean.
3. **Git silently clears skip-worktree.** Git ≥ 2.37 clears it for present files in sparse checkouts; `git update-index --really-refresh`, `git sparse-checkout`, `git reset --hard` and `git checkout -- .` may treat entries differently across versions.
   - *Invariant:* the config pin above, plus re-asserting skip-worktree on every mirror pass, plus the defence in depth of points 5 and 6.
   - *Test matrix (top adversarial item):* each of these Git commands × Git 2.25 / 2.39 / latest, on a frozen repository, followed by `git commit -a`. Run it in CI with whatever Git is installed, with the versions noted.
4. **`git commit` after a deliberate bypass** (`git add -f`, `git update-index --no-skip-worktree`) puts sealed plaintext into a local Git commit.
   - *Invariant:* that commit is local-origin and fails the projection-equality check, so it is superseded: the branch is moved off it, it is recorded in `held`, it is never pushed by `vl git push` (point 6) and never used as a carry-over source (point 5). `vl status` lists it until `vl git colocate --prune`.
   - *Test:* force-add a cloaked file, `git commit`, `vl status`, `vl git push` to a local bare remote; the remote's object dump has no plaintext and the branch is the superseding commit.
5. **Carry-over from a local-origin commit.** `GitBridge::carry` keeps "paths Veil did not change" from the parent Git commit. If the parent is a local commit holding `secrets/x` in plaintext, every later export carries it.
   - *Invariant:* carry-over only draws from commits that are Veil exports, or that are reachable from a fetched remote ref (already public). Superseded commits are never parents of exports.
   - *Test (unit, `git/export.rs`):* a local-origin parent with an extra plaintext path; the export of a child lacks it.
6. **`git push` run directly from the colocated directory.** This bypasses Veil.
   - *Invariant:* the installed `pre-push` hook runs `vl git check-push`, which refuses if any commit in `remote..local` is held, or is not yet imported and fails the import gate (run read-only). `--no-verify` bypasses it; this is documented as the one residual hole, with `vl git colocate --status` showing whether the hook is installed and intact.
   - *Test:* force-add a secret, commit, then `git push`; the push is refused. With `--no-verify`, it is documented as a leak by explicit action.
7. **A Git-driven checkout records sealed content as public.** `git checkout main` from a cloaked workspace leaves sealed edits on disk (skip-worktree or excluded). A naive follow would snapshot them as public edits on top of `main`.
   - *Invariant:* the follow algorithm's hidden-part Veil checkout (step 3.iii) replaces them with `main`'s versions, or keeps them, reported, if they changed since materialisation. They are recorded into the *old* `@` (step 3.i) first.
   - *Test (property, top adversarial item):* random interleavings of `vl` edits in cloaked, public and embargo workspaces, `git checkout`/`switch`/`reset --hard`/`stash`/`stash pop`/`commit -a`/`add -A`, `vl commit`, `vl ws switch`, then `vl git push` to a bare remote and `vl push --public` to a mirror. Check:
     - **I1:** neither remote's decoded objects contain any sealed plaintext;
     - **I2:** no snapshot in Veil history records a path public whose content was ever sealed for this reader (`api::entry_tier`);
     - **I3:** no recorded edit is lost (`vl op log` reachable).
8. **Git overwrites excluded files**, which Git treats as expendable. `git checkout old-tag`, where an old commit has `secrets/db.yml` (public before it was cloaked) or a GitHub-committed `.env`: Git overwrites the member's current cloaked or isolated file without asking.
   - *Invariant (mitigation):* every `vl` command records cloaked content into `@` and backs isolated files up into the vault (`VaultData::removed` / `vl secret recover`). What is lost is only what was edited since the last `vl` command; `vl watch` / `vl serve` narrow the window.
   - Where a path is excluded *and* present in some exported commit's tree, Veil adds it to the index as skip-worktree instead (Git then refuses to overwrite it: "would be overwritten by checkout").
   - *Test:* this case; after `git checkout`, the file either still holds the member's content, or `vl secret recover` / `vl undo` returns it. This is documented in the guide.
9. **Concurrent `git` and `vl`.** `git commit` while a `vl` command runs: if `vl` wrote HEAD or the branch from a stale read, the user's commit would be lost from refs.
   - *Invariant:* ref and HEAD writes are compare-and-swap, the index write is lock-file-exclusive and skipped if held, and Veil never deletes `index.lock`. No Veil lock is held while waiting on Git, and Veil never waits on a Git lock.
   - *Test:* a race harness of 200 `git commit` in a loop against 200 `vl status`/`vl describe`; every Git commit is reachable from a ref, and `git fsck` is clean.
10. **`vl` invoked from a Git hook while Git holds `index.lock`** (a pre-commit framework hook calling `vl status`). *Invariant:* the follow and the mirror skip (index locked); the command still works, with no deadlock and no error. *Test:* a `pre-commit` hook running `vl status`, then `git commit`; it succeeds.
11. **Cloaked descriptions and names in `.git`.** Commits carry `(description withheld: cloaked)`, and cloaked tags never become refs. `info/exclude` holds cloaked and isolated *names*: it is local and never pushed, but it is plaintext on disk (the same exposure as `vl status`).
    - *Test:* an object dump of `.git` after a cloaked workspace session has no sealed description and no cloaked tag name in `packed-refs` or `refs/`.
12. **Embargo key holders.** A security-team member working on the fix: `@-` is withheld, so HEAD stays at the last exportable ancestor, and the mode is frozen. `git log` and `git diff` therefore show nothing of the fix; `git diff` on the working tree shows nothing either (skip-worktree).
    - *Test:* in an embargo workspace, `git diff`, `git status --porcelain` and `git stash -u` show and store nothing of the fix; a `.git` object dump has no fix plaintext.
13. **`git stash -a` / `git clean -fdx`.** `stash -a` stores *ignored* files, including excluded cloaked or isolated plaintext, in a stash commit in `.git/objects`, and removes them from disk. `clean -x` deletes them.
    - *Invariant:* Veil never imports `refs/stash`, and `vl git check-push` refuses pushing `refs/stash`. Deleted files are recoverable as in point 8.
    - This is documented: `stash -a` writes local plaintext into `.git` (local only).
    - *Test:* `git stash -a`, then `vl git push`; the remote has no stash objects.
14. **A hostile `.git` content from a teammate** is impossible: `.git` is never a tree entry (`policy::vcs_metadata`, the bridge's `is_git_dir_name`), checkout never writes it, and clones never bring it. *Invariant:* kept. *Test:* a tree with `.GIT/hooks/post-checkout` (HFS+ variants) is refused on import and on checkout.
15. **A hostile `.gitmodules`, `.gitattributes`, or a `core.hooksPath` placed in a tracked `.git`-lookalike.** Git, not Veil, reads `.gitmodules` and `.gitattributes` in colocated mode; they are normal tracked files (features 5b and 7 cover Veil's own reading). Veil writes no `core.hooksPath` and preserves the user's.
16. **Policy weakening through Git.** A `git pull` (by Git) brings a `.veilpolicy` weakening onto disk. *Invariant:* unchanged: the accepted-policy pin guards every snapshot (`policy::working_copy_policy`), and the follow treats the new `.veilpolicy` as incoming, never as the member's edit (the step-3.iv snapshot uses `policy_incoming` for paths Git wrote). *Test:* `git pull` of `secrets/ public!`, then `vl status`; it shows `P`, and `info/exclude` still excludes `secrets/` (rules come from the effective, pinned policy).
17. **Symlinks in colocated mode.** Git writes links on checkout (its own rules). Veil's hidden-part checkout uses the no-follow writer (feature 6). A Git-written link `secrets -> /tmp/x` cannot make Veil write cloaked files to `/tmp/x`. *Test:* a Git commit replacing the `secrets/` directory by a link, then `git checkout`; the hidden-part checkout refuses (`blocked`) and nothing is written outside the root.
18. **Format and old vl.** An older vl refuses format 5 before reading anything, so it can never snapshot a colocated directory without maintaining the guards. `vl git uncolocate` removes the exclude block, the hooks (restoring chained ones) and skip-worktree bits, and leaves the repository at format 5.
19. **Interactions.** `ws exec` sandboxes, `--only` sparse sandboxes and FUSE mounts are never colocated (they have no `.git`; the follow runs only for the project directory's backend). `vl serve`'s watch runs follow and mirror under the same lock rules. The team vault is untouched. First-class conflicts are mirrored as their public markers (projection), and are skip-worktree because the reader's rendering may differ.
20. **Performance and denial of service.**
    - The follow reads `HEAD` and refs each command, which is O(refs). Import is O(new commits).
    - The mirror rewrites the index only when `@-`, the skip-worktree set or the exclude block changed (hashes in `colocated.json`).
    - A 100 000-file index write takes about 100 ms. A hostile `.git` with 1 million refs is the user's own and is not a threat.
    - *Bench:* `vl status` with colocation on a 20 000-file repository stays within 15 % of without.

## Round 9 fix wave: what changed

The round-9 adversarial pass (`docs/BUGS.md`, BUG-740…755) showed that the
sketch above put Veil's own repository inside Git's work tree, where Git's
checkout, pull, clean and stash may write, replace or delete it, and that
Git's ignore precedence lets a tracked `.gitignore` override every line
Veil writes. The design now says:

* **The repository lives in `.git/veil`** (threats 13, 14, 16; BUG-740,
  741, 746). Git never checks a path out into its own directory, and
  never cleans or stashes it. `.veil` is a symlink marker to it, which
  nothing reads through: every opener and `DiskBackend` find the
  repository in `.git/veil` first, whatever `.veil` is, and the marker is
  repaired at every command (anything else there is set aside, unread).
  Alternatives rejected: Git's sparse checkout (it would rewrite every
  skip-worktree bit Veil sets, at every checkout, differently across Git
  versions) and refusing `.veil` paths on import alone (Git writes the work
  tree before Veil runs). `pre-commit` refuses `.veil` paths, local commits
  holding one are superseded, and a checkout that tracks `.veil` is not
  adopted. Cost: `rm -rf .git` deletes the Veil repository (the guide
  says so).
* **No protection rests on ignore precedence** (threat 1; BUG-742). A
  negation in any `.gitignore` is checked at every mirror against what Veil
  protects (Git is asked, `git check-ignore`); an exposure is reported and
  freezes Git commits. Git cannot be stopped from hashing or stashing what a
  negation un-hides; `pre-commit`, superseding, `pre-push` and `--prune`
  keep it out of commits, remotes and, eventually, `.git`. This residue is
  documented as a limitation.
* **Freeze first** (threats 2, 9; BUG-748). Before cloaked or embargoed
  work is written to disk, the index is frozen and `*` excluded; while Git
  is busy that cannot happen and the move is refused. The exclude block's
  `*` and the `pre-commit` decision come from the repository as it is now,
  not from `colocated.json`.
* **Veil deletes only what it wrote** (BUG-743, 750, 751). The mirror
  deletes only refs it owns (exported as a tag); a branch named like a
  cloaked tag never moves the tag. `--prune` deletes only the reflog
  entries naming held commits, never a stash.
* **Leaving and entering are safe** (threat 18; BUG-744, 745).
  `uncolocate` keeps the exclude block and the skip-worktree bits of hidden
  files, lists the protected files, and is refused on frozen work. Adoption
  keeps the user's own skip-worktree and assume-unchanged edits unrecorded
  until the bit is cleared.
* **Checkout transforms** (BUG-755): `info/attributes` turns `ident` off
  in the colocated work tree. Filters (LFS) are not modelled.
* **After the fact** (BUG-747, 752; threat 8, BUG-754): Git runs no hook
  for `git stash`, `git bundle` or a checkout overwriting an ignored file.
  A stash holding hidden content is reported at the next command; the
  bundle and the overwrite are documented leaks. The skip-worktree entry
  of threat 8's mitigation is not implemented: it would show the file as a
  staged new file in `git status`.

## Open decisions

- **How a cloaked file appears in `.git`.** *Recommendation:* exactly the bridge projection.
  - A policy-cloaked file is **absent**.
  - A public file edited on a cloaked line shows its **last public version** (fallback).
  - An embargoed file shows its pre-merge version.
  - Never a placeholder stub, which Git users would commit, edit or push as real content, and which import would read as an edit.
  - Rationale: one projection function for GitHub, the bridge, patches and `.git` means one thing to test (`project.rs`), and IDE `git blame` matches GitHub.
- **Do local Git commits keep their ids?** *Recommendation:* yes, when they hold only what the projection shows (the common case, so no surprise rewrites). Superseded only when they hold private content, with a clear message. jj rewrites more aggressively; Veil should not, so users can rely on `git commit` working.
- **Frozen mode on cloaked and embargo lines.** *Recommendation:* yes. It costs Git-side visibility of in-progress cloaked work, which Git should not see anyway, and it closes the `git commit -a` route without depending on per-file bookkeeping being up to date.
- **`.gitignore` handling.** *Recommendation:* a one-time import into `.veilpolicy` at colocation (pinned by the accepted policy), plus a warning on any later snapshot that records a file `.gitignore` ignores. Honouring `.gitignore` live would let a teammate's `.gitignore` edit weaken protection without the pin.
- **Ship order.** *Recommendation:* colocated mode ships behind `vl git colocate --experimental` for the first release of this round, until the Git-version matrix of point 3 and the property test of point 7 have run clean on Linux and macOS.
