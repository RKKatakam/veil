# 8. Git tags in the Git bridge (GitHub releases)

Status: design and threat review. It uses the format-5 annotated tag object (`veil:atag`, `Tag.annotation`; feature 5c). Lightweight-only import could work in format 4, but one model is simpler, so this feature requires format 5.

## Design sketch

- **Model.**
  - A Veil tag with `annotation: Some(atag)` is a **release tag**: immutable, and exported as `refs/tags/<name>`.
  - A Veil tag without one stays a **branch**, exported as `refs/heads/<name>`, as today.
  - This splits Veil's single "tag" notion along Git's lines without renaming anything.
- **Export** (`git/export.rs`, `GitBridge::export_in`):
  - For each release tag that passes the existing checks (not cloaked, not the root, `push_closure` not withheld), export its target as today.
  - Then write a Git **annotated tag object**: `object <commit>`, `type commit`, `tag <name>`, `tagger <atag.tagger> <timestamp> +0000`, and the message (plain only; a sealed message is never exported, because a cloaked tag is never exported at all).
  - When the atag came from Git (`git: {oid, raw}`), the original raw object is re-written byte for byte, keeping its GPG signature, if and only if its target commit is the same mapped commit. Otherwise a fresh object is written.
  - Determinism: the same atag and the same commit give the same tag object id. The map gains a line `t <git tag oid> <atag id>` (`git/map.rs`; the map format is device-local and needs no repository format).
- **Push** (`git/mod.rs::push_with_deletions`, `git/transport.rs::push`):
  - Refspecs are `<tagoid>:refs/tags/<name>`, **never forced**: Git tags are immutable on the remote.
  - A tag that exists remotely with another target is reported as `rejected (tag exists with another target)`, and `--force-tags` is needed. With it, `--force-with-lease=refs/tags/<name>:<fetched>` is used.
- **Fetch and import** (`transport::fetch`, `git/mod.rs::fetch_inner`):
  - The refspec adds `+refs/tags/*:refs/veil/tags/<remote>/*`. That is a separate namespace in the bridge, so a remote *branch* named `tags/x` cannot collide with tag `x`. `--no-tags` and `--prune-tags` semantics apply.
  - Each fetched tag is peeled with a depth limit of 8 (tag of a tag). It must reach a **commit** that imports successfully, otherwise it is reported and skipped.
  - It becomes an atag (annotated tags keep tagger, message and `git.raw`; lightweight ones get `kind: "lightweight-git"`), recorded in a **new view field** `View::remote_release_tags: BTreeMap<"<remote>/<name>", atag id>`.
    - This is a format-5 field (FORMAT rule 1). It is separate from `remote_tags`, which holds branches, so a branch `v1` and a tag `v1` never collide.
    - Revsets: `<remote>/<name>` resolves to the branch if both exist, and `tag:<remote>/<name>` names the tag; an ambiguity is reported.
  - `vl git pull` creates a local release tag if absent. It **never moves** an existing local release tag (Git semantics) and reports a moved remote tag.
- **Deletion:** `vl tag delete v1` plus `vl git push --delete-tag v1` (or `-d refs/tags/v1`); that is the existing `--delete` with a tag namespace.
- **Embargo interaction:** a release tag whose target's export is shaped by an unreleased embargo (`map` veiled set non-empty for the target commit) is **held back**, reported as "release tag `v1.2.1` waits for embargo E's release". After the release it is exported pointing at the **publication commit** (export already writes it), never at the pinned pre-release commit.
- **GitHub releases:** out of scope. Veil pushes tags; `gh release create` or CI acts on them.

## Threat review

1. **Exporting a cloaked tag, or its message.** *Invariant:* unchanged rule: a cloaked tag (and its atag) is never exported, and is skipped with the existing reason. *Test:* a cloaked annotated tag plus `vl git push`; the remote's `git ls-remote --tags` and an object dump of the bridge show no tag object and no message text.
2. **A release tag on embargo-withheld history.** A tag on the fix change itself, or on a descendant of it. *Invariant:* the same `push_closure` check as for branches; it is skipped with the `vl push` reason (conformance acceptance). *Test:* tag the fix and push; the tag is absent and the reason is printed.
3. **A release tag on an unreleased embargoed merge.** It would publish a "security release" tag pointing at code *without* the fix (the fallback view), which is misleading, and permanent once pushed since tags are immutable.
   - *Invariant:* held back until release, then exported at the publication commit.
   - *Test:* tag the embargoed merge as `v1.2.1` and push; it is held back. Release and push; `v1.2.1` points at the publication commit, whose tree contains the fix.
4. **Hostile tag names from Git.** `refs/tags/../../heads/main` cannot exist in Git, but names Veil refuses can (`@`, change-id-like prefixes, names containing `/`, Unicode confusables, control characters).
   - *Invariant:* `remote::validate_remote_name` and `commands::validate_tag_name` apply. A name that is also a change or snapshot id prefix is not created locally (`RevisionNames::shadows`, BUG-059/105 class) and is reachable only as `<remote>/<name>`.
   - *Test:* fetch tags named like an existing change id and like `main`; no local tag shadows them.
5. **A tag pointing at a tree, a blob or a missing object.** *Invariant:* peeling must end in a commit within 8 levels, otherwise the tag is skipped and reported (BUG-031 analogue). *Test:* tags to a blob, a tree and a 9-deep tag chain; the pull succeeds and reports three skips.
6. **Collisions between tags and branches.** A remote with branch `v1` and tag `v1`. *Invariant:* the branch maps to Veil tag `v1` (branch kind) and to `remote_tags["origin/v1"]`; the Git tag goes to `remote_release_tags["origin/v1"]`. No local release tag is created because the name is taken; reported, with `tag:origin/v1` named in the hint. *Test:* both exist; no overwrite.
7. **Force-moved remote tags.** A remote re-points `v1.0` (supply-chain style). *Invariant:* the local release tag never moves, and `vl git fetch` reports "remote moved tag v1.0 from X to Y". The remote tag records the new target, and the atag keeps the old one. *Test:* move it on the remote and fetch; the warning is printed and the local tag is unchanged.
8. **Signature confusion.** An imported GPG-signed Git tag must never appear as "verified" in Veil (5c point 19). Export keeps the raw bytes, so the signature still verifies in Git; no new signature is ever forged.
9. **Messages with escapes or huge sizes.** A tag message is capped at 1 MiB on import (larger: skipped), and printed through `render::safe`. *Test:* a 100 MiB tag message from a hostile remote; it is skipped without allocating 100 MiB twice (read via `gix` with a size check first).
10. **Format and upgrade.** Below format 5, `vl git fetch` keeps today's behaviour: tags are not fetched, and one notice names `vl upgrade`. *Test:* in `format_compat.rs`, a format-4 repository fetches from a remote with tags; there is no error and no tag.
11. **Colocated mode** (feature 9). Release tags appear in `.git/refs/tags`, and `git tag -a` made in Git is imported as a release tag by the next `vl` command. A Git-side tag on a *local-only* Git commit is held, like that commit (feature 9).
12. **Determinism and map loss.** The map line for tags can be lost. *Invariant:* re-export produces the same tag object id (fixed encoding), and a fetched tag object equal to a recomputed export is recognised as Veil's own and not re-imported as a new atag. *Test:* delete `.veil/git/map`, then fetch and push; there is no new tag object and no duplicate.
13. **`--json`.** `vl git push --json` (if present) and `vl tag list --json` get additive fields: `kind`, `git_ref`, `held_back_reason`.

## Open decisions

- **Which Veil tags become Git tags?** *Recommendation:* only annotated ones (`vl tag set -a`). They are explicit, immutable, and match Git's split. A naming convention (`v*`) would be a magic rule.
- **Import lightweight Git tags as release tags?** *Recommendation:* yes, as release tags with `kind: lightweight-git`, so they round-trip to `refs/tags` and are never re-pushed as branches (the conformance requirement).
- **Should pushing tags be part of `vl git push` by default?** *Recommendation:* yes for tags whose atag was created or changed since the last push (Git's `push.followTags` behaviour), and never forced.
