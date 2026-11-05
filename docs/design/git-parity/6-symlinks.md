# 6. Symlinks

Status: design and threat review. **Format 5** (a new tree entry kind; see `PLAN.md`). Today symlinks are invisible.
- `DirListing::special`: never recorded or followed.
- A tracked path that became a link keeps its entry and is reported.
- Checkout never writes at or below one (`CheckoutReport::blocked`, `behind_special`).
- `DiskBackend::refuse_symlinked_parent`.

That stays exactly the behaviour of repositories below format 5.

## Design sketch

- **Data model (format 5).**
  - `EntryKind::Symlink` in `object.rs`. `id` names an object whose plaintext is the **link target bytes** (UTF-8 only; a non-UTF-8 target is reported as unrepresentable, like names, BUG-039).
  - The target is sealed like file content when the policy cloaks the link's path: targets can name private paths (`current -> /srv/acme-secret-merger/build`).
  - `executable` must be false, `size` = target length, and a `fallback` is allowed (a line-cloaked link).
  - Conflict terms gain kind bits so a symlink version can sit in a conflict (`PLAN.md`, format 5).
- **VFS** (`vfs/mod.rs`):
  - `NodeKind::Symlink`.
  - `StorageBackend::read_link(path) -> Result<Vec<u8>>` and `write_link(path, target) -> Result<()>`, atomic (`symlinkat` to a temp name, then `renameat`).
  - Default implementations return `Unsupported`.
  - Implemented for `DiskBackend`, `MemoryBackend`, `OverlayBackend`, `TreeView`, `SandboxFs` and `SparseView`. `SftpBackend` refuses (remotes hold objects only).
  - `list_dir_full` reports links as entries of kind `Symlink` in format-5 repositories (the builder asks via `BuildOptions::symlinks: bool` = `repo.format() >= 5`), and keeps them in `special` otherwise.
- **Builder** (`builder.rs`): a `Symlink` listing entry becomes `symlink_entry(path)`.
  - It reads the target with `read_link` (`readlinkat` on the parent's directory fd, never following), and classifies by **the link's own path** (policy, artefact rules, built-in secrets: a link named `id_rsa` is isolated).
  - It scans the target string with `secrets::scan` (cheap; catches `https://user:token@…` targets) and seals as for files (`audience`).
  - The stat cache keys links by (ino, mtime, ctime, size) as for files.
  - `.veilpolicy` is never recorded as a link: today's rule is kept (policy read through the link, the tracked entry kept, a warning).
  - A link named `.git` or `.veil` stays VCS metadata or a nested repository (`policy::vcs_metadata`, `vfs::holds_repository`).
- **Checkout** (`checkout.rs`):
  - writes a link with `write_link`;
  - removes a link with `unlink`, never `remove_dir_all` through it;
  - replaces file ↔ link ↔ directory with removals before writes, as now.
  - The "holds exactly the `from` version" check for a link compares `readlink` bytes.
  - **Every write below the root goes through `openat`-based resolution with `O_NOFOLLOW` on every component** (new `vfs::disk::open_beneath`, or `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` on Linux ≥ 5.6 with an `O_NOFOLLOW` walk as the fallback, as on macOS). This replaces the `lstat` loop in `refuse_symlinked_parent`, which has a time-of-check to time-of-use window.
- **FUSE mount** (`mount/fs.rs`): `readlink` and `symlink` are served from the overlay, path resolution inside `MountFs` never follows links (the kernel follows them for callers, inside the mount's namespace), and the `EPERM` for `symlink()` is lifted in format 5.
- **Sandboxes** (`sandbox.rs`, `vfs/sandbox.rs`): links are checked out as links. Reflink cloning (`clone_known`) applies to files only.
- **Diff and display:** `vl diff` shows `symlink a -> old` / `-> new`; `vl ls` shows `l` and the target, escaped. JSON `kind: "symlink"`, `target`.

## Threat review

1. **Write-through on checkout** (BUG-025 class, CVE-2014-9390 / CVE-2021-21300 style). A tree has `a -> /home/u/.ssh`, and a later tree replaces `a` with a directory holding `authorized_keys`. Or one tree holds `A -> /tmp/x` and `a/file` on a case-insensitive filesystem.
   - *Invariant:* no checkout, restore, sandbox sync or mount write ever resolves through a symlink: every component is opened `O_NOFOLLOW` (beneath the root fd). `checkout::name_collisions` counts links as names, so `A` and `a/` collide on macOS and the checkout is refused.
   - *Tests:* the CVE-2021-21300 shape (a case-folding collision of a link and a directory), run in `macos_support`; a link-then-directory sequence across two checkouts; a race thread swapping a directory for a link during checkout (`checkout_obstacles.rs` style). Nothing appears outside the root.
2. **Reading through links in the builder.** Today `read` refuses links. *Invariant:* the builder reads link *targets* only (`readlinkat`), never content through a link, apart from the existing `.veilpolicy` rule. *Test:* `notes.txt -> /etc/shadow`; the snapshot records the target string only, and no object holds the file's bytes.
3. **Links into isolated files.** `public/env -> ../.env`. The link records only the string `../.env`, so the `.env` *content* is not recorded. The *name* of an isolated file becomes visible in history. This is accepted; `vl status` warns "`public/env` points to an isolated file".
   - *Invariant:* the content is never recorded. *Test:* grep the store for the `.env` value after the snapshot.
4. **Links whose own name is a secret pattern.** `deploy/id_ed25519 -> ../keys/k` is isolated by its name (local-only, vault backup of the *target string*). *Test:* `vl status` lists it as `L`.
5. **A secret in the target string.** `url -> https://u:ghp_xxx@github.com/…` is quarantined like a file. *Test:* the scanner hit is held back, and the previous entry is kept.
6. **Targets outside the repository.** Absolute targets, or `..` escaping the root. Recording them is harmless to Veil itself, which never follows them, but other tools (IDEs, build scripts, sandboxed agents, Git in colocated mode) will.
   - *Invariant:* recorded as is, a warning on first record ("points outside the repository"), and a policy-level option `symlinks: refuse-outside` in a future `.veilpolicy` directive.
   - *Test:* an absolute link round-trips through push and pull and checkout, unchanged.
7. **Agents and sandboxes reaching outside.** A tree link `x -> ../../../../../.env` is materialised inside `.veil/local/sandboxes/<ws>/files/` and resolves to the project's isolated `.env`, which `ws exec` without `--with-isolated` promised not to provide.
   - *Invariant:* the sandbox checkout refuses relative targets that resolve outside the sandbox root (by lexical resolution against the link's directory), with `blocked`. Absolute targets are materialised (they could be reached by absolute path anyway), but a target inside the *project directory* or `$VEIL_HOME` is blocked.
   - *Revised (Git-parity fix wave 3, BUG-708, BUG-709):* the per-link lexical check is not enough. Two links that are each inside chain out (`u -> ../../../..`, `x -> u/../../../../../.env`: the kernel climbs from `u`'s target), and an absolute target's meaning depends on the reader (`/proc/self/cwd/../../.env` is the sandbox, then the project). The sandbox now materialises a link only when its target is relative, all its `..` components come first and stay beneath the root, and names follow (`vfs::sandbox_link_check`). That holds whatever other links the tree holds (each link sits in a real directory at its own depth; by induction over the kernel's expansions, every resolution stays beneath the root), so no knowledge of the tree is needed. Absolute targets are never materialised in a sandbox.
   - *Test:* `ws exec -- cat x` fails, and the sandbox report names the link. This applies to `--only` sparse sandboxes too.
8. **FUSE mount resolution.** `MountFs` resolves paths itself; a link in the overlay must not make `MountFs::lookup` traverse it into the upper directory or `.veil`.
   - *Invariant:* `MountFs` treats links as leaf inodes. *Test:* `mount/fs.rs` unit tests with a link to `../../.veil/local/vault.sealed`; lookup through it fails `ENOTDIR`.
9. **Data loss on a format upgrade.** In format 4, a tracked file the user replaced by a link keeps its old entry. After `vl upgrade`, the next snapshot records the link, and history keeps the file.
   - *Invariant:* the old file content is still in the parent snapshot, and `vl status` shows `T path (file → symlink)`. *Test:* an upgrade fixture with such a path.
10. **Checkout over a user's untracked link.** A user's untracked `vendor -> /shared/vendor` and a tree that tracks `vendor/` as a directory.
    - *Invariant:* unchanged. A link Veil did not materialise is never replaced or removed: `kept`/`blocked`, even in format 5, since the link is not the `from` version. *Test:* the existing `checkout_obstacles` cases, plus format 5.
11. **Directory links and walks.** The builder never descends into a link to a directory, and neither do `walk_files`, gc or fsck. A self-referential link (`a -> .`) is a leaf. *Test:* a link loop; the snapshot terminates, and the link is recorded once.
12. **Conflicts.**
    - A link versus file conflict: in format 5, a conflict entry with a link term.
    - Materialisation for the working copy writes **our side as it is** (a link or a file) and reports the conflict, never a file of markers containing a link target. That would turn a target path into file content, which a later edit could publish.
    - Two link targets: our target, reported.
    - *Test:* a merge with link/link and link/file conflicts; `vl resolve --theirs` gives the right kind.
13. **Hostile trees.** A symlink entry with `executable` set, a non-UTF-8 target object, a target over 4 KiB (`PATH_MAX`), a NUL in the target, or a sealed target with a fallback that is a file blob.
    - *Invariant:* the binary tree decoder refuses invalid flag combinations (canonical-by-construction). At checkout, a target with NUL or over 4 KiB is refused per path (`failed`), never panicking. *Test:* the fuzzer `adversarial_fuzz.rs` gains a symlink-kind generator.
14. **An incoming symlink to `.veilpolicy`, or a link named `.veilpolicy`.** That is refused today (BUG-058). *Invariant:* kept. Format 5 does not make `.veilpolicy` a recordable link.
15. **`vl serve`, `--json`, escapes.** Targets are raw data, escaped by `render::safe` and `to_json`. *Test:* a target holding an OSC 8 hyperlink escape.
16. **macOS.** `symlinkat`/`renameat` semantics and `openat` with `O_NOFOLLOW` exist; `openat2` does not. *Invariant:* the per-component `O_NOFOLLOW` walk is the macOS path, and the CI macOS job runs the traversal tests.

## Open decisions

- **Record links that point outside the repository?** *Recommendation:* yes, as Git does. Veil never follows them, and refusing would break real repositories (`node_modules/.bin`, `/usr/share/…` fixtures). The sandbox and mount mitigations in points 7 and 8 cover the cases where Veil itself hands the link to untrusted code.
- **Should the target be scanned and sealed?** *Recommendation:* yes. The target is content: it is classified by the link's path, scanned, and sealed under its scope.
- **Windows.** Out of scope (1.0 targets Linux and macOS).
