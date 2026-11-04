# 5. Copy-on-write checkouts of the project directory

Status: design and threat review (backlog: "Copy-on-write file clones for project-directory checkouts"). **No repository format change.**

> **This machine cannot exercise real reflinks:** `/` is ext4 (no `FICLONE`) and `/tmp` is tmpfs. Real clone tests run on macOS (APFS `clonefileat`, the `macos_fs.rs` precedent) and on any btrfs or XFS developer machine. Here, a `CloneCounting` test backend covers the logic.

## Today

`checkout::apply_changes` already asks the backend to clone: `fs.clone_known(&c.path, &new.id)`. That happens when:
- the file holds no local edit;
- no CRLF conversion applies;
- there is no fallback;
- and the entry is readable for this reader.

Only `SandboxFs` (`vfs/sandbox.rs`) answers it: it reflinks the **project directory's** file when the project's stat cache vouches for it (`StorageBackend::clone_known`, with the source `fstat`ed before and after). For the project directory itself, `DiskBackend` uses the trait default (`false`), so `vl ws switch`, `vl edit`, `vl new`, `vl undo`'s checkout and `vl clone`'s checkout always decompress (and decrypt) every changed file and write it in full.

## Design sketch

**`vfs/clone_source.rs`: `CloneSources`**, an ordered list of places that may already hold a file with a given blob id, each with a way to vouch for it:

| source | vouched by | verification after the clone |
|---|---|---|
| the project directory itself (renames and copies inside one checkout) | its own stat cache (`statcache.rs`, the racy-window rules) | `fstat` of the source before and after; the stamps are unchanged |
| persistent sandboxes `.veil/local/sandboxes/<ws>/files/` | the sandbox's stat cache (`manifest.json`'s per-file half) | the same, **and the clone's content is hashed** (threats 1–3) |

- **A sandbox is a source only when** its `flock` can be taken *shared and without waiting*, and its manifest:
  - is readable, of this boot, without `running` or `pending`;
  - has no injection in `guard.sealed`;
  - and the path is not listed in its guard.

  A busy or doubtful sandbox is simply skipped.
- **`DiskBackend::with_clone_sources(CloneSources)`** makes `DiskBackend::clone_known` try the sources in order, for regular files only:
  1. open the source beneath its root (`vfs/beneath.rs`, `O_NOFOLLOW`);
  2. `FICLONE` (Linux) or `fclonefileat` (macOS) into a temp file in the destination directory, which is opened without following links;
  3. set the mode explicitly, and on macOS drop the xattrs and ACLs that `clonefile` copies;
  4. verify, then rename into place.

  The first `EOPNOTSUPP` or `EXDEV` turns cloning off for the run, as the sandbox path already does.
- **`Ctx`** builds the sources for project-directory checkouts (`working_copy::move_working_copy`, `Ctx::finish_working_copy`) through the stub hook `clone_sources_for(ctx)` from stream 0, so stream O's `ctx.rs` is not edited by this stream.
- **Ordering in `apply_changes`.** When the target adds content that a path being removed holds (a rename), the clone is made **before** the removal. Resuming a journalled move from `pending` never relies on a source that may be gone: it falls back to a normal write.
- **Not sources:**
  - a mount's `upper/` (unrecorded user data);
  - ephemeral sandboxes;
  - other repositories;
  - **a plaintext blob cache** (a content-addressed directory of checked-out files would keep cloaked plaintext on disk after `vl ws switch` away; see open decision 1).
- **Measuring.** Item 9's `ws switch` case on a reflink-capable file system, with time and `du` (shared extents) before and after.

## Threat review

1. **Cloned content that is not the blob.** The source changed after its stamp was taken but within the racy window, or a background process the sandbox left running rewrites it in place. The project directory then holds bytes that differ from the tree, while the stat cache vouches for the tree's id, so the edit is never seen, or is recorded later under the wrong history.
   - *Invariant:* a cloned file enters the project's stat cache only once verified: its own files by unchanged stamps across the clone; sandbox files by hashing the clone against the blob id.
   - *Test:* a thread rewrites the source in a loop (same size, same mtime when possible) during `vl ws switch`. Afterwards every file equals the tree, or the switch reports it as written normally.
2. **Laundering an injected secret (the BUG-546 class).** A sandbox run with `--with-isolated` (or a background process from one) writes an isolated value into a tracked file. Cloning that file into the project directory puts the secret where the next snapshot records it.
   - *Invariant:* never clone from a sandbox with a live or pending injection, a `running` marker or a `pending` run, or from a path its guard lists; a sandbox-sourced clone is hashed, so it can only ever be the recorded blob.
   - *Test:* `ws exec --with-isolated` whose command leaves a background writer, then `ws switch` to that workspace. The project directory holds the injected value only where the tree itself holds it (never), and the scanner check passes.
3. **Link and hard-link tricks in a sandbox.** An agent replaces a sandbox file with a symlink or a hard link to `~/.ssh/id_rsa`.
   - *Invariant:* sources are opened beneath the sandbox root with `O_NOFOLLOW`; they must be regular files with the vouched inode; sandbox clones are hashed.
   - *Test:* replace a vouched file with a symlink, and separately with a hard link to a file outside. No clone happens, and the project file is written from the store.
4. **A file system without clones.** ext4, tmpfs, NFS, or cross-device paths.
   - *Invariant:* the first `EOPNOTSUPP`/`EXDEV` turns cloning off, and every file is written as today.
   - *Test:* `CloneCounting` returns `EOPNOTSUPP` on the first call. Exactly one clone is attempted, and the output is identical.
5. **A crash in the middle of the switch.**
   - *Invariant:* the journalled move (`checkout.json` `pending`, BUG-113) is unchanged. Resuming writes from the store whenever a source is missing.
   - *Test:* `crash.rs` `crash_during_workspace_switch` with clone sources, plus a crash after the rename's source was removed.
6. **A cloaked file for a reader without the key.**
   - *Invariant:* only entries with `store.entry_readable(new)` are cloned (the existing condition), so a reader without the key gets what checkout gives today (nothing, or the fallback).
   - *Test:* a sandbox of a cloaked-line workspace; the project directory switched by a member without that scope. No plaintext is cloned.
7. **Line endings, fallbacks and conflicts.**
   - *Invariant:* unchanged: never cloned (CRLF conversion, embargo fallbacks and conflict renderings differ from the blob).
   - *Test:* an `eol=crlf` file and a conflicted file in the switch; both are written, not cloned.
8. **macOS metadata.** `clonefileat` copies xattrs (`com.apple.quarantine`), ACLs and mode.
   - *Invariant:* after a clone the mode is the entry's (executable bit only) and no xattr from the source remains.
   - *Test:* in the `macos_fs.rs` style, a source with a quarantine xattr and mode 0777; the clone has neither.
9. **A mount or ephemeral sandbox used as a source.**
   - *Invariant:* only persistent sandboxes and the project directory are sources.
   - *Test:* a mount whose upper directory holds the target blob; nothing is cloned from it.

## Open decisions

1. **A plaintext blob cache for public files** (would make `vl clone` and first checkouts free on reflink file systems).
   - *Recommendation:* not this round. It must never hold sealed plaintext, it needs its own eviction, and the benchmark has to show the win first.
2. **Hash-verifying sandbox sources** (costs one read per cloned file).
   - *Recommendation:* yes, always. The disk-space saving stays; only the write saving is reduced.
3. **Using the project directory as a source for sandboxes** already exists; sharing in the other direction (sandbox → project) is what this item adds. Nothing further is planned.
