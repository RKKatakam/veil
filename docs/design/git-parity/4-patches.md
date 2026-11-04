# 4. Patches: `vl format-patch` (export) and `vl am` (import)

Status: design and threat review. No format change. Patches are the first feature whose output is *meant to leave the device*, to mailing lists, issues and other VCSs, so the default audience is the public view.

## Design sketch

### Export

```text
vl format-patch REVSET [-o DIR | --stdout] [--audience public|me] [--cover-letter] [--binary] [-M]
```

- **Engine:** new `crates/veil-core/src/patch.rs`.
  - `pub fn write_patch(repo, id, audience: Audience, opts, out: &mut dyn Write)` emits Git's mbox format: `From <git-oid-or-zeros> Mon Sep 17 00:00:00 2001`, `From:`, `Date:`, `Subject: [PATCH n/m]`, the body, `---`, a diffstat, then `diff --git` sections.
  - Sections carry `new file mode`, `deleted file mode`, `old/new mode` (100644/100755/120000 symlink, 160000 gitlink after feature 6), `rename from/to` with `-M` (feature 2), and `GIT binary patch` (literal only, zlib + base85) with `--binary`.
  - The `From <oid>` line uses the Git bridge's commit id when the snapshot is mapped (`GitBridge::commit_of`), otherwise 40 zeros.
- **Audience.**
  - `public` (the default) renders **exactly the Git export's view**. Trees go through `git::project` (`Projection`): sealed entries are absent, or shown as their fallback, and conflicts use `Audience::Public` markers. Descriptions go through `project::public_text`, giving `(description withheld: cloaked)`.
    - Snapshots that `remote::embargo_withheld(local, true)` withholds are **refused**, naming them.
  - `me` renders this reader's view. It needs `--audience me`, prints a warning to stderr naming every scope and embargo whose content is included, and writes `X-Veil-Audience: <scope,…>` into each patch header. Patches that include unreleased embargo content additionally need `--include-embargoed ID`.
- **CLI:** `crates/vl/src/patch_cmd.rs` (new). It shares `textmerge::create_patch` for hunks and `hunks.rs` for line handling.

### Import

```text
vl am FILE|DIR|- [-d DEST] [--3way] [--keep-author|--author-as-me] [--signoff]
```

- **Parser:** `patch::parse_mbox(bytes, limits) -> Result<Vec<Patch>>` is a strict parser of the Git format (and of plain unified diffs, with `-p1` paths), written by hand with no regexes. It takes:
  - headers `From`, `Date` and `Subject`;
  - an RFC 2047-decoded subject;
  - the body up to `---`;
  - `diff --git` sections with their extended headers;
  - text hunks;
  - `GIT binary patch` literals (no `delta` this round: refused, naming the file).
- **Applier:** `patch::apply(repo, base_tree, &Patch) -> Result<Applied>`. It never touches the working copy.
  1. It builds an `OverlayBackend` over a `TreeView` of `DEST`'s tree (default `@-`, the parent of the working copy), writes the patched files into the overlay, and runs the **builder** on it, with `SnapshotOptions::policy_incoming = true`, the `ws exec` path for imported trees.
     - Isolation, scanning, cloaking, sealed-content-keeps-audience and the policy pin all apply, exactly as for a Git import's `theirs`.
  2. One new change per patch is created on top of the previous one (`Transaction::new_change`), with description = subject + body, author = `From:` (a claim, as for Git import), and signed by this identity. Everything is one transaction, so `vl undo` takes back the whole series.
  3. `@` is then rebased onto the series' tip (auto-rebase), so the working copy's edits stay.
  - `--3way` uses the `index abc..def` blob ids: if the pre-image blob is in the Git bridge, it does a three-way merge via `merge::merge_trees`; otherwise it is a plain apply.
- **Context mismatch:** a hunk that does not apply exactly is searched within ±`fuzz` lines (default 0 offset search up to 1000 lines, no fuzz factor). Failure aborts the whole series before any transaction. There are no `.rej` files: a `.rej` would be an editor artefact recorded next to its base, and the user may not expect that.

## Threat review

### Export (confidentiality)

1. **Default patch of a cloaked-line change.** *Invariant:* `--audience public` output is byte-identical to `git format-patch` run on the Git bridge's export of the same snapshot range (one projection function).
   - *Test (differential):* export a range, `git format-patch` in the bridge, and compare. Also grep the patch for every cloaked plaintext, sealed description and isolated value (reuse `leak_helper.rs`).
2. **An embargo-withheld change in the range.** *Invariant:* it is refused before anything is written, and a partial `-o DIR` is never left behind (write to a temp dir in the destination, rename at the end). *Test:* a range that includes the fix; there is no output file and the exit code is 1.
3. **`--audience me` used by mistake.** The patch carries cloaked plaintext and is mailed to a list. Mitigations:
   - the flag cannot be shortened, and it is never the default;
   - `X-Veil-Audience` is set in each mail header;
   - with `--stdout` to a non-terminal, `me` also needs `--yes`.
   - *Test:* `--audience me --stdout | cat` without `--yes` is refused.
4. **Rename pairs leaking cloaked names.** With `-M` on the public view, rename detection runs on the projection only (feature 2, point 1), so a cloaked source path never appears as `rename from`. *Test:* move a cloaked file to a public path; a public patch shows `new file`, not `rename from secrets/…`.
5. **Diffstat and `index` lines.** Both are computed from the projected entries. An `index <old>..<new>` built from Veil sealed-object ids would reveal equality. *Invariant:* `index` lines carry Git blob ids of the *projected* content only. *Test:* `index` ids equal `git hash-object` of the projected content.
6. **Conflicts.** A conflict renders with `Audience::Public` (only plaintext versions, plus a `(not shown…)` line). *Test:* a conflict with a sealed side; the patch has no sealed text.

### Import (hostile input)

7. **Path traversal and reserved names.** `diff --git a/../../etc/x b/../../etc/x`, absolute paths, `.veil/repo.json`, `.git/hooks/pre-commit`, NUL, backslashes, overlong names, `//`, and names that differ only by case or Unicode normalisation (macOS).
   - *Invariant:* every path is parsed into a `VPath` (which refuses `..`, `.`, the `.veil` component, NUL and empty components), checked with `policy::vcs_metadata`, and quoted-path decoding follows Git's C-quoting exactly. Nothing is ever joined to an OS path: the overlay is in memory.
   - *Test (proptest):* a fuzzer over path headers, including `"a/\101"` quoting; no entry outside the tree, and `.veil` and `.git` are always refused.
8. **The symlink-then-write attack** (CVE-2023-23946 class). Patch 1 adds `link → /home/u/.ssh` (mode 120000); patch 2 writes `link/authorized_keys`.
   - *Invariant:* the applier works on a `TreeView` + `OverlayBackend`, where a symlink is an entry, not something to traverse. Writing below a path whose entry is a symlink is a "not a directory" error.
   - Checkout later refuses to write through links (feature 6, `refuse_symlinked_parent`).
   - *Test:* both patches in one mbox; `am` fails on patch 2, and nothing exists outside the repository after `vl new`.
9. **Policy weakening by patch.** A patch edits `.veilpolicy` (`secrets/ cloak team` → `secrets/ public!`).
   - *Invariant:* the snapshot uses `policy_incoming`, so the weakening is held back (`P`) and needs `vl policy accept`. It is never folded as the member's edit (BUG-101 class).
   - *Test:* `am` such a patch, then `vl status` shows `P`, and a public push does not contain `secrets/` plaintext.
10. **Secrets in the patch.** A patch adds `config.yml` with an AWS key. *Invariant:* the builder quarantines it, `am` aborts the series and reports "patch 3: config.yml quarantined (aws-access-key)", and no partial change is recorded. *Test:* exit code 1, the view is unchanged, and no object holds the key in the store (no `put` before the scan).
11. **Edits of sealed files.** A patch modifies a cloaked file. If the reader can read it, the applied edit is sealed under the parent's scope (the builder rule). If the reader cannot, `am` fails that patch with "cannot apply to sealed file"; it never treats the fallback as the base, which would turn the edit into a public file. *Test:* both cases.
12. **Decompression bombs and huge patches.**
    - `GIT binary patch` literal: the declared size is checked before inflating (`flate2` with a `take(limit)`), and the limit is `VEIL_MAX_OBJECT` (BUG-490).
    - Patch file size is capped at 1 GiB, hunks per file at 1 000 000, and the offset search is bounded (it is O(hunk × window)).
    - *Test:* a 10 KB patch declaring a 16 GiB literal is refused in under 100 ms, with RSS under 100 MB.
13. **Header injection.** Subjects or authors containing `\n`, `\r`, terminal escapes or RFC 2047-encoded escapes. *Invariant:* decoded headers are refused if they contain control characters other than tab, and descriptions are stored verbatim but printed through `render::safe`. *Test:* `=?UTF-8?B?G10yOzE=?=` in the subject.
14. **Mode and kind tricks.**
    - `new mode 160000` (a gitlink) needs feature 6/5 and a format-5 repository; otherwise it is refused.
    - `old mode` of a nonexistent file, two sections for the same path, or a rename from a missing file are all refused as malformed.
    - A mode change on `.veilpolicy` to a symlink is refused (`.veilpolicy` is never recorded as a symlink, feature 6).
15. **Concurrency.** `am` runs as one transaction under the repository lock. The working copy is snapshotted before (as every command is), then auto-rebased. *Invariant:* no lock is held while parsing large input; parse first, then lock. *Test:* `am` racing `vl commit` from another process; no edit is lost (the BUG-361/362 harness).
16. **CRLF and attributes.** A patch with CRLF context against LF content applies only if the file's `eol` attributes say so (feature 7); otherwise it is a mismatch error, never a silent rewrite of line endings.
17. **Author spoofing.** `From: Alice` is recorded as the author claim; the signature is the importer's. `vl log` shows "signed by Bob, author Alice", consistent with Git imports.

## Open decisions

- **Default audience for `format-patch`.** *Recommendation:* `public`. Patches leave the device, and the owner's invariant is "never publish". A member who wants cloaked content in a patch to a teammate should push to a team remote instead; `--audience me` exists for the rare local case.
- **Apply into the working copy, or into a new change?** *Recommendation:* new changes on top of `@-`, through the builder over an overlay, as `git am` creates commits. Writing into the working copy would turn the patch into the member's own edit and defeat `policy_incoming`.
- **`.rej` files and fuzz.** *Recommendation:* no fuzz and no `.rej`, and abort the whole series. That is simpler to reason about for hostile input, and `--3way` covers the common drift.
- **Binary deltas (`delta` blocks).** *Recommendation:* not this round. Refuse with a clear message: they need the exact pre-image and their own bomb checks.
