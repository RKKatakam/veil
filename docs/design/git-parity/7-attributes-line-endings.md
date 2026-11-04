# 7. Line endings and per-path attributes (`.gitattributes`)

Status: design and threat review. **No format change.** Attributes live in a tracked text file, and conversion only changes which bytes are recorded and written.

## Design sketch

- **Source:** Veil reads `.gitattributes` itself, at the root and in subdirectories, with Git's precedence: deeper files win, last line wins within a file, plus macros (`binary`). This keeps GitHub, Git and colocated mode in agreement, and there is no second file to keep in sync.
  - Device-local overrides go in `.veil/local/attributes` (as `.git/info/attributes`).
  - Parsing uses `gix-attributes` (already in the dependency tree through `gix`), or a small parser in a new `crates/veil-core/src/attributes.rs` if `gix-attributes` cannot be built without `os` for the WASM build.
- **Supported attributes this round:**

  | attribute | effect |
  |---|---|
  | `text`, `-text`, `text=auto` | normalise CRLF → LF when recording (`text`; `auto` = only when the file looks like text: no NUL in its first 8 000 bytes) |
  | `eol=lf`, `eol=crlf` | line endings written at checkout (implies `text`) |
  | `binary` (= `-text -diff -merge`) | no conversion, diff prints "binary", merge is whole-file |
  | `-diff`, `diff=<driver>` | `vl diff`/`show`/`log -p`/`format-patch` show "binary files differ"; a *named* driver uses `textconv` only if it is defined device-locally |
  | `-merge`, `merge=text\|binary\|union\|<driver>` | the content merge in `merge::merge_file_content`; named drivers only if defined device-locally |
  | `linguist-*`, `export-ignore`, `filter`, `ident`, `working-tree-encoding` | ignored, and listed by `vl attr check` as "not supported by Veil" (`filter` gets a warning: Veil records the raw bytes) |

- **Device-local driver definitions** go in `.veil/local/config.toml` or `$VEIL_HOME/config.toml`: `[merge.<name>] command = [...]` and `[diff.<name>] textconv = [...]`. They are argv arrays with placeholders `%O %A %B %P`.
- **API:**
  - `attributes::Attrs::load(fs or tree) -> Attrs`
  - `attrs.for_path(&VPath) -> PathAttrs { text: Text, eol: Option<Eol>, diff: DiffAttr, merge: MergeAttr }`
  - `attrs.id() -> Hash`: the BLAKE3 of every `.gitattributes` content plus the local file, used as a cache key.
- **Recording (builder):** `plain_file_entry` applies `to_odb(bytes, attrs)` before hashing, scanning and sealing.
  - Conversion is done **only if it round-trips**: the file's line endings are all CRLF (or all LF), with no lone CR. Otherwise the bytes are recorded as they are, with a warning ("`x.txt` has mixed line endings; recorded unchanged"), as Git's `core.safecrlf=warn`.
  - The stat cache key gains `attrs.id()`: a changed `.gitattributes` re-checks only the files whose `PathAttrs` changed (a per-path attribute fingerprint is stored with each cache entry).
- **Checkout:** `write` applies `to_worktree(bytes, attrs)` (LF → CRLF for `eol=crlf`). `Materialised` records, for each path written with a conversion, the attribute fingerprint used, so the "holds exactly the `from` version" check (`checkout::holds`) converts the `from` version with the **same** fingerprint before comparing.
- **No silent renormalisation:** changing `.gitattributes` does not re-record unchanged files. `vl renormalize [PATHS]` (an explicit command, an operation of its own) re-records them; `vl status` says "N files would change line endings; run `vl renormalize`".
- **Diff and merge drivers:** `merge::merge_file_content` gets a `ContentMerge` strategy from `PathAttrs` (`Text` → `textmerge::merge`, `Union`, `Binary` → whole-file conflict, `External(cmd)`). Wiring this into `merge.rs` is owned by stream R (see `PLAN.md`); the attributes stream provides `attributes.rs` and the driver runner.
- **CLI:** `vl attr check PATH…` (like `git check-attr`) and `vl renormalize`.

## Threat review

1. **Attributes that disable secret scanning.** `*.yml binary` or `config.yml -text -diff`. *Invariant:* attributes never change classification or scanning. The scanner reads the bytes about to be recorded, after conversion, whatever their attributes (§4 rule 4: binary files are scanned). *Test:* `.gitattributes` `* binary` plus an AWS key in `config.yml`; it is quarantined.
2. **Normalisation hiding a secret, or changing what was scanned.** The scanner must see exactly the bytes that are hashed and sealed. *Invariant:* `to_odb` runs first, then scanning, sealing and the store `put`, in that order and on one buffer. *Test (property):* random CRLF/LF content with planted secrets across line breaks; every planted secret is found.
3. **Data loss through lossy conversion.** A hostile `* text eol=lf` on PNGs and zip files with CR bytes, or a mixed-ending file. *Invariant:* conversion only if `to_worktree(to_odb(x)) == x` for the attributes in force, checked per file; otherwise the bytes are recorded unchanged and a warning is given. *Test (property):* arbitrary bytes under every attribute combination; the recorded bytes check out bytewise identical to the original.
4. **Checkout overwriting a user edit after an attribute change** (the "never overwrite what it did not materialise" rule). A file was written as CRLF under `eol=crlf`, `.gitattributes` then changed to `eol=lf`, and the user edited the file.
   - If `holds()` converted `from` with the *new* attributes, the disk (CRLF + edit) would never match and the file is kept, which is correct. The danger is the other way round: an unedited file compared under the new attributes is reported `kept` forever (wedged).
   - *Invariant:* `holds()` uses the fingerprint recorded in `Materialised` at write time; a record without one (older vl) falls back to "no conversion".
   - *Tests:* edit after an attribute change, then switch: the edit is kept. No edit after an attribute change, then switch: the file is updated, not `kept`.
5. **Code execution through drivers.** `.gitattributes` `* merge=pwn` or `diff=pwn` from a teammate. *Invariant:* attributes only *name* drivers; a name not defined in device-local configuration falls back to the built-in (`text` for merge, the plain diff), with one warning per command. `.gitattributes` can never define a command. *Test:* a pulled `.gitattributes` naming a driver, plus a tracked `config.toml` or `.veil.toml` at the root (trees cannot hold `.veil/`, so this is the closest lookalike); neither is read as driver configuration, and nothing is executed.
6. **Merge drivers and audiences** (BUG-126 class). An external or `union` driver gets the base (`%O`). When the base is sealed for another audience than the result, the driver could copy base text into a public result.
   - *Invariant:* the driver gets the base only when `merge::base_shown` is true, and an empty file otherwise. Its output is the merged content, and the entry's sealing is decided by `merged_visibility` / `audience_clash` as for diff3. A driver is never invoked when two scopes clash, which stays a conflict.
   - *Test:* a `union` merge with a `team`-sealed base and two public sides; the result contains no base-only lines.
7. **Textconv leaking sealed plaintext.** `diff=<driver>` with a device-local textconv sends cloaked plaintext to an external program. That is the user's own configured tool, but its output may be cached by the tool.
   - *Invariant:* Veil never caches textconv output on disk, and `format-patch --audience public` never uses textconv: patches are byte diffs of the projection.
   - *Test:* `format-patch` with a textconv configured; the patch equals the bridge's `git format-patch`.
8. **Attributes affecting the Git export.** The bridge exports recorded blobs as they are; Git applies its own `.gitattributes` at checkout. *Invariant:* export never applies `to_worktree`, so Git blob ids equal those of the recorded bytes. *Test:* a round trip through `vl git push` and a `git clone` with `eol=crlf`; `git status` is clean.
9. **Colocated mode** (feature 9). Git and Veil must convert identically, or `git status` shows every file as modified and a `git commit -a` records converted content as edits. *Invariant:* Veil implements exactly Git's `text`, `eol` and `auto` rules (Git's `convert.c`), and colocated mode sets `core.autocrlf=false` in `.git/config` so only attributes decide. *Test:* a differential test of `git add` versus a Veil snapshot of CRLF/LF files under each attribute; the blob ids are equal.
10. **Denial of service through huge attribute files.** 1 million patterns, or 100 000 nested `.gitattributes`. *Invariant:* each `.gitattributes` is capped at 1 MiB (as `.veilpolicy`), the patterns are compiled into a `globset` once per command, and one tree walk collects them. *Test:* a 1 MiB file on a 20 000-file tree; `vl status` slows by under 20 %.
11. **A cloaked or unreadable `.gitattributes`.** A sealed `.gitattributes` the reader cannot open: defaults apply with a warning (BUG-121 style), and nothing blocks a checkout.
    - Conversion then differs between members and non-members. Non-members write LF where members write CRLF, but the recorded bytes are the same, so no edit is recorded.
    - *Test:* an outsider checks out and runs `vl status`; it is clean.
12. **First-class conflicts.** Markers are rendered on LF content and then converted for the working copy. Parsing back (`conflict::parse_markers`) reads the converted copy, so it must undo the conversion first. *Test:* an `eol=crlf` conflict, edited in an editor that keeps CRLF, resolves cleanly.
13. **Sandboxes, mounts and `ws exec`.** These use the same `Attrs` from the tree they materialise. The mount converts on read (`to_worktree`) and on write (`to_odb`); its stat model is per-overlay. *Test:* a mount of an `eol=crlf` file shows CRLF; writing LF back records no change.
14. **The upgrade path.** Repositories recorded before this feature hold CRLF blobs where `text` would now normalise. *Invariant:* nothing is re-recorded automatically (no renormalisation); the first edit records LF, and the diff of that edit shows the line-ending change. This is documented.

## Open decisions

- **Read `.gitattributes`, or a Veil-specific `.veilattributes`?** *Recommendation:* `.gitattributes`. It is what GitHub, IDEs and Git (colocated) read, so a second file would drift. Attributes cannot weaken confidentiality (point 1) and cannot execute code (point 5), so they need no accepted-policy pin.
- **`core.autocrlf` equivalent.** *Recommendation:* none. Conversion is per repository through attributes only, so behaviour does not depend on device configuration, which caused Git's worst line-ending bugs.
- **`working-tree-encoding`, `filter` (Git LFS), `ident`.** *Recommendation:* not this round. `filter=lfs` gets a specific warning: Veil records the pointer file's raw bytes as they are on disk, which after `git lfs smudge` is the full content.
