# Git-parity round: build plan

From `integration` @ aa78e6d. The feature designs and threat reviews are in `1-…md` to `9-…md` in this directory. Every builder brief must append its feature's "Threat review" list. Each numbered point is a required test (property or hostile-input), and the adversarial pass starts from the same lists.

## 1. Which features need a format bump

| feature | format change? | why |
|---|---|---|
| 1 blame, bisect, duplicate | no | computed; bisect state is device-local (`.veil/local/bisect.json`) |
| 2 renames | no | computed, never stored |
| 3 log -S/-G, grep | no | computed |
| 4 format-patch / am | no | `am` writes ordinary snapshots |
| 5a hooks | no | trust record is device-local |
| 5b submodules | **yes** | new tree entry kind `gitlink` |
| 5c annotated/signed tags | **yes** | new object `veil:atag`, new view field `Tag.annotation` |
| 6 symlinks | **yes** | new tree entry kind `symlink`, symlink terms in conflicts |
| 7 attributes / line endings | no | `.gitattributes` is a tracked file; conversion only changes which bytes are recorded |
| 8 bridge tags | **yes** (uses 5c) | `View::remote_release_tags`, atags for imported Git tags |
| 9 colocated Git | **yes** (gate) | `repo.json` `colocated`; format 5 makes an older vl refuse the directory, so it can never snapshot without the guards |

## 2. The single format-5 proposal

One bump, `REPO_FORMAT = 5`, `min_vl_for_format(5)` = this round's release. It follows FORMAT.md §4.

1. **Tree entries (binary, encoding 2).** Flag **bit 7 = KIND**: when set, one byte `kind` follows `flags`, before `id`.
   - `kind` 1 = symlink, 2 = gitlink; 0 and 3–255 are `Unsupported`.
   - With KIND set, DIR, EXECUTABLE and CONFLICT must be clear. SIZE, FALLBACK and the tier bits keep their meaning.
   - A symlink's `id` names the (plaintext or sealed) object of its target bytes. A gitlink's names a blob `"<hex commit id>\n"`.
   - Canonical by construction: `kind` must be minimal (only 1 or 2) and a set KIND bit must be followed by a valid kind.
   - JSON trees (format 1): `"kind":"symlink"` / `"kind":"gitlink"`.
   - `Object::min_repo_format` returns 5 for any tree holding one. `ObjectStore::check_storable` and the pack sink refuse them below format 5.
2. **Conflict terms (§3.6).** Term flag **bits 6–7 = term kind**: 0 file, 1 symlink, 2 gitlink, 3 reserved. EXECUTABLE must be clear for non-files. Refused below format 5.
3. **New object `veil:atag\n`**, encoding byte `{` (canonical JSON):
   `{name, target, kind:"annotated"|"lightweight-git", message: Text, tagger, timestamp, signature?, git?:{oid, raw}}`.
   - The signature is over the unsigned id, with the new context `SIG_CONTEXT_TAG = "tag"` (added to `crypto/domains.rs` and the CRYPTO.md tables; a new signed body that never changes).
   - It is withheld from public remotes when the tag is cloaked.
4. **View** (operations, remote views): `Tag.annotation: Option<ObjectId>` and `View::remote_release_tags: BTreeMap<String, ObjectId>`, both omitted when empty. A format-4 vl never sees them, because it refuses the repository and the remote.
5. **`repo.json`:** `colocated: {git_dir}` (device-local).
6. **Upgrade `4 → 5`:** no step (nothing is rewritten; ids and signatures are kept). `vl upgrade --remote` as usual.
7. **Fixtures:** `tests/fixtures/format-5/`, generated once with `generate.sh <vl> <out> <format-4 set>`. It holds:
   - a public symlink, a symlink inside a cloaked directory (sealed target), and an absolute-target symlink;
   - a gitlink (public), and a gitlink under a cloak;
   - an annotated signed tag, a cloaked annotated tag, and an imported lightweight Git tag;
   - a link/file conflict;
   - the `upgraded/` set.
   - `encodings.txt` gains: a binary tree with a symlink, one with a gitlink, a conflict with a symlink term, and an atag.
   - `format_compat.rs`: a format-4 build is simulated by checking that the format-5 objects are `Unsupported` there; pushing them to a format-4 remote fails with the upgrade hint; the 4→5 upgrade keeps every id.

## 3. Build streams and file ownership

Rule: a stream edits only the files it owns. Appends to shared files (`lib.rs`, `cli.rs`, `main.rs` dispatch, `serve.rs` method table, `docs/reference/json.md`, `ARCHITECTURE.md`) go through **stream 0**'s stubs, or are one-line appends the orchestrator resolves at merge. Never run `cargo fmt`. Scratch work goes in `.scratch/`. Builds use `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=line-tables-only`.

**Stream 0 — wiring stubs** (orchestrator, before any agent, about 1–2 h, size XS)
- `cli.rs`: variants that delegate to argument structs owned by the streams:
  - `Blame(history::BlameArgs)`, `Grep(history::GrepArgs)`, `Bisect(history::BisectCmd)`;
  - `Duplicate(rewrite_cmd::DuplicateArgs)`, `CherryPick(…)`;
  - `FormatPatch(patch_cmd::FormatPatchArgs)`, `Am(patch_cmd::AmArgs)`;
  - `Hooks(hooks::HooksCmd)`, `Submodule(submodule_cmd::SubmoduleCmd)`;
  - `Attr(attr_cmd::AttrArgs)`, `Renormalize(attr_cmd::RenormalizeArgs)`;
  - `GitCmd::{Colocate, Uncolocate, CheckPush}` → `colocate_cmd`;
  - `Log` gains `#[command(flatten)] filter: history::LogFilterArgs`.
- `main.rs`: one dispatch line each.
- `lib.rs`: `pub mod` for the new core modules (empty files with a doc comment).
- Empty files: `crates/vl/src/{history,rewrite_cmd,patch_cmd,hooks,submodule_cmd,attr_cmd,colocate_cmd}.rs`.
- Handlers return "not yet implemented".

**F — format 5 foundation** (size M; first, blocking W, G, C and the format parts of P)
- Owns: `object.rs`, `tree.rs`, `conflict.rs` (term encoding only), `store.rs`, `repo.rs`, `upgrade.rs`, `fsck.rs`, `gc.rs`, `oplog.rs`, `remote.rs` (atag transfer and withholding), `crypto/domains.rs`, new `tag_object.rs` (atag type, canonical encoding, sign and verify), `docs/FORMAT.md`, `docs/CRYPTO.md` (tag context), `tests/fixtures/**`, `tests/core_format/format_compat.rs`, `tests/core_format/tree_encoding.rs`.
- Adds the minimal `match` arms elsewhere so the tree compiles: new kinds are carried unchanged, and refused where content is read.
- Done when: fixtures exist, golden encodings are appended, and the round-trip and `Unsupported` tests pass.

**H — history read tools** (size L; starts at t0, in parallel with F)
- Owns: new `blame.rs`, `bisect.rs`, `grep.rs`, `search.rs`, `rename.rs` (core); `revset.rs` (ranges); `crates/vl/src/api.rs` (blame, grep, log filters, renames in diff/status/log), `api/text.rs`, `crates/vl/src/history.rs`, `serve.rs` (new read methods only), `docs/reference/json.md`.
- Milestone **H1** = `rename.rs` with its tests, merged early: R and P depend on it.
- Features 1 (blame, bisect), 2 (detection and display) and 3.

**K — hooks** (size M; starts at t0)
- Owns: `crates/vl/src/hooks.rs` (the runner, `.veilhooks` parser, trust store, env scrub, timeout, copy-then-exec), plus the call sites in `cmd_commit`/`cmd_describe`/`cmd_push` (main.rs, those functions only), `cmd_git` push (that arm only) and `serve.rs` commit.
- Feature 5a.

**P — patches** (size L; the parser starts at t0, the writer and applier after F and H1)
- Owns: new `patch.rs` (writer, strict parser, overlay applier), `crates/vl/src/patch_cmd.rs`.
- Uses `git::project` (pub(crate), same crate) and `rename::detect` read-only.
- Feature 4.

**W — working copy** (size XL; after F; two phases by one agent, or two agents in sequence)
- **W1, symlinks and gitlink carry:**
  - `vfs/{mod,disk,memory,overlay,sandbox,sparse,sftp}.rs` (`NodeKind::Symlink`, `read_link`/`write_link`, the `openat`/`O_NOFOLLOW` writer replacing `refuse_symlinked_parent`);
  - `builder.rs` (symlink entries, gitlink carry, the rename-protection hardening from feature 2);
  - `checkout.rs`, `statcache.rs`, `workspace.rs` (`SnapshotOptions::only`, needed by C), `working_copy.rs`, `sandbox.rs` (core), `policy.rs` (`.git` symlink as VCS metadata);
  - `crates/vl/src/mount/fs.rs`, `crates/vl/src/sandbox.rs`.
- **W2, attributes:**
  - new `attributes.rs`, `crates/vl/src/attr_cmd.rs`;
  - the conversion hooks in `builder.rs` / `checkout.rs` / `statcache.rs` / `mount/fs.rs`, which W already owns;
  - the driver runner API (`attributes::MergeDriver`, `run_textconv`) for R.
- Features 6 and 7, and the builder part of 5b.

**G — Git bridge objects and tags** (size L; after F)
- Owns: `git/{import,export,project,map,mod,transport}.rs`, `commands.rs` (`set_tag` annotated and immutable), new `submodule.rs` (`.gitmodules` parse, URL and name validation, clone runner), `crates/vl/src/submodule_cmd.rs`, the `cmd_tag` function in `main.rs`.
- Features 5b (bridge and CLI parts), 5c (CLI) and 8.
- Exposes for C: `GitBridge::export_snapshot_for(@-)` and an `ImportOrigin::{Remote, Local}` parameter on `import_tips` (stubbed as always `Remote`).

**R — rewrites** (size M; after H1; the driver wiring after W2)
- Owns: new `duplicate.rs`, `merge.rs`, `textmerge.rs` (driver hook), `crates/vl/src/rewrite_cmd.rs`.
- Feature 1 (duplicate and cherry-pick), feature 2 (rename-aware merge), and feature 7's merge-driver wiring.

**C — colocated Git** (size XL; after F, W1 and G are merged; K is optional)
- Owns: new `git/colocate.rs` (follow, mirror, supersede, exclude writer), `git/index.rs` (index writer with skip-worktree), new `policy_gitignore.rs`, `crates/vl/src/ctx.rs` (`open` and `finish` hooks), `crates/vl/src/colocate_cmd.rs`, the `cmd_init` `--colocate` path in `main.rs`.
- At hand-over from G, also the `ImportOrigin::Local` logic inside `git/import.rs` and `git/export.rs` (carry-over source rule).
- Feature 9.

## 4. Dependencies and order

```text
t0 ── stream 0 ──┬── F ──┬── W1 ── W2 ──┐
                 │       ├── G ─────────┼── C (after W1 + G) ── adversarial pass B (colocated focus)
                 │       └── P (writer/applier)
                 ├── H ── H1 (rename.rs) ── R (duplicate, rename merge) ── R (drivers, after W2)
                 ├── K
                 └── P (parser)
                                   adversarial pass A: after F, W, G, H, K, P, R are merged
```

- Symlinks and gitlinks share the format-5 entry kind; they are designed together in F and implemented together in W1 and G.
- Attributes need no format but share `builder.rs` and `checkout.rs` with symlinks, so W does W2 after W1 rather than in parallel.
- Colocated mode depends on:
  - bridge tags (G: refs, tags, HEAD export of `@-`);
  - symlinks (W1: the no-follow writer and the restricted checkout);
  - `SnapshotOptions::only` (W1);
  - format 5 (F).
- It ships behind `--experimental` until pass B is clean.
- Pipeline merges (owner's process): merge each stream as soon as it is green. Fix waves for pass A can run while C builds, because their files are disjoint from C's.

## 5. Rough size per stream

| stream | size | production LOC (est.) | tests (est.) | agent time |
|---|---|---|---|---|
| 0 | XS | 150 | – | orchestrator, 1–2 h |
| F | M | 900 | 800 + fixtures | 0.5–1 day |
| H | L | 2 500 | 1 800 | 1.5–2 days |
| K | M | 900 | 700 | 1 day |
| P | L | 2 000 | 1 500 (fuzzers) | 1.5 days |
| W1 | L | 2 000 | 1 500 | 1.5 days |
| W2 | M | 1 300 | 1 000 (differential vs `git`) | 1 day |
| G | L | 1 800 | 1 400 | 1.5 days |
| R | M | 1 200 | 1 000 (property) | 1 day |
| C | XL | 3 000 | 2 500 (race and property harnesses, Git-version matrix) | 2–3 days |

## 6. Highest-risk items for the adversarial passes

1. **Colocated `.git` receiving or publishing sealed plaintext** (feature 9, points 1–8 and 12–13).
   - Covers `git add -A` / `commit -a` / `stash -a` routes, skip-worktree being cleared by some Git version or command, and the HEAD-follow recording a sealed working-copy file as public after `git checkout`.
   - Also: carry-over from local-origin commits, and direct `git push`.
   - Harness: the random git/vl interleaving property test, with invariants I1–I3, plus the Git-version × command matrix. **Pass B is dedicated to this.**
2. **Code execution from a teammate's content.**
   - `.veilhooks` trust bypass: TOCTOU, indirect files, a sandbox or mount writing the trust record.
   - Attribute-named merge or diff drivers.
   - `.gitmodules` URLs and names (`--upload-pack`, `ext::`, `../` names → `.git/modules` hooks).
   - Patches creating symlinks then writing through them.
   - The common invariant: nothing from a tree, a patch or a Git object ever *defines* a command, and repository-suggested commands run only from digest-pinned bytes.
3. **Symlink traversal and case-folding** (feature 6, points 1, 7 and 8).
   - Checkout, `am`, `ws exec` sandboxes (including `--only`), the FUSE mount, and the colocated hidden-part checkout.
   - Includes the CVE-2021-21300 macOS shape and a race thread swapping a directory for a link mid-checkout.
   - Invariant: no write ever resolves through a link, and a sandbox never hands a link escaping to the project directory.
4. **Audience movement in rewrites and exports.**
   - Rename-aware merge pairing across audiences (feature 2, points 2–4); merge and union drivers given a hidden base (feature 7, point 6).
   - `vl duplicate` of embargo-withheld history publishing the fix's file names, and the **pre-existing** `vl restore --from <fix>` route to the same leak (feature 1, point 11; check it in pass A).
   - `format-patch` defaults (feature 4, points 1–5); release tags on unreleased embargoes (feature 8, point 3).
   - Harness: extend `adversarial7/rewrites.rs` (publish to a public mirror after every command and grep the decoded objects) with duplicate, `am`, rename merges and `format-patch` output.

Suggested bug-ID range for this round's findings: BUG-600 to BUG-699.
