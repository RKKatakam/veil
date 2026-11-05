# Git-parity round: build plan

From `integration` @ aa78e6d. The feature designs and threat reviews are in `1-…md` to `7-…md` in this directory (features 4, 5b, 8 and 9, Git interop, were removed on 2026-11-05: Veil does not interoperate with Git). Every builder brief must append its feature's "Threat review" list. Each numbered point is a required test (property or hostile-input), and the adversarial pass starts from the same lists.

## 1. Which features need a format bump

| feature | format change? | why |
|---|---|---|
| 1 blame, bisect, duplicate | no | computed; bisect state is device-local (`.veil/local/bisect.json`) |
| 2 renames | no | computed, never stored |
| 3 log -S/-G, grep | no | computed |
| 5a hooks | no | trust record is device-local |
| 5c annotated/signed tags | **yes** | new object `veil:atag`, new view field `Tag.annotation` |
| 6 symlinks | **yes** | new tree entry kind `symlink`, symlink terms in conflicts |
| 7 attributes / line endings | no | `.veilattributes` is a tracked file; conversion only changes which bytes are recorded |

## 2. The single format-5 proposal

One bump, `REPO_FORMAT = 5`, `min_vl_for_format(5)` = this round's release. It follows FORMAT.md §4.

1. **Tree entries (binary, encoding 2).** Flag **bit 7 = KIND**: when set, one byte `kind` follows `flags`, before `id`.
   - `kind` 1 = symlink; every other value is `Unsupported` (2 is reserved, never reused).
   - With KIND set, DIR, EXECUTABLE and CONFLICT must be clear. SIZE, FALLBACK and the tier bits keep their meaning.
   - A symlink's `id` names the (plaintext or sealed) object of its target bytes.
   - Canonical by construction: a set KIND bit must be followed by a valid kind.
   - JSON trees (format 1): `"kind":"symlink"`.
   - `Object::min_repo_format` returns 5 for any tree holding one. `ObjectStore::check_storable` and the pack sink refuse them below format 5.
2. **Conflict terms (§3.6).** Term flag **bits 6–7 = term kind**: 0 file, 1 symlink, 2 and 3 reserved. EXECUTABLE must be clear for non-files. Refused below format 5.
3. **New object `veil:atag\n`**, encoding byte `{` (canonical JSON):
   `{name, target, kind:"annotated", message: Text, tagger, timestamp, signature?}`.
   - The signature is over the unsigned id, with the new context `SIG_CONTEXT_TAG = "tag"` (added to `crypto/domains.rs` and the CRYPTO.md tables; a new signed body that never changes).
   - It is withheld from public remotes when the tag is cloaked.
4. **View** (operations, remote views): `Tag.annotation: Option<ObjectId>`, omitted when empty. A format-4 vl never sees them, because it refuses the repository and the remote.
5. **Upgrade `4 → 5`:** no step (nothing is rewritten; ids and signatures are kept). `vl upgrade --remote` as usual.
6. **Fixtures:** `tests/fixtures/format-5/`, generated once with `generate.sh <vl> <out> <format-4 set>`. It holds:
   - a public symlink, a symlink inside a cloaked directory (sealed target), and an absolute-target symlink;
   - an annotated signed tag and a cloaked annotated tag;
   - a link/file conflict;
   - the `upgraded/` set.
   - `encodings.txt` gains: a binary tree with a symlink, a conflict with a symlink term, and an atag.
   - `format_compat.rs`: a format-4 build is simulated by checking that the format-5 objects are `Unsupported` there; pushing them to a format-4 remote fails with the upgrade hint; the 4→5 upgrade keeps every id.

## 3. Build streams and file ownership

Rule: a stream edits only the files it owns. Appends to shared files (`lib.rs`, `cli.rs`, `main.rs` dispatch, `serve.rs` method table, `docs/reference/json.md`, `ARCHITECTURE.md`) go through **stream 0**'s stubs, or are one-line appends the orchestrator resolves at merge. Never run `cargo fmt`. Scratch work goes in `.scratch/`. Builds use `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=line-tables-only`.

**Stream 0 — wiring stubs** (orchestrator, before any agent, about 1–2 h, size XS)
- `cli.rs`: variants that delegate to argument structs owned by the streams:
  - `Blame(history::BlameArgs)`, `Grep(history::GrepArgs)`, `Bisect(history::BisectCmd)`;
  - `Duplicate(rewrite_cmd::DuplicateArgs)`, `CherryPick(…)`;
  - `Hooks(hooks::HooksCmd)`;
  - `Attr(attr_cmd::AttrArgs)`, `Renormalize(attr_cmd::RenormalizeArgs)`;
  - `Log` gains `#[command(flatten)] filter: history::LogFilterArgs`.
- `main.rs`: one dispatch line each.
- `lib.rs`: `pub mod` for the new core modules (empty files with a doc comment).
- Empty files: `crates/vl/src/{history,rewrite_cmd,hooks,attr_cmd}.rs`.
- Handlers return "not yet implemented".

**F — format 5 foundation** (size M; first, blocking W and G)
- Owns: `object.rs`, `tree.rs`, `conflict.rs` (term encoding only), `store.rs`, `repo.rs`, `upgrade.rs`, `fsck.rs`, `gc.rs`, `oplog.rs`, `remote.rs` (atag transfer and withholding), `crypto/domains.rs`, new `tag_object.rs` (atag type, canonical encoding, sign and verify), `docs/FORMAT.md`, `docs/CRYPTO.md` (tag context), `tests/fixtures/**`, `tests/core_format/format_compat.rs`, `tests/core_format/tree_encoding.rs`.
- Adds the minimal `match` arms elsewhere so the tree compiles: new kinds are carried unchanged, and refused where content is read.
- Done when: fixtures exist, golden encodings are appended, and the round-trip and `Unsupported` tests pass.

**H — history read tools** (size L; starts at t0, in parallel with F)
- Owns: new `blame.rs`, `bisect.rs`, `grep.rs`, `search.rs`, `rename.rs` (core); `revset.rs` (ranges); `crates/vl/src/api.rs` (blame, grep, log filters, renames in diff/status/log), `api/text.rs`, `crates/vl/src/history.rs`, `serve.rs` (new read methods only), `docs/reference/json.md`.
- Milestone **H1** = `rename.rs` with its tests, merged early: R depends on it.
- Features 1 (blame, bisect), 2 (detection and display) and 3.

**K — hooks** (size M; starts at t0)
- Owns: `crates/vl/src/hooks.rs` (the runner, `.veilhooks` parser, trust store, env scrub, timeout, copy-then-exec), plus the call sites in `cmd_commit`/`cmd_describe`/`cmd_push` (main.rs, those functions only) and `serve.rs` commit.
- Feature 5a.

**W — working copy** (size XL; after F; two phases by one agent, or two agents in sequence)
- **W1, symlinks:**
  - `vfs/{mod,disk,memory,overlay,sandbox,sparse,sftp}.rs` (`NodeKind::Symlink`, `read_link`/`write_link`, the `openat`/`O_NOFOLLOW` writer replacing `refuse_symlinked_parent`);
  - `builder.rs` (symlink entries, the rename-protection hardening from feature 2);
  - `checkout.rs`, `statcache.rs`, `workspace.rs`, `working_copy.rs`, `sandbox.rs` (core), `policy.rs` (`.git` symlink as VCS metadata);
  - `crates/vl/src/mount/fs.rs`, `crates/vl/src/sandbox.rs`.
- **W2, attributes:**
  - new `attributes.rs`, `crates/vl/src/attr_cmd.rs`;
  - the conversion hooks in `builder.rs` / `checkout.rs` / `statcache.rs` / `mount/fs.rs`, which W already owns;
  - the driver runner API (`attributes::MergeDriver`, `run_textconv`) for R.
- Features 6 and 7.

**G — annotated tags** (size M; after F)
- Owns: `commands.rs` (`set_tag` annotated and immutable), the `cmd_tag` function in `main.rs`.
- Feature 5c (CLI).

**R — rewrites** (size M; after H1; the driver wiring after W2)
- Owns: new `duplicate.rs`, `merge.rs`, `textmerge.rs` (driver hook), `crates/vl/src/rewrite_cmd.rs`.
- Feature 1 (duplicate and cherry-pick), feature 2 (rename-aware merge), and feature 7's merge-driver wiring.

## 4. Dependencies and order

```text
t0 ── stream 0 ──┬── F ──┬── W1 ── W2 ──┐
                 │       └── G          │
                 ├── H ── H1 (rename.rs) ── R (duplicate, rename merge) ── R (drivers, after W2)
                 └── K
                                   adversarial pass A: after F, W, G, H, K, R are merged
```

- Attributes need no format but share `builder.rs` and `checkout.rs` with symlinks, so W does W2 after W1 rather than in parallel.
- Pipeline merges (owner's process): merge each stream as soon as it is green.

## 5. Rough size per stream

| stream | size | production LOC (est.) | tests (est.) | agent time |
|---|---|---|---|---|
| 0 | XS | 150 | – | orchestrator, 1–2 h |
| F | M | 900 | 800 + fixtures | 0.5–1 day |
| H | L | 2 500 | 1 800 | 1.5–2 days |
| K | M | 900 | 700 | 1 day |
| W1 | L | 2 000 | 1 500 | 1.5 days |
| W2 | M | 1 300 | 1 000 | 1 day |
| G | M | 400 | 300 | 0.5 day |
| R | M | 1 200 | 1 000 (property) | 1 day |

## 6. Highest-risk items for the adversarial passes

1. **Code execution from a teammate's content.**
   - `.veilhooks` trust bypass: TOCTOU, indirect files, a sandbox or mount writing the trust record.
   - Attribute-named merge or diff drivers.
   - The common invariant: nothing from a tree ever *defines* a command, and repository-suggested commands run only from digest-pinned bytes.
2. **Symlink traversal and case-folding** (feature 6, points 1, 7 and 8).
   - Checkout, `ws exec` sandboxes (including `--only`) and the FUSE mount.
   - Includes the CVE-2021-21300 macOS shape and a race thread swapping a directory for a link mid-checkout.
   - Invariant: no write ever resolves through a link, and a sandbox never hands a link escaping to the project directory.
3. **Audience movement in rewrites.**
   - Rename-aware merge pairing across audiences (feature 2, points 2–4); merge and union drivers given a hidden base (feature 7, point 6).
   - `vl duplicate` of embargo-withheld history publishing the fix's file names, and the **pre-existing** `vl restore --from <fix>` route to the same leak (feature 1, point 11; check it in pass A).
   - Harness: extend `adversarial7/rewrites.rs` (publish to a public mirror after every command and grep the decoded objects) with duplicate and rename merges.

Suggested bug-ID range for this round's findings: BUG-600 to BUG-699.
