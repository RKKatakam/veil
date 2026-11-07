# 2. Rename and copy detection (`diff`, `log`, `status`, merge)

> **Access model:** written for the client of that round, which also restricted paths by cloaking them for a *scope*. Repository format 8 removed that, with every other non-secret encryption: only secret files (`.env`, keys) are encrypted, and access is the ordinary model in `docs/VISIBILITY.md` (admins, private by default, groups and managers, folder access, `public`).

Status: design and threat review. No format change: renames are computed, never stored, as in Git.

## Design sketch

- **Detection engine:** new `crates/veil-core/src/rename.rs`.

  ```rust
  pub struct RenameOptions { pub copies: bool, pub threshold: u8 /*50*/, pub limit: usize /*1000*/, pub budget: u64 }
  pub struct Pair { pub from: VPath, pub to: VPath, pub score: u8, pub copy: bool }
  pub fn detect(repo: &Repo, changes: &[TreeChange], reader: Reader, o: &RenameOptions) -> Result<Detected>
  // Detected { pairs: Vec<Pair>, changes: Vec<TreeChange> /* the rest */, truncated: bool }
  ```

  1. **Exact pass** (O(n)). Match deleted and added entries with equal `id` (and equal kind, after feature 6). Sealed objects pair only with the same sealed id: deterministic sealing makes that equal content, and the equality is already visible to everyone (the threat model's "equality leakage").
  2. **Inexact pass**, only on entries this reader can read as text (`blame::readable_version` = `Plain`).
     - Similarity uses Git's spanhash: 64-byte chunks hashed into a `HashMap<u32, u32>`, score = common / max. It is not Myers.
     - Only when `deleted × added ≤ limit²`; otherwise `truncated = true` and only exact pairs are reported, as with Git's `diff.renameLimit`.
     - Each file is capped at 16 MiB for the inexact pass.
  3. With `copies`, sources also include unchanged files of the old tree, inside the same limit; that is Git's `-C`, without `--find-copies-harder`.
- **CLI:**
  - `vl diff` and `vl show` print `R087 old -> new` and copies as `C`; `--no-renames` turns detection off and `-M[N]` / `-C` tune it.
  - `vl status` shows `R old -> new` (conformance t7525/t7001).
  - `vl log --follow PATH`, path filtering itself being feature 3.
  - JSON is additive in `veil.diff/2` and `veil.status/2`: `{status:"renamed", from, path, score}`. This is additive, so the schema keeps its version; `docs/reference/json.md` is updated.
  - Touches `api::change`, `api::diff_body` and `api::status` in `crates/vl/src/api.rs`, and `api/text.rs`.
- **Merge** (`merge.rs`): a rename on one side plus an edit on the other is a modify/delete conflict today (conformance note). New step in `merge::merge_trees_in`, before the directory walk:
  - Detect renames base→ours and base→theirs, exact plus inexact, with the reader's view. Detection is restricted to the **verified-public or same-audience** pairs below.
  - Build a path map, then merge each renamed file as `merge_file(be@old, oe@new_or_old, te@new_or_old)` at the destination path. The other path is recorded as deleted.
  - rename/rename to two different names is a conflict: both names are kept, and the conflict entry sits at both paths. rename/delete is a conflict.
  - Directory renames (Git's `ort` directory-rename detection) are **out of scope** this round.
  - `MergeOutcome` gains `renames: Vec<Pair>` for reporting. `vl merge` and `vl rebase` print "followed rename a -> b".
- **Builder hardening** (optional, recommended): protection follows content across a rename (see open decisions).

## Threat review

1. **The similarity score as an oracle on sealed content.** If inexact scoring read sealed objects for a reader who holds the key, and the result were stored or exported, it would leak. A score, the old-path pairing, is a few bits of information about sealed plaintext.
   - *Invariant:* renames are never stored in snapshots, trees or operations. They appear only in this reader's output.
   - *Test:* grep the encodings and the op log after a `vl merge` that followed a rename: no rename record.
2. **A merge result that depends on the merger's keys.** A member of `ops` pairs `deploy/.env` (sealed) with `config/env.txt` by content; a non-member cannot. The two merge differently, but that is not a leak. The risk is that a member's merge *moves sealed content to another path whose audience differs*.
   - *Invariant:* the content merge runs through `merge::merge_file` with the real entries, so its audience rules (`merged_visibility`, `audience_clash`, two scopes → conflict, BUG-123) decide the sealing. The pairing only changes which entries are combined.
   - *Test (property):* random trees with sealed and public files and random renames on both sides. After any merge, every result entry's verified audience is one of its inputs' audiences, or narrower (extend `hostile_labels_props.rs`).
3. **An edit following a rename from a sealed to a public path.** Ours moves `deploy/.env` (sealed for `ops`) to `docs/db.yml` *as sealed content*: an exact-id rename, so the sealing is carried. Theirs edits `deploy/.env`. The merged result at `docs/db.yml` must stay sealed for `ops`.
   - *Invariant:* `merged_visibility` of two `ops` versions is `ops`. A rename never re-runs the policy on merged content; only the builder does that, for working-copy edits.
   - *Test:* this exact scenario, then a public push; `docs/db.yml` is redacted on the mirror.
4. **An edit following a rename from a public to a sealed path.** Ours moves `config.yml` to `config/.env`, a secret file the policy cloaks (sealed when ours recorded it). Theirs makes a public edit of `config.yml`. The merge applies theirs' edit at the sealed path and seals it. This narrows the audience, which is allowed. The base text appears in markers only if `base_shown` is true (BUG-126).
   - *Test:* conflict this case and check that the materialised markers for the public reader contain no sealed text.
5. **The pairing reads content the merger cannot read.** *Invariant:* the inexact pass uses `Plain` versions only, so an unreadable entry can pair by exact id only. *Test:* a non-member merges; there are no `Corrupt` or decrypt attempts (a counter in the test store).
6. **Quadratic cost from hostile trees.** A pushed change deletes 50 000 files and adds 50 000 similar ones.
   - *Invariant:* the inexact pass runs only under `limit²` pairs and a byte budget (`budget`, default 1 GiB of hashing). Past that, exact pairs only, `truncated` is reported, and `vl diff` prints "rename detection skipped: too many files (limit 1000)".
   - Merge uses the same limits and falls back to today's behaviour (a modify/delete conflict), which is correct, only coarser.
   - *Test:* the crafted change; `vl diff`, `vl show`, `vl merge` and auto-rebase each take under 1 s in release.
7. **Many-to-one pairs.** Several deleted files are similar to one added file, or one deleted file is copied 10 000 times.
   - *Invariant:* each destination gets at most one source, assigned greedily by score and then by path; sources may be reused only for copies. The output size is linear in the changes.
   - *Test:* 10 000 identical copies; the output has 10 000 lines, and memory stays under 64 MiB.
8. **A rename across embargo views.** Removed in repository format 8 (only secret files are encrypted). An unreleased embargo is withheld from every push.
9. **Conflict entries as rename sources.** A conflict is matched only by an exact equal conflict id, never by inexact content (rendering it costs the materialise budget, and its sides have their own audiences).
10. **Kinds** (feature 6). A symlink renames only to a symlink, by exact id. A file ↔ symlink pair is never a rename.
11. **Case-only renames on macOS** (`README` → `readme`). The builder already keeps recorded spellings stable (`canonical_names`). `vl status` shows `R README -> readme` only after an explicit `mv` that changed the recorded spelling.
    - *Test (`macos_fs.rs` harness):* a case-only rename is shown as a rename, not as D + A.
12. **Auto-rebase churn.** Rename-aware merging in `Repo::rebase_tree` changes results for existing histories. That is a behaviour change, not a format change, but rebasing an old conflicted change could now resolve differently.
    - *Invariant:* rebasing a change onto its own parent is still a no-op (BUG-246); the rename pass runs only when base ≠ side.
    - *Test:* the existing `rebase_noop` tests still pass.
13. **`--json`, `vl serve`.** Additive fields only, with paths escaped by `to_json`. *Test:* the `json_cli.rs` outsider run includes a change with renames.

## Open decisions

- **Should rename detection run inside merges and auto-rebase by default?** *Recommendation:* yes, with exact and inexact passes within the limits, as Git's `ort` does. The modify/delete conflicts users get today are the commonest Git-parity complaint, and point 2 shows audiences are decided by `merge_file`, not by the pairing. Add `VEIL_MERGE_RENAMES=0` as an escape hatch for one release.
- **Protection follows content across a rename in the builder.** Today, `mv deploy/.env docs/db.yml`, where policy cloaks only `deploy/.env`, records `docs/db.yml` as *public* after a scan. *Recommendation:* in this round, the builder carries the deleted entry's verified sealing to the new path when the new file's plaintext id equals a sealed entry deleted in the same snapshot.
  - That is exact content only; the stat cache knows the plaintext id of sealed files it verified (BUG-300).
  - The file stays sealed, with a warning "`docs/db.yml` was `deploy/.env` (cloaked:ops); kept sealed; run `vl expose docs/db.yml` to publish".
  - This is a strengthening, consistent with "protection follows the name" for artefacts (§4 rule 2). Inexact matches only warn. Owner: stream W (builder).
- **Copies (`-C`) by default?** *Recommendation:* no. They are off by default in diff, log and merge, as in Git, because they are expensive and rarely wanted.
