# 1. `vl blame`, `vl bisect`, `vl duplicate` (cherry-pick)

Status: design and threat review for the Git-parity round, from `integration` @ aa78e6d.
No format change.

## Design sketch

### `vl blame` (alias `annotate`)

```text
vl blame PATH [-r REV] [-L START,END] [--follow] [--max-changes N] [--json]
```

- **Output:** one line per line of `PATH` at `REV` (default `@`): the short change id, the author (a claim; see the threat model), the date and the line.
  - `--json` returns `veil.blame/1`: `{path, rev, lines:[{line, change, snapshot, author, timestamp, text}], unattributed?, redacted?}`.
- **Algorithm** (new `crates/veil-core/src/blame.rs`, `pub fn blame(repo, rev, path, opts) -> Result<Blame>`):
  - Walk the ancestors of `REV`, children before parents (`Repo::topo_children_first`). Keep the set of lines not yet attributed. For each snapshot, diff the file between the snapshot and each parent's version.
    - The parent's version comes from `Repo::parents_tree`, the same merged base `vl diff` uses. A line that every parent lacks is attributed to the snapshot. A line a parent holds moves to that parent.
  - Diffs go through `textmerge::create_patch` (bounded; BUG-484/491). When the bound is hit, the whole differing middle is attributed to that snapshot, and the result says `coarse: true`.
  - The walk stops when every line is attributed, at the root, or at `--max-changes` (default 100 000 snapshots visited). Lines that are still open are reported as `unattributed`, never guessed.
  - `--follow` uses `rename::detect` (feature 2) at each step where the path disappears.
- **Content is read as this reader** through one helper, `blame::readable_version(repo, entry) -> Readable`:
  - `Plain(bytes)`: public content, or sealed content this identity opens; `builder::verify_sealing` checks the label.
  - `Fallback(bytes)`: an embargoed entry the reader cannot open, or a line-cloaked public file, shown as its last public version. This is the version `vl cat` shows them.
  - `Redacted(reason)`.
  - A conflict entry is rendered with `conflict::materialize(…, Audience::Reader)`, so marker lines are attributed to the snapshot that recorded the conflict.
- **Descriptions:** blame prints change ids, never descriptions, so a sealed description cannot leak through it. `--json` gives `snapshot_ref`, which already uses `api::description` (`HiddenText`). With `--public` it gives `snapshot_ref_as(…, public)`: the description as a public mirror reads it (`git::public_description`), so a cloaked or unreleased-embargo description is `HiddenText` with reason `not_public` even for a member who holds the key (BUG-704).
- **CLI:** `crates/vl/src/history.rs` (new), `api::blame` in `crates/vl/src/api.rs`, and a `blame` method in `serve.rs`.

### `vl bisect`

```text
vl bisect start --bad REV --good REV [--good REV…]
vl bisect good|bad|skip [REV]
vl bisect run [--with-isolated] -- CMD…
vl bisect reset
vl bisect log
```

- **State** lives in `.veil/local/bisect.json`: pretty JSON `{version:1, workspace, started_from:<wc snapshot>, bad, good[], skip[], log[]}`. It is device-local and not a format change. It needs no gc change: every snapshot it names is visible history when bisect starts. If one becomes unreachable (abandoned, then gc'd), bisect stops with "run `vl bisect reset`".
- **Candidates:** ancestors of `bad` that are not ancestors of any `good`. Pick the candidate that splits the remaining count most evenly, and break ties by id so the choice is deterministic.
  - Merges are handled as Git handles them: the candidate set is the whole DAG difference.
  - New module `crates/veil-core/src/bisect.rs` (pure graph functions: `candidates`, `next`, `verdict`).
- **Interactive steps** check out the candidate with the same path as `vl new <candidate>` (`Repo::new_change`, then a checkout).
  - The empty, undescribed change is abandoned automatically when the user moves on (existing rule).
  - `vl bisect reset` runs `vl edit <started_from>`.
- **`vl bisect run`** never touches the project directory. Each step runs `CMD` in an ephemeral `ws exec` sandbox on the candidate: `sandbox::exec` with `ephemeral` and a revision.
  - Exit code 0 means good, 125 means skip, 1–127 means bad, and anything else aborts, as in Git.
  - The sandbox gets no isolated files unless `--with-isolated` is given (the `ws exec` rule).

### `vl duplicate` (cherry-pick)

```text
vl duplicate REV… [-d DEST…] [--keep-description|-m MSG] [-x]
vl cherry-pick REV… [-d @]     (alias: duplicate onto @-, then @ rebases on top)
```

- **Engine:** `Repo::duplicate(src, dest) -> Result<ObjectId>` in a new `crates/veil-core/src/duplicate.rs`, as an `impl Repo` block next to `commands.rs`.
  - The tree comes from `Repo::rebase_tree(src.parents, dest, src.tree, cloak)`, which is the auto-rebase merge, so first-class conflicts are recorded rather than refused.
  - It gets a new change id, `author` = the original author, `timestamp` = now, and is written through `Transaction::new_change`-style code so it is signed.
- **Description:** kept as the stored `Text`. A sealed description stays sealed for its scope; it is never decrypted and re-written as plaintext. `-x` appends `(duplicated from change <id>)` only when the description is plain.
- **Cloak:**
  - The duplicate takes the destination line's cloak (`trusted_cloak` of the parent).
  - Content keeps its verified sealing (`merge::merge_file`).
  - Duplicating into a cloaked line runs `embargo::seal_introduced` (and `seal_conflict_terms`) on what it brings, as squash does (BUG-480/483).

## Threat review

1. **Blame of a file whose history passed through sealed versions.** A public file is edited on a cloaked line (sealed, with a fallback), then exposed.
   - A non-member's blame must attribute lines using the versions they can read (fallbacks), never call `read_blob` on ciphertext, and never error out or print the error's bytes.
   - *Invariant:* blame reads only through `readable_version`; a `Redacted` step attributes nothing past it. Lines that are open there are `unattributed (history sealed for <scope>)`.
   - *Test:* a non-member and a public-mirror clone run `vl blame --json`; grep the output for every cloaked-line plaintext.
2. **The fallback is attributed to the wrong change.** For a reader without the key, the sealed snapshot shows the fallback, which is identical to its parent. Its lines must stay with the older public change and not be attributed to the cloaked change, which would hint that the cloaked change touched those exact lines.
   - *Invariant:* an unchanged readable version passes all lines to the parent.
   - *Test:* blame as an outsider across a cloaked edit; no line is attributed to the cloaked change.
3. **Embargo metadata.** Attributing a line to the embargoed merge, for a reader without the key, would reveal which lines the fix touched (BUG-018 class).
   - *Invariant:* for non-holders the wrapper resolves to its fallback, which equals the pre-merge version, so nothing is attributed to the merge.
   - *Test:* an embargoed fix of line 10; outsider blame shows line 10 attributed to its pre-fix change.
4. **Hostile history, quadratic cost.** A remote pushes 50 000 snapshots, each rewriting a 20 000-line file, or a merge fan-out.
   - *Invariant:* each diff is bounded by `textmerge`, and the walk is bounded by `--max-changes` and an overall work budget (lines × snapshots visited ≤ 2^32, then stop with `unattributed`).
   - *Test:* the crafted history finishes in under 2 s in release and reports `coarse` or `unattributed`.
5. **A merge with many parents and criss-cross history.** Attributing through each parent multiplies the work.
   - *Invariant:* a line is passed to the first parent that holds it, and each snapshot is visited at most once per blame (memo of open lines per snapshot, merged on revisit).
   - *Test:* an octopus of 64 parents and a 1 000-deep criss-cross both finish within the budget.
6. **Terminal escapes in lines, author or path.** *Invariant:* the text output goes through `render::safe`, and JSON through `api::to_json`. *Test:* a line containing `\x1b]52;` (clipboard OSC) prints escaped.
7. **Bisect runs historic code.** `vl bisect run` executes `CMD` on old trees, which may hold a teammate's scripts. That is the user's own command, as in Git, but it must not inherit vault secrets silently.
   - *Invariant:* there is no `--with-isolated` by default, and `vl run`'s team-vault variables are not injected.
   - *Test:* `bisect run env` in a repository with a local vault and an `.env` shows neither.
8. **Bisect over trees this reader cannot fully read.** A sandbox with redacted files (left out, or a fallback) gives a misleading verdict.
   - *Invariant:* a candidate whose materialisation reports `hidden` or `from_fallback` entries is shown with a warning, and `bisect run` marks it `skip` unless `--trust-partial` is given.
   - *Test:* bisect across a cloaked file as an outsider; those steps are skipped.
9. **Bisect state as an attack surface.** `.veil/local/bisect.json` is local, but a stale or damaged file must not stop other commands.
   - *Invariant:* an unknown version or bad JSON makes bisect commands refuse with "run `vl bisect reset`", and nothing else reads the file.
   - *Test:* write garbage there; `vl status` still works.
10. **Bisect and the working copy.** A user who edited files mid-bisect loses nothing: every command snapshots first, so edits land in the candidate's change, which is then *not* empty and is not abandoned.
    - *Invariant:* `bisect good|bad` refuses to move off a candidate change holding edits unless `--discard` (it names the change).
    - *Test:* edit during bisect, then run `bisect good`; it is refused and the edit is kept.
11. **Duplicating an embargo-withheld change onto a public line.** The fix change is in `remote::withheld_by_embargo`; its files are sealed under the scope. A duplicate on `main` would publish the fix's file names, sizes and the existence of the change before release (the threat model promises the embargoed tree is sealed whole). Sealing keeps the content safe; the metadata leaks.
    - *Invariant:* `duplicate` refuses a source that any unreleased embargo withholds (`remote::embargo_withheld(local, true)` contains it) unless the destination is itself withheld by the same embargo. The hint is `vl merge --embargo`.
    - *Test:* duplicate the fix onto `main`, push to a public remote, and check that no path of the fix appears.
    - *Adversarial note:* the same metadata route exists today through `vl restore --from <fix> PATH` on `main`. Check it in the adversarial pass.
12. **Duplicating a cloaked change into a public line.** Content stays sealed (`merge_file`), the description stays sealed, and the snapshot's `cloak` is `None`. A public file on the cloaked line was sealed with a fallback, and must stay sealed rather than be re-read as plaintext.
    - *Invariant:* the duplicate never calls the builder on materialised content; it is a tree merge only.
    - *Test (property):* random cloaked changes duplicated onto public lines, then a public push; the mirror's decoded objects contain no cloaked plaintext (reuse `adversarial7/rewrites.rs`).
13. **Duplicating a public change into a cloaked line.** It must seal what it introduces (`seal_introduced`, `seal_conflict_terms`, BUG-480). Otherwise the line holds public content that the next declassification would treat as "introduced by the line" (BUG-128 class).
    - *Test:* duplicate into a cloaked workspace and check `api::entry_tier` on every introduced path.
14. **Duplicated conflicts.** A source with conflict entries carries them. Versions keep their sealing, and a conflict with a version sealed for another scope stays as recorded (BUG-123).
    - *Test:* duplicate a two-scope conflict, then `resolve --list` as each member.
15. **Signature and provenance spoofing.** `author` is copied (a claim), the duplicate is signed by the duplicator, and `vl log` shows both. *Invariant:* no field implies the original signer signed the duplicate.
16. **Undo.** One transaction per command, so `vl undo` removes the duplicates exactly. *Test:* duplicate three changes, then `undo`; the view is equal.
17. **`--json` and `vl serve`.** `veil.duplicate/1` lists the new ids only. `serve` exposes `blame` (read) and not `bisect run` (it executes code). *Test:* `serve` method list check (`every_method_is_listed_once`).

## Open decisions

- **Blame attribution through merges.** *Recommendation:* attribute to the first parent holding the line, as Git does without `-m`. It is deterministic and cheapest; `--all-parents` can come later.
- **Should blame for a member show cloaked-line attribution when the output may be piped elsewhere?** *Recommendation:* yes. Blame is a read for this reader, like `vl cat`; nothing is published. A `--public` flag gives the public-mirror view (the audience flag patches use too, feature 4), for screenshots and issues.
- **Should `bisect run` default to a sandbox?** *Recommendation:* yes, always. It never moves the user's working copy, and `ws exec` already gives a clean per-revision tree, which is the main reason Git users bisect in a separate worktree.
- **Cherry-pick naming.** *Recommendation:* the command is `vl duplicate` (jj's name, with `-d`), and `vl cherry-pick REV` is an alias meaning `duplicate REV -d @-`. `@` is then auto-rebased, which matches what Git users expect.
