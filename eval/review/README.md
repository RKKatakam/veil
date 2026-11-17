# Veil Code-Reviewer Evaluation Set (`eval/review`)

This directory evaluates Veil's code-review process (`.claude/skills/veil-review/SKILL.md`, adversarial briefs, and reviewer agents) against historical bugs and clean controls, modelled on the Claude Code team's reviewer evaluation practice:

- Recreate the repository to the exact commit state at review time (`head`) and review `base..head`.
- Grade findings against a **one-sentence answer key** describing the actual bug: only findings naming the right file, citing a line within tolerance, and accurately describing the bug earn credit.
- Include size-matched, clean merged changes as **controls** to measure over-flagging (false-positive blocking findings).
- Measure recall across review stages (**`raw`** candidate findings, **`verified`** post-verification findings, and **`final`** reported findings) when stage tags are emitted.
- Keep a strict **`tuning` / `test` split** (~2/3 `tuning`, 1/3 fixed `test`).

---

## Rule 1: Tune on `tuning` Only

**Never iterate onprompts, `.claude/skills/veil-review/SKILL.md`, or heuristics against `test`.**

- Use `--split tuning` (24 cases) for error analysis, prompt/skill edits, lens tuning, and scorer calibration.
- Run `--split test` (12 fixed cases, stratified across `engine`, `cli`, `sandbox`, and `server`) only to measure whether a candidate reviewer change improves recall without raising false positives on controls.
- Never leak `cases.jsonl` (`answer_key`, `kind`, `files`, or `lines`) into the reviewer's context; `eval/review/run.sh` extracts only `base` and `head`.

---

## Dataset Composition (`cases.jsonl`)

The dataset contains **36 verified commit ranges** reachable from `integration` (`ff29db9b`), with zero overlapping commits between ranges:

| Kind | Meaning | `tuning` | `test` | Total |
|---|---|---:|---:|---:|
| `escape` | Bug introduced by a change that merged into `integration` and was found afterwards | 12 | 5 | **17** |
| `review-catch` | Known-detectable bug introduced on a branch and caught in pre-merge review | 6 | 3 | **9** |
| `control` | Merged, stable change with no later `docs/BUGS.md` regression pointing at it (size-matched) | 6 | 4 | **10** |
| **Total** | | **24** | **12** | **36** |

Stratification by area and diff size (`small` < 300 lines, `medium` 300–1,200 lines, `large` > 1,200 lines):

| Area | Crates / Surface | `escape` | `review-catch` | `control` | `tuning` / `test` |
|---|---|---:|---:|---:|---:|
| `engine` | `crates/veil-core` (`oplog`, `store`, `gc`, `transaction`, `repo`, `checkout`, `settled`) | 4 | 3 | 2 | 6 / 3 |
| `cli` | `crates/vl` (`hub`, `daemon`, `main`, `history`, thin-clone `blame`) | 3 | 2 | 3 | 5 / 3 |
| `sandbox` | `confine.rs`, `sandbox.rs`, `ws_socket.rs`, `secrets.rs` | 5 | 2 | 2 | 6 / 3 |
| `server` | `crates/veil-server` (`pack_gc`, `sync`, `landing`, `derive`, `prs`, `query`, `web`) | 5 | 2 | 3 | 7 / 3 |

### Row Schema (`eval/review/cases.jsonl`)

Each line is one JSON object:

- `id` (`string`): Case identifier (`esc-<bug>`, `catch-<bug>`, or `ctrl-<stream>`).
- `kind` (`"escape" | "review-catch" | "control"`): Provenance of the range.
- `split` (`"tuning" | "test"`): Evaluation split.
- `area` (`"engine" | "cli" | "sandbox" | "server"`): Subsystem stratum.
- `size` (`"small" | "medium" | "large"`) and `diff_lines` (`int`): `insertions + deletions` across `base..head`.
- `base`, `head` (`string`): Full 40-char commit SHAs defining the exact range `base..head` as it stood at review time.
- `severity` (`"critical" | "important" | "medium" | "none"`): Expected blocking severity (`"none"` for controls).
- `files` (`list[string]`): Repo-relative file path(s) where the bug lives at `head` (for controls, the main changed Rust files).
- `lines` (`dict[string, [int, int]]`): 1-indexed `[start_line, end_line]` span at `head` for each target file (`{}` for controls).
- `answer_key` (`string`): Single-sentence description of what the bug was (`""` for controls).
- `source` (`object`): Traceability metadata (`bug` id in `docs/BUGS.md`, introducing/branch merge commit, and `fix_commit`).

---

## Running an Evaluation

### 1. Inspect cases or run a single case

List cases in a split:

```bash
./eval/review/run.sh --list --split test
```

Materialize a detached worktree at `head` under `.scratch/`, write the review prompt (`veil-review` skill + commit range + diffstat), and clean up the worktree automatically on exit:

```bash
./eval/review/run.sh catch-2550 --prompt-out .scratch/prompt.md
```

### 2. Run a Claude / Opus reviewer against the `test` split

For each case in `test`, `eval/review/run.sh` creates `.scratch/review-eval-<id>-<pid>` at `head`, pipes the prompt to your reviewer command running inside that worktree, writes its output to `.scratch/results/<id>.md` (or `.jsonl`), and removes the worktree before moving to the next case:

```bash
mkdir -p .scratch/results

for id in $(./eval/review/run.sh --list --split test | awk 'NR>1 {print $1}'); do
    ./eval/review/run.sh "$id" \
        --findings ".scratch/results/${id}.md" \
        --cmd 'claude -p --model claude-opus-4-6'
done

./eval/review/score.py \
    --split test \
    --findings .scratch/results \
    --manual-csv .scratch/results/manual_grading.csv \
    -v
```

*(Run one reviewer agent at a time per `CLAUDE.md`, and instruct the reviewer to inspect only the recreated checkout at `HEAD` without reading `git log --all` or external checkouts.)*

### 3. Findings Formats & Stage-by-Stage Recall

`eval/review/score.py` (Python 3 stdlib only) accepts either:

1. **Standard `veil-review` Markdown reports** (`1. [critical|important|medium] <class> — crates/.../x.rs:123 — <description>` or `"No issues found."`). Add `## Raw`, `## Verified`, and `## Final` headings (or `[stage:raw|verified|final]`) to track recall across stages.
2. **JSON / JSONL findings**, one object per finding:
   ```json
   {"case_id": "catch-2550", "stage": "raw", "severity": "critical", "file": "crates/veil-core/src/oplog.rs", "line": 765, "description": "..."}
   {"case_id": "catch-2550", "stage": "verified", "severity": "critical", "file": "crates/veil-core/src/oplog.rs", "line": 765, "description": "..."}
   {"case_id": "catch-2550", "stage": "final", "severity": "critical", "file": "crates/veil-core/src/oplog.rs", "line": 765, "description": "..."}
   ```

Non-blocking items (`nit`, `pre-existing`, `out-of-scope`) are ignored. When stage tags are present, `score.py` reports recall on bug cases and false-positive counts on `control` cases separately for `raw`, `verified`, and `final` (using `final` for the overall end-to-end score).

### 4. Conservative Matching & Manual Grading CSV

`score.py` auto-credits a bug case (`FOUND`) only when a blocking finding:
1. Matches a path in `files`,
2. Gives a line number within `--line-tolerance` (default `±50` lines) of `lines[file]`, and
3. Shares sufficient normalized content stems and technical anchors (`identifiers` / backticked symbols) with `answer_key`.

Partial matches (e.g., right file and line with unusual wording, right file without a line number, or strong description overlap citing a caller file) are **not** auto-credited; pass `--manual-csv <path>` to export them with a blank `human_match` column (`1` or `0`) for human adjudication.

---

## Adding a New Escape Case

Whenever a merged change introduces a bug found after merge (an escape):

1. **Identify the review-time range (`base..head`):** Locate the `--no-ff` merge commit `M` on `integration` that introduced the bug. Set `head` to the branch tip `M^2` (full 40-char SHA) and `base` to `git merge-base M^1 M^2`. Confirm both are ancestors of `integration` (`git merge-base --is-ancestor <sha> integration`).
2. **Verify at `head`:** Read `git show <head>:<file>` and `git diff <base>..<head> -- <file>` to confirm the bug exists at `head`, was introduced in `base..head`, and record exact 1-indexed `[start_line, end_line]` spans at `head`.
3. **Write a one-sentence `answer_key`:** State concisely what the code did wrong and what broke, naming the concrete function/type so conservative matching has clear anchors.
4. **Assign `split`:** Default new cases to `tuning` (~2 out of every 3 new escapes) and periodically assign 1 in 3 (stratified by `area` and `size`) to `test`, adding a size-matched clean `control` merge whenever ~3 bug cases are added.
5. **Append to `eval/review/cases.jsonl`** (and add the process lesson to `docs/review-evals.md`), then run `./eval/review/run.sh <new-id> --quiet-prompt --findings <sample>` to sanity-check scoring.
