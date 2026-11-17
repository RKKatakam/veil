# Verification guards and stamps

Veil's development process uses two verification guards modelled on the Claude Code team's engineering practice:

1. **Changes cannot modify their own checks.** If a branch can relax the assertion, property-test oracle, lint rule or gate script that judges it without explicit review — or edit the guard script itself — the check is broken. Review rules and guard scripts are always executed from `integration` (the base branch), never from the branch under review.
2. **Every commit carries a parseable stamp of how it was verified — including `none`.** Recording `Verified-by: none` (rather than omitting a stamp or hiding behind skipped fields) makes unverified commits queryable across any range, and lets a commit gate start in `observe` mode before switching to `enforce`.

Both guards came out of real incidents in Veil's history:
- Merge `57052373` (`t3/bug-2464-2466-merge-rebase`) fixed an op-log rebase bug and simultaneously relaxed `check_model` in `crates/veil-core/tests/core_props/oplog_merge.rs`; only a careful human review confirmed the oracle change was sound.
- Prior to `ff29db9b` (`BUG-2610`), a branch's full check never completed due to lock timeouts, and only the merge check caught a `clippy -D warnings` MSRV failure (`AtomicUsize::try_update` past Rust 1.88).

---

## 1. Guarding checks and oracles (`scripts/check-guard.sh`)

### Base-branch rule

Always run the review skill and guard scripts from `integration`, never from the working tree of the branch being reviewed:

```sh
git show integration:.claude/skills/veil-review/SKILL.md
git show integration:scripts/check-guard.sh | bash -s -- integration...<branch>
```

Running directly (`bash scripts/check-guard.sh [<range>]`, default `integration...HEAD`) is fine for an author self-checking their own branch, but the merge gate in `.claude/skills/veil-review/SKILL.md` always pipes `integration`'s copy.

### What `check-guard.sh` flags

Each flagged diff hunk prints one line:

```text
<file>:<line> — <kind> — <first changed code line of the hunk>
```

| Kind | What triggers it |
|---|---|
| `assertion-removed` | Fewer `assert!` / `assert_eq!` / `assert_ne!` / `prop_assert*!` / `debug_assert*!` calls or `#[should_panic]` attributes in a test hunk than before |
| `assertion-weakened` | Strict `assert_eq!` / `assert_ne!` replaced by looser `assert!`, an existing assertion wrapped in `if …` / `if let …`, or `\|\|` disjuncts added to a 1-for-1 assertion |
| `test-ignored` | `#[ignore]` or `#[ignore = "…"]` added to a test (un-ignoring a fixed bug is never flagged) |
| `retry-or-sleep-added` | `sleep`, `loop`, `while` or `tries` retry logic added to an existing test or test helper |
| `tolerance-or-timeout-widened` | Numeric timeout, deadline, retry cap, tolerance or upper-bound assertion increased in an existing test |
| `proptest-model` | Edits to property-test models/oracles (`check_*`, `model*`, `oracle*`, `verify_*`, `arb_*`, `proptest!`, `ProptestConfig`, `prop_assert*` in `proptest`-backed test files such as `core_props`), or deletions from `*proptest-regressions*` |
| `check-script` | Edits to `scripts/verify-server.sh`, `scripts/bench-server.sh`, `scripts/bench-scale.sh`, `scripts/check-wasm.sh`, `scripts/check-guard.sh`, `scripts/verify-stamp.sh`, `scripts/unverified.sh`, `scripts/hooks/*`, `deploy/gates.sh` or `.github/workflows/*` |
| `bench-gate` | Edits to gate thresholds or accounting in `crates/veil-bench/src/**` (`GATE_*`, `SERVER_GATE_*`, `missed_gates`, `server_over_gate`, `CommitKinds`, `aside`, `target_ms`, `meets_target`, `beats_git`) |
| `check-rules` | Edits to `.claude/skills/**`, `CLAUDE.md`, `docs/RELIABILITY.md`, `docs/VERIFICATION.md` or `docs/review-evals.md` |
| `lint-config` | Edits to `[lints*]` sections, `clippy`, `rustflags`, `warnings`, `rust-version` or lint levels in `*.toml` |
| `lint-allow` | Added `#[allow(…)]` or `#![allow(…)]` attributes in Rust code |

Run `bash scripts/check-guard.sh --self-test` to verify all embedded positive sample diffs, a neutral diff (product code + new test + un-ignoring a fixed bug, which flags nothing), and mode exit codes.

### Modes (`CHECK_GUARD`)

| `CHECK_GUARD` | Behaviour | Exit code |
|---|---|---|
| `off` | Disabled; prints and logs nothing | `0` |
| `observe` *(default)* | Prints flagged hunks to stdout and appends a timestamped entry to `.git/check-guard.log` (worktree-aware via `git rev-parse --git-path check-guard.log`) | `0` |
| `enforce` | Prints and logs flagged hunks; refuses unless a commit message in `<range>` carries a non-empty `Check-change-approved: <reason>` trailer | `1` when unapproved, `0` when clean or approved |

### Approving an intentional check change

After a reviewer verifies that a flagged oracle, assertion, gate or script change is intentional and sound, record the reason in a commit (or merge commit) trailer in the range:

```text
Check-change-approved: check_model relaxed for divergent head rewrites (BUG-2464, verified against guarantee 1)
```

Placeholder reasons (`<reason>`, `...`, empty) are rejected in `enforce` mode.

---

## 2. Verification stamps (`scripts/verify-stamp.sh` and `scripts/unverified.sh`)

### Trailer format

`scripts/verify-stamp.sh` produces a single `Verified-by:` git trailer:

```text
Verified-by: verify-fast=<pass|fail|skipped> verify-server=<pass|fail|skipped|hostile> gate-1g=<pass|fail|skipped> load=<pass|fail|skipped>
```

When **nothing ran** (no inputs given, all suites `skipped`, or `--none`), the stamp always collapses to `none`:

```text
Verified-by: none
Verified-by: none (reason: scripts and docs only)
```

### Feeding check results into `verify-stamp.sh`

`verify-stamp.sh` reads the existing outputs of `~/.cache/veil-orch/verify-fast.sh`, `scripts/verify-server.sh` and `scripts/bench-server.sh` directly (without modifying `~/.cache/veil-orch/verify-fast.sh`):

```sh
# After `bash ~/.cache/veil-orch/verify-fast.sh merge-2610` (reads /tmp/veil-*-merge-2610.log):
bash scripts/verify-stamp.sh --fast-tag merge-2610

# Combining verify-fast tag + verify-server stdout log + 1g memory gate:
bash scripts/verify-server.sh | tee .scratch/verify-server.log
bash scripts/verify-stamp.sh \
  --fast-tag merge-2610 \
  --server-log .scratch/verify-server.log \
  --gate-1g-log .scratch/bench-results/server-1g-abc123.md

# Explicit statuses or docs/scripts-only commits:
bash scripts/verify-stamp.sh verify-fast=pass verify-server=hostile
bash scripts/verify-stamp.sh --none --reason "scripts and docs only"

# Write/replace trailer in a commit message file (placed before Co-Authored-By) or amend HEAD:
bash scripts/verify-stamp.sh -f "$(git rev-parse --git-path MERGE_MSG)" --fast-tag merge-2610
bash scripts/verify-stamp.sh --amend --fast-tag merge-2610
```

 Note on `verify-fast.sh`: `verify-fast.sh` always exits `0` after removing `target/`, writing per-step exit codes (`test exit 0`, `clippy exit 0`, `doc exit 0`, `check-wasm exit 0`, `ignored exit 101`) to `/tmp/veil-*-<tag>.log` and stdout. `verify-stamp.sh --fast-tag <tag>` (or `--fast-log <stdout>`) checks that `test`, `clippy`, `doc` and `check-wasm` each exited `0` and that `ignored` compiled cleanly.

### Querying unverified commits (`scripts/unverified.sh`)

List every commit in `<range>` (default `integration...HEAD`) whose `Verified-by:` trailer is missing, `none`, or carries any `fail` / malformed token:

```sh
bash scripts/unverified.sh integration...HEAD
bash scripts/unverified.sh --merges-only integration~20..integration
bash scripts/unverified.sh --check integration...HEAD   # exits 1 if any commit is unverified
```

Output format:

```text
<short-sha> — <missing|none|failed> — <subject> [(reason: …)]
```

---

## 3. Commit gate (`scripts/hooks/commit-msg`)

`scripts/hooks/commit-msg` is an opt-in git `commit-msg` hook. It is **never** installed automatically by builds or test scripts; install or remove it explicitly with:

```sh
bash scripts/hooks/install.sh
bash scripts/hooks/install.sh --uninstall
```

### Gate modes (`VERIFY_GATE` or `git config veil.verifyGate`)

| Mode | Behaviour |
|---|---|
| `off` | Disabled; exits `0` immediately |
| `observe` *(default)* | Allows every commit; logs commits missing a valid `Verified-by:` trailer to `.git/verify-gate.log` |
| `enforce` | Refuses commits lacking a passing `Verified-by:` trailer unless the message carries `Verified-by: none (reason: <why>)`. Bare `Verified-by: none` (without a reason) and `=fail` stamps are refused |

### Third-attempt escape hatch

In `enforce` mode, consecutive refused commit attempts on the same `HEAD` are counted in `.git/verify-gate.attempts`:
- Attempts 1 and 2 print instructions to stderr, log `action=refused` to `.git/verify-gate.log`, and exit `1`.
- Attempt **3 in a row** on the same `HEAD` resets the counter, logs `action=allowed-third-attempt` to `.git/verify-gate.log`, warns on stderr, and exits `0` so an automated agent cannot deadlock in a commit loop. Because the commit still lacks a passing stamp, `scripts/unverified.sh` surfaces it at review/merge time.

Run `bash scripts/hooks/commit-msg --self-test` (and `bash scripts/verify-stamp.sh --self-test`, `bash scripts/unverified.sh --self-test`) to exercise all modes in an isolated temporary repository.

---

## 4. Validation on `integration` merge history

`scripts/check-guard.sh` was validated against the 15 most recent first-parent merges on `integration` (`<m>^1..<m>^2`, 474 total diff hunks). Note that `<m>^1..<m>^2` is normalized to `<m>^1...<m>^2` (`merge-base(<m>^1, <m>^2)..<m>^2`) when the two parents diverged, so commits merged onto `integration` while a branch was in flight are not misread as reverse deletions on that branch.

| Merge | Branch / summary | Total hunks | Flagged | What `check-guard.sh` flagged | Verdict |
|---|---|---:|---:|---|---|
| `57052373` | `t3/bug-2464-2466-merge-rebase` | 25 | 6 | 5 `proptest-model` hunks in `crates/veil-core/tests/core_props/oplog_merge.rs` (`check_model` head-visibility relaxation + `abandoned`/`moved` transitive closure + `check_every_write_survives_with` describe driver); 1 `retry-or-sleep-added` hunk in `oplog_merge.rs:2370` (`loop { tries += 1; … }` around `bug_2464`) | **6 TP** (caught the target `oplog_merge.rs` oracle relaxation) |
| `c3eaa053` | `t3/bug-2470-durability` | 15 | 0 | — (250 lines of new stress tests in `core_durability/maintenance.rs` cleanly ignored) | Clean |
| `1478c769` | `t3/bug-2560-2531-2511` | 67 | 2 | `warm.rs:322` (`tolerance-or-timeout-widened`: `deadline *= 2` backoff up to 5 s); `scripts/verify-server.sh:79` (`check-script`: `--shm-size=1g`) | **2 TP** |
| `7440a76a` | `t3/bug-2590-gc-retention` | 45 | 3 | `pack_gc.rs:1126` (`retry-or-sleep-added`: `gc_pass` retrying `gave_way`); `pack_gc.rs:1499` (`test-ignored`: `BUG-2602`); `startup.rs:208` (`tolerance-or-timeout-widened`: YugabyteDB migration timeout 250 ms → 3 s) | **3 TP** |
| `13abad48` | `t3/bug-2483-clone-memory` | 38 | 0 | — (`SlowReads` fixture + new `BUG-2480` test cleanly ignored) | Clean |
| `1c06bebc` | `t3/placeholder` (`BUG-2464`) | 2 | 1 | `oplog_merge.rs:2281` (`test-ignored`: three `#[ignore = "BUG-2464/2466…"]` reproductions) | **1 TP** |
| `7e85d5b0` | `t3/bug-2457-2465-gate-retries` | 15 | 0 | — (new `landing_speed.rs` tests cleanly ignored) | Clean |
| `f2e0f8a0` | `t3/fix-bug-2456-clone-memory-gate` | 8 | 0 | — | Clean |
| `f2ea7734` | `t3/one-repo-ceiling` | 58 | 1 | `crates/veil-bench/src/load.rs:1218` (`bench-gate`: `"notice"` added to `CommitKinds::background`, subtracted before `GATE_COMMITS_PER_PUSH`) | **1 TP** |
| `6bfadded` | `t3/server-push-cost-reduction` | 30 | 3 | `sync.rs:785, 818` (`lint-allow`: two `#[allow(clippy::too_many_arguments)]`); `support.rs:1044` (`assertion-weakened`: `Craft::send` split into `send` + `try_send`, replacing `assert_eq!(up.status, 200)` with `assert!(!r.1)` + early return) | **2 TP, 1 FP** (refactor kept equivalent check in wrapper) |
| `9d37eeab` | `t3/branch-tips-cost-cleanup` | 48 | 1 | `branches.rs:151` (`lint-allow`: `#[allow(clippy::too_many_arguments)]`) | **1 TP** |
| `3aa49e21` | `main` (README wording) | 3 | 0 | — | Clean |
| `38c46976` | `main` (README wording) | 2 | 0 | — | Clean |
| `5229eaf4` | `t3/busy-repo-db-throughput` | 73 | 4 | `deploy/gates.sh:63, 81, 112, 258` (`check-script`: `onerepo` gate parameters and runner) | **4 TP** |
| `ef249811` | `d30bd503` into `gcpkit` | 45 | 2 | `store_s3.rs:84, 112` (`assertion-weakened`: two `assert_eq!(format!("{err:#}"), "S3 PUT: HTTP 499/429")` loosened to `.starts_with(…)`) | **2 TP** |

### Summary and tuning notes

- **Coverage across 15 merges (474 hunks):** 23 hunks flagged across 9 merges; 6 merges flagged nothing.
- **False-positive rate:** **1 / 23 flagged hunks (4.3%)**, or **1 / 452 non-check hunks (0.22%)** — the `Craft::send` / `Craft::try_send` helper split in `6bfadded`.
- **Tuning applied from history:**
  1. *Brand-new test functions and fixtures (`+#[test]`, pure top-level `struct`/`impl`/`fn` additions with zero deletions):* excluded from `retry-or-sleep-added` and `tolerance-or-timeout-widened` so new concurrency/server tests that legitimately poll with `sleep` or `Duration` deadlines (`c3eaa053`, `13abad48`, `7e85d5b0`, `5229eaf4`) do not create noise.
  2. *Tail `#[test]` slicing after the last deleted line:* prevented a helper extraction above an existing test (`1478c769` `landing.rs`) from miscounting a moved `sleep` or picking up timeouts from new tests appended in the same hunk.
  3. *Comment-only edits and single-assertion `||` scoping:* ignored doc-comment-only changes in `crates/veil-bench/src/load.rs` (`1478c769`) and restricted `if … assert!` / `||` checks to assertion lines rather than distant lines in the same hunk (`7440a76a` `startup.rs`).
