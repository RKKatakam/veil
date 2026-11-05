---
name: veil-review
description: Review a Veil branch before it merges into `integration` (a fix wave, a feature stream or a merge), or run an adversarial security pass. Use whenever an agent reports a branch done, before committing a merge, or when asked to "review", "verify" or "adversarially test" Veil code. Finds issues by class, verifies each against real code behaviour and Veil's trust boundary, ranks them, and rejects over-engineering.
---

# Reviewing Veil changes

Veil (`vl`) is a version control system with per-path confidentiality (public / cloaked per scope / isolated), embargoes, a Git bridge and SFTP remotes. One bad merge can publish sealed content, and a pushed leak can't be taken back. So review comes **before** merge, never after.

This skill combines four sources:
- how Anthropic's Code Review works;
- the lessons in Anthropic's Scion post;
- the trust boundary in `docs/ARCHITECTURE.md` ("Threat model");
- the mistakes this project has already made. These are listed at the end.

## The pipeline: find → verify → rank → decide

Anthropic's Code Review:
- runs several finders, each looking for a different class of issue in the diff and the code around it;
- has a separate verification step check every candidate against actual code behaviour and drop false positives;
- deduplicates what's left and ranks it by severity;
- scales effort with the change (big PRs get more passes, trivial ones a light pass);
- never approves or blocks on its own. A human decides.

Veil does the same, with these differences:
- **At most one subagent at a time** (owner rule). Run the lenses one after another, in one agent or inline, never in parallel.
- **The orchestrator decides the merge.** A review produces findings and a recommendation; it doesn't merge.
- **Verification is stricter.** A security finding must survive the trust-boundary test (step 3), and every bug needs a failing test.

### Step 0: pick the tier (scale effort to risk)

| Tier | What the change touches | Review |
|---|---|---|
| **A** | sealing, policy and the accepted-policy pin, confinement or embargo, crypto or rings, sync/push/pull/export, the Git bridge, colocated mode, hooks, symlinks or the sandbox, formats | threat review before building; every lens below; an **Opus, high-effort adversarial pass** (never Fable) |
| **B** | other engine or CLI behaviour, performance, error handling | lenses 1–4 and 6, plus a full read of the diff |
| **C** | docs, tests, benchmarks, scripts, tooling | the merge check, plus lens 4 on the diff |

The tier is set by the riskiest file in the diff: `git diff --stat <base>...<branch>`.

### Step 1: read the claims

Read the brief and the agent's report. List every claim to check:
- "BUG-NNN fixed";
- "N tests pass";
- "nothing outside my area touched";
- "added nothing beyond the brief".

**Report claims are not evidence.** Each is checked against the diff or a command's output.

### Step 2: find (one lens at a time)

For each lens, read the diff **and the code around it** (callers, the other match arms, the WASM build), not just the changed lines.

1. **Confidentiality.** Can cloaked, isolated or embargoed content (or a cloaked tag name or description) reach:
   - a public snapshot, a remote, the Git export, a log, JSON output, an error message or a bundle?
   - Is a label used as authority where the object should be (`verify_sealing`)?
   - Is a fallback version one the base doesn't already show publicly?
   - Does confined content move into an unconfined change?
2. **Correctness.**
   - Edge cases: empty repos, the root change, conflicts, renames, symlinks and gitlinks.
   - **Every new enum kind handled in every match.** Format-5 kinds were once missing from `patch.rs`.
   - Error paths, and `Missing` treated as "redacted".
3. **Concurrency and durability.**
   - The lock: is it taken, held across a slow scan, or released early?
   - Crash between steps: is the publish order `.pack`, then `.idx`, then the op head?
   - fsync on the file and on its directory.
   - Races with Git in colocated mode.
4. **Scope and over-engineering** (Scion: often "the role of the engineers was to tell Claude 'no'"). Flag:
   - new flags, config options, commands or abstractions that the bug or design does not need;
   - a generic framework with one user;
   - defensive checks against trusted components;
   - edits outside the stated area;
   - a test changed to pass instead of a root cause fixed.

   Every addition beyond the brief must be justified in the report. If it isn't, it's a finding.
5. **Formats and compatibility.**
   - Did anything written to disk or the wire change?
   - Was the format bumped, are old formats still readable, and is there a `vl upgrade` path (`docs/FORMAT.md`)?
   - Do old clients refuse cleanly instead of misreading? Example: an old vl treating unfetched objects as redacted.
6. **Tests.**
   - Does each fixed bug's `#[ignore = "BUG-NNN…"]` reproduction now run un-ignored, and does it test the bug's whole class?
   - Are there new security tests for new surface?
   - Flaky patterns:
     - substring checks on random change ids;
     - tag names made only of the letters k–z;
     - wall-clock ratios;
     - asserting that something happened (liveness) before checking nothing leaked (safety).

### Step 3: verify every candidate (drop what doesn't survive)

A candidate becomes a finding only if all of these hold:

- **It is real in the code.** It is shown by a failing test (preferred), a command transcript or an exact code trace with `file:line`. "Might" and "could in theory" don't count.
- **Security findings: it crosses the trust boundary.** Name all three:
  - **the attacker**, who must be outside the boundary: a remote operator, a teammate without the scope, a hostile pull/import/patch/bundle, Git writing the work tree in colocated mode, another OS user;
  - **what they control:** the exact input;
  - **the harm:** what leaks, is lost or runs, and to whom.

  A candidate that needs a **trusted** party to be hostile goes under "Out of scope (trusted)", one line each, and is not filed. Trusted parties are the member's own device, OS account, keys, `vl` binary and deliberate commands (`expose`, `public!`, `--force`, `--no-verify`). Anthropic found one of its adversarial reviews "overly defensive about trusting another internal service". Don't build defences nobody needs.
- **It is introduced by this change,** or it is marked **Pre-existing**. Pre-existing bugs are still recorded, but they don't block this merge.
- **It is not a duplicate.** Merge findings with the same root cause.

**Before calling something a regression, check it on the base.** BUG-759 showed up during an unrelated merge's check, and it was pre-existing.

### Step 4: rank

| Severity | Meaning | Blocks the merge? |
|---|---|---|
| **critical** | a leak of sealed content, loss of committed data, or code execution from someone else's content | yes |
| **high** | a leak or loss needing an unusual but realistic sequence | yes |
| **medium** | denial of service, a wrong result, or a confusing failure | yes, unless filed with an ignored test and accepted by the orchestrator |
| **low** | polish, or a rare wrong message | no; file it |
| **nit** | style or naming | no. **Report at most five.** |
| **pre-existing** | was already there | no; file it as BUG-NNN |

Each finding has the same shape:
- `file:line`;
- one sentence stating the defect;
- the failure scenario (input → wrong result);
- how it was verified;
- the smallest fix. Recommend the smallest fix that closes the class, not a new defensive layer.

### Step 5: decide the merge (orchestrator)

1. Merge without committing: `git merge --no-commit --no-ff <branch>` on `integration`.
   - **On a conflict in real code, abort and have the branch's agent rebase.** Don't hand-resolve semantic conflicts. A hand merge once dropped `verified_visibility` from `change()`.
2. Check disk space with `df -h /` (8 GB or more free), then run the merge check: `bash ~/.cache/veil-orch/verify-fast.sh <tag>` in the background (about 5 minutes). It covers:
   - nextest;
   - clippy and the doc build;
   - WASM (`scripts/check-wasm.sh`, run after the tests because it needs `target/debug/vl`);
   - ignored tests, through `verify-ignored.sh`.
3. **Interpret the result.**
   - The proptest seed is pinned (`PROPTEST_RNG_SEED`), so red means this merge broke something.
   - In the ignored-tests step, only the known open bugs may fail: the documented colocated limitations and open BUG reproductions.
   - An ignored test that now *passes* means its bug is fixed. Un-ignore it and mark the BUGS.md row.
4. **Green, with no blocking findings:** commit `Merge <stream>: <summary> (BUG-…)` ending with the attribution line, then `rm -rf` the branch worktree's `target/`.
5. **Otherwise,** send the findings back to the **same** agent's thread. Fix small findings yourself; don't start a new agent for them.

## Always-check rules (any tier)

- **Never `cargo fmt`.** The codebase isn't rustfmt-clean, so a stray format run rewrites about 100 files. Reject any diff that is mostly reformatting.
- **Git-only code is behind `#[cfg(feature = "git")]`.** Run check-wasm on every merge that touches `veil-core`.
- **Every bug has:**
  - a `docs/BUGS.md` row (severity, area, finding, root cause, test);
  - an ignored reproduction test until fixed;
  - `(**fixed**, <wave>)` plus a "**Fixed:** …" note once fixed.
- **A changed CLI has regenerated `docs/reference/`:** `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`.
- **No new dependency without a stated reason. Everything still works offline.**
- **Scratch work stays in the worktree's `.scratch/`.** Never `rm -rf` outside the worktree: it stalls agents for hours waiting on an approval.
- **Tests are consolidated** into a few binaries per crate (`cli_security`, `core_engine`, …). New test files join a binary; they don't add one. The exceptions are the colocated files under `crates/vl/tests/`.

## Skip (don't review line by line)

- `Cargo.lock`;
- regenerated `docs/reference/` (its test checks it);
- anything clippy or rustdoc already enforces;
- benchmark output files.

## Deep randomized run (once per round, not per merge)

`bash ~/.cache/veil-orch/deep-props.sh` runs the property tests with fresh seeds (`PROPTEST_CASES=1000`, `VEIL_COLOCATED_CASES=200`). Pin every failure as an ignored BUG regression test with its minimal input, as was done for BUG-759 (`run_case(&[0, 25, 9, 0, 0, 0])`). This is Veil's small version of Scion's hermetic simulations.

## Output format

```text
Tier: A | B | C        Branch: <branch> @ <sha>      Base: integration @ <sha>
Claims checked: <claim → verified / false>

Findings (most severe first)
1. [high] crates/…/x.rs:123 — <one sentence>
   Scenario: <input → wrong result>   Verified: <test name / transcript>   Fix: <smallest fix>
…
Nits (≤5): …
Pre-existing (file as BUG-NNN): …
Out of scope (trusted): <one line each>

Recommendation: merge | fix first (<list>) | send back to agent
```

## Lessons this project already paid for

- **Report claims ≠ evidence.** Branches have arrived "green" that missed new enum kinds or broke WASM.
- **A branch based on an old commit misses later formats.** Check the merge base, and grep new kinds across the diff.
- **Hand-resolving semantic merge conflicts loses code.** Abort, and have the agent rebase.
- **Random property-test seeds in the merge check make results ambiguous.** Pin the seed, and run deep seeds separately.
- **Flaky tests come from:**
  - substring checks on random ids;
  - k–z tag names colliding with change ids (BUG-105);
  - timing ratios (BUG-758);
  - asserting liveness before safety.
- **Disk:** three agent `target/` directories plus the check's directories filled the disk once. Delete `target/` after every merge, and run one agent at a time.
- **Agents can't be steered between turns,** so warnings go out queued.
- **An agent that `rm -rf`s outside its worktree stalls** on an approval prompt.
- **Not adopted from Scion:**
  - land first and test after (a leak can't be reverted);
  - always-online clients (Veil stays offline-first).

## Sources

- Anthropic, Code Review for Claude Code: [docs](https://code.claude.com/docs/en/code-review), [customizing it (REVIEW.md, severity, nit caps, skip lists)](https://code.claude.com/docs/en/code-review-customize), [launch post](https://claude.com/blog/code-review).
- Anthropic, [Redesigning source control at Anthropic](https://www.anthropic.com/research/redesigning-source-control): "What we learned building Scion".
- `docs/ARCHITECTURE.md` "Threat model" (the trust boundary), `docs/BUGS.md`, `docs/FORMAT.md`.
- `~/.cache/veil-orch/`: `FIX-BRIEF.md`, `FEATURE-BRIEF.md`, `ADVERSARIAL-BRIEF.md`, `verify-fast.sh`, `deep-props.sh`.
