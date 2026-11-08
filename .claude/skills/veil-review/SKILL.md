---
name: veil-review
description: Review a Veil branch before it merges into `integration` (a fix wave, a feature stream or a merge), or run an adversarial security pass. Use whenever an agent reports a branch done, before committing a merge, or when asked to "review", "verify" or "adversarially test" Veil code. Layers of checks scaled by risk; findings verified against real code and Veil's trust boundary; review loops that converge; escaped bugs used as the reviewer's eval.
---

# Reviewing Veil changes

Veil (`vl`) is a server-centric version control system (`docs/OVERVIEW.md`): the client is always connected to the Veil server, which stores the code and enforces who can see what (`docs/VISIBILITY.md`: admins, private by default, groups and managers, folder access, `public`; secrets encrypted automatically). Today's client still restricts paths by cloaking them for a scope; it syncs only through the server (path and SFTP remotes were removed in the simplification pass, part 1; debug builds keep path remotes as a test fixture, `crates/vl/src/test_remotes.rs`). Agents write nearly all of its code, and one agent works at a time.

The question every review answers is not "did someone read every line?" It is **"what could go wrong with this change, and which check, automated or human, is the right one to catch it?"** Anthropic's Claude Code team frames it the same way.

## Cost model: what we optimise

- **Owner time is two-sided.** It includes time spent reviewing *and* time spent on bugs that got through. Cutting the first while raising the second saves nothing.
- **Agent review cycles are expensive.** A nit costs a human a second to dismiss, but costs an agent author another commit and another review cycle, and quota with it. Report fewer, better findings.
- **Guardrail: escapes.** An escape is a bug found after a merge that the merge introduced: a fix-forward, a revert, or a BUGS.md row pointing at a merged wave. If escapes rise, review effort only moved somewhere else.
- **Veil can't fix leaks forward.** Anthropic leans on rollback, feature flags and staged rollouts. Veil keeps rollback too (every merge is one `--no-ff` commit, so `git revert -m 1 <merge>` undoes it in one step). But **a leak of sealed content, once pushed, can't be revoked**. So for tier A, review before merge stays strict, and "land first, test after" is never used.

## Layers, not one gate

Each layer catches some bugs and misses others; few get through all of them.

| # | Layer | Who | Blocks? |
|---|---|---|---|
| 1 | **Verification before the report.** The agent runs the checks and *shows* the results: commands and their output, not "done". | builder agent | yes |
| 2 | **Fresh-context review of the diff** (this skill, steps 1–4) | orchestrator, or the one review agent | yes |
| 3 | **Security review** (adversarial pass, tier A) | Opus at high effort, never Fable, as the one agent | yes, while a finding is open |
| 4 | **Automated checks on the merge applied to `integration`.** This is the merge queue: checks run on the merged result, not just on the branch. | `verify-fast.sh` | yes |
| 5 | **Owner approval scaled by risk** (below) | the owner | only where required |
| 6 | **Experimental flags and staged use.** New risky modes ship behind `--experimental`; the owner uses them before the team does. | — | — |
| 7 | **Fast feedback and rollback.** Deep randomized runs each round, sweeps of existing code, one-step merge reverts, and an escape review that asks which layer should have caught the bug. | orchestrator | — |

## Step 0: pick the tier from the change, not the author

Agent approvals never stand in for the owner's where the owner is required. The tier is set by the riskiest file in `git diff --stat <base>...<branch>`.

| Tier | What the change touches | Review |
|---|---|---|
| **A** | sealing, policy and the accepted-policy pin, confinement or embargo, crypto or rings, sync/push/pull, hooks, symlinks or the sandbox, formats | every lens below **plus** the security review (layer 3), with a **Deep** effort: several passes, each finding verified twice |
| **B** | other engine or CLI behaviour, performance, error handling | lenses 1–4 and 6, plus a full read of the diff (**Standard**) |
| **C** | docs, tests, benchmarks, scripts, tooling | the merge check, plus lens 4 on the diff (**Quick**) |

**The owner must approve** (always, whatever the tier):
- anything that decides *what to build*: new commands, new formats, scope changes, roadmap;
- crypto and key handling (`docs/CRYPTO.md` territory);
- the release and CI workflows and installers;
- the trust boundary itself (`docs/ARCHITECTURE.md` "Threat model");
- deleting files outside the Veil folders;
- anything outward-facing: pushing, publishing, contacting anyone.

**An approval covers one commit.** If the branch changes after review, the new commits get re-reviewed: only the new diff, unless they touch tier A. That includes an agent pushing more work, and **anyone resolving a merge conflict by hand**.

## Step 0.5: design conformance (every tier)
The diff must match `docs/OVERVIEW.md` and `docs/VISIBILITY.md`. Reject anything that:
- encrypts anything but secret files (code, folders, descriptions, tags, embargoes, attribution);
- adds an offline or plain-file remote path;
- uses rings for anything but secrets;
- invents access tiers or names beyond admins, groups, managers, access and public;
- touches Git interop.

## Step 1: check the proofs, not the claims

Read the brief and the agent's report. The report must have:
- **Testing:** commands run, with their output and test counts;
- **Risk:** the tier, and which core constraints the change touches;
- **How to revert:** normally "revert the merge commit". Say so if a format bump or migration makes that unsafe;
- **Beyond the brief:** anything added that the brief didn't ask for, and why.

Every claim ("BUG-NNN fixed", "nothing outside my area", "added nothing beyond the brief") is checked against the diff or a command's output. **If you can't say what the checks would miss, it isn't reviewed yet.**

## Step 2: find (one lens at a time, never in parallel)

For each lens, read the diff **against the whole codebase and the brief's intent**, not just the changed lines. Check three things:
- the change actually fixes the stated problem;
- it fits the surrounding system;
- it breaks nothing elsewhere: callers, other match arms, the WASM build, the docs.

**For a bug fix, find the root cause.** Then check that the fix closes the bug's whole class, not just the one reproduction.

1. **Confidentiality.** Can private, secret, isolated or embargoed content reach someone without access, or:
   - a public snapshot, a remote, a log, JSON output, an error message or a bundle?
   - Is a label used as authority where the object should be (`verify_sealing`)?
   - Does confined content move into an unconfined change?
2. **Correctness.**
   - Edge cases: empty repos, the root change, conflicts, renames and symlinks.
   - **Every new enum kind handled in every match.**
   - Error paths, and `Missing` treated as "redacted".
3. **Concurrency and durability.**
   - **Re-check earlier gates:** a stream that touches sync, transfer, packs or the store must re-run the 1 GB benchmark's memory gate (`scripts/bench-scale.sh 1g`, every case ≤ 512 MiB), not only its own profile. BUG-813 slipped past two merges this way.
   - **Run every changed concurrency test under load:** many copies in parallel (e.g. `for i in $(seq 8); do (for j in $(seq 12); do BIN TEST --exact & done; wait) ; done`), not 10 runs alone. BUG-811 passed 10/10 alone and failed 1 in 3 under load.
   - The lock: is it taken, held across a slow scan, or released early?
   - Crash between steps: is the publish order `.pack`, then `.idx`, then the op head?
   - fsync on the file and on its directory.
4. **Scope and over-engineering.** Anthropic's Scion team found that often "the role of the engineers was to tell Claude 'no'". Flag:
   - new flags, options, commands or abstractions that the bug or design does not need;
   - a framework with one user;
   - defensive checks against trusted components;
   - edits outside the stated area;
   - a test bent to pass instead of a root cause fixed.

   **Diff reduction:** could the same fix be smaller?
5. **Formats and compatibility.**
   - Did anything written to disk or the wire change?
   - Was the format bumped, are old formats still readable, and is there a `vl upgrade` path (`docs/FORMAT.md`)?
   - Do old clients refuse cleanly instead of misreading?
6. **Tests, docs and conventions.**
   - Does each fixed bug's `#[ignore = "BUG-NNN…"]` reproduction now run un-ignored?
   - Are there new security tests for new surface?
   - Flaky patterns:
     - substring checks on random change ids;
     - tag names made only of the letters k–z;
     - wall-clock ratios;
     - leak checks that grep for a short needle (under ~8 bytes): it turns up by chance in ciphertext and compressed packs. Always grep for the whole marker;
     - asserting that something happened (liveness) before checking nothing leaked (safety).
   - **Does every test assert that its primary action succeeded (or was refused, for a refusal test) before anything else?** Reject conditional assertions on the action under test (`if ok { … }`, `if let Ok(..)`, `if r.status == 200 { … }`, an early `return` when it failed): such a test passes when the action fails. BUG-1103's reproduction passed while every 2-change stack was refused (BUG-1110). Check new and changed tests for it, and spot-check the tests a fix claims as proof.
   - Do `CLAUDE.md`, the guide, `ARCHITECTURE.md` and `FORMAT.md` still tell the truth? **Docs that lie are a bug.**

**Drop style, formatting and cleanup-only findings.** Clippy and rustdoc enforce those.

## Step 3: verify every candidate (a finding must earn its place)

Anthropic confirms a finding only when enough independent agents vote for it. Here, with one agent, **re-derive each candidate from scratch**: re-read the code path, without trusting the first reading. For tier A, do this twice. A candidate becomes a finding only if all of these hold:

- **It is real in the code.** It is shown by a failing test (preferred), a command transcript or an exact trace with **`file:line`**. Never guess file names. "Might" and "could in theory" don't count.
- **Security findings: it crosses the trust boundary** (`docs/ARCHITECTURE.md` "Threat model"). Name all three:
  - **the attacker**, who must be outside the boundary: a person without access to the folder, a remote operator (the server, only for secrets and embargoes), a hostile pull or bundle, another OS user;
  - **what they control:** the exact input;
  - **the harm:** what leaks, is lost or runs, and to whom.

  A candidate that needs a trusted party to be hostile goes under "Out of scope (trusted)" and is not filed. Trusted parties are the member's own device, keys, `vl` binary and deliberate commands. Don't build defences nobody needs; Scion's own adversarial review was once "overly defensive".
- **It is introduced by this change.** Otherwise it is marked **Pre-existing**: recorded as BUG-NNN, but it doesn't block the merge or count against the author. **Check it on the base before calling it a regression.**
- **It is not a duplicate,** and **not already reported in an earlier cycle.**

## Step 4: rank and report

| Marker | Meaning | Blocks the merge? |
|---|---|---|
| **critical** | a leak of sealed content, loss of committed data, or code execution from someone else's content | yes |
| **important** | a leak or loss needing an unusual but realistic sequence; a wrong result; a broken invariant, convention or doc | yes |
| **medium** | denial of service, or a confusing failure | yes, unless filed with an ignored test and accepted by the orchestrator |
| **nit** | minor; doesn't block. **At most five**, and none at all in a re-review cycle | no |
| **pre-existing** | was already there | no; file as BUG-NNN |
| *out of scope (trusted)* | needs a trusted party to be hostile | no; one line, never filed |

**Every blocking finding must be addressed** before the merge: either fixed, or closed with a one-line reason (an intentional choice, or a false positive). A later commit that fixes it closes it.

**Name the class of each finding,** so the author fixes every instance, not one line.

Report format:

```text
Tier: A | B | C (Quick | Standard | Deep)   Branch: <branch> @ <sha>   Base: integration @ <sha>   Cycle: n/3
Summary: <N> blocking, <M> nits, <P> pre-existing  —  or exactly "No issues found."
Proofs checked: <claim → verified / false>

1. [critical|important|medium] <class> — crates/…/x.rs:123 — <one sentence>
   Scenario: <input → wrong result>   Verified: <test / transcript / trace>   Fix: <smallest fix for the class>
Nits (≤5): …
Pre-existing (file as BUG-NNN): …
Out of scope (trusted): <one line each>
Recommendation: merge | fix first (<list>) | rethink the approach | send back to the agent
```

## Step 5: make the loop converge

Anthropic once saw an agent author and an agent reviewer cycle more than fifty times overnight. About 59% of what the reviewer kept flagging was code from the first pass, so later cycles mostly found *old* issues one at a time, not new ones. Rules:

1. **At most three review cycles per branch.** After the third, the author stops patching and **re-evaluates the approach**, or the orchestrator escalates to the owner.
2. **After the first cycle, review only the new diff,** except for tier A files the new diff touches.
3. **Never re-report** a finding from an earlier cycle. Report each finding's whole class once, so it gets fixed once.
4. **A pre-existing issue never sends a branch back.** File it.
5. **Pivot early.** If the approach is wrong, say so on the first cycle, not after three rounds of line comments. Agent work is cheap to throw away.
6. **When the same class comes back with a new route, fix what the check compares, not the route.** Simplification part 2 needed three cycles for embargo leaks (abandon, squash, rebase, squash-into-fix, an earlier version) because each fix compared snapshot ids, which every rewrite changes. The fix that closes the class keys the rule on what rewrites keep (change ids and descent). A reviewer who sees a second route of a class should say so and ask for the identity basis to change.

## Step 6: decide and merge (orchestrator)

1. Merge without committing: `git merge --no-commit --no-ff <branch>` on `integration`.
   - **On a conflict in real code, abort and have the branch's agent rebase.** Don't hand-resolve it; a hand merge once dropped `verified_visibility` from `change()`. If you must resolve one by hand, that resolution is a new, untrusted commit: re-review it.
2. Check disk space with `df -h /` (8 GB or more free), then run `bash ~/.cache/veil-orch/verify-fast.sh <tag>` in the background (about 5 minutes). It covers:
   - nextest;
   - clippy and the doc build;
   - WASM, which runs after the tests;
   - ignored tests.
3. **Interpret the result.**
   - The proptest seed is pinned (`PROPTEST_RNG_SEED`), so red means this merge broke something.
   - In the ignored-tests step, only the known open bugs may fail.
   - An ignored test that now passes means its bug is fixed. Un-ignore it and mark the BUGS.md row.
4. **Green, with no open blocking finding:** commit `Merge <stream>: <summary> (BUG-…)` ending with the attribution line, then delete the branch worktree's `target/`.
5. **Otherwise,** send the findings back to the **same** agent's thread (this counts as a cycle). Fix small findings yourself; don't start a new agent for them.

## Make the reviewer better (every round)

- **Escapes are the eval.** Keep `docs/review-evals.md`. Each row is:
  - a bug that escaped a merged review;
  - the merge it came from;
  - the `file:line`;
  - the layer that should have caught it.

  When this skill, a brief or `verify-fast.sh` changes, re-check the change against every row: would the new process catch it?
  Seed it with: the dropped `verified_visibility` in `change()`, a format-5 kind missing from a branch's matches, the WASM break from feature-gated date helpers, and the policy pin that a fix wave closed for only one route of its class.
- **Fix recurring findings at the source.** If the same class keeps being found, turn it into:
  - a test or clippy lint;
  - a line in `CLAUDE.md` or a brief;
  - a check in `verify-fast.sh`;
  - a rule in this skill.

  Whenever a review misses something, ask *what wasn't in the reviewer's context* and add it.
- **Measure noise.** For each finding, note what happened to it: fixed, rejected, intentional, or didn't matter. Mostly "rejected" or "didn't matter" means the lens is too loud: tighten it.
- **Sweep existing code.** Once per round, run `bash ~/.cache/veil-orch/deep-props.sh` (fresh seeds; pin every failure as an ignored BUG test with its minimal input). Run one adversarial pass over code that *wasn't* changed this round, to find old bugs before they spread.

## What only the owner does

- **Should we build this at all?** Vision, goals and scope.
- **Dangerous code:** crypto and keys, release, CI and installers, the trust boundary.
- **Architecture choices** that set conventions everyone else follows.
- **Responsibility.** Whoever typed it, the owner answers for what ships. The orchestrator (the agents' operator) counts as their reviewer.

When the owner wants to understand an area, generate an explainer of that exact slice of the code instead of asking them to read diffs.

## Always-check rules (any tier)

- **Never `cargo fmt`.** A stray format run rewrites about 100 files. Reject reformat-heavy diffs.
- **OS-only code is behind `#[cfg(feature = "os")]`.** Run check-wasm on every merge that touches `veil-core`.
- **Every bug has:**
  - a `docs/BUGS.md` row;
  - an ignored reproduction until fixed;
  - `(**fixed**, <wave>)` plus a "**Fixed:** …" note once fixed.
- **A changed CLI has regenerated `docs/reference/`:** `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`.
- **No new dependency without a stated reason.**
- **Scratch work stays in the worktree's `.scratch/`.** Never `rm -rf` outside the worktree; it stalls agents on an approval.
- **Tests join an existing binary** per crate (`cli_security`, `core_engine`, …).
- **Every test asserts a positive outcome for the action under test** (`assert_eq!(status, Landed)`), never `if ok { … }` around its assertions. A test that would pass when the action fails is a finding (tier C on its own; blocking when it is a fix's only proof).

**Skip:**
- `Cargo.lock`;
- regenerated `docs/reference/`;
- anything clippy or rustdoc enforce;
- benchmark output.

## Lessons this project already paid for

- **Report claims ≠ proof.** "Green" branches have missed new enum kinds and broken WASM.
- **A branch based on an old commit misses later formats.** Check the merge base, and grep new kinds across the diff.
- **Hand-resolved semantic conflicts lose code.** Abort and rebase.
- **Random seeds in the merge check make results ambiguous.** Pin them, and run deep seeds separately.
- **Flaky tests come from:**
  - substring checks on random ids;
  - k–z tag names (BUG-105);
  - timing ratios (BUG-758);
  - liveness asserted before safety.
- **Disk:** several `target/` directories filled the disk once. Delete them after every merge, and run one agent at a time.
- **An agent that `rm -rf`s outside its worktree stalls** on approval. Agents can't be steered between turns, so warnings go out queued.

**Not adopted from Anthropic:**
- landing first and testing after (a leak can't be reverted);
- parallel finders and voting (one agent at a time, so candidates are re-derived in sequence).

## Sources

- Anthropic, on code review for the Claude Code repositories. The owner pasted the article on 2026-11-05. It covers:
  - layers, not one gate;
  - verification before the PR;
  - risk tiers set by the change, not the author;
  - approvals valid for one commit;
  - convergence: three cycles, then review only the new diff;
  - incidents as the eval;
  - measuring noise;
  - what humans keep.
- Anthropic, Code Review for Claude Code: [docs](https://code.claude.com/docs/en/code-review), [customizing it](https://code.claude.com/docs/en/code-review-customize).
- Anthropic, [Redesigning source control at Anthropic](https://www.anthropic.com/research/redesigning-source-control): "What we learned building Scion".
- `docs/ARCHITECTURE.md` "Threat model", `docs/BUGS.md`, `docs/FORMAT.md`, `CLAUDE.md`.
- `~/.cache/veil-orch/`: `FIX-BRIEF.md`, `FEATURE-BRIEF.md`, `ADVERSARIAL-BRIEF.md`, `verify-fast.sh`, `deep-props.sh`.
