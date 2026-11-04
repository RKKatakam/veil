# Investigating history

Who wrote this line, when did this string appear, which change broke the
build? Veil answers with `vl blame`, `vl grep`, the `vl log` filters and
`vl bisect`. Renames are detected in `vl status`, `vl diff` and `vl show`.

All of them read history **as you may see it**. Content cloaked for a scope
you are not in, an unreleased embargo, and your own local-only files never
show up in their output, not even as a count, and they never decrypt
anything you do not hold the key for. [Confidentiality](#what-you-cannot-see-stays-out)
below says exactly what that means.

The examples come from a small project: `src/price.rs` was added, given a
discount, moved to `src/billing/price.rs`, and its discount raised.

## Renames

`vl status`, `vl diff` and `vl show` detect renames by default, as Git does.
A file moved unchanged is an exact rename; a file moved *and* edited is
paired by content similarity (50 % by default):

```text
$ mkdir -p src/billing && mv src/price.rs src/billing/price.rs
$ vl status
Working copy changes:
R src/price.rs -> src/billing/price.rs
…
$ vl diff --stat
R100 src/price.rs -> src/billing/price.rs
$ vl diff
diff --veil a/src/price.rs b/src/billing/price.rs
similarity index 100%
rename from src/price.rs
rename to src/billing/price.rs
```

| Flag | Effect |
|---|---|
| `-M=N` (`--find-renames=N`) | Pair files at least `N` % similar (default 50) |
| `-C` (`--find-copies`) | Detect copies too (`C087 a -> b`); off by default, as in Git |
| `--no-renames` | Show a deletion and an addition instead |

Renames are computed when you look, never stored: nothing in a snapshot,
the operation log, a remote or the Git export records them. In `--json`,
a renamed file has `"status": "renamed"`, `from` and `score`
([JSON reference](../reference/json.md#change)).

Merges, rebases and `vl cherry-pick` use the same detection to make an
edit follow a rename made on the other side
([Copying changes](copying-changes.md#merges-and-rebases-follow-renames)).

Detection is bounded so that a hostile change cannot stall it: content is
compared only while `deleted × added ≤ 1000²` (and within a byte budget);
past that only exact renames are shown and `vl diff` says
`rename detection skipped: too many files`.

## Who wrote this line: `vl blame`

```text
$ vl blame src/billing/price.rs
vxrzxktr (alice 2026-11-04 1) fn price(n: u32) -> u32 {
vxrzxktr (alice 2026-11-04 2)     n * 100
vxrzxktr (alice 2026-11-04 3) }
vxrzxktr (alice 2026-11-04 4)
vxrzxktr (alice 2026-11-04 5) fn discount(p: u32) -> u32 {
uvqqwpzr (alice 2026-11-04 6)     p - p / 5
vxrzxktr (alice 2026-11-04 7) }
```

Each line shows the change that introduced it, its author and date, and the
line number. Without `--follow`, blame stops where the file got its current
name (`vxrzxktr` moved it). With it, blame follows the rename:

```text
$ vl blame --follow src/billing/price.rs
tpvxqwrp (alice 2026-11-04 1) fn price(n: u32) -> u32 {
tpvxqwrp (alice 2026-11-04 2)     n * 100
tpvxqwrp (alice 2026-11-04 3) }
owsxoqpu (alice 2026-11-04 4)
owsxoqpu (alice 2026-11-04 5) fn discount(p: u32) -> u32 {
uvqqwpzr (alice 2026-11-04 6)     p - p / 5
owsxoqpu (alice 2026-11-04 7) }
```

* `-r REV` blames the file as it was at `REV`; `-L 5,7` only lines 5 to 7.
* Through a merge, a line goes to the first parent that has it (Git's
  default).
* Blame prints change ids, never descriptions: `vl show <change>` tells you
  more. The author is a claim (whoever made the snapshot wrote it); `vl log`
  shows whether the signature is good.
* `vl annotate` is the same command.
* `--json` gives [`veil.blame/1`](../reference/json.md#veilblame1).

**Limits.** Blame visits each snapshot at most once. It stops after
`--max-changes` snapshots (default 100 000) or when its work budget is
spent; lines it has not attributed by then are printed with `????????`
and a note, never guessed. Two versions too different to compare line by
line in bounded time have their differing middle attributed whole (the
JSON says `coarse: true`).

## Search the files: `vl grep`

```text
$ vl grep -n discount
src/billing/price.rs:5:fn discount(p: u32) -> u32 {
```

`vl grep PATTERN [PATH…]` searches the files of a snapshot (`-r REV`, by
default `@`, which every command snapshots first) with a regular expression.
`-i` ignores case, `-F` takes the pattern literally, `-w` matches whole words,
`-n` prints line numbers, `-l` only file names, `-c` counts, `--max-count N`
stops after `N` lines per file, and `-a` prints the lines of binary files
(otherwise `binary file X matches`). It exits 1 when nothing matches.

`vl grep` **never reads the disk**. It searches recorded files only, so your
`.env`, other isolated files, quarantined files and ignored build output are
never searched, and are not counted either. That is deliberate: agents and
editor plugins run `grep` and send the result to a model or a log. Use your
own `rg` for the directory itself.

## Search history: the `vl log` filters

| Filter | Lists the snapshots that… |
|---|---|
| `vl log PATH…` (or `-- PATH…`) | change those files or directories |
| `--follow PATH` | change that one file, under its older names too |
| `-S STRING` | change how many times `STRING` occurs in a file |
| `-G REGEX` | add or remove a line matching `REGEX` |
| `-i` | match `-S`, `-G` and `--author` ignoring case |
| `--author PAT` | have an author matching the regex `PAT` (a claim anyone can write) |
| `--signed-by MEMBER` | carry a good signature by that member (verified by your key rings) |
| `-r REVSET` | are in `X`, `A..B` (ancestors of B that are not ancestors of A), `::B`, `..B` or `A..` |

```text
$ vl log -S 'p / 10'
○  uvqqwpzr alice ✓ 2026-11-04 19:50:41 15373fd2
│  Raise the discount to 20%
│  matched in: src/billing/price.rs
○  owsxoqpu alice ✓ 2026-11-04 19:50:40 ea1ce8c2
│  Add a 10% discount
│  matched in: src/price.rs
```

The 10 % discount was added in `owsxoqpu` and removed in `uvqqwpzr`; the
move in between changed no count (renames are paired before counting, as
Git does). A filtered log is a flat list: the snapshots it leaves out
would break the graph's lines. `-n` still stops early (`vl log -S x -n 1`
returns at the first match). `-S` and `-G` stop after `--max-changes`
snapshots (default 100 000); `--pickaxe-all` lists every changed file of a
match, not just the matching ones.

Use `--author` to find what someone *says* they wrote, and `--signed-by` to
find what they provably did.

## Find the change that broke it: `vl bisect`

```text
$ vl tag set v1 -r tpvxqwrp        # pricing worked here
$ vl bisect start --bad @- --good v1
Bisecting: 1 snapshot(s) left to test after this one (about 2 step(s))
Testing vxrzxktr a72827bf Move pricing into billing
Updated 1 files, removed 0
Working copy now at: pwslwyps 503d8623 (empty) (no description set)
$ cargo test                       # passes
$ vl bisect good
…
The first bad snapshot is uvqqwpzr 15373fd2 Raise the discount to 20%
$ vl bisect reset
Bisection ended; working copy now at krtlpzsn 8a7d5861 (empty) (no description set)
```

Each step checks the candidate out as a new change on top of it (as
`vl new` does); `vl bisect good`, `bad` or `skip` records your verdict and
moves on. `vl bisect reset` takes you back to where you started, and
`vl bisect log` lists the steps.

If you edit files while testing a candidate, the edits are recorded in
that candidate's change like any other work, and `vl bisect good|bad`
refuses to move on until you have saved them elsewhere (`vl new`,
`vl squash`), or pass `--discard`: the edits then stay in that change,
which is not abandoned.

**`vl bisect run`** does it all by itself:

```text
$ vl bisect start --bad @- --good v1
$ vl bisect run -- ./check.sh
Bisecting: 1 snapshot(s) left to test after this one (about 2 step(s))
Testing vxrzxktr a72827bf Move pricing into billing
running ./check.sh in /tmp/veil-ws-bisect-444343-6bf335c0
  good (exit 0)
The first bad snapshot is uvqqwpzr 15373fd2 Raise the discount to 20%
```

It never touches your working copy. Each candidate is checked out in a
throwaway sandbox (the directory `vl ws exec --ephemeral` uses, `0700`
under `$TMPDIR`, removed afterwards), `CMD` runs there, and nothing is
recorded. Exit code 0 means good, 125 means skip, 1–127 bad (except 125),
and anything else, a signal included, stops the bisection, as in Git.

* The sandbox holds the snapshot only: your `.env` and other isolated files
  are not in it, and no vault secret is injected. `--with-isolated` copies
  your local-only files in, as `vl ws exec --with-isolated` does.
* A candidate with files you cannot read (cloaked for someone else, or
  shown as their last public version) may give a misleading verdict:
  `bisect run` marks it `skip` and says so. `--trust-partial` keeps the
  verdict instead.
* The state lives in `.veil/local/bisect.json` on this device only.
  Nothing else reads it; if it is damaged, `vl bisect` asks you to run
  `vl bisect reset`, which removes it.

`vl serve` offers `blame` and `grep`, never `bisect`: `bisect run`
executes code.

## What you cannot see stays out

These tools never show you more than `vl cat` and a checkout would:

* **Cloaked content you hold no key for** is never opened. `vl blame` and
  `vl grep` read a public file edited on a cloaked line as its last public
  version: blame attributes nothing to the cloaked change, and grep labels
  such hits `(last public version)` (`"tier": "fallback"` in JSON), since
  members see newer content there. A file with no public version is
  skipped: blame refuses it with the usual explanation, grep counts it in
  `skipped.sealed`, and `vl log -S` leaves the snapshot out (with
  `--show-skipped` it is listed as `not searched: sealed for …`). Nothing is
  ever matched or counted on ciphertext.
* **An unreleased embargo** looks to you exactly like its pre-merge tree:
  `vl log -- src/vuln.c`, `vl log -S <the fixed line>`, `vl blame` and
  rename detection do not reveal which files the fix touched or created.
* **Local-only files** (isolated, quarantined, ignored) are in no snapshot,
  so none of these tools can find them.
* `vl blame --public` shows the history as a public mirror sees it, for a
  screenshot or a bug report.
* Search memos live in memory only: nothing derived from sealed content is
  written to disk.
