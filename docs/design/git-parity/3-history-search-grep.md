# 3. History search (`log -S/-G`, path and author filters) and `vl grep`

Status: design and threat review. No format change.

## Design sketch

### `vl log` filters

```text
vl log [-r REVSET] [-n N] [--author PAT] [--signed-by MEMBER] [-S STRING | -G REGEX] [--pickaxe-all]
       [--follow] [--] [PATH…]
```

- **Engine:** new `crates/veil-core/src/search.rs`.
  - `pub struct LogFilter { paths: Vec<VPath>, author: Option<Regex>, signed_by: Option<MemberId>, pickaxe: Option<Pickaxe> }`
  - `pub fn matches(repo, id, filter, reader) -> Result<Match>`.
  - `api::log_entries` in `crates/vl/src/api.rs` takes the filter and skips entries that do not match; it stays lazy, so `| head` still stops early.
- **Path filter:** compares the snapshot's *reader-resolved* tree with its parents' merged tree, restricted to the paths (`tree::diff_trees` on subtrees, so it costs O(path depth) when nothing changed).
- **`-S STRING`:** the number of occurrences in the readable versions of each changed file differs between parent and child.
- **`-G REGEX`:** a line matching the regex is added or removed in the diff (`textmerge::create_patch`).
  - Regexes use the `regex` crate (linear time) with `size_limit(1 MiB)` and `dfa_size_limit(8 MiB)`, case-sensitive by default with `-i`.
- **`--author`:** a regex over the free-form `author` claim. `--signed-by` matches the *verified* signer through `Keychain`, the same check `vl log` uses for its signature column.
- **Revsets:** the conformance doc lists the revset language as a pending feature. This round adds only `-r` with `A..B` and `::B` (needed by bisect) in `revset.rs` (`resolve_set`).

### `vl grep`

```text
vl grep PATTERN [-r REV] [-i] [-F] [-w] [-n] [-l] [-c] [--max-count N] [-a] [--json] [--] [PATH…]
```

- **Engine:** new `crates/veil-core/src/grep.rs`, `pub fn grep(repo, tree, pattern, opts, reader, sink)`.
  - It walks `tree::walk_files` of the *snapshot* (default `@`, which every command snapshots first). It **never reads the working copy**, so isolated, quarantined and ignored files are never searched.
  - Each file is read through `blame::readable_version`. `Plain` is searched. `Fallback` is searched and labelled `(last public version)`. `Redacted` is counted in `skipped: {sealed: N}` and never searched.
  - Binary content (a NUL in the first 8 KiB, or attribute `binary`/`-text`, feature 7) prints "binary file matches" unless `-a`.
  - Conflict entries are searched in their rendering for this reader (`conflict::materialize`).
- **Output:** `path:line:text`, escaped with `render::safe`. JSON is `veil.grep/1` `{rev, matches:[{path, line, text, tier}], skipped:{sealed, binary, too_large}}`. `serve` gets a `grep` method.
- **Parallelism:** files are searched on `remote::par_map`-style worker threads. Output order is sorted by path, so it is deterministic.

## Threat review

1. **Isolated secrets through `vl grep`.** Agents and editor integrations run `grep` and pipe the result into an LLM context or a log. Today `.env` never leaves the device; a grep of the working copy would print `API_KEY=…` lines.
   - *Invariant:* `vl grep` searches recorded snapshots only. No option reads isolated or quarantined files. The user's own `rg` is the tool for the disk.
   - *Test:* a repository with `.env` (isolated) and a quarantined file; `vl grep -r @ KEY` and `--json` print neither, and `skipped` does not count them either (no existence oracle).
2. **Searching ciphertext.** A naive implementation runs the regex over sealed object bytes, giving false hits and wasted CPU.
   - *Invariant:* only `Plain` and `Fallback` bytes reach the matcher, and `readable_version` is the only reader.
   - *Test:* a store wrapper counts `read_raw` of sealed objects in grep with no keys: 0 opens attempted beyond the label check.
3. **Pickaxe as an oracle for a non-member.** `log -S` over history where the file is sealed: a non-member's count is taken on the fallback or skipped, never on ciphertext.
   - *Invariant:* a snapshot whose relevant version is `Redacted` is not listed for `-S`/`-G`. With `--show-skipped`, it is listed as "not searched (sealed for …)".
   - *Test:* an outsider's `log -S <cloaked string>` returns nothing; a member's returns the change.
4. **The path filter reveals embargo contents.** A non-holder's `vl log -- src/vuln.c` must not list the embargoed merge (the wrapper names objects, the sealed tree names paths).
   - *Invariant:* the path filter compares reader-resolved trees (`checkout::resolve_view`); for non-holders the wrapper is its fallback, unchanged at that path.
   - *Test:* an embargoed fix of `src/vuln.c`; an outsider and a public-mirror reader run `log -- src/vuln.c` and `log -S <fixed line>`, and neither lists the merge.
5. **Sealed descriptions through `--grep`.** If `log --grep MSG` (searching descriptions) is added, it must search `repo.description(s)` as this reader sees it: `api::description`, so `HiddenText` is never matched. *Test:* `--grep` on words of a cloaked description as an outsider gives no match.
6. **Regex DoS.** Pattern `(a*)*b`, or a 100 MB literal.
   - *Invariant:* the `regex` crate is linear; the compile limits above apply; a pattern over 64 KiB is refused; lines over 1 MiB are matched but printed truncated (`…`).
   - *Test:* a pathological pattern on a 50 MiB file finishes in under 2 s in release.
7. **`-S` over huge histories.** Each step diffs and counts across every changed file.
   - *Invariant:* the per-file work is linear (counting via `memchr::memmem`), the walk is lazy (`-n` stops it) and there is a `--max-changes` budget (as in blame). Decrypting sealed versions is the dominant cost; the stat-cache-like memo `search::Memo` holds no plaintext, only per-object counts.
   - *Test:* a 10 000-snapshot history with 1 MiB files; `log -S x -n 1` returns quickly.
8. **Memo or caches holding plaintext.** A cache of per-object match results must never be written to disk if it was derived from sealed content. Even a boolean "contains `password`" is an oracle.
   - *Invariant:* no on-disk cache for search. Any in-memory memo dies with the process.
9. **Authors are claims.** `--author alice` matches anything a pusher writes, so documentation and help text say so; `--signed-by` is the authenticated filter. *Test:* a forged author and a valid signature by Bob; `--signed-by alice` excludes it.
10. **Escapes and JSON.** Matched lines go through `render::safe` (text) and `to_json` (JSON), including bidi overrides (Trojan Source). *Test:* a line containing U+202E.
11. **Sparse sandboxes, FUSE mount, `ws exec`.** `vl grep` run inside a sandbox (an agent) searches the sandbox workspace's snapshot, which follows the same reader rules; a sparse sandbox's `only` set does not limit what history holds.
    - *Invariant:* grep's paths are the snapshot's, so the result can name files outside the sparse set. This is documented, since sparse is not an access boundary.
12. **Fallback lines attributed as current content.** For a reader without the key, a fallback hit is labelled so the user does not take an old public version for what members see. *Test:* the JSON `tier: "fallback"`.

## Open decisions

- **Should `vl grep` ever search the working copy?** *Recommendation:* no. It searches the snapshot, which equals the working copy minus local-only files, because every command snapshots first. That gives Git's "tracked files only" behaviour, and closes the agent exfiltration route in point 1.
- **`log -S` default scope.** *Recommendation:* the same set `vl log` shows (visible history), with `-r` to widen or narrow it. Full revsets are a separate feature.
- **Searching fallbacks.** *Recommendation:* yes, labelled. A non-member's checkout contains exactly those bytes, so hiding them from grep would be inconsistent, and they reveal nothing new.
