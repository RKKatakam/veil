# Compatibility fixtures

`format-N/` holds what the release that introduced repository format N
wrote, produced once with

```sh
cargo build --release -p vl
crates/veil-core/tests/fixtures/generate.sh target/release/vl crates/veil-core/tests/fixtures/format-N
```

Never regenerate or edit an existing set: it is the record of what that
release wrote, and `tests/core_format/format_compat.rs` checks that every later
release still opens, reads, verifies, `fsck`s, upgrades and syncs it.

* `format-1/`: vl 0.1.0 (integration at 8aa7a22), JSON trees.
* `format-2/`: the release that introduced binary trees.
* `format-3/`: the release that introduced standard cryptography (AES-SIV,
  HPKE, independent signing keys), generated with
  `generate.sh target/release/vl …/format-3 …/format-2`: adds `home-dave`
  (a legacy identity, granted to `team`) and `upgraded/` (format-2's
  `alice/` and `team-remote/` after `vl upgrade`, plus one commit).

* `format-4/`: the release that introduced first-class conflicts,
  generated with `generate.sh target/debug/vl …/format-4 …/format-3`
  (a debug build of the same sources): adds the tag `conflicted` (a merge
  whose cloaked `secrets/notes.txt` stays a conflict entry, both sides
  sealed for `team`, and whose public `src/util/strings.rs` conflict was
  resolved with `vl resolve --theirs`); `upgraded/` is format-3's `alice/`
  after `vl upgrade` (3 → 4). `generate.sh` now reads the full `public key`
  line of `vl identity show` (the identity binding made it longer than the
  128 digits the earlier script expected).

* `format-5/`: the release that introduced format 5 (symlinks and
  annotated tags), generated with `VEIL_FIXTURE_EXTRAS=<core_format test
  binary> generate.sh target/debug/vl …/format-5 …/format-4` (a debug
  build of the same sources; `cargo test -p veil-core --test core_format
  --no-run` prints the binary). No CLI writes links or annotated tags yet,
  so `generate.sh` has the `write_format_5_extras` test of
  `format_compat.rs` add them through the engine before the embargo, the
  cloaked tag and the pushes: the tag `links` (`links/readme` →
  `../README.md`, `links/words` → an absolute target, `secrets/current` →
  a target sealed for `team`), `link-conflict` (a link/file conflict at
  `links/both`), and annotated tags on `links`: `v5.0` (signed by alice)
  and `team-release` (cloaked, its message sealed, signed). `upgraded/` is
  format-4's `alice/` after `vl upgrade` (4 → 5). Regenerated once, before
  release, when Git interop was removed (2026-11-05): the first set also
  held Git-only data that format 5 no longer has.

* `format-6/`: the lock-free op log (`op_heads/`, `Operation::workspace`
  and `rewritten`), generated with `VEIL_FIXTURE_EXTRAS=<core_format test
  binary> generate.sh target/debug/vl …/format-6 …/format-5` (a debug build
  of the same sources). After the usual history, the `write_format_6_extras`
  test of `format_compat.rs` writes concurrent operations last: an amend of
  `links`' change racing a new workspace `concurrent` on it (merged by the
  next open, so the log holds a merge whose side carries `rewritten` and
  `workspace`), then two tag sets (`head-c`, `head-d`) left as two heads.
  `upgraded/` is format-5's `alice/` and `team-remote/` after `vl upgrade
  --remote origin` and `vl upgrade` (5 → 6). Format 6 is unreleased: streams
  A (attribution) and C (partial clone) extend it, and regenerate this set
  with their additions before the release.

* `format-7/`: the release that introduced format 7 (key rings of ring
  format 4: invites, shares by members, a member's removal of their own
  device; `docs/HUB.md` §13.12), generated with `VEIL_FIXTURE_EXTRAS=<core_format
  test binary> generate.sh target/debug/vl …/format-7 …/format-6`. Before the
  pushes, the `write_format_7_extras` test adds the scope `rule-fixture`:
  alice invites bob (a fixed test invite secret) and shares the key under his
  join; bob shares it with a laptop he vouched for and removes it again. It
  reaches `team-remote/` with the push. `upgraded/` is format-6's `alice/` and
  `team-remote/` after `vl upgrade` (6 → 7); its one more commit pushes `main`
  only (`generate.sh` now pushes `--tag main` there: the format-6 extras amend
  `links` after that set's push). No object encoding changed.

* `format-10/`: agent attribution and attempts (`Snapshot.agent`,
  `abandoned`, `attempts`), generated with `VEIL_FIXTURE_EXTRAS=<core_format
  test binary> generate.sh target/debug/vl …/format-10 …/format-8` (a debug
  build of the same sources). On the released fix, `agent-work` is a change
  committed with `VEIL_AGENT`, `VEIL_AGENT_TASK` and `VEIL_AGENT_RUN` set,
  whose first try was kept with `vl attempt drop --reason …`; it reaches both
  remotes. `upgraded/` is the format-8 set after `vl upgrade` (8 → 10,
  nothing rewritten); its one more commit stays in `alice/`, as `main`
  builds on the unreleased embargo there. Format 9 has no set: it is only
  ever a thin clone, made by a clone from a server; the server's `thin`
  tests make one with S3's clone code and upgrade it to 10.

`encodings.txt` pins the bytes of every object encoding. Append to it (with
`VEIL_BLESS_ENCODINGS=1`) only together with a new format; see
`docs/FORMAT.md` §4 and §6.

The identity files (`home-*/identity.json`) hold test-only keys, and
`alice/.env` is a deliberately harmless file: isolated up to the format-6
set, sealed for `team` from the format-7 set on (`vl init` syncs shared
secrets).

* `format-8/`: only secret files are encrypted, generated with
  `VEIL_FIXTURE_EXTRAS=<core_format test binary> generate.sh target/debug/vl
  …/format-8 …/format-7` (a debug build of the same sources). The sealed
  file is `secrets/.env.notes` (a secret file; there is no cloaked
  directory), the sealed link `secrets/.env.current`, the embargoed fixes
  are developed in ordinary workspaces, `team-only` is an ordinary tag and
  `team-release` an ordinary signed annotated tag. `upgraded/` is absent:
  the format-7 set holds what format 8 removed, so `vl upgrade` refuses it
  (`format_compat.rs` checks that, and that the format-1 to 7 sets are
  refused and left unchanged). Both remotes lack `main`, which builds on
  the unreleased embargo.
