# Compatibility fixtures

`format-N/` holds what the release that introduced repository format N
wrote, produced once with

```sh
cargo build --release -p vl
crates/veil-core/tests/fixtures/generate.sh target/release/vl crates/veil-core/tests/fixtures/format-N
```

Never regenerate or edit an existing set: it is the record of what that
release wrote, and `tests/format_compat.rs` checks that every later
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

`encodings.txt` pins the bytes of every object encoding. Append to it (with
`VEIL_BLESS_ENCODINGS=1`) only together with a new format; see
`docs/FORMAT.md` §4 and §6.

The identity files (`home-*/identity.json`) hold test-only keys, and
`alice/.env` is a deliberately harmless isolated file.
