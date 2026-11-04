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

`encodings.txt` pins the bytes of every object encoding. Append to it (with
`VEIL_BLESS_ENCODINGS=1`) only together with a new format; see
`docs/FORMAT.md` §4 and §6.

The identity files (`home-*/identity.json`) hold test-only keys, and
`alice/.env` is a deliberately harmless isolated file.
