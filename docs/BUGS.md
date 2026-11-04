# Veil adversarial test findings

> **Status (round 2, `integration` @ 81fcd28 and later): all 40 findings are
> fixed.** Every reproduction below is now an ordinary, un-ignored test that
> passes; `cargo test --no-fail-fast` runs them all. The instructions that
> follow describe the suite as originally delivered against the baseline.
> Fixes are summarised in `docs/ARCHITECTURE.md` (threat model) and in the
> merge commits `Merge fix stream: …`.

Baseline: `integration` @ `06f8757` ("Veil MVP: veil-core engine and vl CLI").
Every finding below was **demonstrated** by a test in this branch. Each test
asserts the *secure / correct* behaviour and is marked
`#[ignore = "BUG-NNN: …"]`, so:

```sh
cargo test                                  # green: 58 new regression guards pass, bug tests ignored
cargo test --no-fail-fast -- --ignored      # 62 tests, all FAIL, one or more per finding
cargo test -p veil-core --test adversarial_remote -- --ignored dotdot   # a single repro
PROPTEST_CASES=2000 cargo test --release -p veil-core --test adversarial_props   # deeper fuzzing
```

(`--no-fail-fast` is needed because cargo otherwise stops at the first failing
test binary.)

Suspected-but-unproven issues are listed separately under
[Hypotheses](#hypotheses-not-demonstrated). Line numbers refer to `06f8757`.

## Summary

| Severity | Count | IDs |
|---|---|---|
| critical | 3 | 001–003 |
| high | 11 | 004–014 |
| medium | 13 | 015–027 |
| low | 13 | 028–040 |

Test files:

* `crates/veil-core/tests/adversarial_remote.rs`: malicious remotes, tampered `.veil/`, forged key rings and embargo records
* `crates/veil-core/tests/adversarial_confidentiality.rs`: leaks of cloaked, embargoed, isolated and quarantined data; policy and scanner bypasses; key distribution
* `crates/veil-core/tests/adversarial_fuzz.rs`: proptest fuzzing of `Object::decode`, `Envelope::from_bytes`, `Policy::parse`, the revset resolver, tree decoding, the secret scanner and id parsers; envelope tampering
* `crates/veil-core/tests/adversarial_lock.rs`: the lock, concurrent writers, a slow snapshot
* `crates/veil-core/tests/adversarial_props.rs`: random operation sequences with invariant checks; model equivalence of the Memory, Overlay and Disk backends
* `crates/vl/tests/adversarial_cli_remote.rs`: `vl clone` and `vl pull` from hostile repositories
* `crates/vl/tests/adversarial_cli_crash.rs`: concurrent processes, `kill -9`, stale locks, the `ws exec` sandbox
* `crates/vl/tests/adversarial_cli_abuse.rs`: hostile arguments and revsets, odd files, empty repositories, data-loss scenarios

---

## Critical

### BUG-001: Tree entry names are never validated; checkout writes outside the working copy
* **Category:** malicious remote / path traversal
* **Repro:** A remote serves a tree with a directory entry named `..` that contains `PWNED.sh`. Run `vl clone <remote> dest`, or `vl pull` followed by `vl new upstream`.
* **Expected:** The pull is rejected (invalid entry name), and nothing is written outside `dest`.
* **Actual:** `PWNED.sh` is written next to `dest` (with two `..` levels, into its parent). Entries that are empty or contain `/` hit a `debug_assert!` panic in debug builds. In release builds a name like `a/../../x` traverses as well.
* **Root cause:** `Object::decode` deserialises trees without validating names (`object.rs:234`). `tree.rs:47` and `tree.rs:106` build paths with `VPath::join`, which only has a `debug_assert!` (`vpath.rs:52`) and no check for `.`, `..`, `/`, `\0` or empty names. `DiskBackend::full_path` then pushes the raw components (`vfs/disk.rs:43`), and checkout writes them (`checkout.rs:58`). `put_raw` verifies the hash but never the structure.
* **Tests:** `adversarial_remote::{dotdot_entry_cannot_escape_the_working_copy, dotdot_file_entry_cannot_overwrite_a_sibling_file, slash_and_empty_entry_names_are_rejected_without_panicking}`, `adversarial_fuzz::tree_operations_never_panic_on_hostile_names`, `adversarial_cli_remote::{clone_cannot_write_outside_the_destination, pull_and_new_cannot_write_outside_the_working_copy}`

### BUG-002: A remote tree can overwrite `.veil/`: key rings, `repo.json` and the op log
* **Category:** malicious remote / repository takeover
* **Repro:** The remote's tree has a root entry `.veil/` containing `repo.json` (whose `origin` URL points to an attacker path) or `meta/keyrings/team.json`. Run `vl clone`, or `vl pull` then `vl new`.
* **Expected:** `.veil` is reserved and rejected at any depth where it would land on the repository's own metadata.
* **Actual:** The victim's `.veil/repo.json` is replaced. The test reads back `"url":"/tmp/attacker-controlled"`. The same path can substitute a key ring, so future cloaked content is sealed under an attacker key, or rewrite `op_head`/`ops`.
* **Root cause:** Only the *builder* skips `.veil`, and only at the root (`builder.rs:107`). `checkout` (`checkout.rs:58`) writes whatever the tree contains.
* **Tests:** `adversarial_remote::remote_tree_cannot_write_into_dot_veil`, `adversarial_cli_remote::clone_cannot_overwrite_repository_metadata`

### BUG-003: Pushing an embargoed merge ships the fix itself, in plaintext, to public remotes
* **Category:** confidentiality / embargo
* **Repro:** This is the README flow. Develop the fix as an ordinary change, run `vl merge fix --into main --embargo`, then `vl push mirror` (even with `-t main`).
* **Expected:** Before release, the public mirror holds no content of the fix.
* **Actual:** The mirror contains the fix snapshot (the merge's second parent) and its plaintext blobs (`verify_signature` is found in `.veil/objects/...`). Only the merge's own tree is embargoed.
* **Root cause:** `remote::push` walks every ancestor of the tips (`remote.rs:193`) and copies each snapshot's tree (`remote.rs:86`). Nothing withholds the non-first parents of an unreleased embargo merge, or re-seals the fix branch. The embargo only seals the merge tree (`embargo.rs:50`).
* **Test:** `adversarial_confidentiality::embargoed_merge_does_not_push_the_fix_branch_to_a_public_mirror`

## High

### BUG-004: Merging a cloaked line of work publishes its files without secret scanning
* **Category:** confidentiality / secret scanner bypass
* **Repro:** Create `vl ws new exp --cloak team` and write `cfg.js` containing an AWS key there. Inside a cloaked workspace the file is sealed, not scanned. Run `vl merge exp@ --into main`, then `vl push mirror`.
* **Expected:** Files that become public in the merge are scanned and quarantined, as on every other path into a public snapshot.
* **Actual:** `AKIAIOSFODNN7EXAMPLE` is found in a plaintext object on the public mirror.
* **Root cause:** `normalize_tree` re-stores entries with the destination visibility via `store.store_file` and never calls `secrets::scan` (`embargo.rs:79`, `embargo.rs:88`).
* **Test:** `adversarial_confidentiality::merging_a_cloaked_workspace_scans_files_that_become_public`

### BUG-005: Auto-rebase downgrades cloaked content to public
* **Category:** confidentiality / cloaking
* **Repro:** A change cloaked under `ops` edits line 12 of `settings.conf`. Its public parent is amended at line 1, which triggers an auto-rebase with a clean 3-way merge. Tag the change and push it to the team remote. Bob, who is on the team remote but not in `ops`, clones it.
* **Expected:** The rebased file stays sealed under `ops`.
* **Actual:** The rebased entry is `Public`, and Bob reads `db_pass hunter2-OPS-ONLY`.
* **Root cause:** `merge_file` stores the merged bytes with **ours**' visibility (`merge.rs:148`). During a rebase, "ours" is the new parent, which is public. `rebase_descendants` does not re-normalise visibility.
* **Tests:** `adversarial_confidentiality::auto_rebase_never_downgrades_cloaked_content_to_public`. Also covered by the property test `adversarial_props::cloaked_lines_of_work_never_hold_public_entries`.

### BUG-006: `vl new <cloaked change>` in an ordinary workspace declassifies it at the next snapshot
* **Category:** confidentiality / cloaking
* **Repro:** A cloaked workspace `exp` holds `plan.md`. In the default workspace, run `vl new exp@` and then any command (auto-snapshot), commit, and push to the mirror.
* **Expected:** The inherited sealed entries stay sealed, or the user is warned.
* **Actual:** The next snapshot re-stores `plan.md` as public plaintext, which then reaches the public mirror. There is no warning.
* **Root cause:** The new change takes the *workspace's* cloak, not the parents' (`commands.rs:51`, `transaction.rs:83`). The builder only cloaks when `opts.cloak` is set (`builder.rs:205`), so a sealed parent entry with changed bytes, or any re-hash, becomes `Public`.
* **Tests:** `adversarial_confidentiality::new_change_on_a_cloaked_change_does_not_declassify_it`, `adversarial_props::cloaked_lines_of_work_never_hold_public_entries` (the property test found this one)

### BUG-007: `vl cloak` / `vl isolate` on a file name with glob metacharacters leaves it public
* **Category:** confidentiality / policy
* **Repro:** `vl cloak 'config[prod].yml' 'app/[id]/token?.json'`, `vl isolate 'notes{1}.txt'`, then `vl commit`.
* **Expected:** These literal files are cloaked or isolated, or the command refuses.
* **Actual:** The CLI prints `Added rule config[prod].yml cloak team`, but `vl files` shows the files `public`. They are pushed in plaintext. Next.js-style `[id]` paths are common.
* **Root cause:** `cmd_policy_rules` writes the user's path verbatim as a glob (`vl/src/main.rs:619`). `Rule::new` compiles it with `GlobBuilder` (`policy.rs:101`), so `[prod]` is a character class.
* **Test:** `adversarial_cli_abuse::cloaking_a_file_with_glob_metacharacters_cloaks_that_file`

### BUG-008: `.veilpolicy` accepts reserved scopes (`embargo/<id>`, `local`, path-like names)
* **Category:** confidentiality / policy / crypto misuse
* **Repro:** A one-line policy change, `secrets/ cloak embargo/<released-id>`. Commit `secrets/db.yml` and `vl push mirror`.
* **Expected:** Only valid scope names (as enforced by `validate_scope_name`) are accepted in policy rules.
* **Actual:** The files are sealed under the released embargo key. That key is public, and released-embargo objects are pushed to public remotes, so an anonymous mirror reader decrypts `prod_db_password…`. `cloak local` seals team content under a device-only key, and `cloak ../../x` panics (see BUG-015).
* **Root cause:** `Policy::parse` takes `parts[2]` as the scope without validation (`policy.rs:194`).
* **Tests:** `adversarial_confidentiality::{policy_cannot_cloak_under_a_released_embargo_key, policy_rejects_reserved_and_malformed_scope_names}`

### BUG-009: Merging a `.veilpolicy` change silently re-keys or declassifies existing cloaked files
* **Category:** confidentiality / policy (a malicious PR)
* **Repro:**
  1. Mallory can write to the team remote but is not in `ops`. She creates scope `opz` (members: herself and Alice), pushes the ring, and opens a PR that only changes `prod/ cloak ops` to `prod/ cloak opz`.
  2. Alice runs `vl merge pr` and pushes.
  3. Variant: the PR changes `secrets/ cloak team` to `secrets/ public!`.
* **Expected:** At minimum a loud warning and explicit confirmation before existing cloaked content is re-encrypted to a different scope or published. Ideally, scope changes to existing content require a member of the *old* scope to opt in.
* **Actual:** `normalize_tree` decrypts every `prod/` file and re-seals it under `opz`, and Mallory reads `ops-only-password`. In the variant, every secret becomes a public blob. Nothing is printed.
* **Root cause:** `commands.rs` `merge` calls `normalize_tree` against the *merged* policy. `embargo.rs:79` and `embargo.rs:88` re-seal under any scope this user can open, including one an attacker just granted them.
* **Tests:** `adversarial_confidentiality::{policy_pr_cannot_rekey_cloaked_files_to_an_attacker_scope, merging_a_policy_change_does_not_silently_declassify_cloaked_files}`

### BUG-010: `scope grant` accepts low-order X25519 keys, which publishes the scope key
* **Category:** cryptography misuse
* **Repro:** `vl scope grant team veil1000…0` (any low-order point). Push. Anyone who can read the key ring (rings go to every remote, public ones included) computes the KEK from shared secret `0^32`, unwraps the scope key, and decrypts cloaked blobs.
* **Expected:** Reject low-order or non-contributory public keys.
* **Actual:** The test, as an outsider with no identity, decrypts `team-only-api-token`.
* **Root cause:** `parse_public_key` (`identity.rs:52`) accepts any 32 bytes. `wrap_key` uses `diffie_hellman` without checking `was_contributory()` (`identity.rs:66`).
* **Test:** `adversarial_confidentiality::granting_a_low_order_public_key_does_not_publish_the_scope_key`
* **Reopened and fixed (crypto hardening):** the test only inspected the legacy `members` map, so after rings became signed logs it passed without looking at any wrap, and the legacy box still accepted low-order keys. Now HPKE (format 3) and the legacy box (`wrap_key_legacy`, formats 1–2) both refuse them; the test inspects every wrap in the log, and `granting_a_low_order_public_key_is_refused_by_the_legacy_wrapping_too` covers format 2.

### BUG-011: Revocation never reaches remotes; key rings merge as unions
* **Category:** access control / forged or replayed key rings
* **Repro:**
  1. Grant Bob `ops` and push.
  2. `vl scope revoke ops <bob>` *before Bob ever pulled*, add new `ops` content, and push.
  3. Bob clones.
  4. Variant: Bob writes his old copy of the ring back to the remote, and Alice pulls.
* **Expected:** The remote ring no longer wraps the key for Bob, and a replayed ring does not resurrect him.
* **Actual:** Bob decrypts the post-revocation content. In the variant, Bob is silently re-added to Alice's local ring.
* **Root cause:** `sync_meta` does `merged.members.entry(k).or_insert(m)`, a pure union (`remote.rs:137`). Removals are never propagated, rings carry no version or signature, and there is no key rotation (`keychain.rs:239`).
* **Tests:** `adversarial_confidentiality::{revoked_member_cannot_obtain_the_scope_key_from_the_remote, replayed_key_ring_does_not_undo_a_revocation}`

### BUG-012: A forged "released" embargo record is accepted
* **Category:** forged embargo records / confidentiality
* **Repro:**
  1. Anyone who can write to the team remote (no key needed) sets `released_key` of an embargo record to random bytes.
  2. The key holder pulls, keeps working, commits and pushes `main` to the public mirror.
* **Expected:** A release is accepted only if the published key matches the record (for example, it opens `wrapped` for members, or matches a key fingerprint stored at creation).
* **Actual:**
  * The key holder's engine treats the embargo as released and can no longer read the embargoed bytes. `read_entry` falls back to the pre-merge content.
  * The next snapshot re-stores the working-copy content (the fix) as **public**, so `verify_signature` reaches the mirror before the real release.
* **Root cause:** `sync_meta` overwrites an unreleased record with any incoming "released" one (`remote.rs:145`). `Keychain::resolve` trusts `released_key` blindly (`keychain.rs:140`). The builder then treats the entry as released and re-encodes it (`builder.rs:228`).
* **Tests:** `adversarial_remote::{forged_embargo_release_does_not_publish_the_fix, forged_embargo_release_does_not_lock_out_key_holders}`. The control `embargo_from_cloaked_branch_stays_hidden_until_release` passes.

### BUG-013: The lock is stolen from a live holder after 120 s, and an operation is lost
* **Category:** concurrency / data loss
* **Repro:**
  1. Process A's transaction takes more than 2 minutes, for example snapshotting a huge tree. There is no stat cache, so every file is re-hashed.
  2. Process B sees the lock as stale, deletes it, and commits.
  3. A commits on top of the old op head.
  4. The test simulates this by back-dating A's lock file.
* **Expected:** B waits or fails. Liveness is checked via PID or a heartbeat, and A detects that its lock was stolen before writing `op_head`.
* **Actual:** Both commit, and B's operation disappears from the op log (the test reports `tags = ["from-a"]`). A's `Drop` also deletes whatever lock file exists, even one that now belongs to someone else.
* **Root cause:** `lock.rs:40` judges staleness by timestamp only. There is no refresh, `commit` does no compare-and-swap on `op_head`, and `Drop` removes the file unconditionally (`lock.rs:54`).
* **Tests:** `adversarial_lock::{a_live_lock_holder_is_never_robbed, dropping_a_lock_never_releases_someone_elses_lock}`

### BUG-014: A quarantined edit to a tracked file is overwritten, then purged from the vault
* **Category:** data loss
* **Repro:**
  1. Edit the tracked `config.js` and accidentally include an AWS key. `vl status` shows it quarantined, and `@` records `D config.js`.
  2. `vl new main` (or any command that checks out another change), then `vl status`.
* **Expected:** Local-only (quarantined) files are protected from checkout, like isolated files, or at least remain in the vault.
* **Actual:** Checkout overwrites the edited file with the old version, and the next snapshot drops `config.js` from the vault. The edit is gone (`disk: "const a = 1;\n", vault: false`). Committing in the quarantined state also records the file as *deleted* for everyone else.
* **Root cause:** `checkout` protects only *policy* local-only paths (`checkout.rs:78`), not quarantined ones (`builder.rs:261`). `capture_local_files` prunes vault entries that are no longer local-only (`vault.rs:67`).
* **Test:** `adversarial_cli_abuse::quarantined_edits_are_never_lost`

## Medium

### BUG-015: Path-like scope or embargo names panic (`VPath::new(..).unwrap()`)
* **Category:** malicious remote / DoS / input validation
* **Repro:** Any of these:
  * A pulled key ring whose `scope` field is `../../evil`.
  * An embargo record with `id` `../../../x`.
  * A sealed object whose envelope names scope `../../x` (read by `cat`, checkout or `log`).
  * A snapshot whose `cloak` is `../../x`, followed by `ws exec --ephemeral`.
  * CLI input: `vl embargo release ../../x`, `vl scope grant ../x <pk>`, `vl cloak x --scope ../x`.
* **Expected:** A clean error.
* **Actual:** The process panics: `keychain.rs:156` and `keychain.rs:254` hit `called Result::unwrap() on an Err value: InvalidPath(…)`. A remote can crash every pull or checkout of the victim.
* **Root cause:** `ring_path` and `embargo_path` (`keychain.rs:155`, `keychain.rs:253`) build paths from untrusted strings and `unwrap()`.
* **Tests:** `adversarial_remote::{ring_with_path_like_scope_does_not_crash_pull, embargo_record_with_path_like_id_does_not_crash_pull, sealed_object_with_path_like_scope_does_not_crash_readers, hostile_cloak_field_on_snapshot_does_not_panic}`, `adversarial_cli_abuse::path_like_scope_and_embargo_names_do_not_panic`

### BUG-016: Embargo messages are published in plaintext before release
* **Category:** confidentiality / embargo
* **Repro:** `vl merge fix --embargo -m "Fix CVE-2026-31337: auth bypass via unsigned tokens"` (the fix branch itself is cloaked), then `vl push mirror -t main`.
* **Expected:** Nothing about the fix is public before release.
* **Actual:** The string appears in the merge snapshot object and in `.veil/meta/embargoes/<id>.json` on the public mirror.
* **Root cause:** The merge description is plain unless `into` is cloaked (`commands.rs:203`). `create_embargo` stores `description` in clear (`keychain.rs:306`), and records are synced to public remotes.
* **Test:** `adversarial_confidentiality::embargo_messages_are_not_public_before_release`

### BUG-017: Squashing a cloaked change into a public parent writes its description in plaintext
* **Category:** confidentiality / cloaking
* **Repro:** A cloaked workspace change is described "secret plan: acquire Initech in Q3". Run `vl squash` into its public parent, then push `main` to the mirror.
* **Expected:** The sealed description stays sealed, or the squash is refused.
* **Actual:** The joined description is stored as `Text::Plain` and reaches the mirror.
* **Root cause:** `commands.rs:161`: `make_text(&joined, p.cloak)` uses the *parent's* cloak.
* **Test:** `adversarial_confidentiality::squash_keeps_cloaked_descriptions_sealed`

### BUG-018: An embargoed tree reveals which files the fix touches, their new sizes and new file names
* **Category:** confidentiality / embargo (metadata side channel)
* **Repro:** Run an embargoed merge whose fix edits `auth.rs` and adds `CVE-2026-31337-auth-bypass.md`, then push to the public mirror.
* **Expected:** The docs say non-members "see the main line exactly as it was before the merge".
* **Actual:** The mirror's tree lists `CVE-2026-31337-auth-bypass.md` (size 8). `auth.rs` shows the *new* size (66 instead of 28), and the set of embargoed entries is exactly the set of changed files.
* **Root cause:** `apply_embargo` keeps `name` and `size` from the merged entry (`..e.clone()`, `embargo.rs:50`) and adds new names with no fallback.
* **Test:** `adversarial_confidentiality::embargoed_tree_reveals_nothing_about_the_fix`

### BUG-019: Built-in secret rules are case-sensitive
* **Category:** policy / glob edge cases (case-insensitive filesystems)
* **Repro:** Commit `.ENV`, `.Env`, `certs/Server.PEM`, `deploy/ID_RSA`, `prod.TFSTATE` or `.NETRC`, then push to the mirror.
* **Expected:** Isolated. On macOS and Windows these *are* the files that tools read as `.env` and friends.
* **Actual:** They are classified `public`. `.ENV` containing `DB_PASSWORD=hunter2hunter2` (unquoted, so the scanner misses it; see BUG-032) reaches the public mirror.
* **Root cause:** `GlobBuilder` without `case_insensitive(true)` (`policy.rs:101`). User rules are equally case-sensitive.
* **Tests:** `adversarial_confidentiality::{builtin_secret_rules_are_case_insensitive, uppercase_dotenv_never_reaches_a_public_mirror}`

### BUG-020: The secret scanner skips files with a NUL byte, including UTF-16 text, and files over 8 MiB
* **Category:** secret-scanner bypass
* **Repro:** Any of these is committed publicly:
  * A UTF-16LE file with BOM containing `aws_access_key_id = AKIA…` (as Windows tools write it).
  * A text file with one leading NUL.
  * An 8 MiB + 1 file with an AWS key at the end.
* **Expected:** The scanner decodes UTF-16 and scans large files (streaming, or at least the first and last N MiB), or quarantines what it cannot scan.
* **Actual:** All three are recorded publicly.
* **Root cause:** `secrets.rs:88`: `if data.len() > MAX_SCAN_BYTES || looks_binary(data) { return vec![] }`.
* **Tests:** `adversarial_confidentiality::{scanner_is_not_bypassed_by_utf16_encoding, scanner_is_not_bypassed_by_a_single_nul_byte, scanner_is_not_bypassed_by_file_size}`

### BUG-021: Deeply nested hostile trees overflow the stack (`vl clone` aborts)
* **Category:** malicious remote / DoS
* **Repro:** A remote with a tree nested 60,000 levels deep (each level is a 1-entry tree, about 6 MB total), then `vl clone`.
* **Expected:** A clean error (depth limit) or success.
* **Actual:** `fatal runtime error: stack overflow, aborting` (SIGABRT, exit 134) in **both debug and release** builds.
* **Root cause:** Recursive walks over untrusted depth: `Transfer::copy` (`remote.rs:64`), then `diff_dir` (`tree.rs:93`), `walk_into`, `merge_dir` and `normalize_dir`.
* **Test:** `adversarial_cli_remote::deeply_nested_remote_tree_does_not_crash_clone`

### BUG-022: The `vl ws exec` sandbox exposes plaintext secrets to other local users, and outlives a crash
* **Category:** confidentiality / temp directories
* **Repro:** `vl ws exec agent --with-isolated -- …` in a repository with cloaked `secrets/` and an isolated `.env`. Inspect the sandbox mode, or `kill -9` vl while the command runs.
* **Expected:** The sandbox is `0700` (files `0600`), and is cleaned up or reclaimable after a crash.
* **Actual:** The directory is `0775`/`0755` (umask-dependent) under `$TMPDIR`, typically a shared `/tmp`, and contains plaintext cloaked files and `.env`. After `kill -9` the directory and secrets stay on disk indefinitely.
* **Root cause:** `std::fs::create_dir_all(&dir)` with default permissions (`vl/src/main.rs:910`). Isolated files are written from the vault (`main.rs:916`). Cleanup is in-process only (`main.rs:941`).
* **Tests:** `adversarial_cli_crash::{ws_exec_sandbox_is_private_to_the_user, killed_ws_exec_leaves_no_plaintext_behind}`

### BUG-023: Isolated secrets injected by `ws exec --with-isolated` are recorded if the command copies them
* **Category:** confidentiality / isolation (agent workflows)
* **Repro:** `vl ws exec agent --with-isolated -- sh -c 'cp .env config.txt'`.
* **Expected:** Content the engine itself injected from the vault is never recorded under another name; quarantine it like a scanner hit.
* **Actual:** `config.txt` containing `API_TOKEN=super-secret-isolated-value` is recorded in the workspace's history. The unquoted value also evades the scanner (BUG-032).
* **Root cause:** The builder only knows *policy* paths and regex hits. The values injected at `vl/src/main.rs:916` are not checked against what is recorded.
* **Test:** `adversarial_cli_crash::ws_exec_cannot_launder_isolated_secrets_into_history`

### BUG-024: `--until +Nd` overflows; it panics in debug and releases the embargo immediately in release
* **Category:** CLI abuse / embargo
* **Repro:** `vl merge fix --into main --embargo --until +213503955787d`.
* **Expected:** The value is rejected as out of range.
* **Actual:** In debug: `attempt to multiply with overflow` panic at `vl/src/main.rs:475`. In a release build the product wraps to a date in 1954, so the next `vl` command prints `Released embargo …: its release time has passed`.
* **Root cause:** `now_millis() + n * mult` uses unchecked arithmetic (`vl/src/main.rs:475`).
* **Test:** `adversarial_cli_abuse::embargo_deadline_overflow_is_rejected`

### BUG-025: Checkout writes through symlinked directories in the working copy
* **Category:** path traversal (symlinks)
* **Repro:**
  1. Bob has an untracked symlink `vendor -> /shared/vendor`. Veil ignores symlinks when snapshotting.
  2. Alice's history adds `vendor/postinstall.sh`.
  3. Bob runs `vl pull` then `vl new origin/main`.
* **Expected:** Refuse to write beyond a symlink, as git does.
* **Actual:** `postinstall.sh` is created in `/shared/vendor`, outside the working copy.
* **Root cause:** `DiskBackend::write` uses `create_dir_all(parent)` and a rename that follow intermediate symlinks (`vfs/disk.rs:77`). Checkout never checks parent components with `symlink_metadata`.
* **Test:** `adversarial_cli_abuse::checkout_never_writes_through_a_symlinked_directory`

### BUG-026: A lock left by a crashed process blocks the repository for 2 minutes
* **Category:** crash recovery / availability
* **Repro:** `kill -9` vl while it snapshots a large tree (the test actually kills it while the lock is held), then run `vl status`.
* **Expected:** A dead holder's lock is detected (PID liveness on the same host) and recovered at once.
* **Actual:** Each command waits 15 s and fails with `repository is locked by another process` until the lock is 120 s old.
* **Root cause:** `lock.rs:40` (age only) and `lock.rs:14`/`lock.rs:46`. The PID in the lock file is never checked.
* **Tests:** `adversarial_lock::lock_of_a_dead_process_does_not_block_for_minutes`, `adversarial_cli_crash::repository_is_usable_right_after_a_crash_while_locked`

### BUG-027: Replacing the identity bricks every repository that has a vault
* **Category:** availability / key management
* **Repro:** In a repository with an isolated `.env` (so a vault exists), run `vl identity new --force`, then `vl status`.
* **Expected:** The vault is reported as unreadable (or re-keyed), and other commands keep working.
* **Actual:** Every command, including `status` and `log`, fails with `crypto error: authentication failed for scope 'local'`.
* **Root cause:** `Ctx::snapshot` calls `capture_local_files` (`vl/src/ctx.rs:211`), which calls `vault_load()`, which propagates the AEAD failure (`vault.rs:41`).
* **Test:** `adversarial_cli_abuse::rotating_the_identity_does_not_brick_the_repository`

## Low

### BUG-028: Objects are never re-verified on read
* **Category:** integrity / tampered `.veil/`
* **Repro:** Overwrite a blob file in `.veil/objects` with other bytes, then `read_blob(id)`.
* **Expected:** `Corrupt` (hash mismatch), as `put_raw` enforces on write.
* **Actual:** The tampered bytes are returned. There is no `fsck` either.
* **Root cause:** `ObjectStore::get_raw` (`store.rs:53`) and `open` do not hash-check.
* **Test:** `adversarial_remote::tampered_local_object_is_detected_on_read`

### BUG-029: Non-canonical trees (unsorted or duplicate entries) are accepted
* **Category:** malicious remote / integrity
* **Repro:** A remote tree with entries ordered `[c, b, a]`.
* **Expected:** Rejected on pull, or handled consistently.
* **Actual:** `walk_files` (`vl files`) lists `c`, but binary search in `Tree::get` cannot find it. `lookup`, `diff_trees`, checkout and `vl cat` treat it as absent, so reviewers and checkout see different trees. Logically equal trees also get different ids.
* **Root cause:** No canonical-form check in `Object::decode` (`object.rs:234`). `Tree::get`/`insert` assume sorted entries (`object.rs:130`).
* **Test:** `adversarial_remote::non_canonical_trees_are_rejected_or_consistent`

### BUG-030: `vl tag set` accepts any object id, for example a blob
* **Category:** CLI abuse / consistency
* **Repro:** `vl tag set bad -r <64-hex id of a blob>`, then `vl log`.
* **Expected:** "not a snapshot".
* **Actual:** The view references a blob, and every graph query fails until `vl undo`.
* **Root cause:** `set_tag` (`commands.rs:232`) does not check the target type. The revset accepts any stored 64-hex id.
* **Test:** `adversarial_remote::tag_cannot_point_at_a_non_snapshot_object`

### BUG-031: `pull` accepts remote tags whose target is missing
* **Category:** malicious or partial remote / availability
* **Repro:** A remote view with `main -> <non-existent id>`, then `vl pull`.
* **Expected:** The tag is skipped with a warning.
* **Actual:** The tag is stored, after which `visible_snapshots` and `vl log` fail with `object … is not present`.
* **Root cause:** `ancestors_in` skips `Missing` (`remote.rs:111`), but the tag is still inserted.
* **Test:** `adversarial_remote::pulled_tag_pointing_at_missing_object_does_not_brick_the_repo`

### BUG-032: Scanner regex gaps: unquoted credentials, keys glued to identifiers
* **Category:** secret-scanner bypass
* **Repro:** `password: Xk9mQ2vL7pR4wZt8` (YAML), `API_KEY=Xk9m…` (dotenv), `AWS_KEY_AKIAIOSFODNN7EXAMPLE`.
* **Expected:** Detected.
* **Actual:** All are committed publicly.
* **Root cause:** `generic-secret-assignment` requires quotes (`secrets.rs:49`). The AWS rule requires `\b`, and `_` is a word character (`secrets.rs:39`).
* **Tests:** `adversarial_confidentiality::{scanner_detects_unquoted_credentials, scanner_detects_aws_key_glued_to_an_identifier}`

### BUG-033: `Envelope::to_bytes` truncates the scope length to `u16`
* **Category:** crypto encoding
* **Repro:** `Envelope::seal(k, &"s".repeat(70_000), …)`, then `to_bytes`, then `from_bytes`.
* **Expected:** An error, or a faithful round-trip.
* **Actual:** A silently corrupt encoding. This is not reachable from the CLI (scope names are 64 characters or fewer), only through the library API.
* **Root cause:** `crypto.rs:103` (`len() as u16`).
* **Test:** `adversarial_fuzz::envelope_encoding_roundtrips_or_refuses_long_scopes`

### BUG-034: `OverlayBackend` silently replaces a lower-layer file with a directory
* **Category:** backend model equivalence (found by `adversarial_props`)
* **Repro:** The lower layer has file `a`. `overlay.write("a/b")` or `create_dir_all("a")`.
* **Expected:** Like Memory and Disk: `InvalidPath` / `ENOTDIR`.
* **Actual:** Succeeds; `a` is whited out. In an agent's ephemeral workspace, `mkdir -p a` where `a` is a file deletes that file from the snapshot.
* **Root cause:** `prepare_parents` (`vfs/overlay.rs:84`).
* **Test:** `adversarial_props::overlay_does_not_replace_a_lower_file_with_a_directory`

### BUG-035: `DiskBackend` reports ENOTDIR as an error for paths below a file
* **Category:** backend model equivalence (found by `adversarial_props`)
* **Repro:** File `a` exists. `metadata("a/b")`, `remove_file("a/b")`, `remove_dir_all("a/b")`.
* **Expected:** Like Memory: `Ok(None)` / `Ok(())`, as the trait docs say.
* **Actual:** `Err(Io(NotADirectory))`. Checkout probes `metadata(..)?` and would abort.
* **Root cause:** `io_err` maps only `NotFound` (`vfs/disk.rs:21`).
* **Test:** `adversarial_props::disk_paths_below_a_file_are_simply_missing`

### BUG-036: Remote-controlled metadata is printed raw (terminal escape injection)
* **Category:** malicious remote / CLI output
* **Repro:** A remote tag named `v1\e[1A\e[2Kfake-line` and a description with OSC title or hyperlink sequences. Then `vl clone`, `vl log`, `vl tag list`, `vl show main`, `vl pull`.
* **Expected:** Control characters are escaped, and remote tag names are validated (`validate_tag_name`).
* **Actual:** Raw ESC sequences reach the terminal. They can rewrite previous lines, set the title, or plant clickable links.
* **Root cause:** `pull` inserts remote tag names unvalidated (`remote.rs:253`). `render::one_line` and `print_log` (`vl/src/render.rs:79`, `vl/src/render.rs:125`) print descriptions and authors verbatim.
* **Test:** `adversarial_cli_remote::remote_metadata_cannot_inject_terminal_escapes`

### BUG-037: Crash leftovers (`.name.vltmpXXXXXXXX`) are snapshotted into history
* **Category:** crash consistency
* **Repro:** `DiskBackend::write` killed between create and rename leaves `src/.main.rs.vltmp1a2b3c4d` (simulated byte-for-byte). Then `vl commit`.
* **Expected:** These temp files are ignored or cleaned up.
* **Actual:** The half-written file is recorded and pushed.
* **Root cause:** The temp-file naming at `vfs/disk.rs:79` is not excluded by the builder.
* **Test:** `adversarial_cli_crash::interrupted_write_leftovers_are_not_snapshotted`

### BUG-038: One unreadable file makes every command fail, even `vl ignore`
* **Category:** robustness
* **Repro:** `chmod 000 locked.bin`, then `vl ignore locked.bin` or `vl status`.
* **Expected:** A warning and skip; `ignore` should still work.
* **Actual:** `I/O error … Permission denied` from every command. The auto-snapshot runs before the command (`--no-snapshot` is the only escape).
* **Root cause:** `builder.rs:222` propagates read errors.
* **Test:** `adversarial_cli_abuse::an_unreadable_file_does_not_brick_the_cli`

### BUG-039: Files with non-UTF-8 names are silently never recorded
* **Category:** data loss (silent)
* **Repro:** Create `report-\xff\xfe.csv`, then `vl commit`.
* **Expected:** Recorded, or at least a warning.
* **Actual:** `(empty)` commit, with no warning. The file never reaches clones.
* **Root cause:** `vfs/disk.rs:146` (`continue`).
* **Test:** `adversarial_cli_abuse::non_utf8_file_names_are_not_silently_dropped`

### BUG-040: `vl undo` with uncommitted edits removes them from disk
* **Category:** data loss (recoverable)
* **Repro:** Run any command, create `new-work.txt`, then `vl undo`.
* **Expected:** Undo the last *command*; working-copy edits survive.
* **Actual:** The auto-snapshot of the edits becomes the last operation; undo reverts it and checkout deletes `new-work.txt`. It is recoverable only via `vl undo` again or `vl op restore`. The message says `Undid: snapshot working copy`.
* **Root cause:** `Ctx::open` snapshots before `Cmd::Undo` (`vl/src/ctx.rs:210`). `Repo::undo` (`commands.rs:284`) undoes whatever op is newest.
* **Test:** `adversarial_cli_abuse::undo_does_not_discard_uncommitted_edits`

---

## Hypotheses (not demonstrated)

These were reasoned from the code but **not** proven by a test:

* **Ciphertext replay or rollback across paths and snapshots.** A non-member with push access can build trees that move or roll back existing ciphertexts (for example, revert a rotated credential to an old ciphertext). Envelopes bind the scope but not the path or snapshot, and nothing is signed. This is outside the documented claims; per-snapshot signatures are on the roadmap.
* **Case-insensitive and normalising filesystems (macOS, Windows).** `README.md`/`readme.md` and NFC/NFD `é.txt` are tracked separately (round-trip verified on Linux) and would clobber each other on checkout there. User rules like `secrets/` would not match `Secrets/`. Not testable on this ext4 host.
* **Release-build traversal with `/` in names.** Debug builds panic on the `debug_assert!` (demonstrated). In release, `VPath::join` would produce `a/../../x`, which `DiskBackend` resolves outside the root. Inferred from code; the `..` variant is demonstrated in BUG-001.
* **Identity-file race.** `write_identity` writes the secret with default permissions and then `chmod 0600`. There is a brief window in which another local user could read it.
* **Clock-skew lock theft.** On shared or network filesystems, a host whose clock runs ahead sees other hosts' fresh locks as stale. This follows from BUG-013.
* **Timing side channels.** None measured. Documented leaks (cloaked file names and sizes, equality from deterministic sealing) were confirmed but are not reported as bugs.

## Coverage notes

* **Fuzzing.** `cargo-fuzz` is not installed, so all fuzz targets use proptest (`adversarial_fuzz.rs`): `Object::decode`, `Envelope::from_bytes`/`peek_scope`, `Policy::parse` + `classify`, the revset resolver, tree decoding with `walk`/`diff`/`lookup`/`checkout`, `secrets::scan`, `ObjectId`/`ChangeId` parsing, and `VPath::new`.
* **Random operation sequences.**
  * `adversarial_props.rs` runs 18 operation kinds, checking invariants after every step and checking undo and redo after every history op. Commits must be recoverable via `op restore`, and pushes must round-trip.
  * It passed 1,500 cases in release (`PROPTEST_CASES=1500`). The only failures came from the cloaked-workspace variant (BUG-005, BUG-006).
* **Backend model equivalence.** Memory, Disk, Overlay over empty, Overlay over memory, and Overlay over `TreeView` agree with the reference model, apart from BUG-034 and BUG-035, whose cases those tests skip and which have their own repros.

---

# Round 2 findings (BUG-041 … BUG-056)

Found by the second adversarial pass against `integration` @ `8aa7a22`
(after all of BUG-001…040 were fixed). Each reproduction is an
`#[ignore = "BUG-NNN: …"]` test in `crates/*/tests/adversarial2_*.rs`;
`cargo test --no-fail-fast -- --ignored` runs them. The tester's reasons and
tests are the primary record; the root cause noted here is where known.

| ID | Sev. | Area | Finding | Reproducing tests |
|---|---|---|---|---|
| BUG-041 | critical (**fixed**, embargo wave) | embargo | Releasing an older embargo publishes the content of a newer, unreleased one (and a member of the first embargo's scope can read the second fix). Overlapping embargoes are wrapped under the first. | `adversarial2_embargo`: `releasing_the_first_embargo_does_not_publish_the_second_fix`, `a_member_of_the_first_embargo_scope_cannot_read_the_second_fix`; `adversarial2_props`: `visibility_invariants_hold_with_overlapping_embargoes` |
| BUG-050 | critical (**fixed**, embargo wave) | embargo / visibility | After a release, reverting a file to its pre-embargo content is silently not recorded (`builder.rs` ≈586–594 treats "matches the fallback" as a stale working copy). Chained with expose → release → re-cloak → cloaked embargoed merge → release, cloaked content becomes readable on the public mirror. | `adversarial2_embargo`: `reverting_a_file_to_its_pre_embargo_content_after_release_is_recorded`; `adversarial2_props`: `recloak_after_a_released_expose_survives_a_cloaked_embargo_release` |
| BUG-045 | critical | policy | **Fixed:** a `.veilpolicy` arriving by merge or pull could publish the local member's isolated files (`.env`, keys) without warning. Working-copy snapshots now keep the device's accepted policy where an incoming one weakens it, warn, and wait for `vl policy accept` (ARCHITECTURE §4; `policy_accept.rs`). | `adversarial2_visibility`: `a_merged_policy_cannot_publish_the_merging_members_isolated_files`, `a_pulled_policy_cannot_publish_isolated_files` |
| BUG-049 | high (**fixed**, lock/durability wave) | lock | Clearing a dead contender's takeover guard (`lock.steal`) can delete a live one; two processes both acquire the lock. | `adversarial2_durability`: `two_contenders_never_both_take_over_a_dead_lock` |
| BUG-044 | high (**fixed**, lock/durability wave) | durability | After a failed fsync barrier, a retried command reuses objects that never became durable. | `adversarial2_durability`: `a_retried_command_after_an_fsync_failure_loses_no_acknowledged_data` |
| BUG-042 | high (**fixed**, embargo wave) | embargo / scanner | Edits of embargoed files skip the secret scanner, and the release publishes them. | `adversarial2_embargo`: `an_edit_on_an_embargoed_file_is_secret_scanned_before_release_publishes_it` |
| BUG-043 | high (**fixed**, embargo wave) | embargo / scopes | A fix cloaked under a wider scope than the embargo's reaches every member of that wider scope (history readable outside the embargo scope). | `adversarial2_embargo`: `the_fix_history_is_not_readable_outside_the_embargo_scope` |
| BUG-053 | high (**fixed**, embargo wave) | embargo | Commit messages of follow-up commits on an embargoed line are public before release. | `adversarial2_embargo`: `follow_up_commit_messages_on_an_embargoed_line_are_not_public` |
| BUG-047 | medium (**fixed**, embargo wave) | embargo | Releasing a newer embargo first reveals the older one's changed file names and sizes. | `adversarial2_embargo`: `releasing_the_second_embargo_first_hides_the_first_fix_metadata` |
| BUG-048 | medium (**fixed**, embargo wave) | embargo | An embargoed merge's conflict list names the fix's files in plaintext. | `adversarial2_embargo`: `an_embargoed_merge_does_not_name_the_fix_files_in_its_conflict_list` |
| BUG-054 | medium (**fixed**, embargo wave) | sync | An embargoed fix with a plaintext ancestor blocks pushing `main` to a team remote. | `adversarial2_visibility`: `main_can_be_pushed_to_the_team_when_the_fix_line_starts_in_plaintext` |
| BUG-046 | medium | undo | **Fixed** (round 3): `vl undo` could not undo `expose`/`cloak`/`isolate`/`ignore`/`restore`; it silently undid the command before (those commands edit the working copy, which edit-preserving undo keeps). They now record their own operation instead of an automatic snapshot. | `adversarial2_cli`: `undo_reverts_an_accidental_expose`, `undo_reverts_a_restore` |
| BUG-052 | medium (**fixed**, lock/durability wave) | lock | A dead holder's lock whose pid was reused by a live process blocks the repository indefinitely. | `adversarial2_durability`: `a_reused_pid_does_not_keep_a_dead_holders_lock` |
| BUG-055 | medium | scanner | **Fixed:** common credential keywords were not detected: `aws_secret_access_key`, `*_secret`, `*_token`, passwords in URLs (also suffixed keys and XML elements, from the backlog). | `adversarial2_scanner`: `common_credential_assignments_are_detected` |
| BUG-056 | medium | scanner | **Fixed:** BOM-less UTF-16 in non-Latin scripts, and UTF-16 starting mid-chunk, bypassed the scanner. (Reported as a second "BUG-050"; renumbered.) | `adversarial2_scanner`: `bomless_utf16_with_cjk_text_is_scanned`, `utf16_starting_just_before_a_chunk_boundary_is_scanned` |
| BUG-051 | medium | untrusted input | **Fixed** by the macOS stream (c4247ea): tree names that HFS+ folds to `.veil` (ignorable code points) were accepted. | `adversarial2_scanner`: `hfs_ignorable_spellings_of_dot_veil_are_refused` |

Overlapping embargoes are refused in 1.0 (owner's decision), which fixes
BUG-041/047 by design. The `adversarial2_props` skips for BUG-041 and BUG-050
have been removed; both variants pass 1,000 release cases.

---

# Round 3 findings (BUG-057 … BUG-068)

Found by the third adversarial pass against `integration` @ `c7fa614`,
aimed at the surface round 3 added: the Git bridge, SFTP remotes, the
format freeze and the release artefacts. Each reproduction is an
`#[ignore = "BUG-NNN: …"]` test in `crates/*/tests/adversarial3_*.rs`;
`cargo test -p veil-core -p vl --test 'adversarial3_*' -- --ignored` runs
them.

| ID | Sev. | Area | Finding | Root cause | Reproducing tests |
|---|---|---|---|---|---|
| BUG-057 | critical (**fixed** by the policy pin, BUG-045 wave) | Git import / policy | A `.veilpolicy` edit made on GitHub (`.env public!`, or deleting a user `isolate` rule) is imported silently. The next snapshot records the local isolated `.env` in plaintext, and the next `vl git push` uploads it to GitHub: any contributor can exfiltrate a maintainer's local secrets. This is the Git-import path of BUG-045; check that its fix covers `git/import.rs` too. | `git/import.rs:237` `guard_policy` asks `policy_rekeys` (`embargo.rs:549`), which only looks at files that are already `Cloaked`. Isolated files are never in the tree, so a rule that un-isolates them never counts. | `adversarial3_git_cli`: `a_github_policy_edit_cannot_exfiltrate_the_local_dotenv` |
| BUG-063 | high (**fixed**, Git bridge wave) | Git export / embargo | After an embargo release, GitHub keeps the vulnerable pre-fix file whenever a GitHub commit sits on the exported embargoed merge. `main` is exported as the imported commit, which is never recomputed. Carry-over then treats that stale file as "Git's version", so later Veil commits are exported with the vulnerable file too. The import of the next GitHub commit then reads as "Git reverted the fix"; only BUG-050's heuristic keeps that revert out of Veil today, so fixing BUG-050 turns this into a silent revert in Veil. | `git/export.rs:173`: `Origin::Imported` commits are never recomputed, and no publication commit is written for them. `git/export.rs:311` (`carry`): `same(tx, bx)` keeps `ours`, because the parent's projection changed under its pinned Git commit. | `adversarial3_git`: `a_released_fix_reaches_github_past_a_github_commit`, `a_released_fix_is_not_reverted_by_the_next_github_round_trip` |
| BUG-058 | medium (**fixed**, Git bridge wave) | Git import, untrusted input | One hostile branch makes every `vl git fetch`/`pull` fail. For example, a branch whose tree holds `.veilpolicy` as a symlink fails with `invalid path: .veilpolicy is not a regular file`, which names no branch or commit. No other branch is imported. Anyone who can push a branch to the GitHub repository can stop every Veil user's fetch. | `git/import.rs:114`: only `VeilError::Policy` is handled per commit; any other error aborts `import_tips`. `Policy::load` (`import.rs:177`) propagates `GitTreeFs::read`'s `InvalidPath` (`import.rs:426`). | `adversarial3_git_cli`: `a_hostile_branch_does_not_block_importing_the_other_branches` |
| BUG-059 | medium (**fixed**, Git bridge wave) | Git import / revsets | GitHub can take over the names of the user's changes. Exported commits publish the full change id. A branch named after it becomes a local tag on `vl git pull`, and tags win over change ids, so `vl new <change>` checks out the attacker's commit. A commit with a forged `change-id` header equal to the user's change makes that id "divergent" and unusable. | `revset.rs:48`: tags are resolved before change ids. `git/mod.rs:442` (`update_tag`) creates tags for any valid branch name. `git/import.rs:41` (`change_id_of`) trusts the header. | `adversarial3_git_cli`: `a_branch_named_after_a_change_id_does_not_hijack_it`, `a_forged_change_id_header_does_not_break_the_users_change_id` |
| BUG-064 | medium (**fixed**, Git bridge wave) | Git map / determinism | The mapping is documented as recomputable. That holds only if the next command is an export. If `.veil/git/map` is lost and the next command is `vl git pull`, every commit Veil exported is imported again as a new snapshot. The result is a parallel copy of the history, without the cloaked files, with duplicate change ids. `github/main` points into it, and `main` "has diverged". | `git/import.rs:131` (`mapped`): an unmapped commit carrying a Veil `change-id` header is treated as a Git-made commit. Nothing re-derives the mapping by export first. | `adversarial3_git`: `a_lost_mapping_does_not_duplicate_history_on_pull` |
| BUG-065 | medium (**fixed**: limits, see ARCHITECTURE §1) | SFTP client, hostile server | A hostile SFTP server can exhaust the client's memory. One file it calls 16 bytes and then never ends (`/dev/zero`-like) is buffered without limit; the stub hung up at 256 MiB. An endless `READDIR` is accumulated the same way. Op heads, locks, pack indexes and object listings are all read this way. | `vfs/sftp.rs:242` (`read_handle`, non-exact): it probes past the size hint until EOF, with no ceiling. `vfs/sftp.rs:480` (`readdir`): it loops until EOF, with no ceiling. | `adversarial3_sftp`: `an_endless_file_is_refused_before_exhausting_memory`, `an_endless_listing_is_refused_before_exhausting_memory` |
| BUG-066 | medium (**fixed**: per-request timeouts, stray replies are protocol errors, `VEIL_SFTP_TIMEOUT`; the test now runs with a 2 s timeout) | SFTP client, hostile server | A server that never answers, but sends a stray reply with an unknown id every 200 ms, hangs every Veil command forever. The 300 s request timeout never fires, so `vl push`/`vl pull` hang, and the remote lock stays held meanwhile. | `vfs/sftp_client.rs:582`: `last_rx` is updated for every packet, even one that answers no pending request. `Pending::wait` (`sftp_client.rs:387`) times out only when `last_rx` is old. | `adversarial3_sftp`: `stray_replies_do_not_defeat_the_request_timeout`, `stray_replies_are_a_protocol_error`, `other_threads_replies_do_not_keep_a_dead_request_alive` |
| BUG-060 | low (**fixed**, Git bridge wave) | Git fetch | A branch deleted on GitHub while a fetch fails keeps its `origin/<branch>` remote tag forever, and no "deleted" report ever appears. | `git/mod.rs:388`: `git fetch --prune` updates the bridge's tracking refs before the import runs. When the import fails, the transaction that removes remote tags is dropped, and the next fetch's `before` no longer lists the branch. | `adversarial3_git_cli`: `a_branch_deleted_during_a_failed_fetch_loses_its_remote_tag` |
| BUG-061 | low (**fixed**, Git bridge wave) | Git transport | A token embedded in a Git remote URL (`https://user:ghp_…@host/x.git`) is printed in `vl git fetch`/`push` errors, which end up in CI logs. `git` itself redacts it in the same message. | `git/transport.rs:70`, `:148`: `{url}` is formatted as is. | `adversarial3_git_cli`: `credentials_in_a_git_url_are_not_printed_in_errors` |
| BUG-062 | low (**fixed**, Git bridge wave) | Git remotes | `vl git remote add origin ../github.git` stores the relative path. `git` resolves it against the current directory, so `vl git push` run from a subdirectory pushes to a different repository (`proj/github.git`). `vl git import` canonicalises paths; `remote add` does not. | `git/mod.rs:294`/`:307` stores the URL unchanged; `transport::fetch`/`push` run `git` in the caller's cwd. | `adversarial3_git_cli`: `a_relative_git_remote_is_the_same_repository_from_a_subdirectory` |
| BUG-067 | low (**fixed**, release wave) | release / Homebrew | `render-formula.sh` accepts tags such as `v1.2.3";system "id";"` or `v1.2.3\|g;1e <cmd>;s\|x`. The tag ends up as Ruby code in the published formula, run by every `brew install`, and as a GNU sed `e` command run on the release runner, which holds `contents: write` and the tap token. Git allows `"`, `;` and `\|` in tag names. dist's SemVer check stops it on the automatic path; `workflow_dispatch` takes any tag that has a release. | `packaging/homebrew/render-formula.sh:20`: the `case` pattern `[0-9]*.[0-9]*.[0-9]*`, where `*` matches anything. The tag is then pasted into `sed "s\|…\|$tag\|"`. | `adversarial3_release`: `the_formula_renderer_refuses_hostile_tags` |
| BUG-068 | low (**fixed**, release wave) | CI supply chain | Every action is referenced by a mutable tag (`actions/checkout@v6`, `Swatinem/rust-cache@v2.9.3`, …), including in `publish-homebrew.yml`, which runs with `contents: write` and `HOMEBREW_TAP_TOKEN`. `ci.yml` pipes `cargo-dist-installer.sh` into `sh` without a checksum, while `actionlint` in the same job is verified. (`release.yml` is generated by dist, with the same pattern.) | `.github/workflows/*.yml` `uses:` lines; the `ci.yml` "dist plan" step. | `adversarial3_release`: `workflow_actions_are_pinned_by_commit`, `ci_verifies_what_it_downloads_and_runs` |

## Round 3 hypotheses (not demonstrated)

* **Clock skew beyond the allowance.** If a holder's wall clock runs more than `lease + grace + skew` (165 s) behind, any contender takes over its live, renewing fencing lock at once. The holder notices at its next `ensure_held` or heartbeat and aborts, so the expected result is a failed push, not a double publish. The documented residual window (between the final check and the `op_head` write) then needs no stall. This is by design; not tested end to end, because remote pushes cannot take an injected clock. **Addressed** (SFTP hardening wave): documented in `lock.rs` and ARCHITECTURE §9, and `vl doctor --remotes` now connects to SSH remotes and warns when a remote's clock (the mtime of a probe file) is more than 60 s off this machine's (`adversarial3_sftp`: `the_servers_clock_offset_is_measured`; `sftp_cli`).
* **Heartbeat TOCTOU.** The renewal reads the lock, compares the token, then writes (`lock.rs` heartbeat). A takeover that lands between the read and the write is overwritten. **Real, and worse than both-lose; fixed** (SFTP hardening wave). After renewals failing for 25 s and one renewal stalled on the wire for more than `grace`, the late write landed on the successor's lock. The old holder then counted it as confirmed (its lease ran from the renewal's *start*), so its own `ensure_held` passed and both could publish. Now a renewal that returns after the lease lapsed counts as losing the lock, and a lapsed holder never removes the lock file on release (`remote_lock`: `a_late_renewal_that_lands_on_a_successor_fences_the_old_holder`, which fails on the old code). With skew beyond the allowance, the race needs no stall, but then only the contender loses.
* **HFS+ spellings of `.git`** (**closed**, Git bridge wave). The Git bridge filtered `.git` with `eq_ignore_ascii_case` (`git/import.rs`, `git/project.rs`), not with the HFS+-ignorable folding that BUG-051's fix added for `.veil`. On HFS+, `.g\u{200c}it/…` from GitHub would be checked out as `.git/…` in a colocated working copy. Both directions now refuse every such spelling (`adversarial3_git_cli`: `hfs_spellings_of_dot_git_are_refused_both_ways`).
* **`git` transport policy.** Veil leaves `protocol.allow` to the user's Git configuration. Git's defaults block `ext::`, but a configuration that allows it would let a Git remote URL run commands. Passing `-c protocol.ext.allow=never` (and `fd`) would close this. The bridge's `git push` also runs hooks (`pre-push`, `reference-transaction`, `core.hooksPath`), and `--no-verify` is not passed. Only someone who can already write `.veil/git/repo.git` or the user's configuration can plant one.
* **Whole-pack prefetch.** `PullSource::prefetch` downloads every remote pack that holds any object the client lacks, into memory, whether or not the walk needs it. A hostile remote with a huge unreferenced pack makes every pull download it. This is close to the documented "a pull holds the remote packs it downloads in memory".
* **Re-import after a release** (**closed**, Git bridge wave). Importing the same Git commit after the embargo under it was released yields a different snapshot id (the merge is no longer re-wrapped), so "re-importing gives the same snapshot" fails there too. Related to BUG-064. An earlier import is now found by its derived change id and metadata before anything is re-imported (`adversarial3_git`: `a_lost_mapping_after_a_release_is_recomputed`).

## Round 3 coverage notes

* **Git bridge, CLI** (`adversarial3_git_cli`; terminal escapes and bidi characters in Git authors and messages were also checked by hand and are escaped by `vl git import`, `vl log` and `vl show`): hostile trees written with `git hash-object --literally`. These are `.veil`, `.VEIL`, `..`, `.Git`, symlinks, gitlinks, a zero-padded mode, unsorted entries, escape codes in names, trees 1,100 deep, and `.veilpolicy` as a symlink. All are refused or reported except as listed above. Also covered: forged `change-id` headers, a branch named after a change id, relative and credential-bearing URLs, force-push and deletion bookkeeping, and the Git-side un-cloaking control.
* **Git bridge, library** (`adversarial3_git`): embargoes with GitHub commits on top, releases, carry-over, and loss of the map and cache.
* **Round-trip property model** (`adversarial3_git_props`): interleaved Veil commits (public, cloaked and isolated files, deletions), GitHub commits (including files under cloaked directories), pull, merge and push, and re-exports. Invariants: no cloaked or isolated token in any object of the bare repository or the bridge; cloaked files intact in Veil; public files identical on both sides; re-export writes nothing. 400 cases passed. Embargo operations are not in the model; they are covered by the targeted tests.
* **SFTP** (`adversarial3_sftp`): an in-process hostile server over a socket pair, testing endless data, endless listings, keep-alive noise and a 2³²−1 name count (control). URL parsing was reviewed (`-o` injection through hosts and users, IPv6, scp style, `--` before the host) and found sound.
* **Format** (`adversarial3_format`): a mutation fuzzer over JSON and binary trees, checking that whatever decodes re-encodes byte for byte. 2,000 cases, plus the golden fixtures; no second encoding found. One logical tree still has one id per encoding (JSON and binary), by design.
* **Release** (`adversarial3_release`): `render-formula.sh` run with hostile tags, and the workflows checked statically.

---

# Round 4 findings (BUG-069 …)

Found by the fourth adversarial pass against `integration` @ `d034203`,
aimed at the format-3 cryptography and `vl upgrade`, the accepted-policy
pin, the materialisation record and durability. Each reproduction is an
`#[ignore = "BUG-NNN: …"]` test in `crates/*/tests/adversarial4_*.rs`;
`cargo test -p veil-core -p vl --test 'adversarial4_*' -- --ignored` runs
them.

| ID | Sev. | Area | Finding | Root cause | Reproducing tests |
|---|---|---|---|---|---|
| BUG-073 | high (**fixed**, policy wave: in-place fold + exhaustive check, `policy::fold_edit`) | policy pin | If a member edits `.veilpolicy` by hand while a teammate's change is still waiting for `vl policy accept`, the edit is accepted out of order. Bob writes `notes/** public` *above* `notes/private.md isolate`. In the accepted policy the new rule ends up *below* the exception and overrides it, so the accepted policy now says his isolated file is public. Nothing shows this, because his working copy's own file still isolates it. When a later policy drops the exception, Bob's local `notes/private.md` is recorded in plaintext and pushed to the team remote, with no warning and no `vl policy accept`. | `policy.rs:470` (`Policy::with_edit`): the rules the member added are appended to the end of the accepted rules (`out.extend(added)`) instead of keeping their position. Rules are last-match-wins, so a rule's position is part of its meaning. Called from `working_copy_policy` (`policy.rs:623`). | `adversarial4_cli`: `a_members_edit_during_a_pending_change_keeps_their_rule_order` (control: `a_members_reordered_edit_is_accepted_in_their_order`) |
| BUG-069 | medium (**fixed**, key-management wave) | identities / signatures | Nothing checks that the two halves of a full public identity `veil1<x25519><ed25519>` belong together. Mallory gives an admin her X25519 key followed by **Alice's** public signing key, and the grant is accepted. The ring's signer table then maps Alice's key to Mallory. From then on every reader judges all of Alice's signatures "unknown key". Her embargo records stop being trusted, so her timed embargoes never auto-release. Mallory can also re-label an Alice-signed snapshot with `signer: mallory` and have it show as "signed by mallory" (the signature does not cover `signer`). | `keychain.rs:1122` (`grant_role`): no proof of possession, and no check that the signing key is not already bound to another member. `keychain.rs:538` (`add_member`): `ever_signers` is keyed by signing key, so a later grant overwrites an earlier member. Checked by `judge` (`keychain.rs` ≈1353). | `adversarial4_crypto`: `a_grant_cannot_rebind_another_members_signing_key` (control: `a_forged_signing_half_does_not_let_mallory_sign`) **Fix:** the full public identity carries a binding (the Ed25519 key's signature over the X25519 key, context `member-binding`); grants refuse an identity without a valid one, record it from format 3, replay checks it, and a signing key can belong to only one member per ring; across rings a proved binding wins and an unproved conflict is attributed to nobody (CRYPTO.md C4). Tests: the reproduction, the adapted control, `round4_keys`. |
| BUG-070 | medium (**fixed**, key-management wave) | keychain / upgrade | One low-order X25519 member key in a ring blocks every key rotation. Such keys come from legacy grants made before the BUG-010 fix, or from any signed grant: replay never checks member keys. HPKE and the legacy box both refuse to wrap to such a key, so the admin can no longer **revoke anyone else**: a revocation re-wraps to the remaining members. `vl upgrade` to format 3 fails at `3:hpke-ring-keys`, after its commit point, and fails again on every resume, leaving `.veil/upgrade.json` behind. The error names no member. | `keychain.rs:1140` (`rotation`) wraps to every remaining member with `?`. `KeyRing::verify` (`Grant`/`Genesis`) accepts low-order member ids. `upgrade.rs` `hpke_ring_keys` propagates the error. | `adversarial4_crypto`: `a_low_order_member_does_not_block_revocation_or_upgrade` **Fix:** rotations leave out members no key may be wrapped to (low-order ids) and replay allows exactly that omission; `rotate`/`revoke`/`upgrade` name the member; past the commit point a scope that cannot be rotated is a note, never an error. `round4_keys`: `rotations_skip_a_low_order_member_and_it_can_be_revoked`. |
| BUG-071 | medium (**fixed**, key-management wave) | upgrade / migration | When a non-admin upgrades first, the upgrade note tells the admin to "run `vl upgrade` … in an upgraded clone". `vl upgrade --remote` says rings move to HPKE "when an admin who has upgraded their clone pushes". If the admin's clone is already at format 3 (a fresh clone of the upgraded remote, or the clone the non-admin upgraded), `vl upgrade` answers "already at format 3" and never runs `3:hpke-ring-keys`. The scope keeps sealing new content under a key published under the legacy wrap, silently. Only `vl scope rotate` fixes it, and nothing says the ring still needs it. | `upgrade.rs:246`: the early return when `config.format == to` with no journal. `post_commit_steps` (`upgrade.rs:141`) adds the ring step only for a `from < 3` transition. | `adversarial4_crypto`: `an_admin_upgrading_an_upgraded_clone_moves_their_rings_to_hpke` **Fix:** `vl upgrade` at format 3 runs `3:hpke-ring-keys` whenever one of this identity's rings still has legacy wraps on its current key (dry run included), and otherwise notes the scopes waiting for their admin. `round4_keys`: `the_ring_step_runs_whenever_it_is_pending`. |
| BUG-072 | medium (**fixed**, key-management wave) | upgrade / SFTP remotes | `vl upgrade --remote <name>` turns the remote URL into a local path without checking whether it is an SSH remote (every other command does). For `host:path` or `sftp://…` it opens `<project>/host:path`. That is an error at best; with a directory at that path, it "upgrades" that directory and reports success, while the real SFTP remote stays at format 2 and keeps refusing AES-SIV objects and HPKE rings. | `vl/src/main.rs:1785` (`cmd_upgrade`): `PathBuf::from(&r.url)` with no `SshUrl::parse`, unlike `remote_backend` (`main.rs:1479`). | `adversarial4_cli`: `upgrade_remote_does_not_treat_an_ssh_url_as_a_local_path` **Fix:** `vl upgrade --remote` resolves SSH URLs to `SftpBackend` as push and pull do. `sftp_cli`: `upgrade_remote_over_a_stand_in_ssh`. |

## Round 4 hypotheses (not demonstrated)

* **Checkout's local-only check uses the incoming policy.** `apply_changes` (`checkout.rs` ≈482) decides `is_local_only` with the *target tree's* `.veilpolicy`, unguarded by the accepted policy. A hostile `.env public!` plus a tracked decoy `.env` therefore does not count as "protected". The member's own `.env` still survives, because `holds()` refuses to overwrite or remove content checkout did not write. Defence in depth is one layer thinner than ARCHITECTURE §4 suggests. No loss was demonstrated.
* **Upgrade journal is trusted.** `upgrade.rs` takes `to` from `.veil/upgrade.json` without `check_format_supported`, and a journal that lists `set-format` as done is believed even if `repo.json` is still at format 2. In that case the HPKE ring step would write a ring-format-3 ring into a format-2 repository. This needs a tampered journal, or a remote whose host writes one, and that host could write `repo.json` directly anyway.
* **Mixed-format processes.** A long-running process that opened a repository before `vl upgrade` committed keeps its in-memory format (2) and goes on writing legacy wraps, including for the new HPKE-only generation. The CLI's per-command lifetime makes the window small. Not tested.
* **Ring `format` is unsigned.** `KeyRing.format` is outside every signature. A hostile remote can relabel a signed ring as legacy (`format: 0`), which then replays as the attacker-controlled `members`/`key_id`. `merge_ring` refuses this for existing replicas (unsigned never overrides signed). For a fresh clone it is part of the documented trust-on-first-use limit.

## Round 4 coverage notes

* **Crypto** (`adversarial4_crypto`): construction swaps between `veil:seal` and `veil:sea2` bodies; scope binding of both wrap constructions; every low-order X25519 point, plus its top-bit variant, as an HPKE `enc` and as a recipient (all refused); forged signing halves in public identities; low-order ring members; the migration step after a non-admin upgrade and on a fresh format-3 clone. The crypto primitives themselves held up; the findings are key management and migration.
* **Policy pin** (`adversarial4_cli`): the member's own edit with and without a pending change. Reviewed by hand and found sound: the "rules unchanged" comparison (comments, spacing, escapes, NFC/NFD, tier aliases, invalid rules that fail safe), the auto-advance rule (appended isolate/ignore, dropped `public!`, including the `builtin_secret` interplay), merge-conflict markers in `.veilpolicy`, undo, stale-working-copy recovery and crash ordering in `Ctx::record`/`finish`.
* **Materialisation record:** fill-in of hidden and fallback paths over a user's own file was reviewed and is kept (`holds`). Path validation of `checkout.json` was reviewed. No test was written beyond the existing suites.
* **Not covered this round:** scanner v3 bypass work, the durability and lock paths (failed barriers, `recover` locks, `since_stamp` tampering, nested `lock.steal.<hash>`), the `crash.rs` sweep of `vl upgrade`, and concurrent upgrade plus push.
  * *Since covered (key-management wave):* `crash.rs` sweeps `vl upgrade` 1→3 and 2→3 across every write in every crash mode, including crashes between the commit point and the ring rotation (`crash_during_upgrade_from_format_1/2`).

---

# Round 4 documentation findings (BUG-074 … BUG-089)

Found by the agent writing the user guide (`docs/guide/`), which ran every
example against the real binary at `integration` @ `d034203`. They have no
reproduction tests yet; the fix wave adds them. (A further finding duplicated
BUG-072, and one — `vl doctor --remotes` skipping SSH remotes — was fixed by
the SFTP wave.)

| ID | Sev. | Area | Finding |
|---|---|---|---|
| BUG-074 | high (**fixed**, cloaked-work wave) | workspaces / Git export | **Fixed:** a public file edited on a cloaked line is sealed with its last public version as `fallback`, which Git export, public remotes and readers without the key see (ARCHITECTURE §4 rule 4); together with BUG-075, cloaked work no longer reaches `main` by `vl commit`. Tests: `cloaked_work_cli.rs`, `cloaked_fallback.rs`. Originally: editing a *public* file in a cloaked workspace and committing seals it; the commit lands on `main` (BUG-075), and `vl git push` then sends a commit that **deletes** that file on GitHub; a public-mirror clone also loses it on its next update. Repro: `vl ws new p -r main --cloak team; vl ws switch p; echo x >> README.md; vl commit -m m; vl git push`. |
| BUG-075 | medium (**fixed**, cloaked-work wave) | commit / tags | **Fixed:** on a cloaked line `vl commit` moves only tags cloaked under the same scope; `--no-advance` moves none (ARCHITECTURE §5). Originally: `vl commit` advances every tag at the parent, whatever workspace it runs in (including cloaked ones), so committing in a separate fix workspace publishes the fix on `main` before any embargo. |
| BUG-076 | medium (**fixed**, policy wave: built-in VCS metadata ignore, `policy::vcs_metadata`; tests in `policy_round4_cli`, `policy_accept`) | init / policy | `vl init` inside a Git checkout records the whole `.git/` directory as public content (56 files in the test), which would be pushed to Veil remotes. `.jj/`, `.hg/` likewise. |
| BUG-077 | medium (**fixed**, key-management wave) | sync / privacy | Key rings are synced to public remotes (public readers need them to verify embargo records), so `vl scope list` on a public-mirror clone shows member names and ids. Not in the threat model. **Fix:** public remotes receive no key rings; their clones accept embargo records unverified (they hold no scope key, so they never auto-release; released keys are checked against the fingerprint) and a member-signed record later replaces an unverified one; rings an earlier vl pushed there are reported, not deleted. What stays visible is in the threat model. `round4_keys`. |
| BUG-089 | medium (**fixed**, key-management wave) | identity | Replacing your identity (`vl identity new --force`) while being a scope's only admin freezes the scope: no command restores admin rights; only a manual restore of the retired identity file works. **Fix:** `vl identity new --force` warns about scopes whose only admin it is replacing; `vl identity recover-admin [--from FILE] [--revoke-old]` lets the retired identity grant the new one admin rights (then optionally revokes it). `identity_cli`: `a_sole_admin_can_hand_over_after_replacing_the_identity`; `round4_keys`. |
| BUG-078 | low (**fixed**, CLI polish wave) | CLI | `vl log \| head` (any truncated pipe) panics with exit code 101. |
| BUG-079 | low (**fixed**) | status | **Fixed:** status lists conflicts of `@` and of its parents whose file `@` has not touched, with a hint. Originally: `vl status` never shows the conflicts of a merge (they are recorded on `@-`; status only lists `@`'s). |
| BUG-080 | low (**fixed**) | squash | **Fixed:** squash keeps a conflict only if the squashed change left the file untouched (or has the conflict itself). Originally: `vl squash` of a conflict resolution into the merge keeps the `(conflict)` mark. |
| BUG-081 | low (**fixed**, CLI polish wave) | push | A push that skips diverged tags exits 0 (Git exits non-zero). |
| BUG-082 | low (**fixed**, CLI polish wave) | doctor | A legacy-format stale lock shows a nonsense time in `vl doctor` (`lease renewed -1793763700901071.5s ago`). |
| BUG-083 | low (**fixed**, policy wave) | policy | After `vl expose t.pem` the ignored `public` rule warns on every command, even after `vl expose --force` adds `public!`; `vl policy check` shows both. |
| BUG-084 | low (**fixed**, CLI polish wave) | messages | `vl cat` of a cloaked file in a public-mirror clone says `object … is not present in this store` instead of "withheld/redacted". |
| BUG-085 | low (**fixed**, policy wave) | messages | `vl cloak x` by a non-member of an existing `team` scope suggests `vl scope create team`. |
| BUG-086 | low (**fixed**, CLI polish wave) | messages | A clone from a public mirror suggests asking for a grant, but public remotes never deliver cloaked content. |
| BUG-087 | low (**fixed**, CLI polish wave) | messages | `vl merge --embargo` reports embargoed files as "published from the cloaked line" and prints `until +7d` literally rather than the date. |
| BUG-088 | low (**fixed**, CLI polish wave) | docs | The README Quick start log shows a `main` tag that `vl init` + `vl commit` never creates. |

---

# Round 5 findings (BUG-090 … BUG-098)

Found by the fifth adversarial pass against `integration` @ `3eb15e2`,
aimed at scanner v3, durability and locks after the latest fixes, the
materialisation record, the Git bridge after its fix wave and the hardened
SFTP client. Each reproduction is an `#[ignore = "BUG-NNN: …"]` test in
`crates/*/tests/adversarial5_*.rs`;
`cargo test -p veil-core -p vl --test 'adversarial5_*' -- --ignored` runs
them. Line numbers refer to `3eb15e2`.

| Severity | Count | IDs |
|---|---|---|
| high | 1 | 098 |
| medium | 4 | 090, 091, 092, 096 |
| low | 4 | 093, 094, 095, 097 |

| ID | Sev. | Area | Finding | Root cause | Reproducing tests |
|---|---|---|---|---|---|
| BUG-098 | high (**fixed**, policy wave 2) | isolation / auto-snapshot | **Fixed:** editor scratch files are ignored by a built-in rule, and every editor or backup artefact of a protected file (`.x.swp`, `x~`, `#x#`, `.#x`, `x.bak`, …) takes that file's protection (ARCHITECTURE §4 rule 2; `editor_artefacts.rs`, `artefacts_cli.rs`); the scanner also reads NUL-separated text. Editor artifacts of isolated files are ordinary public files. Vim's swap file of an isolated `id_ed25519` or `server.pem` (`.id_ed25519.swp`, `.server.pem.swp`) is recorded by the next `vl` command (every command snapshots) and pushed to every remote, public mirrors included, with the private key in plaintext. The scanner does not catch it: the PEM header sits in binary data, where a newline and key material must follow it, and Vim ends lines with NUL. Emacs's default backup `.env~` (Vim with `backup`) carries `.env`'s values out the same way; `.env~` matches neither `.env` nor `.env.*`, and the scanner misses typical `.env` values (`APP_KEY`, `RAILS_MASTER_KEY`, see BUG-092). Any user-isolated file (`notes/private.md` → `.private.md.swp`) leaks with no scanner rule at all. Git users are protected by `git add`; Veil records the swap file whenever any `vl` command (the user's, or an agent's) runs while the editor is open. | `policy.rs:60` (`BUILTIN_SECRETS`): no rule for editor swap and backup files of isolated paths (`.<name>.swp`, `.<name>.sw?`, `<name>~`, `#<name>#`), and isolation is per path, not per content. `secrets.rs:348` (`pem_body_follows`) and `secrets.rs:465` (`Check::PemHeader`): in binary data the header must be followed by `\n`; NUL-separated lines (and the NUL-stripped pass, `secrets.rs:552`, which glues them) never qualify. | `adversarial5_visibility`: `a_swap_file_of_an_isolated_key_is_not_recorded`, `an_editor_backup_of_dotenv_is_not_recorded` (control: `the_key_and_its_text_backups_stay_local`) |
| BUG-096 | medium (**fixed**, durability/lock wave) | durability / crash recovery | A crash recovery that fails hands the next holder a recovery window that skips the original dead holder's objects. A's barrier fails (EIO) and its voided objects cannot be removed, so A leaves the lock flagged `"recover": true` (the documented path). B takes over; its recovery fails on the first rewrite (disk full), so B abandons the lock in turn, but with **B's own** `since_stamp`. C's recovery then only looks at files modified after B took over and never rewrites A's remaining objects, which still read back intact from the page cache. C's retried snapshot reuses them, its barrier succeeds, the commit is acknowledged, and after the next power loss the head operation references corrupt blobs (`fsck`: "content does not match its hash", 15 objects in the test). On disk the window has a five-minute margin, which a retry after freeing space easily exceeds. | `lock.rs:712–714` (`acquire_in`): `recover_interrupted_writes` fails → `lock.abandon()`. `lock.rs:857` (`Drop`) writes the flagged lock with `self.extra`, whose `since` was set to the new holder's own acquisition stamp in `held()` (`lock.rs:744`), instead of carrying over the window it was recovering (`recovery_window`, `lock.rs:587`). | `adversarial5_durability`: `a_failed_recovery_does_not_narrow_the_next_recovery_window` (control: `a_successful_recovery_makes_the_retry_durable`) |
| BUG-090 | medium (**fixed**, scanner v4) | scanner / availability | **Fixed** (scanner v4): scanning is linear in the input size. Repetitions that could hold another match are bounded, so each search reads at most ~1 KiB past its match; work redone after a restart inside a rejected match is counted, and past 16× the input the search ends with a `scan-limit` finding (the file is quarantined). Crafted inputs: 24+ MiB/s in a release build (1 MiB of `xsk-` was about an hour). Originally: The scanner takes quadratic time on crafted input. 64 KiB of `xgithub_pat_` repeated takes ~5 s in a release build, `xsk-` ~14 s; 256 KiB takes minutes, 1 MiB about an hour. Every snapshot (`vl status`, `vl commit`, any command) and `vl scan` in CI stall on one such public file. It is remotely triggerable: files a Git commit adds are scanned on import, so anyone who can push a branch to the team's GitHub repository stalls `vl git fetch` / `vl git pull` for every member, holding the repository lock throughout (128 KiB: still running after 30 s in the test). | `secrets.rs:447` and `secrets.rs:455` (`search_with`): a match rejected for the byte before it (`Edge::Alnum`) or for its key (`credential_key`) restarts the search at `whole.start() + 1`. The unbounded token patterns (`github_pat_[A-Za-z0-9_]{60,}`, `sk-…{32,}`, `glpat-…{20,}`) and the unquoted assignment value (`secrets.rs:206`, class includes `=`) can contain their own prefix, so each repetition yields one rejected match as long as the rest of the run, and its capture groups are computed every time (`secrets.rs:443`). The token pass is not chunked. | `adversarial5_scanner`: `crafted_token_runs_do_not_make_the_scanner_quadratic` (control: `ordinary_text_scans_quickly`); `adversarial5_cli`: `fetching_a_branch_with_a_crafted_fixture_is_quick` (control: `fetching_a_branch_with_an_ordinary_fixture_is_quick`) |
| BUG-091 | medium (**fixed**, scanner v4) | scanner | **Fixed** (scanner v4): references count only as whole values or closed templates with a name made of words; quoted values take escaped quotes and YAML `''`; the rest of a configuration line is the value (`.properties`); long words are judged by letter-pair frequencies; the entropy bar depends on length and alphabet; Google app passwords are found with and without spaces. Measured over 20,000 passwords per cell, 16+ characters: ≤ 0.04 % missed (alphanumeric, `A-Za-z0-9!@#$%^&*`, printable ASCII, lower-case), 0 % at 24+ except lower-case (0.05 %). Originally: Strong random passwords are missed often. Measured with 2,000 generated passwords per cell in dotenv, YAML, JSON and `.properties` files (escaped as each format requires): passwords from `A-Za-z0-9!@#$%^&*` (a password manager with symbols on) are missed 6–8 % of the time in every format; passwords from all printable ASCII ~28 % in dotenv/YAML/JSON and ~90 % in `.properties`. Even 16 random alphanumerics are missed ~0.6 % of the time, and a Google app password (16 random lower-case letters) always. These are not the documented "weak passwords" or "word-only passphrases". | `secrets.rs:280` (`plausible_value`): any value starting with `$ % & * @ < {` or containing `${`, `{{`, `#{`, `%(` is taken for a reference. `secrets.rs:206`: the quoted value class `[!#-&(-~\x80-\xff]` excludes `"`, `'` and space, so a (correctly escaped) quote inside the password prevents any match; the unquoted class excludes `,;()[]{}<>'"\` and backquote and must be followed by a terminator. `secrets.rs:259` (`wordlike`): a mixed-case run with no two capitals in a row, or any all-lower-case run, counts as a word whatever its entropy. | `adversarial5_scanner`: `strong_random_passwords_are_found` (control: `long_random_alphanumeric_passwords_are_found`) |
| BUG-092 | medium (**fixed**, scanner v4) | scanner | **Fixed** (scanner v4): all 17 shapes are found (comma and `]` after a quoted key, Kubernetes `value:`, plural/numbered keys, six suffix words, element attributes and CDATA, plist, SQL, `*_KEY`/`*_SALT` names), plus `key="…" value="…"` attributes. Originally: Common credential shapes are never matched (17 of 17 in the test): WordPress `wp-config.php` (`define( 'DB_PASSWORD', '…' )`, and its eight `AUTH_KEY`/`…_SALT` secrets), `os.environ["API_KEY"] = "…"`, `config['password'] = '…'`, `ENV.fetch('SECRET_KEY', '…')`, `System.setProperty("db.password", "…")`, Kubernetes `- name: DB_PASSWORD` / `value: "…"`, numbered and plural keys (`PASSWORD2=`, `API_KEYS=`), four suffix words (`DB_PASSWORD_PROD_EU_WEST_1`), XML elements with an attribute or CDATA (`<password type="plain">…`), plist `<key>Password</key><string>…`, SQL `WITH PASSWORD '…'`, and `*_KEY` names (`APP_KEY` of Laravel, `RAILS_MASTER_KEY`, `ENCRYPTION_KEY`). | `secrets.rs:206`: the separator (`=`, `:`, `:=`, `=>`, `>`) must follow the keyword, at most one quote and up to three suffix words directly; a quote plus `,` / `]` / `)` between key and value, a digit or `s` after the keyword, or attributes in the element, never match. `secrets.rs:113` (`KEYWORDS`): `key` only counts as `api_key`, `secret_key`, `private_key`. | `adversarial5_scanner`: `common_credential_shapes_are_found` (control: `documented_assignment_shapes_are_found`) |
| BUG-093 | low (**fixed**, scanner v4) | scanner | **Fixed** (scanner v4): percent-decoded, `:` allowed in the password, `:\/\/` matched, user names up to 128 characters. Originally: URL passwords are missed when the first character is percent-encoded (`postgres://app:%21Xk9mQ2vL7@db`, as RFC 3986 requires for a leading `!`), in JSON that escapes `/` as `\/` (PHP's `json_encode` default: `postgres:\/\/app:…@db`), when the password contains `:` (`redis://:Xk9mQ2:vL7pR4wZ@cache`; userinfo may), and after a user name longer than 64 characters. | `secrets.rs:190`: the rule is anchored on the literal `://`, its password class excludes `:` and the user part is `{0,64}`. `secrets.rs:331` (`plausible_url_password`): a leading `%` is taken for a reference. | `adversarial5_scanner`: `url_password_variants_are_found` (control: `url_passwords_in_the_documented_form_are_found`) |
| BUG-094 | low (**fixed**, scanner v4) | scanner / UTF-16 | **Fixed** (scanner v4): where the NUL positions show UTF-16/32 (either byte order), a non-ASCII character next to ASCII text becomes a space in the stripped view. Originally: In UTF-16LE (and UTF-32), a token directly after kana or about half the CJK ideographs is missed. CJK text puts no space before a Latin token (`令牌ghp_…`, `アクセスキーAKIA…`), and Windows tools write UTF-16LE (Notepad "Unicode", Excel "Unicode text", PowerShell 5 redirection). The same text in UTF-8, or with a space, is found. | `secrets.rs:552–554`: the NUL-padded pass deletes NUL bytes instead of decoding, so the non-NUL byte of the preceding code unit (its high byte in UTF-16LE: `0`–`9` for U+30xx–39xx, `N`–`Z` / `a`–`z` for U+4Exx–5Axx / U+61xx–7Axx) becomes the token's "ASCII" neighbour, and the boundary check (`Edge::Alnum`, `Edge::UpperDigit`) rejects the token. | `adversarial5_scanner`: `cjk_text_glued_to_a_token_in_utf16_is_found` (control: `cjk_text_before_a_token_is_found_in_utf8_and_spaced_utf16`) |
| BUG-095 | low (**fixed**, scanner v4) | scanner | **Fixed** (scanner v4): in binary data an escaped `\n` before key material counts, so the key is found in a `.tar` or stored `.zip` (scanned as their bytes are). Compressed archives are not decompressed (documented limit). Originally: A Google Cloud service-account key (JSON with `"private_key": "-----BEGIN PRIVATE KEY-----\n…"`) is found as a file but missed inside an uncompressed archive (`.tar`: the header's NUL padding comes right before the content), and likewise in a SQLite database or core dump. | `secrets.rs:465` (`Check::PemHeader`): with NUL bytes within 256 bytes, the header must be followed by a real newline and key material (`pem_body_follows`, `secrets.rs:348`); JSON has the two characters `\n`. The assignment rule cannot match the value either (it contains spaces). | `adversarial5_scanner`: `a_service_account_key_inside_a_tar_is_found` (control: `a_service_account_key_file_is_found`) |
| BUG-097 | low (**fixed**, durability/lock wave) | locks | A `vl` killed with `kill -9` (or crashed) whose parent has not reaped it yet is a zombie, and keeps the repository locked for as long as the parent lives: the expired lock is judged "still running but no longer renews its lease" and never taken over, contrary to the instant recovery ARCHITECTURE §9 promises for `kill -9`. Parents that do this: an IDE, an agent harness or a script that killed a hung `vl` and has not waited for it. | `lock.rs:1388–1391` (`process_alive`): `/proc/<pid>` existence counts zombies as running (documented as intended); `pid_reused` sees the same start time, and `assess_full` returns `Verdict::Stuck`. The state field (`Z`) of `/proc/<pid>/stat` is never read. | `adversarial5_durability`: `a_killed_but_unreaped_holder_is_taken_over` (control: `a_killed_and_reaped_holder_is_taken_over`) |

## Round 5 hypotheses (not demonstrated)

* **Locks under `hidepid=2` / `ProtectProc=invisible`.** `process_alive` (`lock.rs:1391`) only checks that `/proc/<pid>` exists. When `/proc` hides other users' processes (`mount -o hidepid=2`, systemd's `ProtectProc=invisible` for a service such as a CI runner), a live holder that belongs to another user on the same machine (a shared team remote on local disk, a service and a user on one repository) looks dead, and its lock is taken over at once: two writers, a lost operation (the BUG-013 class). The same happens when `/proc` belongs to another pid namespace than the processes (`unshare -p` without `--mount-proc`), where `/proc/<pid>` names a different process. Not tested: needs root or user namespaces, neither available here. **Settled (durability/lock wave): it was real, and is fixed.** A missing `/proc/<pid>` is no longer proof of death: `kill(pid, 0)` decides (`EPERM`: another user's live process), and `/proc` is only read when `/proc/self` names our own pid (else it belongs to another pid namespace, and neither its entries nor its start times are used). Tested by injecting what such a `/proc` shows through `LockContext::probe` (`veil-core/tests/lock.rs`: `a_holder_hidden_by_hidepid_is_not_taken_over`, `a_foreign_proc_falls_back_to_kill`, `liveness_needs_proof_of_death`); a real `hidepid` mount or pid namespace is still not exercised.
* **Stale local edits after a release revert the fix.** A non-holder's edit of a file shown as its embargo fallback (or an untracked file at a path the fix adds) is kept at fill-in and recorded on top of the released fix, so the next commit silently drops the fix from that file. `materialise_cli::a_local_edit_over_an_embargo_fallback_survives_the_release` asserts exactly this as intended. The warning shown (`kept … local edit not in history, e.g. quarantined`) does not say the release changed the file underneath, and nothing asks for a merge.
* **Derived change ids at import.** `import.rs` ≈368 maps a Git commit to an existing snapshot whose change id is the commit's *derived* id when parents, author, time and description match, without comparing trees. Someone with push access to both the Veil remote and the Git remote can create, in advance, a snapshot with the derived id of a commit they will push to Git, so that Veil and GitHub show different content for the "same" commit (a review bypass). Not tested.
* **Redaction edge cases.** `secret_of` (`git/transport.rs`) ends the authority at the first `/`, `?` or `#`, so a password containing one of them unencoded is printed in full by Veil's own messages (`Added Git remote …`, `remote list`, fetch errors); `git` rejects such URLs, so they never work. For `http(s)` only the whole `user:password` is replaced, so a server message that echoes the password alone would not be redacted. Credentials in the URL also reach `git`'s command line (`/proc/<pid>/cmdline`), as with plain `git`.
* **Assignment values longer than the chunk overlap.** A quoted value that starts within the last 16 KiB of a 256 KiB chunk and runs past the overlap cannot close inside the window, and the next chunk never sees the keyword. Needs a value over 16 KiB; not tested.
* **SFTP slow drip.** A server that answers each request just before the 300 s timeout keeps an operation alive for up to (requests × 300 s): each reply to an earlier request extends the later ones, and there is no overall deadline. A request that is never answered still fails after at most (earlier outstanding requests + 1) × 300 s, so it cannot be kept alive forever. Consistent with the documented design.

## Round 5 coverage notes

* **Scanner v3** (`adversarial5_scanner`, 13 tests): property-style generation of random passwords in four file formats (miss rates above), about 130 hand-made shapes (keywords, suffix exclusions, URL forms, XML, PEM variants, UTF-16/32 with and without BOM, mixed scripts, odd offsets, chunk boundaries), and timing of crafted runs. **False positives**, measured on `~/.cargo/registry/src` (329 crates, 12,941 files, 155 MiB, scanned in about 1 s in release): 22 files flagged (0.17 %). 13 of them hold real test or documentation private keys (`pkcs8`, `ed25519` fixtures), which are correct hits; the other 9 (0.07 %) are genuine false positives: `windows-sys` constants such as `D3DVSD_TOKENTYPE` and `WSMAN_OPTION_USE_INTEARACTIVE_TOKEN`, an `X509RequestInheritOptions` type, and `gix-url` test URLs (`ssh://jörg:passwörd@…`). Rerun with `VEIL_FP_DIR=<dir> … scanner_false_positive_rate`.
* **Durability and locks** (`adversarial5_durability`): a simulated disk with Linux's EIO semantics, ENOSPC on rewrites and power loss, shared by several simulated processes; failed barrier → `"recover": true` lock → failed recovery → retry → power loss; zombie and reaped holders. Reviewed without a finding: the store's discard-or-abandon path, the takeover guard and its nested `lock.steal.<hash>` sub-guards (each dead guard has one winner; a leftover sub-guard is cleaned by the next contender), fencing renewals and the 165 s skew rule (as documented), pack writes after a failed barrier (an index is only written after a successful one). `since_stamp` tampering by mtime alone is caught (recovery also requires an old `ctime`); a clock step of more than five minutes backwards is the documented margin.
* **Materialisation record:** `fill_in`, `absorb`, `holds`, the builder's `carry_unreadable` and the BUG-050 backstop, and the crash ordering in `Ctx::record`/`finish` were reviewed. A tampered or stale `checkout.json` cannot overwrite a local edit (fill-in always compares content), write outside the repository or into `.veil/` (paths are validated and reserved names refused), or keep a fallback across a release (fill-in materialises it first and drops it from the record). A `hidden` entry does make the builder carry a readable file that is absent, but fill-in removes every readable hidden entry first. No new bug beyond the hypothesis above.
* **Git bridge:** export recognition and publication commits are matched by exact commit id, so forged `change-id` headers and spoofed publication commits are imported as ordinary changes; per-branch failure isolation holds (gix errors are not fatal); `protocol.ext`/`fd` and hooks are disabled. Redaction was checked against git 2.53's own messages (git strips credentials itself). The map is device-local, so veil-set tampering needs local write access. BUG-090 is reachable through `vl git fetch`.
* **SFTP client:** reviewed the per-request timeout rule, the packet, listing, depth and stray-reply limits, and the writer thread. No new finding (see the slow-drip hypothesis).
* **Not covered this round:** a real clock step on a DiskBackend; `hidepid`/pid-namespace setups (no root); an SFTP server test harness for the timeout rule (reviewed only); concurrent fill-in against a live editor; macOS.

---

# Round 6 findings (Fable)

Found by the sixth adversarial pass against `integration` @ `b0f5544`,
with fresh eyes on the engine's visibility rules under hostile tree
metadata, the working-copy and workspace commands of the user guide
(undo, switch, restore, checkout), the policy file as a file, embargo
records, and `ws exec --with-isolated`. Each reproduction is an
`#[ignore = "BUG-NNN: …"]` test in `crates/*/tests/adversarial6_*.rs`;
`cargo test -p veil-core -p vl --test 'adversarial6_*' -- --ignored` runs
them (every one fails; the controls next to them pass). Line numbers refer
to `b0f5544`.

| Severity | Count | IDs |
|---|---|---|
| high | 6 | 099, 101, 103, 106, 109, 110 |
| medium | 10 | 100, 104, 105, 108, 111, 113, 116, 117, 119, 120 |
| low | 6 | 102, 107, 112, 114, 115, 118 |

| ID | Sev. | Area | Finding | Root cause | Reproducing tests |
|---|---|---|---|---|---|
| BUG-103 | high (**fixed**) | builder / hostile remote | **Fixed:** visibility labels and the snapshot `cloak` field are claims: the audience of new content comes from the accepted policy, a cloak that names a scope, and the parent entry's sealing as verified against its object's envelope label; a mismatch warns (`BuildReport::relabelled`) and is decided on the object; released embargoes, key generations and `local` never seal new content. Same rule in merges/rebases, normalisation and declassification, embargo wrapping, squash, descriptions and the Git import (ARCHITECTURE §4 rule 5, threat model; `hostile_labels_props.rs`). Originally: A tree entry's visibility label from a remote is trusted. Mallory (write access to the team remote, not in `team`) pushes `main` forward with Alice's tree, except that the entry of a cloaked file (`secrets/db.yml`) says `cloaked:embargo/<id>` for an embargo Mallory created under a scope of her own and released, or `cloaked:mal` for a scope she granted Alice into. The sealed object is Alice's (opened through its own label), so after `vl pull` + `vl new main`/`vl rebase -d main` (the guide's post-pull step) her working copy shows the right content and nothing warns. Her next edit of the file is sealed under the embargo key, which is public: the public mirror accepts the object as "released" and an anonymous reader decrypts her new secret. With `cloaked:mal`, her edit is re-keyed to Mallory's scope (BUG-009 by another route; `vl merge` refuses it, `vl new`/`rebase` do not). The same relabelling freezes any public file for everyone (edits held back for "no key for scope 'mal'"). | `builder.rs:777–791` (`file_entry`, "sealed content keeps its audience"): the *parent entry's* `visibility` decides the audience of the new content, without checking that the sealed object's envelope label matches it, and without refusing `embargo/…` labels, which the policy parser refuses (BUG-008). `keychain.rs:1663–1666` (`embargo_key`): a released embargo's key is handed to everyone, so `sealing_key("embargo/<released>")` seals new content under a public key. `vl fsck` does warn about the relabelled entry ("entry says sealed under 'embargo/…' but object … is sealed under 'team'"); pull, checkout, `vl files` and the builder do not. | `adversarial6_visibility`: `a_relabelled_entry_cannot_seal_the_victims_edit_under_a_public_key`, `a_relabelled_entry_cannot_rekey_the_victims_edit_to_an_attacker_scope`, `a_hostile_cloak_field_cannot_seal_the_victims_work_under_a_public_key` (the snapshot's `cloak` field naming a released embargo seals every new file and message under the public key) |
| BUG-106 | high (**fixed**, policy wave) | policy file / declassification | **Fixed:** A symlinked `.veilpolicy` is now followed (to a regular file ≤ 1 MiB named `*veilpolicy*`, FIFOs refused, non-blocking open) but never taken as the member's edit; a missing one is not an edit either; both stay guarded by the pin (`policy::read_policy_file`, ARCHITECTURE §4). `vl cloak` & co. refuse to write over the link; `vl policy accept` reads through it. When `.veilpolicy` is a symlink (a dotfiles manager, `stow`, `chezmoi`, `cp -s`, a monorepo pointing it at a shared file), `DiskBackend` reports nothing at it, `Policy::load` finds no policy, and every user rule stops applying. The "deleted" policy counts as the member's own edit, the accepted policy follows it, and because the policy changed the builder lifts "sealed content keeps its audience": the next snapshot re-stores every cloaked file **in plaintext** (`secrets/db.yml`: `cloaked:team` → `public`), new secrets are quarantined instead of cloaked, and the next push sends the plaintext to the public mirror. The only message, `.veilpolicy is tracked but is now a symlink …; Veil never follows it and keeps the recorded version`, says the opposite of what happens (the recorded *entry* is kept, the rules are not). | `vfs/disk.rs:586` (`metadata`: nothing at a symlink) with `policy.rs:495` (`Policy::load`: `None` → built-in only); `wc_policy.rs:46–57` (`snapshot_policy`: the member's "edit" is folded); `builder.rs:788` (`reclassified` lifts the audience rule). | `adversarial6_cli`: `a_symlinked_policy_file_still_applies` |
| BUG-109 | high (**fixed**, embargo wave) | undo / embargo | **Fixed:** `vl embargo release` previews what becomes public (merge, withheld history, tags, remotes) and asks (`--yes` skips; required off a terminal). The release is *staged* in device-local state (`.veil/local/releases/`, read by no sync, honoured only by the identity that signed it) and written into the synced record only by the next push or Git export (`Keychain::publish_staged_releases`). Until then `vl undo` deletes it ("Embargo … is unreleased again: its key had not left this repository"); afterwards undo is refused and changes nothing, and so is undoing the undo of a release. `vl op restore` takes back staged releases made after the target and warns about published ones. Was: `vl embargo release` records an operation, so `vl undo` prints `Undid: release embargo <id>`. The release lives in the embargo record (the published key), not in the view the operation log restores, so nothing is undone: `vl embargo list` still says `released`, and the next `vl push mirror` publishes the security fix. The guide promises "Undo anything" and lists every repository-changing command as an operation; this one is the one whose accidental use publishes a vulnerability. | `commands.rs:550` (`release_embargo`): `keys().release_embargo(id)` writes the record, then an op with `record_always` and an unchanged view; `Repo::undo_keeping_edits` only reinstates a view. | `adversarial6_cli`: `undo_of_an_embargo_release_keeps_the_fix_embargoed` |
| BUG-101 | high (**fixed**, policy wave) | policy pin | **Fixed:** `vl restore` that writes `.veilpolicy` snapshots with `SnapshotOptions::policy_incoming`, so the restored policy is guarded like a pulled one. Every other route is covered by `policy_routes_cli.rs`. `vl restore --from REV` writes REV's files into the working copy, `.veilpolicy` included, then snapshots as its own operation. The snapshot compares `.veilpolicy` with the tree the directory was checked out from, so a policy that arrived by `restore --from` counts as **the member's own edit** and is folded into the accepted policy at once: a teammate's `.env public!` applies without `vl policy accept`, `.env` is recorded in plaintext (`A .env`, `public 27 .env`), and the next commit and push publish it. The guide names merge, pull, checkout, rebase, Git import and undo as the guarded routes; `restore --from` is a seventh. | `main.rs:873–923` (`cmd_restore`: `ctx.fs.write` of every differing path, then `snapshot_as`); `wc_policy.rs:46` (`snapshot_policy(fs, Some(&wc.tree))`: any difference from the checked-out tree is the member's edit, `policy::fold_edit`). | `adversarial6_cli`: `restore_from_a_revision_does_not_accept_its_policy` (control: `a_pulled_policy_is_held_back_after_a_rebase`) |
| BUG-099 | high (**fixed**) | isolation / `ws exec --with-isolated` | **Fixed:** binary injected files (and the DER of PEM blocks) contribute their whole content plus distinctive 32-byte windows of the raw bytes, base64 and hex, matched by a bounded rolling hash (ARCHITECTURE §4; `injected_binary.rs`, with `openssl`-generated keystores). Originally: The injected-secret guard derives its needles from `String::from_utf8_lossy` of each injected file and drops every candidate containing U+FFFD, so a **binary** isolated file yields no needle at all. `*.p12`, `*.pfx`, `*.jks`, `*.keystore` (built-in secrets) and DER keys are binary: `vl ws exec agent --with-isolated -- sh -c 'cp server.p12 dist/bundle.bin'` records the keystore in the workspace (`public 300 dist/bundle.bin`), the scanner finds nothing in it (no PEM header, no assignment), and the next push ships it to every remote. ARCHITECTURE §4: "Any new or changed file, of any tier, that contains one of the injected values is quarantined". | `builder.rs:133` (`InjectedSecrets::from_files`: lossy text) and `builder.rs:195–196` (`secret_like`: `v.contains('\u{fffd}')` → not a needle); no raw-bytes needle. | `adversarial6_visibility`: `an_injected_binary_secret_is_recognised_in_a_copy`, `a_copy_of_an_injected_keystore_is_quarantined`; `adversarial6_cli`: `a_copied_keystore_is_quarantined_in_the_sandbox` (controls: `an_injected_text_secret_is_recognised_in_a_copy`, `a_copied_text_secret_is_quarantined_in_the_sandbox`) |
| BUG-110 | high (**fixed**, working-copy wave) | checkout / data loss | Checkout never overwrites a *file* it did not write, but when the target tree has a file where the working copy has a directory it runs `remove_dir_all` on that directory without looking inside. An isolated directory (`private/ isolate`) or an ignored one (`target/`, `node_modules/`) holds content that is in no snapshot, and the file entry `private` does not match the directory rule `private/`, so `is_local_only` does not protect it. One `vl new <rev>` (a teammate's change, or a hostile remote's tree with a file named `node_modules`) deletes the user's private notes and the build tree; the next snapshot prunes the vault's backup of the notes because they no longer exist. Unrecoverable. | `checkout.rs:533` (`apply_changes`: `if current is Dir { fs.remove_dir_all(&c.path)? }`), with `is_local_only` evaluated for the file path only. | `adversarial6_cli`: `checkout_does_not_delete_a_local_only_directory_to_place_a_file` |
| BUG-113 | medium (**fixed**, working-copy wave) | workspaces / crash safety | `vl ws switch` changes nothing in the repository; the attachment lives only in `.veil/local/checkout.json`, written **after** the checkout that replaces the directory's files. If that checkout fails half way (BUG-111; a `kill -9` or a full disk at that point leaves the same state), the directory holds a mix of both workspaces but is still attached to `default`, nothing is stale (same workspace, same snapshot), and the next command records the mix as `default`'s working copy: `agent`'s files appear as additions and `default`'s own files, already removed by the checkout, are recorded as deleted (`default.txt` gone from disk and from `@`; only the evolution log has it). `vl new`/`vl edit` survive the same crash (the view moved, the directory is stale, its state is saved as a change); `ws switch` does not. | `main.rs:1620` (`WsCmd::Switch` → `Ctx::attach`, no operation, no marker); `ctx.rs:342` (`finish`: `save_checkout` only after `checkout_tree_recorded`); `ctx.rs` `record`: `stale` is false when the workspace name and snapshot are unchanged. | `adversarial6_cli`: `an_interrupted_workspace_switch_does_not_corrupt_the_old_workspace` |
| BUG-108 | medium (**fixed**, embargo wave) | embargo / revocation | **Fixed:** a release counts only if it is signed by a **current** member of the scope with the signing key the ring registers (or the record's good-signed deadline has passed), judged on every lookup wherever a verified signed ring for the scope is held (`Keychain::release_rejection`); `merge_embargo` drops an unaccepted release with a warning and lets an accepted one replace it; `release_embargo`/`stage_release` refuse a non-member. Out-of-band leaking of the key a revoked member holds is not preventable and is documented (ARCHITECTURE §7, threat model; CRYPTO C7). Was: Bob was in `team` when the embargo was created, so he holds the embargo key. Alice revokes him; revocation is forward-only, so he keeps reading the fix (documented). He can also **release** it: `release_embargo` needs only the key, and `merge_embargo` accepts any valid release signature by anyone as long as the published key matches the fingerprint. Bob pushes the released record to the team remote (any writer can; `vl push` with nothing to push still syncs records); on her next pull Alice's replica treats the embargo as released, and her next `vl push mirror` publishes the fix. The guide: "nobody can force a key holder to release". | `keychain.rs:1797` (`merge_embargo`: the release signature is only checked for validity, not against membership at any point of the log) and `keychain.rs:1845` (the release fields are copied); `release_embargo` (`keychain.rs:1743`) checks the key only. | `adversarial6_visibility`: `a_revoked_member_cannot_release_an_embargo` |
| BUG-104 | medium (**fixed**, embargo wave) | embargo metadata | **Fixed:** `seal_dir` lists only new ciphertext (sealed trees, files sealed under the embargo key); fallbacks are reached through the wrapper's fallback tree and are not listed, and scope-sealed ids are listed only if the public view does not hold them. Same encoding, so no format change (older readers keep fallbacks through the fallback tree). The number of listed objects stays visible (documented). Was: An embargo wrapper lists, in plaintext, the objects "reachable only through the sealed side"; `seal_dir` also lists each sealed file's **fallback**, the id of the pre-merge version of every file the fix changed. Those ids are public (every outsider holds the pre-merge tree), so an anonymous reader of the public mirror maps them back to paths (`auth/jwt.rs`) and learns which files the fix touches. The threat model says the set of changed files is hidden; BUG-018's test only compared the listing seen through `ObjectStore::tree`, which resolves the wrapper to its fallback. | `embargo.rs:313–315` (`seal_dir`: `listed.insert(ne.id); if let Some(fb) = ne.fallback { listed.insert(fb) }`): fallbacks are reachable through the fallback tree and need no listing for gc or transfer. | `adversarial6_visibility`: `the_wrapper_does_not_reveal_which_files_the_fix_changed` |
| BUG-105 | medium (**fixed**, lock/remote wave) | revsets / hostile team remote | **Fixed:** `vl pull` no longer creates a local tag whose name is a change-id or snapshot-id prefix of local history or of what the pull brings in (warning; `origin/<name>` still names it), the same rule as `vl git pull` (`revset::RevisionNames`, shared). A divergent change id resolves to its one snapshot in local history (reachable from this repository's heads or working copies) when the others are only reachable through tags, so a pushed snapshot carrying someone else's change id no longer makes it divergent (ARCHITECTURE §8). Tags are still resolved before change ids (tags carry no provenance; existing tags named after a change were created by the user or an older `vl`). Originally: `vl git pull` refuses to create a local tag whose name is a change-id prefix (BUG-059); `vl pull` from a Veil remote records any name `validate_tag_name` accepts, and tags win over change ids. Alice's change ids are visible on the team remote, so Mallory tags her own snapshot with the 8-letter prefix `vl log` shows for Alice's change; after `vl pull`, Alice's `vl edit <prefix>` (or `vl new`, `vl squash -r`, `vl rebase -s`) lands on Mallory's snapshot. Likewise a pushed snapshot carrying Alice's full change id makes her own id "divergent" in every revset (the Git bridge guards that too; `vl pull` does not). | `remote.rs:1268` (`pull_with`: every remote tag becomes a local tag); `revset.rs:48` (tags before change ids) and `revset.rs:79` (divergence counts remote-tag snapshots). | `adversarial6_cli`: `a_pulled_tag_named_after_a_change_id_does_not_hijack_the_change`; `adversarial6_visibility`: `a_pulled_snapshot_with_a_forged_change_id_does_not_make_the_change_divergent` |
| BUG-116 | medium (**fixed**, working-copy wave) | undo / messages | "Every command that changes the repository is an operation in the operation log" (guide). `vl scope grant\|revoke\|rotate`, `vl remote add\|rm` and `vl secret set\|rm\|import` change the repository but record no operation, so `vl undo` right after one of them undoes the **previous** operation instead (`Undid: set tag main`; it could be the last commit or merge): the grant stays, the unrelated operation is gone, and a member who granted the wrong key, "undid" it and pushes, ships the ring with that key. The same one-line message is what BUG-109 shows for the one command that *is* an operation but whose effect undo cannot reach. | `main.rs` `cmd_scope`/`cmd_remote`/`cmd_secret`: metadata writes outside any transaction (`Keychain::grant_role`, `Repo::update_config`, `vault_update`); `Repo::undo_keeping_edits` undoes the newest operation whatever the last command was. | `adversarial6_cli`: `undo_after_a_scope_grant_does_not_undo_an_unrelated_operation` |
| BUG-117 | medium (**fixed**, working-copy wave) | `vl watch` / data loss | `vl watch` ("records continuously, as files change") keeps one `Ctx` for its whole life with the checkout pointer it read at start; each tick reloads the view, not `checkout.json`. When another `vl` command in the same directory moves the working copy (`vl commit`, `vl new`), the watcher's next tick finds the view's working copy different from its cached pointer, judges the directory *stale*, saves what the user wrote since as `recovered working-copy edits` on top of the obsolete snapshot it remembers (a branch off a predecessor that is no longer visible), and checks the directory out again, which removes those files from disk. The user's new file vanishes while they edit; it survives only in the stray change. | `main.rs` `cmd_watch` (loop: `ctx.repo.reload()`, `ctx.snapshot()`); `ctx.rs` `record`: `stale` is judged against `self.checkout`, loaded once in `Ctx::open` and never re-read. | `adversarial6_cli`: `watch_does_not_move_new_files_off_disk_after_a_concurrent_command` |
| BUG-119 | medium (**fixed**, lock/remote wave) | lock / hostile remote / DoS | **Fixed:** every way round `acquire_in`'s loop passes the deadline and the back-off, and a lock or takeover guard path that is a symlink (or other non-file; new `StorageBackend::special_at`, disk and SFTP) fails at once with `.veil/lock is a symlink, not a lock file; … remove .veil/lock` (ARCHITECTURE §9). Originally: `RepoLock::acquire_in` loops: `create_new` fails because the lock path exists, `read_opt` returns `None` because `DiskBackend` and `SftpBackend` report nothing at a symlink, and the loop `continue`s before the back-off sleep and the deadline check. A `.veil/lock` that is a symlink (dangling or not) spins every command at full CPU for ever with no error, locally (another user on a shared checkout, a restore that turned files into links) and on an SSH remote (one hostile or mangled file wedges every `vl push`/`vl pull` client; measured 25 s of CPU per 40 s, still running after 5 min), although ARCHITECTURE §1 says a hostile or broken server "can neither hang the client nor exhaust its memory". A plain unreadable lock file is reclaimed after a lease; a directory is refused at once. | `lock.rs:701–703` (`acquire_in`: `let Some(raw) = backend.read_opt(&path)? else { continue; }` runs before the `wait` check and the `sleep(backoff)` at the end of the loop). | `adversarial6_lock`: `a_symlinked_lock_file_does_not_spin_for_ever` (control: `a_garbage_lock_file_is_handled_within_the_wait`); `adversarial6_cli`: `a_push_to_a_remote_with_a_symlinked_lock_fails_instead_of_spinning` (skipped without `sftp-server`) |
| BUG-100 | medium (**fixed**, working-copy wave) | undo / data loss | "Both keep the files on disk that you had not recorded yet" (guide). `undo_keeping_edits` skips automatic snapshots of the *attached* workspace only; `vl ws switch` records no operation, so right after a switch the newest operation is the automatic snapshot of the workspace just left, and `vl undo` undoes *that*: `Undid: snapshot working copy of 'default'`, the edits made in `default` before switching vanish from its working copy, and the directory (now attached to `agent`) no longer holds them. They survive only in the op log (`vl op restore`). | `workspace.rs:437–443` (`last_command_op`: compares the description with `snapshot working copy of '<ws>'` for the current workspace only). | `adversarial6_cli`: `undo_after_a_workspace_switch_does_not_discard_the_previous_workspaces_edits` (control: `undo_after_a_commit_keeps_the_edits_made_since`) |
| BUG-111 | medium (**fixed**, working-copy wave) | checkout / availability | A *file* in the working copy (a quarantined `cfg`, never recorded; any untracked file) where the target tree has a directory `cfg/`: checkout writes `cfg/settings.json`, `DiskBackend::write` fails with `File exists` on the parent, the checkout aborts half way, and the error is returned after the view already moved. Every later command fails the same way (`vl status`, `vl log`: each finds the working copy stale and retries the same checkout). Only `vl --no-snapshot undo` or deleting the file by hand gets out. The documented behaviour for a file in the way is to keep it and report it (`CheckoutReport::blocked`/`kept_local`). | `checkout.rs:535` (`apply_changes`: `fs.write` with no check that the parent chain is made of directories; `SpecialGuard` only knows symlinks and special files). | `adversarial6_cli`: `a_file_in_the_way_of_a_directory_is_kept_and_reported` |
| BUG-107 | low (**fixed**, policy wave) | policy file / availability | **Fixed:** An unreadable `.veilpolicy`, a directory, or a dangling/looping link: the accepted policy applies with a warning; `vl policy accept` refuses. "Nothing in the working copy can fail a snapshot" (ARCHITECTURE §4): an unreadable file is reported and skipped. `.veilpolicy` is the exception: `Policy::load` runs before the build and propagates the I/O error, so with `chmod 000 .veilpolicy` (or a directory named `.veilpolicy`) every command fails, `vl ignore` and `vl status` included (BUG-038 for the policy file). | `policy.rs:495` (`Policy::load`: `fs.read_opt(&path)?`), called from `wc_policy.rs:46` before the builder. | `adversarial6_cli`: `an_unreadable_policy_file_does_not_brick_the_cli` |
| BUG-102 | low (**fixed**, working-copy wave) | messages | `vl ws write NAME PATH` prints `Recorded PATH in …` whatever the builder did with it: a path the policy isolates (`.env`, `*.pem`, a user rule; also `.veil/…`) is silently dropped with the overlay, and the message says it was recorded. The user, or the agent driving `vl`, believes the file is in the workspace; `vl ws cat` then says it does not exist. | `main.rs:1657` (`WsCmd::Write`: unconditional `Recorded`; `print_build_warnings` does not mention isolated paths). | `adversarial6_cli`: `ws_write_of_an_isolated_path_does_not_claim_it_was_recorded` |
| BUG-112 | low (**fixed**, lock/remote wave) | identity file | **Fixed:** `write_identity` writes a fresh temp file created with mode `0600` (`create_new`), syncs it and renames it over `identity.json`; a new `$VEIL_HOME` is created `0700`. Retired identities were already created `0600`. Originally: `ctx::write_identity` creates `identity.json` with `std::fs::write` (`openat(…, O_CREAT, 0666)`, so `0644` under the usual umask) and only then `chmod 0600`s it: the private keys are world-readable for a moment, on every first use and on `vl identity new`. The retired copy is created the right way (`create_new`, mode `0600`). Round-1 hypothesis "identity-file race", now demonstrated with `strace` (the test skips where `strace` is unavailable or cannot attach). | `ctx.rs:64` (`std::fs::write` then `set_permissions`). | `adversarial6_cli`: `the_identity_file_is_never_world_readable_even_briefly` |
| BUG-118 | low (**fixed**, lock/remote wave) | SSH remotes | **Fixed:** `host:~`, `host:~/path` (and `ssh://host/~/path`, as before) are home-relative; `~user` is refused in both forms with a message asking for the absolute path, instead of creating a directory named `~user`. Originally: Git, `scp` and `sftp` take `host:~/path` as the home directory. Veil's scp-style parsing hands the path to the SFTP server verbatim and OpenSSH's `sftp-server` does not expand `~`, so `vl push origin` with `fakehost:~/repo` creates a directory literally named `~` in the login directory and the repository under it. Push and pull keep working against that path (nothing is lost), but the repository is not where the admin looks for it or backs it up, and `ssh host ls '~/repo'` says it does not exist. `ssh://host/~/repo` is resolved. | `vfs/sftp_url.rs` `parse` (scp branch): only `ssh://…/~/` is special-cased (`parse_url`, line 121). | `adversarial6_cli`: `scp_style_tilde_paths_resolve_to_the_home_directory` (skipped without `sftp-server`) |
| BUG-114 | low (**fixed**, lock/remote wave) | docs | **Fixed:** the maintenance guide describes `vl doctor --remotes` contacting SSH remotes and checking their clock. Originally: The maintenance guide says "SSH remotes are not contacted by `doctor` in 1.0 (`not a local path; vl pull origin checks it`)". `vl doctor --remotes` connects to SSH remotes and compares their clock (`doctor.rs` `check_ssh_remote`, SFTP hardening wave; the README documents it). An admin debugging a remote lock or clock-skew problem is sent elsewhere. | `docs/guide/maintenance.md:111–112` (stale since the SFTP wave). | `adversarial6_docs`: `the_guide_does_not_say_doctor_skips_ssh_remotes` (control: `the_readme_documents_the_ssh_clock_check`) |
| BUG-115 | low (**fixed**, policy wave) | `vl scan` / CI | **Fixed:** New CI gate `vl scan --policy-from FILE` (the base branch's policy): no rule is taken from the checkout, every file counts as public except FILE's `public!` paths, no repository needed. The guide's recipe uses it; the test was adapted to the new recipe (also with `vl init`, and with `** public!`, `cloak`, `isolate`, `ignore` rules). The guide's CI recipe (`vl init` in the Git checkout, `vl --no-snapshot scan`; "this fails the job on a hit") takes its rules from the checkout it scans: `vl init` keeps the checked-out `.veilpolicy`, and `vl scan` skips `public!` and `ignore` paths. The pull request that adds the leaked key adds `leak.js public!` (or `** public!`) next to it, and the gate prints `ok: no secrets in public files`. There is no option to disregard `public!` or to take the policy from a trusted ref. | `main.rs` `cmd_scan` (`class.allow_secrets` → skip) with `cmd_init` keeping an existing `.veilpolicy`; by design for a working copy, not for a gate. | `adversarial6_cli`: `the_ci_scan_recipe_cannot_be_switched_off_by_the_scanned_policy` (control: `the_ci_scan_recipe_fails_on_a_leaked_key`) |
| BUG-120 | medium (**fixed**, lock/remote wave; found by the editor-artefacts wave) | sync / remote initialisation | **Fixed:** a push to an empty remote initialises it under the remote's lock and re-checks once the lock is held, so concurrent first pushes all succeed (one initialises, the others push normally); an error while checking whether the remote is a repository is an error, never a reason to initialise. `SftpBackend::create_new` also retries when the file it collided with is gone by the time it looks (a briefly held lock), instead of failing with `sftp: Failure`. Originally: `remote::push_with` checked whether the remote was a repository, then initialised it without a lock. When several pushes hit an empty remote at once, a loser whose check came just before the winner's `repo.json` failed with `AlreadyExists("a Veil repository")`; concurrent initialisations also overwrote each other's `repo.json` (different repository ids) and `op_head`, so a late one could reset the view after a winner's push. Seen as the occasional failure of `sftp_sync::concurrent_pushers_serialise_on_the_remote_lock` under load (listed under the round-6 hypotheses). | `remote.rs` `push_with` (`is_repo` then `Repo::init_bare`, no lock); `repo.rs` `is_repo` (`unwrap_or(false)`); `vfs/sftp.rs` `create_new` (`lstat` after a failed link treated a vanished file as an error). | `remote_init_race`: `concurrent_first_pushes_to_an_empty_remote_all_succeed` (fails on the old code in the first rounds); `sftp_sync`: `concurrent_pushers_serialise_on_the_remote_lock` |

## Round 6 fixes: working-copy wave

* **BUG-110, BUG-111:** checkout removes a directory in the way of a file only once it has emptied it, and keeps a file in the way of a directory; both are reported (`CheckoutReport::obstructed`, `kept X (…)`) and the rest of the checkout goes ahead. `prune_empty_parents` no longer deletes a directory holding only a symlink or a non-UTF-8 name. The vault keeps the backup of a vanished isolated file for 30 days (`vl secret files`, `vl secret recover`). Tests: `checkout_obstacles.rs`.
* **BUG-113:** moving the directory is journalled in `checkout.json` (`pending`) and finished by the next command (`working_copy.rs`); swept by `crash.rs` `crash_during_workspace_switch`.
* **BUG-117:** `vl watch` re-reads `checkout.json` every tick and yields while the directory is behind the view; every snapshot is checked against the working copy it was checked out from under the lock (`SnapshotOptions::expected_wc`).
* **BUG-100:** `vl ws switch` is an operation; `vl undo` right after it switches back. Property test: `workspace_undo_props.rs`.
* **BUG-116:** `vl scope create|grant|revoke|rotate`, `vl remote add|rm`, `vl secret set|rm|import` and `vl policy accept` record operations marked `manual_undo`; `vl undo` refuses them with instructions, `vl op restore` warns. `vl embargo release` (BUG-109) is left to the embargo wave, which can mark it the same way (`Transaction::manual_undo`).
* **BUG-102:** `vl ws write` fails, saying why, when the builder did not record the path.

## Round 6 hypotheses (not demonstrated)

* **Policy trust on first use.** A clone, or `vl init` in a Git checkout (the CI recipe), accepts the checked-out `.veilpolicy` as the device's accepted policy, `public!` rules included, and nothing at clone time lists them. A user who clones a hostile repository and then drops a `.env` into it has it recorded in plaintext (the `A .env` line of `vl status` is the only signal). Documented as "first use"; the same mechanism as BUG-115.
* **Legacy embargo records without `key_id`.** `release_consistent` accepts *any* published key for a record that has no `key_id` (format-1 records made before BUG-012's fix). A forged release of such a record would be accepted and lock key holders out of the content, as in BUG-012. The golden fixtures all carry `key_id`; not demonstrated against a real old record.
* **`Snapshot.embargo` naming an unknown embargo.** A snapshot from a remote whose `embargo` field names an id with no record counts as "unreleased and unknown" (`carried_embargo`), so no `--embargo` merge is possible on that line until it is rewritten, and its merged-in parents are withheld from every push. A hostile writer can thus disable embargoes on `main`; a legitimate record that failed to sync has the same effect. Reasoned from `commands.rs` `carried_embargo` and `remote.rs` `embargo_withheld`; not tested.
* **`vl ws exec` and a concurrent command.** Like `vl watch` (BUG-117), a long `ws exec` finishes with the checkout pointer it read at start. Its `finish` re-applies the diff between the stale pointer and the current working copy onto a directory the other command already updated; `holds` makes that benign (files already hold the target content), but edits the user made meanwhile at paths that differ between the two snapshots are reported as `kept` and the "Updated N files" line is wrong. Not demonstrated as data loss.
* **`vl op restore` to before the attached workspace existed** ends with `error: not found: workspace '<ws>'` after the restore is recorded; the next command attaches to another workspace and checks the directory out from the removed workspace's snapshot (recoverable, as the removed snapshot is in the op log). Cosmetic.
* **`VEIL_HOME=` (set but empty)** puts `identity.json` in the current directory (`PathBuf::from("")`); in a working copy the scanner quarantines it (the JSON holds 64-hex keys). `VEIL_FS_FOLDING=garbage` is silently ignored. Remote names are not validated (`vl remote add '' …`, `../evil`, `origin/main` all work; the last makes `origin/main` both a remote-tag key of `origin` and a remote name).
* **`sftp_sync::concurrent_pushers_serialise_on_the_remote_lock`** (since demonstrated and fixed as BUG-120) failed in both full-workspace runs (`unwrap` on a push error at `sftp_sync.rs:206`) and passed three times alone: flaky under load (five clients racing a fencing lock on a stand-in server), not a regression of this round.

## Round 6 coverage notes

* **Visibility rules under hostile metadata** (`adversarial6_visibility`): tree entries and snapshot fields (`visibility`, `cloak`, `change_id`) crafted by a team-remote writer and pulled by a member; what the builder, `vl new`, `vl rebase`, `vl edit` and a public push then do with them. `vl merge` was reviewed and holds (`normalize_tree` keeps the destination's audience). `vl fsck` reports the relabelled entry (`entry says sealed under … but object … is sealed under …`); nothing on the pull/checkout/edit path does.
* **Embargo records**: creation, release and merge rules against revoked members, non-members and public-mirror clones; the wrapper's plaintext `listed` set. Timed release and the `until` field were reviewed (signed, so tamper-proof) and not re-tested.
* **The user guide's workflows through the real binary** (`adversarial6_cli`): undo after `ws switch`, `ws rm`, `op restore`, scope/remote/secret commands and `embargo release`; `restore --from`; checkout over local-only directories and files in the way; interrupted `ws switch`; `vl watch` next to another command; `ws write`/`ws exec` messages; the policy file as a symlink, unreadable, a directory, cloaked by its own rule (stays public), and with pathological globs (fast); the CI scan recipe; odd revisions, tags, workspace and remote names (no panics); environment variables (`VEIL_FS_FOLDING`, `VEIL_SFTP_*`, `VEIL_USER`, empty `VEIL_HOME`) and broken state files (garbage lock, garbage identity, unreadable `VEIL_HOME`): clean errors except as listed.
* **Injected secrets** (`ws exec --with-isolated`): text, binary, UTF-16, `.netrc`/`.pgpass` shapes were reviewed; only the binary case fails (BUG-099). `.netrc` lines and other whitespace-separated formats yield only a whole-file needle, so transformed copies (`awk`, `grep`) of them are not caught; documented as "values that look like secrets".
* **Property tests** (`adversarial6_props`): the policy fold's own invariant over random accepted/parent/member policies and overlapping patterns (600 cases, no counterexample); never-panic fuzzing of `SshUrl::parse` (also: no option-like host or user reaches `ssh`), `parse_public_identity`, `parse_public_key`, `ChangeId`/`ObjectId` parsing, tag/workspace/scope name validation and `VPath`; byte-mutated signed rings (a mutated ring that still verifies derives the same state) and embargo records.
* **SSH remotes** through a fake `ssh` serving the local `sftp-server`: tilde paths, a hostile server's lock file (symlink: BUG-119; garbage: handled; directory: refused), `.veil/objects` replaced by a symlink to `/etc` (clean error), clone over it.
* **Locks** (`adversarial6_lock`): only the absent-but-existing lock path; the lock's takeover rules, fencing and recovery windows were left to the parallel fix wave for BUG-096/097.
* **Not covered this round:** the Git bridge beyond spot checks (a GitHub commit deleting `.veilpolicy` is refused; newlines in `VEIL_USER` are stripped by gix); `vl upgrade`; `gc` beyond cloaked-fallback reachability (kept) and the wrapper's listed set; the scanner (BUG-090…095 in progress elsewhere); macOS; concurrent processes beyond `vl watch`; the identity-file race itself (only the creation mode is shown).

## Findings from the round-6 fix wave (not yet reproduced)

Reported by the fix agents while working on round 6 (`integration` @
`a0c3d71`). They are inferred from the code and have no reproduction test
yet; the next fix wave writes one first.

| ID | Sev. | Area | Finding | Root cause | Reproducing tests |
|---|---|---|---|---|---|
| BUG-121 | medium | policy / hostile remote | A recorded *directory* named `.veilpolicy` (pushed by a hostile teammate) probably makes `Policy::load` on that tree fail during checkout or merge, blocking `vl new main` for everyone who pulls it. A member's own working copy never records one (an empty directory records the file as deleted). Found by the policy wave. | `Policy::load` on a tree expects a blob at `.veilpolicy`. | none yet |
| BUG-122 | medium | declassification / hostile remote | A merged-in line can declassify a teammate's genuine sealed objects: Mallory writes a snapshot with `cloak: "team"` whose tree puts Alice's real `cloaked:team` objects at new paths; when Alice merges that "team line" into a public line, those files are published (after a secret scan). Label verification (BUG-103) cannot stop it, because the labels are true. Found by the visibility wave. | Declassification on merge publishes every cloaked entry of the merged line, not only the content that line introduced. Limit it to introduced content, or to lines signed by scope members. | none yet |
| BUG-123 | medium | merge / audiences | When the two sides of a merge are sealed under different scopes, the result is sealed under ours' scope. If Mallory replaces a file's object with a genuinely `mal`-sealed one and Alice is a `mal` member, Alice's pending `team` edit is merged and resealed under `mal` on auto-rebase, moving her content to another audience. Should be a conflict when neither scope is narrower. Found by the visibility wave. | `merge_file` picks ours' audience whenever both sides are sealed. | none yet |
| BUG-124 | low | workspaces | `vl ws create --cloak embargo/<id>` is accepted, because it only checks `is_member` (true for any embargo whose key you hold). The builder and descriptions now ignore such a cloak (BUG-103), but the command should refuse non-scope names. Found by the visibility wave. | `create_workspace` does not call `validate_scope_name`. | none yet |

## Conformance findings: history, diff, merge and rewriting

Found by porting Git's t4xxx (diff, log), t6xxx (revision walking,
merging) and t34xx (rebase) scenarios, and jj's rebase, squash, abandon,
diff, log, evolog, revset and conflict tests, to Veil (`integration` @
`8dbdb61`). Each reproduction is an `#[ignore = "BUG-NNN: …"]` test in
`crates/vl/tests/conformance_history/`;
`cargo test -p vl --test conformance_history -- --ignored` runs them (every
one fails). The coverage map is `docs/conformance/history.md`. Line numbers
refer to `8dbdb61`.

| Severity | Count | IDs |
|---|---|---|
| high | 1 | 251 |
| medium | 4 | 243, 244, 247, 249 |
| low | 7 | 240, 241, 242, 245, 246, 248, 250 |

| ID | Sev. | Area | Finding | Root cause | Reproducing tests |
|---|---|---|---|---|---|
| BUG-251 | high | auto-rebase / merges | A merge whose first parent is rebased loses files that its *other* parent still has. `a ← b ← c`, `a ← side`, `m = merge(c, side)`; `vl rebase -s b -d nb` (where `nb` doesn't contain `a`) leaves `m` with parents `c'` and `side`, but `a` is gone from `m`'s tree, and from every descendant and the working copy on top of it. No conflict or warning. The natural merge of `c'` and `side` contains `a`, as jj and `git rebase --rebase-merges` keep it. The content is still in `side`'s history and in the op log. | `rebase_descendants` (`transaction.rs:234`) rebases a merge one parent at a time: `merge_trees(old parent tree, new parent tree, tree)` for each moved parent. That replays "`b`'s line lost `a`" onto the merge, without the other parents. It should rebase the merge onto the merge of its new parents against the merge of its old parents (as `parents_tree` computes). | `conformance_history::rewrite::rebase_carries_a_descendant_merge` (control: `rebase_carries_a_descendant_merge_with_disjoint_files`) |
| BUG-244 | medium | merge | A criss-cross merge picks one merge base and silently takes one side's earlier resolution. `left` and `right` change the same line (`B`/`C`). `R2 = merge(right, left)` is resolved as `B`, and `L2 = merge(left, right)` as `C`. `vl merge` of `R2` and `L2` produces `B` with no conflict, which drops `L2`'s resolution. Git (virtual merge base) and jj report a conflict. Which side wins depends on parent order. | `Repo::common_ancestor` (`repo.rs:466`) returns the first common ancestor a BFS meets, and `parents_tree` (`repo.rs:503`) merges against that single base. With two merge bases, that base equals one side's version, so the other side's resolution looks like the only change. | `conformance_history::merge::criss_cross_merge_with_different_resolutions_conflicts` (control: `criss_cross_merge_with_agreeing_resolutions_is_clean`) |
| BUG-243 | medium | merge / file-directory conflict | When one side replaces file `thing` with a directory `thing/inner.txt` and the other side edits `thing`, `vl merge` reports `conflicts in: thing`, but the result keeps only the file. `thing/inner.txt` is in neither the merged tree nor the working copy, and nothing (no marker, no renamed copy) shows that it existed. Once the user edits `thing`, the conflict clears and the directory side is gone from the line. Git keeps both (`thing~HEAD`); jj records a file/directory conflict. | `merge_dir` (`merge.rs:226`): "modify/delete or file/directory conflict: keep the surviving side (ours first) and flag it", i.e. `oe.or(te)`. For a file/directory clash both sides survive, and the other one is dropped. | `conformance_history::merge::file_directory_conflict_keeps_both_sides_content` (controls: `file_directory_conflict_is_flagged`, `directory_file_conflict_is_flagged`) |
| BUG-247 | medium | undo | The guide says "`vl undo` undoes the last operation. Run it again to go further back." The second `vl undo` instead undoes the first undo, re-applying the operation the user just took back (`Undid: undo: describe change …`). Two undos after two rewrites leave the repository after the *second* rewrite, not before the first. Recoverable with `vl op restore`, but surprising when cleaning up a botched rebase. **Update (`a0c3d71`):** the guide now says a second undo is a redo, so the docs match the code; the fix still to make is the jj-style design (repeated `vl undo` goes further back, plus a `vl redo`). | `undo_keeping_edits` (`workspace.rs:413`) restores the parent of the newest non-snapshot operation. After an undo, that operation is the undo itself, whose parent is the state it undid. Nothing skips earlier undos (jj's `undo` tracks what was already undone). Either implement "further back" or document undo-as-toggle. | `conformance_history::rewrite::repeated_undo_walks_back_through_rewrites` (control: `op_restore_walks_back_several_rewrites`) |
| BUG-249 | medium | embargo / encryption at rest | `vl merge fix@ --into main --embargo`, with the fix developed in a cloaked workspace as the guide says, writes the merged file's **plaintext** to `.veil/objects` as a public blob. Nothing references it (`vl fsck` reports "2 unreachable object(s) … harmless"), so it is not pushed, but it stays on disk until `vl gc` prunes it after the grace period. Before the merge, the fix existed only sealed (control test). Copies of `.veil` (backups, a synced folder, a disk image) then hold the embargoed fix unencrypted. | `Repo::merge` (`commands.rs:417`): `normalize_tree` declassifies the cloaked line's files (the "published from the cloaked line" step) and stores them as public blobs. `apply_embargo` (`commands.rs:452`) then seals them, which leaves the public blobs written but unused. For an embargoed merge, the declassified content should be sealed under the embargo key directly. | `conformance_history::veil_angles::embargoed_merge_stores_no_plaintext_of_the_fix` (controls: `cloaked_fix_line_is_encrypted_at_rest_before_the_merge`, `embargo_fixture_hides_the_fix_from_outsiders`) |
| BUG-240 | low | merge / graph invariants | `vl merge main --into main` and `vl new X X` (with work in progress in `@`) record a snapshot whose parent list holds the same snapshot twice. `vl show` lists `Parent :` twice (Git export with such a parent list was not checked). The duplicate disappears only if a later transaction happens to auto-rebase the snapshot. The same happens transiently to `vl merge X` where `X` is the destination; then `Merged <id>` names a snapshot id that the auto-rebase replaced in the same command. `vl rebase -d X -d X` is fine (control). | `Repo::merge` (`commands.rs:371`) and `Transaction::new_change` take the parent list as given. Only `rebase_descendants` deduplicates, and only for snapshots it rewrites. Refuse or deduplicate repeated parents when a snapshot is created. | `conformance_history::merge::merging_a_snapshot_into_itself_records_no_duplicate_parent`, `…::new_with_a_repeated_parent_records_one_parent` (control: `rewrite::rebase_with_a_repeated_destination_records_one_parent`) |
| BUG-246 | low | rewrite | Rewrites that change nothing still rewrite. `vl rebase -s b -d a` where `a` is already `b`'s parent, and `vl describe -r b -m <the same message>`, create new snapshots of `b` and of every descendant, each re-signed by the current user ("Rebasing someone else's change: … the signature becomes ours"). They record an operation and add a version to `vl evolog`. jj reports "Nothing changed" / skips the rebase. | `Repo::rebase` and `Repo::describe` (`commands.rs:270`, `commands.rs:165`) set `predecessors = [old]` before `Transaction::rewrite`, whose "content identical to `old`" check (`transaction.rs:135`) compares the unsigned snapshot including predecessors, so it never matches. Compare without predecessors (and timestamp) instead. | `conformance_history::rewrite::rebase_onto_the_current_parent_is_a_no_op`, `…::describe_with_the_same_message_is_a_no_op` |
| BUG-241 | low | diff | `vl diff` and `vl show` print only `diff --veil a/run.sh b/run.sh` for a `chmod +x`: no line says that the executable bit changed. `--stat` lists `M run.sh`, and the bit is recorded (control), but the full diff is indistinguishable from an empty change. Git prints `old mode 100644` / `new mode 100755`; jj prints a mode-change line. | `print_diff` (`vl/src/render.rs:653`) labels additions, deletions and visibility changes (`render.rs:684`) but never compares `executable`. | `conformance_history::diff::mode_only_change_is_described_in_the_diff` (controls: `mode_only_change_is_listed_by_stat`, `removing_the_executable_bit_is_recorded`) |
| BUG-245 | low | show | `vl show REV` of a snapshot with recorded conflicts never mentions them: no `(conflict)` in the header and no list of paths. `vl log` marks the same snapshot `×`/`(conflict)`, and `vl status` lists conflicts only for `@` and its parents. The diff of a conflicted merge is also empty (relative to the auto-merged parents, as in jj), so `show` gives no hint at all. | `cmd_show` (`vl/src/main.rs:827`) prints change, snapshot, author, signature, parents, tags, cloak and embargo, but not `Snapshot::conflicts`. | `conformance_history::diff::show_of_a_conflicted_merge_names_the_conflicts` |
| BUG-242 | low | diff / CLI | `vl diff -r A --from B` silently ignores `-r` and diffs `B` against `@`. jj refuses the combination; a user who means "the diff of A" gets something else without a warning. | `Cmd::Diff` (`vl/src/main.rs:147`) uses `rev` only when neither `--from` nor `--to` is given; clap does not declare the conflict. | `conformance_history::diff::diff_rev_with_from_is_refused` |
| BUG-248 | low | remote tags / revisions | The guide defines `origin/main` as "where `main` was on remote `origin` at the last pull or push" and says it is "updated by `vl pull`/`vl push`". After `vl push origin -t main`, `origin/main` does not resolve (`revision 'origin/main' not found`) and `vl log` shows no remote tag until the next `vl pull`. | Only `pull_with` records remote tags (`remote.rs:1265`); `push_with` never updates `view.remote_tags`. | `conformance_history::revisions::remote_tags_are_recorded_by_push` (control: `remote_tags_resolve_after_a_pull`) |
| BUG-250 | low | docs | The getting-started guide ("Conflicts") says: "Resolving in `@` and then running `vl squash` gives the right content but leaves the merge marked `(conflict)` in `vl log`." `vl squash` clears the mark (squash keeps a conflict only when the squashed change left the file untouched, ARCHITECTURE §5), and `vl status`'s own hint recommends "Fold the resolution into the merge with `vl squash`". | Stale text at `docs/guide/getting-started.md:329`. | `conformance_history::log::guide_describes_squashing_a_resolution_correctly` (behaviour: `merge::squashing_a_resolution_clears_the_conflict`) |

---

## Conformance findings: working copy and everyday commands

Found by the conformance pass that ports Git's and Jujutsu's working-copy
tests to Veil (Git t0xxx basics, t15xx revisions, t2xxx checkout, restore
and worktrees, t3xxx ls-files, branch, add/rm/mv and stash, t7xxx commit,
status, reset, clean and tag; jj's status, commit, new, describe, edit,
restore, workspace, working-copy, file, tag, bookmark and operation tests),
against `integration` @ `8dbdb61`. Each reproduction is an
`#[ignore = "BUG-2NN: …"]` test in `crates/vl/tests/conformance_worktree/`;
`cargo test -p vl --test conformance_worktree -- --ignored` runs them
(every one fails). Coverage is in `docs/conformance/worktree.md`. Line
numbers refer to `8dbdb61`.

| Severity | Count | IDs |
|---|---|---|
| high | 1 | 200 |
| medium | 5 | 201, 202, 206, 207, 208 |
| low | 5 | 203, 204, 205, 209, 210 |

| ID | Sev. | Area | Finding | Root cause | Reproducing tests |
|---|---|---|---|---|---|
| BUG-200 | high | builder / nested repositories | A Veil repository inside another one (a vendored project, a monorepo member, or `vl init` run by mistake in `~/projects`) is recorded file by file by the enclosing repository: only the inner `.veil/` is skipped. The inner repository's **cloaked** files are plaintext on disk, and the outer policy does not cloak them, so the outer repository records them as `public` (`public 30 inner/secrets/plan.txt`), and the next push sends them to every remote and to Git. The same holds for the inner repository's own `isolate` and `ignore` rules (only the built-in secret names stay protected). Git records an embedded repository as a gitlink, never its files. | `builder.rs:442` (`is_reserved_name(&child.name)` → `continue` drops `.veil` alone; the directory that contains it is walked like any other). | `conformance_worktree`: `init::outer_repository_does_not_record_a_nested_repositorys_cloaked_files` (control: `init::nested_repository_is_independent_of_the_outer_one`) |
| BUG-201 | medium | `vl restore` / working copy | `vl restore` across a file ↔ directory swap fails half way. Directory in the source, file on disk (`f` vs `f/g.txt`): it writes `f/g.txt` before removing `f`, and fails with `File exists`. File in the source, directory on disk: it deletes `f/g.txt`, then fails to write `f` (`Is a directory`), so the directory's files are gone from disk and every retry fails the same way; only `rm -r f` by hand gets out. Checkout handles both orders. | `main.rs:874–901` (`cmd_restore`: one `fs.write`/`fs.remove_file` per diff entry, in path order, with no removal of a file or directory in the way). | `conformance_worktree`: `restore::restore_a_directory_over_a_file`, `restore::restore_a_file_over_a_directory` (control: `checkout::file_to_directory_and_back_on_checkout`) |
| BUG-202 | medium | checkout / file names | A file whose name is 241–255 bytes long (legal on ext4, APFS, btrfs, XFS) is recorded, but can never be written back: every write goes through a temporary `.<name>.vltmpXXXXXXXX`, 15 bytes longer, which fails with `ENAMETOOLONG`. `vl new`/`vl edit` of such a snapshot fails after the view moved; every later command finds the working copy stale, saves another `recovered working-copy edits` change, retries the checkout and fails again, until `vl --no-snapshot undo`. `vl restore` of the file fails the same way. | `vfs/disk.rs:177` (`temp_path`: `format!(".{}.vltmp{}", name, 8 hex)` with no length check or fallback name). | `conformance_worktree`: `filesystem::a_name_of_250_bytes_round_trips`, `filesystem::restore_of_a_250_byte_name` (control: `filesystem::a_name_of_240_bytes_round_trips`) |
| BUG-206 | medium (**duplicate of BUG-247**) | undo / docs | The guide says "`vl undo` undoes the last operation. Run it again to go further back." A second `vl undo` undoes the first one instead (`Undid: undo: commit change …`): repeated undos toggle between two states. A user stepping back over two mistakes (a bad rebase, then a bad commit) re-applies the first one and continues on the state they meant to leave. `vl op restore` works. | `workspace.rs:413` (`undo_keeping_edits`: the newest non-snapshot operation is undone, and an undo is such an operation); `docs/guide/getting-started.md:270`. | `conformance_worktree`: `undo::undo_again_goes_further_back` (control: `undo::undo_of_a_commit_reopens_the_change`) |
| BUG-207 | medium | revsets / recovery | The guide: "Because every command snapshots, a change gets a new snapshot id each time … `vl evolog` shows the versions … Use snapshot ids when you mean one exact version (to compare with `vl diff --from` …)". The ids `vl evolog` prints for earlier versions do not resolve (`error: revision '0d503b6f' not found`) in `vl show`, `vl cat -r`, `vl diff --from` or `vl restore --from`, because prefixes are only looked up among visible snapshots, and nothing prints the full 64-hex id of a hidden one. Getting back a file as it was two snapshots ago needs `vl op restore`. | `revset.rs:62–96` (`resolve_base`: change-id and snapshot-id prefixes are matched against `repo.visible_snapshots()` only; only a full 64-hex id reaches hidden snapshots). | `conformance_worktree`: `revisions::evolog_snapshot_ids_resolve_as_revisions` (control: `revisions::snapshot_id_prefixes_need_four_hex_digits`) |
| BUG-208 | medium | `vl restore` / merges | With a merge as the working copy (`vl new A B`), `vl status` compares with the merged parents, but `vl restore` (default `--from @-`) restores from the **first** parent alone: to drop a stray edit it deletes every file that came from `B` (`Restored 2 path(s)`, then `D b.txt`). A `vl commit` afterwards records a merge that silently discards `B`'s work. jj restores from the merged parents. | `cli.rs:596` (`--from` defaults to `@-`); `main.rs:875` (`cmd_restore` takes `snapshot(src).tree`, not `parents_tree(&s.parents)` as `cmd_status` does). | `conformance_worktree`: `restore::restore_in_a_merge_goes_back_to_the_merged_parents` (control: `status::status_of_a_merge_shows_both_parents`) |
| BUG-203 | low | policy / ignore | "The last matching rule wins": with `build/ ignore` then `build/keep.txt public`, `vl policy check build/keep.txt` says `public via rule 'build/keep.txt'`, but no snapshot ever records the file, because the walk never enters an ignored directory, and nothing reports it. (Git documents that a file cannot be re-included below an excluded directory; Veil documents the opposite.) The user believes the file is in history. | `builder.rs:457` (an `Ignored` directory is skipped before its entries are classified); `vl policy check` classifies the path alone. | `conformance_worktree`: `ignores::policy_check_and_the_snapshot_agree_below_an_ignored_directory` (control: `ignores::a_later_public_rule_re_includes_a_file`) |
| BUG-204 | low | path arguments | `Ctx::repo_path` rewrites every `\` to `/` (a Windows habit; Veil 1.0 runs on Linux and macOS, where `\` is an ordinary name character) and turns an absolute path outside the repository into a path relative to its root. `vl cat 'back\slash'` prints `back/slash`; `vl restore 'back\slash'` discards the edit of `back/slash` and leaves the named file alone; `vl restore /etc/passwd` restores the repository's own `etc/passwd`. Recoverable with `vl undo`. | `ctx.rs:403–407` (`strip_prefix(root)` failure falls back to the argument as given; `.replace('\\', "/")`). | `conformance_worktree`: `filesystem::a_backslash_in_a_path_argument_names_that_file`, `restore::restore_of_an_absolute_path_outside_the_repository_is_refused` (control: `restore::restore_paths_relative_to_the_current_directory`) |
| BUG-205 | low | messages | `vl cat <directory>` (and `vl cat .`, `vl cat ''`, `vl ws cat W <directory>`) fails with `error: corrupt object <id>: expected blob, found tree`. The repository is fine (`vl fsck` agrees); the message sends the user hunting for corruption. | `main.rs:166–172` (`Cmd::Cat`: `read_file` on the entry whatever its kind; the store reports a kind mismatch as `Corrupt`); `WsCmd::Cat` likewise. | `conformance_worktree`: `files::cat_of_a_directory_is_a_clear_error` (control: `files::cat_of_a_missing_path_fails`) |
| BUG-209 | low | `vl restore` | Directories that `vl restore` empties stay on disk (`newdir/a/b/`), unlike a checkout, which removes them, and Git's `reset --hard` / `clean -d`. Empty directories are not recorded, so `vl status` shows nothing, but the tree on disk no longer matches the snapshot. | `main.rs:898` (`cmd_restore`: `ctx.fs.remove_file` only; no pruning of emptied parents as `checkout` does). | `conformance_worktree`: `restore::restore_removes_directories_it_empties`, `clean::restore_removes_the_new_directories_it_empties` (control: `filesystem::empty_directories_are_not_recorded`) |
| BUG-210 | low | tags / scopes | `vl tag set NAME --cloak SCOPE` accepts any scope string: one that does not exist or that you are not a member of (a typo: `--cloak tema`), reserved names (`local`, `embargo/x`), path-like and upper-case names, and the empty string. `vl cloak --scope` and `vl ws new --cloak` refuse a scope you hold no key for. The tag is withheld from public remotes as intended, but `vl commit` in a cloaked workspace only advances tags cloaked under *its* scope, so a mistyped tag never moves, silently. | `commands.rs:515` (`set_tag`: `validate_tag_name` only; the cloak scope is neither validated with `validate_scope_name` nor checked for membership); `main.rs:1128` (`TagCmd::Set`). | `conformance_worktree`: `tags::a_cloaked_tag_needs_a_valid_scope` (control: `tags::a_cloaked_tag_is_marked_in_the_list`) |

### Conformance (working copy) hypotheses and notes

* **Git-incompatible tag names.** `validate_tag_name` accepts `-x`, `.hidden`, `x.lock`, `trail/`, `HEAD` and `origin/main` (the last is also a remote-tag key; a local tag of that name shadows the remote one in revsets). Tags export to Git as branches, where all of these are invalid ref names (`git check-ref-format`). Not tested here (the Git bridge belongs to the interop conformance pass).
* **`vl ws new --cloak local`** is accepted (`local` is a reserved scope name for policy rules); what is recorded there was not examined.
* **`VEIL_FS_FOLDING=macos` on Linux** rehearses the checkout refusal for colliding names but cannot rehearse NFC recording of new names (a decomposed name is recorded as is); the macOS CI run is the only real test of `t3910`-style behaviour.
* **Checkout from inside a directory it removes** (`cd sub && vl new root`) deletes the current directory; Git keeps it (t2501). Harmless but surprising; not filed.
