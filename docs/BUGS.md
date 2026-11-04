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
them (BUG-066 takes about 330 s).

| ID | Sev. | Area | Finding | Root cause | Reproducing tests |
|---|---|---|---|---|---|
| BUG-057 | critical (**fixed** by the policy pin, BUG-045 wave) | Git import / policy | A `.veilpolicy` edit made on GitHub (`.env public!`, or deleting a user `isolate` rule) is imported silently. The next snapshot records the local isolated `.env` in plaintext, and the next `vl git push` uploads it to GitHub: any contributor can exfiltrate a maintainer's local secrets. This is the Git-import path of BUG-045; check that its fix covers `git/import.rs` too. | `git/import.rs:237` `guard_policy` asks `policy_rekeys` (`embargo.rs:549`), which only looks at files that are already `Cloaked`. Isolated files are never in the tree, so a rule that un-isolates them never counts. | `adversarial3_git_cli`: `a_github_policy_edit_cannot_exfiltrate_the_local_dotenv` |
| BUG-063 | high | Git export / embargo | After an embargo release, GitHub keeps the vulnerable pre-fix file whenever a GitHub commit sits on the exported embargoed merge. `main` is exported as the imported commit, which is never recomputed. Carry-over then treats that stale file as "Git's version", so later Veil commits are exported with the vulnerable file too. The import of the next GitHub commit then reads as "Git reverted the fix"; only BUG-050's heuristic keeps that revert out of Veil today, so fixing BUG-050 turns this into a silent revert in Veil. | `git/export.rs:173`: `Origin::Imported` commits are never recomputed, and no publication commit is written for them. `git/export.rs:311` (`carry`): `same(tx, bx)` keeps `ours`, because the parent's projection changed under its pinned Git commit. | `adversarial3_git`: `a_released_fix_reaches_github_past_a_github_commit`, `a_released_fix_is_not_reverted_by_the_next_github_round_trip` |
| BUG-058 | medium | Git import, untrusted input | One hostile branch makes every `vl git fetch`/`pull` fail. For example, a branch whose tree holds `.veilpolicy` as a symlink fails with `invalid path: .veilpolicy is not a regular file`, which names no branch or commit. No other branch is imported. Anyone who can push a branch to the GitHub repository can stop every Veil user's fetch. | `git/import.rs:114`: only `VeilError::Policy` is handled per commit; any other error aborts `import_tips`. `Policy::load` (`import.rs:177`) propagates `GitTreeFs::read`'s `InvalidPath` (`import.rs:426`). | `adversarial3_git_cli`: `a_hostile_branch_does_not_block_importing_the_other_branches` |
| BUG-059 | medium | Git import / revsets | GitHub can take over the names of the user's changes. Exported commits publish the full change id. A branch named after it becomes a local tag on `vl git pull`, and tags win over change ids, so `vl new <change>` checks out the attacker's commit. A commit with a forged `change-id` header equal to the user's change makes that id "divergent" and unusable. | `revset.rs:48`: tags are resolved before change ids. `git/mod.rs:442` (`update_tag`) creates tags for any valid branch name. `git/import.rs:41` (`change_id_of`) trusts the header. | `adversarial3_git_cli`: `a_branch_named_after_a_change_id_does_not_hijack_it`, `a_forged_change_id_header_does_not_break_the_users_change_id` |
| BUG-064 | medium | Git map / determinism | The mapping is documented as recomputable. That holds only if the next command is an export. If `.veil/git/map` is lost and the next command is `vl git pull`, every commit Veil exported is imported again as a new snapshot. The result is a parallel copy of the history, without the cloaked files, with duplicate change ids. `github/main` points into it, and `main` "has diverged". | `git/import.rs:131` (`mapped`): an unmapped commit carrying a Veil `change-id` header is treated as a Git-made commit. Nothing re-derives the mapping by export first. | `adversarial3_git`: `a_lost_mapping_does_not_duplicate_history_on_pull` |
| BUG-065 | medium | SFTP client, hostile server | A hostile SFTP server can exhaust the client's memory. One file it calls 16 bytes and then never ends (`/dev/zero`-like) is buffered without limit; the stub hung up at 256 MiB. An endless `READDIR` is accumulated the same way. Op heads, locks, pack indexes and object listings are all read this way. | `vfs/sftp.rs:242` (`read_handle`, non-exact): it probes past the size hint until EOF, with no ceiling. `vfs/sftp.rs:480` (`readdir`): it loops until EOF, with no ceiling. | `adversarial3_sftp`: `an_endless_file_is_refused_before_exhausting_memory`, `an_endless_listing_is_refused_before_exhausting_memory` |
| BUG-066 | medium | SFTP client, hostile server | A server that never answers, but sends a stray reply with an unknown id every 200 ms, hangs every Veil command forever. The 300 s request timeout never fires, so `vl push`/`vl pull` hang, and the remote lock stays held meanwhile. | `vfs/sftp_client.rs:582`: `last_rx` is updated for every packet, even one that answers no pending request. `Pending::wait` (`sftp_client.rs:387`) times out only when `last_rx` is old. | `adversarial3_sftp`: `stray_replies_do_not_defeat_the_request_timeout` (≈330 s) |
| BUG-060 | low | Git fetch | A branch deleted on GitHub while a fetch fails keeps its `origin/<branch>` remote tag forever, and no "deleted" report ever appears. | `git/mod.rs:388`: `git fetch --prune` updates the bridge's tracking refs before the import runs. When the import fails, the transaction that removes remote tags is dropped, and the next fetch's `before` no longer lists the branch. | `adversarial3_git_cli`: `a_branch_deleted_during_a_failed_fetch_loses_its_remote_tag` |
| BUG-061 | low | Git transport | A token embedded in a Git remote URL (`https://user:ghp_…@host/x.git`) is printed in `vl git fetch`/`push` errors, which end up in CI logs. `git` itself redacts it in the same message. | `git/transport.rs:70`, `:148`: `{url}` is formatted as is. | `adversarial3_git_cli`: `credentials_in_a_git_url_are_not_printed_in_errors` |
| BUG-062 | low | Git remotes | `vl git remote add origin ../github.git` stores the relative path. `git` resolves it against the current directory, so `vl git push` run from a subdirectory pushes to a different repository (`proj/github.git`). `vl git import` canonicalises paths; `remote add` does not. | `git/mod.rs:294`/`:307` stores the URL unchanged; `transport::fetch`/`push` run `git` in the caller's cwd. | `adversarial3_git_cli`: `a_relative_git_remote_is_the_same_repository_from_a_subdirectory` |
| BUG-067 | low | release / Homebrew | `render-formula.sh` accepts tags such as `v1.2.3";system "id";"` or `v1.2.3\|g;1e <cmd>;s\|x`. The tag ends up as Ruby code in the published formula, run by every `brew install`, and as a GNU sed `e` command run on the release runner, which holds `contents: write` and the tap token. Git allows `"`, `;` and `\|` in tag names. dist's SemVer check stops it on the automatic path; `workflow_dispatch` takes any tag that has a release. | `packaging/homebrew/render-formula.sh:20`: the `case` pattern `[0-9]*.[0-9]*.[0-9]*`, where `*` matches anything. The tag is then pasted into `sed "s\|…\|$tag\|"`. | `adversarial3_release`: `the_formula_renderer_refuses_hostile_tags` |
| BUG-068 | low | CI supply chain | Every action is referenced by a mutable tag (`actions/checkout@v6`, `Swatinem/rust-cache@v2.9.3`, …), including in `publish-homebrew.yml`, which runs with `contents: write` and `HOMEBREW_TAP_TOKEN`. `ci.yml` pipes `cargo-dist-installer.sh` into `sh` without a checksum, while `actionlint` in the same job is verified. (`release.yml` is generated by dist, with the same pattern.) | `.github/workflows/*.yml` `uses:` lines; the `ci.yml` "dist plan" step. | `adversarial3_release`: `workflow_actions_are_pinned_by_commit`, `ci_verifies_what_it_downloads_and_runs` |

## Round 3 hypotheses (not demonstrated)

* **Clock skew beyond the allowance.** If a holder's wall clock runs more than `lease + grace + skew` (165 s) behind, any contender takes over its live, renewing fencing lock at once. The holder notices at its next `ensure_held` or heartbeat and aborts, so the expected result is a failed push, not a double publish. The documented residual window (a stall between the final check and the `op_head` write) applies. This is by design; not tested end to end, because remote pushes cannot take an injected clock.
* **Heartbeat TOCTOU.** The renewal reads the lock, compares the token, then writes (`lock.rs` heartbeat). A takeover that lands between the read and the write is overwritten. The contender then fails `ensure_held`, so both sides lose rather than both win. Only possible after a real stall, or with the skew above.
* **HFS+ spellings of `.git`.** The Git bridge filters `.git` with `eq_ignore_ascii_case` (`git/import.rs`, `git/project.rs`), not with the HFS+-ignorable folding that BUG-051's fix added for `.veil`. On HFS+, `.g\u{200c}it/…` from GitHub would be checked out as `.git/…` in a colocated working copy. Not testable on ext4.
* **`git` transport policy.** Veil leaves `protocol.allow` to the user's Git configuration. Git's defaults block `ext::`, but a configuration that allows it would let a Git remote URL run commands. Passing `-c protocol.ext.allow=never` (and `fd`) would close this. The bridge's `git push` also runs hooks (`pre-push`, `reference-transaction`, `core.hooksPath`), and `--no-verify` is not passed. Only someone who can already write `.veil/git/repo.git` or the user's configuration can plant one.
* **Whole-pack prefetch.** `PullSource::prefetch` downloads every remote pack that holds any object the client lacks, into memory, whether or not the walk needs it. A hostile remote with a huge unreferenced pack makes every pull download it. This is close to the documented "a pull holds the remote packs it downloads in memory".
* **Re-import after a release.** Importing the same Git commit after the embargo under it was released yields a different snapshot id (the merge is no longer re-wrapped), so "re-importing gives the same snapshot" fails there too. Related to BUG-064.

## Round 3 coverage notes

* **Git bridge, CLI** (`adversarial3_git_cli`; terminal escapes and bidi characters in Git authors and messages were also checked by hand and are escaped by `vl git import`, `vl log` and `vl show`): hostile trees written with `git hash-object --literally`. These are `.veil`, `.VEIL`, `..`, `.Git`, symlinks, gitlinks, a zero-padded mode, unsorted entries, escape codes in names, trees 1,100 deep, and `.veilpolicy` as a symlink. All are refused or reported except as listed above. Also covered: forged `change-id` headers, a branch named after a change id, relative and credential-bearing URLs, force-push and deletion bookkeeping, and the Git-side un-cloaking control.
* **Git bridge, library** (`adversarial3_git`): embargoes with GitHub commits on top, releases, carry-over, and loss of the map and cache.
* **Round-trip property model** (`adversarial3_git_props`): interleaved Veil commits (public, cloaked and isolated files, deletions), GitHub commits (including files under cloaked directories), pull, merge and push, and re-exports. Invariants: no cloaked or isolated token in any object of the bare repository or the bridge; cloaked files intact in Veil; public files identical on both sides; re-export writes nothing. 400 cases passed. Embargo operations are not in the model; they are covered by the targeted tests.
* **SFTP** (`adversarial3_sftp`): an in-process hostile server over a socket pair, testing endless data, endless listings, keep-alive noise and a 2³²−1 name count (control). URL parsing was reviewed (`-o` injection through hosts and users, IPv6, scp style, `--` before the host) and found sound.
* **Format** (`adversarial3_format`): a mutation fuzzer over JSON and binary trees, checking that whatever decodes re-encodes byte for byte. 2,000 cases, plus the golden fixtures; no second encoding found. One logical tree still has one id per encoding (JSON and binary), by design.
* **Release** (`adversarial3_release`): `render-formula.sh` run with hostile tags, and the workflows checked statically.
